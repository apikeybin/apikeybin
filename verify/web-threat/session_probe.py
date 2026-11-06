#!/usr/bin/env python3
"""Does a tab keep its sessionStorage when it leaves for another site and comes back?

The reading page keeps the link's key in sessionStorage while the person looks at the page with
ads, so that the key never reaches that page. That only works if the browser really keeps it,
including across the switch that Cross-Origin-Opener-Policy causes. Real HTTP and no interception,
because Playwright's interception distorts COOP. The same answers decide the design, so this also
checks that the other site cannot read the value.
"""
import asyncio
import http.server
import json
import threading

from playwright.async_api import async_playwright

APP, SITE = 18741, 18742


class H(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_GET(self):
        port = self.server.server_address[1]
        if self.path == "/favicon.ico":
            self.send_response(404)
            self.end_headers()
            return
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        if port == APP:
            self.send_header("Cross-Origin-Opener-Policy", "same-origin")
            self.send_header("Cross-Origin-Embedder-Policy", "require-corp")
            self.send_header("Referrer-Policy", "no-referrer")
        self.end_headers()
        self.wfile.write(b"<!doctype html><title>t</title><a id=go href='#'>go</a>")


async def one(browser):
    ctx = await browser.new_context()
    page = await ctx.new_page()
    app = f"http://localhost:{APP}"
    site = f"http://127.0.0.1:{SITE}"
    await page.goto(app + "/s/abc")
    await page.evaluate("sessionStorage.setItem('pending', 'KEY')")
    # Replace the entry, as the reading page does, so Back does not return to the bounce.
    await page.evaluate(f"setTimeout(() => location.replace({json.dumps(site + '/open')}), 10)")
    await page.wait_for_url(site + "/open", timeout=8000)
    other = await page.evaluate("sessionStorage.getItem('pending')")
    referrer = await page.evaluate("document.referrer")
    # A script on the other site opens the reading page in a new window and tries to reach into it.
    async with ctx.expect_page() as info:
        await page.evaluate(f"window.w = window.open({json.dumps(app + '/open')}); 0")
    popup = await info.value
    await popup.wait_for_load_state()
    popup_copy = await popup.evaluate("sessionStorage.getItem('pending')")
    popup_location = await page.evaluate(
        "(() => { try { return String(window.w.location.href); } catch (e) { return 'blocked: ' + e.name; } })()"
    )
    through_opener = await page.evaluate(
        "(() => { try { return String(window.w.sessionStorage.getItem('pending')); } catch (e) { return 'blocked: ' + e.name; } })()"
    )
    await popup.close()
    await page.goto(app + "/open")
    back = await page.evaluate("sessionStorage.getItem('pending')")
    # A new tab has its own storage, unless it was opened by the same site with an opener.
    second = await ctx.new_page()
    await second.goto(app + "/open")
    other_tab = await second.evaluate("sessionStorage.getItem('pending')")
    await second.close()
    await page.evaluate("sessionStorage.removeItem('pending')")
    await page.reload()
    cleared = await page.evaluate("sessionStorage.getItem('pending')")
    await ctx.close()
    return {"kept_after_coming_back": back == "KEY", "other_site_saw": other, "referrer_seen_by_site": referrer,
            "another_tab_saw": other_tab, "after_removal": cleared, "popup_has_a_copy": popup_copy,
            "opener_reading_popup_location": popup_location, "opener_reading_popup_storage": through_opener}


async def main():
    for port in (APP, SITE):
        srv = http.server.ThreadingHTTPServer(("127.0.0.1", port), H)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
    async with async_playwright() as pw:
        for name in ("chromium", "webkit", "firefox"):
            b = await getattr(pw, name).launch(headless=True)
            print(name, b.version, json.dumps(await one(b), ensure_ascii=False), flush=True)
            await b.close()


asyncio.run(main())
