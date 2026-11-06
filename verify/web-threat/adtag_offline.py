#!/usr/bin/env python3
"""Local, offline observation of what the saved AdSense scripts try to request.

Nothing leaves this machine:
  * every request is intercepted; only the fixture pages and the two saved
    scripts are answered, everything else is recorded and aborted;
  * Chromium is also started with a dead proxy and a resolver rule that fails
    every name, so an un-intercepted request could not get out either.

usage: adtag_local_test.py <adsbygoogle.js> <show_ads_impl.js> <show_ads_impl_with_ama.js>
"""
import re
import sys
import time
import urllib.parse

from playwright.sync_api import sync_playwright

LOADER, IMPL, IMPL_AMA = sys.argv[1:4]
FRAG = "KEYFRAGMENTTOKEN0123456789"
TA = "TEXTAREASECRETTOKEN"
BODY = "BODYTEXTSECRETTOKEN"
MAIN = "https://secret-share-test.example/s/abc123"
FRAME = "https://ads-frame-test.example/frame.html"
TAG = (
    '<script async src="https://pagead2.googlesyndication.com/pagead/js/adsbygoogle.js'
    '?client=ca-pub-0000000000000000" crossorigin="anonymous"></script>'
    '<ins class="adsbygoogle" style="display:inline-block;width:728px;height:90px" '
    'data-ad-client="ca-pub-0000000000000000" data-ad-slot="1234567890" data-adtest="on"></ins>'
    "<script>(adsbygoogle = window.adsbygoogle || []).push({});</script>"
)
CONTENT = (
    f"<h1>Secret</h1><p>{BODY}</p><textarea id=t>{TA}</textarea>"
    "<p>" + ("Plain filler text for the page so that it is not empty. " * 30) + "</p>"
)
PAGE_TOP = f"<!doctype html><html><head><title>t</title></head><body>{CONTENT}{TAG}</body></html>"
PAGE_XFRAME = (
    f"<!doctype html><html><head><title>t</title></head><body>{CONTENT}"
    f'<iframe src="{FRAME}" width=760 height=120></iframe></body></html>'
)
PAGE_SANDBOX = (
    f"<!doctype html><html><head><title>t</title></head><body>{CONTENT}"
    f'<iframe sandbox="allow-scripts" src="{FRAME}" width=760 height=120></iframe></body></html>'
)
PAGE_SANDBOX_SO = (
    f"<!doctype html><html><head><title>t</title></head><body>{CONTENT}"
    f'<iframe sandbox="allow-scripts allow-same-origin" src="{FRAME}" width=760 height=120></iframe></body></html>'
)
PAGE_FRAME = f"<!doctype html><html><head><title>f</title></head><body>{TAG}</body></html>"
SCENARIOS = [
    ("A top-level tag", PAGE_TOP),
    ("B tag in cross-origin iframe", PAGE_XFRAME),
    ("C tag in sandbox=allow-scripts iframe", PAGE_SANDBOX),
    ("D tag in sandbox=allow-scripts allow-same-origin iframe", PAGE_SANDBOX_SO),
]


def run(browser, name, html):
    ctx = browser.new_context(user_agent=None, viewport={"width": 1200, "height": 900})
    page = ctx.new_page()
    seen = []
    errors = []
    page.on("pageerror", lambda e: errors.append(str(e)[:200]))

    def handler(route, request):
        u = request.url
        if u.startswith(MAIN):
            return route.fulfill(status=200, content_type="text/html; charset=utf-8", body=html)
        if u.startswith(FRAME):
            return route.fulfill(status=200, content_type="text/html; charset=utf-8", body=PAGE_FRAME)
        if "/pagead/js/adsbygoogle.js" in u:
            seen.append(("SERVED", request.method, u, None))
            return route.fulfill(status=200, content_type="text/javascript",
                                 headers={"Access-Control-Allow-Origin": "*"}, path=LOADER)
        if "show_ads_impl_with_ama" in u:
            seen.append(("SERVED", request.method, u, None))
            return route.fulfill(status=200, content_type="text/javascript",
                                 headers={"Access-Control-Allow-Origin": "*"}, path=IMPL_AMA)
        if "show_ads_impl" in u:
            seen.append(("SERVED", request.method, u, None))
            return route.fulfill(status=200, content_type="text/javascript",
                                 headers={"Access-Control-Allow-Origin": "*"}, path=IMPL)
        seen.append(("ABORTED", request.method, u, request.post_data))
        return route.abort()

    ctx.route("**/*", handler)
    page.goto(MAIN + "#" + FRAG, wait_until="load", timeout=30000)
    page.fill("#t", TA)
    time.sleep(10)
    probe = page.evaluate(
        """() => {
          const frames = [...document.querySelectorAll('iframe')].map(f => ({src:f.src, name:f.name||'', sandbox:f.getAttribute('sandbox')}));
          return {url: document.URL, hash: location.hash,
                  adsbygoogleType: typeof window.adsbygoogle,
                  loaded: window.adsbygoogle && window.adsbygoogle.loaded === true,
                  frames};
        }"""
    )
    print(f"\n================ {name}")
    print("page probe:", probe)
    print("page errors:", errors[:5])
    print("requests:", len(seen))
    for kind, method, u, body in seen:
        p = urllib.parse.urlsplit(u)
        q = urllib.parse.parse_qs(p.query, keep_blank_values=True)
        shown = {k: q[k][0][:160] for k in ("url", "loc", "ref", "top", "frm", "ife", "client") if k in q}
        hit = []
        decoded = urllib.parse.unquote(urllib.parse.unquote(u))
        for label, tok in (("FRAGMENT", FRAG), ("TEXTAREA", TA), ("BODYTEXT", BODY)):
            if tok in decoded or (body and tok in body):
                hit.append(label)
        print(f"  {kind:7} {method:4} {p.scheme}://{p.netloc}{p.path[:70]}  params={shown}  HIT={hit}")
    ctx.close()


with sync_playwright() as pw:
    browser = pw.chromium.launch(
        headless=True,
        args=[
            "--proxy-server=http://127.0.0.1:9",
            "--host-resolver-rules=MAP * ~NOTFOUND",
            "--disable-background-networking",
        ],
    )
    print("chromium", browser.version)
    for name, html in SCENARIOS:
        run(browser, name, html)
    browser.close()
