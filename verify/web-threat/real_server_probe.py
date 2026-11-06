#!/usr/bin/env python3
"""Things that need real HTTP, because Playwright interception distorts them.

1. Does COOP stop an opener from navigating the opened secret page?
2. Does CSP img-src stop an image from redirecting to a host it does not allow?

The main harness fulfils responses inside Playwright, so an unexpected browser
result there could be an artefact of interception. This probe uses real local HTTP
servers and no interception: http://localhost is a secure context, and localhost vs
127.0.0.1 are different sites, which is what COOP needs to matter.
"""
import asyncio, http.server, json, sys, threading
from playwright.async_api import async_playwright

OPENER_PORT, APP_COOP, APP_PLAIN = 18731, 18732, 18733
SEEN = []
REDIR_PORT, COLLECT_PORT = 18734, 18735

class H(http.server.BaseHTTPRequestHandler):
    coop = None
    def log_message(self, *a): pass
    def do_GET(self):
        SEEN.append((self.server.server_address[1], self.path))
        port = self.server.server_address[1]
        if port == REDIR_PORT and self.path.startswith('/redirect.gif'):
            self.send_response(302)
            self.send_header('Location', f'http://127.0.0.1:{COLLECT_PORT}/collected')
            self.end_headers()
            return
        if port == REDIR_PORT and self.path.startswith('/page'):
            allow = 'http://127.0.0.1:%d' % REDIR_PORT
            if 'open' in self.path:
                allow += ' http://127.0.0.1:%d' % COLLECT_PORT
            body = (f'<!doctype html><title>page</title><img id=i src="http://127.0.0.1:{REDIR_PORT}/redirect.gif">').encode()
            self.send_response(200)
            self.send_header('Content-Type', 'text/html; charset=utf-8')
            self.send_header('Content-Security-Policy', f"default-src 'none'; img-src {allow}")
            self.end_headers()
            self.wfile.write(body)
            return
        if port == COLLECT_PORT:
            self.send_response(204); self.end_headers(); return
        if self.path.startswith('/phish'):
            body = b'<!doctype html><title>phish</title>phish'
        elif self.path == '/favicon.ico':
            self.send_response(404); self.end_headers(); return
        elif self.server.server_address[1] == OPENER_PORT:
            target = self.path.split('?to=')[1]
            body = ("<!doctype html><title>opener</title><a id=go href='#'>go</a><script>"
                    "document.getElementById('go').addEventListener('click',function(e){e.preventDefault();"
                    f"var w=window.open('{target}');window.__w=w;"
                    "setTimeout(function(){window.__closed=w.closed;try{w.location='http://127.0.0.1:%d/phish'}catch(e){window.__err=e.name}},1200)});"
                    "</script>" % OPENER_PORT).encode()
        else:
            body = b'<!doctype html><title>app</title><p id=app>app page</p>'
        self.send_response(200)
        self.send_header('Content-Type', 'text/html; charset=utf-8')
        self.send_header('Cache-Control', 'no-store')
        if self.server.server_address[1] == APP_COOP and not self.path.startswith('/phish'):
            self.send_header('Cross-Origin-Opener-Policy', 'same-origin')
        self.end_headers()
        self.wfile.write(body)

async def one(browser, target, label):
    ctx = await browser.new_context()
    popups = []
    ctx.on('page', lambda p: popups.append(p))
    page = await ctx.new_page()
    await page.goto(f'http://127.0.0.1:{OPENER_PORT}/o?to={target}')
    n = len(popups)
    await page.click('#go')
    for _ in range(40):
        if len(popups) > n: break
        await asyncio.sleep(0.05)
    await asyncio.sleep(2.0)
    popup = popups[n] if len(popups) > n else None
    url = popup.url if popup else None
    closed = await page.evaluate('window.__closed')
    await ctx.close()
    return {'case': label, 'popup_url': url, 'hijacked': bool(url and 'phish' in url), 'opener_saw_closed': closed}

async def main():
    for port in (OPENER_PORT, APP_COOP, APP_PLAIN, REDIR_PORT, COLLECT_PORT):
        srv = http.server.ThreadingHTTPServer(('127.0.0.1', port), H)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
    out = {}
    async with async_playwright() as pw:
        for name in sys.argv[1:] or ['chromium', 'webkit', 'firefox']:
            b = await getattr(pw, name).launch(headless=True)
            rows = []
            for i in range(2):
                rows.append(await one(b, f'http://localhost:{APP_PLAIN}/app', 'no COOP (control)'))
                rows.append(await one(b, f'http://localhost:{APP_COOP}/app', 'COOP same-origin'))
            redir = []
            for label, path in (('img-src allows only the ad host', '/page?blocked'), ('control: img-src also allows the collector', '/page?open')):
                SEEN.clear()
                ctx = await b.new_context()
                pg = await ctx.new_page()
                await pg.goto(f'http://127.0.0.1:{REDIR_PORT}{path}', wait_until='domcontentloaded')
                await asyncio.sleep(1.0)
                await ctx.close()
                redir.append({'case': label, 'collector_reached': any(p == COLLECT_PORT for p, _ in SEEN)})
            out[name] = {'version': b.version, 'rows': rows, 'redirect': redir}
            for r in redir: print('  ', json.dumps(r, ensure_ascii=False))
            print(name, b.version)
            for r in rows: print('  ', json.dumps(r, ensure_ascii=False))
            await b.close()
    json.dump(out, open('real_server_results.json', 'w'), ensure_ascii=False, indent=2)
asyncio.run(main())
