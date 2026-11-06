#!/usr/bin/env python3
"""See the pages at phone and desktop width side by side, on this machine only.

Starts the real local server and puts a small proxy in front of it. The proxy changes exactly
two things, for the preview only: it lets the pages sit in a frame, and it can force the colour
scheme. Everything else is the real thing.

    python3 web/tools/preview.py     then open http://127.0.0.1:8766/__preview
"""
from __future__ import annotations

import http.client
import http.server
import json
import os
import re
import sys
from pathlib import Path
from urllib.parse import parse_qs, urlparse

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "verify/web-real"))
from common import Server, b64u  # noqa: E402

PORT = 8766
UPSTREAM_PORT = 8787
SITE = Path(__file__).resolve().parents[2] / "site/public"
SAMPLE = 'STRIPE_KEY=not_a_real_key_0123456789\nDATABASE_URL=postgres://user:not_a_password@db.example.com/app\nOPENAI_API_KEY=not_a_real_key_abcdef\n'

PAGE = """<!doctype html><html lang="ja"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="robots" content="noindex"><title>APIキー便のプレビュー</title>
<style>
:root{color-scheme:light dark;--ink:#1b2430;--sub:#56606e;--bg:#eef1f5;--panel:#fff;--line:#cdd5df;--acc:#1f4fbf;--on:#eaf0fb}
@media (prefers-color-scheme:dark){:root{--ink:#e8edf3;--sub:#a8b3c0;--bg:#0c0f13;--panel:#1a2028;--line:#3a4452;--acc:#94b7f7;--on:#18283a}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);font:14px/1.5 "Hiragino Sans","Noto Sans JP",system-ui,sans-serif}
.bar{position:sticky;top:0;z-index:5;background:var(--panel);border-block-end:1px solid var(--line);padding:8px 16px;display:flex;flex-wrap:wrap;gap:6px 16px;align-items:center}.bar b{font-size:15px}
.grp{display:flex;align-items:center;gap:4px;flex-wrap:wrap}.grp>span{color:var(--sub);font-weight:700;margin-inline-end:2px}
.grp button{font:inherit;font-weight:700;min-height:32px;padding:2px 10px;border:1.5px solid var(--line);border-radius:8px;background:transparent;color:var(--ink);cursor:pointer}
.grp button.on{border-color:var(--acc);background:var(--on);color:var(--acc)}
.stage{display:flex;gap:20px;padding:16px;align-items:flex-start;justify-content:center}figure{margin:0}figcaption{display:flex;justify-content:space-between;gap:12px;font-weight:700;margin:0 0 6px}
figcaption a{color:var(--acc);font-weight:600}.frame{background:#fff;border:1px solid var(--line);overflow:hidden}
#spWrap{flex:none;width:390px}#sp{display:block;width:390px;height:844px;border:0;background:#fff}#spBox{border-radius:18px}
#pcWrap{flex:1;min-width:0;max-width:1200px}#pcBox{position:relative;border-radius:8px}#pc{display:block;width:1200px;height:800px;border:0;background:#fff;transform-origin:0 0}
@media (max-width:1100px){.stage{flex-direction:column;align-items:center}#pcWrap{flex:none;width:100%}}
</style></head><body>
<div class="bar"><b>APIキー便のプレビュー</b>
<div class="grp" data-key="page"><span>画面</span><button data-v="new">作る（広告あり）</button><button data-v="noad">作る（広告なし）</button><button data-v="cushion">クッションページ</button><button data-v="cushion-nolink">クッションページ（リンクなしで来た人）</button><button data-v="open">受け取る</button><button data-v="file">受け取る（ファイル）</button><button data-v="binary">受け取る（バイナリ）</button><button data-v="openpw">受け取る（合言葉）</button><button data-v="gone">使えないリンク</button><button data-v="bad">切れたリンク</button><button data-v="guides">読み物</button><button data-v="privacy">プライバシー</button><button data-v="terms">利用規約</button><button data-v="report">通報</button></div>
<div class="grp" data-key="ads"><span>広告</span><button data-v="on">枠あり（審査のあと）</button><button data-v="off">なし（審査の間）</button></div>
<div class="grp" data-key="theme"><span>色</span><button data-v="light">明るい</button><button data-v="dark">暗い</button></div>
</div>
<div class="stage">
<figure id="spWrap"><figcaption><span>スマホ（390×844）</span></figcaption><div id="spBox" class="frame"><iframe id="sp" title="スマホ"></iframe></div></figure>
<figure id="pcWrap"><figcaption><span id="pcCap">PC（1200×800）</span></figcaption><div id="pcBox" class="frame"><iframe id="pc" title="PC"></iframe></div></figure>
</div>
<script>
(function () {
  var q = new URLSearchParams(location.search);
  var state = { page: q.get("page") || "new", theme: q.get("theme") || "light", ads: q.get("ads") || "on" };
  var sp = document.getElementById("sp"), pc = document.getElementById("pc"), box = document.getElementById("pcBox"), wrap = document.getElementById("pcWrap");
  function mark() {
    document.querySelectorAll(".grp").forEach(function (g) {
      g.querySelectorAll("button").forEach(function (b) { b.classList.toggle("on", state[g.dataset.key] === b.dataset.v); });
    });
    history.replaceState(null, "", "?" + new URLSearchParams(state).toString());
  }
  // A secret opens once, so each frame gets a link of its own.
  function linkFor() {
    return fetch("/__sample?page=" + state.page).then(function (r) { return r.json(); }).then(function (d) { return d.link; });
  }
  function load() {
    mark();
    fetch("/__theme?set=" + state.theme + "&ads=" + state.ads).then(function () {
      return Promise.all([linkFor(), linkFor()]);
    }).then(function (links) {
      sp.src = "about:blank"; pc.src = "about:blank";
      setTimeout(function () { sp.src = links[0]; pc.src = links[1]; }, 30);
    });
  }
  function fit() {
    var s = Math.min(1, wrap.clientWidth / 1200);
    pc.style.transform = "scale(" + s + ")";
    box.style.height = Math.round(800 * s) + "px";
    box.style.width = Math.round(1200 * s) + "px";
    document.getElementById("pcCap").textContent = "PC（1200×800・" + Math.round(s * 100) + "%で表示）";
  }
  document.querySelectorAll(".grp").forEach(function (g) {
    g.addEventListener("click", function (e) {
      if (e.target.dataset && e.target.dataset.v) { state[g.dataset.key] = e.target.dataset.v; load(); }
    });
  });
  window.addEventListener("resize", fit); fit(); load();
})();
</script></body></html>"""


class Handler(http.server.BaseHTTPRequestHandler):
    server_version = "preview"
    theme = "light"
    ads = "on"
    upstream: Server

    def log_message(self, *_):
        pass

    def _json(self, value):
        data = json.dumps(value).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        url = urlparse(self.path)
        if url.path == "/__preview":
            data = PAGE.encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
            return
        if url.path == "/__theme":
            Handler.theme = parse_qs(url.query).get("set", ["light"])[0]
            Handler.ads = parse_qs(url.query).get("ads", ["on"])[0]
            self._json({"theme": Handler.theme})
            return
        if url.path == "/__sample":
            self._json({"link": self._sample(parse_qs(url.query).get("page", ["new"])[0])})
            return
        if url.path == "/__read":
            # Stands in for the return from the page with ads: a fresh sample each time.
            self.send_response(302)
            self.send_header("Location", self._sample("file"))
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        self._forward()

    def do_HEAD(self):
        self._forward()

    def do_POST(self):
        self._forward()

    def _sample(self, page: str) -> str:
        base = f"http://127.0.0.1:{PORT}"
        if page == "new":
            return f"{base}/"
        if page == "noad":
            return f"{base}/__noad"
        if page == "cushion":
            return f"{base}/__cushion#go"
        if page == "cushion-nolink":
            return f"{base}/__cushion"
        if page == "guides":
            return f"{base}/guides/"
        if page in ("privacy", "terms", "report"):
            return f"{base}/{page}"
        up = self.upstream
        if page == "file":
            rid, secret, _ = up.create(SAMPLE, name=".env.production")
            return f"{base}/s/{rid}#1.{b64u(secret)}"
        if page == "binary":
            rid, secret, _ = up.create(bytes(range(256)) * 3, name="cert.p12")
            return f"{base}/s/{rid}#1.{b64u(secret)}"
        if page == "open":
            rid, secret, _ = up.create(SAMPLE)
            return f"{base}/s/{rid}#1.{b64u(secret)}"
        if page == "openpw":
            rid, secret, _ = up.create(SAMPLE, passphrase="sakura")
            return f"{base}/s/{rid}#1p.{b64u(secret)}"
        if page == "gone":
            rid, secret, _ = up.create("x")
            up.open(rid, secret)
            return f"{base}/s/{rid}#1.{b64u(secret)}"
        rid, _, _ = up.create("x")
        return f"{base}/s/{rid}"

    def _themed(self, text: str) -> bytes:
        scheme = "all" if Handler.theme == "dark" else "not all"
        return re.sub(r"@media \(prefers-color-scheme: dark\)", f"@media {scheme}", text).encode()

    def _site(self, path: str) -> bool:
        """Serves the shell from site/public, pointed at the tool on this same proxy."""
        name = {"/": "index.html", "/__cushion": "open.html", "/open-article": "open.html", "/privacy": "privacy.html", "/terms": "terms.html", "/report": "report.html", "/site.css": "site.css", "/favicon.svg": "favicon.svg"}.get(path)
        if name is None and path.startswith("/guides/"):
            name = "guides/index.html" if path == "/guides/" else f"guides/{path[8:]}.html"
            if not (SITE / name).exists():
                return False
        if name is None:
            return False
        data = (SITE / name).read_bytes()
        ctype = {"html": "text/html; charset=utf-8", "css": "text/css; charset=utf-8", "svg": "image/svg+xml"}[name.rsplit(".", 1)[1]]
        if name == "open.html":
            data = data.decode().replace("https://app.apikeybin.com/open", "/__read").encode()
        data = data.replace(b'href="/open"', b'href="/__cushion"')
        if (name in ("index.html", "open.html") or name.startswith("guides/")) and Handler.ads == "on":
            data = data.replace(b' class="no-ads"', b"")
        if name == "index.html":
            data = data.decode().replace("https://app.apikeybin.com/embed", "/embed").replace("https://app.apikeybin.com/", "/__noad").encode()
        elif name == "site.css":
            data = self._themed(data.decode())
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)
        return True

    def _forward(self):
        path_only = urlparse(self.path).path
        if self.command in ("GET", "HEAD") and self._site(path_only):
            return
        if path_only == "/__noad":
            self.path = "/"
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length) if length else None
        conn = http.client.HTTPConnection("127.0.0.1", UPSTREAM_PORT, timeout=30)
        headers = {k: v for k, v in self.headers.items() if k.lower() not in ("host", "connection", "accept-encoding", "if-none-match", "if-modified-since")}
        conn.request(self.command, self.path, body=body, headers=headers)
        r = conn.getresponse()
        data = r.read()
        conn.close()
        if urlparse(self.path).path == "/app.css":
            data = self._themed(data.decode())
        if path_only == "/open" or path_only.startswith("/s/"):
            data = data.replace(b"https://apikeybin.com/", b"/")
        self.send_response(r.status)
        for name, value in r.getheaders():
            low = name.lower()
            if low in ("content-length", "transfer-encoding", "connection", "x-frame-options"):
                continue
            if low == "content-security-policy":
                value = re.sub(r"frame-ancestors [^;]+", "frame-ancestors 'self'", value)
            if low == "cache-control":
                value = "no-store"
            self.send_header(name, value)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(data)


def main():
    if os.environ.get("NODE_BIN") is None and Path("/opt/homebrew/opt/node@22/bin").exists():
        os.environ["NODE_BIN"] = "/opt/homebrew/opt/node@22/bin"
    with Server(port=UPSTREAM_PORT) as up:
        Handler.upstream = up
        srv = http.server.ThreadingHTTPServer(("127.0.0.1", PORT), Handler)
        print(f"http://127.0.0.1:{PORT}/__preview", flush=True)
        try:
            srv.serve_forever()
        except KeyboardInterrupt:
            pass


if __name__ == "__main__":
    main()
