#!/usr/bin/env python3
"""Is the deployed site exactly what this repository says it is?

    python3 verify/web-real/check_live.py https://app.apikeybin.com https://apikeybin.com

Compares the served files byte for byte with web/public and site/public, so anything a platform
feature injected (an analytics snippet, a bot check, email obfuscation) shows up as a difference.
Checks every security header, and does one real round trip with the second implementation, not
the site's JS. Checks that plain HTTP is sent to HTTPS on the same host, and that the site's
Strict-Transport-Security header meets what hstspreload.org asks for.

It cannot prove the site serves the same thing to everyone. Run it from more than one place.
"""
from __future__ import annotations

import hashlib
import json
import re
import ssl
import sys
import urllib.error
import urllib.request

from common import WEB, b64u, seal, token_of, unseal

PAGES = {"/": "index.html", "/app.js": "app.js", "/app.css": "app.css", "/favicon.svg": "favicon.svg", "/robots.txt": "robots.txt"}
SITE_PUBLIC = WEB.parent / "site/public"
SITE_PAGES = {"/": "index.html", "/open": "open.html", "/privacy": "privacy.html", "/terms": "terms.html", "/report": "report.html", "/guides/": "guides/index.html", "/guides/api-key-sharing": "guides/api-key-sharing.html", "/guides/env-file-sharing": "guides/env-file-sharing.html", "/guides/api-key-leaked": "guides/api-key-leaked.html", "/guides/password-by-email": "guides/password-by-email.html", "/guides/one-time-link-comparison": "guides/one-time-link-comparison.html", "/guides/how-it-works": "guides/how-it-works.html", "/site.css": "site.css", "/favicon.svg": "favicon.svg", "/robots.txt": "robots.txt", "/sitemap.xml": "sitemap.xml", "/og.png": "og.png"}
# The one origin allowed to frame /embed. Fixed here rather than taken from the arguments, so that
# a wrong value in production is reported even when checking a copy.
FRAMER = "https://apikeybin.com"


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


def fetch(base, path, method="GET", body=None, headers=None):
    req = urllib.request.Request(base + path, data=body, method=method, headers={"User-Agent": "apikeybin-check", **(headers or {})})
    opener = urllib.request.build_opener(NoRedirect, urllib.request.HTTPSHandler(context=ssl.create_default_context()))
    try:
        r = opener.open(req, timeout=30)
    except urllib.error.HTTPError as e:
        return e.code, {k.lower(): v for k, v in e.headers.items()}, e.read()
    return r.status, {k.lower(): v for k, v in r.headers.items()}, r.read()


def http_problems(origin, paths, get=None):
    """A .com is not on the browsers' HTTPS-only list until it is submitted to hstspreload.org
    and shipped, so plain HTTP has to answer with a redirect to HTTPS on the same host and path.
    The preload list asks for exactly that, before any other redirect."""
    get = get or fetch
    if not origin.startswith("https://"):
        return []
    plain = "http://" + origin[len("https://"):]
    found = []
    for path in paths:
        try:
            status, headers, _ = get(plain, path)
        except (urllib.error.URLError, OSError) as e:
            found.append(f"{plain}{path}: not reachable over HTTP ({e}); fine only if nothing listens on port 80")
            continue
        if status not in (301, 308) or headers.get("location") != origin + path:
            found.append(f"{plain}{path}: status {status}, location {headers.get('location')!r}, want a redirect to {origin + path}")
    return found


def preload_problems(value):
    """What hstspreload.org asks of the header on the base domain."""
    parts = [p.strip() for p in (value or "").split(";")]
    found = []
    ages = [p.split("=", 1)[1] for p in parts if p.lower().startswith("max-age=")]
    if len(ages) != 1 or not ages[0].isdigit() or int(ages[0]) < 31536000:
        found.append(f"strict-transport-security max-age is {ages!r}, the preload list wants at least 31536000")
    for name in ("includeSubDomains", "preload"):
        if name.lower() not in [p.lower() for p in parts]:
            found.append(f"strict-transport-security has no {name}")
    return found


def want_headers(file=None, least=10):
    text = (file or WEB / "public/_headers").read_text()
    out = {}
    for line in text.splitlines():
        if line.startswith("  ") and ":" in line:
            name, value = line.strip().split(":", 1)
            out[name.lower()] = value.strip()
    out.pop("cache-control", None)
    assert len(out) >= least, f"could not read {file or 'public/_headers'}"
    return out


def main():
    base = (sys.argv[1] if len(sys.argv) > 1 else "https://app.apikeybin.com").rstrip("/")
    site = (sys.argv[2] if len(sys.argv) > 2 else "https://apikeybin.com").rstrip("/")
    problems = []
    want = want_headers()

    def check_headers(path, headers):
        for name, value in want.items():
            if headers.get(name) != value:
                problems.append(f"{path}: {name} is {headers.get(name)!r}")
        if "set-cookie" in headers:
            problems.append(f"{path}: sets a cookie: {headers['set-cookie'][:60]}")
        for name in headers:
            if name.startswith("access-control-"):
                problems.append(f"{path}: CORS header {name}")

    digests = {}
    for path, name in PAGES.items():
        status, headers, body = fetch(base, path)
        local = (WEB / "public" / name).read_bytes()
        digests[name] = hashlib.sha256(body).hexdigest()
        if status != 200:
            problems.append(f"{path}: status {status}")
        if body != local:
            problems.append(f"{path}: served bytes differ from the repository ({len(body)} vs {len(local)})")
        check_headers(path, headers)

    probe = "A" * 22
    for path in (f"/s/{probe}", "/open"):
        status, headers, body = fetch(base, path)
        if status != 200:
            problems.append(f"{path}: status {status}, a redirect here would carry the key along")
        if body != (WEB / "public/s.html").read_bytes():
            problems.append(f"{path}: served bytes differ from the repository")
        check_headers(path, headers)
        if headers.get("cache-control") != "no-store":
            problems.append(f"{path}: cache-control is {headers.get('cache-control')!r}")
        if "noindex" not in headers.get("x-robots-tag", ""):
            problems.append(f"{path}: can be indexed")

    # The tool in a frame. The same as everything else, except that one origin may frame it.
    status, headers, body = fetch(base, "/embed")
    digests["embed.html"] = hashlib.sha256(body).hexdigest()
    if status != 200:
        problems.append(f"/embed: status {status}")
    if body != (WEB / "public/embed.html").read_bytes():
        problems.append("/embed: served bytes differ from the repository")
    framed = dict(want)
    framed.pop("x-frame-options")
    framed["content-security-policy"] = want["content-security-policy"].replace("frame-ancestors 'none'", f"frame-ancestors {FRAMER}")
    for name, value in framed.items():
        if headers.get(name) != value:
            problems.append(f"/embed: {name} is {headers.get(name)!r}")
    if "x-frame-options" in headers:
        problems.append("/embed: x-frame-options would stop the site from showing the tool")
    if "noindex" not in headers.get("x-robots-tag", ""):
        problems.append("/embed: can be indexed")

    # One real secret, written and read without the site's JavaScript.
    api = {"Content-Type": "application/json", "X-Apikeybin": "1"}
    text = "check_live " + hashlib.sha256(base.encode()).hexdigest()[:8]
    record, secret = seal(text, ttl=600)
    status, headers, out = fetch(base, "/api/s", "POST", json.dumps(record).encode(), api)
    if status != 201:
        problems.append(f"create: status {status}: {out[:100]!r}")
    else:
        check_headers("create", headers)
        rid = json.loads(out)["id"]
        token = json.dumps({"token": b64u(token_of(secret))}).encode()
        wrong = json.dumps({"token": b64u(b"\x01" * 32)}).encode()
        if fetch(base, f"/api/s/{rid}/open", "POST", wrong, api)[0] != 404:
            problems.append("open: a wrong token was not refused")
        status, headers, out = fetch(base, f"/api/s/{rid}/open", "POST", token, api)
        if status != 200:
            problems.append(f"open: status {status}")
        else:
            check_headers("open", headers)
            if unseal(json.loads(out), secret).decode() != text:
                problems.append("open: wrong plaintext")
            if fetch(base, f"/api/s/{rid}/open", "POST", token, api)[0] != 404:
                problems.append("open: could be read twice")

    # The largest record there can be, with a passphrase. The local server enforces neither the
    # database's limits nor the free plan's CPU limit, so this is the first place that can show them.
    largest = "x" * 65530
    record, secret = seal(largest, passphrase="check_live", ttl=600)
    status, headers, out = fetch(base, "/api/s", "POST", json.dumps(record).encode(), api)
    if status != 201:
        problems.append(f"largest record: create status {status}: {out[:100]!r}")
    else:
        rid = json.loads(out)["id"]
        token = json.dumps({"token": b64u(token_of(secret))}).encode()
        status, headers, out = fetch(base, f"/api/s/{rid}/open", "POST", token, api)
        if status != 200:
            problems.append(f"largest record: open status {status}")
        elif unseal(json.loads(out), secret, "check_live").decode() != largest:
            problems.append("largest record: wrong plaintext")

    html = fetch(base, "/")[2].decode(errors="replace")
    outside = [m for m in re.findall(r'(?:src|href)="([^"]+)"', html) if not m.startswith("/")]
    if outside:
        problems.append(f"page loads from elsewhere: {outside[:3]}")

    # The public site. It handles no secret, but what it serves is still only what is here.
    site_want = want_headers(SITE_PUBLIC / "_headers", least=4)
    for path, name in SITE_PAGES.items():
        status, headers, body = fetch(site, path)
        digests["site/" + name] = hashlib.sha256(body).hexdigest()
        if status != 200:
            problems.append(f"site {path}: status {status}")
        if body != (SITE_PUBLIC / name).read_bytes():
            problems.append(f"site {path}: served bytes differ from the repository")
        for header, value in site_want.items():
            if headers.get(header) != value:
                problems.append(f"site {path}: {header} is {headers.get(header)!r}")
        if "set-cookie" in headers:
            problems.append(f"site {path}: sets a cookie: {headers['set-cookie'][:60]}")
    problems += ["site /: " + p for p in preload_problems(fetch(site, "/")[1].get("strict-transport-security"))]
    problems += http_problems(base, ["/", f"/s/{probe}"])
    problems += http_problems(site, ["/", "/guides/"])
    status, _, body = fetch(site, "/no-such-page")
    if status != 404:
        problems.append(f"site /no-such-page: status {status}")
    if body != (SITE_PUBLIC / "404.html").read_bytes():
        problems.append("site /no-such-page: not the 404 page in the repository")

    for name, digest in digests.items():
        print(f"{digest}  {name}")
    print()
    for p in problems:
        print("PROBLEM", p)
    print(f"{base} {site}: {'OK' if not problems else str(len(problems)) + ' problems'}")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
