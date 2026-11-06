#!/usr/bin/env python3
"""Puts both sites on Cloudflare. A person runs this, after `wrangler login`.

    python3 web/tools/deploy.py --check    looks, changes nothing
    python3 web/tools/deploy.py            database, schema, app.apikeybin.com, apikeybin.com, then check_live.py

Safe to run again: the schema only adds what is missing, and the database is created once.
Nothing here is a secret, and nothing here reads one.
"""
from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
WEB = ROOT / "web"
SITE = ROOT / "site"
CONFIG = WEB / "wrangler.jsonc"
PLACEHOLDER = "00000000-0000-0000-0000-000000000000"
DATABASE = "apikeybin"
DOMAIN = "apikeybin.com"
APP = "https://app.apikeybin.com"
PUBLIC = "https://apikeybin.com"
UUID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")
PYTHON = ROOT / "verify/web-threat/.venv/bin/python"


class Stop(Exception):
    """Says what to do next. Nothing after this point has been changed."""


def environment():
    env = dict(os.environ, WRANGLER_SEND_METRICS="false")
    node = os.environ.get("NODE_BIN") or "/opt/homebrew/opt/node@22/bin"
    if Path(node).exists():
        env["PATH"] = node + os.pathsep + env["PATH"]
    return env


def wrangler(*args, cwd=WEB, show=False):
    command = os.environ.get("APIKEYBIN_WRANGLER", str(WEB / "node_modules/.bin/wrangler"))
    result = subprocess.run([command, *args], cwd=cwd, env=environment(), capture_output=not show, text=True)
    return result


def logged_in():
    """Who wrangler acts as. Everything below creates things in this account, so it is shown, and it must be one."""
    r = wrangler("whoami", "--json")
    out = r.stdout or ""
    try:
        info = json.loads(out[out.index("{"):])
    except ValueError:
        info = {}
    if r.returncode != 0 or info.get("loggedIn") is not True:
        raise Stop(f"Cloudflare にログインしていません。先に実行してください:\n  ! cd {WEB} && PATH=/opt/homebrew/opt/node@22/bin:$PATH npx wrangler login")
    accounts = [a for a in info.get("accounts") or [] if isinstance(a, dict)]
    print(f"ログイン: {info.get('email') or '（メールは読めませんでした）'}")
    for a in accounts:
        print(f"  アカウント: {a.get('name')}（{a.get('id')}）")
    if len(accounts) != 1:
        raise Stop(f"このログインで使えるアカウントが {len(accounts)} 個あります。APIキー便の専用のアカウントだけで入り直してください（wrangler logout のあと wrangler login）。")


def domain_is_on_cloudflare():
    r = subprocess.run(["dig", "+short", "NS", DOMAIN, "@1.1.1.1"], capture_output=True, text=True)
    servers = r.stdout.split()
    if not any(s.rstrip(".").endswith("ns.cloudflare.com") for s in servers):
        raise Stop(f"{DOMAIN} はまだ Cloudflare のネームサーバーを指していません（今: {servers or 'なし'}）。ドメインを取った会社の画面で、ネームサーバーを Cloudflare が示す2つに変えてください。Cloudflare で Active になってから、もう一度実行してください。")
    print(f"ドメイン: {DOMAIN} は Cloudflare を指しています")


def existing_database():
    r = wrangler("d1", "list", "--json")
    if r.returncode != 0:
        raise Stop("データベースの一覧を読めませんでした:\n" + (r.stderr or r.stdout)[-400:])
    for row in json.loads(r.stdout[r.stdout.index("["):]):
        if row.get("name") == DATABASE:
            return row["uuid"]
    return None


def configured_database():
    found = re.findall(r'"database_id":\s*"([^"]+)"', CONFIG.read_text(encoding="utf-8"))
    if len(found) != 1:
        raise Stop(f"{CONFIG} に database_id が1つではありません: {found}")
    return found[0]


def write_database(uuid):
    if not UUID.fullmatch(uuid):
        raise Stop(f"データベースの ID の形が違います: {uuid!r}")
    text = CONFIG.read_text(encoding="utf-8")
    current = configured_database()
    if current not in (PLACEHOLDER, uuid):
        raise Stop(f"{CONFIG} の database_id（{current}）が、Cloudflare のもの（{uuid}）と違います。別のアカウントにログインしていませんか。")
    CONFIG.write_text(text.replace(current, uuid), encoding="utf-8")


def check_live():
    # A new custom domain takes a moment to get its certificate.
    for attempt in range(10):
        r = subprocess.run([str(PYTHON), str(ROOT / "verify/web-real/check_live.py"), APP, PUBLIC], cwd=ROOT / "verify/web-real", env=environment(), capture_output=True, text=True)
        if r.returncode == 0:
            print(r.stdout[-1500:])
            return
        if attempt < 9 and ("CERTIFICATE" in r.stdout + r.stderr or "resolve" in r.stdout + r.stderr or "URLError" in r.stdout + r.stderr):
            print("証明書かDNSの反映を待っています…", flush=True)
            time.sleep(30)
            continue
        print(r.stdout[-3000:], r.stderr[-1000:])
        raise Stop("配信物の確かめで問題が見つかりました。上の内容を返してください。")
    raise Stop("証明書かDNSの反映が終わりませんでした。しばらくしてから check_live.py を流してください。")


def main():
    only_look = "--check" in sys.argv[1:]
    try:
        logged_in()
        domain_is_on_cloudflare()
        uuid = existing_database()
        print(f"データベース: {uuid or 'まだありません'}")
        print(f"設定の database_id: {configured_database()}")
        if only_look:
            print("見ただけです。何も変えていません。")
            return 0
        if uuid is None:
            r = wrangler("d1", "create", DATABASE, "--location", "apac")
            if r.returncode != 0:
                raise Stop("データベースを作れませんでした:\n" + (r.stderr or r.stdout)[-400:])
            uuid = existing_database()
            if uuid is None:
                raise Stop("データベースを作ったはずが、一覧に出ません。")
            print(f"データベースを作りました: {uuid}")
        write_database(uuid)
        r = wrangler("d1", "execute", DATABASE, "--remote", "--file", "schema.sql", "--yes")
        if r.returncode != 0:
            raise Stop("表を作れませんでした:\n" + (r.stderr or r.stdout)[-400:])
        print("表: 済み")
        if wrangler("deploy", show=True).returncode != 0:
            raise Stop("app.apikeybin.com を出せませんでした。")
        if wrangler("deploy", cwd=SITE, show=True).returncode != 0:
            raise Stop("apikeybin.com を出せませんでした。")
        check_live()
        print("できました。")
        return 0
    except Stop as stop:
        print(f"\n止まりました: {stop}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
