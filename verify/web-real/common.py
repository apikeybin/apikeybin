"""Shared by the web tests: a real local server, and a second implementation of the link format.

The second implementation is the point. It is written from the format in docs/SPEC.md using
Python's standard library and `cryptography`, and shares no code with web/public/app.js. If the
browser and this agree in both directions, neither can be quietly wrong on its own.
"""
from __future__ import annotations

import base64
import glob
import hashlib
import hmac
import http.client
import json
import os
import secrets
import shutil
import signal
import socket
import sqlite3
import subprocess
import tempfile
import time
import unicodedata
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

ROOT = Path(__file__).resolve().parents[2]
WEB = Path(os.environ.get("APIKEYBIN_WEB") or ROOT / "web")
AAD = b"apikeybin/link/1"
BUCKETS = [1024, 4096, 16384, 65536]
PBKDF2_ITERATIONS = 600_000


# Sending a file that is not text is closed on the real page for now. Tests of what it does once it is
# open serve the page with the switch turned, and one test holds the shipped value.
BINARY_SWITCH = "const BINARY_OPEN = false;"


async def open_binary(route):
    response = await route.fetch()
    text = await response.text()
    assert BINARY_SWITCH in text
    await route.fulfill(response=response, body=text.replace(BINARY_SWITCH, "const BINARY_OPEN = true;"))


def b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def unb64u(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def hkdf(ikm: bytes, info: bytes) -> bytes:
    prk = hmac.new(b"", ikm, hashlib.sha256).digest()
    return hmac.new(prk, info + b"\x01", hashlib.sha256).digest()


def token_of(secret: bytes) -> bytes:
    return hkdf(secret, b"apikeybin/link/1/token")


def key_of(secret: bytes, passphrase: str | None, salt: bytes | None) -> bytes:
    if passphrase is None:
        return hkdf(secret, b"apikeybin/link/1/key")
    stretched = hashlib.pbkdf2_hmac(
        "sha256", unicodedata.normalize("NFC", passphrase).encode(), salt, PBKDF2_ITERATIONS, 32
    )
    return hkdf(secret + stretched, b"apikeybin/link/1/key+pw")


def frame(name: str | None, content: bytes) -> bytes:
    raw = name.encode() if name is not None else b""
    return len(raw).to_bytes(2, "big") + raw + content


def unframe(body: bytes) -> tuple[str | None, bytes]:
    n = int.from_bytes(body[:2], "big")
    return (body[2:2 + n].decode() if n else None), body[2 + n:]


def pad(data: bytes) -> bytes:
    bucket = next(b for b in BUCKETS if b >= len(data) + 4)
    return len(data).to_bytes(4, "big") + data + b"\0" * (bucket - 4 - len(data))


def pad_content(content: bytes, name: str | None = None) -> bytes:
    return pad(frame(name, content))


def unpad(padded: bytes) -> bytes:
    assert len(padded) in BUCKETS
    n = int.from_bytes(padded[:4], "big")
    assert n <= len(padded) - 4
    assert not any(padded[4 + n :])
    return padded[4:4 + n]


def seal(text: str | bytes, passphrase: str | None = None, ttl: int = 86400, padded: bytes | None = None, name: str | None = None):
    """A create request the way a correct client builds it. Returns (body, secret)."""
    data = text.encode() if isinstance(text, str) else text
    secret = secrets.token_bytes(32)
    iv = secrets.token_bytes(12)
    salt = secrets.token_bytes(16) if passphrase is not None else None
    key = key_of(secret, passphrase, salt)
    ct = AESGCM(key).encrypt(iv, padded if padded is not None else pad_content(data, name), AAD)
    body = {
        "v": 1,
        "iv": b64u(iv),
        "ct": b64u(ct),
        "token_hash": b64u(hashlib.sha256(token_of(secret)).digest()),
        "ttl": ttl,
        "pw": passphrase is not None,
    }
    if salt is not None:
        body["salt"] = b64u(salt)
    return body, secret


def unseal_named(record: dict, secret: bytes, passphrase: str | None = None) -> tuple[str | None, bytes]:
    salt = unb64u(record["salt"]) if record.get("salt") else None
    key = key_of(secret, passphrase, salt)
    return unframe(unpad(AESGCM(key).decrypt(unb64u(record["iv"]), unb64u(record["ct"]), AAD)))


def unseal(record: dict, secret: bytes, passphrase: str | None = None) -> bytes:
    return unseal_named(record, secret, passphrase)[1]


def parse_link(link: str):
    head, frag = link.split("#", 1)
    version, secret = frag.split(".", 1)
    return head.rsplit("/", 1)[-1], version, unb64u(secret)


def unique_ip() -> str:
    return f"10.{secrets.randbelow(255)}.{secrets.randbelow(255)}.{secrets.randbelow(255)}"


API_HEADERS = {"Content-Type": "application/json", "X-Apikeybin": "1"}


def port_in_use(port: int) -> bool:
    # Binding, not connecting: a connection can also fail while the port is held, when its queue is full.
    with socket.socket() as probe:
        probe.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            probe.bind(("127.0.0.1", port))
        except OSError:
            return True
    return False


class Server:
    """wrangler dev on a fresh database. Local only: nothing here contacts Cloudflare."""

    def __init__(self, port: int | None = None, cwd: Path | None = None):
        self.port = port or int(os.environ.get("APIKEYBIN_PORT") or 8791)
        self.cwd = cwd or WEB
        self.state = tempfile.mkdtemp(prefix="apikeybin-state-")
        self.proc = None
        self.env = dict(os.environ, WRANGLER_SEND_METRICS="false", NO_D1_WARNING="true", CI="1", FORCE_COLOR="0")
        if os.environ.get("NODE_BIN"):
            self.env["PATH"] = os.environ["NODE_BIN"] + ":" + self.env["PATH"]

    def _npx(self, *args, **kw):
        return subprocess.run(["npx", "wrangler", *args], cwd=self.cwd, env=self.env, capture_output=True, text=True, **kw)

    def start(self):
        # Whatever answers on this port would be taken for the server started below, and the results
        # would be about that one instead.
        if port_in_use(self.port):
            raise RuntimeError(f"port {self.port} is already in use")
        r = self._npx("d1", "execute", "apikeybin", "--local", "--persist-to", self.state, "--file", "schema.sql")
        if r.returncode != 0:
            raise RuntimeError("schema failed: " + (r.stdout + r.stderr)[-800:])
        self.log = open(os.path.join(self.state, "dev.log"), "w")
        self.proc = subprocess.Popen(
            ["npx", "wrangler", "dev", "--ip", "127.0.0.1", "--port", str(self.port), "--persist-to", self.state,
             "--test-scheduled", "--show-interactive-dev-session=false"],
            cwd=self.cwd, env=self.env, stdout=self.log, stderr=subprocess.STDOUT, start_new_session=True,
        )
        # It has a session of its own, so whoever ends this process from outside has to end it as well.
        if os.environ.get("APIKEYBIN_SERVER_PIDS"):
            Path(os.environ["APIKEYBIN_SERVER_PIDS"]).write_text(f"{self.proc.pid}\n", encoding="utf-8")
        deadline = time.monotonic() + 60
        while time.monotonic() < deadline:
            if self.proc.poll() is not None:
                raise RuntimeError("wrangler exited: " + self.logs()[-800:])
            try:
                if self.call("GET", "/robots.txt")[0] == 200:
                    return self
            except OSError:
                pass
            time.sleep(0.2)
        raise RuntimeError("wrangler did not come up: " + self.logs()[-800:])

    def logs(self) -> str:
        self.log.flush()
        return Path(self.state, "dev.log").read_text(errors="replace")

    def stop(self):
        if self.proc and self.proc.poll() is None:
            os.killpg(self.proc.pid, signal.SIGTERM)
            try:
                self.proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                os.killpg(self.proc.pid, signal.SIGKILL)
        shutil.rmtree(self.state, ignore_errors=True)

    def __enter__(self):
        return self.start()

    def __exit__(self, *exc):
        self.stop()

    @property
    def base(self) -> str:
        return f"http://localhost:{self.port}"

    def call(self, method, path, headers=None, body=None, chunked=False):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=30)
        try:
            if chunked:
                conn.request(method, path, body=body, headers=headers or {}, encode_chunked=True)
            else:
                conn.request(method, path, body=body, headers=headers or {})
            r = conn.getresponse()
            return r.status, {k.lower(): v for k, v in r.getheaders()}, r.read()
        finally:
            conn.close()

    def post(self, path, obj, ip=None, extra=None):
        headers = {**API_HEADERS, "CF-Connecting-IP": ip or unique_ip(), **(extra or {})}
        return self.call("POST", path, headers, json.dumps(obj).encode())

    def create(self, text="hello", passphrase=None, ttl=86400, name=None):
        body, secret = seal(text, passphrase, ttl, name=name)
        status, _, out = self.post("/api/s", body)
        assert status == 201, (status, out)
        rid = json.loads(out)["id"]
        version = "1p" if passphrase is not None else "1"
        return rid, secret, f"{self.base}/s/{rid}#{version}.{b64u(secret)}"

    def open(self, rid, secret):
        return self.post(f"/api/s/{rid}/open", {"token": b64u(token_of(secret))})

    # The database itself, read and written directly, the way a thief would.
    def db_path(self) -> str:
        paths = [p for p in glob.glob(self.state + "/v3/d1/**/*.sqlite", recursive=True) if "metadata" not in p]
        assert len(paths) == 1, paths
        return paths[0]

    def sql(self, statement, *params):
        conn = sqlite3.connect(self.db_path(), timeout=10)
        try:
            rows = conn.execute(statement, params).fetchall()
            conn.commit()
            return rows
        finally:
            conn.close()


class Results:
    def __init__(self):
        self.passed = 0
        self.failed: list[str] = []

    def run(self, fn, *args):
        name = fn.__name__
        try:
            fn(*args)
            self.passed += 1
            print(f"ok   {name}", flush=True)
        except Exception as e:  # noqa: BLE001
            self.failed.append(name)
            print(f"FAIL {name}: {type(e).__name__}: {str(e)[:300]}", flush=True)

    def finish(self, label) -> int:
        print(f"\n{label}: {self.passed} passed, {len(self.failed)} failed {self.failed}", flush=True)
        return 1 if self.failed else 0
