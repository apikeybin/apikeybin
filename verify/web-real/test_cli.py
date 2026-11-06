#!/usr/bin/env python3
"""The CLI, as a real binary, against the real local server, with the browser and Python."""
from __future__ import annotations

import asyncio
import http.client
import http.server
import json
import os
import pty
import select
import stat
import subprocess
import sys
import tempfile
import termios
import threading
import time
from pathlib import Path

from playwright.async_api import async_playwright

from common import ROOT, Results, Server, b64u, frame, open_binary, parse_link, seal, unique_ip, unseal, unseal_named

BIN = ROOT / "target/debug/apikeybin"
TEXT = 'STRIPE_KEY=sk_live_CANARY$abc\nPW="pa$$word"\n日本語のメモ🔑\n'
PASS = "correct horse バッテリー"


def cli(*args, stdin: str | bytes | None = None, env=None, timeout=60):
    data = stdin.encode() if isinstance(stdin, str) else stdin
    return subprocess.run([str(BIN), *args], input=data, capture_output=True, timeout=timeout,
                          env={**os.environ, **(env or {})})


def clean(result) -> None:
    """Nothing secret on stderr, whatever happened."""
    err = result.stderr.decode(errors="replace")
    for needle in ["CANARY", "sk_live", "pa$$word", "correct horse"]:
        assert needle not in err, f"{needle} on stderr: {err}"


def tmpdir():
    return Path(tempfile.mkdtemp(prefix="apikeybin-cli-"))


def file_with(text) -> Path:
    path = tmpdir() / "secret.env"
    path.write_bytes(text.encode() if isinstance(text, str) else text)
    return path


def c_python_writes_cli_reads(s):
    _, _, link = s.create(TEXT)
    r = cli("open", link)
    clean(r)
    assert r.returncode == 0, r.stderr
    assert r.stdout.decode() == TEXT
    assert b"shell history" in r.stderr, "a link given as an argument must warn"


def c_a_link_from_stdin_is_not_in_the_arguments_and_gets_no_warning(s):
    _, _, link = s.create(TEXT)
    r = cli("open", stdin=link + "\n")
    clean(r)
    assert r.returncode == 0 and r.stdout.decode() == TEXT, r.stderr
    assert b"shell history" not in r.stderr


def c_cli_writes_python_reads(s):
    r = cli("link", str(file_with(TEXT)), "--server", f"http://127.0.0.1:{s.port}")
    clean(r)
    assert r.returncode == 0, r.stderr
    link = r.stdout.decode().strip()
    assert link.count("\n") == 0, "stdout must hold the link and nothing else"
    rid, version, secret = parse_link(link)
    assert version == "1"
    status, _, out = s.open(rid, secret)
    assert status == 200
    assert unseal(json.loads(out), secret).decode() == TEXT


def c_a_second_read_is_refused_with_its_own_exit_code(s):
    _, _, link = s.create(TEXT)
    assert cli("open", link).returncode == 0
    r = cli("open", link)
    clean(r)
    assert r.returncode == 20, (r.returncode, r.stderr)
    assert r.stdout == b""
    assert b"someone else may have" in r.stderr, "must say what this can mean"


def c_passphrase_both_ways_and_retries(s):
    # CLI writes, Python reads.
    r = cli("link", str(file_with(TEXT)), "--passphrase", "--server", f"http://127.0.0.1:{s.port}", stdin=PASS + "\n")
    clean(r)
    assert r.returncode == 0, r.stderr
    link = r.stdout.decode().strip()
    rid, version, secret = parse_link(link)
    assert version == "1p"
    assert unseal(json.loads(s.open(rid, secret)[2]), secret, PASS).decode() == TEXT
    # Python writes, CLI reads, after two wrong tries: the record is held in memory for retries.
    _, _, link = s.create(TEXT, passphrase=PASS)
    r = cli("open", stdin=f"{link}\nwrong\nalso wrong\n{PASS}\n")
    clean(r)
    assert r.returncode == 0, r.stderr
    assert r.stdout.decode() == TEXT
    # Out of tries.
    _, _, link = s.create(TEXT, passphrase=PASS)
    r = cli("open", stdin=f"{link}\nw1\nw2\nw3\n")
    clean(r)
    assert r.returncode == 21, (r.returncode, r.stderr)
    assert r.stdout == b""


def c_a_link_and_record_that_disagree_about_the_passphrase_stop_at_once(s):
    _, _, link = s.create(TEXT, passphrase=PASS)
    r = cli("open", link.replace("#1p.", "#1."), stdin=f"{PASS}\n")
    clean(r)
    assert r.returncode == 1 and r.stdout == b"", (r.returncode, r.stdout)
    assert b"disagree" in r.stderr


def c_a_tampered_record_prints_nothing(s):
    rid, secret, link = s.create(TEXT)
    ct = s.sql("SELECT ct FROM secrets WHERE id = ?", rid)[0][0]
    s.sql("UPDATE secrets SET ct = ? WHERE id = ?", ("B" if ct[0] == "A" else "A") + ct[1:], rid)
    r = cli("open", link)
    clean(r)
    assert r.returncode == 1 and r.stdout == b"", (r.returncode, r.stdout)


def c_writing_to_a_file(s):
    d = tmpdir()
    target = d / "out.env"
    _, _, link = s.create(TEXT)
    r = cli("open", link, "--out", str(target))
    clean(r)
    assert r.returncode == 0, r.stderr
    assert r.stdout == b"", "with --out nothing goes to stdout"
    assert target.read_text() == TEXT
    assert stat.S_IMODE(target.stat().st_mode) == 0o600, oct(target.stat().st_mode)


def c_an_existing_file_is_refused_before_the_read_is_spent(s):
    d = tmpdir()
    target = d / "out.env"
    target.write_text("keep me")
    rid, secret, link = s.create(TEXT)
    r = cli("open", link, "--out", str(target))
    assert r.returncode == 23, (r.returncode, r.stderr)
    assert target.read_text() == "keep me"
    assert s.sql("SELECT COUNT(*) FROM secrets WHERE id = ?", rid)[0][0] == 1, "the read was wasted"
    r = cli("open", link, "--out", str(target), "--force")
    assert r.returncode == 0, r.stderr
    assert target.read_text() == TEXT
    assert stat.S_IMODE(target.stat().st_mode) == 0o600
    assert [p.name for p in d.iterdir()] == ["out.env"], "a temporary file was left behind"


def c_a_symlink_is_not_followed(s):
    d = tmpdir()
    victim = d / "victim"
    victim.write_text("original")
    link_path = d / "out.env"
    link_path.symlink_to(victim)
    _, _, link = s.create(TEXT)
    r = cli("open", link, "--out", str(link_path))
    assert r.returncode == 23, (r.returncode, r.stderr)
    assert victim.read_text() == "original"
    r = cli("open", link, "--out", str(link_path), "--force")
    assert r.returncode == 0, r.stderr
    assert victim.read_text() == "original", "--force wrote through the symlink"
    assert not link_path.is_symlink() and link_path.read_text() == TEXT


def c_synced_folders_are_refused_before_the_read_is_spent(s):
    for name in ["Dropbox", "OneDrive - Company", "Google Drive", "Box Sync", "pCloud Drive"]:
        d = tmpdir() / name
        d.mkdir()
        rid, secret, link = s.create(TEXT)
        r = cli("open", link, "--out", str(d / "x.env"))
        assert r.returncode == 23, (name, r.returncode, r.stderr)
        assert s.sql("SELECT COUNT(*) FROM secrets WHERE id = ?", rid)[0][0] == 1, name
        r = cli("open", link, "--out", str(d / "x.env"), "--allow-synced")
        assert r.returncode == 0, (name, r.stderr)
    d = tmpdir() / "Library" / "Mobile Documents"
    d.mkdir(parents=True)
    _, _, link = s.create(TEXT)
    assert cli("open", link, "--out", str(d / "x.env")).returncode == 23
    # A name that merely contains the word is fine.
    d = tmpdir() / "notes-about-dropbox"
    d.mkdir()
    _, _, link = s.create(TEXT)
    assert cli("open", link, "--out", str(d / "x.env")).returncode == 0


def c_exec_injects_exactly_what_was_written(s):
    env_text = 'API_KEY=sk_live_CANARY$abc\nPW="pa$$word"\nEMPTY=\n'
    _, _, link = s.create(env_text)
    script = 'import os,json;print(json.dumps({k:os.environ.get(k) for k in ["API_KEY","PW","EMPTY","KEEP"]}))'
    r = cli("open", link, "--exec", "--", sys.executable, "-c", script, env={"KEEP": "from-parent"})
    clean(r)
    assert r.returncode == 0, r.stderr
    assert json.loads(r.stdout) == {"API_KEY": "sk_live_CANARY$abc", "PW": "pa$$word", "EMPTY": "", "KEEP": "from-parent"}
    assert b"API_KEY" in r.stderr and b"PW" in r.stderr, "the variable names must be shown"


def c_exec_passes_the_exit_code_through(s):
    _, _, link = s.create("A=1\n")
    r = cli("open", link, "--exec", "--", sys.executable, "-c", "raise SystemExit(7)")
    assert r.returncode == 7, r.returncode


def c_exec_refuses_variables_that_run_code(s):
    for name in ["NODE_OPTIONS", "PATH", "LD_PRELOAD", "DYLD_INSERT_LIBRARIES", "PYTHONSTARTUP", "BASH_ENV", "GIT_SSH_COMMAND"]:
        _, _, link = s.create(f"GOOD=1\n{name}=/tmp/evil\n")
        marker = tmpdir() / "ran"
        r = cli("open", link, "--exec", "--", "/usr/bin/touch", str(marker))
        clean(r)
        assert r.returncode == 22, (name, r.returncode, r.stderr)
        assert name.encode() in r.stderr
        assert not marker.exists(), f"{name}: the command ran"


def c_exec_allows_a_named_variable_only_when_asked(s):
    script = "import os;print(os.environ['NODE_OPTIONS'])"
    _, _, link = s.create("NODE_OPTIONS=--trace-warnings\n")
    r = cli("open", link, "--exec", "--allow-env", "NODE_OPTIONS", "--", sys.executable, "-c", script)
    assert r.returncode == 0, r.stderr
    assert r.stdout.decode().strip() == "--trace-warnings"
    _, _, link = s.create("NODE_OPTIONS=x\nPATH=/evil\n")
    r = cli("open", link, "--exec", "--allow-env", "NODE_OPTIONS", "--", sys.executable, "-c", script)
    assert r.returncode == 22, "only the named variable may pass"


def c_exec_needs_a_valid_env_file(s):
    _, _, link = s.create("this is not a dotenv sk_live_CANARY\n")
    r = cli("open", link, "--exec", "--", "/usr/bin/true")
    clean(r)
    assert r.returncode == 1, r.returncode
    assert b"line 1" in r.stderr


class Scripted(http.server.BaseHTTPRequestHandler):
    seen: list = []
    reply = (302, {"Location": "/stolen"}, b"")

    def log_message(self, *_):
        pass

    def do_GET(self):
        Scripted.seen.append((self.path, b""))
        self.send_response(200)
        self.send_header("Content-Length", "2")
        self.end_headers()
        self.wfile.write(b"{}")

    def do_POST(self):
        length = int(self.headers.get("Content-Length") or 0)
        Scripted.seen.append((self.path, self.rfile.read(length)))
        status, headers, body = Scripted.reply
        self.send_response(status)
        for k, v in headers.items():
            self.send_header(k, v)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def with_scripted(reply, fn):
    Scripted.seen = []
    Scripted.reply = reply
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Scripted)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        return fn(srv.server_address[1])
    finally:
        srv.shutdown()


SECRET_B = bytes(range(32))
LINK_PATH = "/s/AAAAAAAAAAAAAAAAAAAAAA#1." + b64u(SECRET_B)


def c_a_redirect_is_not_followed(s):
    def run(port):
        return cli("open", f"http://127.0.0.1:{port}{LINK_PATH}")
    r = with_scripted((302, {"Location": "/stolen"}, b""), run)
    assert r.returncode != 0 and r.stdout == b""
    assert [p for p, _ in Scripted.seen] == ["/api/s/AAAAAAAAAAAAAAAAAAAAAA/open"], Scripted.seen


def c_a_huge_or_strange_reply_is_refused(s):
    def run(port):
        return cli("open", f"http://127.0.0.1:{port}{LINK_PATH}", timeout=30)
    for body in [b"x" * (10 * 1024 * 1024), b"{}", b'{"v":1,"iv":"!","ct":"!","pw":false}', b"not json"]:
        r = with_scripted((200, {}, body), run)
        assert r.returncode == 1, (len(body), r.returncode)
        assert r.stdout == b""
        if len(body) > 1024 * 1024:
            assert b"unreadable" in r.stderr, "the size limit did not stop reading"


def c_a_file_travels_with_its_name_inside_the_encryption(s):
    d = tmpdir()
    path = d / ".env.local"
    path.write_text(TEXT)
    r = cli("link", str(path), "--server", f"http://127.0.0.1:{s.port}")
    assert r.returncode == 0, r.stderr
    rid, _, secret = parse_link(r.stdout.decode().strip())
    assert ".env.local" not in json.dumps(s.sql("SELECT * FROM secrets WHERE id = ?", rid))
    assert unseal_named(json.loads(s.open(rid, secret)[2]), secret) == (".env.local", TEXT.encode())
    r = cli("link", str(path), "--no-name", "--server", f"http://127.0.0.1:{s.port}")
    rid, _, secret = parse_link(r.stdout.decode().strip())
    assert unseal_named(json.loads(s.open(rid, secret)[2]), secret)[0] is None


def at_terminal(args, answers=(), cwd=None, timeout=45):
    """A real terminal for stdin, stdout and stderr, and a controlling terminal for hidden prompts.
    answers is a list of (what to wait for, what to type). Returns the exit code and everything the
    terminal received, which includes what it echoed."""
    pid, fd = pty.fork()
    if pid == 0:
        try:
            if cwd:
                os.chdir(cwd)
            os.execv(str(BIN), [str(BIN), *args])
        finally:
            os._exit(127)
    seen = b""
    start = 0
    pending = list(answers)
    deadline = time.time() + timeout
    while time.time() < deadline:
        ready, _, _ = select.select([fd], [], [], 0.2)
        if ready:
            try:
                data = os.read(fd, 65536)
            except OSError:
                break
            if not data:
                break
            seen += data
        if pending and pending[0][0] in seen[start:]:
            start = len(seen)
            # rpassword writes the prompt and then turns echo off, so a program that answers within
            # that moment gets its answer echoed (it happened here, about one run in six). A person
            # takes longer. Wait as a person would: a prompt with echo still on after this shows it.
            settle = time.time() + 0.5
            while time.time() < settle:
                try:
                    if not termios.tcgetattr(fd)[3] & termios.ECHO:
                        break
                except termios.error:
                    break
                time.sleep(0.01)
            os.write(fd, pending.pop(0)[1])
    os.close(fd)
    _, status = os.waitpid(pid, 0)
    assert not pending, ("never asked for", pending, seen[-300:])
    return os.waitstatus_to_exitcode(status), seen


def still_there(s, rid):
    return s.sql("SELECT COUNT(*) FROM secrets WHERE id = ?", rid)[0][0] == 1


def c_the_senders_name_is_shown_and_never_chooses_the_path(s):
    d = tmpdir()
    _, _, link = s.create(TEXT, name=".zshenv")
    r = subprocess.run([str(BIN), "open", link], cwd=d, capture_output=True, timeout=60)
    clean(r)
    assert r.returncode == 0, r.stderr
    assert r.stdout.decode() == TEXT
    assert b".zshenv" in r.stderr
    assert list(d.iterdir()) == [], "a file appeared under the sender's name"
    _, _, link = s.create(TEXT, name=".zshenv")
    r = subprocess.run([str(BIN), "open", link, "--out", "mine.env"], cwd=d, capture_output=True, timeout=60)
    assert r.returncode == 0, r.stderr
    assert b".zshenv" in r.stderr
    assert [p.name for p in d.iterdir()] == ["mine.env"]
    assert (d / "mine.env").read_text() == TEXT
    _, _, link = s.create(TEXT)
    r = cli("open", link)
    assert r.returncode == 0 and b"named this file" not in r.stderr
    assert cli("open", link, "--save").returncode == 2, "--save was taken out on purpose"


def c_a_hostile_name_goes_nowhere(s):
    d = tmpdir()
    for name in ["../escaped", "a/b", "..", "a\u202egpj.exe", "a\x1b[2Jb", "a.html.", "a.exe ", " a", "a\u00adb", "\ufeff.env"]:
        data = frame(name, TEXT.encode())
        padded = len(data).to_bytes(4, "big") + data
        padded += b"\0" * (1024 - len(padded))
        body, secret = seal(b"x", padded=padded)
        status, _, out = s.post("/api/s", body)
        assert status == 201
        link = f"http://127.0.0.1:{s.port}/s/{json.loads(out)['id']}#1.{b64u(secret)}"
        r = subprocess.run([str(BIN), "open", link], cwd=d, capture_output=True, timeout=60)
        assert r.returncode == 1, (name, r.returncode, r.stderr)
        assert r.stdout == b"", name
        assert b"\x1b" not in r.stderr, "an escape reached the terminal"
    assert list(d.iterdir()) == [] and not (d.parent / "escaped").exists()


def c_a_folder_that_cannot_be_written_is_refused_before_the_read_is_spent(s):
    d = tmpdir() / "locked"
    d.mkdir()
    rid, secret, link = s.create(TEXT)
    d.chmod(0o500)
    try:
        r = cli("open", link, "--out", str(d / "out.env"))
        assert r.returncode == 23, (r.returncode, r.stderr)
        assert still_there(s, rid), "the read was wasted"
    finally:
        d.chmod(0o700)
    assert list(d.iterdir()) == []
    # And the check leaves nothing behind where it can write.
    r = cli("open", link, "--out", str(d / "out.env"))
    assert r.returncode == 0, r.stderr
    assert [p.name for p in d.iterdir()] == ["out.env"], list(d.iterdir())


def c_a_folder_as_the_out_path_is_refused_before_the_read_is_spent(s):
    d = tmpdir()
    rid, secret, link = s.create(TEXT)
    for args in (["--out", str(d)], ["--out", str(d), "--force"]):
        r = cli("open", link, *args)
        assert r.returncode == 23, (args, r.returncode, r.stderr)
    assert still_there(s, rid), "the read was wasted"


def c_a_terminal_never_gets_the_senders_escape_sequences(s):
    evil = "KEY=1\x1b]52;c;ZXZpbA==\x07\x1b[2Aend\rNEXT=\u202eabc\r\nLAST=ok\n"
    _, _, link = s.create(evil)
    code, seen = at_terminal(["open", link])
    assert code == 0, (code, seen[-300:])
    for bad in [b"\x1b", b"\x07", "\u202e".encode()]:
        assert bad not in seen, (bad, seen)
    text = seen.decode()
    assert "\\u{1b}" in text and "\\u{202e}" in text, text
    assert "KEY=1" in text and "LAST=ok" in text, text
    assert "control this terminal" in text, text
    # Ordinary text is left alone and not remarked on.
    _, _, link = s.create(TEXT)
    code, seen = at_terminal(["open", link])
    assert code == 0 and "control this terminal" not in seen.decode(), seen[-300:]
    assert TEXT.splitlines()[0] in seen.decode()
    # A pipe still gets the exact bytes.
    _, _, link = s.create(evil)
    r = cli("open", link)
    assert r.returncode == 0 and r.stdout.decode() == evil


def c_the_passphrase_is_asked_for_before_the_read_is_spent(s):
    rid, secret, link = s.create(TEXT, passphrase=PASS)
    # Nothing to give, in a pipe.
    r = cli("open", link, stdin="")
    clean(r)
    assert r.returncode == 2, (r.returncode, r.stderr)
    assert b"has not been used" in r.stderr, r.stderr
    assert still_there(s, rid), "the read was spent with no passphrase"
    # Changing one's mind at the prompt.
    code, seen = at_terminal(["open", link], [(b"Passphrase: ", b"\x03")])
    assert code != 0, seen[-300:]
    assert still_there(s, rid), "the read was spent before the passphrase"
    # And it works at a terminal, without showing what was typed.
    code, seen = at_terminal(["open", link], [(b"Passphrase: ", PASS.encode() + b"\n")])
    assert code == 0, (code, seen[-300:])
    assert TEXT.splitlines()[0] in seen.decode() and PASS not in seen.decode(), seen[-300:]


def c_a_typing_mistake_in_a_new_passphrase_is_caught(s):
    path = file_with(TEXT)
    args = ["link", str(path), "--passphrase", "--server", f"http://127.0.0.1:{s.port}"]
    before = s.sql("SELECT COUNT(*) FROM secrets")[0][0]
    code, seen = at_terminal(args, [(b"Passphrase: ", b"one\n"), (b"Again: ", b"two\n")])
    assert code == 2, (code, seen[-300:])
    assert b"different" in seen
    assert s.sql("SELECT COUNT(*) FROM secrets")[0][0] == before, "a link was made anyway"
    code, seen = at_terminal(args, [(b"Passphrase: ", b"same\n"), (b"Again: ", b"same\n")])
    assert code == 0 and b"/s/" in seen, (code, seen[-300:])


def c_what_could_not_be_delivered_can_still_be_kept_at_a_terminal(s):
    d = tmpdir()
    content = "GOOD=1\nNODE_OPTIONS=--require ./evil\n"
    marker = d / "ran"
    run = ["--exec", "--", "/usr/bin/touch", str(marker)]
    # An answer that cannot be used is asked again, and nothing is overwritten.
    _, _, link = s.create(content)
    other = d / "other.txt"
    other.write_text("keep me")
    saved = d / "kept.env"
    code, seen = at_terminal(["open", link, *run], [
        (b"Save it to", str(other).encode() + b"\n"),
        (b"Save it to", str(saved).encode() + b"\n"),
    ])
    assert code == 22, (code, seen[-400:])
    assert not marker.exists(), "the command ran"
    assert other.read_text() == "keep me"
    assert saved.read_text() == content
    assert stat.S_IMODE(saved.stat().st_mode) == 0o600
    assert b"saved to" in seen
    # Enter discards.
    _, _, link = s.create(content)
    code, seen = at_terminal(["open", link, *run], [(b"Save it to", b"\n")])
    assert code == 22 and b"ask for a new one" in seen, (code, seen[-300:])
    # In a pipe nobody can answer, and it says what happened.
    _, _, link = s.create(content)
    r = cli("open", link, *run)
    clean(r)
    assert r.returncode == 22 and b"ask for a new one" in r.stderr, (r.returncode, r.stderr)
    # A value on several lines, which --exec cannot read.
    multi = 'KEY="line one\nline two"\n'
    _, _, link = s.create(multi)
    kept = d / "multi.env"
    code, seen = at_terminal(["open", link, "--exec", "--", "/usr/bin/true"], [(b"Save it to", str(kept).encode() + b"\n")])
    assert code == 1, (code, seen[-300:])
    assert kept.read_text() == multi


def c_a_missing_command_is_found_before_the_read_is_spent(s):
    rid, secret, link = s.create("A=1\n")
    plain = file_with("not a program")
    for command in ["no-such-command-at-all", "/no/such/path/cmd", str(tmpdir()), str(plain)]:
        r = cli("open", link, "--exec", "--", command)
        assert r.returncode == 2, (command, r.returncode, r.stderr)
        assert b"has not been used" in r.stderr, r.stderr
    assert still_there(s, rid), "the read was wasted"
    # A name found on the PATH is fine.
    r = cli("open", link, "--exec", "--", "true")
    assert r.returncode == 0, r.stderr


def c_a_command_without_exec_is_refused_before_anything_is_read(s):
    rid, secret, link = s.create(TEXT)
    r = cli("open", link, "--", "echo", "hi")
    assert r.returncode == 2 and r.stdout == b"", (r.returncode, r.stdout)
    assert still_there(s, rid)


BINARY = bytes(range(256)) * 3  # every byte value, so NUL and what is not UTF-8 are both in it


def c_a_binary_file_travels_byte_for_byte(s):
    d = tmpdir()
    path = d / "cert.p12"
    path.write_bytes(BINARY)
    server = f"http://127.0.0.1:{s.port}"
    # The CLI writes, Python reads.
    r = cli("link", str(path), "--server", server)
    assert r.returncode == 0, r.stderr
    rid, _, secret = parse_link(r.stdout.decode().strip())
    assert unseal_named(json.loads(s.open(rid, secret)[2]), secret) == ("cert.p12", BINARY)
    # Python writes, the CLI reads: a pipe and a file get the exact bytes.
    _, _, link = s.create(BINARY, name="cert.p12")
    r = cli("open", link)
    assert r.returncode == 0, r.stderr
    assert r.stdout == BINARY
    _, _, link = s.create(BINARY, name="cert.p12")
    out = d / "got.p12"
    r = cli("open", link, "--out", str(out))
    assert r.returncode == 0, r.stderr
    assert out.read_bytes() == BINARY
    assert stat.S_IMODE(out.stat().st_mode) == 0o600
    # Text with a NUL or in another encoding is sent the same way.
    for content in [b"abc\x00def", b"PASSWORD=caf\xe9\n"]:
        r = cli("link", str(file_with(content)), "--server", server)
        assert r.returncode == 0, r.stderr
        rid, _, secret = parse_link(r.stdout.decode().strip())
        assert unseal(json.loads(s.open(rid, secret)[2]), secret) == content


def c_the_largest_record_travels_both_ways(s):
    d = tmpdir()
    data = b"a" * (65536 - 4 - 2 - len("a.env"))
    path = d / "a.env"
    path.write_bytes(data)
    server = f"http://127.0.0.1:{s.port}"
    r = cli("link", str(path), "--server", server)
    assert r.returncode == 0, r.stderr
    rid, _, secret = parse_link(r.stdout.decode().strip())
    assert unseal_named(json.loads(s.open(rid, secret)[2]), secret) == ("a.env", data)
    # With a passphrase the reply is as big as a reply gets.
    _, _, link = s.create(data, name="a.env", passphrase="pw")
    r = cli("open", stdin=f"{link}\npw\n")
    assert r.returncode == 0, r.stderr
    assert r.stdout == data


def c_a_terminal_is_not_given_a_binary_file(s):
    d = tmpdir()
    # Each is wrong in one way only: a NUL in what is otherwise text, and bytes that are not UTF-8.
    for number, content in enumerate([b"abc\x00def", b"PASSWORD=caf\xe9\xe8\n", BINARY]):
        _, _, link = s.create(content, name="cert.p12")
        kept = d / f"kept{number}.p12"
        code, seen = at_terminal(["open", link], [(b"Save it to", str(kept).encode() + b"\n")])
        assert code == 1, (code, seen[-300:])
        assert b"not text" in seen, seen[-300:]
        assert kept.read_bytes() == content
        assert content not in seen and b"\x80\x81\x82" not in seen and b"\xe9\xe8" not in seen, "it reached the terminal"
    # Nobody to ask, with the link from a pipe and a terminal for the output: says what happened.
    _, _, link = s.create(BINARY)
    code, seen = at_terminal(["open", link], [(b"Save it to", b"\n")])
    assert code == 1 and b"ask for a new one" in seen, (code, seen[-300:])


def c_a_server_that_only_looks_local_is_refused(s):
    path = file_with(TEXT)
    for server in ["http://localhost.evil.example", "http://127.0.0.1.evil.example:8080", "https://user:pw@example.com", "https://example.com/path", "ftp://example.com"]:
        r = cli("link", str(path), "--server", server)
        assert r.returncode == 2, (server, r.returncode, r.stderr)


def c_a_name_the_cli_cannot_send_is_refused(s):
    d = tmpdir()
    path = d / ("a\u202egpj.exe")
    path.write_text("x")
    r = cli("link", str(path), "--server", f"http://127.0.0.1:{s.port}")
    assert r.returncode == 2, (r.returncode, r.stderr)
    assert b"--no-name" in r.stderr, "the way out should be named"
    r = cli("link", str(path), "--no-name", "--server", f"http://127.0.0.1:{s.port}")
    assert r.returncode == 0, r.stderr


def c_only_https_or_this_machine(s):
    secret = b64u(SECRET_B)
    r = cli("open", f"http://example.test/s/AAAAAAAAAAAAAAAAAAAAAA#1.{secret}", timeout=20)
    assert r.returncode == 2, r.returncode
    assert secret.encode() not in r.stderr
    r = cli("link", str(file_with("x")), "--server", "http://example.test")
    assert r.returncode == 2, r.returncode


def c_a_failed_replacement_leaves_no_copy_beside_the_file(s):
    # --force writes a temporary file and renames it. If the rename fails, that copy must not stay.
    # A locked file is how to make it fail, and the switch for that is on macOS only.
    if sys.platform != "darwin":
        return
    d = tmpdir()
    target = d / "x.env"
    target.write_text("old")
    subprocess.run(["chflags", "uchg", str(target)], check=True)
    try:
        _, _, link = s.create(TEXT)
        r = cli("open", link, "--out", str(target), "--force")
        clean(r)
        assert r.returncode == 23, (r.returncode, r.stderr)
        assert b"could not write the file" in r.stderr, r.stderr
        assert [p.name for p in d.iterdir()] == ["x.env"], list(d.iterdir())
        assert target.read_text() == "old"
    finally:
        subprocess.run(["chflags", "nouchg", str(target)], check=True)


def c_what_may_be_sent(s):
    server = f"http://127.0.0.1:{s.port}"
    assert cli("link", str(file_with(b"")), "--server", server).returncode == 2
    assert cli("link", str(file_with(b"a" * 65531)), "--server", server).returncode == 2
    # These three would also fail further down. The words show it was the check meant for them,
    # and they are what tells a person what to do.
    before = s.sql("SELECT COUNT(*) FROM secrets")[0][0]
    r = cli("link", str(file_with(b"a" * 65531)), "--server", server)
    assert b"the limit is 65530 bytes" in r.stderr, r.stderr
    r = cli("link", str(file_with("x")), "--passphrase", "--server", server, stdin="\n")
    assert r.returncode == 2 and b"the passphrase is empty" in r.stderr, (r.returncode, r.stderr)
    r = cli("link", "-", "--passphrase", "--server", server, stdin="from stdin\n")
    assert r.returncode == 2 and b"needs a file" in r.stderr, (r.returncode, r.stderr)
    assert s.sql("SELECT COUNT(*) FROM secrets")[0][0] == before, "a link was made anyway"
    assert cli("link", str(file_with("x")), "--ttl", "2d", "--server", server).returncode == 2
    assert cli("link", str(tmpdir() / "missing"), "--server", server).returncode == 1
    r = cli("link", "-", "--server", server, stdin="from stdin")
    assert r.returncode == 0, r.stderr
    rid, _, secret = parse_link(r.stdout.decode().strip())
    assert unseal(json.loads(s.open(rid, secret)[2]), secret) == b"from stdin"
    for ttl, seconds in [("10m", 600), ("1h", 3600), ("7d", 604800)]:
        r = cli("link", str(file_with("x")), "--ttl", ttl, "--server", server)
        rid, _, _ = parse_link(r.stdout.decode().strip())
        left = s.sql("SELECT expires_at - unixepoch() FROM secrets WHERE id = ?", rid)[0][0]
        assert seconds - 30 <= left <= seconds, (ttl, left)


def c_malformed_links_are_refused_without_spending_anything(s):
    rid, secret, link = s.create(TEXT)
    for bad in [link.split("#")[0], link + "x", link.replace("#1.", "#9."), "not a link", ""]:
        r = cli("open", bad)
        assert r.returncode == 2, (bad[:50], r.returncode)
        assert b64u(secret).encode() not in r.stderr
    assert s.open(rid, secret)[0] == 200


async def browser_legs(s) -> list[str]:
    failures = []
    async with async_playwright() as pw:
        browser = await pw.chromium.launch(headless=True)
        ctx = await browser.new_context()
        page = await ctx.new_page()
        # The CLI writes, the browser reads.
        r = cli("link", str(file_with(TEXT)), "--server", s.base)
        link = r.stdout.decode().strip()
        await page.goto(link)
        await page.click("#open")
        await page.locator("#output").wait_for(state="visible", timeout=15000)
        if await page.locator("#output").text_content() != TEXT:
            failures.append("browser read the CLI's link wrongly")
        # The browser writes, the CLI reads.
        await page.goto(s.base + "/")
        await page.fill("#text", TEXT)
        await page.fill("#passphrase", PASS)
        await page.click("#make")
        await page.locator("#result").wait_for(state="visible", timeout=15000)
        link = (await page.locator("#link").text_content()).replace("localhost", "127.0.0.1")
        r = cli("open", stdin=f"{link}\n{PASS}\n")
        if r.returncode != 0 or r.stdout.decode() != TEXT:
            failures.append(f"CLI read the browser's link wrongly: {r.returncode} {r.stderr[:200]}")
        # The largest size both ways.
        largest = b"a" * (65536 - 4 - 2 - len("a.env"))
        big = tmpdir() / "a.env"
        big.write_bytes(largest)
        r = cli("link", str(big), "--server", s.base)
        await page.goto(r.stdout.decode().strip())
        await page.click("#open")
        await page.locator("#output").wait_for(state="visible", timeout=15000)
        if await page.locator("#output").text_content() != largest.decode():
            failures.append("browser read the CLI's largest file wrongly")
        await page.goto(s.base + "/")
        await page.set_input_files("#file", str(big))
        await page.locator("#file-chip").wait_for(state="visible", timeout=15000)
        await page.click("#make")
        await page.locator("#result").wait_for(state="visible", timeout=15000)
        link = (await page.locator("#link").text_content()).replace("localhost", "127.0.0.1")
        r = cli("open", stdin=f"{link}\n")
        if r.returncode != 0 or r.stdout != largest:
            failures.append(f"CLI read the browser's largest file wrongly: {r.returncode} {r.stderr[:200]}")
        # A binary file both ways: the browser saves the CLI's, and the CLI reads the browser's.
        path = tmpdir() / "cert.p12"
        path.write_bytes(BINARY)
        r = cli("link", str(path), "--server", s.base)
        await page.goto(r.stdout.decode().strip())
        await page.click("#open")
        try:
            await page.locator("#output-binary").wait_for(state="visible", timeout=15000)
        except Exception:
            shown = await page.evaluate("[...document.querySelectorAll('[id^=state-]')].filter(e => !e.hidden).map(e => e.id)")
            failures.append(f"browser did not offer the CLI's binary file: on screen {shown}, url {page.url[:40]}")
            await browser.close()
            return failures
        async with page.expect_download() as info:
            await page.click("#save-output")
        download = await info.value
        if Path(await download.path()).read_bytes() != BINARY or download.suggested_filename != "cert.p12":
            failures.append(f"browser saved the CLI's binary file wrongly: {download.suggested_filename}")
        await page.route("**/app.js", open_binary)
        await page.goto(s.base + "/")
        await page.set_input_files("#file", str(path))
        await page.locator("#file-chip").wait_for(state="visible", timeout=15000)
        await page.click("#make")
        await page.locator("#result").wait_for(state="visible", timeout=15000)
        link = (await page.locator("#link").text_content()).replace("localhost", "127.0.0.1")
        r = cli("open", stdin=f"{link}\n")
        if r.returncode != 0 or r.stdout != BINARY:
            failures.append(f"CLI read the browser's binary file wrongly: {r.returncode} {r.stderr[:200]}")
        await browser.close()
    return failures


class FreshAddress(http.server.BaseHTTPRequestHandler):
    """The CLI does not say who it is, so all its calls would count against one rate limit, and this
    suite makes more of them in a minute than the limit allows. It was failing now and then for that
    reason alone. Here each call gets an address of its own. The limit itself is tested in test_api."""

    upstream = 0

    def log_message(self, *_):
        pass

    def forward(self):
        body = self.rfile.read(int(self.headers.get("Content-Length") or 0))
        headers = {k: v for k, v in self.headers.items() if k.lower() not in ("host", "connection")}
        if not any(k.lower() == "cf-connecting-ip" for k in headers):
            headers["CF-Connecting-IP"] = unique_ip()
        conn = http.client.HTTPConnection("127.0.0.1", self.upstream, timeout=30)
        conn.request(self.command, self.path, body=body, headers=headers)
        reply = conn.getresponse()
        data = reply.read()
        conn.close()
        self.send_response(reply.status)
        for key, value in reply.getheaders():
            if key.lower() not in ("connection", "content-length", "transfer-encoding", "date", "server"):
                self.send_header(key, value)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(data)

    do_GET = do_POST = do_HEAD = do_PUT = do_DELETE = do_OPTIONS = forward


def main():
    build = subprocess.run(["cargo", "build", "-p", "apikeybin-cli", "--quiet"], cwd=ROOT,
                           env={**os.environ, "PATH": f"{Path.home()}/.cargo/bin:{os.environ['PATH']}"},
                           capture_output=True, text=True)
    if build.returncode != 0:
        print(build.stderr[-1500:])
        return 2
    results = Results()
    with Server() as s:
        FreshAddress.upstream = s.port
        proxy = http.server.ThreadingHTTPServer(("127.0.0.1", 0), FreshAddress)
        threading.Thread(target=proxy.serve_forever, daemon=True).start()
        s.port = proxy.server_address[1]
        for fn in [v for k, v in sorted(globals().items()) if k.startswith("c_")]:
            results.run(fn, s)
        failures = asyncio.run(browser_legs(s))
        if failures:
            results.failed.extend(failures)
            print("FAIL browser_legs", failures)
        else:
            results.passed += 1
            print("ok   browser_legs")
    return results.finish("cli")


if __name__ == "__main__":
    raise SystemExit(main())
