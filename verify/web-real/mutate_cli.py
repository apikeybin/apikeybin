#!/usr/bin/env python3
"""Do the CLI tests notice when a check is removed? Restores the source afterwards."""
from __future__ import annotations

import os
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
SRC = HERE.parents[1] / "crates/apikeybin-cli/src"
MUTATIONS = [
    ("http.rs", "redirects are followed", ".max_redirects(0)", ".max_redirects(5)"),
    ("http.rs", "reply size not limited", ".limit(MAX_REPLY)", ".limit(1024 * 1024 * 1024)"),
    ("http.rs", "the largest record does not fit the reply limit", "const MAX_REPLY: u64 = 96 * 1024;", "const MAX_REPLY: u64 = 64 * 1024;"),
    ("http.rs", "any origin allowed", "if link::allowed_origin(origin) {", "if true {"),
    ("deliver.rs", "code execution variables let through", "if !blocked.is_empty() {", "if false {"),
    ("deliver.rs", "allow-env ignored", "let blocked = envfile::blocked_names(&vars, &allowed);", "let blocked = envfile::blocked_names(&vars, &[]);"),
    ("deliver.rs", "variable names not shown", 'eprintln!("Setting {} variables: {}", names.len(), names.join(", "));', "let _ = names;"),
    ("deliver.rs", "file open to everyone", "options.mode(0o600);", "options.mode(0o644);"),
    ("deliver.rs", "existing file overwritten", "options.write(true).create_new(true);", "options.write(true).create(true).truncate(true);"),
    ("deliver.rs", "existing file not checked first", "if !force && std::fs::symlink_metadata(&full).is_ok() {", "if false {"),
    ("deliver.rs", "synced folders allowed", "if !allow_synced && let Some(service) = synced_folder(&full) {", "if false && let Some(service) = synced_folder(&full) {"),
    ("deliver.rs", "force writes through a symlink", 'let result = create_exclusive(&temp, content).and_then(|()| std::fs::rename(&temp, &full));', 'let result = std::fs::write(&full, content);'),
    ("main.rs", "out path not checked before reading", "deliver::check_out_path(path, force, allow_synced)?;", "let _ = (path, force, allow_synced);"),
    ("main.rs", "argument warning removed", "Note: a link given as an argument stays in your shell history until it is used.", ""),
    ("deliver.rs", "the terminal gets the sender's bytes", "let bytes = if terminal { shown.as_bytes() } else { content };", "let _ = &shown; let bytes = content;"),
    ("deliver.rs", "a pipe gets changed bytes", "let bytes = if terminal { shown.as_bytes() } else { content };", "let bytes = shown.as_bytes();"),
    ("deliver.rs", "escaped text is not mentioned", "if terminal && changed {", "if false && changed {"),
    ("deliver.rs", "a failed delivery does not ask", "if !std::io::stdin().is_terminal() {\n        return Failure::new(exit, used);\n    }", "if true {\n        return Failure::new(exit, used);\n    }"),
    ("deliver.rs", "saving what failed overwrites", "write_file(Path::new(path), content, false, false)", "write_file(Path::new(path), content, true, true)"),
    ("main.rs", "a failed delivery says nothing of the link", "delivered.map_err(|failure| deliver::rescue(&opened.content, failure))", "delivered"),
    ("deliver.rs", "a folder as --out found only after the read", "if full.is_dir() {", "if false {"),
    ("deliver.rs", "a file that cannot run counts as a command", "m.is_file() && m.permissions().mode() & 0o111 != 0", "m.is_file()"),
    ("main.rs", "a missing command found only after the read", "deliver::check_program(program)?;", "let _ = program;"),
    ("main.rs", "the passphrase asked for after the read", "let passphrase = if parsed.needs_passphrase {", "let passphrase = if false {"),
    ("main.rs", "no passphrase still spends the read", "if given.is_empty() {", "if false {"),
    ("main.rs", "a new passphrase asked for once", 'secret_line("Again: ")?.as_str() != first.as_str()', "false"),
    ("main.rs", "a command without --exec accepted", '#[arg(last = true, value_name = "COMMAND", requires = "exec")]', '#[arg(last = true, value_name = "COMMAND")]'),
    ("main.rs", "the sender's name not shown", 'eprintln!("The sender named this file {name}.");', "let _ = name;"),
    ("deliver.rs", "unwritable folder found only after the read (--out)", 'check_writable(full.parent().unwrap_or(Path::new(".")))', "Ok(())"),
    ("deliver.rs", "the check leaves a file behind", "        .and_then(|()| std::fs::remove_file(&probe))\n", ""),
    ("main.rs", "file names not checked before sending", "&& !link::valid_name(name)", "&& false"),
    ("main.rs", "nothing to send goes through", 'if bytes.is_empty() {\n        return Err(Failure::new(code::USAGE, "nothing to send"));\n    }', ""),
    ("main.rs", "too large goes through", 'if bytes.len() > link::MAX_TEXT {\n        return Err(Failure::new(\n            code::USAGE,\n            format!("too large: the limit is {} bytes", link::MAX_TEXT),\n        ));\n    }', ""),
    ("main.rs", "an empty new passphrase accepted", 'if first.is_empty() {\n            return Err(Failure::new(code::USAGE, "the passphrase is empty"));\n        }', ""),
    ("main.rs", "stdin with a passphrase accepted", 'if ask_passphrase {\n            return Err(Failure::new(\n                code::USAGE,\n                "--passphrase needs a file, because stdin cannot carry both",\n            ));\n        }', ""),
    ("deliver.rs", "iCloud Drive not noticed", 'if in_library("mobile documents") {\n        return Some("iCloud Drive");\n    }', ""),
    ("deliver.rs", "cloud storage folders not noticed", 'if in_library("cloudstorage") {\n        return Some("a cloud storage folder");\n    }', ""),
    ("deliver.rs", "Dropbox not noticed", 'if has("dropbox") {\n        return Some("Dropbox");\n    }', ""),
    ("deliver.rs", "OneDrive not noticed", 'if has_prefix("onedrive") {\n        return Some("OneDrive");\n    }', ""),
    ("deliver.rs", "Google Drive not noticed", 'if has("google drive") || has("googledrive") {\n        return Some("Google Drive");\n    }', ""),
    ("deliver.rs", "Box and pCloud not noticed", 'if has("box sync") || has("pcloud drive") {\n        return Some("a cloud storage folder");\n    }', ""),
    ("deliver.rs", "line breaks escaped at the terminal", "if c == '\\n' || c == '\\t' {\n            shown.push(c);\n        } else if c == '\\r'", "if c == '\\r'"),
    ("deliver.rs", "a Windows line ending shown as a code", "} else if c == '\\r' && chars.peek() == Some(&'\\n') {\n            // A Windows line ending looks the same without it.\n        } else if text::is_forbidden(c)", "} else if text::is_forbidden(c)"),
    ("deliver.rs", "Enter does not end the question", 'if path.is_empty() {\n            break;\n        }\n        match write_file', "match write_file"),
    ("main.rs", "a secret prompt shows what is typed", "rpassword::prompt_password(prompt)", '{ eprint!("{prompt}"); let mut typed = String::new(); std::io::stdin().read_line(&mut typed).map(|_| typed.trim_end().to_owned()) }'),
    ("deliver.rs", "a failed write leaves the temporary file", "if result.is_err() {\n        let _ = std::fs::remove_file(&temp);\n    }", ""),
    ("deliver.rs", "a terminal is given a file with a NUL", "if terminal && (content.contains(&0) || std::str::from_utf8(content).is_err()) {", "if terminal && std::str::from_utf8(content).is_err() {"),
    ("deliver.rs", "a terminal is given bytes that are not text", "if terminal && (content.contains(&0) || std::str::from_utf8(content).is_err()) {", "if terminal && content.contains(&0) {"),
    ("main.rs", "only one passphrase try", "for attempt in 1..=3 {", "for attempt in 3..=3 {"),
    ("main.rs", "record flag not compared", "if record.pw != parsed.needs_passphrase {", "if false {"),
]


def suite(env):
    unit = subprocess.run(["cargo", "test", "-p", "apikeybin-cli", "--quiet"], cwd=HERE.parents[1], env=env, capture_output=True, text=True)
    if unit.returncode != 0:
        out = unit.stdout + unit.stderr
        code = 2 if "could not compile" in out else 1
        failing = [l.split()[1] for l in out.splitlines() if l.startswith("---- ")]
        return subprocess.CompletedProcess([], code, "".join(f"FAIL {n}: unit\n" for n in failing), "")
    return subprocess.run([sys.executable, str(HERE / "test_cli.py")], cwd=HERE, env=env, capture_output=True, text=True, timeout=300)


def main():
    only = sys.argv[1] if len(sys.argv) > 1 else ""
    env = dict(os.environ, PATH=f"{Path.home()}/.cargo/bin:{os.environ['PATH']}", APIKEYBIN_PORT="8794", PYTHONDONTWRITEBYTECODE="1", RUSTFLAGS="-A warnings")
    results = []
    base = suite(env)
    print("baseline:", "ok" if base.returncode == 0 else "FAIL", flush=True)
    if base.returncode != 0:
        print(base.stdout[-1500:])
        return 2
    for fname, name, old, new in MUTATIONS:
        if only and only not in name:
            continue
        path = SRC / fname
        original = path.read_text(encoding="utf-8")
        if old not in original:
            results.append((name, "NOT_APPLIED"))
            print(f"NOT_APPLIED {name}", flush=True)
            continue
        t0 = time.time()
        try:
            path.write_text(original.replace(old, new, 1), encoding="utf-8")
            r = suite(env)
        finally:
            path.write_text(original, encoding="utf-8")
        failing = [l.split()[1].rstrip(":") for l in r.stdout.splitlines() if l.startswith("FAIL ")]
        # Only a test that names the failure counts. A suite that did not start says nothing.
        status = "caught" if failing else ("SURVIVED" if r.returncode == 0 else "NO_RESULT")
        if r.returncode == 2:
            status = "NO_COMPILE"
        results.append((name, status))
        print(f"{status:11} {name} ({time.time()-t0:.0f}s) {failing[:2]}", flush=True)
    # The results above stand only if the suite still passes once the file is back.
    after = suite(env)
    print("afterwards:", "ok" if after.returncode == 0 else "FAIL", flush=True)
    if after.returncode != 0:
        print(after.stdout[-1500:])
        print("VOID: the suite no longer passes without a mutation", flush=True)
        return 2
    bad = [n for n, s in results if s != "caught"]
    print(f"\n{len(results) - len(bad)}/{len(results)} caught; not caught: {bad}\nDONE", flush=True)
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
