#!/usr/bin/env python3
"""deploy.py, with a fake wrangler: it shows which Cloudflare account it would act in, and stops before
anything is created unless that is exactly one account. No network: the domain check is replaced."""
from __future__ import annotations

import contextlib
import importlib.util
import io
import json
import os
import sys
import tempfile
from pathlib import Path

from common import ROOT, Results

spec = importlib.util.spec_from_file_location("deploy", ROOT / "web/tools/deploy.py")
deploy = importlib.util.module_from_spec(spec)
spec.loader.exec_module(deploy)

ONE = {"loggedIn": True, "authType": "OAuth Token", "email": "ops@example.test",
       "accounts": [{"id": "0123456789abcdef0123456789abcdef", "name": "APIキー便"}], "tokenPermissions": []}


def run(whoami_out: str, rc: int):
    """deploy.py --check against a wrangler that answers whoami with this, and fails anything else."""
    with tempfile.TemporaryDirectory() as tmp:
        fake = Path(tmp) / "wrangler"
        log = Path(tmp) / "calls"
        fake.write_text(
            f"#!{sys.executable}\n"
            "import sys\n"
            f"open({str(log)!r}, 'a').write(' '.join(sys.argv[1:]) + '\\n')\n"
            "if sys.argv[1:] == ['whoami', '--json']:\n"
            f"    sys.stdout.write({whoami_out!r})\n"
            f"    sys.exit({rc})\n"
            "sys.exit(99)\n", encoding="utf-8")
        fake.chmod(0o755)
        reached = []

        def no_network():
            reached.append(True)
            raise deploy.Stop("domain check reached")

        out, err = io.StringIO(), io.StringIO()
        old_env, old_argv, old_check = os.environ.get("APIKEYBIN_WRANGLER"), sys.argv, deploy.domain_is_on_cloudflare
        os.environ["APIKEYBIN_WRANGLER"] = str(fake)
        sys.argv, deploy.domain_is_on_cloudflare = ["deploy.py", "--check"], no_network
        try:
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                code = deploy.main()
        finally:
            sys.argv, deploy.domain_is_on_cloudflare = old_argv, old_check
            if old_env is None:
                os.environ.pop("APIKEYBIN_WRANGLER", None)
            else:
                os.environ["APIKEYBIN_WRANGLER"] = old_env
        calls = log.read_text().splitlines() if log.exists() else []
        return code, out.getvalue(), err.getvalue(), bool(reached), calls


def t_one_account_is_shown_and_the_check_goes_on():
    code, out, err, reached, calls = run(json.dumps(ONE), 0)
    assert "ログイン: ops@example.test" in out, out
    assert "アカウント: APIキー便（0123456789abcdef0123456789abcdef）" in out, out
    assert reached and code == 1 and "domain check reached" in err, (code, err)
    assert calls == ["whoami --json"], calls


def t_two_accounts_stop_before_anything_else():
    two = dict(ONE, accounts=ONE["accounts"] + [{"id": "f" * 32, "name": "another"}])
    code, out, err, reached, calls = run(json.dumps(two), 0)
    assert code == 1 and not reached, (code, reached)
    assert "2 個" in err and "入り直して" in err, err
    assert "アカウント: another" in out, out
    assert calls == ["whoami --json"], calls


def t_no_account_stops_too():
    code, out, err, reached, calls = run(json.dumps(dict(ONE, accounts=[])), 0)
    assert code == 1 and not reached and "0 個" in err, (code, reached, err)


def t_logged_out_stops_with_the_login_command():
    code, out, err, reached, calls = run('{"loggedIn":false}\n', 1)
    assert code == 1 and not reached, (code, reached)
    assert "ログインしていません" in err and "wrangler login" in err, err
    assert "ログイン:" not in out, out


def t_anything_unexpected_is_not_taken_for_a_login():
    for text, rc in [("Something went wrong", 0), ("", 0), ('{"loggedIn":"yes","accounts":[]}', 0), (json.dumps(ONE), 1)]:
        code, out, err, reached, calls = run(text, rc)
        assert code == 1 and not reached and "ログインしていません" in err, (text, rc, err)


TESTS = [v for k, v in sorted(globals().items()) if k.startswith("t_")]


def main():
    results = Results()
    for fn in TESTS:
        results.run(fn)
    return results.finish("deploy")


if __name__ == "__main__":
    raise SystemExit(main())
