#!/usr/bin/env python3
"""The server, over real HTTP, on a real local D1. Run through run.py."""
from __future__ import annotations

import hashlib
import json
import re
import unicodedata
import threading
from concurrent.futures import ThreadPoolExecutor

from common import API_HEADERS, BINARY_SWITCH, ROOT, Results, Server, WEB, b64u, seal, token_of, unb64u, unique_ip, unseal

CANARY = "sk_live_CANARY_0123456789"
VALID_ID_UNUSED = "A" * 22
SITE_LINKS = {"https://apikeybin.com/", "https://apikeybin.com/privacy", "https://apikeybin.com/terms", "https://apikeybin.com/report"}


def count(s):
    return s.sql("SELECT COUNT(*) FROM secrets")[0][0]


def t_round_trip_with_the_python_implementation(s):
    rid, secret, _ = s.create(CANARY)
    status, headers, out = s.open(rid, secret)
    assert status == 200, status
    record = json.loads(out)
    assert set(record) == {"v", "iv", "ct", "pw"}, record.keys()
    assert unseal(record, secret) == CANARY.encode()
    assert headers["cache-control"] == "no-store"


def t_round_trip_with_a_passphrase(s):
    rid, secret, _ = s.create(CANARY, passphrase="correct horse")
    status, _, out = s.open(rid, secret)
    assert status == 200, status
    record = json.loads(out)
    assert set(record) == {"v", "iv", "ct", "pw", "salt"}, record.keys()
    assert record["pw"] is True
    assert unseal(record, secret, "correct horse") == CANARY.encode()


def t_reading_takes_a_token_and_nothing_else(s):
    rid, secret, _ = s.create()
    token = b64u(token_of(secret))
    for body in [{"token": token, "extra": 1}, {"token": "+" * (len(token) - 1) + "A"}]:
        status = s.post(f"/api/s/{rid}/open", body)[0]
        assert status == 400, (status, list(body))
    for raw in [b"", b"not json", b"[]", b"\xff\xfe"]:
        status = s.call("POST", f"/api/s/{rid}/open", {**API_HEADERS, "CF-Connecting-IP": unique_ip()}, raw)[0]
        assert status == 400, (status, raw)
    # None of those used it up.
    assert s.open(rid, secret)[0] == 200


def t_a_second_open_finds_nothing(s):
    rid, secret, _ = s.create()
    assert s.open(rid, secret)[0] == 200
    status, _, out = s.open(rid, secret)
    assert status == 404 and json.loads(out) == {"error": "gone"}, (status, out)
    assert s.sql("SELECT COUNT(*) FROM secrets WHERE id = ?", rid)[0][0] == 0


def t_knowing_the_id_is_not_enough_to_read_or_burn(s):
    rid, secret, _ = s.create()
    wrong = s.post(f"/api/s/{rid}/open", {"token": b64u(b"\x01" * 32)})
    assert wrong[0] == 404, wrong[0]
    assert s.post(f"/api/s/{rid}/open", {})[0] == 400
    assert s.post(f"/api/s/{rid}/open", {"token": "short"})[0] == 400
    # The secret's raw value is not the token either.
    assert s.post(f"/api/s/{rid}/open", {"token": b64u(secret)})[0] == 404
    # Still there for the person who has the link.
    assert s.open(rid, secret)[0] == 200


def t_every_kind_of_miss_gives_the_same_answer(s):
    rid, secret, _ = s.create()
    s.open(rid, secret)
    expired, esecret, _ = s.create()
    s.sql("UPDATE secrets SET expires_at = 1 WHERE id = ?", expired)
    token = {"token": b64u(token_of(b"\x02" * 32))}
    answers = [
        s.post(f"/api/s/{rid}/open", {"token": b64u(token_of(secret))}),  # already opened
        s.post(f"/api/s/{expired}/open", {"token": b64u(token_of(esecret))}),  # expired
        s.post(f"/api/s/{VALID_ID_UNUSED}/open", token),  # never existed
        s.post(f"/api/s/not-a-valid-id/open", token),  # malformed id
        s.post(f"/api/s/not-a-valid-id/open", {}),  # malformed id, and nothing else right either
    ]
    assert {(a[0], a[2]) for a in answers} == {(404, b'{"error":"gone"}')}, answers


def t_expired_records_cannot_be_opened_and_are_purged(s):
    rid, secret, _ = s.create()
    keep, keep_secret, _ = s.create()
    s.sql("UPDATE secrets SET expires_at = 1 WHERE id = ?", rid)
    assert s.open(rid, secret)[0] == 404
    assert s.sql("SELECT COUNT(*) FROM secrets WHERE id = ?", rid)[0][0] == 1, "not deleted by a failed open"
    status = s.call("GET", "/__scheduled?cron=*/30+*+*+*+*")[0]
    assert status == 200, status
    assert s.sql("SELECT COUNT(*) FROM secrets WHERE id = ?", rid)[0][0] == 0
    assert s.sql("SELECT COUNT(*) FROM secrets WHERE id = ?", keep)[0][0] == 1
    assert s.open(keep, keep_secret)[0] == 200


def t_only_correctly_padded_ciphertext_is_stored(s):
    good, _ = seal("x")
    before = count(s)
    def with_ct_len(n):
        return {**good, "ct": b64u(b"\0" * n)}
    for n in [0, 1, 1024, 1039, 1041, 4096, 8208, 16400 + 1, 65551, 65553, 262160]:
        status = s.post("/api/s", with_ct_len(n))[0]
        assert status in (400, 413), (n, status)
    assert count(s) == before
    for bucket in [1024, 4096, 16384, 65536]:
        assert s.post("/api/s", with_ct_len(bucket + 16))[0] == 201, bucket


def t_malformed_create_requests_change_nothing(s):
    good, _ = seal("x")
    before = count(s)
    cases = {
        "unknown field": {**good, "text": CANARY},
        "wrong version": {**good, "v": 2},
        "ttl not offered": {**good, "ttl": 1},
        "ttl too long": {**good, "ttl": 2592000},
        "ttl text": {**good, "ttl": "86400"},
        "pw not boolean": {**good, "pw": 1},
        # With a salt, so the rule about salts has nothing to say: only the type is wrong.
        "pw a number, with a salt": {**good, "pw": 1, "salt": b64u(b"\0" * 16)},
        "pw a word, with a salt": {**good, "pw": "true", "salt": b64u(b"\0" * 16)},
        "pw zero": {**good, "pw": 0},
        "pw missing": {k: v for k, v in good.items() if k != "pw"},
        "pw without salt": {**good, "pw": True},
        "salt without pw": {**good, "salt": b64u(b"\0" * 16)},
        "salt wrong size": {**good, "pw": True, "salt": b64u(b"\0" * 8)},
        "iv wrong size": {**good, "iv": b64u(b"\0" * 8)},
        "iv not canonical": {**good, "iv": good["iv"] + "A"},
        "token hash wrong size": {**good, "token_hash": b64u(b"\0" * 16)},
        "ct the wrong length and not base64url": {**good, "ct": "+" * 1388},
        # The right length and a last character that is canonical: only the alphabet is wrong.
        "ct not base64url": {**good, "ct": "+" * (len(good["ct"]) - 1) + "A"},
        "iv not base64url": {**good, "iv": "+" * (len(good["iv"]) - 1) + "A"},
        "token hash not base64url": {**good, "token_hash": "+" * (len(good["token_hash"]) - 1) + "A"},
        "salt not base64url": {**good, "pw": True, "salt": "+" * 21 + "A"},
        "ct missing": {k: v for k, v in good.items() if k != "ct"},
        "iv missing": {k: v for k, v in good.items() if k != "iv"},
    }
    for name, body in cases.items():
        status, _, out = s.post("/api/s", body)
        assert status == 400, (name, status, out)
        assert CANARY.encode() not in out, f"{name}: echoed input"
    for raw in [b"", b"not json", b"[]", b"null", b"1", b'"x"', b"\xff\xfe"]:
        status = s.call("POST", "/api/s", {**API_HEADERS, "CF-Connecting-IP": unique_ip()}, raw)[0]
        assert status == 400, (raw, status)
    assert count(s) == before


def t_non_canonical_base64_is_refused(s):
    # A 16-byte salt leaves 4 unused bits in its last character. Setting one gives a second
    # spelling of the same bytes, which must not be accepted.
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
    good, _ = seal("x", passphrase="p")
    salt = good["salt"]
    tampered = salt[:-1] + alphabet[alphabet.index(salt[-1]) | 1]
    assert tampered != salt and unb64u(tampered) == unb64u(salt), "the fixture is not a second spelling"
    assert s.post("/api/s", {**good, "salt": tampered})[0] == 400
    assert s.post("/api/s", good)[0] == 201, "control: the canonical spelling is accepted"


def t_oversized_bodies_are_refused(s):
    headers = {**API_HEADERS, "CF-Connecting-IP": unique_ip()}
    big = b'{"v":1,"x":"' + b"a" * (100 * 1024) + b'"}'
    assert s.call("POST", "/api/s", headers, big)[0] == 413
    def chunks():
        for _ in range(100):
            yield b"a" * 1024
    assert s.call("POST", "/api/s", dict(headers), chunks(), chunked=True)[0] == 413


def t_requests_from_other_sites_are_refused(s):
    body, secret = seal("x")
    for site in ["cross-site", "same-site", "none"]:
        assert s.post("/api/s", body, extra={"Sec-Fetch-Site": site})[0] == 403, site
    rid, secret, _ = s.create()
    token = {"token": b64u(token_of(secret))}
    for site in ["cross-site", "same-site", "none"]:
        assert s.post(f"/api/s/{rid}/open", token, extra={"Sec-Fetch-Site": site})[0] == 403, site
    assert s.post(f"/api/s/{rid}/open", token, extra={"Sec-Fetch-Site": "same-origin"})[0] == 200


def t_the_custom_header_and_content_type_are_required(s):
    rid, secret, _ = s.create()
    raw = json.dumps({"token": b64u(token_of(secret))}).encode()
    ip = {"CF-Connecting-IP": unique_ip()}
    assert s.call("POST", f"/api/s/{rid}/open", {"Content-Type": "application/json", **ip}, raw)[0] == 403
    assert s.call("POST", f"/api/s/{rid}/open", {"X-Apikeybin": "1", "Content-Type": "text/plain", **ip}, raw)[0] == 415
    assert s.call("POST", f"/api/s/{rid}/open", {"X-Apikeybin": "1", **ip}, raw)[0] == 415
    assert s.open(rid, secret)[0] == 200, "refused requests must not have consumed it"


def t_wrong_methods_are_refused(s):
    assert s.call("GET", "/api/s")[0] == 405
    assert s.call("DELETE", "/api/s")[0] == 405
    assert s.call("GET", f"/api/s/{VALID_ID_UNUSED}/open")[0] == 405
    assert s.call("POST", f"/s/{VALID_ID_UNUSED}")[0] == 405
    assert s.call("GET", "/api/other")[0] == 404
    assert s.call("OPTIONS", "/api/s")[0] == 405


def expected_headers():
    src = (WEB / "worker/index.js").read_text()
    block = src[src.index("const SECURITY_HEADERS = {") :]
    block = block[: block.index("};")]
    out = {}
    for m in re.finditer(r"^\s*'([\w-]+)':\s*((?:\s*(?:'[^']*'|\"[^\"]*\")\s*\+?)+),?\s*$", block, re.M):
        parts = re.findall(r"'([^']*)'|\"([^\"]*)\"", m.group(2))
        out[m.group(1).lower()] = "".join(a or b for a, b in parts)
    assert len(out) >= 10, f"could not parse the worker's header table: {list(out)}"
    return out


def t_static_and_worker_headers_are_the_same_and_strict(s):
    want = expected_headers()
    assert "default-src 'none'" in want["content-security-policy"]
    assert "unsafe" not in want["content-security-policy"]
    assert want["referrer-policy"] == "no-referrer"
    assert want["cross-origin-opener-policy"] == "same-origin"
    rid, secret, _ = s.create()
    paths = ["/", "/app.js", "/app.css", "/favicon.svg", "/robots.txt", f"/s/{rid}", "/s", "/s/bad"]
    for path in paths:
        status, headers, _ = s.call("GET", path)
        assert status in (200, 404), (path, status)
        for name, value in want.items():
            assert headers.get(name) == value, (path, name, headers.get(name))
    body, _ = seal("x")
    for status, headers, _ in [s.post("/api/s", body), s.post("/api/s", {"bad": 1}), s.call("GET", "/api/s"), s.open(rid, secret)]:
        for name, value in want.items():
            assert headers.get(name) == value, ("api", status, name, headers.get(name))
        assert headers.get("cache-control") == "no-store", status


def t_only_the_embed_page_can_be_framed_and_only_by_the_site(s):
    want = expected_headers()
    status, headers, body = s.call("GET", "/embed")
    assert status == 200, status
    csp = headers["content-security-policy"]
    assert "frame-ancestors https://apikeybin.com;" in csp, csp
    assert "x-frame-options" not in headers
    assert csp.replace("frame-ancestors https://apikeybin.com;", "frame-ancestors 'none';") == want["content-security-policy"]
    for name, value in want.items():
        if name not in ("content-security-policy", "x-frame-options"):
            assert headers.get(name) == value, name
    assert "noindex" in headers["x-robots-tag"]
    assert b'id="create"' in body and b"<iframe" not in body
    for path in ["/", f"/s/{VALID_ID_UNUSED}", "/app.js"]:
        h = s.call("GET", path)[1]
        assert "frame-ancestors 'none'" in h["content-security-policy"], path
        assert h.get("x-frame-options") == "DENY", path
    assert s.call("POST", "/embed")[0] == 405


def t_no_cookies_and_no_cors_anywhere(s):
    rid, secret, _ = s.create()
    body, _ = seal("x")
    for status, headers, _ in [
        s.call("GET", "/"), s.call("GET", f"/s/{rid}"), s.call("GET", "/app.js"),
        s.post("/api/s", body), s.open(rid, secret), s.call("OPTIONS", "/api/s"),
    ]:
        assert "set-cookie" not in headers, status
        assert not [k for k in headers if k.startswith("access-control-")], (status, headers)


def t_the_page_to_come_back_to_is_the_same_reading_page(s):
    status, headers, body = s.call("GET", "/open")
    assert status == 200, "a redirect here would be a place for things to go wrong"
    assert body == s.call("GET", f"/s/{VALID_ID_UNUSED}")[2]
    assert headers["cache-control"] == "no-store"
    assert "noindex" in headers["x-robots-tag"]
    assert "frame-ancestors 'none'" in headers["content-security-policy"]
    assert s.call("POST", "/open")[0] == 405


def t_nothing_on_this_origin_is_for_search(s):
    # Search should find apikeybin.com. Every page here says noindex, either in the page or in a header.
    for path in ["/", "/embed", "/open", f"/s/{VALID_ID_UNUSED}"]:
        status, headers, body = s.call("GET", path)
        assert status == 200, path
        assert b'name="robots" content="noindex' in body or "noindex" in headers.get("x-robots-tag", ""), path


def t_the_full_page_and_the_framed_page_have_the_same_form(s):
    def form(name):
        html = (WEB / "public" / name).read_text()
        return html[html.index('<form id="create"'):html.index('<section id="result"')]
    assert form("index.html") == form("embed.html")


def t_the_reading_page_gives_nothing_away_and_consumes_nothing(s):
    rid, secret, _ = s.create()
    responses = [s.call("GET", f"/s/{rid}") for _ in range(3)] + [s.call("HEAD", f"/s/{rid}")]
    unknown = s.call("GET", f"/s/{VALID_ID_UNUSED}")
    assert all(r[0] == 200 for r in responses), "a redirect here would carry the fragment along"
    assert responses[0][2] == unknown[2], "the page differs for real and unknown ids"
    headers = responses[0][1]
    assert headers["cache-control"] == "no-store"
    assert "noindex" in headers["x-robots-tag"]
    assert s.open(rid, secret)[0] == 200, "viewing the page consumed the record"


def t_exactly_one_of_many_simultaneous_readers_wins(s):
    rid, secret, _ = s.create(CANARY)
    token = {"token": b64u(token_of(secret))}
    barrier = threading.Barrier(24)
    def reader(_):
        barrier.wait()
        return s.post(f"/api/s/{rid}/open", token)
    with ThreadPoolExecutor(24) as pool:
        answers = list(pool.map(reader, range(24)))
    statuses = sorted(a[0] for a in answers)
    assert statuses.count(200) == 1, statuses
    assert statuses.count(404) == 23, statuses
    winner = next(a for a in answers if a[0] == 200)
    assert unseal(json.loads(winner[2]), secret) == CANARY.encode()


def t_a_stolen_database_holds_no_key_token_or_plaintext(s):
    rid, secret, _ = s.create(CANARY, passphrase="correct horse")
    columns = [r[1] for r in s.sql("PRAGMA table_info(secrets)")]
    assert columns == ["id", "token_hash", "iv", "ct", "salt", "pw", "size", "expires_at"], columns
    row = s.sql("SELECT * FROM secrets WHERE id = ?", rid)[0]
    dump = json.dumps(row)
    token = token_of(secret)
    assert CANARY not in dump
    assert b64u(secret) not in dump and b64u(token) not in dump
    assert row[1] == b64u(hashlib.sha256(token).digest())
    # What a thief could do with it: nothing, without the link.
    raw = (s.db_path(),)
    import pathlib
    contents = pathlib.Path(raw[0]).read_bytes()
    assert CANARY.encode() not in contents and b64u(secret).encode() not in contents


def t_tampering_with_the_stored_ciphertext_is_detected(s):
    rid, secret, _ = s.create(CANARY)
    ct = s.sql("SELECT ct FROM secrets WHERE id = ?", rid)[0][0]
    flipped = ("B" if ct[0] == "A" else "A") + ct[1:]
    s.sql("UPDATE secrets SET ct = ? WHERE id = ?", flipped, rid)
    record = json.loads(s.open(rid, secret)[2])
    try:
        unseal(record, secret)
    except Exception:  # noqa: BLE001
        return
    raise AssertionError("tampered ciphertext decrypted")


def t_usage_is_counted_and_the_cap_holds(s):
    start = s.sql("SELECT bytes FROM usage")[0][0]
    rid, secret, _ = s.create()
    stored = s.sql("SELECT LENGTH(ct) FROM secrets WHERE id = ?", rid)[0][0]
    assert stored > 1040, "the ciphertext is kept as text, which is longer than its bytes"
    assert s.sql("SELECT bytes FROM usage")[0][0] == start + stored + 1024
    s.open(rid, secret)
    for _ in range(50):
        if s.sql("SELECT bytes FROM usage")[0][0] == start:
            break
        import time
        time.sleep(0.05)
    assert s.sql("SELECT bytes FROM usage")[0][0] == start, "not released after opening"
    before_rows = count(s)
    s.sql("UPDATE usage SET bytes = ?", 400 * 1000 * 1000 - 100)
    body, _ = seal("x")
    status = s.post("/api/s", body)[0]
    bytes_after = s.sql("SELECT bytes FROM usage")[0][0]
    s.sql("UPDATE usage SET bytes = ?", start)
    assert status == 507, status
    assert count(s) == before_rows, "a refused create stored a row"
    assert bytes_after == 400 * 1000 * 1000 - 100, "a refused create changed the counter"


def t_the_counter_covers_what_the_database_really_holds(s):
    # The free database stops at 500 MB. The counter has to reach its own cap of 400 MB first, or
    # creating a link ends in an error from the database instead of a clean "full".
    def on_disk():
        return s.sql("PRAGMA page_count")[0][0] * s.sql("PRAGMA page_size")[0][0]

    for text in ["x", "x" * 15000, "x" * 60000]:
        # Enough rows that the growth is past the free pages left by earlier tests.
        s.sql("VACUUM")
        disk = on_disk()
        counted = s.sql("SELECT bytes FROM usage")[0][0]
        for _ in range(60):
            s.create(text)
        grown = on_disk() - disk
        added = s.sql("SELECT bytes FROM usage")[0][0] - counted
        assert grown > 0, "the measurement saw nothing"
        assert grown <= added, (len(text), grown, added)


def t_usage_is_recomputed_by_the_scheduled_job(s):
    s.create()
    s.create("x" * 16000)
    s.create("x" * 20000)
    s.sql("UPDATE usage SET bytes = 999999, large = 999999")
    assert s.call("GET", "/__scheduled?cron=*/30+*+*+*+*")[0] == 200
    real = s.sql("SELECT COALESCE(SUM(size), 0) FROM secrets")[0][0]
    real_large = s.sql("SELECT COALESCE(SUM(size), 0) FROM secrets WHERE LENGTH(ct) > 80000")[0][0]
    assert 0 < real_large < real
    assert s.sql("SELECT bytes, large FROM usage")[0] == (real, real_large)


def wait_until(check):
    import time
    for _ in range(50):
        if check():
            return True
        time.sleep(0.05)
    return False


def t_the_largest_record_round_trips(s):
    # The biggest request there can be: the largest content, with a passphrase and its salt.
    for size, passphrase in [(16379, None), (65530, None), (65530, "a passphrase")]:
        text = b"a" * size
        rid, secret, _ = s.create(text, passphrase=passphrase)
        assert unseal(json.loads(s.open(rid, secret)[2]), secret, passphrase) == text, size


def t_a_large_record_counts_four_times_against_the_limit(s):
    ip = unique_ip()
    statuses = []
    for _ in range(12):
        body, _ = seal("x" * 20000)
        statuses.append(s.post("/api/s", body, ip=ip)[0])
    assert 429 in statuses, statuses
    # The limit is 20 a minute, which is five of these. A new minute can start while this runs.
    assert 3 <= statuses.index(429) <= 10, statuses
    body, _ = seal("x" * 20000)
    assert s.post("/api/s", body)[0] == 201, "another client was limited too"


def t_a_large_record_needs_room_for_all_four(s):
    # With 18 of the 20 used, one more large record does not fit. A new minute can start while this
    # runs, but not twice in a row.
    for _attempt in range(2):
        ip = unique_ip()
        for _ in range(18):
            body, _ = seal("x")
            assert s.post("/api/s", body, ip=ip)[0] == 201
        before = count(s)
        body, _ = seal("x" * 20000)
        status = s.post("/api/s", body, ip=ip)[0]
        if status == 429:
            assert count(s) == before, "refused, but stored"
            return
    raise AssertionError(status)


def t_large_records_may_use_only_half_of_the_store(s):
    half = 200 * 1000 * 1000
    start = s.sql("SELECT large FROM usage")[0][0]
    bytes_before = s.sql("SELECT bytes FROM usage")[0][0]
    s.sql("UPDATE usage SET large = ?", half - 100)
    try:
        before = count(s)
        body, _ = seal("x" * 20000)
        assert s.post("/api/s", body)[0] == 507
        assert count(s) == before, "a refused create stored a row"
        assert s.sql("SELECT bytes, large FROM usage")[0] == (bytes_before, half - 100), "a refused create changed a counter"
        # An ordinary key still goes through.
        rid, _, _ = s.create("x")
        assert s.sql("SELECT large FROM usage")[0][0] == half - 100
    finally:
        s.sql("UPDATE usage SET large = ?", start)


def t_the_large_counter_follows_what_is_stored(s):
    def large():
        return s.sql("SELECT large FROM usage")[0][0]

    start = large()
    # The biggest size that is not large, then the smallest that is.
    rid, secret, _ = s.create("x" * 16000)
    assert large() == start, "a 16 KiB record counted as large"
    s.open(rid, secret)
    assert wait_until(lambda: large() == start), "reading one that is not large changed the counter"
    rid, secret, _ = s.create("x" * 20000)
    stored = s.sql("SELECT size FROM secrets WHERE id = ?", rid)[0][0]
    assert large() == start + stored
    s.open(rid, secret)
    assert wait_until(lambda: large() == start), "not released after opening"


def t_each_load_of_the_tool_is_counted(s):
    def loads():
        return s.sql("SELECT COALESCE(SUM(tool_loads), 0) FROM daily")[0][0]

    start = loads()
    assert s.call("GET", "/embed")[0] == 200
    assert wait_until(lambda: loads() == start + 1), "not counted"
    assert s.call("HEAD", "/embed")[0] == 200
    assert s.call("GET", "/")[0] == 200
    assert not wait_until(lambda: loads() != start + 1), "something else counted as a load"


def t_files_that_are_not_text_stay_closed_for_now(s):
    # Opened by hand after the ad review (docs/SPEC.md 19.4), and this test goes when it is.
    assert BINARY_SWITCH in (WEB / "public/app.js").read_text()


def t_daily_counts_hold_numbers_and_nothing_personal(s):
    import time
    columns = [r[1] for r in s.sql("PRAGMA table_info(daily)")]
    assert columns == ["day", "created", "opened", "tool_loads"], columns
    rid, secret, _ = s.create()
    s.open(rid, secret)
    time.sleep(0.2)
    created, opened = s.sql("SELECT SUM(created), SUM(opened) FROM daily")[0]
    assert created >= 1 and opened >= 1, (created, opened)


def t_rate_limit_applies_per_client(s):
    ip = unique_ip()
    statuses = []
    for _ in range(40):
        body, _ = seal("x")
        statuses.append(s.post("/api/s", body, ip=ip)[0])
    assert 429 in statuses, f"never limited: {set(statuses)}"
    assert statuses.index(429) >= 15, f"limited too early at {statuses.index(429)}"
    body, _ = seal("x")
    assert s.post("/api/s", body)[0] == 201, "another client was limited too"


def t_rate_limit_applies_to_reading_too(s):
    ip = unique_ip()
    rid, secret, _ = s.create()
    token = {"token": b64u(b"\x09" * 32)}
    statuses = [s.post(f"/api/s/{rid}/open", token, ip=ip)[0] for _ in range(80)]
    assert 429 in statuses, f"never limited: {set(statuses)}"
    assert statuses.index(429) >= 40, f"limited too early at {statuses.index(429)}"
    assert s.open(rid, secret)[0] == 200, "another client was limited, or the guesses burned it"


def t_reading_pages_exist_only_for_well_formed_ids(s):
    assert s.call("GET", f"/s/{VALID_ID_UNUSED}")[0] == 200
    for bad in ["bad", "A" * 21, "A" * 23, "A" * 21 + "!"]:
        assert s.call("GET", f"/s/{bad}")[0] == 404, bad


def t_the_site_loads_nothing_from_anywhere_else(s):
    for path in ["/", "/s/" + VALID_ID_UNUSED]:
        html = s.call("GET", path)[2].decode()
        for src in re.findall(r'(?:src|href|action)="([^"]+)"', html):
            # The site, for what it alone has: not the screen without ads, and nothing else.
            assert src.startswith("/") or src in SITE_LINKS, (path, src)
        assert "<style" not in html and " style=" not in html and " on" not in re.sub(r'"[^"]*"', '""', html.split("</head>")[0]), path
    assert "https://" not in (WEB / "public/app.css").read_text()
    js = (WEB / "public/app.js").read_text()
    # Two addresses are known to the script, as constants: this site, and the page with ads. The
    # second is only ever navigated to, never loaded and never sent anything.
    addresses = sorted(re.findall(r"https?://[^'\"`\s)]*", js))
    assert addresses == sorted(["https://app.apikeybin.com", "https://apikeybin.com/open#go"]), addresses
    assert js.count("CUSHION") == 2 and "location.replace(CUSHION);" in js
    for sink in ["innerHTML", "outerHTML", "insertAdjacentHTML", "document.write", "eval(", "new Function", "localStorage", "indexedDB", "document.cookie", "readText"]:
        assert sink not in js, sink


def t_session_storage_holds_one_thing_and_only_for_the_trip(s):
    js = (WEB / "public/app.js").read_text()
    uses = re.findall(r"sessionStorage\.(\w+)\(([^,)]*)", js)
    assert uses and {key for _, key in uses} == {"PENDING"}, uses
    assert {name for name, _ in uses} == {"setItem", "getItem", "removeItem"}, uses
    assert "at: Date.now()" in js and "PENDING_MAX_AGE_MS" in js


def t_no_source_file_hides_an_invisible_character(s):
    # Bidirectional overrides make source read differently from what it does ("Trojan Source"),
    # and U+2028 inside a regular expression literal ends the line and breaks the page.
    roots = [WEB / "public", WEB / "worker"] + [ROOT / p for p in ["site/public", "crates", "verify/web-real", "verify/kat", "verify/mutation", "docs"]]
    kinds = {".js", ".html", ".css", ".rs", ".py", ".md", ".jsonc", ".toml", ".txt", ".sql"}
    seen = 0
    for root in roots:
        for path in root.rglob("*"):
            if not path.is_file() or path.suffix not in kinds or {"node_modules", ".venv", "target", ".wrangler"} & set(path.parts):
                continue
            seen += 1
            bad = {f"U+{ord(c):04X}" for c in path.read_text(encoding="utf-8") if unicodedata.category(c) in ("Cf", "Zl", "Zp")}
            assert not bad, (str(path), sorted(bad))
    assert seen > 40, seen


def t_a_server_already_on_the_port_stops_the_suite(s):
    other = Server(port=s.port, cwd=s.cwd)
    try:
        other.start()
    except RuntimeError as e:
        assert "already in use" in str(e), e
    else:
        raise AssertionError("started beside a server that was already there")
    finally:
        other.stop()


TESTS = [v for k, v in sorted(globals().items()) if k.startswith("t_")]


def main():
    results = Results()
    with Server() as s:
        for fn in TESTS:
            results.run(fn, s)
        leaked = [needle for needle in (CANARY,) if needle in s.logs()]
        if leaked:
            results.failed.append("server_log_contains_secret")
    return results.finish("api")


if __name__ == "__main__":
    raise SystemExit(main())
