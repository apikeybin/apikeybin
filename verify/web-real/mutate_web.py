#!/usr/bin/env python3
"""Do the web tests notice when a safety check is removed?

Works on a temporary copy of web/, so the tree stays usable while it runs. Each entry removes
one check; the named suite must then fail. A mutation that survives is a hole in the tests.
"""
from __future__ import annotations

import json
import os
import shutil
import signal
import subprocess
import sys
import tempfile
import time
from pathlib import Path

from common import port_in_use

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
PORT = 8793
SUITES = ("api", "chromium", "webkit", "shell")
# Without its check a suite can take long: every test that can no longer finish waits out its own limit.
LIMIT = 1800
W = "worker/index.js"
A = "public/app.js"
I = "public/index.html"
S = "public/s.html"
H = "public/_headers"

READ_SQL = "'DELETE FROM secrets WHERE id = ?1 AND token_hash = ?2 AND expires_at > ?3 RETURNING iv, ct, salt, pw, size',"
RL = "if (!success) return fail(429, 'slow_down', { 'Retry-After': '60' });"

MUTATIONS = [
    # ---------------------------------------- server
    ("api", "custom header not required", W, "if (request.headers.get('X-Apikeybin') !== '1') return fail(403, 'forbidden');", ""),
    ("api", "other sites not refused", W, "if (site !== null && site !== 'same-origin') return fail(403, 'forbidden');", ""),
    ("api", "content type not checked", W, "if (type !== 'application/json') return fail(415, 'unsupported_media_type');", ""),
    ("api", "reading needs no token", W, READ_SQL, READ_SQL.replace("token_hash = ?2", "?2 = ?2")),
    ("api", "expired records can be read", W, READ_SQL, READ_SQL.replace("expires_at > ?3", "?3 = ?3")),
    ("api", "reading does not delete", W, READ_SQL, "'SELECT iv, ct, salt, pw, size FROM secrets WHERE id = ?1 AND token_hash = ?2 AND expires_at > ?3',"),
    ("api", "unknown fields accepted", W, "if (!onlyFields(b, ['v', 'iv', 'ct', 'token_hash', 'ttl', 'pw', 'salt'])) return fail(400, 'bad_request');", ""),
    ("api", "any expiry accepted", W, "|| !TTLS.has(b.ttl)", ""),
    ("api", "any size accepted", W, "if (size === 0) return fail(400, 'bad_size');", "if (size === 0) size = 1040;"),
    ("api", "iv and token hash not validated", W, "if (!isB64u(b.iv, 12) || !isB64u(b.token_hash, 32)) return fail(400, 'bad_request');", ""),
    ("api", "passphrase and salt can disagree", W, "if (b.pw ? !isB64u(b.salt, 16) : b.salt !== undefined) return fail(400, 'bad_request');", ""),
    ("api", "non-canonical base64 accepted", W, "return rem === 1 ? (last & 0x0f) === 0 : (last & 0x03) === 0;", "return true;"),
    ("api", "storage cap removed", W, "AND bytes + ?1 <= ?3", "AND ?3 = ?3"),
    ("api", "large records may fill the store", W, ".bind(size, large, STORAGE_CAP, LARGE_CAP)", ".bind(size, large, STORAGE_CAP, STORAGE_CAP)"),
    ("api", "a large record counts once", W, "for (let i = 1; i < LARGE_WEIGHT; i++) {", "for (let i = 1; i < 1; i++) {"),
    ("api", "the limit on large records answers as if it worked", W, "if (!within) return fail(429, 'slow_down', { 'Retry-After': '60' });", ""),
    ("api", "16 KiB counts as large", W, "const LARGE_ROW = Math.ceil(((16384 + AEAD_TAG) * 4) / 3) + ROW_OVERHEAD;", "const LARGE_ROW = Math.ceil(((4096 + AEAD_TAG) * 4) / 3) + ROW_OVERHEAD;"),
    ("api", "the largest record does not fit the body limit", W, "const MAX_BODY = 96 * 1024;", "const MAX_BODY = 64 * 1024;"),
    ("api", "tool loads not counted", W, "if (request.method === 'GET') ctx.waitUntil(count(env, 'tool_loads'));", ""),
    ("api", "a look at the headers counts as a load", W, "if (request.method === 'GET') ctx.waitUntil(count(env, 'tool_loads'));", "ctx.waitUntil(count(env, 'tool_loads'));"),
    ("api", "files that are not text are open", A, "const BINARY_OPEN = false;", "const BINARY_OPEN = true;"),
    ("api", "the counter counts less than is stored", W, "size = b.ct.length + ROW_OVERHEAD;", "size = bucket + AEAD_TAG;"),
    ("api", "row stored even when refused", W, "WHERE changes() = 1", ""),
    ("api", "body size not limited", W, [
        ("if (declared !== null && Number(declared) > MAX_BODY) return { error: fail(413, 'too_large') };", ""),
        ("if (total > MAX_BODY) {\n      await reader.cancel();\n      return { error: fail(413, 'too_large') };\n    }", ""),
    ], None),
    ("api", "API responses can be cached", W, "{ 'Cache-Control': 'no-store', ...extra },", "{ ...extra },"),
    ("api", "reading page can be cached", W, "'Cache-Control': 'no-store',\n    'X-Robots-Tag'", "'X-Robots-Tag'"),
    ("api", "reading page can be indexed", W, "'X-Robots-Tag': 'noindex, nofollow, noarchive',", ""),
    ("api", "script policy weakened in worker", W, "script-src 'self'; style-src", "script-src 'self' 'unsafe-inline'; style-src"),
    ("api", "referrer policy loosened in worker", W, "'Referrer-Policy': 'no-referrer',", "'Referrer-Policy': 'origin',"),
    ("api", "static files lose the script policy", H, "  Content-Security-Policy: default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'; require-trusted-types-for 'script'; trusted-types 'none'\n", ""),
    ("api", "static files lose COOP", H, "  Cross-Origin-Opener-Policy: same-origin\n", ""),
    ("api", "create not rate limited", W, RL, "", 1),
    ("api", "read not rate limited", W, RL, "", 2),
    ("api", "pages served for malformed ids", W, "return ID_RE.test(pathname.slice(3)) ? secretPage(request, env) : fail(404, 'not_found');", "return secretPage(request, env);"),
    ("api", "space not released after reading", W, "UPDATE usage SET bytes = MAX(0, bytes - ?1), large = MAX(0, large - ?2) WHERE id = 1", "UPDATE usage SET large = MAX(0, large - ?2) WHERE ?1 = ?1 AND id = 1"),
    ("api", "large space not released after reading", W, "UPDATE usage SET bytes = MAX(0, bytes - ?1), large = MAX(0, large - ?2) WHERE id = 1", "UPDATE usage SET bytes = MAX(0, bytes - ?1) WHERE ?2 = ?2 AND id = 1"),
    ("api", "expired records never purged", W, "env.DB.prepare('DELETE FROM secrets WHERE expires_at <= ?1').bind(now),", ""),
    ("api", "usage not recomputed", W, "'UPDATE usage SET bytes = (SELECT COALESCE(SUM(size), 0) FROM secrets), ' +", "'UPDATE usage SET ' +"),
    ("api", "large usage not recomputed", W, "'large = (SELECT COALESCE(SUM(size), 0) FROM secrets WHERE size > ?1) WHERE id = 1',", "'large = large WHERE ?1 = ?1 AND id = 1',"),
    ("api", "every record recomputed as large", W, "FROM secrets WHERE size > ?1) WHERE id = 1',", "FROM secrets WHERE ?1 = ?1) WHERE id = 1',"),
    ("api", "embed can be framed by anyone", W, "`frame-ancestors ${site}`,", "`frame-ancestors *`,"),
    ("api", "embed keeps no frame rule", W, "out.headers.delete('X-Frame-Options');", ""),
    ("api", "reading page can be framed", W, "return withHeaders(asset, {\n    'Cache-Control': 'no-store',", "return withHeaders(asset, {\n    'Content-Security-Policy': SECURITY_HEADERS['Content-Security-Policy'].replace(\"frame-ancestors 'none'\", 'frame-ancestors *'),\n    'Cache-Control': 'no-store',"),
    ("api", "third-party script added to the page", I, '<script src="/app.js" defer></script>', '<script src="/app.js" defer></script><script src="https://cdn.example.test/x.js"></script>'),
    # ---------------------------------------- client
    ("api", "the direct tool page can be found by search", I, '<meta name="robots" content="noindex,nofollow">\n', ""),
    ("api", "an invisible character in the source", A, "const PENDING =", chr(0x202e) + "const PENDING ="),
    ("api", "no page to come back to", W, "if (pathname === '/open') {", "if (pathname === '/nope') {"),
    ("api", "the two forms drift apart", "public/embed.html", 'rows="6"', 'rows="9"'),
    ("api", "sessionStorage used for something else", A, "sessionStorage.removeItem(PENDING);", "sessionStorage.removeItem(PENDING); sessionStorage.setItem('other', '1');"),
    ("api", "another address in the script", A, "const CUSHION = 'https://apikeybin.com/open#go';", "const CUSHION = 'https://apikeybin.com/open#go'; const OTHER = 'https://ads.example/x';"),
    ("chromium", "the reading page has no way to report", S, '<a href="https://apikeybin.com/report" rel="noopener noreferrer">このリンクの悪用を通報する</a>', ""),
    ("chromium", "the reading page leads to the screen without ads", S, '<a class="secondary" href="https://apikeybin.com/"', '<a class="secondary" href="/"'),
    ("chromium", "the dropped dot is not mentioned", A, "show($('hint-dot'), framed.name.startsWith('.'));", ""),
    ("chromium", "the added .txt is not mentioned", A, "show($('hint-txt'), fileIsText && !KEEPS_ITS_NAME.test(framed.name));", ""),
    ("chromium", "no name saves under a wrong name", A, "framed.name ?? (fileIsText ? 'apikeybin.txt' : 'apikeybin.bin')", "framed.name"),
    ("chromium", "what is saved is not what arrived", A, "fileBytes = framed.content.slice();", "fileBytes = null;"),
    ("chromium", "the file name is written as markup", A, "$('output-name').textContent = framed.name;", "$('output-name').insertAdjacentHTML('beforeend', framed.name);"),
    ("shell", "ads beside the buttons", "../site/public/site.css", "gap: 150px;", "gap: 100px;"),
    ("shell", "the message pushes the button at the ad", "../site/public/site.css", ".ad-below { margin-top: 96px; }\n", ""),
    ("shell", "the ad close to the button on the page with ads", "../site/public/site.css", ".ad-clear { margin-top: 96px; }\n", ""),
    ("shell", "the top ad close to the tool", "../site/public/site.css", ".ad-top { margin: 8px auto 14px;", ".ad-top { margin: 8px auto 0;"),
    ("shell", "the frame too short for its tool", "../site/public/site.css", "#tool { display: block; width: 100%; height: 500px; border: 0; }", "#tool { display: block; width: 100%; height: 300px; border: 0; }"),
    ("shell", "the frame too short with a pointer on a narrow window", "../site/public/site.css", "@media (hover: hover) and (max-width: 480px) {\n  #tool { height: 620px; }\n}\n", ""),
    ("shell", "the page with ads back over the share", "../site/public/open.html", '<div class="ad-box ad-300x250" data-ad-slot="open-rail">', '<div class="ad-box ad-300x600" data-ad-slot="open-rail"></div><div class="ad-box ad-300x600"></div><div class="ad-box ad-300x600">'),
    ("shell", "an empty place for an ad shows before the ads are live", "../site/public/site.css", ".no-ads .ad, .no-ads .rail { display: none; }\n", ""),
    ("shell", "the privacy page loses what Google requires", "../site/public/privacy.html", "過去にアクセスした際の情報", "x"),
    ("shell", "a page loses its way to the privacy page", "../site/public/open.html", '<a href="/privacy">', '<a href="/terms">'),
    ("shell", "a link inside the site leads nowhere", "../site/public/index.html", '<a href="/guides/api-key-leaked">', '<a href="/guides/no-such-page">'),
    ("shell", "an article shows a place for an ad before the ads are live", "../site/public/guides/how-it-works.html", '<html lang="ja" class="no-ads">', '<html lang="ja">'),
    ("shell", "an ad too close to the button in an article", "../site/public/guides/how-it-works.html", '<h2>リンクができるまで</h2>', '<aside class="ad" style="margin:0"><div class="ad-box ad-300x250"></div></aside><h2>リンクができるまで</h2>'),
    ("shell", "a page is left out of the sitemap", "../site/public/sitemap.xml", "<url><loc>https://apikeybin.com/report</loc></url>", ""),
    ("shell", "the button to nowhere", "../site/public/site.css", ".with-link { display: none; }\n", ""),
    ("shell", "the reader arrives without the mark", A, "const CUSHION = 'https://apikeybin.com/open#go';", "const CUSHION = 'https://apikeybin.com/open';"),
    ("shell", "the sentence for someone without a link stays", "../site/public/site.css", "#go:target .without-link { display: none; }\n", ""),
    ("shell", "the button pushed off the first screen", "../site/public/index.html", '<p class="lead">1回だけ読めるリンクを作ります。</p>', '<p class="lead">1回だけ読めるリンクを作ります。<br>2<br>3<br>4<br>5</p>'),
    ("shell", "the key goes along to the page with ads", A, "location.replace(CUSHION);", "location.replace(CUSHION + fragment);"),
    ("shell", "the id goes along to the page with ads", A, "location.replace(CUSHION);", "location.replace(CUSHION.replace('#go', `?id=${id}#go`));"),
    ("shell", "the key stays in the address bar on the way", A, "history.replaceState(null, '', '/open');\n      location.replace(CUSHION);", "location.replace(CUSHION);"),
    ("shell", "the key is left in storage after reading", A, "history.replaceState(null, '', location.pathname);\n          clearPending();", "history.replaceState(null, '', location.pathname);"),
    ("shell", "an old pending entry still works", A, "if (value && Date.now() - value.at < PENDING_MAX_AGE_MS) return value;", "if (value) return value;"),
    ("shell", "no way forward when storage fails", A, "if (!coming_back && location.origin === APP_ORIGIN && savePending(id, fragment)) {", "if (!coming_back && location.origin === APP_ORIGIN) {\n      savePending(id, fragment);"),
    ("shell", "pending id not checked", A, "if (!match || !ID.test(String(id))) {", "if (!match) {"),
    ("shell", "the page with ads loses its content", "../site/public/open.html", "<h2>受け取ったあとにすること</h2>", "<h2>x</h2><script>location.href='https://app.apikeybin.com/open'</script>"),
    ("chromium", "a hostile file name is accepted", A, "return validName(name) ? { name, content } : null;", "return { name, content };"),
    ("chromium", "the name is left out of the frame", A, "out.set(nameBytes, NAME_PREFIX);", ""),
    ("chromium", "a file that would run is saved as is", A, "anchor.download = KEEPS_ITS_NAME.test(fileName) ? fileName : `${fileName}.${fileIsText ? 'txt' : 'bin'}`;", "anchor.download = fileName;"),
    ("chromium", "every name gets .txt", A, "anchor.download = KEEPS_ITS_NAME.test(fileName) ? fileName : `${fileName}.${fileIsText ? 'txt' : 'bin'}`;", "anchor.download = `${fileName}.txt`;"),
    ("chromium", "names may end in a dot or a space", A, " && !BAD_ENDS.test(name)", ""),
    ("chromium", "a mark at the start of a name is dropped", A, "name = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true })", "name = new TextDecoder('utf-8', { fatal: true })"),
    ("chromium", "a mark at the start of the content is dropped", A, "return new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes);", "return new TextDecoder('utf-8', { fatal: true }).decode(bytes);"),
    ("chromium", "saving after the wipe writes the word null", A, "if (!fileBytes) return;", ""),
    ("chromium", "binary shown as text", A, "output.textContent = asText ?? '';", "output.textContent = new TextDecoder().decode(framed.content);"),
    ("chromium", "the text area stays for a binary file", A, "show($('output-text'), fileIsText);", ""),
    ("chromium", "binary can be copied", A, "show($('copy-output'), fileIsText);", ""),
    ("chromium", "nothing says why a binary file is not shown", A, "show($('output-binary'), !fileIsText);", ""),
    ("chromium", "a NUL counts as text", A, "if (bytes.includes(0)) return null;", ""),
    ("chromium", "another encoding counts as text", A, "new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes);\n    } catch {\n      return null;", "new TextDecoder('utf-8', { ignoreBOM: true }).decode(bytes);\n    } catch {\n      return null;"),
    ("chromium", "a binary file that would run keeps its name", A, "`${fileName}.${fileIsText ? 'txt' : 'bin'}`", "fileName"),
    ("chromium", "a binary file gets .txt", A, "`${fileName}.${fileIsText ? 'txt' : 'bin'}`", "`${fileName}.txt`"),
    ("chromium", "the added .bin is not mentioned", A, "show($('hint-bin'), !fileIsText && !KEEPS_ITS_NAME.test(framed.name));", ""),
    ("chromium", "binary with no name saves as text", A, "framed.name ?? (fileIsText ? 'apikeybin.txt' : 'apikeybin.bin')", "framed.name ?? 'apikeybin.txt'"),
    ("chromium", "file names not checked when chosen", A, "if (!validName(file.name)) return showError('name');", ""),
    ("chromium", "the chosen file stays after the link is made", A, "passphrase.value = '';\n        clearFile();", "passphrase.value = '';"),
    ("chromium", "the file's content shown in the box", A, "show($('text-area'), false);", "text.value = new TextDecoder().decode(bytes);"),
    ("chromium", "key stays in the address bar", A, "history.replaceState(null, '', location.pathname);", ""),
    ("chromium", "key goes out in a header", A, [
        ("history.replaceState(null, '', location.pathname);", "window.__k = location.hash; history.replaceState(null, '', location.pathname);"),
        ("headers: { 'Content-Type': 'application/json', 'X-Apikeybin': '1' },", "headers: { 'Content-Type': 'application/json', 'X-Apikeybin': '1', 'X-Debug': window.__k || '' },"),
    ], None),
    ("chromium", "typed secret left in the box", A, "text.value = '';\n        passphrase.value = '';\n        clearFile();", "passphrase.value = '';\n        clearFile();"),
    # Expected to survive: it only matters when a page is restored from the back/forward cache,
    # which could not be reproduced under Playwright. Listed so the gap stays visible.
    ("chromium", "fields not wiped on leaving", A, "window.addEventListener('beforeunload', wipe);\n    window.addEventListener('pagehide', wipe);", ""),
    ("webkit", "secret shown in a form field again", S, '<pre id="output" class="secretbox notranslate" translate="no"></pre>', '<textarea id="output" class="secretbox notranslate" translate="no"></textarea>'),
    ("chromium", "padding bytes not checked", A, "if (padded[i] !== 0) return null;", ""),
    ("chromium", "declared length not checked", A, "if (length > padded.length - LEN_PREFIX) return null;", ""),
    ("chromium", "passphrase flag not compared", A, "if (record.pw !== needsPassphrase) return setState('state-error');", ""),
    ("chromium", "no associated data", A, "{ name: 'AES-GCM', iv, additionalData: AAD }", "{ name: 'AES-GCM', iv }"),
    ("chromium", "empty passphrase spends the read", A, "if (needsPassphrase && passphrase.value.length === 0) return show(wrong, true);", ""),
    ("chromium", "oversized text not caught", A, "if (padded === null) return showError('big');", ""),
    ("chromium", "opens itself on load", A, "setState('state-ask');\n", "setState('state-ask');\n    setTimeout(() => $('open').click(), 0);\n"),
    ("chromium", "token derived with the key's label", A, "'apikeybin/link/1/token'", "'apikeybin/link/1/key'", 0),
    ("chromium", "weak passphrase stretching", A, "const PBKDF2_ITERATIONS = 600000;", "const PBKDF2_ITERATIONS = 1000;"),
    ("chromium", "passphrase not normalized", A, ".normalize('NFC')", ""),
    # ---------------------------------------- guards the first full list did not reach
    # Not listed: "if (body.length < NAME_PREFIX) return null". Removing it changes nothing, because
    # the next line refuses the same input: a length of 0 or 1 is always shorter than prefix + name.
    ("chromium", "a name longer than the frame", A, "if (length > MAX_NAME || body.length < NAME_PREFIX + length) return null;", "if (length > MAX_NAME) return null;"),
    ("chromium", "a record of no known size is read", A, "if (!BUCKETS.includes(padded.length)) return null;", ""),
    ("chromium", "an empty secret can be sent", A, "if (content.length === 0) return showError('empty');", ""),
    ("chromium", "an oversized file is read anyway", A, "if (file.size > BUCKETS[BUCKETS.length - 1]) return showError('big');", ""),
    ("chromium", "the button can be pressed before the script is ready", I, 'type="submit" disabled>', 'type="submit">'),
    ("chromium", "a file that cannot be read says nothing", A, "return showError('read');", "return undefined;"),
    ("chromium", "a file that is not text can be chosen", A, "if (!BINARY_OPEN && textOf(bytes) === null) {\n        bytes.fill(0);\n        return showError('binary');\n      }", ""),
    ("chromium", "the largest size is not offered", A, "const BUCKETS = [1024, 4096, 16384, 65536];", "const BUCKETS = [1024, 4096, 16384];"),
    ("chromium", "the drop zone shows on a phone", "public/app.css", "@media (hover: hover) {\n  .drop-zone {", "@media all {\n  .drop-zone {"),
    ("chromium", "no drop zone", "public/app.css", ".drop-zone { border: 1.5px dashed var(--line);", ".drop-zone { border: 0;"),
    ("chromium", "a refused create still shows a link", A, "if (response.status !== 201) return showError('net');", ""),
    ("chromium", "too many requests is not explained", A, "if (response.status === 429) return showError('slow');", ""),
    ("chromium", "a full store is not explained", A, "if (response.status === 507) return showError('full');", ""),
    ("chromium", "a used link does not say so", A, "if (response.status === 404) return setState('state-gone');", ""),
    ("chromium", "a wrong passphrase ends everything", A, "if (record.pw) {\n            show(wrong, true);\n            passphrase.select();\n            return undefined;\n          }", ""),
    ("shell", "nothing pending is not handled", A, "if (!pending) return setState('state-nopending');", ""),
    ("api", "base64 alphabet not checked", W, " || !B64U_RE.test(text)) return false;", ") return false;"),
    ("api", "base64 length not checked", W, " || text.length !== Math.ceil((n * 4) / 3)", ""),
    ("api", "JSON that is not an object accepted", W, "if (value === null || typeof value !== 'object' || Array.isArray(value)) throw new Error('shape');", ""),
    ("api", "record version not checked", W, "if (b.v !== 1 || !TTLS.has(b.ttl)", "if (!TTLS.has(b.ttl)"),
    ("api", "passphrase flag type not checked", W, " || typeof b.pw !== 'boolean') return fail(400, 'bad_request');", ") return fail(400, 'bad_request');"),
    ("api", "a full store answers as if it worked", W, "if (reserved.meta.changes !== 1 || inserted.meta.changes !== 1) return fail(507, 'full');", ""),
    ("api", "making a link skips the site check", W, "const refused = refuseForeign(request);\n  if (refused) return refused;\n  const { success } = await env.RL_CREATE", "const { success } = await env.RL_CREATE"),
    ("api", "reading a link skips the site check", W, "const refused = refuseForeign(request);\n  if (refused) return refused;\n  const { success } = await env.RL_OPEN", "const { success } = await env.RL_OPEN"),
    ("api", "malformed ids reach the database", W, "if (!ID_RE.test(id)) return fail(404, 'gone');", ""),
    ("api", "token shape not checked", W, "if (!onlyFields(b, ['token']) || !isB64u(b.token, 32)) return fail(400, 'bad_request');", "if (!onlyFields(b, ['token'])) return fail(400, 'bad_request');"),
    ("api", "extra fields on reading accepted", W, "if (!onlyFields(b, ['token']) || !isB64u(b.token, 32)) return fail(400, 'bad_request');", "if (!isB64u(b.token, 32)) return fail(400, 'bad_request');"),
    ("api", "a miss is not answered cleanly", W, "if (!row) return fail(404, 'gone');", ""),
    ("api", "the salt is not returned", W, "if (row.salt) out.salt = row.salt;", ""),
    ("api", "making a link answers other methods", W, "return method === 'POST' ? create(request, env, ctx) : fail(405, 'method_not_allowed', { Allow: 'POST' });", "return create(request, env, ctx);"),
    ("api", "the reading page answers other methods", W, "if (pathname.startsWith('/s/')) {\n    if (method !== 'GET' && method !== 'HEAD') return fail(405, 'method_not_allowed', { Allow: 'GET, HEAD' });", "if (pathname.startsWith('/s/')) {"),
    ("api", "the framed page answers other methods", W, "if (pathname === '/embed') {\n    if (method !== 'GET' && method !== 'HEAD') return fail(405, 'method_not_allowed', { Allow: 'GET, HEAD' });", "if (pathname === '/embed') {"),
    ("api", "the page to come back to answers other methods", W, "if (pathname === '/open') {\n    if (method !== 'GET' && method !== 'HEAD') return fail(405, 'method_not_allowed', { Allow: 'GET, HEAD' });", "if (pathname === '/open') {"),
    ("chromium", "text too long for any size", A, "if (bucket === undefined) return null;", ""),
    ("chromium", "a mistyped passphrase asks the server again", A, "if (record === null) {", "if (true) {"),
    # Not listed: "if (!request.body)". A POST with no length, a length of 0 and an empty chunked body
    # all arrive with a stream here, so removing it changes nothing. It stays because nothing promises that.
    ("api", "a bad body on making a link is not answered cleanly", W, "if (error) return error;", "", 1),
    ("api", "a bad body on reading is not answered cleanly", W, "if (error) return error;", "", 2),
    ("chromium", "broken link still tries", A, "if (!match || !ID.test(String(id))) {\n      clearPending();\n      return setState('state-badlink');\n    }", "if (!match) { setState('state-ask'); return; }"),
    ("chromium", "spellcheck left on for the secret", I, 'id="text" rows="6" placeholder="STRIPE_KEY=sk_live_..." spellcheck="false"', 'id="text" rows="6" placeholder="STRIPE_KEY=sk_live_..."'),
    ("chromium", "translation left on for the secret", S, 'class="secretbox notranslate" translate="no"', 'class="secretbox"'),
    ("chromium", "link left off the no-translate list", I, 'class="secretbox link notranslate" translate="no"', 'class="secretbox link"'),
]


class Void(Exception):
    """Something other than the mutation decides the outcome, so the run says nothing."""


def wait_for_the_port():
    deadline = time.monotonic() + 20
    while port_in_use(PORT):
        if time.monotonic() > deadline:
            raise Void(f"port {PORT} is held by something else")
        time.sleep(0.5)


def run(copy: Path, suite: str, limit: int = LIMIT):
    """The return code, the output and whether time ran out. Leaves nothing running behind it."""
    wait_for_the_port()
    pids = copy.parent / "server.pids"
    pids.write_text("", encoding="utf-8")
    env = dict(os.environ, APIKEYBIN_WEB=str(copy), APIKEYBIN_PORT=str(PORT), APIKEYBIN_SERVER_PIDS=str(pids), PYTHONDONTWRITEBYTECODE="1")
    if suite == "api":
        cmd = [sys.executable, str(HERE / "test_api.py")]
    elif suite == "shell":
        env["BROWSERS"] = "chromium"
        cmd = [sys.executable, str(HERE / "test_shell.py")]
    else:
        env["BROWSERS"] = suite
        cmd = [sys.executable, str(HERE / "test_browser.py")]
    with tempfile.TemporaryFile("w+", encoding="utf-8") as out:
        proc = subprocess.Popen(cmd, cwd=HERE, env=env, stdout=out, stderr=subprocess.STDOUT, start_new_session=True)
        late = False
        try:
            code = proc.wait(timeout=limit)
        except subprocess.TimeoutExpired:
            late = True
            os.killpg(proc.pid, signal.SIGKILL)
            code = proc.wait()
            for pid in pids.read_text(encoding="utf-8").split():
                try:
                    os.killpg(int(pid), signal.SIGKILL)
                except ProcessLookupError:
                    pass
        out.seek(0)
        text = out.read()
    wait_for_the_port()
    return code, text, late


def apply(text: str, old, new, which):
    if isinstance(old, list):
        for o, n in old:
            if o not in text:
                return None
            text = text.replace(o, n, 1)
        return text
    if old not in text:
        return None
    if which == 0:
        return text.replace(old, new)
    if which == 2:
        first = text.index(old)
        second = text.index(old, first + 1)
        return text[:second] + new + text[second + len(old):]
    return text.replace(old, new, 1)


def main():
    tmp = Path(tempfile.mkdtemp(prefix="apikeybin-mutate-"))
    try:
        return campaign(tmp)
    except Void as e:
        print(f"\nVOID, nothing recorded: {e}", flush=True)
        return 2
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def campaign(tmp: Path):
    copy = tmp / "web"
    shutil.copytree(ROOT / "web", copy, ignore=shutil.ignore_patterns("node_modules", ".wrangler"), symlinks=True)
    shutil.copytree(ROOT / "site", tmp / "site")
    os.symlink(ROOT / "web/node_modules", copy / "node_modules")
    results = []
    only = sys.argv[1:]
    for suite in SUITES:
        code, text, _ = run(copy, suite)
        print(f"baseline {suite}: {'ok' if code == 0 else 'FAIL'}", flush=True)
        if code != 0:
            print(text[-2800:])
            return 2
    for m in MUTATIONS:
        suite, name, fname, old, new = m[0], m[1], m[2], m[3], m[4]
        which = m[5] if len(m) > 5 else 1
        if only and not any(o in name for o in only):
            continue
        path = copy / fname
        original = path.read_text(encoding="utf-8")
        mutated = apply(original, old, new, which)
        if mutated is None or mutated == original:
            results.append({"mutation": name, "status": "NOT_APPLIED"})
            print(f"NOT_APPLIED {name}", flush=True)
            continue
        t0 = time.time()
        path.write_text(mutated, encoding="utf-8")
        try:
            code, text, late = run(copy, suite)
        finally:
            path.write_text(original, encoding="utf-8")
        failed_lines = [l for l in text.splitlines() if l.startswith("FAIL ")]
        failing = [l.split()[1].rstrip(":") for l in failed_lines]
        # Only a test that names the failure counts. A suite that did not start or did not finish says
        # nothing about the mutation.
        status = "caught" if failing else ("SURVIVED" if code == 0 else "NO_RESULT")
        # The messages stay: a test that fails for a reason other than the mutation can only be read here.
        results.append({"mutation": name, "status": status, "suite": suite, "failing": failing, "why": [l[:400] for l in failed_lines], "ran_out_of_time": late})
        print(f"{status:11} {name} ({time.time()-t0:.0f}s{', ran out of time' if late else ''}) {failing[:2]}", flush=True)
    # The results above stand only if the suites still pass once the file is back.
    for suite in SUITES:
        code, text, _ = run(copy, suite)
        print(f"afterwards {suite}: {'ok' if code == 0 else 'FAIL'}", flush=True)
        if code != 0:
            print(text[-2800:])
            raise Void(f"{suite} no longer passes without a mutation")
    record = HERE / "mutation_results.json"
    if only and record.exists():
        kept = {r["mutation"]: r for r in json.loads(record.read_text(encoding="utf-8"))}
        kept.update({r["mutation"]: r for r in results})
        order = [m[1] for m in MUTATIONS]
        whole = sorted((r for r in kept.values() if r["mutation"] in order), key=lambda r: order.index(r["mutation"]))
    else:
        whole = results
    record.write_text(json.dumps(whole, ensure_ascii=False, indent=1), encoding="utf-8")
    bad = [r for r in results if r["status"] != "caught"]
    print(f"\n{len(results) - len(bad)}/{len(results)} caught; not caught: {[r['mutation'] for r in bad]}", flush=True)
    print("DONE", flush=True)
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
