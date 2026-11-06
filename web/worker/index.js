// The server's whole job: keep a ciphertext for a while, hand it over once, then forget it.
//
// It never sees a key. The link's secret stays after the "#", which browsers do not send.
// To read a record the client proves it holds that secret by presenting a token derived from
// it, and the server keeps only a hash of the token. So knowing a link's path (from a log, a
// history sync, anything) is not enough to read the ciphertext or to burn the secret.

const BUCKETS = new Set([1024, 4096, 16384, 65536]);
const AEAD_TAG = 16;
const TTLS = new Set([600, 3600, 86400, 604800]);
const MAX_BODY = 96 * 1024;
const STORAGE_CAP = 400 * 1000 * 1000; // The free database stops at 500 MB.
// What a row takes beyond its ciphertext text: the other columns, the index and the page it sits on.
const ROW_OVERHEAD = 1024;
// A row bigger than one of these 16 KiB records is "large". Large records take four times the room,
// so each counts four times against the rate limit, and together they may fill only half the store:
// a flood of them still leaves room for an ordinary key.
const LARGE_ROW = Math.ceil(((16384 + AEAD_TAG) * 4) / 3) + ROW_OVERHEAD;
const LARGE_WEIGHT = 4;
const LARGE_CAP = STORAGE_CAP / 2;
const ID_RE = /^[A-Za-z0-9_-]{22}$/;
const B64U_RE = /^[A-Za-z0-9_-]*$/;
const B64U = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';

// Kept identical to public/_headers. A test compares them.
const SECURITY_HEADERS = {
  'Content-Security-Policy':
    "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self'; " +
    "base-uri 'none'; form-action 'none'; frame-ancestors 'none'; " +
    "require-trusted-types-for 'script'; trusted-types 'none'",
  'Referrer-Policy': 'no-referrer',
  'X-Content-Type-Options': 'nosniff',
  'X-Frame-Options': 'DENY',
  'Cross-Origin-Opener-Policy': 'same-origin',
  'Cross-Origin-Resource-Policy': 'same-origin',
  'Cross-Origin-Embedder-Policy': 'require-corp',
  'Origin-Agent-Cluster': '?1',
  'Permissions-Policy':
    'accelerometer=(), camera=(), geolocation=(), gyroscope=(), magnetometer=(), microphone=(), ' +
    'payment=(), usb=(), clipboard-read=(), clipboard-write=(self)',
  'Strict-Transport-Security': 'max-age=63072000; includeSubDomains; preload',
};

function withHeaders(response, extra) {
  const out = new Response(response.body, response);
  for (const [name, value] of Object.entries(SECURITY_HEADERS)) out.headers.set(name, value);
  for (const [name, value] of Object.entries(extra)) out.headers.set(name, value);
  out.headers.delete('Set-Cookie');
  return out;
}

function json(status, body, extra = {}) {
  return withHeaders(
    new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } }),
    { 'Cache-Control': 'no-store', ...extra },
  );
}

const fail = (status, code, extra) => json(status, { error: code }, extra);

/** True if text is the unpadded, canonical base64url of exactly n bytes. */
function isB64u(text, n) {
  if (typeof text !== 'string' || text.length !== Math.ceil((n * 4) / 3) || !B64U_RE.test(text)) return false;
  const rem = n % 3;
  if (rem === 0) return true;
  const last = B64U.indexOf(text[text.length - 1]);
  return rem === 1 ? (last & 0x0f) === 0 : (last & 0x03) === 0;
}

function decodeB64u(text) {
  const bytes = new Uint8Array(Math.floor((text.length * 3) / 4));
  let acc = 0;
  let bits = 0;
  let at = 0;
  for (const ch of text) {
    acc = (acc << 6) | B64U.indexOf(ch);
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      bytes[at++] = (acc >> bits) & 0xff;
    }
  }
  return bytes;
}

function encodeB64u(bytes) {
  let out = '';
  let acc = 0;
  let bits = 0;
  for (const byte of bytes) {
    acc = (acc << 8) | byte;
    bits += 8;
    while (bits >= 6) {
      bits -= 6;
      out += B64U[(acc >> bits) & 0x3f];
    }
    acc &= (1 << bits) - 1;
  }
  if (bits > 0) out += B64U[(acc << (6 - bits)) & 0x3f];
  return out;
}

async function sha256b64u(bytes) {
  return encodeB64u(new Uint8Array(await crypto.subtle.digest('SHA-256', bytes)));
}

/**
 * Applies to every API request. There are no cookies, so a cross-site request carries no
 * authority of its own, but refusing it is still cheap and removes a whole class of questions.
 * The custom header cannot be set cross-site without a preflight, and there is no CORS here.
 * CLI clients send no Sec-Fetch-Site, which is why absence is allowed.
 */
function refuseForeign(request) {
  if (request.headers.get('X-Apikeybin') !== '1') return fail(403, 'forbidden');
  const site = request.headers.get('Sec-Fetch-Site');
  if (site !== null && site !== 'same-origin') return fail(403, 'forbidden');
  const type = (request.headers.get('Content-Type') || '').split(';')[0].trim().toLowerCase();
  if (type !== 'application/json') return fail(415, 'unsupported_media_type');
  return null;
}

/** Reads at most MAX_BODY bytes however the length is declared, and rejects anything else that isn't an object. */
async function readObject(request) {
  const declared = request.headers.get('Content-Length');
  if (declared !== null && Number(declared) > MAX_BODY) return { error: fail(413, 'too_large') };
  if (!request.body) return { error: fail(400, 'bad_request') };
  const reader = request.body.getReader();
  const chunks = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.length;
    if (total > MAX_BODY) {
      await reader.cancel();
      return { error: fail(413, 'too_large') };
    }
    chunks.push(value);
  }
  const bytes = new Uint8Array(total);
  let at = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, at);
    at += chunk.length;
  }
  try {
    const value = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes));
    if (value === null || typeof value !== 'object' || Array.isArray(value)) throw new Error('shape');
    return { value };
  } catch {
    return { error: fail(400, 'bad_request') };
  }
}

function onlyFields(value, allowed) {
  return Object.keys(value).every((key) => allowed.includes(key));
}

const clientKey = (request) => request.headers.get('CF-Connecting-IP') || 'unknown';
const today = () => new Date().toISOString().slice(0, 10);
const nowSeconds = () => Math.floor(Date.now() / 1000);

async function create(request, env, ctx) {
  const refused = refuseForeign(request);
  if (refused) return refused;
  const { success } = await env.RL_CREATE.limit({ key: clientKey(request) });
  if (!success) return fail(429, 'slow_down', { 'Retry-After': '60' });

  const { value: b, error } = await readObject(request);
  if (error) return error;
  if (!onlyFields(b, ['v', 'iv', 'ct', 'token_hash', 'ttl', 'pw', 'salt'])) return fail(400, 'bad_request');
  if (b.v !== 1 || !TTLS.has(b.ttl) || typeof b.pw !== 'boolean') return fail(400, 'bad_request');
  if (!isB64u(b.iv, 12) || !isB64u(b.token_hash, 32)) return fail(400, 'bad_request');
  if (b.pw ? !isB64u(b.salt, 16) : b.salt !== undefined) return fail(400, 'bad_request');
  // The ciphertext must be exactly a bucket plus the tag. Nothing else fits a padded secret,
  // and this keeps the store from being a general place to put arbitrary sizes of data.
  let size = 0;
  for (const bucket of BUCKETS) if (isB64u(b.ct, bucket + AEAD_TAG)) size = b.ct.length + ROW_OVERHEAD;
  if (size === 0) return fail(400, 'bad_size');
  const large = size > LARGE_ROW ? size : 0;
  if (large) {
    // The call at the top of this function was the first of them.
    for (let i = 1; i < LARGE_WEIGHT; i++) {
      const { success: within } = await env.RL_CREATE.limit({ key: clientKey(request) });
      if (!within) return fail(429, 'slow_down', { 'Retry-After': '60' });
    }
  }

  const id = encodeB64u(crypto.getRandomValues(new Uint8Array(16)));
  const expiresAt = nowSeconds() + b.ttl;
  const [reserved, inserted] = await env.DB.batch([
    env.DB.prepare(
      'UPDATE usage SET bytes = bytes + ?1, large = large + ?2 WHERE id = 1 AND bytes + ?1 <= ?3 AND large + ?2 <= ?4',
    ).bind(size, large, STORAGE_CAP, LARGE_CAP),
    env.DB.prepare(
      'INSERT INTO secrets (id, token_hash, iv, ct, salt, pw, size, expires_at) ' +
        'SELECT ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8 WHERE changes() = 1',
    ).bind(id, b.token_hash, b.iv, b.ct, b.salt ?? null, b.pw ? 1 : 0, size, expiresAt),
  ]);
  if (reserved.meta.changes !== 1 || inserted.meta.changes !== 1) return fail(507, 'full');
  ctx.waitUntil(count(env, 'created'));
  return json(201, { id, expires_at: expiresAt });
}

async function open(request, env, ctx, id) {
  const refused = refuseForeign(request);
  if (refused) return refused;
  const { success } = await env.RL_OPEN.limit({ key: clientKey(request) });
  if (!success) return fail(429, 'slow_down', { 'Retry-After': '60' });
  if (!ID_RE.test(id)) return fail(404, 'gone');

  const { value: b, error } = await readObject(request);
  if (error) return error;
  if (!onlyFields(b, ['token']) || !isB64u(b.token, 32)) return fail(400, 'bad_request');

  // One statement, so two readers cannot both win. Every way of not finding the row gives the
  // same answer: opened already, expired, never existed, or the wrong token.
  const tokenHash = await sha256b64u(decodeB64u(b.token));
  const row = await env.DB.prepare(
    'DELETE FROM secrets WHERE id = ?1 AND token_hash = ?2 AND expires_at > ?3 RETURNING iv, ct, salt, pw, size',
  )
    .bind(id, tokenHash, nowSeconds())
    .first();
  if (!row) return fail(404, 'gone');

  ctx.waitUntil(
    Promise.all([
      env.DB.prepare('UPDATE usage SET bytes = MAX(0, bytes - ?1), large = MAX(0, large - ?2) WHERE id = 1')
        .bind(row.size, row.size > LARGE_ROW ? row.size : 0)
        .run(),
      count(env, 'opened'),
    ]),
  );
  const out = { v: 1, iv: row.iv, ct: row.ct, pw: row.pw === 1 };
  if (row.salt) out.salt = row.salt;
  return json(200, out);
}

const COUNTS = {
  created: 'INSERT INTO daily (day, created) VALUES (?1, 1) ON CONFLICT (day) DO UPDATE SET created = created + 1',
  opened: 'INSERT INTO daily (day, opened) VALUES (?1, 1) ON CONFLICT (day) DO UPDATE SET opened = opened + 1',
  tool_loads: 'INSERT INTO daily (day, tool_loads) VALUES (?1, 1) ON CONFLICT (day) DO UPDATE SET tool_loads = tool_loads + 1',
};

function count(env, column) {
  return env.DB.prepare(COUNTS[column]).bind(today()).run();
}

/** The reading page, at /s/<id> and at /open where the reader returns from the page with ads. It
 * is the same file for every id and looks nothing up, so opening a link says nothing about whether
 * the record exists and cannot consume it. The server never redirects here, because a redirect
 * would carry the fragment along to wherever it pointed. */
async function secretPage(request, env) {
  const url = new URL(request.url);
  const asset = await env.ASSETS.fetch(new Request(`${url.origin}/s`, { method: request.method }));
  if (asset.status !== 200) return fail(500, 'server_error');
  return withHeaders(asset, {
    'Cache-Control': 'no-store',
    'X-Robots-Tag': 'noindex, nofollow, noarchive',
  });
}

/** The only page that may sit in a frame, and only in a frame on the site. Everything else
 * stays frame-ancestors 'none'. The site runs Google's ad script at its top level; that script
 * cannot read this page because they are different origins. With no SITE_ORIGIN set, nothing
 * may frame it: this fails closed. */
async function embedPage(request, env, ctx) {
  const url = new URL(request.url);
  const asset = await env.ASSETS.fetch(new Request(`${url.origin}/embed`, { method: request.method }));
  if (asset.status !== 200) return fail(500, 'server_error');
  const site = /^https?:\/\/[a-z0-9.:-]+$/.test(env.SITE_ORIGIN || '') ? env.SITE_ORIGIN : "'none'";
  const out = withHeaders(asset, {
    'Cache-Control': 'no-cache',
    'X-Robots-Tag': 'noindex, nofollow, noarchive',
    'Content-Security-Policy': SECURITY_HEADERS['Content-Security-Policy'].replace(
      "frame-ancestors 'none'",
      `frame-ancestors ${site}`,
    ),
  });
  out.headers.delete('X-Frame-Options');
  // Links made per load of the tool is how a change to the page around it gets judged.
  if (request.method === 'GET') ctx.waitUntil(count(env, 'tool_loads'));
  return out;
}

async function route(request, env, ctx) {
  const { pathname } = new URL(request.url);
  const method = request.method;

  if (pathname === '/api/s') {
    return method === 'POST' ? create(request, env, ctx) : fail(405, 'method_not_allowed', { Allow: 'POST' });
  }
  const opening = pathname.match(/^\/api\/s\/([^/]+)\/open$/);
  if (opening) {
    return method === 'POST'
      ? open(request, env, ctx, opening[1])
      : fail(405, 'method_not_allowed', { Allow: 'POST' });
  }
  if (pathname === '/embed') {
    if (method !== 'GET' && method !== 'HEAD') return fail(405, 'method_not_allowed', { Allow: 'GET, HEAD' });
    return embedPage(request, env, ctx);
  }
  if (pathname === '/open') {
    if (method !== 'GET' && method !== 'HEAD') return fail(405, 'method_not_allowed', { Allow: 'GET, HEAD' });
    return secretPage(request, env);
  }
  if (pathname.startsWith('/s/')) {
    if (method !== 'GET' && method !== 'HEAD') return fail(405, 'method_not_allowed', { Allow: 'GET, HEAD' });
    return ID_RE.test(pathname.slice(3)) ? secretPage(request, env) : fail(404, 'not_found');
  }
  return fail(404, 'not_found');
}

async function purge(env) {
  const now = nowSeconds();
  await env.DB.batch([
    env.DB.prepare('DELETE FROM secrets WHERE expires_at <= ?1').bind(now),
    env.DB.prepare(
      'UPDATE usage SET bytes = (SELECT COALESCE(SUM(size), 0) FROM secrets), ' +
        'large = (SELECT COALESCE(SUM(size), 0) FROM secrets WHERE size > ?1) WHERE id = 1',
    ).bind(LARGE_ROW),
  ]);
}

export default {
  async fetch(request, env, ctx) {
    try {
      return await route(request, env, ctx);
    } catch {
      // Say nothing specific, and log nothing: there is nothing here worth keeping.
      return fail(500, 'server_error');
    }
  },
  async scheduled(_event, env, ctx) {
    ctx.waitUntil(purge(env));
  },
};
