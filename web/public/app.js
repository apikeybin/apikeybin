// The whole client. No dependencies, nothing loaded from anywhere else, and every piece of
// text comes from the HTML: this file only encrypts, decrypts and switches which part shows.
//
// Link format:  /s/<id>#1.<secret>  or  /s/<id>#1p.<secret>  (p: a passphrase is also needed)
//   secret  32 random bytes, base64url. Stays after the "#", so it never reaches the server.
//   token   HKDF(secret, "apikeybin/link/1/token"). Proves to the server that you hold the link.
//   key     HKDF(secret, "apikeybin/link/1/key"), or with a passphrase
//           HKDF(secret || PBKDF2(passphrase, salt), "apikeybin/link/1/key+pw")
//   body    AES-256-GCM(key, random iv, pad(frame(name, content)), aad = "apikeybin/link/1")
//   frame   u16 name length || file name, if any || content. The name is encrypted with the rest.
// docs/SPEC.md has the reasoning, and verify/web-real has a second implementation in Python.
'use strict';

(() => {
  const BUCKETS = [1024, 4096, 16384, 65536];
  const LEN_PREFIX = 4;
  const NAME_PREFIX = 2;
  const MAX_NAME = 128;
  // Whether a file that is not text can be sent from this page. Reading one always works.
  const BINARY_OPEN = false;
  const PBKDF2_ITERATIONS = 600000;
  const AAD = new TextEncoder().encode('apikeybin/link/1');
  const FRAGMENT = /^#(1p?)\.([A-Za-z0-9_-]{43})$/;
  const ID = /^[A-Za-z0-9_-]{22}$/;
  // Control characters, separators, and invisible or direction-changing characters. A file name
  // comes from someone else and ends up on screen and on disk.
  const BAD_NAME =
    /[\u0000-\u001f\u007f-\u009f/\\:\u00ad\u034f\u061c\u115f\u1160\u17b4\u17b5\u180b-\u180f\u200b-\u200f\u2028\u2029\u202a-\u202e\u2060-\u206f\u3164\ufe00-\ufe0f\ufeff\uffa0\ufff0-\ufffb\u{1bca0}-\u{1bca3}\u{1d173}-\u{1d17a}\u{e0000}-\u{e0fff}]/u;
  // Spaces at either end, or a dot at the end. Some systems drop them on saving, which would turn
  // "a.html." into "a.html" after the check below has looked at it.
  const BAD_ENDS =
    /^\s|[\s.]$/u;
  // Saved under their own name. Anything else gets .txt added: what a double click does depends on
  // the machine, and the list of file types that run something keeps growing.
  const KEEPS_ITS_NAME =
    /^[^.]*$|^\.?env\.(local|dev|development|prod|production|stage|staging|test|testing|example|sample|preview|ci)$|\.(env|txt|json|yaml|yml|toml|ini|conf|cfg|properties|pem|key|p8|pub|md|log|p12|pfx|jks|keystore|bks|der|cer|crt|gpg|pgp|asc|ppk|kdbx|bin)$/i;

  // On the real site, a reader passes through the page with ads before seeing the content. The
  // key stays in this origin's sessionStorage for that trip, so it never reaches that page.
  const APP_ORIGIN = 'https://app.apikeybin.com';
  // #go is the same for everyone. That page shows its button only to someone who arrives with it.
  const CUSHION = 'https://apikeybin.com/open#go';
  const PENDING = 'apikeybin.pending';
  const PENDING_MAX_AGE_MS = 60 * 60 * 1000;

  const $ = (id) => document.getElementById(id);
  const encoder = new TextEncoder();

  function show(element, visible) {
    element.hidden = !visible;
  }

  function toB64u(bytes) {
    let text = '';
    for (const byte of bytes) text += String.fromCharCode(byte);
    return btoa(text).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  }

  function fromB64u(text) {
    const plain = text.replace(/-/g, '+').replace(/_/g, '/');
    const raw = atob(plain + '==='.slice((plain.length + 3) % 4));
    const out = new Uint8Array(raw.length);
    for (let i = 0; i < raw.length; i++) out[i] = raw.charCodeAt(i);
    return out;
  }

  async function hkdf(ikm, info) {
    const base = await crypto.subtle.importKey('raw', ikm, 'HKDF', false, ['deriveBits']);
    const bits = await crypto.subtle.deriveBits(
      { name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(0), info: encoder.encode(info) },
      base,
      256,
    );
    return new Uint8Array(bits);
  }

  async function aesKey(secret, passphrase, salt) {
    let raw;
    if (passphrase === null) {
      raw = await hkdf(secret, 'apikeybin/link/1/key');
    } else {
      const base = await crypto.subtle.importKey(
        'raw',
        encoder.encode(passphrase.normalize('NFC')),
        'PBKDF2',
        false,
        ['deriveBits'],
      );
      const stretched = new Uint8Array(
        await crypto.subtle.deriveBits(
          { name: 'PBKDF2', hash: 'SHA-256', salt, iterations: PBKDF2_ITERATIONS },
          base,
          256,
        ),
      );
      const ikm = new Uint8Array(secret.length + stretched.length);
      ikm.set(secret);
      ikm.set(stretched, secret.length);
      raw = await hkdf(ikm, 'apikeybin/link/1/key+pw');
      ikm.fill(0);
      stretched.fill(0);
    }
    const key = await crypto.subtle.importKey('raw', raw, 'AES-GCM', false, ['encrypt', 'decrypt']);
    raw.fill(0);
    return key;
  }

  function validName(name) {
    const length = encoder.encode(name).length;
    return length > 0 && length <= MAX_NAME && !BAD_NAME.test(name) && !BAD_ENDS.test(name);
  }

  /** The content as text, or null if it is not text: then it is only saved, never displayed. */
  function textOf(bytes) {
    if (bytes.includes(0)) return null;
    try {
      return new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes);
    } catch {
      return null;
    }
  }

  /** The file name, if there is one, then the content. */
  function frame(name, content) {
    const nameBytes = name === null ? new Uint8Array(0) : encoder.encode(name);
    const out = new Uint8Array(NAME_PREFIX + nameBytes.length + content.length);
    new DataView(out.buffer).setUint16(0, nameBytes.length);
    out.set(nameBytes, NAME_PREFIX);
    out.set(content, NAME_PREFIX + nameBytes.length);
    return out;
  }

  /** Refuses a name that could not have been sent by this page: it came from someone else. */
  function unframe(body) {
    if (body.length < NAME_PREFIX) return null;
    const length = new DataView(body.buffer, body.byteOffset).getUint16(0);
    if (length > MAX_NAME || body.length < NAME_PREFIX + length) return null;
    const content = body.subarray(NAME_PREFIX + length);
    if (length === 0) return { name: null, content };
    let name;
    try {
      name = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(body.subarray(NAME_PREFIX, NAME_PREFIX + length));
    } catch {
      return null;
    }
    return validName(name) ? { name, content } : null;
  }

  /** Length prefix, the data, then zeros up to a fixed size, so only a size class is visible. */
  function pad(bytes) {
    const bucket = BUCKETS.find((size) => size >= bytes.length + LEN_PREFIX);
    if (bucket === undefined) return null;
    const out = new Uint8Array(bucket);
    new DataView(out.buffer).setUint32(0, bytes.length);
    out.set(bytes, LEN_PREFIX);
    return out;
  }

  /** Accepts only what pad produces. */
  function unpad(padded) {
    if (!BUCKETS.includes(padded.length)) return null;
    const length = new DataView(padded.buffer, padded.byteOffset).getUint32(0);
    if (length > padded.length - LEN_PREFIX) return null;
    for (let i = LEN_PREFIX + length; i < padded.length; i++) {
      if (padded[i] !== 0) return null;
    }
    return padded.subarray(LEN_PREFIX, LEN_PREFIX + length);
  }

  async function api(path, body) {
    return fetch(path, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-Apikeybin': '1' },
      body: JSON.stringify(body),
      credentials: 'omit',
      cache: 'no-store',
      redirect: 'error',
      referrerPolicy: 'no-referrer',
    });
  }

  /** Selects the text as well, so that if the browser refuses, copying by hand is one step. */
  async function copyFrom(element, doneLabel) {
    const selection = window.getSelection();
    selection.selectAllChildren(element);
    try {
      await navigator.clipboard.writeText(element.textContent);
      show(doneLabel, true);
      setTimeout(() => show(doneLabel, false), 3000);
    } catch {
      // Blocked or unsupported: the text is selected and can be copied by hand.
    }
  }

  /** Runs before the page is left. WebKit saves form fields into the history entry before
   * pagehide fires and restores them on Back, so anything left in a field would stay in the
   * browser. Secrets on screen are not in form fields for that reason. */
  function wipeOnLeaving(wipe) {
    window.addEventListener('beforeunload', wipe);
    window.addEventListener('pagehide', wipe);
  }

  function savePending(id, fragment) {
    try {
      sessionStorage.setItem(PENDING, JSON.stringify({ id, fragment, at: Date.now() }));
      return sessionStorage.getItem(PENDING) !== null;
    } catch {
      return false;
    }
  }

  function clearPending() {
    try {
      sessionStorage.removeItem(PENDING);
    } catch {
      // Nothing stored, then.
    }
  }

  function loadPending() {
    try {
      const value = JSON.parse(sessionStorage.getItem(PENDING));
      if (value && Date.now() - value.at < PENDING_MAX_AGE_MS) return value;
    } catch {
      // Unreadable is the same as absent.
    }
    clearPending();
    return null;
  }

  // --------------------------------------------------------------- creating a link
  function initCreate() {
    const text = $('text');
    const passphrase = $('passphrase');
    const ttl = $('ttl');
    const form = $('create');
    const result = $('result');
    const link = $('link');
    const fileInput = $('file');
    const errors = {
      empty: $('err-empty'),
      big: $('err-big'),
      binary: $('err-binary'),
      read: $('err-read'),
      name: $('err-name'),
      slow: $('err-slow'),
      full: $('err-full'),
      net: $('err-net'),
    };
    // The chosen file, held here instead of being shown in the box.
    let picked = null;

    function showError(which) {
      for (const [name, element] of Object.entries(errors)) show(element, name === which);
    }

    function clearFile() {
      if (picked) picked.bytes.fill(0);
      picked = null;
      fileInput.value = '';
      $('file-name').textContent = '';
      show($('file-chip'), false);
      show($('text-area'), true);
    }

    async function pick(file) {
      showError(null);
      clearFile();
      if (file.size > BUCKETS[BUCKETS.length - 1]) return showError('big');
      if (!validName(file.name)) return showError('name');
      let bytes;
      try {
        bytes = new Uint8Array(await file.arrayBuffer());
      } catch {
        // A folder dragged in, or a file moved since it was chosen.
        return showError('read');
      }
      if (!BINARY_OPEN && textOf(bytes) === null) {
        bytes.fill(0);
        return showError('binary');
      }
      picked = { name: file.name, bytes };
      $('file-name').textContent = file.name;
      show($('file-chip'), true);
      show($('text-area'), false);
      return undefined;
    }

    async function make(event) {
      event.preventDefault();
      showError(null);
      const content = picked ? picked.bytes : encoder.encode(text.value);
      if (content.length === 0) return showError('empty');
      const padded = pad(frame(picked ? picked.name : null, content));
      if (padded === null) return showError('big');

      const button = $('make');
      button.disabled = true;
      try {
        const secret = crypto.getRandomValues(new Uint8Array(32));
        const iv = crypto.getRandomValues(new Uint8Array(12));
        const pw = passphrase.value.length > 0;
        const salt = pw ? crypto.getRandomValues(new Uint8Array(16)) : null;
        const key = await aesKey(secret, pw ? passphrase.value : null, salt);
        const ct = new Uint8Array(
          await crypto.subtle.encrypt({ name: 'AES-GCM', iv, additionalData: AAD }, key, padded),
        );
        const token = await hkdf(secret, 'apikeybin/link/1/token');
        const tokenHash = new Uint8Array(await crypto.subtle.digest('SHA-256', token));
        const body = {
          v: 1,
          iv: toB64u(iv),
          ct: toB64u(ct),
          token_hash: toB64u(tokenHash),
          ttl: Number(ttl.value),
          pw,
        };
        if (pw) body.salt = toB64u(salt);

        const response = await api('/api/s', body);
        if (response.status === 429) return showError('slow');
        if (response.status === 507) return showError('full');
        if (response.status !== 201) return showError('net');
        const { id } = await response.json();

        link.textContent = `${location.origin}/s/${id}#${pw ? '1p' : '1'}.${toB64u(secret)}`;
        $('expires-text').textContent = ttl.options[ttl.selectedIndex].textContent;
        show($('pw-note'), pw);
        text.value = '';
        passphrase.value = '';
        clearFile();
        show(form, false);
        show(result, true);
        $('copy-link').focus();
      } catch {
        showError('net');
      } finally {
        padded.fill(0);
        button.disabled = false;
      }
      return undefined;
    }

    form.addEventListener('submit', make);
    // The page starts with this off: pressed before this point, it would do nothing and say nothing.
    $('make').disabled = false;
    $('pick-file').addEventListener('click', () => fileInput.click());
    fileInput.addEventListener('change', () => {
      if (fileInput.files.length > 0) pick(fileInput.files[0]);
    });
    $('clear-file').addEventListener('click', clearFile);
    form.addEventListener('dragover', (event) => {
      event.preventDefault();
      form.classList.add('dragging');
    });
    form.addEventListener('dragleave', () => form.classList.remove('dragging'));
    form.addEventListener('drop', (event) => {
      event.preventDefault();
      form.classList.remove('dragging');
      if (event.dataTransfer.files.length > 0) pick(event.dataTransfer.files[0]);
    });
    $('copy-link').addEventListener('click', () => copyFrom(link, $('copied-link')));
    $('again').addEventListener('click', () => {
      link.textContent = '';
      show(result, false);
      show(form, true);
      text.focus();
    });
    wipeOnLeaving(() => {
      text.value = '';
      passphrase.value = '';
      link.textContent = '';
      clearFile();
    });
  }

  // --------------------------------------------------------------- reading a link
  function initRead() {
    const states = ['state-ask', 'state-shown', 'state-gone', 'state-badlink', 'state-nopending', 'state-error'];
    const setState = (name) => {
      for (const id of states) show($(id), id === name);
    };

    // Either the link itself, or the page coming back from the page with ads.
    const coming_back = location.pathname === '/open';
    let id;
    let fragment;
    if (coming_back) {
      const pending = loadPending();
      if (!pending) return setState('state-nopending');
      ({ id, fragment } = pending);
    } else {
      id = location.pathname.split('/').pop();
      fragment = location.hash;
    }
    const match = String(fragment).match(FRAGMENT);
    if (!match || !ID.test(String(id))) {
      clearPending();
      return setState('state-badlink');
    }

    if (!coming_back && location.origin === APP_ORIGIN && savePending(id, fragment)) {
      // The key leaves the address bar first, then the tab goes on without it. If storage is
      // unavailable this is skipped and the reader goes straight to the content.
      history.replaceState(null, '', '/open');
      location.replace(CUSHION);
      return undefined;
    }

    const needsPassphrase = match[1] === '1p';
    const secret = fromB64u(match[2]);
    const passphrase = $('read-passphrase');
    const output = $('output');
    const wrong = $('err-passphrase');
    const openButton = $('open');
    show($('pw-field'), needsPassphrase);
    setState('state-ask');

    // Kept once fetched: the server no longer has it, so a mistyped passphrase can be retried.
    let record = null;
    let fileName = null;
    let fileBytes = null;
    let fileIsText = true;

    async function reveal(event) {
      event.preventDefault();
      show(wrong, false);
      if (needsPassphrase && passphrase.value.length === 0) return show(wrong, true);
      openButton.disabled = true;
      try {
        if (record === null) {
          // The key leaves the address bar and storage now. The browser's history may still hold
          // it, which is why the record is gone from the server after this request.
          history.replaceState(null, '', location.pathname);
          clearPending();
          const token = await hkdf(secret, 'apikeybin/link/1/token');
          const response = await api(`/api/s/${encodeURIComponent(id)}/open`, { token: toB64u(token) });
          if (response.status === 404) return setState('state-gone');
          if (response.status !== 200) return setState('state-error');
          record = await response.json();
        }
        if (record.pw !== needsPassphrase) return setState('state-error');
        const salt = record.pw ? fromB64u(record.salt) : null;
        const key = await aesKey(secret, record.pw ? passphrase.value : null, salt);
        let plain;
        try {
          plain = new Uint8Array(
            await crypto.subtle.decrypt(
              { name: 'AES-GCM', iv: fromB64u(record.iv), additionalData: AAD },
              key,
              fromB64u(record.ct),
            ),
          );
        } catch {
          if (record.pw) {
            show(wrong, true);
            passphrase.select();
            return undefined;
          }
          return setState('state-error');
        }
        const body = unpad(plain);
        if (body === null) return setState('state-error');
        const framed = unframe(body);
        if (framed === null) return setState('state-error');
        const asText = textOf(framed.content);
        fileIsText = asText !== null;
        output.textContent = asText ?? '';
        show($('output-text'), fileIsText);
        show($('copy-output'), fileIsText);
        show($('hint-said'), fileIsText);
        show($('output-binary'), !fileIsText);
        $('save-output').className = fileIsText ? 'secondary' : 'primary';
        fileName = framed.name ?? (fileIsText ? 'apikeybin.txt' : 'apikeybin.bin');
        fileBytes = framed.content.slice();
        if (framed.name !== null) {
          $('output-name').textContent = framed.name;
          show($('output-file'), true);
          show($('hint-dot'), framed.name.startsWith('.'));
          show($('hint-txt'), fileIsText && !KEEPS_ITS_NAME.test(framed.name));
          show($('hint-bin'), !fileIsText && !KEEPS_ITS_NAME.test(framed.name));
        }
        plain.fill(0);
        secret.fill(0);
        passphrase.value = '';
        setState('state-shown');
      } catch {
        setState('state-error');
      } finally {
        openButton.disabled = false;
      }
      return undefined;
    }

    /** Saved as bytes, so what was sent is what arrives. Never opened by this page. */
    function save() {
      if (!fileBytes) return;
      const blob = new Blob([fileBytes], { type: 'application/octet-stream' });
      const url = URL.createObjectURL(blob);
      const anchor = document.createElement('a');
      anchor.href = url;
      anchor.download = KEEPS_ITS_NAME.test(fileName) ? fileName : `${fileName}.${fileIsText ? 'txt' : 'bin'}`;
      document.body.append(anchor);
      anchor.click();
      anchor.remove();
      setTimeout(() => URL.revokeObjectURL(url), 30000);
    }

    function forget() {
      output.textContent = '';
      passphrase.value = '';
      record = null;
      if (fileBytes) fileBytes.fill(0);
      fileBytes = null;
      fileName = null;
    }

    $('ask').addEventListener('submit', reveal);
    $('copy-output').addEventListener('click', () => copyFrom(output, $('copied-output')));
    $('save-output').addEventListener('click', save);
    $('clear-output').addEventListener('click', () => {
      forget();
      setState('state-gone');
      show($('gone-why'), false);
      show($('cleared'), true);
    });
    wipeOnLeaving(forget);
    return undefined;
  }

  if ($('create')) initCreate();
  if ($('ask')) initRead();
})();
