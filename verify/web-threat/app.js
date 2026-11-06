// Minimal browser flow under test: encrypt in the page, key only in the URL fragment,
// server holds ciphertext, reading requires a click. Fixture for harness.py, not the product.
'use strict';

const $ = (id) => document.getElementById(id);

function enc(buf) {
  const bytes = new Uint8Array(buf);
  let s = '';
  for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function dec(text) {
  const b = text.replace(/-/g, '+').replace(/_/g, '/');
  const s = atob(b + '==='.slice((b.length + 3) % 4));
  const out = new Uint8Array(s.length);
  for (let i = 0; i < s.length; i++) out[i] = s.charCodeAt(i);
  return out;
}

async function make() {
  const text = $('in').value;
  const key = crypto.getRandomValues(new Uint8Array(32));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const k = await crypto.subtle.importKey('raw', key, 'AES-GCM', false, ['encrypt']);
  const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, k, new TextEncoder().encode(text));
  const res = await fetch('/api/s', { method: 'POST', body: JSON.stringify({ iv: enc(iv), ct: enc(ct) }) });
  const { id } = await res.json();
  $('link').textContent = location.origin + '/s/' + id + '#' + enc(key);
}

async function reveal() {
  const id = location.pathname.split('/').pop();
  const keyText = location.hash.slice(1);
  history.replaceState(null, '', location.pathname);
  const res = await fetch('/api/s/' + id + '/consume', { method: 'POST', headers: { 'X-Apikeybin': '1' } });
  if (!res.ok) {
    $('status').textContent = 'gone';
    return;
  }
  const rec = await res.json();
  try {
    const k = await crypto.subtle.importKey('raw', dec(keyText), 'AES-GCM', false, ['decrypt']);
    const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: dec(rec.iv) }, k, dec(rec.ct));
    const text = new TextDecoder().decode(pt);
    $('secret').textContent = text;
    $('status').textContent = 'ok';
  } catch (e) {
    $('status').textContent = 'tampered';
  }
}

window.addEventListener('DOMContentLoaded', () => {
  if ($('make')) $('make').addEventListener('click', make);
  if ($('reveal')) $('reveal').addEventListener('click', reveal);
});
