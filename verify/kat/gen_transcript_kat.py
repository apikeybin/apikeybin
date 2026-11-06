#!/usr/bin/env python3
"""Independent second implementation of the transcript and KDF rules, stdlib only.

Writes the expected values the Rust tests compare against, so a mistake in
transcript.rs cannot also be a mistake in its own test.
"""
import hashlib, hmac, sys

H = lambda *parts: hashlib.sha256(b"".join(parts)).digest()

def hkdf_sha256(ikm, salt, info, length):
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    okm, t, i = b"", b"", 1
    while len(okm) < length:
        t = hmac.new(prk, t + info + bytes([i]), hashlib.sha256).digest()
        okm += t
        i += 1
    return okm[:length]

eid_s = bytes([0x11]) * 32
eid_r = bytes([0x22]) * 32
offer_body = b"offer-body-bytes"
offer_frame = b"offer-frame-bytes"
accept_frame = b"accept-frame-bytes"
data_frame = b"data-frame-bytes"
id_ = bytes(range(16))
ek = bytes([0x33]) * 1216
ct = bytes([0x44]) * 1120
nonce = bytes([0x55]) * 24
body = b"ciphertext-body"
shared = bytes([0x66]) * 32

th0 = H(b"apikeybin/xfer/1", eid_s, eid_r)
offer_sig = b"apikeybin/offer" + H(th0, offer_body)
th1 = H(th0, offer_frame)
accept_sig = b"apikeybin/accept" + H(th1, id_, ek)
th2 = H(th1, accept_frame)
key = hkdf_sha256(shared, th2, b"apikeybin/xfer/payload/v1", 32)
ad = th2 + ct
data_sig = b"apikeybin/data" + H(th2, id_, ct, nonce, body)
th3 = H(th2, data_frame)
ack_sig = b"apikeybin/ack" + H(th3, id_, b"\x01")
ack_sig_false = b"apikeybin/ack" + H(th3, id_, b"\x00")
vault_kek = hkdf_sha256(bytes([0x77]) * 32, bytes([0x88]) * 32, b"apikeybin/vault-kek/v1", 32)

vals = dict(TH0=th0, OFFER_SIG=offer_sig, TH1=th1, ACCEPT_SIG=accept_sig, TH2=th2, PAYLOAD_KEY=key,
            AD_SHA=hashlib.sha256(ad).digest(), DATA_SIG=data_sig, TH3=th3, ACK_SIG=ack_sig,
            ACK_SIG_FALSE=ack_sig_false, VAULT_KEK=vault_kek)
for k, v in vals.items():
    print(f"{k} {v.hex()}")
