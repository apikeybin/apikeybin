#!/usr/bin/env python3
"""Known answers for the link format, from the second implementation in verify/web-real/common.py.

    verify/web-threat/.venv/bin/python verify/kat/gen_link_kat.py > crates/apikeybin-core/tests/data/link_kat.txt
"""
import hashlib, sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "web-real"))
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from common import AAD, b64u, key_of, pad_content, token_of

secret = bytes(range(32))
iv = bytes(range(100, 112))
salt = bytes(range(200, 216))
text = "STRIPE_KEY=sk_live_$abc\n日本語🔑\n".encode()
pass_ = "correct horse バッテリー"

print("SECRET", secret.hex())
print("IV", iv.hex())
print("SALT", salt.hex())
print("TEXT", text.hex())
print("PASS", pass_.encode().hex())
print("TOKEN", token_of(secret).hex())
print("TOKEN_HASH", b64u(hashlib.sha256(token_of(secret)).digest()).encode().hex())
print("CT_PLAIN", AESGCM(key_of(secret, None, None)).encrypt(iv, pad_content(text), AAD).hex())
print("CT_PASS", AESGCM(key_of(secret, pass_, salt)).encrypt(iv, pad_content(text), AAD).hex())
print("NAME", ".env.local".encode().hex())
print("CT_NAMED", AESGCM(key_of(secret, None, None)).encrypt(iv, pad_content(text, ".env.local"), AAD).hex())
