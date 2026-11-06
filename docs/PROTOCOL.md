# Protocol

The full text is in [`SPEC.md`](SPEC.md), in Japanese. This is where to look.

| What | Where |
|---|---|
| The link format used by the browser version and the CLI | §19.2 |
| The server's API | §19.3 |
| Direct transfer between devices: messages, transcript, keys, padding | §7 |
| Pairing | §6 |

The link format, in short:

```
secret  = random[32]                         # after the "#" in the link. Never sent to the server
token   = HKDF-SHA256(secret, info = "apikeybin/link/1/token")
key     = HKDF-SHA256(secret, info = "apikeybin/link/1/key")
          # with a passphrase: HKDF-SHA256(secret || PBKDF2-HMAC-SHA256(NFC(passphrase), salt = random[16], 600000), info = "apikeybin/link/1/key+pw")
          # HKDF's own salt is empty. The output is 32 bytes.
frame   = u16 name length || file name, if any || content      # lengths are big-endian
padded  = u32 length of frame || frame || zeros, up to 1, 4, 16 or 64 KiB
body    = AES-256-GCM(key, iv = random[12], padded, aad = "apikeybin/link/1")
link    = https://app.apikeybin.com/s/<id>#1.<secret>     # with a passphrase: #1p.<secret>
```

The server keeps `SHA-256(token)`, the ciphertext, the expiry and the passphrase's salt. Reading a
record means showing the token, and removes the record in the same statement.

`verify/web-real/common.py` is a second implementation in Python. `web/public/app.js`,
`crates/apikeybin-core/src/link.rs` and that file read and write each other's records in the tests.
