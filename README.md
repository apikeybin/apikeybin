# APIキー便 (apikeybin)

API keys and `.env` files, handed over without a server being able to read them.

**Status: pre-release. Not audited. Do not trust it with real secrets yet.**

What exists today: the protocol core (`crates/apikeybin-core`), the browser version (`web/` and
`site/`, not deployed), a CLI that makes and opens the same links (`crates/apikeybin-cli`), and the
tests that try to break them. Text and text files such as `.env` can be sent, up to 64 KB. The file
name is encrypted with the content. Direct transfer between your own devices is not built yet.

- Design and threat model: [`docs/SPEC.md`](docs/SPEC.md)
- How the claims were tested, and how to run the tests yourself: [`verify/README.md`](verify/README.md)

## What this cannot protect against

Said up front because it matters more than the feature list.

1. Who talked to whom and when is visible to relays and network operators.
2. Malware running as you can read the secret once it is decrypted.
3. The `x-wing` crate has not been independently audited, and neither has this code.
4. Whatever a browser version does, a compromised web server could serve code that steals
   the secret. Page security headers cannot stop that. `apikeybin open` decrypts on your machine
   and avoids this. `docs/SPEC.md` §19 has the measurements.
5. `apikeybin.com` shows Google ads. The tool runs in a frame from another origin, so the ad script
   cannot read it, but a compromised ad script could replace the frame with a fake form.
   `app.apikeybin.com` has no ads and no third-party code. The page that shows the content never has
   ads, but a person opening a link passes through a page on `apikeybin.com` first, which may show
   image ads and runs no ad script. The key and the id stay behind on `app.apikeybin.com` and never
   reach that page. If `apikeybin.com` itself were compromised, that page could send the person to a
   fake page, so check the address. `apikeybin open` skips it.
6. If what you send is valuable for a long time, no transport fixes that. Prefer short-lived,
   narrowly scoped keys.

## License

Licensed under either of

- Apache License, Version 2.0 ([`LICENSE-APACHE`](LICENSE-APACHE))
- MIT license ([`LICENSE-MIT`](LICENSE-MIT))

at your option.

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in this
work by you, as defined in the Apache-2.0 license, shall be dual licensed as above, without any
additional terms or conditions.
