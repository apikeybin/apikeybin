# Threat model

The full text is in [`SPEC.md`](SPEC.md), in Japanese. This is where to look.

| What | Where |
|---|---|
| Who the attackers are and what stops them, for the direct transfer between devices | §3.1 |
| What cannot be reduced to zero, for the direct transfer | §3.2 |
| What the browser version cannot protect against | §19.5 |
| What was measured, with hostile scripts in three browsers | §19.6 |

In short, for the browser version:

1. If `app.apikeybin.com` itself is compromised, secrets can be stolen. Headers cannot prevent that,
   because whoever controls the server controls the headers. `apikeybin open` decrypts on your machine
   and avoids this.
2. If Google's ad script is compromised, it can replace the framed tool on `apikeybin.com` with a fake
   form. `app.apikeybin.com` has no ads and no third-party code.
3. Malware on the reader's device and browser extensions are out of reach.
4. The browser's history keeps the link with its key. After reading it is worthless; before reading
   it is not. A passphrase reduces this.
5. Software that presses the button, not only fetches the page, can use a link up first.
6. A lookalike domain cannot be prevented. Check the address.
7. The content cannot be inspected, so abuse cannot be searched for. Short lifetimes, one read, a size
   limit and a place to report reduce it.

This code has not been independently audited.
