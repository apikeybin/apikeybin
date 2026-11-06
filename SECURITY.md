# Security

## Reporting a problem

Please report security problems privately, through GitHub's "Report a vulnerability" on this
repository, or by mail to contact@apikeybin.com. Please do not open a public issue for them.

There is no bounty. You will get an answer, and credit if you want it.

A real secret is never needed to show a problem. If you found a link being used for abuse, that is
not a security report: use https://apikeybin.com/report instead.

## What is in scope

- `web/`: anything that lets the server, another site, or a script on `apikeybin.com` read a secret or
  a key, or read or destroy a record without holding its link.
- `site/`: anything that carries a link's id or key to the page with ads.
- `crates/apikeybin-core` and `crates/apikeybin-cli`: anything that breaks the format, leaks a secret, or
  writes somewhere the reader did not choose.
- The tests: a check whose test still passes when the check is removed.

## What is already known

`docs/THREAT_MODEL.md` lists what this cannot protect against. A compromised web server or ad script,
malware on the reader's device, and browser extensions are on that list.

This code has not been independently audited.
