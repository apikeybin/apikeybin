# web-threat

A hostile script in real Chromium, WebKit and Firefox. All hosts are reserved `.test` names
fulfilled inside Playwright, and a request to any other host fails the run.

```
python3 -m venv .venv && .venv/bin/pip install playwright==1.64.1
.venv/bin/playwright install chromium webkit firefox
.venv/bin/python harness.py            # placements, XSS, link previews, database theft
.venv/bin/python session_probe.py      # does a tab keep sessionStorage across another site, and can that site reach it
.venv/bin/python real_server_probe.py  # COOP and redirects, over real HTTP
```

`harness.py` fails if a variant that should leak stops leaking, or if the hostile code did not
run, so "no leak" cannot pass by accident. It fulfils responses through interception, and that
distorts a few things: WebKit's COOP looks ineffective under interception but works over real
HTTP, which is why `real_server_probe.py` exists. Read F2 on WebKit through that probe.

`adtag_offline.py` watches what the public AdSense scripts request, with all outbound traffic
blocked. It takes local copies of three scripts as arguments; they are not in this repository.
