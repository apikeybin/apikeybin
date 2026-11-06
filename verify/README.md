# Verification

Each directory tries to break a specific claim. Failing to break it is the result.

| Directory | Question | How to run |
|---|---|---|
| `../crates/apikeybin-core/tests` | Does tampering, replay, or a stolen or malicious key get anything? | `cargo test -p apikeybin-core` |
| `mutation` | If a safety check is removed, does a test fail? | `python3 verify/mutation/mutate.py` |
| `kat` | Do the transcript rules match a second implementation? XChaCha and X-Wing match the published vectors? | `python3 verify/kat/gen_transcript_kat.py`, then the `kat` tests |
| `web-threat` | What can a hostile third party script obtain in each page arrangement? Does a tab keep its storage across another site? | `verify/web-threat/README.md`, `session_probe.py` |
| `web-real` | Does the real site hold up: real browsers, a real local database, a second implementation of the format, the page with ads, and the real CLI? | `verify/web-real/test_api.py`, `test_browser.py`, `test_shell.py`, `test_cli.py`, `mutate_web.py`, `mutate_cli.py` |
| `iroh-probe` | Are strangers really cut off before the application sees them? | `cd verify/iroh-probe && cargo run` |
| `dotenvy-probe` | Why the spec stopped using a common `.env` parser | `cd verify/dotenvy-probe && cargo run` |
| `proverif` | Is there a logical flaw in the message flow, with the network fully hostile? | `verify/proverif/README.md` |

Some tests in `web-real/test_shell.py` run Google's real ad script against the site. That script is not in
this repository. Put copies named `adsbygoogle.js.txt`, `show_ads_impl.js.txt` and
`show_ads_impl_with_ama.js.txt` in `~/.cache/apikeybin/adsense_scripts`, or point `APIKEYBIN_ADSENSE_DIR` at them.
Without them those tests are reported as not tested.

Things worth knowing from doing this:

- The mutation run found three checks whose tests passed for the wrong reason.
- A property test found on its third run that a one-bit change to a signed frame still
  verified, because CBOR allowed two encodings of the same value. Now each message has one.
- A test found that byte strings over 4 KiB were being rejected by the decoder.
- A browser test found that WebKit keeps a `<textarea>` value in the history entry and restores
  it on Back, even with `autocomplete="off"` and after `pagehide` cleared it. Secrets on screen
  are not in form fields any more.
- A regular expression written through an editing tool came out with the real U+2028 character in
  it instead of the escape. The page stopped working. Any invisible character in a source file now
  fails a test, which also covers the "Trojan Source" trick.
- All three browsers save `.env` as `env`. Measured, then said on the page.
- `--out` into a read-only folder spent the one read and then lost the content. It now checks
  before reading.
- A clean mutation run found tests that passed for the wrong reason: a bad input that was wrong in
  two ways was stopped by the other check, so the check it was written for was never tested. Make
  each bad input wrong in exactly one way.
- The mutation lists are written by hand and had gaps. Comparing them with the guard lines in the
  code added about sixty entries, and seventeen of those survived at first. Two of those changed
  nothing when removed and came off the list; the rest got tests. The lists are still not everything:
  what is left is a check repeated elsewhere, code that cannot be reached, wiping memory (which cannot
  be seen from outside), or the wording of an error.
- rpassword writes the prompt and then turns echo off. A program that answers within that moment
  has its answer echoed, which showed up as a test failing about one run in six. The test helper now
  waits for echo to go off, as a person would, and still fails if a prompt leaves it on.
- An independent read of the code found what the tests had not: the CLI passed a sender's escape
  sequences straight to the terminal, spent the read before asking for the passphrase, and let a
  sender choose a file name like `.zshenv` when saving. All fixed, and saving under the sender's
  name was removed altogether.

- The storage counter added raw ciphertext bytes while the column holds base64 text, so the database
  would have hit its own limit before the counter reached its cap. It now counts what is stored, and
  a test compares that with the real growth of the database.
- The CLI suite makes more calls in a minute than the rate limit allows, and the CLI does not say who
  it is, so the suite failed now and then for that reason alone. Each call now gets its own address
  through a small proxy in the test. The limit itself is tested in `test_api.py`.

- A web mutation run once reported 124/124 when 39 of those said nothing. One suite ran out of time
  and only the suite was stopped, so its server stayed on the port. Every suite after that talked to
  it and failed for that reason alone, and a failing suite counted as caught. Reading which tests
  failed is what showed it: the same few, whatever had been removed. Now a suite refuses a busy port,
  the runner ends the server too, only a test that names the failure counts, and the suites run again
  at the end: if they no longer pass, nothing is recorded.
- The tests of the page with ads failed now and then, each time a click that did nothing. A mutation run
  showed it: one entry also failed a test that had nothing to do with what was removed. A recorder in
  every frame then showed where such a click went. Chromium sends a click to whatever it last drew at
  that point, so just after loading or scrolling, a click aimed at the page arrived in the tool's frame,
  which is another process. That was 6 of 2,700, within about 50 ms of the load. Nobody can press that
  fast, so the tests now wait for the page to be drawn before they press (0 of 6,000). They do not press
  again, because that would also hide a button that really does nothing.

None of this is an audit.
