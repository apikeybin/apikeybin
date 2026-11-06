#!/usr/bin/env python3
"""Do the tests notice when a safety check is removed?

Each entry deletes one check from the source. The tests must then FAIL. A mutation that
survives means a test suite that would not have noticed the hole, which is the same thing
as not having the test. Restores the source afterwards, also on Ctrl-C.
"""
import json, os, subprocess, sys, time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SRC = ROOT / "crates/apikeybin-core/src"
MUTATIONS = [
    ("xfer.rs", "offer signature not verified", "verify(peer, &tr::offer_to_sign(&th0, &offer.body), &offer.sig_o)?;", ""),
    ("xfer.rs", "accept signature not verified",
     "verify(\n            &self.peer,\n            &tr::accept_to_sign(&self.th1, &accept.id, &accept.ek),\n            &accept.sig_r,\n        )?;", ""),
    ("xfer.rs", "data signature not verified",
     "verify(\n            &self.peer,\n            &tr::data_to_sign(&self.th2, &data.id, &data.ct, &data.nonce, &data.body),\n            &data.sig_s,\n        )?;", ""),
    ("xfer.rs", "ack signature not verified",
     "verify(\n            &self.peer,\n            &tr::ack_to_sign(&self.th3, &ack.id, ack.ok),\n            &ack.sig_a,\n        )?;", ""),
    ("xfer.rs", "offer time window not checked", "if body.ts.abs_diff(now) > OFFER_WINDOW_SECS {\n        return Err(Error::Expired);\n    }", ""),
    ("xfer.rs", "offer version not checked", "if body.v != PROTOCOL_VERSION {\n        return Err(Error::UnsupportedVersion);\n    }", ""),
    ("xfer.rs", "offer bucket not checked", "if !padding::is_bucket(body.bucket) {\n        return Err(Error::BadBucket);\n    }", ""),
    ("xfer.rs", "accept id not compared", "if accept.id != self.id {\n            return Err(Error::IdMismatch);\n        }", ""),
    ("xfer.rs", "received label not validated", "if let Some(label) = &plain.label {\n            text::validate(label, text::MAX_LABEL_BYTES)?;\n        }", ""),
    ("xfer.rs", "sent label not validated", "if let Some(label) = label {\n        text::validate(label, text::MAX_LABEL_BYTES)?;\n    }", ""),
    ("xfer.rs", "weak peer keys accepted", "if identity.is_weak() {\n            return Err(Error::WeakPeerKey);\n        }", ""),
    ("padding.rs", "padding bytes not checked", "if zeros.iter().any(|b| *b != 0) {\n        return Err(Error::BadPadding);\n    }", ""),
    ("padding.rs", "padded size not checked", "if padded.len() != size {\n        return Err(Error::BadPadding);\n    }", ""),
    ("cbor.rs", "frame length not checked first", "if bytes.len() > max_len {\n        return Err(Error::FrameTooLong);\n    }", ""),
    ("cbor.rs", "non-canonical encodings accepted", "if again.as_slice() != bytes {\n        return Err(Error::Decode);\n    }", ""),
    ("kem.rs", "non-contributory X25519 accepted", "DecapsulationKeyRejectNonContrib::from(*seed)", "DecapsulationKeyRejectNonContrib::from(*seed)", "ACCEPT_NONCONTRIB"),
    ("xfer.rs", "data id not compared", "if data.id != self.info.id {\n            return Err(Error::IdMismatch);\n        }", ""),
    ("xfer.rs", "ack id not compared", "if ack.id != self.id {\n            return Err(Error::IdMismatch);\n        }", ""),
    ("transcript.rs", "payload key not bound to the transcript", "Hkdf::<Sha256>::new(Some(th2), shared)", "Hkdf::<Sha256>::new(None, shared)"),
    ("transcript.rs", "accept and ack share a label", 'pub const LABEL_ACK: &[u8] = b"apikeybin/ack";', 'pub const LABEL_ACK: &[u8] = b"apikeybin/accept";'),
    ("transcript.rs", "ack does not bind the ok flag", "hash(&[th3, id, &[u8::from(ok)]])", "hash(&[th3, id])"),
    ("vault.rs", "vault header not authenticated", "aad: raw_header,", "aad: b\"\","),
    ("vault.rs", "vault nonce fixed", "getrandom::fill(&mut nonce).map_err(|_| Error::Rng)?;", ""),
    ("vault.rs", "short passphrase accepted", "if passphrase.chars().count() < MIN_PASSPHRASE_CHARS {\n        return Err(Error::WeakPassphrase);\n    }", ""),
    ("vault.rs", "device name not validated", "text::validate(&body.device_name, text::MAX_DEVICE_NAME_BYTES)?;", ""),
    ("envfile.rs", "code execution variables not blocked", "EXACT.contains(&upper.as_str()) || PREFIX.iter().any(|p| upper.starts_with(p))", "false"),
    ("envfile.rs", "case not folded when blocking", "let upper = name.to_ascii_uppercase();", "let upper = name.to_owned();"),
    ("envfile.rs", "duplicate names accepted", "if out.iter().any(|v| v.name == name) {\n            return Err(EnvError::DuplicateName { line });\n        }", ""),
    ("envfile.rs", "explicit allow ignored", "&& !allowed.contains(&v.name.as_str())", ""),
    ("link.rs", "plain http allowed anywhere", """        "http" => {
            let host = authority.split(':').next().unwrap_or("");
            host == "localhost" || host == "127.0.0.1"
        }""", """        "http" => true,"""),
    ("link.rs", "link padding bytes not checked", "if zeros.iter().any(|b| *b != 0) {\n        return Err(Error::BadPadding);\n    }", ""),
    ("link.rs", "the largest size is not offered", "[usize; 4] = [1024, 4096, 16384, 65536]", "[usize; 4] = [1024, 4096, 16384, 16384]"),
    ("link.rs", "link padded size not checked", "if !BUCKETS.contains(&padded.len()) {\n        return Err(Error::BadPadding);\n    }", ""),
    ("link.rs", "base64 trailing bits ignored", "if bits >= 6 || acc != 0 {\n        return Err(Error::Decode);\n    }", ""),
    ("link.rs", "link ttl not checked", "if !TTLS.contains(&ttl) {\n        return Err(Error::Decode);\n    }", ""),
    ("link.rs", "unknown reply fields accepted", "            (\"salt\", FlatValue::Text(t)) => salt = Some(t),\n            _ => return Err(Error::Decode),", "            (\"salt\", FlatValue::Text(t)) => salt = Some(t),\n            _ => {}"),
    ("link.rs", "duplicate reply fields accepted", "if out.iter().any(|(k, _)| *k == key) {\n            return Err(Error::Decode);\n        }", ""),
    ("link.rs", "created id not checked", "if id.len() != ID_LEN || b64u_decode(&id).map(|b| b.len()) != Ok(16) {\n        return Err(Error::Decode);\n    }\n    Ok(id)", "Ok(id)"),
    ("link.rs", "link id not checked", "if id.len() != ID_LEN || b64u_decode(id).map(|b| b.len()) != Ok(16) {\n        return Err(Error::Decode);\n    }", ""),
    ("link.rs", "secret shown in debug", '.field("secret", &"[redacted]")', '.field("secret", &*self.secret)'),
    ("link.rs", "received file names not checked", "if !valid_name(name) {\n        return Err(Error::BadText);\n    }\n    Ok((Some(name.to_owned()), content))", "Ok((Some(name.to_owned()), content))"),
    ("link.rs", "sent file names not checked", "if !name.is_empty() && !valid_name(name) {\n        return Err(Error::BadText);\n    }", ""),
    ("link.rs", "path separators allowed in names", "&& !name.contains(['/', '\\\\', ':'])", ""),
    ("link.rs", "names may end in a dot or a space", "&& !name.ends_with(|c: char| c.is_whitespace() || c == '.')", ""),
    ("link.rs", "names may start with a space", "&& !name.starts_with(char::is_whitespace)", ""),
    ("text.rs", "soft hyphen allowed", "0x00AD\n            | 0x034F", "0x034F"),
    ("text.rs", "variation selectors allowed", "| 0xFE00..=0xFE0F\n", ""),
    ("text.rs", "tag characters and the rest allowed", "| 0xE0000..=0xE0FFF\n", ""),
    ("text.rs", "direction overrides allowed", "| 0x202A..=0x202E\n", ""),
    ("link.rs", "content shown in debug", '.field("content", &"[redacted]")', '.field("content", &*self.content)'),
    ("link.rs", "origin characters not checked", """    if authority.is_empty()
        || !authority
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || c == b'.' || c == b'-' || c == b':')
    {
        return false;
    }
""", ""),
    ("link.rs", "reply strings may hold escapes", """    if inner
        .bytes()
        .any(|c| c == b'"' || c == b'\\\\' || c.is_ascii_control())
    {
        return Err(Error::Decode);
    }
""", ""),
    ("padding.rs", "any size accepted when padding", "if !is_bucket(bucket) {\n        return Err(Error::BadBucket);\n    }\n    let size = usize::try_from(bucket).map_err(|_| Error::BadBucket)?;\n    let declared", "let size = usize::try_from(bucket).map_err(|_| Error::BadBucket)?;\n    let declared"),
    ("padding.rs", "any size accepted when unpadding", "if !is_bucket(bucket) {\n        return Err(Error::BadBucket);\n    }\n    let size = usize::try_from(bucket).map_err(|_| Error::BadBucket)?;\n    if padded.len()", "let size = usize::try_from(bucket).map_err(|_| Error::BadBucket)?;\n    if padded.len()"),
    ("padding.rs", "too much for its size class", "if plaintext.len().saturating_add(LEN_PREFIX) > size {\n        return Err(Error::PayloadTooLarge);\n    }", ""),
    ("vault.rs", "vault size not limited", "if file.len() > MAX_VAULT_LEN {\n        return Err(Error::VaultFormat);\n    }", ""),
    ("vault.rs", "vault magic not checked", "if magic != MAGIC.as_slice() {\n        return Err(Error::VaultFormat);\n    }", ""),
    ("vault.rs", "vault header fields not checked", "if header.v != 1 || header.salt.len() != 32 || header.nonce.len() != 24 {\n        return Err(Error::VaultFormat);\n    }", ""),
    ("text.rs", "empty text allowed", "if text.is_empty() || text.len() > max_bytes", "if text.len() > max_bytes"),
    ("text.rs", "long text allowed", "if text.is_empty() || text.len() > max_bytes ||", "if text.is_empty() ||"),
    ("envfile.rs", "bad variable names accepted", "if !valid_name(name) {\n            return Err(EnvError::BadName { line });\n        }", ""),
    ("envfile.rs", "text after a quote accepted", "if !after.is_empty() && !after.starts_with('#') {\n                return Err(EnvError::TextAfterQuote { line });\n            }", ""),
    ("link.rs", "links to any server accepted", "if !allowed_origin(origin) {\n        return Err(Error::Decode);\n    }", ""),
    ("text.rs", "control characters allowed", "c.is_control()\n        || matches!", "false\n        || matches!"),
]


def run_tests():
    env = dict(os.environ, PATH=f"{Path.home()}/.cargo/bin:{os.environ['PATH']}", RUSTFLAGS="-A warnings")
    return subprocess.run(["cargo", "test", "-p", "apikeybin-core", "--tests", "--quiet"], cwd=ROOT, env=env, capture_output=True, text=True)


def main():
    baseline = run_tests()
    if baseline.returncode != 0:
        print("baseline tests fail; aborting\n", baseline.stdout[-1500:], baseline.stderr[-1500:])
        return 2
    results = []
    for m in MUTATIONS:
        fname, name, old, new = m[0], m[1], m[2], m[3]
        path = SRC / fname
        original = path.read_text(encoding="utf-8")
        if old not in original:
            results.append({"mutation": name, "status": "NOT_APPLIED"})
            print(f"NOT APPLIED  {name}")
            continue
        mutated = original.replace(old, new, 1)
        if len(m) > 4 and m[4] == "ACCEPT_NONCONTRIB":
            mutated = original.replace("if !ss_x.was_contributory()", "if !ss_x.was_contributory()")
            # The check lives in the x-wing crate; mutate our use of it instead.
            mutated = original.replace(
                "type DecapsulationKey = DecapsulationKeyRejectNonContrib;",
                "type DecapsulationKey = x_wing::DecapsulationKey;",
            ).replace(
                "DecapsulationKeyRejectNonContrib::from(*seed)", "x_wing::DecapsulationKey::from(*seed)"
            ).replace(
                "let mut shared = dk.try_decapsulate(&ct).map_err(|_| Error::Crypto)?;",
                "let mut shared = x_wing::Decapsulate::decapsulate(dk, &ct);",
            )
        t0 = time.time()
        try:
            path.write_text(mutated, encoding="utf-8")
            r = run_tests()
        finally:
            path.write_text(original, encoding="utf-8")
        out = r.stdout + r.stderr
        failing = sorted({l.split()[1] for l in out.splitlines() if l.startswith("---- ") and l.endswith(" stdout ----")})
        # Only a test that names the failure counts.
        if "could not compile" in out:
            status = "NO_COMPILE"
        elif failing:
            status = "caught"
        elif r.returncode != 0:
            status = "NO_RESULT"
        else:
            status = "SURVIVED"
        results.append({"mutation": name, "status": status, "failing_tests": failing[:4]})
        print(f"{status:11} {name}  ({time.time()-t0:.0f}s) {failing[:2]}", flush=True)
    Path(ROOT / "verify/mutation/results.json").write_text(json.dumps(results, ensure_ascii=False, indent=1), encoding="utf-8")
    bad = [r for r in results if r["status"] != "caught"]
    print(f"\n{len(results) - len(bad)}/{len(results)} caught; not caught: {[r['mutation'] + ':' + r['status'] for r in bad]}")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
