//! The link format: answers from the Python implementation, and everything a hostile server, a
//! hostile sender or a malformed link can try.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]

use std::collections::HashMap;

use aes_gcm::aead::{Aead, Payload};
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use hkdf::Hkdf;
use proptest::prelude::*;
use apikeybin_core::Error;
use apikeybin_core::link::{
    self, BUCKETS, FlatValue, MAX_TEXT, Record, b64u_decode, b64u_encode, flat_json, fragment,
    open, parse, parse_created, parse_record, seal, seal_with, token_of,
};
use sha2::Sha256;

fn table() -> HashMap<&'static str, Vec<u8>> {
    include_str!("data/link_kat.txt")
        .lines()
        .map(|l| {
            let (k, v) = l.split_once(' ').unwrap();
            let bytes = (0..v.len())
                .step_by(2)
                .map(|i| u8::from_str_radix(&v[i..i + 2], 16).unwrap())
                .collect();
            (k, bytes)
        })
        .collect()
}

fn a<const N: usize>(v: &[u8]) -> [u8; N] {
    v.try_into().unwrap()
}

#[test]
fn seal_matches_the_python_implementation() {
    let k = table();
    assert_eq!(k.len(), 11, "the KAT file is not the expected shape");
    let secret: [u8; 32] = a(&k["SECRET"]);
    let iv: [u8; 12] = a(&k["IV"]);
    let salt: [u8; 16] = a(&k["SALT"]);
    let pass = String::from_utf8(k["PASS"].clone()).unwrap();
    let name = String::from_utf8(k["NAME"].clone()).unwrap();

    assert_eq!(token_of(&secret).unwrap().as_slice(), k["TOKEN"]);

    let plain = seal_with(&k["TEXT"], None, None, 86400, &secret, &iv, None).unwrap();
    assert_eq!(b64u_decode(&plain.ct).unwrap(), k["CT_PLAIN"]);
    assert_eq!(plain.token_hash.as_bytes(), k["TOKEN_HASH"]);
    assert_eq!(plain.salt, None);

    let guarded = seal_with(
        &k["TEXT"],
        None,
        Some(&pass),
        600,
        &secret,
        &iv,
        Some(&salt),
    )
    .unwrap();
    assert_eq!(b64u_decode(&guarded.ct).unwrap(), k["CT_PASS"]);
    assert_eq!(guarded.salt.as_deref(), Some(b64u_encode(&salt).as_str()));

    let named = seal_with(&k["TEXT"], Some(&name), None, 86400, &secret, &iv, None).unwrap();
    assert_eq!(b64u_decode(&named.ct).unwrap(), k["CT_NAMED"]);
}

#[test]
fn open_reads_what_python_wrote() {
    let k = table();
    let secret: [u8; 32] = a(&k["SECRET"]);
    let pass = String::from_utf8(k["PASS"].clone()).unwrap();
    let record = |ct: &[u8], salt: Option<String>| Record {
        iv: b64u_encode(&k["IV"]),
        ct: b64u_encode(ct),
        pw: salt.is_some(),
        salt,
    };
    let out = open(&record(&k["CT_PLAIN"], None), &secret, None).unwrap();
    assert_eq!(&*out.content, &k["TEXT"][..]);
    assert_eq!(out.name, None);

    let named = open(&record(&k["CT_NAMED"], None), &secret, None).unwrap();
    assert_eq!(&*named.content, &k["TEXT"][..]);
    assert_eq!(named.name.as_deref(), Some(".env.local"));

    let guarded = record(&k["CT_PASS"], Some(b64u_encode(&k["SALT"])));
    assert_eq!(
        &*open(&guarded, &secret, Some(&pass)).unwrap().content,
        &k["TEXT"][..]
    );
    assert_eq!(
        open(&guarded, &secret, Some("wrong")).err(),
        Some(Error::Crypto)
    );
    assert_eq!(open(&guarded, &secret, None).err(), Some(Error::Crypto));
    assert!(open(&record(&k["CT_PLAIN"], None), &secret, Some(&pass)).is_err());
}

fn round_trip(text: &[u8], pass: Option<&str>) -> Vec<u8> {
    let (sealed, secret) = seal(text, None, pass, 3600).unwrap();
    let record = Record {
        iv: sealed.iv,
        ct: sealed.ct,
        pw: sealed.salt.is_some(),
        salt: sealed.salt,
    };
    open(&record, &secret, pass).unwrap().content.to_vec()
}

#[test]
fn sizes_up_to_the_limit_round_trip_and_land_in_a_bucket() {
    for size in [1usize, 1018, 1019, 4090, 4091, 16378, 16379, MAX_TEXT] {
        let text = vec![b'a'; size];
        assert_eq!(round_trip(&text, None), text, "{size}");
        let (sealed, _) = seal(&text, None, None, 600).unwrap();
        let ct_len = b64u_decode(&sealed.ct).unwrap().len();
        assert!(BUCKETS.contains(&(ct_len - 16)), "{size} gave {ct_len}");
    }
    assert_eq!(
        seal(&vec![0u8; MAX_TEXT + 1], None, None, 600).err(),
        Some(Error::PayloadTooLarge)
    );
}

#[test]
fn only_the_offered_expiries_are_accepted() {
    for ttl in link::TTLS {
        assert!(seal(b"x", None, None, ttl).is_ok());
    }
    assert!(seal(b"x", None, None, 1).is_err());
    assert!(seal(b"x", None, None, 2_592_000).is_err());
}

#[test]
fn each_link_gets_fresh_randomness() {
    let (a1, s1) = seal(b"same", None, Some("p"), 600).unwrap();
    let (a2, s2) = seal(b"same", None, Some("p"), 600).unwrap();
    assert_ne!(*s1, *s2);
    assert_ne!(a1.iv, a2.iv);
    assert_ne!(a1.ct, a2.ct);
    assert_ne!(a1.salt, a2.salt);
}

#[test]
fn flipping_any_ciphertext_byte_is_detected() {
    let (sealed, secret) = seal(b"secret", None, None, 600).unwrap();
    let ct = b64u_decode(&sealed.ct).unwrap();
    for i in (0..ct.len()).step_by(37) {
        let mut bad = ct.clone();
        bad[i] ^= 1;
        let record = Record {
            iv: sealed.iv.clone(),
            ct: b64u_encode(&bad),
            pw: false,
            salt: None,
        };
        assert_eq!(
            open(&record, &secret, None).err(),
            Some(Error::Crypto),
            "{i}"
        );
    }
}

/// A record encrypted correctly, by someone who controls what is inside.
fn crafted(padded: &[u8], secret: &[u8; 32]) -> Record {
    let mut key = [0u8; 32];
    Hkdf::<Sha256>::new(None, secret)
        .expand(b"apikeybin/link/1/key", &mut key)
        .unwrap();
    let iv = [9u8; 12];
    let ct = Aes256Gcm::new_from_slice(&key)
        .unwrap()
        .encrypt(
            &Nonce::from(iv),
            Payload {
                msg: padded,
                aad: b"apikeybin/link/1",
            },
        )
        .unwrap();
    Record {
        iv: b64u_encode(&iv),
        ct: b64u_encode(&ct),
        pw: false,
        salt: None,
    }
}

#[test]
fn hostile_padding_is_refused() {
    let secret = [7u8; 32];
    // Length prefix, an empty name, one byte of content, zeros, and a chosen last byte.
    let padded = |declared: u32, size: usize, last: u8| {
        let mut v = vec![0u8; size];
        v[..4].copy_from_slice(&declared.to_be_bytes());
        v[6] = b'x';
        v[size - 1] = last;
        v
    };
    let try_it = |v: Vec<u8>| open(&crafted(&v, &secret), &secret, None).err();
    assert_eq!(try_it(padded(3, 1024, 0)), None, "control failed");
    assert_eq!(
        try_it(padded(3, 1024, 1)),
        Some(Error::BadPadding),
        "hidden data"
    );
    assert_eq!(
        try_it(padded(1021, 1024, 0)),
        Some(Error::BadPadding),
        "length too long"
    );
    assert_eq!(
        try_it(padded(u32::MAX, 1024, 0)),
        Some(Error::BadPadding),
        "length huge"
    );
    assert_eq!(
        try_it(padded(3, 1000, 0)),
        Some(Error::BadPadding),
        "not a bucket"
    );
}

/// A body with this name field and some content, padded and encrypted by a hostile sender.
fn with_name_bytes(name: &[u8], secret: &[u8; 32]) -> Record {
    let mut body = u16::try_from(name.len()).unwrap().to_be_bytes().to_vec();
    body.extend_from_slice(name);
    body.extend_from_slice(b"content");
    let mut padded = u32::try_from(body.len()).unwrap().to_be_bytes().to_vec();
    padded.extend_from_slice(&body);
    padded.resize(1024, 0);
    crafted(&padded, secret)
}

#[test]
fn file_names_round_trip_and_hostile_ones_are_refused() {
    let secret = [7u8; 32];
    for good in [
        ".env",
        ".env.local",
        "service-account.json",
        "本番の鍵.txt",
        "id_rsa",
        "a b.pem",
    ] {
        let opened = open(&with_name_bytes(good.as_bytes(), &secret), &secret, None).unwrap();
        assert_eq!(opened.name.as_deref(), Some(good));
        assert_eq!(&*opened.content, b"content");
        assert!(link::valid_name(good), "{good}");
    }
    for bad in [
        "../secret",
        "..",
        ".",
        "a/b",
        "a\\b",
        "C:evil",
        "/etc/passwd",
        "a\u{1b}[2J",
        "a\nb",
        "a\u{202e}gpj.exe",
        "a\u{200b}b",
        "a\u{0}b",
        "a.exe ",
        "a.html.",
        " a",
        "a\u{3000}",
        "\u{feff}.env",
        "a\u{ad}b",
        "a\u{fe0f}b",
        "a\u{180e}b",
        "a\u{e0100}b",
    ] {
        assert!(!link::valid_name(bad), "{bad:?}");
        assert_eq!(
            open(&with_name_bytes(bad.as_bytes(), &secret), &secret, None).err(),
            Some(Error::BadText),
            "{bad:?}"
        );
    }
    let long = "a".repeat(129);
    assert_eq!(
        open(&with_name_bytes(long.as_bytes(), &secret), &secret, None).err(),
        Some(Error::BadText)
    );
    assert_eq!(
        open(&with_name_bytes(&[0xff, 0xfe], &secret), &secret, None).err(),
        Some(Error::BadText)
    );
    // Declares more name than there is body.
    let mut padded = 2u32.to_be_bytes().to_vec();
    padded.extend_from_slice(&100u16.to_be_bytes());
    padded.resize(1024, 0);
    assert!(open(&crafted(&padded, &secret), &secret, None).is_err());
    // A sender cannot make one either.
    assert_eq!(
        seal(b"x", Some("../x"), None, 600).err(),
        Some(Error::BadText)
    );
    // Shown, it reveals only the name.
    let opened = open(&with_name_bytes(b".env", &secret), &secret, None).unwrap();
    let shown = format!("{opened:?}");
    assert!(
        shown.contains("[redacted]") && !shown.contains("content\""),
        "{shown}"
    );
}

/// One member of a regular expression's character class.
fn class_member(chars: &mut std::iter::Peekable<std::str::Chars<'_>>) -> u32 {
    let c = chars.next().unwrap();
    if c != '\\' {
        return c as u32;
    }
    match chars.next().unwrap() {
        'u' => {
            let hex: String = if chars.peek() == Some(&'{') {
                chars.next();
                chars.by_ref().take_while(|c| *c != '}').collect()
            } else {
                (0..4).map(|_| chars.next().unwrap()).collect()
            };
            u32::from_str_radix(&hex, 16).unwrap()
        }
        other => other as u32,
    }
}

/// The browser's rule is a regular expression in app.js and this one is Rust. They must agree on
/// every character there is, so this reads the character class out of app.js.
#[test]
fn the_browser_and_this_code_agree_on_every_character_in_a_name() {
    let js = include_str!("../../../web/public/app.js");
    let rest = &js[js.find("const BAD_NAME =").unwrap()..];
    let class = &rest[rest.find("/[").unwrap() + 2..rest.find("]/u;").unwrap()];
    let mut chars = class.chars().peekable();
    let mut ranges = Vec::new();
    while chars.peek().is_some() {
        let low = class_member(&mut chars);
        let high = if chars.peek() == Some(&'-') {
            chars.next();
            class_member(&mut chars)
        } else {
            low
        };
        ranges.push((low, high));
    }
    assert!(ranges.len() > 15, "could not read the class: {ranges:?}");
    let mut checked = 0u32;
    for code in 0..=0x10FFFFu32 {
        let Some(c) = char::from_u32(code) else {
            continue;
        };
        let refused_there = ranges
            .iter()
            .any(|(low, high)| (*low..=*high).contains(&code));
        assert_eq!(
            link::valid_name(&format!("a{c}b")),
            !refused_there,
            "U+{code:04X}"
        );
        checked += 1;
    }
    assert!(checked > 1_000_000, "{checked}");
    // The ends are a separate rule there too: /^\s|[\s.]$/u. Among characters not already refused,
    // \s is exactly these. Space inside a name is fine.
    for code in [
        0x20u32, 0xA0, 0x1680, 0x2000, 0x2005, 0x200A, 0x202F, 0x205F, 0x3000,
    ] {
        let c = char::from_u32(code).unwrap();
        assert!(c.is_whitespace(), "U+{code:04X}");
        assert!(!link::valid_name(&format!("{c}a")), "U+{code:04X}");
        assert!(!link::valid_name(&format!("a{c}")), "U+{code:04X}");
        assert!(link::valid_name(&format!("a{c}b")), "U+{code:04X}");
    }
}

#[test]
fn the_name_is_encrypted_with_the_content() {
    let (sealed, secret) = seal(b"x", Some("very-visible-name.env"), None, 600).unwrap();
    let wire = format!("{sealed:?}");
    assert!(!wire.contains("very-visible-name"), "{wire}");
    let record = Record {
        iv: sealed.iv,
        ct: sealed.ct,
        pw: false,
        salt: None,
    };
    let opened = open(&record, &secret, None).unwrap();
    assert_eq!(opened.name.as_deref(), Some("very-visible-name.env"));
    // A name costs room, so the largest text no longer fits with one.
    assert_eq!(
        seal(&vec![0u8; MAX_TEXT], Some("a.env"), None, 600).err(),
        Some(Error::PayloadTooLarge)
    );
}

#[test]
fn a_record_cannot_mix_the_flag_and_the_salt() {
    let (sealed, secret) = seal(b"x", None, None, 600).unwrap();
    let with = |pw, salt: Option<String>| Record {
        iv: sealed.iv.clone(),
        ct: sealed.ct.clone(),
        pw,
        salt,
    };
    assert_eq!(
        open(&with(true, None), &secret, Some("p")).err(),
        Some(Error::Decode)
    );
    let salt = Some(b64u_encode(&[0u8; 16]));
    assert_eq!(
        open(&with(false, salt.clone()), &secret, None).err(),
        Some(Error::Decode)
    );
    let short = Some(b64u_encode(&[0u8; 8]));
    assert_eq!(
        open(&with(true, short), &secret, Some("p")).err(),
        Some(Error::Decode)
    );
}

const ID: &str = "AAAAAAAAAAAAAAAAAAAAAA";

fn good_secret() -> String {
    b64u_encode(&[5u8; 32])
}

#[test]
fn well_formed_links_parse() {
    let s = good_secret();
    let parsed = parse(&format!("https://app.apikeybin.com/s/{ID}#1.{s}")).unwrap();
    assert_eq!(parsed.origin, "https://app.apikeybin.com");
    assert_eq!(parsed.id, ID);
    assert_eq!(*parsed.secret, [5u8; 32]);
    assert!(!parsed.needs_passphrase);
    assert!(
        parse(&format!("https://app.apikeybin.com/s/{ID}#1p.{s}"))
            .unwrap()
            .needs_passphrase
    );
    assert!(
        parse(&format!("  https://x.test:8443/s/{ID}#1.{s}\n")).is_ok(),
        "spaces around a pasted link"
    );
    assert!(parse(&format!("http://localhost:8787/s/{ID}#1.{s}")).is_ok());
    assert!(parse(&format!("http://127.0.0.1:8787/s/{ID}#1.{s}")).is_ok());
}

#[test]
fn anything_else_is_refused_and_says_nothing_of_the_secret() {
    let s = good_secret();
    let cases = [
        format!("http://app.apikeybin.com/s/{ID}#1.{s}"),
        format!("http://localhost.evil.test/s/{ID}#1.{s}"),
        format!("http://127.0.0.1.evil.test/s/{ID}#1.{s}"),
        format!("ftp://app.apikeybin.com/s/{ID}#1.{s}"),
        format!("https://user:pw@app.apikeybin.com/s/{ID}#1.{s}"),
        format!("https://app.apikeybin.com/x/s/{ID}?a=1#1.{s}"),
        format!("https://app.apikeybin.com/s/{ID}"),
        format!("https://app.apikeybin.com/s/{ID}#"),
        format!("https://app.apikeybin.com/s/{ID}#1."),
        format!("https://app.apikeybin.com/s/{ID}#{s}"),
        format!("https://app.apikeybin.com/s/{ID}#2.{s}"),
        format!("https://app.apikeybin.com/s/{ID}#1.{s}A"),
        format!("https://app.apikeybin.com/s/AAAA#1.{s}"),
        format!("https://app.apikeybin.com/s/{ID}A#1.{s}"),
        format!("https://app.apikeybin.com/s/{}#1.{s}", "A".repeat(21) + "!"),
        format!("https:///s/{ID}#1.{s}"),
        format!("/s/{ID}#1.{s}"),
        String::new(),
    ];
    for case in &cases {
        let result = parse(case);
        assert!(result.is_err(), "accepted: {case}");
        assert!(!format!("{:?}", result.err()).contains(&s));
    }
    // A shown link never reveals the secret either.
    let parsed = parse(&format!("https://app.apikeybin.com/s/{ID}#1.{s}")).unwrap();
    let shown = format!("{parsed:?}");
    assert!(
        shown.contains("[redacted]") && !shown.contains(&s),
        "{shown}"
    );
}

#[test]
fn base64url_has_exactly_one_spelling() {
    assert_eq!(b64u_encode(b""), "");
    assert_eq!(b64u_encode(&[0xfb, 0xff]), "-_8");
    assert_eq!(b64u_decode("-_8").unwrap(), vec![0xfb, 0xff]);
    assert!(b64u_decode("-_9").is_err(), "unused bits set");
    assert!(b64u_decode("A").is_err(), "impossible length");
    assert!(b64u_decode("+/8").is_err(), "the other alphabet");
    assert!(b64u_decode("AA==").is_err(), "padding");
    assert!(b64u_decode("A A").is_err());
}

#[test]
fn replies_are_read_strictly() {
    let good = r#"{"v":1,"iv":"abc","ct":"def","pw":false}"#;
    let r = parse_record(good).unwrap();
    assert_eq!(
        (r.iv.as_str(), r.ct.as_str(), r.pw, r.salt),
        ("abc", "def", false, None)
    );
    assert_eq!(
        flat_json(r#"{"a":"b","n":12,"t":true}"#).unwrap(),
        vec![
            ("a".to_owned(), FlatValue::Text("b".to_owned())),
            ("n".to_owned(), FlatValue::Number(12)),
            ("t".to_owned(), FlatValue::Bool(true)),
        ]
    );
    for bad in [
        r#"{"v":1,"iv":"abc","ct":"def","pw":false,"extra":"x"}"#,
        r#"{"v":2,"iv":"abc","ct":"def","pw":false}"#,
        r#"{"iv":"abc","ct":"def","pw":false}"#,
        r#"{"v":1,"iv":"abc","pw":false}"#,
        r#"{"v":1,"v":1,"iv":"abc","ct":"def","pw":false}"#,
        r#"{"v":1,"iv":"a\"bc","ct":"def","pw":false}"#,
        r#"{"v":1,"iv":{"x":1},"ct":"def","pw":false}"#,
        r#"[{"v":1}]"#,
        "",
        "null",
    ] {
        assert!(parse_record(bad).is_err(), "accepted: {bad}");
    }
    assert_eq!(
        parse_created(&format!(r#"{{"id":"{ID}","expires_at":123}}"#)).unwrap(),
        ID
    );
    for bad in [
        r#"{"id":"short"}"#,
        r#"{"expires_at":1}"#,
        r#"{"id":"../../etc/passwd/xxxxxx"}"#,
    ] {
        assert!(parse_created(bad).is_err(), "accepted: {bad}");
    }
}

#[test]
fn the_fragment_has_the_documented_shape() {
    let secret = [5u8; 32];
    assert_eq!(fragment(&secret, false), format!("1.{}", good_secret()));
    assert_eq!(fragment(&secret, true), format!("1p.{}", good_secret()));
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(500))]

    #[test]
    fn base64url_round_trips(data in proptest::collection::vec(any::<u8>(), 0..200)) {
        prop_assert_eq!(b64u_decode(&b64u_encode(&data)).unwrap(), data);
    }

    #[test]
    fn readers_never_panic(text in ".{0,300}") {
        let _ = b64u_decode(&text);
        let _ = parse(&text);
        let _ = flat_json(&text);
        let _ = parse_record(&text);
        let _ = parse_created(&text);
        let _ = link::valid_name(&text);
    }

    #[test]
    fn text_round_trips(text in proptest::collection::vec(any::<u8>(), 1..3000)) {
        prop_assert_eq!(round_trip(&text, None), text);
    }

    /// Any bytes inside a correctly encrypted record: an error or a result, never a panic.
    #[test]
    fn hostile_plaintext_never_panics(mut body in proptest::collection::vec(any::<u8>(), 1..1000)) {
        body.resize(1024, 0);
        let secret = [7u8; 32];
        let _ = open(&crafted(&body, &secret), &secret, None);
    }
}
