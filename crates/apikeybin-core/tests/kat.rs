//! Known answers from outside this crate:
//!   * transcript and HKDF values from verify/kat/gen_transcript_kat.py (stdlib Python);
//!   * XChaCha20-Poly1305 from draft-irtf-cfrg-xchacha-03 appendix A.3.1;
//!   * X-Wing from the vectors in the x-wing crate, checked against the IETF draft text.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]

use std::collections::HashMap;

use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{KeyInit, XChaCha20Poly1305, XNonce};
use apikeybin_core::transcript as tr;
use sha2::{Digest, Sha256};
use x_wing::{Decapsulate, DecapsulationKey, Decapsulator, KeyExport};

fn table(src: &str) -> HashMap<&str, Vec<u8>> {
    src.lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| {
            let (k, v) = l.split_once(' ').expect("key value");
            (k, hex(v))
        })
        .collect()
}

fn hex(s: &str) -> Vec<u8> {
    let s = s.trim();
    assert!(s.len().is_multiple_of(2), "odd hex length");
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex"))
        .collect()
}

fn a32(v: &[u8]) -> [u8; 32] {
    v.try_into().expect("32 bytes")
}

#[test]
fn transcript_matches_the_independent_implementation() {
    let k = table(include_str!("data/transcript_kat.txt"));
    assert_eq!(k.len(), 12, "the KAT file is not the expected shape");

    let eid_s = [0x11u8; 32];
    let eid_r = [0x22u8; 32];
    let id: [u8; 16] = core::array::from_fn(|i| i as u8);
    let ek = [0x33u8; 1216];
    let ct = [0x44u8; 1120];
    let nonce = [0x55u8; 24];

    let th0 = tr::th0(&eid_s, &eid_r);
    assert_eq!(th0.as_slice(), k["TH0"]);
    assert_eq!(tr::offer_to_sign(&th0, b"offer-body-bytes"), k["OFFER_SIG"]);

    let th1 = tr::next(&th0, b"offer-frame-bytes");
    assert_eq!(th1.as_slice(), k["TH1"]);
    assert_eq!(tr::accept_to_sign(&th1, &id, &ek), k["ACCEPT_SIG"]);

    let th2 = tr::next(&th1, b"accept-frame-bytes");
    assert_eq!(th2.as_slice(), k["TH2"]);
    let key = tr::payload_key(&[0x66u8; 32], &th2).unwrap();
    assert_eq!(key.as_slice(), k["PAYLOAD_KEY"]);
    assert_eq!(
        Sha256::digest(tr::payload_ad(&th2, &ct)).as_slice(),
        k["AD_SHA"]
    );
    assert_eq!(
        tr::data_to_sign(&th2, &id, &ct, &nonce, b"ciphertext-body"),
        k["DATA_SIG"]
    );

    let th3 = tr::next(&th2, b"data-frame-bytes");
    assert_eq!(th3.as_slice(), k["TH3"]);
    assert_eq!(tr::ack_to_sign(&th3, &id, true), k["ACK_SIG"]);
    assert_eq!(tr::ack_to_sign(&th3, &id, false), k["ACK_SIG_FALSE"]);
}

#[test]
fn xchacha20poly1305_matches_the_ietf_vector() {
    let k = table(include_str!("data/xchacha_kat.txt"));
    let cipher = XChaCha20Poly1305::new_from_slice(&k["KEY"]).unwrap();
    let nonce: [u8; 24] = k["IV"].as_slice().try_into().expect("24 bytes");
    let out = cipher
        .encrypt(
            &XNonce::from(nonce),
            Payload {
                msg: &k["PT"],
                aad: &k["AAD"],
            },
        )
        .unwrap();
    let mut expected = k["CT"].clone();
    expected.extend_from_slice(&k["TAG"]);
    assert_eq!(out, expected);
    let back = cipher
        .decrypt(
            &XNonce::from(nonce),
            Payload {
                msg: &out,
                aad: &k["AAD"],
            },
        )
        .unwrap();
    assert_eq!(back, k["PT"]);
}

#[test]
fn xwing_matches_the_published_vector() {
    let k = table(include_str!("data/xwing_kat.txt"));
    let dk = DecapsulationKey::from(a32(&k["SK"]));
    let exported = dk.encapsulation_key().to_bytes();
    assert_eq!(exported.as_slice(), k["PK"]);

    let eseed: [u8; 64] = k["ESEED"].as_slice().try_into().expect("64 bytes");
    let (ct, ss) = dk
        .encapsulation_key()
        .encapsulate_deterministic(&eseed.into());
    assert_eq!(ct.as_slice(), k["CT"]);
    assert_eq!(ss.as_slice(), k["SS"]);

    let ct = x_wing::Ciphertext::try_from(k["CT"].as_slice()).unwrap();
    assert_eq!(dk.decapsulate(&ct).as_slice(), k["SS"]);
}
