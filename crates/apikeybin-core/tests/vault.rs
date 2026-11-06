//! The vault file against someone who can read and rewrite it.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]

use apikeybin_core::vault::{self, Body, Header, Peer, ProtectorHeader};
use apikeybin_core::{Error, cbor};

const PASS: &str = "correct horse battery staple";

fn body() -> Body {
    Body {
        device_name: "mac".to_owned(),
        identity_sk: vec![0xAB; 32],
        transport_sk: vec![0xCD; 32],
        peers: vec![Peer {
            name: "win".to_owned(),
            endpoint_id: vec![1; 32],
            identity_pk: vec![2; 32],
            paired_at: 1_800_000_000,
        }],
        created_at: 1_800_000_000,
    }
}

fn protector() -> ProtectorHeader {
    ProtectorHeader {
        kind: "passphrase".to_owned(),
        data: Vec::new(),
    }
}

fn sealed() -> (Vec<u8>, [u8; 32]) {
    let salt = [7u8; 32];
    let secret = vault::passphrase_secret(PASS, &salt).unwrap();
    (
        vault::seal(protector(), &secret[..], salt, &body()).unwrap(),
        salt,
    )
}

#[test]
fn round_trip() {
    let (file, salt) = sealed();
    let secret = vault::passphrase_secret(PASS, &salt).unwrap();
    let opened = vault::open(&file, &secret[..]).unwrap();
    assert_eq!(opened.device_name, "mac");
    assert_eq!(opened.identity_sk, vec![0xAB; 32]);
    assert_eq!(opened.transport_sk, vec![0xCD; 32]);
    assert_eq!(opened.peers.len(), 1);
}

#[test]
fn the_file_holds_no_secret_in_the_clear() {
    let (file, _) = sealed();
    for needle in [
        &[0xABu8; 32][..],
        &[0xCDu8; 32][..],
        b"win".as_slice(),
        b"mac".as_slice(),
    ] {
        assert!(!file.windows(needle.len()).any(|w| w == needle));
    }
}

#[test]
fn wrong_passphrase_fails() {
    let (file, salt) = sealed();
    let wrong = vault::passphrase_secret("incorrect horse battery", &salt).unwrap();
    assert_eq!(vault::open(&file, &wrong[..]).err(), Some(Error::VaultAuth));
}

#[test]
fn short_passphrase_is_refused() {
    assert_eq!(
        vault::passphrase_secret("elevenchars", &[0; 32]).err(),
        Some(Error::WeakPassphrase)
    );
    assert!(vault::passphrase_secret("twelve chars", &[0; 32]).is_ok());
}

#[test]
fn flipping_any_byte_of_the_file_fails() {
    let (file, salt) = sealed();
    let secret = vault::passphrase_secret(PASS, &salt).unwrap();
    for i in 0..file.len() {
        let mut bad = file.clone();
        bad[i] ^= 0x01;
        assert!(vault::open(&bad, &secret[..]).is_err(), "byte {i} accepted");
    }
}

#[test]
fn truncated_and_extended_files_fail() {
    let (file, salt) = sealed();
    let secret = vault::passphrase_secret(PASS, &salt).unwrap();
    for n in [0, 1, 4, 7, 8, 9, file.len() / 2, file.len() - 1] {
        assert!(vault::open(&file[..n], &secret[..]).is_err(), "length {n}");
    }
    let mut longer = file.clone();
    longer.push(0);
    assert!(vault::open(&longer, &secret[..]).is_err());
}

#[test]
fn oversized_header_length_is_refused_before_allocating() {
    let mut file = b"SAV1".to_vec();
    file.extend_from_slice(&u32::MAX.to_be_bytes());
    assert_eq!(vault::read_header(&file).err(), Some(Error::VaultFormat));
}

#[test]
fn a_file_over_the_limit_is_refused_before_it_is_read() {
    const LIMIT: usize = 8 * 1024 * 1024;
    let (mut file, _) = sealed();
    file.resize(LIMIT + 1, 0);
    assert_eq!(vault::read_header(&file).err(), Some(Error::VaultFormat));
    // One byte less gets as far as the header, so it was the limit that stopped the longer one.
    file.truncate(LIMIT);
    assert!(vault::read_header(&file).is_ok());
}

fn file_with(header: &Header) -> Vec<u8> {
    let bytes = cbor::encode(header).unwrap();
    let mut file = vault::MAGIC.to_vec();
    file.extend_from_slice(&u32::try_from(bytes.len()).unwrap().to_be_bytes());
    file.extend_from_slice(&bytes);
    file
}

#[test]
fn a_header_with_the_wrong_version_or_lengths_is_refused() {
    let (file, _) = sealed();
    let good = vault::read_header(&file).unwrap();
    assert!(vault::read_header(&file_with(&good)).is_ok());
    let bad = [
        Header {
            v: 2,
            ..good.clone()
        },
        Header {
            salt: vec![0; 31],
            ..good.clone()
        },
        Header {
            nonce: vec![0; 23],
            ..good
        },
    ];
    for header in bad {
        assert_eq!(
            vault::read_header(&file_with(&header)).err(),
            Some(Error::VaultFormat),
            "{header:?}"
        );
    }
}

#[test]
fn sealing_twice_gives_different_ciphertext() {
    let (a, _) = sealed();
    let (b, _) = sealed();
    assert_ne!(a, b, "the nonce must be fresh every time");
}

#[test]
fn device_name_with_escapes_is_refused() {
    let salt = [7u8; 32];
    let secret = vault::passphrase_secret(PASS, &salt).unwrap();
    let mut b = body();
    b.device_name = "mac\u{1b}[2J".to_owned();
    assert_eq!(
        vault::seal(protector(), &secret[..], salt, &b).err(),
        Some(Error::BadText)
    );
}

#[test]
fn a_vault_sealed_under_another_secret_cannot_be_swapped_in() {
    // Someone replaces vault.bin with one they made. Unlocking with the owner's secret
    // must fail rather than silently trust the attacker's peer list.
    let salt = [9u8; 32];
    let attacker = vault::passphrase_secret("attacker passphrase", &salt).unwrap();
    let swapped = vault::seal(protector(), &attacker[..], salt, &body()).unwrap();
    let owner = vault::passphrase_secret(PASS, &salt).unwrap();
    assert_eq!(
        vault::open(&swapped, &owner[..]).err(),
        Some(Error::VaultAuth)
    );
}
