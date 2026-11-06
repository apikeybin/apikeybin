//! The vault file: everything secret this device holds, under one key.
//!
//! vault.bin := "SAV1" || u32_be(header_len) || header || aead_ct
//! KEK       := HKDF-SHA256(ikm = protector_secret, salt = salt, info = "apikeybin/vault-kek/v1")
//!
//! The header is authenticated as associated data, so changing it makes opening fail.

use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{KeyInit, XChaCha20Poly1305, XNonce};
use hkdf::Hkdf;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::cbor;
use crate::error::Error;
use crate::messages::bstr_vec;
use crate::text;

pub const MAGIC: &[u8; 4] = b"SAV1";
const MAX_HEADER_LEN: usize = 64 * 1024;
const MAX_VAULT_LEN: usize = 8 * 1024 * 1024;
const INFO_KEK: &[u8] = b"apikeybin/vault-kek/v1";

pub const MIN_PASSPHRASE_CHARS: usize = 12;
const ARGON2_M_KIB: u32 = 64 * 1024;
const ARGON2_T: u32 = 3;
const ARGON2_P: u32 = 1;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProtectorHeader {
    pub kind: String,
    #[serde(with = "bstr_vec")]
    pub data: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Header {
    pub v: u8,
    pub protector: ProtectorHeader,
    #[serde(with = "bstr_vec")]
    pub salt: Vec<u8>,
    #[serde(with = "bstr_vec")]
    pub nonce: Vec<u8>,
    pub created_at: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Peer {
    pub name: String,
    #[serde(with = "bstr_vec")]
    pub endpoint_id: Vec<u8>,
    #[serde(with = "bstr_vec")]
    pub identity_pk: Vec<u8>,
    pub paired_at: u64,
}

/// Holds the identity key and the transport key. Neither lives anywhere else, so a stolen
/// disk yields only ciphertext. Debug is redacted by hand.
#[derive(Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(deny_unknown_fields)]
pub struct Body {
    pub device_name: String,
    #[serde(with = "bstr_vec")]
    pub identity_sk: Vec<u8>,
    #[serde(with = "bstr_vec")]
    pub transport_sk: Vec<u8>,
    #[zeroize(skip)]
    pub peers: Vec<Peer>,
    pub created_at: u64,
}

impl core::fmt::Debug for Body {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Body")
            .field("device_name", &self.device_name)
            .field("identity_sk", &"[redacted]")
            .field("transport_sk", &"[redacted]")
            .field("peers", &self.peers.len())
            .field("created_at", &self.created_at)
            .finish()
    }
}

fn kek(protector_secret: &[u8], salt: &[u8]) -> Result<Zeroizing<[u8; 32]>, Error> {
    let mut out = Zeroizing::new([0u8; 32]);
    Hkdf::<Sha256>::new(Some(salt), protector_secret)
        .expand(INFO_KEK, out.as_mut_slice())
        .map_err(|_| Error::Crypto)?;
    Ok(out)
}

/// Encrypts with a fresh salt and nonce every time. `seal` never reuses a nonce under a
/// key, because the key changes with the salt as well.
pub fn seal(
    protector: ProtectorHeader,
    protector_secret: &[u8],
    salt: [u8; 32],
    body: &Body,
) -> Result<Vec<u8>, Error> {
    text::validate(&body.device_name, text::MAX_DEVICE_NAME_BYTES)?;
    let mut nonce = [0u8; 24];
    getrandom::fill(&mut nonce).map_err(|_| Error::Rng)?;
    let header = cbor::encode(&Header {
        v: 1,
        protector,
        salt: salt.to_vec(),
        nonce: nonce.to_vec(),
        created_at: body.created_at,
    })?;
    let plain = Zeroizing::new(cbor::encode(body)?);
    let key = kek(protector_secret, &salt)?;
    let cipher = XChaCha20Poly1305::new_from_slice(key.as_slice()).map_err(|_| Error::Crypto)?;
    let ct = cipher
        .encrypt(
            &XNonce::from(nonce),
            Payload {
                msg: &plain,
                aad: &header,
            },
        )
        .map_err(|_| Error::Crypto)?;
    let header_len = u32::try_from(header.len()).map_err(|_| Error::VaultFormat)?;
    let mut out = Vec::with_capacity(8 + header.len() + ct.len());
    out.extend_from_slice(MAGIC);
    out.extend_from_slice(&header_len.to_be_bytes());
    out.extend_from_slice(&header);
    out.extend_from_slice(&ct);
    Ok(out)
}

fn split(file: &[u8]) -> Result<(&[u8], &[u8]), Error> {
    if file.len() > MAX_VAULT_LEN {
        return Err(Error::VaultFormat);
    }
    let (magic, rest) = file.split_at_checked(4).ok_or(Error::VaultFormat)?;
    if magic != MAGIC.as_slice() {
        return Err(Error::VaultFormat);
    }
    let (len, rest) = rest.split_at_checked(4).ok_or(Error::VaultFormat)?;
    let len: [u8; 4] = len.try_into().map_err(|_| Error::VaultFormat)?;
    let len = usize::try_from(u32::from_be_bytes(len)).map_err(|_| Error::VaultFormat)?;
    if len > MAX_HEADER_LEN {
        return Err(Error::VaultFormat);
    }
    rest.split_at_checked(len).ok_or(Error::VaultFormat)
}

/// Reads the header without decrypting, because the protector needs it to unlock. Nothing
/// here is trusted until `open` authenticates it.
pub fn read_header(file: &[u8]) -> Result<Header, Error> {
    let (header, _) = split(file)?;
    let header: Header =
        cbor::decode_strict(header, MAX_HEADER_LEN).map_err(|_| Error::VaultFormat)?;
    if header.v != 1 || header.salt.len() != 32 || header.nonce.len() != 24 {
        return Err(Error::VaultFormat);
    }
    Ok(header)
}

pub fn open(file: &[u8], protector_secret: &[u8]) -> Result<Body, Error> {
    let header = read_header(file)?;
    let (raw_header, ct) = split(file)?;
    let nonce: [u8; 24] = header
        .nonce
        .as_slice()
        .try_into()
        .map_err(|_| Error::VaultFormat)?;
    let key = kek(protector_secret, &header.salt)?;
    let cipher = XChaCha20Poly1305::new_from_slice(key.as_slice()).map_err(|_| Error::Crypto)?;
    let plain = Zeroizing::new(
        cipher
            .decrypt(
                &XNonce::from(nonce),
                Payload {
                    msg: ct,
                    aad: raw_header,
                },
            )
            .map_err(|_| Error::VaultAuth)?,
    );
    cbor::decode_strict(&plain, MAX_VAULT_LEN).map_err(|_| Error::VaultFormat)
}

/// protector_secret for the passphrase protector. The parameters are fixed in v1 and are
/// not read from the file, so a tampered file cannot weaken them or demand huge memory.
pub fn passphrase_secret(passphrase: &str, salt: &[u8; 32]) -> Result<Zeroizing<[u8; 32]>, Error> {
    if passphrase.chars().count() < MIN_PASSPHRASE_CHARS {
        return Err(Error::WeakPassphrase);
    }
    let params =
        Params::new(ARGON2_M_KIB, ARGON2_T, ARGON2_P, Some(32)).map_err(|_| Error::Crypto)?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut out = Zeroizing::new([0u8; 32]);
    argon
        .hash_password_into(passphrase.as_bytes(), salt, out.as_mut_slice())
        .map_err(|_| Error::Crypto)?;
    Ok(out)
}
