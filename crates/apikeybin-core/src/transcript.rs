//! The transcript hashes raw bytes as sent and received, never a re-encoding. Every
//! concatenation below has at most one variable length field, and it is last, so there is
//! no ambiguity about where one field ends.

use hkdf::Hkdf;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::error::Error;

pub const XFER_CONTEXT: &[u8] = b"apikeybin/xfer/1";
pub const LABEL_OFFER: &[u8] = b"apikeybin/offer";
pub const LABEL_ACCEPT: &[u8] = b"apikeybin/accept";
pub const LABEL_DATA: &[u8] = b"apikeybin/data";
pub const LABEL_ACK: &[u8] = b"apikeybin/ack";
pub const INFO_PAYLOAD: &[u8] = b"apikeybin/xfer/payload/v1";

fn hash(parts: &[&[u8]]) -> [u8; 32] {
    let mut h = Sha256::new();
    for part in parts {
        h.update(part);
    }
    h.finalize().into()
}

fn with_label(label: &[u8], digest: [u8; 32]) -> Vec<u8> {
    let mut out = Vec::with_capacity(label.len() + digest.len());
    out.extend_from_slice(label);
    out.extend_from_slice(&digest);
    out
}

pub fn th0(eid_sender: &[u8; 32], eid_receiver: &[u8; 32]) -> [u8; 32] {
    hash(&[XFER_CONTEXT, eid_sender, eid_receiver])
}

/// th1 = H(th0 || Offer frame), th2 = H(th1 || Accept frame), th3 = H(th2 || Data frame).
pub fn next(previous: &[u8; 32], raw_frame: &[u8]) -> [u8; 32] {
    hash(&[previous, raw_frame])
}

pub fn offer_to_sign(th0: &[u8; 32], offer_body: &[u8]) -> Vec<u8> {
    with_label(LABEL_OFFER, hash(&[th0, offer_body]))
}

pub fn accept_to_sign(th1: &[u8; 32], id: &[u8; 16], ek: &[u8]) -> Vec<u8> {
    with_label(LABEL_ACCEPT, hash(&[th1, id, ek]))
}

pub fn data_to_sign(
    th2: &[u8; 32],
    id: &[u8; 16],
    ct: &[u8],
    nonce: &[u8; 24],
    body: &[u8],
) -> Vec<u8> {
    with_label(LABEL_DATA, hash(&[th2, id, ct, nonce, body]))
}

pub fn ack_to_sign(th3: &[u8; 32], id: &[u8; 16], ok: bool) -> Vec<u8> {
    with_label(LABEL_ACK, hash(&[th3, id, &[u8::from(ok)]]))
}

pub fn payload_key(shared: &[u8], th2: &[u8; 32]) -> Result<Zeroizing<[u8; 32]>, Error> {
    let mut key = Zeroizing::new([0u8; 32]);
    Hkdf::<Sha256>::new(Some(th2), shared)
        .expand(INFO_PAYLOAD, key.as_mut_slice())
        .map_err(|_| Error::Crypto)?;
    Ok(key)
}

pub fn payload_ad(th2: &[u8; 32], ct: &[u8]) -> Vec<u8> {
    let mut ad = Vec::with_capacity(th2.len() + ct.len());
    ad.extend_from_slice(th2);
    ad.extend_from_slice(ct);
    ad
}
