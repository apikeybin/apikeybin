//! The transfer as two state machines. Each step consumes the previous state, so sending
//! `Data` before `Accept`, or using an ephemeral key twice, does not compile.

use core::fmt;

use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{KeyInit, XChaCha20Poly1305, XNonce};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, Zeroizing};

use crate::cbor;
use crate::error::Error;
use crate::kem::{Kem, XWing};
use crate::messages::{
    Accept, Ack, Data, Kind, Offer, OfferBody, PROTOCOL_VERSION, Reject, bstr_vec, decode_frame,
};
use crate::padding;
use crate::text;
use crate::transcript as tr;

/// How far an offer's timestamp may be from the receiver's clock, in seconds.
pub const OFFER_WINDOW_SECS: u64 = 300;

/// This device: the signing identity and the transport id it connects under.
pub struct Identity {
    signing: SigningKey,
    pub endpoint_id: [u8; 32],
}

impl fmt::Debug for Identity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Identity")
            .field("signing", &"[redacted]")
            .field("endpoint_id", &self.endpoint_id)
            .finish()
    }
}

impl Identity {
    pub fn from_secret(secret: &[u8; 32], endpoint_id: [u8; 32]) -> Self {
        Self {
            signing: SigningKey::from_bytes(secret),
            endpoint_id,
        }
    }

    pub fn public(&self) -> [u8; 32] {
        self.signing.verifying_key().to_bytes()
    }
}

/// A paired device, as stored in the vault.
#[derive(Debug, Clone)]
pub struct PeerKeys {
    identity: VerifyingKey,
    pub endpoint_id: [u8; 32],
}

impl PeerKeys {
    pub fn new(identity_pk: &[u8; 32], endpoint_id: [u8; 32]) -> Result<Self, Error> {
        let identity = VerifyingKey::from_bytes(identity_pk).map_err(|_| Error::WeakPeerKey)?;
        if identity.is_weak() {
            return Err(Error::WeakPeerKey);
        }
        Ok(Self {
            identity,
            endpoint_id,
        })
    }
}

fn verify(peer: &PeerKeys, msg: &[u8], sig: &[u8; 64]) -> Result<(), Error> {
    peer.identity
        .verify_strict(msg, &Signature::from_bytes(sig))
        .map_err(|_| Error::BadSignature)
}

fn random<const N: usize>() -> Result<[u8; N], Error> {
    let mut out = [0u8; N];
    getrandom::fill(&mut out).map_err(|_| Error::Rng)?;
    Ok(out)
}

/// The plaintext inside the AEAD. The label travels here, end to end encrypted, instead of
/// in the Offer. The kind lives only in the signed Offer, so the two cannot disagree.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Plain {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    label: Option<String>,
    #[serde(with = "bstr_vec")]
    content: Vec<u8>,
}

impl Drop for Plain {
    fn drop(&mut self) {
        self.content.zeroize();
    }
}

/// The content handed to delivery. Debug never shows it.
pub struct Delivered {
    pub kind: Kind,
    pub label: Option<String>,
    pub content: Zeroizing<Vec<u8>>,
}

impl fmt::Debug for Delivered {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Delivered")
            .field("kind", &self.kind)
            .field("label", &self.label)
            .field("content", &"[redacted]")
            .finish()
    }
}

/// State machines hold signing keys and ephemeral secrets, so Debug names the type only.
macro_rules! opaque_debug {
    ($($t:ty),* $(,)?) => {$(
        impl fmt::Debug for $t {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(stringify!($t))
            }
        }
    )*};
}

opaque_debug!(
    SenderAwaitingAccept,
    SenderAwaitingAck,
    ReceiverOffered,
    ReceiverAwaitingData
);

// ---------------------------------------------------------------------------- sender

pub struct SenderAwaitingAccept {
    id: [u8; 16],
    th1: [u8; 32],
    signing: SigningKey,
    peer: PeerKeys,
    padded: Zeroizing<Vec<u8>>,
}

pub struct SenderAwaitingAck {
    id: [u8; 16],
    th3: [u8; 32],
    peer: PeerKeys,
}

pub fn sender_start(
    me: &Identity,
    peer: &PeerKeys,
    kind: Kind,
    label: Option<&str>,
    content: &[u8],
    now: u64,
) -> Result<(SenderAwaitingAccept, Vec<u8>), Error> {
    if let Some(label) = label {
        text::validate(label, text::MAX_LABEL_BYTES)?;
    }
    let plain = Plain {
        label: label.map(str::to_owned),
        content: content.to_vec(),
    };
    let encoded = Zeroizing::new(cbor::encode(&plain)?);
    let bucket = padding::bucket_for(encoded.len())?;
    let padded = padding::pad(&encoded, bucket)?;

    let id = random::<16>()?;
    let body = cbor::encode(&OfferBody {
        v: PROTOCOL_VERSION,
        id,
        kind,
        bucket,
        ts: now,
    })?;
    let th0 = tr::th0(&me.endpoint_id, &peer.endpoint_id);
    let sig_o = me.signing.sign(&tr::offer_to_sign(&th0, &body)).to_bytes();
    let frame = cbor::encode(&Offer { body, sig_o })?;
    let th1 = tr::next(&th0, &frame);
    Ok((
        SenderAwaitingAccept {
            id,
            th1,
            signing: me.signing.clone(),
            peer: peer.clone(),
            padded,
        },
        frame,
    ))
}

impl SenderAwaitingAccept {
    /// Takes the peer's reply. `Err(RejectedByPeer)` if it was a matching Reject.
    pub fn on_reply(self, frame: &[u8]) -> Result<(SenderAwaitingAck, Vec<u8>), Error> {
        let accept: Accept = match decode_frame(frame) {
            Ok(accept) => accept,
            Err(first) => {
                return match decode_frame::<Reject>(frame) {
                    Ok(reject) if reject.id == self.id => Err(Error::RejectedByPeer(reject.reason)),
                    _ => Err(first),
                };
            }
        };
        if accept.id != self.id {
            return Err(Error::IdMismatch);
        }
        verify(
            &self.peer,
            &tr::accept_to_sign(&self.th1, &accept.id, &accept.ek),
            &accept.sig_r,
        )?;

        let th2 = tr::next(&self.th1, frame);
        let (ct, shared) = XWing::encapsulate(&accept.ek)?;
        let data = seal_data(
            &self.signing,
            &th2,
            &self.id,
            &ct,
            shared.as_slice(),
            &self.padded,
        )?;
        let frame = cbor::encode(&data)?;
        let th3 = tr::next(&th2, &frame);
        Ok((
            SenderAwaitingAck {
                id: self.id,
                th3,
                peer: self.peer,
            },
            frame,
        ))
    }
}

/// Public so the adversarial tests can act as a malicious but correctly signing sender.
pub fn seal_data(
    signing: &SigningKey,
    th2: &[u8; 32],
    id: &[u8; 16],
    ct: &[u8; crate::kem::CT_LEN],
    shared: &[u8],
    padded: &[u8],
) -> Result<Data, Error> {
    let key = tr::payload_key(shared, th2)?;
    let nonce = random::<24>()?;
    let aad = tr::payload_ad(th2, ct);
    let cipher = XChaCha20Poly1305::new_from_slice(key.as_slice()).map_err(|_| Error::Crypto)?;
    let body = cipher
        .encrypt(
            &XNonce::from(nonce),
            Payload {
                msg: padded,
                aad: &aad,
            },
        )
        .map_err(|_| Error::Crypto)?;
    let sig_s = signing
        .sign(&tr::data_to_sign(th2, id, ct, &nonce, &body))
        .to_bytes();
    Ok(Data {
        id: *id,
        ct: *ct,
        nonce,
        body,
        sig_s,
    })
}

impl SenderAwaitingAck {
    /// Ok(true) only for a correctly signed Ack saying the content was delivered.
    pub fn on_ack(self, frame: &[u8]) -> Result<bool, Error> {
        let ack: Ack = decode_frame(frame)?;
        if ack.id != self.id {
            return Err(Error::IdMismatch);
        }
        verify(
            &self.peer,
            &tr::ack_to_sign(&self.th3, &ack.id, ack.ok),
            &ack.sig_a,
        )?;
        Ok(ack.ok)
    }
}

// -------------------------------------------------------------------------- receiver

/// What may be shown to the person deciding. The sender's name and fingerprint come from
/// the vault entry the caller already looked up, not from this message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OfferInfo {
    pub id: [u8; 16],
    pub kind: Kind,
    pub bucket: u32,
}

pub struct ReceiverOffered {
    info: OfferInfo,
    th1: [u8; 32],
    signing: SigningKey,
    peer: PeerKeys,
}

pub struct ReceiverAwaitingData {
    info: OfferInfo,
    th2: [u8; 32],
    signing: SigningKey,
    peer: PeerKeys,
    dk: <XWing as Kem>::DecapsulationKey,
}

/// The caller already matched the connection's endpoint id to `peer`. A frame from anyone
/// else fails here, because `th0` includes both ids and the signature covers it.
pub fn receiver_on_offer(
    me: &Identity,
    peer: &PeerKeys,
    frame: &[u8],
    now: u64,
) -> Result<(ReceiverOffered, OfferInfo), Error> {
    let offer: Offer = decode_frame(frame)?;
    let th0 = tr::th0(&peer.endpoint_id, &me.endpoint_id);
    verify(peer, &tr::offer_to_sign(&th0, &offer.body), &offer.sig_o)?;
    let body: OfferBody = cbor::decode_strict(&offer.body, 256)?;
    if body.v != PROTOCOL_VERSION {
        return Err(Error::UnsupportedVersion);
    }
    if !padding::is_bucket(body.bucket) {
        return Err(Error::BadBucket);
    }
    if body.ts.abs_diff(now) > OFFER_WINDOW_SECS {
        return Err(Error::Expired);
    }
    let info = OfferInfo {
        id: body.id,
        kind: body.kind,
        bucket: body.bucket,
    };
    Ok((
        ReceiverOffered {
            info,
            th1: tr::next(&th0, frame),
            signing: me.signing.clone(),
            peer: peer.clone(),
        },
        info,
    ))
}

impl ReceiverOffered {
    pub fn accept(self) -> Result<(ReceiverAwaitingData, Vec<u8>), Error> {
        let seed = Zeroizing::new(random::<32>()?);
        let (dk, ek) = XWing::generate(seed)?;
        let sig_r = self
            .signing
            .sign(&tr::accept_to_sign(&self.th1, &self.info.id, &ek))
            .to_bytes();
        let frame = cbor::encode(&Accept {
            id: self.info.id,
            ek,
            sig_r,
        })?;
        let th2 = tr::next(&self.th1, &frame);
        Ok((
            ReceiverAwaitingData {
                info: self.info,
                th2,
                signing: self.signing,
                peer: self.peer,
                dk,
            },
            frame,
        ))
    }

    pub fn reject(self, reason: u8) -> Result<Vec<u8>, Error> {
        cbor::encode(&Reject {
            id: self.info.id,
            reason,
        })
    }
}

impl ReceiverAwaitingData {
    /// Verifies before decrypting. The decapsulation key is consumed and dropped here,
    /// which is what gives each transfer forward secrecy.
    pub fn on_data(self, frame: &[u8]) -> Result<(Delivered, Vec<u8>), Error> {
        let data: Data = decode_frame(frame)?;
        if data.id != self.info.id {
            return Err(Error::IdMismatch);
        }
        verify(
            &self.peer,
            &tr::data_to_sign(&self.th2, &data.id, &data.ct, &data.nonce, &data.body),
            &data.sig_s,
        )?;
        let shared = XWing::decapsulate(&self.dk, &data.ct)?;
        let key = tr::payload_key(shared.as_slice(), &self.th2)?;
        let aad = tr::payload_ad(&self.th2, &data.ct);
        let cipher =
            XChaCha20Poly1305::new_from_slice(key.as_slice()).map_err(|_| Error::Crypto)?;
        let padded = Zeroizing::new(
            cipher
                .decrypt(
                    &XNonce::from(data.nonce),
                    Payload {
                        msg: &data.body,
                        aad: &aad,
                    },
                )
                .map_err(|_| Error::Crypto)?,
        );
        let encoded = padding::unpad(&padded, self.info.bucket)?;
        let plain: Plain = cbor::decode_strict(encoded, crate::messages::MAX_FRAME_LEN)?;
        if let Some(label) = &plain.label {
            text::validate(label, text::MAX_LABEL_BYTES)?;
        }
        let th3 = tr::next(&self.th2, frame);
        let sig_a = self
            .signing
            .sign(&tr::ack_to_sign(&th3, &self.info.id, true))
            .to_bytes();
        let ack = cbor::encode(&Ack {
            id: self.info.id,
            ok: true,
            sig_a,
        })?;
        Ok((
            Delivered {
                kind: self.info.kind,
                label: plain.label.clone(),
                content: Zeroizing::new(plain.content.clone()),
            },
            ack,
        ))
    }
}
