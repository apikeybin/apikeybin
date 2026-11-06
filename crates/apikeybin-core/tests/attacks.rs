//! The attacker controls the network and may hold some keys. Each test says which, and
//! what must not happen. A test that only checks "an error came back" would pass on a
//! broken decoder, so the happy path is checked first in every helper.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]

use ed25519_dalek::{Signer, SigningKey};
use apikeybin_core::cbor;
use apikeybin_core::kem::{CT_LEN, Kem, XWing};
use apikeybin_core::messages::{Accept, Ack, Data, Kind, Offer, OfferBody, decode_frame};
use apikeybin_core::padding;
use apikeybin_core::transcript as tr;
use apikeybin_core::xfer::{
    Identity, OFFER_WINDOW_SECS, PeerKeys, receiver_on_offer, seal_data, sender_start,
};
use apikeybin_core::{Error, text};

const NOW: u64 = 1_800_000_000;
const SECRET: &[u8] = b"STRIPE_KEY=sk_live_CANARY";

struct Party {
    secret: [u8; 32],
    id: Identity,
}

fn party(n: u8) -> Party {
    let secret = [n; 32];
    let mut eid = [n; 32];
    eid[0] ^= 0xA5;
    Party {
        secret,
        id: Identity::from_secret(&secret, eid),
    }
}

fn keys(p: &Party) -> PeerKeys {
    PeerKeys::new(&p.id.public(), p.id.endpoint_id).unwrap()
}

/// Runs one honest transfer and returns all frames.
fn honest() -> (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>) {
    let (s, r) = (party(1), party(2));
    let (st, offer) =
        sender_start(&s.id, &keys(&r), Kind::Env, Some("prod.env"), SECRET, NOW).unwrap();
    let (rt, info) = receiver_on_offer(&r.id, &keys(&s), &offer, NOW).unwrap();
    assert_eq!(info.kind, Kind::Env);
    let (rt, accept) = rt.accept().unwrap();
    let (st, data) = st.on_reply(&accept).unwrap();
    let (got, ack) = rt.on_data(&data).unwrap();
    assert_eq!(&*got.content, SECRET);
    assert_eq!(got.kind, Kind::Env);
    assert_eq!(got.label.as_deref(), Some("prod.env"));
    assert!(st.on_ack(&ack).unwrap());
    (offer, accept, data, ack)
}

#[test]
fn honest_run_round_trips() {
    honest();
}

#[test]
fn every_bucket_boundary_round_trips() {
    let (s, r) = (party(1), party(2));
    for size in [
        0usize, 1, 1000, 1024, 4000, 4096, 16_000, 65_000, 262_000, 1_048_000,
    ] {
        let content = vec![0x41u8; size];
        let (st, offer) = sender_start(&s.id, &keys(&r), Kind::Text, None, &content, NOW).unwrap();
        let (rt, _) = receiver_on_offer(&r.id, &keys(&s), &offer, NOW).unwrap();
        let (rt, accept) = rt.accept().unwrap();
        let (st, data) = st.on_reply(&accept).unwrap();
        let (got, ack) = rt.on_data(&data).unwrap();
        assert_eq!(&*got.content, &content, "size {size}");
        assert!(st.on_ack(&ack).unwrap());
    }
}

#[test]
fn too_large_content_is_refused_by_the_sender() {
    let (s, r) = (party(1), party(2));
    let content = vec![0u8; 1_048_576];
    let e = sender_start(&s.id, &keys(&r), Kind::File, None, &content, NOW).err();
    assert_eq!(e, Some(Error::PayloadTooLarge));
}

#[test]
fn flipping_any_byte_of_the_offer_is_rejected() {
    let (s, r) = (party(1), party(2));
    let (_, offer) = sender_start(&s.id, &keys(&r), Kind::Env, None, SECRET, NOW).unwrap();
    for i in 0..offer.len() {
        for bit in 0..8 {
            let mut bad = offer.clone();
            bad[i] ^= 1 << bit;
            assert!(
                receiver_on_offer(&r.id, &keys(&s), &bad, NOW).is_err(),
                "byte {i} bit {bit} accepted"
            );
        }
    }
}

#[test]
fn flipping_any_byte_of_the_accept_is_rejected() {
    let (s, r) = (party(1), party(2));
    let session = || {
        let (st, offer) = sender_start(&s.id, &keys(&r), Kind::Env, None, SECRET, NOW).unwrap();
        let (rt, _) = receiver_on_offer(&r.id, &keys(&s), &offer, NOW).unwrap();
        let (_, accept) = rt.accept().unwrap();
        (st, accept)
    };
    let len = session().1.len();
    for i in 0..len {
        let (st, mut bad) = session();
        bad[i] ^= 0x01;
        assert!(st.on_reply(&bad).is_err(), "byte {i} accepted");
    }
}

#[test]
fn flipping_bytes_of_data_is_rejected_at_every_field() {
    let (s, r) = (party(1), party(2));
    // Sample across the whole frame: id, ct, nonce, body, signature, and the CBOR framing.
    let probe = {
        let (st, offer) = sender_start(&s.id, &keys(&r), Kind::Env, None, SECRET, NOW).unwrap();
        let (rt, _) = receiver_on_offer(&r.id, &keys(&s), &offer, NOW).unwrap();
        let (_, accept) = rt.accept().unwrap();
        let (_, data) = st.on_reply(&accept).unwrap();
        data.len()
    };
    let mut positions: Vec<usize> = (0..probe).step_by(11).collect();
    positions.extend(0..60);
    positions.extend(probe - 80..probe);
    for i in positions {
        let (st, offer) = sender_start(&s.id, &keys(&r), Kind::Env, None, SECRET, NOW).unwrap();
        let (rt, _) = receiver_on_offer(&r.id, &keys(&s), &offer, NOW).unwrap();
        let (rt, accept) = rt.accept().unwrap();
        let (_, data) = st.on_reply(&accept).unwrap();
        let mut bad = data.clone();
        bad[i] ^= 0x01;
        assert!(rt.on_data(&bad).is_err(), "byte {i} accepted");
    }
}

#[test]
fn stolen_transport_key_alone_cannot_get_a_prompt() {
    // Attacker holds the sender's transport id but not its identity key. They sign the
    // Offer with their own key. No prompt, because verification fails before anything is
    // shown.
    let (s, r, attacker) = (party(1), party(2), party(9));
    let impostor = Identity::from_secret(&attacker.secret, s.id.endpoint_id);
    let (_, offer) = sender_start(&impostor, &keys(&r), Kind::Env, None, SECRET, NOW).unwrap();
    let e = receiver_on_offer(&r.id, &keys(&s), &offer, NOW).err();
    assert_eq!(e, Some(Error::BadSignature));
}

#[test]
fn stolen_receiver_transport_key_cannot_complete_the_exchange() {
    // Attacker answers as the receiver's endpoint with their own identity key. The sender
    // has the real identity key pinned, so it never encrypts to the attacker's ek.
    let (s, r, attacker) = (party(1), party(2), party(9));
    let impostor = Identity::from_secret(&attacker.secret, r.id.endpoint_id);
    let (st, offer) = sender_start(&s.id, &keys(&r), Kind::Env, None, SECRET, NOW).unwrap();
    let (rt, _) = receiver_on_offer(&impostor, &keys(&s), &offer, NOW).unwrap();
    let (_, accept) = rt.accept().unwrap();
    assert_eq!(st.on_reply(&accept).err(), Some(Error::BadSignature));
}

#[test]
fn offer_is_bound_to_both_endpoints() {
    // A valid offer, delivered to a different receiver, or claimed from a different
    // transport id, must not verify.
    let (s, r, other) = (party(1), party(2), party(3));
    let (_, offer) = sender_start(&s.id, &keys(&r), Kind::Env, None, SECRET, NOW).unwrap();
    assert!(receiver_on_offer(&other.id, &keys(&s), &offer, NOW).is_err());

    let moved = PeerKeys::new(&s.id.public(), [0x77; 32]).unwrap();
    assert!(receiver_on_offer(&r.id, &moved, &offer, NOW).is_err());
}

#[test]
fn signatures_do_not_cross_message_types() {
    // Take the receiver's Accept signature and present it as its Ack signature.
    let (s, r) = (party(1), party(2));
    let (st, offer) = sender_start(&s.id, &keys(&r), Kind::Env, None, SECRET, NOW).unwrap();
    let (rt, _) = receiver_on_offer(&r.id, &keys(&s), &offer, NOW).unwrap();
    let (rt, accept) = rt.accept().unwrap();
    let parsed: Accept = decode_frame(&accept).unwrap();
    let (st, data) = st.on_reply(&accept).unwrap();
    let (_, ack) = rt.on_data(&data).unwrap();
    let mut forged: Ack = decode_frame(&ack).unwrap();
    forged.sig_a = parsed.sig_r;
    assert_eq!(
        st.on_ack(&cbor::encode(&forged).unwrap()).err(),
        Some(Error::BadSignature)
    );
}

#[test]
fn ack_cannot_be_forged_or_flipped() {
    let (s, r, attacker) = (party(1), party(2), party(9));
    let session = || {
        let (st, offer) = sender_start(&s.id, &keys(&r), Kind::Env, None, SECRET, NOW).unwrap();
        let (rt, _) = receiver_on_offer(&r.id, &keys(&s), &offer, NOW).unwrap();
        let (rt, accept) = rt.accept().unwrap();
        let (st, data) = st.on_reply(&accept).unwrap();
        let (_, ack) = rt.on_data(&data).unwrap();
        (st, ack)
    };
    // Flip ok=true to ok=false without the key.
    let (st, ack) = session();
    let mut parsed: Ack = decode_frame(&ack).unwrap();
    parsed.ok = false;
    assert_eq!(
        st.on_ack(&cbor::encode(&parsed).unwrap()).err(),
        Some(Error::BadSignature)
    );
    // Forge with another key.
    let (st, ack) = session();
    let mut parsed: Ack = decode_frame(&ack).unwrap();
    parsed.sig_a = SigningKey::from_bytes(&attacker.secret)
        .sign(b"anything")
        .to_bytes();
    assert_eq!(
        st.on_ack(&cbor::encode(&parsed).unwrap()).err(),
        Some(Error::BadSignature)
    );
    // Replay an Ack from another session.
    let (_, old_ack) = session();
    let (st, _) = session();
    assert!(st.on_ack(&old_ack).is_err());
}

#[test]
fn frames_from_another_session_do_not_work() {
    let (s, r) = (party(1), party(2));
    let session = || {
        let (st, offer) = sender_start(&s.id, &keys(&r), Kind::Env, None, SECRET, NOW).unwrap();
        let (rt, _) = receiver_on_offer(&r.id, &keys(&s), &offer, NOW).unwrap();
        let (rt, accept) = rt.accept().unwrap();
        (st, rt, accept)
    };
    // Replay an old Accept into a new sender.
    let (_, _, old_accept) = session();
    let (st, _, _) = session();
    assert!(st.on_reply(&old_accept).is_err());
    // Replay an old Data into a new receiver.
    let (st_a, _, accept_a) = session();
    let (_, old_data) = st_a.on_reply(&accept_a).unwrap();
    let (_, rt_b, _) = session();
    assert!(rt_b.on_data(&old_data).is_err());
}

#[test]
fn stale_or_future_offers_are_rejected_and_the_edge_is_accepted() {
    let (s, r) = (party(1), party(2));
    let (_, offer) = sender_start(&s.id, &keys(&r), Kind::Env, None, SECRET, NOW).unwrap();
    for now in [NOW - OFFER_WINDOW_SECS, NOW + OFFER_WINDOW_SECS] {
        assert!(receiver_on_offer(&r.id, &keys(&s), &offer, now).is_ok());
    }
    for now in [
        NOW - OFFER_WINDOW_SECS - 1,
        NOW + OFFER_WINDOW_SECS + 1,
        0,
        u64::MAX,
    ] {
        assert_eq!(
            receiver_on_offer(&r.id, &keys(&s), &offer, now).err(),
            Some(Error::Expired)
        );
    }
}

/// A paired sender that signs correctly but sends something other than what it promised.
/// Protects the receiver from a compromised paired device.
fn malicious_data(
    tweak_padded: impl Fn(&[u8]) -> Vec<u8>,
    tweak_ct: impl Fn(&mut [u8; CT_LEN]),
) -> Result<(), Error> {
    let (s, r) = (party(1), party(2));
    let body = cbor::encode(&OfferBody {
        v: 1,
        id: [7; 16],
        kind: Kind::Text,
        bucket: 1024,
        ts: NOW,
    })
    .unwrap();
    let th0 = tr::th0(&s.id.endpoint_id, &r.id.endpoint_id);
    let signing = SigningKey::from_bytes(&s.secret);
    let sig_o = signing.sign(&tr::offer_to_sign(&th0, &body)).to_bytes();
    let offer = cbor::encode(&Offer { body, sig_o }).unwrap();
    let th1 = tr::next(&th0, &offer);
    let (rt, _) = receiver_on_offer(&r.id, &keys(&s), &offer, NOW).unwrap();
    let (rt, accept) = rt.accept().unwrap();
    let parsed: Accept = decode_frame(&accept).unwrap();
    let th2 = tr::next(&th1, &accept);
    let (mut ct, shared) = XWing::encapsulate(&parsed.ek).unwrap();
    tweak_ct(&mut ct);
    let plain = cbor::encode(&PlainProbe {
        content: serde_bytes_ref(SECRET),
    })
    .unwrap();
    let padded = padding::pad(&plain, 1024).unwrap();
    let padded = tweak_padded(&padded);
    let data = seal_data(&signing, &th2, &[7; 16], &ct, &shared[..], &padded).unwrap();
    rt.on_data(&cbor::encode(&data).unwrap()).map(|_| ())
}

#[derive(serde::Serialize)]
struct PlainProbe<'a> {
    content: BytesRef<'a>,
}
struct BytesRef<'a>(&'a [u8]);
impl serde::Serialize for BytesRef<'_> {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_bytes(self.0)
    }
}
fn serde_bytes_ref(b: &[u8]) -> BytesRef<'_> {
    BytesRef(b)
}

#[test]
fn malicious_sender_control_passes() {
    // Without this, the tests below could be failing for the wrong reason.
    assert_eq!(malicious_data(|p| p.to_vec(), |_| {}), Ok(()));
}

#[test]
fn malicious_sender_wrong_bucket_size() {
    // Promised 1024, padded to 4096.
    let r = malicious_data(
        |p| {
            let mut v = p.to_vec();
            v.resize(4096, 0);
            v
        },
        |_| {},
    );
    assert_eq!(r, Err(Error::BadPadding));
}

#[test]
fn malicious_sender_nonzero_padding_is_a_covert_channel_and_refused() {
    let r = malicious_data(
        |p| {
            let mut v = p.to_vec();
            *v.last_mut().unwrap() = 1;
            v
        },
        |_| {},
    );
    assert_eq!(r, Err(Error::BadPadding));
}

#[test]
fn malicious_sender_lying_length_prefix() {
    let r = malicious_data(
        |p| {
            let mut v = p.to_vec();
            v[..4].copy_from_slice(&u32::MAX.to_be_bytes());
            v
        },
        |_| {},
    );
    assert_eq!(r, Err(Error::BadPadding));
}

#[test]
fn malicious_sender_non_contributory_x25519_is_refused() {
    // The X25519 part of an X-Wing ciphertext is its last 32 bytes. An all zero point
    // makes the X25519 output all zero whatever the receiver's key is.
    let r = malicious_data(|p| p.to_vec(), |ct| ct[CT_LEN - 32..].fill(0));
    assert_eq!(r, Err(Error::Crypto));
}

#[test]
fn malicious_label_with_terminal_escapes_is_refused() {
    let (s, r) = (party(1), party(2));
    for evil in [
        "\u{1b}]52;c;ZXZpbA==\u{7}",
        "a\nb",
        "a\u{202e}b",
        "a\u{0000}b",
        "a\u{200b}b",
        "\u{9b}31m",
        "",
    ] {
        assert_eq!(
            sender_start(&s.id, &keys(&r), Kind::Text, Some(evil), SECRET, NOW).err(),
            Some(Error::BadText),
            "{evil:?}"
        );
        assert_eq!(text::validate(evil, 128), Err(Error::BadText), "{evil:?}");
    }
    assert!(text::validate("prod.env", 128).is_ok());
    assert!(text::validate("本番の鍵", 128).is_ok());
    assert_eq!(text::validate(&"a".repeat(129), 128), Err(Error::BadText));
}

#[test]
fn offer_with_unknown_bucket_or_version_is_refused_even_if_signed() {
    let (s, r) = (party(1), party(2));
    let th0 = tr::th0(&s.id.endpoint_id, &r.id.endpoint_id);
    let signing = SigningKey::from_bytes(&s.secret);
    let signed = |v: u8, bucket: u32| {
        let body = cbor::encode(&OfferBody {
            v,
            id: [7; 16],
            kind: Kind::Text,
            bucket,
            ts: NOW,
        })
        .unwrap();
        let sig_o = signing.sign(&tr::offer_to_sign(&th0, &body)).to_bytes();
        cbor::encode(&Offer { body, sig_o }).unwrap()
    };
    assert_eq!(
        receiver_on_offer(&r.id, &keys(&s), &signed(1, 1000), NOW).err(),
        Some(Error::BadBucket)
    );
    assert_eq!(
        receiver_on_offer(&r.id, &keys(&s), &signed(2, 1024), NOW).err(),
        Some(Error::UnsupportedVersion)
    );
    assert!(receiver_on_offer(&r.id, &keys(&s), &signed(1, 1024), NOW).is_ok());
}

#[test]
fn weak_peer_keys_are_refused_at_pairing_time() {
    // The all-zero encoding and the identity element are small order points.
    let mut identity = [0u8; 32];
    identity[0] = 1;
    assert_eq!(
        PeerKeys::new(&identity, [1; 32]).err(),
        Some(Error::WeakPeerKey)
    );
}

#[test]
fn oversized_frames_are_refused_before_parsing() {
    let huge = vec![0u8; apikeybin_core::messages::MAX_FRAME_LEN + 1];
    assert_eq!(decode_frame::<Data>(&huge).err(), Some(Error::FrameTooLong));
    assert_eq!(
        decode_frame::<Accept>(&huge).err(),
        Some(Error::FrameTooLong)
    );
}

#[test]
fn malformed_cbor_is_refused_and_does_not_allocate_wildly() {
    let (offer, _, _, _) = honest();
    // Trailing garbage.
    let mut trailing = offer.clone();
    trailing.push(0);
    assert_eq!(decode_frame::<Offer>(&trailing).err(), Some(Error::Decode));
    // A map entry claiming a 2^64-1 byte string, as the first field value.
    let mut bomb = vec![0xA2, 0x64, b'b', b'o', b'd', b'y', 0x5B];
    bomb.extend_from_slice(&[0xFF; 8]);
    assert!(decode_frame::<Offer>(&bomb).is_err());
    // Deep nesting.
    let deep = vec![0x81u8; 10_000];
    assert!(decode_frame::<Offer>(&deep).is_err());
    // Indefinite length and wrong types.
    for bad in [
        &[0xBFu8, 0xFF][..],
        &[0x00][..],
        &[][..],
        &[0xF6][..],
        &[0x5F, 0xFF][..],
    ] {
        assert!(decode_frame::<Offer>(bad).is_err(), "{bad:?}");
    }
}

#[test]
fn unknown_and_duplicate_fields_are_refused() {
    use ciborium::value::Value;
    let (offer, _, _, _) = honest();
    let parsed: Offer = decode_frame(&offer).unwrap();
    let base = vec![
        (
            Value::Text("body".into()),
            Value::Bytes(parsed.body.clone()),
        ),
        (
            Value::Text("sig_o".into()),
            Value::Bytes(parsed.sig_o.to_vec()),
        ),
    ];
    let enc = |m: Vec<(Value, Value)>| {
        let mut out = Vec::new();
        ciborium::ser::into_writer(&Value::Map(m), &mut out).unwrap();
        out
    };
    assert!(
        decode_frame::<Offer>(&enc(base.clone())).is_ok(),
        "control failed"
    );

    let mut extra = base.clone();
    extra.push((Value::Text("label".into()), Value::Text("x".into())));
    assert!(decode_frame::<Offer>(&enc(extra)).is_err());

    let mut dup = base.clone();
    dup.push((Value::Text("body".into()), Value::Bytes(vec![1])));
    assert!(decode_frame::<Offer>(&enc(dup)).is_err());

    let wrong_len = vec![
        (
            Value::Text("body".into()),
            Value::Bytes(parsed.body.clone()),
        ),
        (Value::Text("sig_o".into()), Value::Bytes(vec![0; 63])),
    ];
    assert!(decode_frame::<Offer>(&enc(wrong_len)).is_err());
}

#[test]
fn each_transfer_uses_fresh_key_material() {
    let (_, a1, d1, _) = honest();
    let (_, a2, d2, _) = honest();
    let (a1, a2): (Accept, Accept) = (decode_frame(&a1).unwrap(), decode_frame(&a2).unwrap());
    let (d1, d2): (Data, Data) = (decode_frame(&d1).unwrap(), decode_frame(&d2).unwrap());
    assert_ne!(a1.ek.as_slice(), a2.ek.as_slice());
    assert_ne!(d1.ct.as_slice(), d2.ct.as_slice());
    assert_ne!(d1.nonce, d2.nonce);
    assert_ne!(d1.body, d2.body);
    assert_ne!(a1.id, a2.id);
}

#[test]
fn no_frame_contains_the_secret_or_the_label_in_the_clear() {
    let (offer, accept, data, ack) = honest();
    for (name, frame) in [
        ("offer", &offer),
        ("accept", &accept),
        ("data", &data),
        ("ack", &ack),
    ] {
        for needle in [SECRET, b"CANARY".as_slice(), b"prod.env".as_slice()] {
            assert!(
                !frame.windows(needle.len()).any(|w| w == needle),
                "{name} contains {:?}",
                String::from_utf8_lossy(needle)
            );
        }
    }
}

#[test]
fn debug_output_redacts_secrets() {
    let (s, r) = (party(1), party(2));
    let debug_id = format!("{:?}", s.id);
    assert!(debug_id.contains("[redacted]"));
    let (st, offer) = sender_start(&s.id, &keys(&r), Kind::Env, None, SECRET, NOW).unwrap();
    let (rt, _) = receiver_on_offer(&r.id, &keys(&s), &offer, NOW).unwrap();
    let (rt, accept) = rt.accept().unwrap();
    let (_, data) = st.on_reply(&accept).unwrap();
    let (got, _) = rt.on_data(&data).unwrap();
    let shown = format!("{got:?}");
    assert!(
        !shown.contains("CANARY") && !shown.contains("sk_live"),
        "{shown}"
    );
    assert!(shown.contains("[redacted]"));
}

// ---- added after mutation testing showed these checks could be removed unnoticed ----

#[test]
fn x25519_non_contributory_is_refused_by_the_kem_itself() {
    // Through the whole protocol this case also fails later, at the AEAD, with the same
    // error, so only a test at this level proves the KEM check exists. The control shows a
    // plain X-Wing decapsulation key does accept the same ciphertext.
    let (dk, ek) = XWing::generate(zeroize::Zeroizing::new([3u8; 32])).unwrap();
    let (mut ct, _) = XWing::encapsulate(&ek).unwrap();
    assert!(
        XWing::decapsulate(&dk, &ct).is_ok(),
        "honest ciphertext must work"
    );
    ct[CT_LEN - 32..].fill(0);
    assert_eq!(XWing::decapsulate(&dk, &ct).err(), Some(Error::Crypto));

    use x_wing::Decapsulate;
    let plain = x_wing::DecapsulationKey::from([3u8; 32]);
    let c = x_wing::Ciphertext::try_from(ct.as_slice()).unwrap();
    let _accepted_without_error = plain.decapsulate(&c);
}

#[test]
fn accept_with_a_different_id_is_refused_even_when_correctly_signed() {
    // A compromised paired receiver signs properly but answers about a different transfer.
    let (s, r) = (party(1), party(2));
    let (st, offer) = sender_start(&s.id, &keys(&r), Kind::Env, None, SECRET, NOW).unwrap();
    let th1 = tr::next(&tr::th0(&s.id.endpoint_id, &r.id.endpoint_id), &offer);
    let (_, ek) = XWing::generate(zeroize::Zeroizing::new([5u8; 32])).unwrap();
    let wrong_id = [0xEE; 16];
    let sig_r = SigningKey::from_bytes(&r.secret)
        .sign(&tr::accept_to_sign(&th1, &wrong_id, &ek))
        .to_bytes();
    let forged = cbor::encode(&Accept {
        id: wrong_id,
        ek,
        sig_r,
    })
    .unwrap();
    assert_eq!(st.on_reply(&forged).err(), Some(Error::IdMismatch));
}

#[test]
fn data_with_a_different_id_is_refused_even_when_correctly_signed() {
    let (s, r) = (party(1), party(2));
    let (_, offer) = sender_start(&s.id, &keys(&r), Kind::Env, None, SECRET, NOW).unwrap();
    let (rt, _) = receiver_on_offer(&r.id, &keys(&s), &offer, NOW).unwrap();
    let (rt, accept) = rt.accept().unwrap();
    let parsed: Accept = decode_frame(&accept).unwrap();
    let th2 = tr::next(
        &tr::next(&tr::th0(&s.id.endpoint_id, &r.id.endpoint_id), &offer),
        &accept,
    );
    let (ct, shared) = XWing::encapsulate(&parsed.ek).unwrap();
    let padded = padding::pad(b"x", 1024).unwrap();
    let data = seal_data(
        &SigningKey::from_bytes(&s.secret),
        &th2,
        &[0xEE; 16],
        &ct,
        &shared[..],
        &padded,
    )
    .unwrap();
    assert_eq!(
        rt.on_data(&cbor::encode(&data).unwrap()).err(),
        Some(Error::IdMismatch)
    );
}

/// Runs one Data frame from a sender that bypasses sender_start, carrying `plain` as the
/// encoded plaintext, and returns what the receiver did with it.
fn malicious_plain(plain: &[u8]) -> Result<(), Error> {
    let (s, r) = (party(1), party(2));
    let (_, offer) = sender_start(&s.id, &keys(&r), Kind::Text, None, b"x", NOW).unwrap();
    let (rt, info) = receiver_on_offer(&r.id, &keys(&s), &offer, NOW).unwrap();
    let (rt, accept) = rt.accept().unwrap();
    let parsed: Accept = decode_frame(&accept).unwrap();
    let th2 = tr::next(
        &tr::next(&tr::th0(&s.id.endpoint_id, &r.id.endpoint_id), &offer),
        &accept,
    );
    let (ct, shared) = XWing::encapsulate(&parsed.ek).unwrap();
    let padded = padding::pad(plain, info.bucket).unwrap();
    let data = seal_data(
        &SigningKey::from_bytes(&s.secret),
        &th2,
        &info.id,
        &ct,
        &shared[..],
        &padded,
    )
    .unwrap();
    rt.on_data(&cbor::encode(&data).unwrap()).map(|_| ())
}

#[test]
fn malicious_sender_cannot_put_terminal_escapes_in_the_received_label() {
    use ciborium::value::Value;
    let plain = |label: &str| {
        let mut out = Vec::new();
        ciborium::ser::into_writer(
            &Value::Map(vec![
                (Value::Text("label".into()), Value::Text(label.into())),
                (Value::Text("content".into()), Value::Bytes(b"x".to_vec())),
            ]),
            &mut out,
        )
        .unwrap();
        out
    };
    assert_eq!(
        malicious_plain(&plain("fine.env")),
        Ok(()),
        "control failed"
    );
    assert_eq!(
        malicious_plain(&plain("\u{1b}]52;c;ZXZpbA==\u{7}")),
        Err(Error::BadText)
    );
    assert_eq!(malicious_plain(&plain("a\u{202e}b")), Err(Error::BadText));
    assert_eq!(
        malicious_plain(&plain(&"a".repeat(200))),
        Err(Error::BadText)
    );
}

#[test]
fn malicious_sender_cannot_add_fields_or_a_kind_to_the_plaintext() {
    use ciborium::value::Value;
    let mut out = Vec::new();
    ciborium::ser::into_writer(
        &Value::Map(vec![
            (Value::Text("kind".into()), Value::Text("env".into())),
            (Value::Text("content".into()), Value::Bytes(b"x".to_vec())),
        ]),
        &mut out,
    )
    .unwrap();
    assert_eq!(malicious_plain(&out), Err(Error::Decode));
}

#[test]
fn a_frame_has_exactly_one_encoding() {
    use ciborium::value::Value;
    let (offer, accept, data, ack) = honest();
    // The original find: a text map key rewritten as a byte string with the same contents.
    let parsed: Offer = decode_frame(&offer).unwrap();
    let mut key_as_bytes = Vec::new();
    ciborium::ser::into_writer(
        &Value::Map(vec![
            (
                Value::Bytes(b"body".to_vec()),
                Value::Bytes(parsed.body.clone()),
            ),
            (
                Value::Text("sig_o".into()),
                Value::Bytes(parsed.sig_o.to_vec()),
            ),
        ]),
        &mut key_as_bytes,
    )
    .unwrap();
    assert_eq!(
        decode_frame::<Offer>(&key_as_bytes).err(),
        Some(Error::Decode)
    );

    // Reordered keys.
    let mut reordered = Vec::new();
    ciborium::ser::into_writer(
        &Value::Map(vec![
            (
                Value::Text("sig_o".into()),
                Value::Bytes(parsed.sig_o.to_vec()),
            ),
            (
                Value::Text("body".into()),
                Value::Bytes(parsed.body.clone()),
            ),
        ]),
        &mut reordered,
    )
    .unwrap();
    assert_eq!(decode_frame::<Offer>(&reordered).err(), Some(Error::Decode));

    // Honest frames still round trip byte for byte, which is what the rule depends on.
    assert_eq!(
        cbor::encode(&decode_frame::<Offer>(&offer).unwrap()).unwrap(),
        offer
    );
    assert_eq!(
        cbor::encode(&decode_frame::<Accept>(&accept).unwrap()).unwrap(),
        accept
    );
    assert_eq!(
        cbor::encode(&decode_frame::<Data>(&data).unwrap()).unwrap(),
        data
    );
    assert_eq!(
        cbor::encode(&decode_frame::<Ack>(&ack).unwrap()).unwrap(),
        ack
    );
}

#[test]
fn ack_with_a_different_id_is_refused_even_when_correctly_signed() {
    // A compromised paired receiver signs an Ack for a different transfer id.
    let (s, r) = (party(1), party(2));
    let (st, offer) = sender_start(&s.id, &keys(&r), Kind::Env, None, SECRET, NOW).unwrap();
    let (rt, _) = receiver_on_offer(&r.id, &keys(&s), &offer, NOW).unwrap();
    let (rt, accept) = rt.accept().unwrap();
    let (st, data) = st.on_reply(&accept).unwrap();
    let (_, _) = rt.on_data(&data).unwrap();
    let th0 = tr::th0(&s.id.endpoint_id, &r.id.endpoint_id);
    let th3 = tr::next(&tr::next(&tr::next(&th0, &offer), &accept), &data);
    let wrong_id = [0xEE; 16];
    let sig_a = SigningKey::from_bytes(&r.secret)
        .sign(&tr::ack_to_sign(&th3, &wrong_id, true))
        .to_bytes();
    let forged = cbor::encode(&Ack {
        id: wrong_id,
        ok: true,
        sig_a,
    })
    .unwrap();
    assert_eq!(st.on_ack(&forged).err(), Some(Error::IdMismatch));
}
