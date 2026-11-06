//! Property tests: nothing an attacker sends may panic, and padding must round trip.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]

use proptest::prelude::*;
use apikeybin_core::messages::{Accept, Ack, Data, Kind, Offer, Reject, decode_frame};
use apikeybin_core::padding;
use apikeybin_core::vault;
use apikeybin_core::xfer::{Identity, PeerKeys, receiver_on_offer, sender_start};

const NOW: u64 = 1_800_000_000;

fn pair() -> (Identity, PeerKeys, Identity, PeerKeys) {
    let s = Identity::from_secret(&[1; 32], [11; 32]);
    let r = Identity::from_secret(&[2; 32], [22; 32]);
    let sk = PeerKeys::new(&s.public(), s.endpoint_id).unwrap();
    let rk = PeerKeys::new(&r.public(), r.endpoint_id).unwrap();
    (s, sk, r, rk)
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(2000))]

    #[test]
    fn pad_then_unpad_returns_the_input(data in proptest::collection::vec(any::<u8>(), 0..70_000)) {
        let bucket = padding::bucket_for(data.len()).unwrap();
        let padded = padding::pad(&data, bucket).unwrap();
        prop_assert_eq!(padded.len() as u32, bucket);
        prop_assert_eq!(padding::unpad(&padded, bucket).unwrap(), data.as_slice());
    }

    #[test]
    fn unpad_never_panics(data in proptest::collection::vec(any::<u8>(), 0..5000), bucket in any::<u32>()) {
        let _ = padding::unpad(&data, bucket);
    }

    #[test]
    fn decoders_never_panic_on_arbitrary_bytes(data in proptest::collection::vec(any::<u8>(), 0..4096)) {
        let _ = decode_frame::<Offer>(&data);
        let _ = decode_frame::<Accept>(&data);
        let _ = decode_frame::<Reject>(&data);
        let _ = decode_frame::<Data>(&data);
        let _ = decode_frame::<Ack>(&data);
        let _ = vault::read_header(&data);
        let _ = vault::open(&data, &[0u8; 32]);
    }

    #[test]
    fn receiver_never_panics_on_arbitrary_offers(data in proptest::collection::vec(any::<u8>(), 0..2048), now in any::<u64>()) {
        let (_, sk, r, _) = pair();
        prop_assert!(receiver_on_offer(&r, &sk, &data, now).is_err());
    }

    #[test]
    fn sender_never_panics_on_arbitrary_replies(data in proptest::collection::vec(any::<u8>(), 0..2048)) {
        let (s, _, _, rk) = pair();
        let (st, _) = sender_start(&s, &rk, Kind::Text, None, b"x", NOW).unwrap();
        prop_assert!(st.on_reply(&data).is_err());
    }

    #[test]
    fn receiver_never_panics_on_arbitrary_data(data in proptest::collection::vec(any::<u8>(), 0..2048)) {
        let (s, sk, r, rk) = pair();
        let (_, offer) = sender_start(&s, &rk, Kind::Text, None, b"x", NOW).unwrap();
        let (rt, _) = receiver_on_offer(&r, &sk, &offer, NOW).unwrap();
        let (rt, _) = rt.accept().unwrap();
        prop_assert!(rt.on_data(&data).is_err());
    }

    #[test]
    fn mutated_real_accepts_are_never_accepted(pos in 0usize..4000, mask in 1u8..=255) {
        let (s, sk, r, rk) = pair();
        let (st, offer) = sender_start(&s, &rk, Kind::Env, None, b"KEY=value", NOW).unwrap();
        let (rt, _) = receiver_on_offer(&r, &sk, &offer, NOW).unwrap();
        let (_, mut accept) = rt.accept().unwrap();
        let i = pos % accept.len();
        accept[i] ^= mask;
        prop_assert!(st.on_reply(&accept).is_err());
    }

    #[test]
    fn mutated_real_data_is_never_accepted(pos in 0usize..4000, mask in 1u8..=255) {
        let (s, sk, r, rk) = pair();
        let (st, offer) = sender_start(&s, &rk, Kind::Env, None, b"KEY=value", NOW).unwrap();
        let (rt, _) = receiver_on_offer(&r, &sk, &offer, NOW).unwrap();
        let (rt, accept) = rt.accept().unwrap();
        let (_, mut data) = st.on_reply(&accept).unwrap();
        let i = pos % data.len();
        data[i] ^= mask;
        prop_assert!(rt.on_data(&data).is_err());
    }

    #[test]
    fn mutated_real_acks_are_never_accepted(pos in 0usize..200, mask in 1u8..=255) {
        let (s, sk, r, rk) = pair();
        let (st, offer) = sender_start(&s, &rk, Kind::Env, None, b"KEY=value", NOW).unwrap();
        let (rt, _) = receiver_on_offer(&r, &sk, &offer, NOW).unwrap();
        let (rt, accept) = rt.accept().unwrap();
        let (st, data) = st.on_reply(&accept).unwrap();
        let (_, mut ack) = rt.on_data(&data).unwrap();
        let i = pos % ack.len();
        ack[i] ^= mask;
        prop_assert!(st.on_ack(&ack).is_err());
    }

    /// Structure-aware: start from a real frame and mutate it, which reaches far deeper than
    /// random bytes do.
    #[test]
    fn mutated_real_offers_never_panic_and_never_verify(pos in 0usize..4000, mask in 1u8..=255) {
        let (s, sk, r, rk) = pair();
        let (_, mut offer) = sender_start(&s, &rk, Kind::Env, None, b"KEY=value", NOW).unwrap();
        let i = pos % offer.len();
        offer[i] ^= mask;
        prop_assert!(receiver_on_offer(&r, &sk, &offer, NOW).is_err());
    }
}
