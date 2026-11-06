//! Wire messages. Fixed size binary fields are CBOR byte strings of exactly that length.

use serde::{Deserialize, Serialize};

use crate::cbor;
use crate::error::Error;
use crate::kem::{CT_LEN, EK_LEN};

/// 1 MiB + 64 KiB. Enforced before any parsing.
pub const MAX_FRAME_LEN: usize = 1_114_112;
pub const PROTOCOL_VERSION: u8 = 1;

mod bstr_array {
    use core::fmt;
    use serde::de::{Error as _, Visitor};
    use serde::{Deserializer, Serializer};

    pub fn serialize<S: Serializer, const N: usize>(v: &[u8; N], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_bytes(v)
    }

    struct V<const N: usize>;
    impl<const N: usize> Visitor<'_> for V<N> {
        type Value = [u8; N];
        fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(f, "a byte string of length {N}")
        }
        fn visit_bytes<E: serde::de::Error>(self, v: &[u8]) -> Result<Self::Value, E> {
            v.try_into().map_err(|_| E::custom("wrong length"))
        }
        fn visit_byte_buf<E: serde::de::Error>(self, v: Vec<u8>) -> Result<Self::Value, E> {
            self.visit_bytes(&v)
        }
    }

    pub fn deserialize<'de, D: Deserializer<'de>, const N: usize>(
        d: D,
    ) -> Result<[u8; N], D::Error> {
        d.deserialize_bytes(V::<N>).map_err(D::Error::custom)
    }
}

pub(crate) mod bstr_vec {
    use core::fmt;
    use serde::de::Visitor;
    use serde::{Deserializer, Serializer};

    pub fn serialize<S: Serializer>(v: &[u8], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_bytes(v)
    }

    struct V;
    impl Visitor<'_> for V {
        type Value = Vec<u8>;
        fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("a byte string")
        }
        fn visit_bytes<E: serde::de::Error>(self, v: &[u8]) -> Result<Self::Value, E> {
            Ok(v.to_vec())
        }
        fn visit_byte_buf<E: serde::de::Error>(self, v: Vec<u8>) -> Result<Self::Value, E> {
            Ok(v)
        }
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        // Not deserialize_bytes: ciborium refuses a byte string longer than its 4096 byte
        // scratch buffer there, which silently capped payloads at 4 KiB.
        d.deserialize_byte_buf(V)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Kind {
    Env,
    Text,
    File,
}

/// What the receiver reads before deciding. Signed by the sender's identity key, so a
/// stolen transport key alone cannot produce an approval prompt. Holds no label: this
/// frame is protected only by the transport's TLS, which is not post-quantum by default.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OfferBody {
    pub v: u8,
    #[serde(with = "bstr_array")]
    pub id: [u8; 16],
    pub kind: Kind,
    pub bucket: u32,
    pub ts: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Offer {
    /// The exact bytes of a CBOR encoded [`OfferBody`], so the signature covers raw bytes.
    #[serde(with = "bstr_vec")]
    pub body: Vec<u8>,
    #[serde(with = "bstr_array")]
    pub sig_o: [u8; 64],
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Accept {
    #[serde(with = "bstr_array")]
    pub id: [u8; 16],
    #[serde(with = "bstr_array")]
    pub ek: [u8; EK_LEN],
    #[serde(with = "bstr_array")]
    pub sig_r: [u8; 64],
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Reject {
    #[serde(with = "bstr_array")]
    pub id: [u8; 16],
    pub reason: u8,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Data {
    #[serde(with = "bstr_array")]
    pub id: [u8; 16],
    #[serde(with = "bstr_array")]
    pub ct: [u8; CT_LEN],
    #[serde(with = "bstr_array")]
    pub nonce: [u8; 24],
    #[serde(with = "bstr_vec")]
    pub body: Vec<u8>,
    #[serde(with = "bstr_array")]
    pub sig_s: [u8; 64],
}

/// Signed so the sender knows the real receiver got exactly this transfer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Ack {
    #[serde(with = "bstr_array")]
    pub id: [u8; 16],
    pub ok: bool,
    #[serde(with = "bstr_array")]
    pub sig_a: [u8; 64],
}

pub fn decode_frame<T: serde::de::DeserializeOwned + Serialize>(bytes: &[u8]) -> Result<T, Error> {
    cbor::decode_strict(bytes, MAX_FRAME_LEN)
}
