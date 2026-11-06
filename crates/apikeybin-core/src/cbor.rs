//! Strict CBOR: the length is checked before anything is parsed, nesting is capped, and a
//! value is accepted only if encoding it again gives back exactly the same bytes.
//!
//! That last rule means every message has one encoding. Without it, flipping a type bit
//! turned a text map key into a byte string that serde reads as the same field name, so a
//! changed frame still decoded to the same value and passed its signature check. Later
//! transcript hashes would have differed and failed the transfer, but a frame should not be
//! malleable in the first place. The rule also rejects trailing bytes, duplicate keys,
//! reordered keys, non-minimal integers and indefinite lengths, without a case for each.

use std::io::Cursor;

use serde::Serialize;
use serde::de::DeserializeOwned;
use zeroize::Zeroizing;

use crate::error::Error;

const RECURSION_LIMIT: usize = 8;

pub fn encode<T: Serialize>(value: &T) -> Result<Vec<u8>, Error> {
    let mut out = Vec::new();
    ciborium::ser::into_writer(value, &mut out).map_err(|_| Error::Encode)?;
    Ok(out)
}

pub fn decode_strict<T: DeserializeOwned + Serialize>(
    bytes: &[u8],
    max_len: usize,
) -> Result<T, Error> {
    if bytes.len() > max_len {
        return Err(Error::FrameTooLong);
    }
    let mut cursor = Cursor::new(bytes);
    let value: T = ciborium::de::from_reader_with_recursion_limit(&mut cursor, RECURSION_LIMIT)
        .map_err(|_| Error::Decode)?;
    if usize::try_from(cursor.position()).ok() != Some(bytes.len()) {
        return Err(Error::Decode);
    }
    // The vault body passes through here, so the copy is zeroized.
    let again = Zeroizing::new(encode(&value)?);
    if again.as_slice() != bytes {
        return Err(Error::Decode);
    }
    Ok(value)
}
