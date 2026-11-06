//! Fixed size buckets, so the size of a secret is visible only as a coarse class.

use zeroize::Zeroizing;

use crate::error::Error;

pub const BUCKETS: [u32; 6] = [1024, 4096, 16_384, 65_536, 262_144, 1_048_576];
const LEN_PREFIX: usize = 4;

pub fn is_bucket(value: u32) -> bool {
    BUCKETS.contains(&value)
}

/// The smallest bucket that fits `plaintext_len` bytes plus the length prefix.
pub fn bucket_for(plaintext_len: usize) -> Result<u32, Error> {
    let needed = plaintext_len
        .checked_add(LEN_PREFIX)
        .ok_or(Error::PayloadTooLarge)?;
    BUCKETS
        .iter()
        .copied()
        .find(|b| usize::try_from(*b).is_ok_and(|b| b >= needed))
        .ok_or(Error::PayloadTooLarge)
}

pub fn pad(plaintext: &[u8], bucket: u32) -> Result<Zeroizing<Vec<u8>>, Error> {
    if !is_bucket(bucket) {
        return Err(Error::BadBucket);
    }
    let size = usize::try_from(bucket).map_err(|_| Error::BadBucket)?;
    let declared = u32::try_from(plaintext.len()).map_err(|_| Error::PayloadTooLarge)?;
    if plaintext.len().saturating_add(LEN_PREFIX) > size {
        return Err(Error::PayloadTooLarge);
    }
    let mut out = Zeroizing::new(Vec::with_capacity(size));
    out.extend_from_slice(&declared.to_be_bytes());
    out.extend_from_slice(plaintext);
    out.resize(size, 0);
    Ok(out)
}

/// Accepts only exactly what `pad` produces: the right total size, a declared length that
/// fits, and all padding bytes zero.
pub fn unpad(padded: &[u8], bucket: u32) -> Result<&[u8], Error> {
    if !is_bucket(bucket) {
        return Err(Error::BadBucket);
    }
    let size = usize::try_from(bucket).map_err(|_| Error::BadBucket)?;
    if padded.len() != size {
        return Err(Error::BadPadding);
    }
    let (prefix, rest) = padded
        .split_at_checked(LEN_PREFIX)
        .ok_or(Error::BadPadding)?;
    let prefix: [u8; 4] = prefix.try_into().map_err(|_| Error::BadPadding)?;
    let declared = usize::try_from(u32::from_be_bytes(prefix)).map_err(|_| Error::BadPadding)?;
    let (plaintext, zeros) = rest.split_at_checked(declared).ok_or(Error::BadPadding)?;
    if zeros.iter().any(|b| *b != 0) {
        return Err(Error::BadPadding);
    }
    Ok(plaintext)
}
