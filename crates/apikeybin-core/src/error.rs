//! Errors carry a reason and never a value, so they are safe to print.

use core::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    FrameTooLong,
    Decode,
    Encode,
    UnsupportedVersion,
    BadBucket,
    BadText,
    BadSignature,
    WeakPeerKey,
    IdMismatch,
    Expired,
    Crypto,
    BadPadding,
    PayloadTooLarge,
    Rng,
    VaultFormat,
    VaultAuth,
    WeakPassphrase,
    RejectedByPeer(u8),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Error::FrameTooLong => "frame exceeds the size limit",
            Error::Decode => "malformed message",
            Error::Encode => "could not encode message",
            Error::UnsupportedVersion => "unsupported protocol version",
            Error::BadBucket => "invalid size bucket",
            Error::BadText => "text contains characters that are not allowed",
            Error::BadSignature => "signature verification failed",
            Error::WeakPeerKey => "peer public key is weak or malformed",
            Error::IdMismatch => "transfer id mismatch",
            Error::Expired => "offer outside the accepted time window",
            Error::Crypto => "decryption failed",
            Error::BadPadding => "invalid padding",
            Error::PayloadTooLarge => "payload too large",
            Error::Rng => "OS random number generator failed",
            Error::VaultFormat => "vault file is malformed",
            Error::VaultAuth => "vault could not be unlocked",
            Error::WeakPassphrase => "passphrase is too short",
            Error::RejectedByPeer(_) => "the peer rejected the transfer",
        };
        f.write_str(s)
    }
}

impl std::error::Error for Error {}
