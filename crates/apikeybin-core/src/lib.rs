//! apikeybin protocol core: wire types, transcript, padding, KEM and AEAD assembly,
//! and the vault file format. No I/O, no clock, no terminal.
//!
//! Every secret lives in a zeroizing container and no type that holds one implements
//! `Display`; `Debug` output is redacted.

pub mod cbor;
pub mod envfile;
pub mod error;
pub mod kem;
pub mod link;
pub mod messages;
pub mod padding;
pub mod text;
pub mod transcript;
pub mod vault;
pub mod xfer;

pub use error::Error;
