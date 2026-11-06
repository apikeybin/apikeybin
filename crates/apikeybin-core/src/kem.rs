//! The KEM is behind a trait so it can be replaced after audit. `x-wing` has not been
//! independently audited; its README says so.

use x_wing::{
    DecapsulationKeyRejectNonContrib, Decapsulator, Encapsulate, EncapsulationKey, KeyExport,
    TryDecapsulate,
};
use zeroize::{Zeroize, Zeroizing};

use crate::error::Error;

pub const EK_LEN: usize = 1216;
pub const CT_LEN: usize = 1120;
pub const SS_LEN: usize = 32;

pub trait Kem {
    type DecapsulationKey;

    /// Derives a key pair from a seed the caller filled from the OS RNG.
    fn generate(seed: Zeroizing<[u8; 32]>)
    -> Result<(Self::DecapsulationKey, [u8; EK_LEN]), Error>;
    fn encapsulate(ek: &[u8; EK_LEN]) -> Result<([u8; CT_LEN], Zeroizing<[u8; SS_LEN]>), Error>;
    fn decapsulate(
        dk: &Self::DecapsulationKey,
        ct: &[u8; CT_LEN],
    ) -> Result<Zeroizing<[u8; SS_LEN]>, Error>;
}

/// X-Wing, refusing non-contributory X25519 output. Both ends of this protocol are ours,
/// so there is no compatibility reason to accept it.
#[derive(Debug, Clone, Copy)]
pub struct XWing;

impl Kem for XWing {
    type DecapsulationKey = DecapsulationKeyRejectNonContrib;

    fn generate(
        seed: Zeroizing<[u8; 32]>,
    ) -> Result<(Self::DecapsulationKey, [u8; EK_LEN]), Error> {
        let dk = DecapsulationKeyRejectNonContrib::from(*seed);
        let exported = dk.encapsulation_key().to_bytes();
        let mut ek = [0u8; EK_LEN];
        if exported.len() != EK_LEN {
            return Err(Error::Crypto);
        }
        ek.copy_from_slice(exported.as_slice());
        Ok((dk, ek))
    }

    fn encapsulate(ek: &[u8; EK_LEN]) -> Result<([u8; CT_LEN], Zeroizing<[u8; SS_LEN]>), Error> {
        let key = EncapsulationKey::try_from(ek.as_slice()).map_err(|_| Error::Crypto)?;
        let (ct, mut shared) = key.encapsulate();
        let mut out = [0u8; CT_LEN];
        out.copy_from_slice(ct.as_slice());
        let ss = to_secret(shared.as_slice());
        shared.as_mut_slice().zeroize();
        Ok((out, ss?))
    }

    fn decapsulate(
        dk: &Self::DecapsulationKey,
        ct: &[u8; CT_LEN],
    ) -> Result<Zeroizing<[u8; SS_LEN]>, Error> {
        let ct = x_wing::Ciphertext::try_from(ct.as_slice()).map_err(|_| Error::Crypto)?;
        let mut shared = dk.try_decapsulate(&ct).map_err(|_| Error::Crypto)?;
        let ss = to_secret(shared.as_slice());
        shared.as_mut_slice().zeroize();
        ss
    }
}

fn to_secret(bytes: &[u8]) -> Result<Zeroizing<[u8; SS_LEN]>, Error> {
    let mut out = Zeroizing::new([0u8; SS_LEN]);
    if bytes.len() != SS_LEN {
        return Err(Error::Crypto);
    }
    out.copy_from_slice(bytes);
    Ok(out)
}
