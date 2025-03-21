//! TLS cryptography.

use core::fmt;

use zeroize::Zeroize;

/// An AEAD per TODO
pub trait Aead: fmt::Debug {}

/// HKDF per TODO
pub trait Hkdf: fmt::Debug {
    /// Extracts a fixed-length pseudorandom key (PRK) from the
    /// input keying material (IKM) and an optional salt.
    ///
    /// It handles IKMs and salts of arbitrary lengths.
    fn extract(&self, ikm: &[u8], salt: &[u8]) -> Prk;
    /// Expands the PRK with an optional info parameter into
    /// a key.
    ///
    /// It returns [`HkdfError`] if `out` is larger than the
    /// maximum number of bytes that can be expanded from a PRK.
    fn expand(&self, out: &mut [u8], prk: &Prk, info: &[u8]) -> Result<(), HkdfError>;
}

/// A pseudorandom key.
#[derive(Clone)]
pub struct Prk([u8; 32]);

impl Drop for Prk {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl fmt::Debug for Prk {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("Prk").finish_non_exhaustive()
    }
}

/// Returned when [`Hkdf::expand`] fails.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct HkdfError;

/// A cryptographically secure pseudo-random number generator.
pub trait Csprng: fmt::Debug {
    /// Fills `buf` with cryptographically secure pseudo-random
    /// bytes.
    fn fill_bytes(&self, buf: &mut [u8]);
}
