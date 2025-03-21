//! TLS 1.3.

mod msgs;

use crate::crypto::{Aead, Hkdf};
#[doc(inline)]
pub use crate::wire::tls13::CipherSuiteId;

/// A TLS 1.3 cipher suite.
#[derive(Clone, Debug)]
pub struct CipherSuite {
    /// The cipher suite ID.
    pub id: CipherSuiteId,
    /// An AEAD.
    pub aead: &'static dyn Aead,
    /// A HKDF instance.
    pub hkdf: &'static dyn Hkdf,
}
