pub(crate) mod ext;
pub(crate) mod msgs;

use core::fmt;

use crate::{
    tls13,
    wire::{self, ProtocolVersion},
};

pub(crate) const MAX_HANDSHAKE_SIZE: usize = 1 << 16;

/// A TLS ciphersuite.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub enum CipherSuite {
    /// A TLS 1.3 cipher suite.
    Tls13(tls13::CipherSuite),
}

/// TLS versions.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum Version {
    /// TLS 1.2.
    #[cfg(feature = "tls12")]
    Tls12 = 0x0303,
    /// TLS 1.3.
    Tls13 = 0x0304,
}

impl Version {
    pub(crate) const fn to_wire(self) -> ProtocolVersion {
        match self {
            #[cfg(feature = "tls12")]
            Self::Tls12 => ProtocolVersion::Tls12,
            Self::Tls13 => ProtocolVersion::Tls13,
        }
    }
    pub(crate) const fn from_wire(pv: ProtocolVersion) -> Option<Self> {
        match pv {
            #[cfg(feature = "tls12")]
            ProtocolVersion::Tls12 => Some(Self::Tls12),
            ProtocolVersion::Tls13 => Some(Self::Tls13),
            _ => None,
        }
    }
}

/// The system time.
pub trait Time: fmt::Debug {
    /// Returns the current number of non-leap seconds since the
    /// Unix epoch.
    fn now(&self) -> u64;
}

/// The maximum allowed fragment length.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct MaxFragmentLength(pub(crate) wire::MaxFragmentLength);

impl MaxFragmentLength {
    /// Creates a `MaxFragmentLength`.
    ///
    /// It returns `None` if `size` is not one of:
    ///
    /// - 2^9
    /// - 2^10
    /// - 2^11
    /// - 2^12
    pub const fn new(size: usize) -> Option<Self> {
        if size > u8::MAX as usize {
            return None;
        };
        match wire::MaxFragmentLength::try_from_repr(size as u8) {
            Ok(size) => Some(Self(size)),
            Err(_) => None,
        }
    }
}
