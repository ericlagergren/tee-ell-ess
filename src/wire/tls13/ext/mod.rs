//! Extensions

mod groups;
mod key_share;
mod psk;

pub use groups::{NamedGroup, NamedGroupList};
pub use key_share::{
    KeyShare, KeyShareClientHello, KeyShareHelloRetryRequest, KeyShareServerHello, Secp256r1,
    Secp384r1, Secp521r1, X25519, X448,
};
pub use psk::{OfferedPsksList, PskBinderEntry, PskIdentity, PskKexMode, PskKexModesList};
use subtle::{Choice, ConstantTimeEq};

use crate::wire::{
    macros::{define_list, define_struct},
    types::opaque,
    ProtocolVersion,
};

define_struct! {
    /// The `cookie` extension.
    #[doc(alias = "cookie")]
    #[derive(Debug)]
    pub struct {
        opaque cookie<1..2^16-1>;
    } Cookie<'a>;
}

impl ConstantTimeEq for Cookie<'_> {
    fn ct_eq(&self, other: &Self) -> Choice {
        ConstantTimeEq::ct_eq(&self.cookie, &other.cookie)
    }
}

#[cfg(test)]
impl Eq for Cookie<'_> {}

#[cfg(test)]
impl PartialEq for Cookie<'_> {
    fn eq(&self, other: &Self) -> bool {
        bool::from(self.ct_eq(other))
    }
}

define_list! {
    /// The [supported_versions][0] extension from the
    /// `ClientHello`.
    ///
    /// [0]: https://datatracker.ietf.org/doc/html/rfc8446#section-4.2.1
    #[doc(alias = "supported_versions")]
    #[derive(Eq, PartialEq)]
    pub struct {
        ProtocolVersion versions<2..254>;
    } SupportedVersionsList;
}
