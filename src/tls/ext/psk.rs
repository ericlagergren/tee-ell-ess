//! `pre_shared_key` and `psk_key_exchange_modes` extensions.

use core::fmt;

use subtle::{Choice, ConstantTimeEq};

use crate::{
    util::{Hex, Sensitive},
    wire::tls13::ext::{PskBinderEntry, PskIdentity},
};

/// A preshared key identity.
pub struct Identity<'a>(PskIdentity<'a>);

impl Identity<'_> {
    /// Returns the identity.
    #[inline]
    pub const fn identity(&self) -> Sensitive<'_> {
        // It isn't necessary to compare identities in constant
        // time since they are not secret. However, it can help
        // prevent clients from enumerating the PSK identities
        // stored on a sever.
        Sensitive(self.0.identity.as_slice())
    }

    /// Returns the obfuscated ticket age.
    #[inline]
    pub const fn obfuscated_ticket_age(&self) -> u32 {
        self.0.obfuscated_ticket_age
    }
}

impl Eq for PskIdentity<'_> {}

impl PartialEq for PskIdentity<'_> {
    fn eq(&self, other: &Self) -> bool {
        bool::from(ConstantTimeEq::ct_eq(self, other))
    }
}

impl ConstantTimeEq for PskIdentity<'_> {
    fn ct_eq(&self, other: &Self) -> Choice {
        let ident = ConstantTimeEq::ct_eq(&self.identity(), &other.identity());
        let age = ConstantTimeEq::ct_eq(&self.obfuscated_ticket_age, &other.obfuscated_ticket_age);
        ident & age
    }
}

/// A preshared key binder (MAC).
pub struct Binder<'a>(PskBinderEntry<'a>);

impl Binder<'_> {
    const fn tag(&self) -> &[u8] {
        self.0.as_slice()
    }
}

impl ConstantTimeEq for Binder<'_> {
    fn ct_eq(&self, other: &Self) -> Choice {
        ConstantTimeEq::ct_eq(self.tag(), other.tag())
    }
}

impl fmt::Debug for Binder<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("Binder").field(&Hex(self.tag())).finish()
    }
}
