//! `pre_shared_key` and `psk_key_exchange_modes` extensions.

use core::iter::{self, FusedIterator, Zip};

use crate::{
    util::Sensitive,
    wire::{
        macros::{define_list, define_scalar_enum, define_struct, define_type_alias},
        types::{opaque, uint32},
        vec::Iter,
        Error, Object, Size, TryParse,
    },
};

define_struct! {
    /// [PskIdentity][0].
    ///
    /// [0]: https://datatracker.ietf.org/doc/html/rfc8446#autoid-37
    #[derive(Debug)]
    pub struct {
        opaque identity<1..2^16-1>;
        uint32 obfuscated_ticket_age;
    } PskIdentity<'a>;
}

impl PskIdentity<'_> {
    /// Returns the identity.
    #[inline]
    pub const fn identity(&self) -> Sensitive<'_> {
        // It isn't necessary to compare identities in constant
        // time since they are not secret. However, it can help
        // prevent clients from enumerating the PSK identities
        // stored on a sever.
        Sensitive(self.identity.as_slice())
    }

    /// Returns the obfuscated ticket age.
    #[inline]
    pub const fn obfuscated_ticket_age(&self) -> u32 {
        self.obfuscated_ticket_age
    }
}

define_type_alias! {
    /// [PskBinderEntry][0].
    ///
    /// [0]: https://datatracker.ietf.org/doc/html/rfc8446#autoid-37
    pub opaque PskBinderEntry<32..255>;
}

#[cfg(test)]
impl Eq for PskBinderEntry<'_> {}

#[cfg(test)]
impl PartialEq for PskBinderEntry<'_> {
    fn eq(&self, other: &Self) -> bool {
        bool::from(ConstantTimeEq::ct_eq(self, other))
    }
}

define_list! {
    struct {
        PskIdentity<'a> identities<7..2^16-1>;
    } PskIdentityList;
}

define_list! {
    struct {
        PskBinderEntry<'a> binders<33..2^16-1>;
    } PskBinderEntryList;
}

define_struct! {
    /// `OfferedPsks`.
    #[derive(Debug)]
    #[cfg_attr(test, derive(Eq, PartialEq))]
    struct {
        PskIdentity<'a> identities<7..2^16-1>;
        PskBinderEntry<'a> binders<33..2^16-1>;
    } OfferedPsksRepr<'a>;
}

/// `OfferedPsks`.
#[derive(Copy, Clone, Debug)]
#[cfg_attr(test, derive(Eq, PartialEq))]
pub struct OfferedPsksList<'a> {
    repr: OfferedPsksRepr<'a>,
}

impl OfferedPsksList<'_> {
    /// Returns an iterator over the [`PskIdentity`] and
    /// [`PskBinderEntry`] pairs.
    #[inline]
    pub fn iter(&self) -> OfferedPsks<'_> {
        OfferedPsks::new(self.repr.identities.iter(), self.repr.binders.iter())
    }
}

impl Object for OfferedPsksList<'_> {
    const SIZE: Size = OfferedPsksRepr::SIZE;
}

impl<'de: 'a, 'a> TryParse<'de> for OfferedPsksList<'a> {
    #[inline]
    fn try_parse(data: &'de [u8]) -> Result<(Self, &'de [u8]), Error> {
        let (repr, rest) = OfferedPsksRepr::try_parse(data)?;
        if repr.identities.iter().count() != repr.binders.iter().count() {
            return Err(Error::illegal_parameter("mismatched lengths"));
        }
        Ok((Self { repr }, rest))
    }
}

impl<'a> IntoIterator for OfferedPsksList<'a> {
    type Item = <OfferedPsks<'a> as Iterator>::Item;
    type IntoIter = OfferedPsks<'a>;

    #[inline]
    fn into_iter(self) -> Self::IntoIter {
        OfferedPsks::new(
            self.repr.identities.into_iter(),
            self.repr.binders.into_iter(),
        )
    }
}

/// An iterator over [`PskIdentity`] and [`PskBinderEntry`]
/// pairs.
#[derive(Clone, Debug)]
pub struct OfferedPsks<'a> {
    iter: Zip<Iter<'a, PskIdentity<'a>>, Iter<'a, PskBinderEntry<'a>>>,
}

impl<'a> OfferedPsks<'a> {
    fn new(identities: Iter<'a, PskIdentity<'a>>, binders: Iter<'a, PskBinderEntry<'a>>) -> Self {
        Self {
            iter: iter::zip(identities, binders),
        }
    }
}

impl<'a> Iterator for OfferedPsks<'a> {
    type Item = (PskIdentity<'a>, PskBinderEntry<'a>);

    #[inline]
    fn next(&mut self) -> Option<Self::Item> {
        self.iter.next()
    }
}

impl FusedIterator for OfferedPsks<'_> {}

define_list! {
    /// The `psk_key_exchange_modes` extension.
    #[doc(alias = "psk_key_exchange_modes")]
    #[doc(alias = "PskKeyExchangeModes")]
    #[derive(Eq, PartialEq)]
    pub struct {
        PskKexMode ke_modes<1..255>;
    } PskKexModesList;
}

define_scalar_enum! {
    /// `PskKeyExchangeMode`.
    #[doc(alias = "PskKeyExchangeMode")]
    #[repr(u8)]
    pub enum PskKexMode {
        /// Preshared key only mode.
        #[doc(alias = "PSK_KE")]
        Psk = 0,
        /// Preshared key with DHE mode.
        #[doc(alias = "PSK_DHE_KE")]
        DhePsk = 1,
    }
}
