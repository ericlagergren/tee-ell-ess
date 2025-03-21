//! Core types.

use core::num::TryFromIntError;

use buggy::BugExt;
/// An unsigned 16-bit integer.
pub use u16 as uint16;
/// An unsigned 24-bit integer.
pub use u24 as uint24;
/// An unsigned 32-bit integer.
pub use u32 as uint32;
/// An unsigned 8-bit integer.
pub use u8 as uint8;
/// Uninterpreted data.
pub use u8 as opaque;

use crate::wire::{Error, TryParse};

/// An unsigned 24-bit integer.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
#[allow(non_camel_case_types)]
pub struct u24(u32);

impl u24 {
    pub(crate) const MAX: Self = Self((1 << 24) - 1);

    #[inline(always)]
    pub(crate) const fn from_be_bytes(bytes: [u8; 3]) -> Self {
        let [a, b, c] = bytes;
        Self(u32::from_be_bytes([0, a, b, c]))
    }

    #[inline(always)]
    pub(crate) const fn to_be_bytes(self) -> [u8; 3] {
        let [_, a, b, c] = self.0.to_be_bytes();
        [a, b, c]
    }
}

impl<'de> TryParse<'de, usize> for u24 {
    #[inline]
    fn try_parse(data: &[u8]) -> Result<(usize, &[u8]), Error> {
        <Self as TryParse<Self>>::try_parse(data).map(|(x, rest)| {
            let u = x.try_into().assume("`u24` should fit in `usize`")?;
            Ok((u, rest))
        })?
    }
}

impl TryFrom<usize> for u24 {
    type Error = TryFromIntError;

    #[inline]
    fn try_from(value: usize) -> Result<Self, Self::Error> {
        let x = value.try_into()?;
        if x > Self::MAX.0 {
            // This never panics.
            Err(u8::try_from(u64::MAX).unwrap_err())
        } else {
            Ok(Self(x))
        }
    }
}

impl TryFrom<u24> for usize {
    type Error = TryFromIntError;

    #[inline]
    fn try_from(value: u24) -> Result<Self, Self::Error> {
        usize::try_from(value.0)
    }
}
