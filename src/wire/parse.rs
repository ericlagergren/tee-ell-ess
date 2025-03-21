use core::marker::PhantomData;

use crate::wire::{types::u24, Error, Object};

/// Parses the TLS wire format.
///
/// # Lifetime
///
/// `'de` is the lifetime of the the data that can be borrowed by
/// `Self`.
///
/// ```ignore
/// // Good!
/// impl<'de: 'a, 'a> TryParse<'de> for Good<'a> {
///     fn try_parse(data: &'de [u8]) -> Result<(Self, &'de [u8]) -> Result<(Self, &'de [u8]), Error> {
///         ...
///     }
/// }
///
/// // Bad!
/// impl<'de> TryParse<'de> for Bad<'de> {
///     fn try_parse(data: &'de [u8]) -> Result<(Self, &'de [u8]) -> Result<(Self, &'de [u8]), Error> {
///         ...
///     }
/// }
/// ```
pub trait TryParse<'de, T = Self>: Object + Sized {
    /// Parses `T` from `data` and returns `T` and the remaining
    /// data, if any.
    fn try_parse(data: &'de [u8]) -> Result<(T, &'de [u8]), Error>;

    /// Like [`try_parse`][Self::try_parse], but there cannot be
    /// any remaining data.
    #[inline]
    fn try_parse_all(data: &'de [u8]) -> Result<T, Error> {
        let (v, rest) = Self::try_parse(data)?;
        if !rest.is_empty() {
            println!("rest = {rest:x?}");
            Err(Error::decode_error("unexpected trailing data"))
        } else {
            Ok(v)
        }
    }

    /// Skips past the current object and returns the remaining
    /// data.
    #[inline]
    fn try_skip(data: &'de [u8]) -> Result<&'de [u8], Error> {
        Self::try_parse(data).map(|(_, rest)| rest)
    }
}

impl<'de> TryParse<'de> for () {
    #[inline]
    fn try_parse(data: &'de [u8]) -> Result<(Self, &'de [u8]), Error> {
        Ok(((), data))
    }
}

macro_rules! impl_scalar_try_parse {
    ($($name:ident)*) => {
        $( impl<'de> TryParse<'de> for $name {
            #[inline]
            fn try_parse(data: &'de [u8]) -> Result<(Self, &'de [u8]), Error> {
                data.split_first_chunk()
                    .ok_or(Error::unexpected_eof())
                    .map(|(bytes, rest)| {
                        let x = <$name>::from_be_bytes(*bytes);
                        (x, rest)
                    })
            }
        } )*
    };
}
impl_scalar_try_parse!(u8 u16 u24 u32 u64);

impl<'de, const N: usize> TryParse<'de> for [u8; N] {
    #[inline]
    fn try_parse(data: &'de [u8]) -> Result<(Self, &'de [u8]), Error> {
        let (data, rest) = data.split_first_chunk().ok_or(Error::unexpected_eof())?;
        Ok((*data, rest))
    }
}

impl<'de: 'a, 'a, const N: usize> TryParse<'de> for &'a [u8; N] {
    #[inline]
    fn try_parse(data: &'de [u8]) -> Result<(Self, &'de [u8]), Error> {
        data.split_first_chunk().ok_or(Error::unexpected_eof())
    }
}

impl<'de: 'a, 'a, T> TryParse<'de> for PhantomData<T>
where
    T: TryParse<'de>,
{
    #[inline]
    fn try_parse(data: &'de [u8]) -> Result<(Self, &'de [u8]), Error> {
        T::try_parse(data).map(|(_, rest)| (PhantomData, rest))
    }
}
