use core::{fmt, ops::Deref};

use buggy::{bug, Bug, BugExt};

use crate::{error::Error, wire::alert::Alert};

/// TODO
#[derive(Debug, thiserror::Error)]
#[error("parse error: {repr}")]
pub struct ParseError {
    repr: Repr,
}

impl ParseError {
    #[inline]
    pub(crate) const fn unexpected_eof() -> Self {
        Self {
            repr: Repr::Decode("unexpected end of input"),
        }
    }
}

impl Clone for ParseError {
    #[inline]
    fn clone(&self) -> Self {
        Self {
            repr: self.repr.clone(),
        }
    }
}

impl<T: Into<Repr>> From<T> for ParseError {
    fn from(err: T) -> Self {
        Self { repr: err.into() }
    }
}

impl From<ParseError> for Alert {
    fn from(_err: ParseError) -> Self {
        Alert::decode_error()
    }
}

impl From<ParseError> for Error {
    fn from(_err: ParseError) -> Self {
        Error::from(Alert::decode_error())
    }
}

#[derive(Clone, Debug, thiserror::Error)]
enum Repr {
    #[error("{0}")]
    Bug(#[from] Bug),
    #[error("{0}")]
    Decode(&'static str),
}

impl From<&'static str> for Repr {
    fn from(context: &'static str) -> Self {
        Self::Decode(context)
    }
}

/// TODO
pub trait TryParse<'a, T = Self>: Sized {
    /// TODO
    fn try_parse(data: &'a [u8]) -> Result<(T, &'a [u8]), ParseError>;
}

/// A variable-length vector.
#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd)]
pub(crate) struct Vector<'a, const MIN: usize, const MAX: usize> {
    pub(crate) data: &'a [u8],
}

impl<'a, const MIN: usize, const MAX: usize> Vector<'a, MIN, MAX> {
    pub(crate) const MAX: usize = MAX;

    const SIZE: usize = {
        let bits = usize::BITS - MAX.leading_zeros();
        ((bits + 7) / 8) as usize
    };

    #[inline]
    fn parse_len(data: &[u8]) -> Result<(usize, &[u8]), ParseError> {
        let (len_bytes, rest) = data
            .split_at_checked(Self::SIZE)
            .ok_or(ParseError::unexpected_eof())?;
        let len64 = match len_bytes {
            [a] => u64::from(*a),
            [a, b] => u64::from(u16::from_be_bytes([*a, *b])),
            [a, b, c, d] => u64::from(u32::from_be_bytes([*a, *b, *c, *d])),
            #[cfg(target_pointer_width = "64")]
            [a, b, c, d, e, f, g, h] => u64::from_be_bytes([*a, *b, *c, *d, *e, *f, *g, *h]),
            _ => bug!("unreachable pattern"),
        };
        let len = usize::try_from(len64).assume("`len64` should not overflow")?;
        if len < MIN || len > MAX {
            return Err("invalid length".into());
        }
        Ok((len, rest))
    }

    #[inline]
    pub(crate) const fn as_slice(&self) -> &'a [u8] {
        self.data
    }
}

impl<'a, const MIN: usize, const MAX: usize> TryParse<'a> for Vector<'a, MIN, MAX> {
    #[inline]
    fn try_parse(data: &'a [u8]) -> Result<(Self, &'a [u8]), ParseError> {
        let (len, rest) = Self::parse_len(data)?;
        let (data, rest) = rest
            .split_at_checked(len)
            .ok_or(ParseError::unexpected_eof())?;
        Ok((Self { data }, rest))
    }
}

impl<'a, const MIN: usize, const MAX: usize> PartialEq<[u8]> for Vector<'a, MIN, MAX> {
    fn eq(&self, other: &[u8]) -> bool {
        PartialEq::eq(self.data, other)
    }
}

impl<'a, const MIN: usize, const MAX: usize> PartialEq<&[u8]> for Vector<'a, MIN, MAX> {
    fn eq(&self, other: &&[u8]) -> bool {
        PartialEq::eq(self.data, *other)
    }
}

impl<const MIN: usize, const MAX: usize> Deref for Vector<'_, MIN, MAX> {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        self.data
    }
}

impl<'a, const MIN: usize, const MAX: usize> fmt::Debug for Vector<'a, MIN, MAX> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Vector<{MIN}, {MAX}>({:?})", self.data)
    }
}

impl TryParse<'_> for u16 {
    #[inline]
    fn try_parse(data: &[u8]) -> Result<(Self, &[u8]), ParseError> {
        let (v, rest) = data
            .split_first_chunk()
            .ok_or(ParseError::unexpected_eof())?;
        let x = u16::from_be_bytes(*v);
        Ok((x, rest))
    }
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
#[allow(non_camel_case_types)]
pub(crate) struct u24(u32);

impl TryParse<'_, usize> for u24 {
    #[inline]
    fn try_parse(data: &[u8]) -> Result<(usize, &[u8]), ParseError> {
        let (v, rest) = data
            .split_first_chunk::<3>()
            .ok_or(ParseError::unexpected_eof())?;
        // TODO(eric): what if `usize` is 16 bits?
        let x = usize::try_from(u32::from_be_bytes([0, v[0], v[1], v[2]]))
            .assume("`x` should not overflow")?;
        Ok((x, rest))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vector() {
        let mut data = vec![42; 2 + 300];
        [data[0], data[1]] = u16::to_be_bytes(300);
        let (got, rest) = Vector::<300, 400>::try_parse(&data).unwrap();
        assert_eq!(got, &data[2..]);
        assert_eq!(rest, &[]);
    }
}
