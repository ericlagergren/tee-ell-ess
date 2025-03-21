use core::{fmt, iter::FusedIterator, marker::PhantomData};

use buggy::{bug, Bug, BugExt};
use subtle::{Choice, ConstantTimeEq};

use crate::wire::{EncBuf, Error, Object, Size, TryEncode, TryParse};

/// A variable-length [vector].
///
/// - `T` is the type of data stored in the vector.
/// - `MIN` is the minimum length of the vector.
/// - `MAX` is the maximum length of the vector.
///
/// [vector]: https://datatracker.ietf.org/doc/html/rfc8446#section-3.4
#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd)]
pub struct Vector<'a, T, const MIN: usize, const MAX: usize> {
    data: &'a [u8],
    _marker: PhantomData<fn() -> T>,
}

impl<T, const MIN: usize, const MAX: usize> Vector<'_, T, MIN, MAX> {
    /// The size in bytes of the leading length.
    const LENGTH_SIZE: usize = {
        let bits = usize::BITS - MAX.leading_zeros();
        ((bits + 7) / 8) as usize
    };

    pub(crate) const fn as_slice(&self) -> &[u8] {
        self.data
    }

    pub(crate) const fn iter(&self) -> Iter<'_, T> {
        Iter::new(self.data)
    }

    #[allow(dead_code)] // TODO
    pub(crate) const fn try_iter(&self) -> TryIter<'_, T> {
        TryIter::new(self.data)
    }
}

impl<'a, T, const MIN: usize, const MAX: usize> Vector<'a, T, MIN, MAX> {
    pub(crate) const fn new(data: &'a [u8]) -> Self {
        debug_assert!(data.len() >= MIN);
        debug_assert!(data.len() <= MAX);

        Self {
            data,
            _marker: PhantomData,
        }
    }

    pub(crate) fn try_new(data: &'a [u8]) -> Result<Self, Bug> {
        if data.len() < MIN || data.len() > MAX {
            bug!("invalid vector length: {data:?}");
        } else {
            Ok(Self::new(data))
        }
    }

    pub(crate) const fn into_slice(self) -> &'a [u8] {
        self.data
    }

    pub(crate) fn map<U>(self) -> Vector<'a, U, MIN, MAX>
    where
        U: TryParse<'a>,
    {
        Vector::new(self.data)
    }
}

impl<T, const MAX: usize> Vector<'_, T, 0, MAX> {
    #[inline]
    pub(crate) const fn empty() -> Self {
        Self::new(&[])
    }
}

impl<'a, T, const MIN: usize, const MAX: usize> IntoIterator for Vector<'a, T, MIN, MAX>
where
    T: TryParse<'a>,
{
    type Item = T;
    type IntoIter = Iter<'a, T>;

    #[inline]
    fn into_iter(self) -> Self::IntoIter {
        Iter::new(self.data)
    }
}

impl<T, const MIN: usize, const MAX: usize> Object for Vector<'_, T, MIN, MAX>
where
    T: Object,
{
    const SIZE: Size = {
        // `T` cannot be smaller than the minimum length of the
        // vector, except for when the vector is empty.
        assert!(MIN == 0 || T::SIZE.min() <= MIN);

        // It's (unfortuantely) alright if `T::MAX` is larger
        // than `MAX`, though. This happens with TLS 1.3 where
        // `PskIdentity` is max 2 + (2^16)-1 + 4 bytes, but
        // `OfferedPsks` allows at most (2^16)-1 bytes for the
        // identities.
        Size::new(MIN, MAX)
    };
}

impl<'de: 'a, 'a, T, const MIN: usize, const MAX: usize> TryParse<'de> for Vector<'a, T, MIN, MAX>
where
    T: TryParse<'de>,
{
    #[inline]
    fn try_parse(data: &'de [u8]) -> Result<(Self, &'de [u8]), Error> {
        let (len_bytes, rest) = data
            .split_at_checked(Self::LENGTH_SIZE)
            .ok_or(Error::unexpected_eof())?;
        // NB: The compiler should DCE the unused patterns.
        let len64 = match len_bytes {
            [a] => u64::from(*a),
            [a, b] => u64::from(u16::from_be_bytes([*a, *b])),
            [a, b, c, d] => u64::from(u32::from_be_bytes([*a, *b, *c, *d])),
            #[cfg(target_pointer_width = "64")]
            [a, b, c, d, e, f, g, h] => u64::from_be_bytes([*a, *b, *c, *d, *e, *f, *g, *h]),
            _ => bug!("unreachable pattern"),
        };
        let len = usize::try_from(len64).assume("`len64` should not overflow")?;
        if len < MIN {
            return Err(Error::unexpected_eof());
        }
        if len > MAX {
            return Err(Error::decode_error("vector length too large"));
        }
        // RFC 8446: "The length of an encoded vector must be an
        // exact multiple of the length of a single element
        // (e.g., a 17-byte vector of uint16 would be illegal)."
        //
        // TODO(eric): ...but some types have a variable length?
        if T::SIZE.fixed().is_some_and(|size| len % size != 0) {
            return Err(Error::decode_error(
                "length must be a multiple of the element size",
            ));
        }

        let (data, rest) = rest.split_at_checked(len).ok_or(Error::unexpected_eof())?;
        if !data.is_empty()
            && (T::SIZE.fixed().is_some_and(|size| data.len() < size) || data.len() < T::SIZE.min())
        {
            // Not enough data for at least one element.
            return Err(Error::unexpected_eof());
        }

        let v = Self::new(data);

        // TODO
        // Make sure all items are valid.
        // {
        //     v.try_iter().find(Result::is_err).transpose()?;
        // }

        Ok((v, rest))
    }
}

impl<T, const MIN: usize, const MAX: usize> TryEncode for Vector<'_, T, MIN, MAX>
where
    T: TryEncode,
{
    #[inline]
    fn try_encode(&self, out: &mut EncBuf<'_>) -> Result<(), Error> {
        super::write_length::<MIN, MAX>(out, self.data.len())?;
        out.write(&self.data)?;
        Ok(())
    }
}

impl<T, const MIN: usize, const MAX: usize> ConstantTimeEq for Vector<'_, T, MIN, MAX> {
    fn ct_eq(&self, other: &Self) -> Choice {
        ConstantTimeEq::ct_eq(self.data, other.data)
    }
}

impl<U, T, const MIN: usize, const MAX: usize> PartialEq<U> for Vector<'_, T, MIN, MAX>
where
    U: AsRef<[u8]>,
{
    #[inline]
    fn eq(&self, other: &U) -> bool {
        PartialEq::eq(self.data, other.as_ref())
    }
}

impl<T, const MIN: usize, const MAX: usize> PartialEq<[u8]> for Vector<'_, T, MIN, MAX> {
    #[inline]
    fn eq(&self, other: &[u8]) -> bool {
        PartialEq::eq(self.data, other)
    }
}

impl<T, const MIN: usize, const MAX: usize> fmt::Debug for Vector<'_, T, MIN, MAX> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Vector<{MIN}, {MAX}>({:x?})", self.data)
    }
}

/// An iterator over elements in a [`Vector`].
pub struct Iter<'a, T> {
    iter: TryIter<'a, T>,
}

impl<'a, T> Iter<'a, T> {
    #[inline]
    pub(crate) const fn new(data: &'a [u8]) -> Self {
        Self {
            iter: TryIter::new(data),
        }
    }

    #[inline]
    pub(crate) const fn empty() -> Self {
        Self::new(&[])
    }

    /// [`Clone`], but `const`.
    #[inline]
    pub(crate) const fn const_clone(&self) -> Self {
        Self {
            iter: self.iter.const_clone(),
        }
    }
}

impl<T> Clone for Iter<'_, T> {
    #[inline]
    fn clone(&self) -> Self {
        self.const_clone()
    }
}

impl<'a, T> Iterator for Iter<'a, T>
where
    T: TryParse<'a>,
{
    type Item = T;

    #[inline]
    fn next(&mut self) -> Option<Self::Item> {
        self.iter.next().and_then(|v| v.ok())
    }

    #[inline]
    fn count(self) -> usize
    where
        Self: Sized,
    {
        self.iter.count()
    }

    #[inline]
    fn last(self) -> Option<Self::Item>
    where
        Self: Sized,
    {
        self.iter.last().and_then(|v| v.ok())
    }

    #[inline]
    fn size_hint(&self) -> (usize, Option<usize>) {
        self.iter.size_hint()
    }
}

impl<'a, T> FusedIterator for Iter<'a, T> where T: TryParse<'a> {}

impl<'a, T> fmt::Debug for Iter<'a, T>
where
    T: TryParse<'a> + fmt::Debug,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("Iter").field(&self.iter).finish()
    }
}

/// An iterator over elements in a [`Vector`].
pub struct TryIter<'a, T> {
    data: &'a [u8],
    _marker: PhantomData<fn() -> T>,
}

impl<T> Clone for TryIter<'_, T> {
    #[inline]
    fn clone(&self) -> Self {
        self.const_clone()
    }
}

impl<'a, T> TryIter<'a, T> {
    #[inline]
    pub(crate) const fn new(data: &'a [u8]) -> Self {
        Self {
            data,
            _marker: PhantomData,
        }
    }

    /// [`Clone`], but `const`.
    #[inline]
    pub(crate) const fn const_clone(&self) -> Self {
        Self {
            data: self.data,
            _marker: PhantomData,
        }
    }
}

impl<'a, T> TryIter<'a, T>
where
    T: TryParse<'a>,
{
    /// Returns the number of remaining items in the iterator, or
    /// `None` if the items are not fixed size.
    #[inline]
    const fn len(&self) -> Option<usize> {
        let Some(size) = T::SIZE.fixed() else {
            // `T` has a variable length, so it's unclear how
            // many items are left.
            return None;
        };
        if size == 0 {
            // `T` has a fixed length of zero, so the iterator is
            // always empty.
            Some(0)
        } else {
            Some(self.data.len() / size)
        }
    }

    /// Reports whether the iterator is empty.
    #[inline]
    const fn is_empty(&self) -> bool {
        matches!(self.len(), Some(0))
    }

    /// See [`Iterator::advance_by`].
    #[inline]
    fn advance_by(&mut self, n: usize) -> Result<(), usize> {
        // NB: The compiler should constant DCE the unused
        // patterns.
        match T::SIZE.fixed() {
            // `T` has a fixed length of zero, so the iterator is
            // empty.
            Some(0) => return Err(n),
            // `T` has a fixed length, so advance directly.
            Some(size) => {
                let Some((_, rest)) = self.data.split_at_checked(n * size) else {
                    // Out of range; the iterator is now empty.
                    self.data = &[];
                    let remaining = self.data.len() / size;
                    return Err(n - remaining);
                };
                self.data = rest;
            }
            // `T` is variable length, so we have to parse each
            // item.
            None => {
                for i in 0..n {
                    if self.skip_next().is_some() {
                        return Err(n - i);
                    }
                }
            }
        }
        Ok(())
    }

    /// Like [`Iterator::next`], but skips the item instead of
    /// parsing it.
    #[inline]
    fn skip_next(&mut self) -> Option<Result<(), Error>> {
        if self.is_empty() {
            return None;
        }
        let result = T::try_skip(self.data)
            .inspect(|rest| self.data = rest)
            .map(|_| ());
        Some(result)
    }
}

impl<'a, T> Iterator for TryIter<'a, T>
where
    T: TryParse<'a>,
{
    type Item = Result<T, Error>;

    #[inline]
    fn next(&mut self) -> Option<Self::Item> {
        if self.is_empty() {
            return None;
        }
        let result = T::try_parse(self.data)
            .inspect(|(_, rest)| self.data = rest)
            .map(|(item, _)| item);
        Some(result)
    }

    #[inline]
    fn count(mut self) -> usize
    where
        Self: Sized,
    {
        if let Some(n) = self.len() {
            // We know exactly how many items are left.
            return n;
        }
        let mut n = 0;
        while self.skip_next().is_some() {
            n += 1;
        }
        n
    }

    #[inline]
    fn last(mut self) -> Option<Self::Item>
    where
        Self: Sized,
    {
        match self.len() {
            Some(0) => return None,
            Some(n) => return self.nth(n - 1),
            None => {}
        }
        // We don't know how many items are in the iterator, so
        // fall back to manually skipping each item.
        loop {
            match T::try_skip(self.data).ok()? {
                &[] => break,
                rest => self.data = rest,
            };
        }
        self.next()
    }

    #[inline]
    fn nth(&mut self, n: usize) -> Option<Self::Item> {
        self.advance_by(n).ok()?;
        self.next()
    }

    #[inline]
    fn size_hint(&self) -> (usize, Option<usize>) {
        if let Some(n) = self.len() {
            (n, Some(n))
        } else {
            let lower = self.data.len().checked_div(T::SIZE.min()).unwrap_or(0);
            let upper = self.data.len().checked_div(T::SIZE.max()).unwrap_or(0);
            (lower, Some(upper))
        }
    }
}

impl<'a, T> FusedIterator for TryIter<'a, T> where T: TryParse<'a> {}

impl<'a, T> fmt::Debug for TryIter<'a, T>
where
    T: TryParse<'a> + fmt::Debug,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if f.alternate() {
            f.debug_list().entries(self.clone()).finish()
        } else {
            f.debug_tuple("TryIter").field(&self.data).finish()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    macro_rules! hex {
        ($($s:literal)*) => {
            &::hex_literal::hex!($($s)*)
        }
    }

    impl<'a, T, const MIN: usize, const MAX: usize> Vector<'a, T, MIN, MAX> {
        const fn len(&self) -> usize {
            self.as_slice().len()
        }
    }

    #[test]
    fn test_vector() {
        let mut data = vec![42; 2 + 300];
        [data[0], data[1]] = u16::to_be_bytes(300);
        let (got, rest) = Vector::<u8, 300, 400>::try_parse(&data).unwrap();
        assert_eq!(got, &data[2..]);
        assert_eq!(rest, &[]);
    }

    #[test]
    fn test_try_iter() {
        let data = hex!("0014001d0017001e0019001801000101010201030104");
        let v = Vector::<u16, 0, { (1 << 16) - 1 }>::try_parse_all(data).unwrap();

        // First two bytes of `data` are the length.
        assert_eq!(v.len() % 2, 0);
        assert_eq!(v.len() / 2, (data.len() - 2) / 2);

        let chunks = v
            .as_slice()
            .chunks_exact(2)
            .map(|chunk| u16::from_be_bytes(chunk.try_into().unwrap()));
        let nchunks = chunks.len();

        assert_eq!(v.try_iter().count(), nchunks);
        assert_eq!(v.iter().count(), nchunks);

        assert_eq!(v.try_iter().size_hint(), (nchunks, Some(nchunks)));
        assert_eq!(v.iter().size_hint(), (nchunks, Some(nchunks)));

        assert!(v.try_iter().eq(chunks.clone().map(Ok)));
        assert!(v.iter().eq(chunks.clone()));
    }
}
