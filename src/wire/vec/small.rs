use core::{fmt, iter::FusedIterator, marker::PhantomData};

use buggy::{bug, BugExt};
use subtle::{Choice, ConstantTimeEq};

use crate::wire::{EncBuf, Error, Object, Size, TryEncode, TryParse};

/// A small variable-length [vector].
///
/// - `T` is the type of data stored in the vector.
/// - `MIN` is the minimum length of the vector.
/// - `MAX` is the maximum length of the vector.
///
/// [vector]: https://datatracker.ietf.org/doc/html/rfc8446#section-3.4
#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd)]
pub struct SmallVec<T, const MIN: usize, const MAX: usize> {
    data: [u8; MAX],
    len: usize,
    _marker: PhantomData<fn() -> T>,
}

impl<T, const MIN: usize, const MAX: usize> SmallVec<T, MIN, MAX> {
    const LENGTH_SIZE: usize = {
        let bits = usize::BITS - MAX.leading_zeros();
        ((bits + 7) / 8) as usize
    };

    pub(crate) const fn new(data: [u8; MAX], len: usize) -> Self {
        debug_assert!(data.len() >= MIN);
        debug_assert!(data.len() <= MAX);
        debug_assert!(len <= data.len());

        Self {
            data,
            len,
            _marker: PhantomData,
        }
    }

    pub(crate) const fn as_slice(&self) -> &[u8] {
        match self.data.split_at_checked(self.len) {
            Some((head, _)) => head,
            None => &[],
        }
    }

    pub(crate) const fn iter(&self) -> IntoIter<T, MAX> {
        IntoIter::new(self.data, self.len)
    }

    #[allow(dead_code)] // TODO
    pub(crate) const fn try_iter(&self) -> TryIntoIter<T, MAX> {
        TryIntoIter::new(self.data, self.len)
    }
}

impl<T, const MIN: usize, const MAX: usize> IntoIterator for SmallVec<T, MIN, MAX>
where
    T: for<'de> TryParse<'de>,
{
    type Item = T;
    type IntoIter = IntoIter<T, MAX>;

    #[inline]
    fn into_iter(self) -> Self::IntoIter {
        IntoIter::new(self.data, self.len)
    }
}

impl<T, const MIN: usize, const MAX: usize> Object for SmallVec<T, MIN, MAX>
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

impl<T, const MIN: usize, const MAX: usize> TryParse<'_> for SmallVec<T, MIN, MAX>
where
    T: for<'de> TryParse<'de>,
{
    fn try_parse(data: &[u8]) -> Result<(Self, &[u8]), Error> {
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
        let data = data.try_into().assume("slice is the correct length")?;

        let v = Self::new(data, len);

        // TODO
        // Make sure all items are valid.
        // {
        //     v.try_iter().find(Result::is_err).transpose()?;
        // }

        Ok((v, rest))
    }
}

impl<T, const MIN: usize, const MAX: usize> TryEncode for SmallVec<T, MIN, MAX>
where
    T: TryEncode,
{
    #[inline]
    fn try_encode(&self, out: &mut EncBuf<'_>) -> Result<(), Error> {
        super::write_length::<MIN, MAX>(out, self.len)?;
        out.write(&self.data)?;
        Ok(())
    }
}

impl<T, const MIN: usize, const MAX: usize> ConstantTimeEq for SmallVec<T, MIN, MAX> {
    fn ct_eq(&self, other: &Self) -> Choice {
        ConstantTimeEq::ct_eq(self.as_slice(), other.as_slice())
    }
}

impl<U, T, const MIN: usize, const MAX: usize> PartialEq<U> for SmallVec<T, MIN, MAX>
where
    U: AsRef<[u8]>,
{
    #[inline]
    fn eq(&self, other: &U) -> bool {
        PartialEq::eq(self.as_slice(), other.as_ref())
    }
}

impl<T, const MIN: usize, const MAX: usize> PartialEq<[u8]> for SmallVec<T, MIN, MAX> {
    #[inline]
    fn eq(&self, other: &[u8]) -> bool {
        PartialEq::eq(self.as_slice(), other)
    }
}

impl<T, const MIN: usize, const MAX: usize> fmt::Debug for SmallVec<T, MIN, MAX> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SmallVec<{MIN}, {MAX}>({:x?})", self.as_slice())
    }
}

/// An iterator over elements in a [`Vector`].
pub struct IntoIter<T, const MAX: usize> {
    iter: TryIntoIter<T, MAX>,
}

impl<T, const MAX: usize> IntoIter<T, MAX> {
    #[inline]
    pub(crate) const fn new(data: [u8; MAX], len: usize) -> Self {
        Self {
            iter: TryIntoIter::new(data, len),
        }
    }

    /// [`Clone`], but `const`.
    #[inline]
    pub(crate) const fn const_clone(&self) -> Self {
        Self {
            iter: self.iter.const_clone(),
        }
    }
}

impl<T, const MAX: usize> Clone for IntoIter<T, MAX> {
    #[inline]
    fn clone(&self) -> Self {
        self.const_clone()
    }
}

impl<T, const MAX: usize> Iterator for IntoIter<T, MAX>
where
    T: for<'de> TryParse<'de>,
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

impl<T, const MAX: usize> FusedIterator for IntoIter<T, MAX> where T: for<'de> TryParse<'de> {}

impl<T, const MAX: usize> fmt::Debug for IntoIter<T, MAX>
where
    T: for<'de> TryParse<'de> + fmt::Debug,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("IntoIter").field(&self.iter).finish()
    }
}

/// An iterator over elements in a [`Vector`].
pub struct TryIntoIter<T, const MAX: usize> {
    data: [u8; MAX],
    start: usize,
    end: usize,
    _marker: PhantomData<fn() -> T>,
}

impl<T, const MAX: usize> Clone for TryIntoIter<T, MAX> {
    #[inline]
    fn clone(&self) -> Self {
        self.const_clone()
    }
}

impl<T, const MAX: usize> TryIntoIter<T, MAX> {
    #[inline]
    pub(crate) const fn new(data: [u8; MAX], len: usize) -> Self {
        Self {
            data,
            start: 0,
            end: len,
            _marker: PhantomData,
        }
    }

    /// [`Clone`], but `const`.
    #[inline]
    pub(crate) const fn const_clone(&self) -> Self {
        Self {
            data: self.data,
            start: self.start,
            end: self.end,
            _marker: PhantomData,
        }
    }

    const fn as_slice(&self) -> &[u8] {
        let Some((data, _)) = self.data.split_at_checked(self.end) else {
            return &[];
        };
        match data.split_at_checked(self.start) {
            Some((_, data)) => data,
            None => &[],
        }
    }
}

impl<T, const MAX: usize> TryIntoIter<T, MAX>
where
    T: for<'de> TryParse<'de>,
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
            Some(self.as_slice().len() / size)
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
                if self.as_slice().get(..n * size).is_none() {
                    // Out of range; the iterator is now empty.
                    let remaining = self.as_slice().len() / size;
                    self.start = MAX;
                    self.end = MAX;
                    return Err(n - remaining);
                };
                self.start += n * size;
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
        let result = T::try_skip(self.as_slice())
            .map(|rest| rest.len())
            .inspect(|n| self.start += self.as_slice().len() - n)
            .map(|_| ());
        Some(result)
    }
}

impl<T, const MAX: usize> Iterator for TryIntoIter<T, MAX>
where
    T: for<'de> TryParse<'de>,
{
    type Item = Result<T, Error>;

    #[inline]
    fn next(&mut self) -> Option<Self::Item> {
        if self.is_empty() {
            return None;
        }
        let result = T::try_parse(self.as_slice())
            .map(|(item, rest)| (item, rest.len()))
            .inspect(|(_, n)| self.start += self.as_slice().len() - n)
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
            match T::try_skip(self.as_slice()).ok()? {
                &[] => break,
                rest => self.start += self.as_slice().len() - rest.len(),
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
            let lower = self
                .as_slice()
                .len()
                .checked_div(T::SIZE.min())
                .unwrap_or(0);
            let upper = self
                .as_slice()
                .len()
                .checked_div(T::SIZE.max())
                .unwrap_or(0);
            (lower, Some(upper))
        }
    }
}

impl<T, const MAX: usize> FusedIterator for TryIntoIter<T, MAX> where T: for<'de> TryParse<'de> {}

impl<T, const MAX: usize> fmt::Debug for TryIntoIter<T, MAX>
where
    T: for<'de> TryParse<'de> + fmt::Debug,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if f.alternate() {
            f.debug_list().entries(self.clone()).finish()
        } else {
            f.debug_tuple("TryIntoIter")
                .field(&self.as_slice())
                .finish()
        }
    }
}
