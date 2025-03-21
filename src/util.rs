use core::{fmt, ops::Deref};

use buggy::BugExt;
use subtle::{Choice, ConstantTimeEq};

use crate::{
    io::Read,
    wire::{self, TryEncode, TryParse},
    Error,
};

#[derive(Copy, Clone, Debug)]
pub(crate) struct Buffer<const N: usize> {
    data: [u8; N],
    read: usize,
    write: usize,
}

impl<const N: usize> Buffer<N> {
    /// Creates an empty buffer.
    pub const fn new() -> Self {
        Self {
            data: [0; N],
            read: 0,
            write: 0,
        }
    }

    /// Returns the length of the unread portion of the buffer.
    pub const fn len(&self) -> usize {
        self.as_bytes().len()
    }

    /// Reports whether the unread portion of the buffer is
    /// empty.
    pub const fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Returns the unread portion of the buffer.
    pub const fn as_bytes(&self) -> &[u8] {
        if self.read >= self.write {
            // This shouldn't ever happen.
            return &[];
        }
        let Some((written, _)) = self.data.split_at_checked(self.write) else {
            return &[];
        };
        match written.split_at_checked(self.read) {
            Some((_, data)) => data,
            None => &[],
        }
    }

    fn with_bytes<'a, R>(&'a self, f: impl FnOnce(&'a [u8]) -> R) -> R {
        f(self.as_bytes())
    }

    /// Returns the remaining space available for writing.
    fn unused(&mut self) -> &mut [u8] {
        self.data.get_mut(self.write..).unwrap_or_default()
    }

    /// Writes `data` to the buffer.
    #[inline]
    pub fn write(&mut self, data: &[u8]) -> Result<(), OutOfSpace> {
        self.unused()
            .get_mut(..data.len())
            .ok_or(OutOfSpace)?
            .copy_from_slice(data);
        // If `get_mut(..data.len())` returns `Some`, then
        // `idx+data.len()` cannot overflow since slices can have
        // at most `isize::MAX` elements and `self.write` is
        // `usize`.
        self.write += data.len();
        Ok(())
    }

    /// Writes `data` to the buffer.
    #[inline]
    pub fn write_fixed<const M: usize>(&mut self, data: &[u8; M]) -> Result<(), OutOfSpace> {
        let (dst, _) = self.unused().split_first_chunk_mut().ok_or(OutOfSpace)?;
        *dst = *data;
        // If `split_first_chunk_mut` returns `Some`, then
        // `idx+data.len()` cannot overflow since slices can have
        // at most `isize::MAX` elements and `self.write` is
        // `usize`.
        self.write += data.len();
        Ok(())
    }

    /// Writes the encoding of `data` to the buffer.
    pub fn write_type<T: TryEncode>(&mut self, data: T) -> Result<(), Error> {
        let mut buf = wire::EncBuf::new(self.unused());
        data.try_encode(&mut buf)?;
        // This does not overflow because `buf.len()` is at most
        // `self.unused().len()`, which is at most `isize::MAX`
        // and `self.write` is `usize`.
        self.write += buf.len();
        Ok(())
    }

    /// Reads exactly `n` bytes from `rd` and writes the bytes to
    /// the buffer.
    pub async fn read_exact_from<R: Read>(&mut self, rd: &mut R, n: usize) -> Result<(), Error> {
        let buf = self
            .unused()
            .get_mut(..n)
            .assume("buffer should have `n` bytes of space")?;
        rd.read_exact(buf).await?;
        // If `get_mut(..n)` returns `Some`, then `idx+n` cannot
        // overflow since slices can have at most `isize::MAX`
        // elements and `self.write` is `usize`.
        self.write += n;
        Ok(())
    }

    /// Reads a `T` from the buffer without advancing the read
    /// index.
    pub fn peek_type<'a, T>(&'a self) -> Result<T, Error>
    where
        T: TryParse<'a>,
    {
        let size = T::SIZE.max().min(self.len());
        let buf = self
            .as_bytes()
            .get(..size)
            .assume("buffer should have `T::SIZE` bytes of space")?;
        T::try_parse(buf).map(|(v, _)| v).map_err(Into::into)
    }

    /// Reads a `T` from the buffer.
    pub fn read_type<'a, T>(&'a mut self) -> Result<T, Error>
    where
        T: TryParse<'a>,
    {
        let size = T::SIZE.max().min(self.len());
        let buf = self
            .data
            .get_mut(self.read..size)
            .assume("buffer should have `T::SIZE` bytes of space")?;
        let (v, rest) = T::try_parse(buf)?;
        let nr = buf.len() - rest.len();

        self.read += nr;

        Ok(v)
    }

    pub fn clear(&mut self) {
        self.read = 0;
    }
}

/// Sensitive, but not secret data.
#[derive(Copy, Clone, Debug)]
pub struct Sensitive<'a>(pub(crate) &'a [u8]);

impl Deref for Sensitive<'_> {
    type Target = [u8];

    #[inline]
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<'a> AsRef<[u8]> for Sensitive<'a>
where
    <Sensitive<'a> as Deref>::Target: AsRef<[u8]>,
{
    #[inline]
    fn as_ref(&self) -> &[u8] {
        self.deref().as_ref()
    }
}

impl Eq for Sensitive<'_> {}
impl PartialEq for Sensitive<'_> {
    fn eq(&self, other: &Self) -> bool {
        bool::from(ConstantTimeEq::ct_eq(self, other))
    }
}

impl ConstantTimeEq for Sensitive<'_> {
    fn ct_eq(&self, other: &Self) -> Choice {
        ConstantTimeEq::ct_eq(self.0, other.0)
    }
}

/// Constant time hex implementations of `Display` and `Debug`.
pub(crate) struct Hex<'a>(pub &'a [u8]);

impl fmt::Display for Hex<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use fmt::Write;

        // From https://docs.rs/spideroak-crypto/0.2.1/spideroak_crypto/hex/index.html
        #[inline(always)]
        const fn enc_nibble(c: u8) -> u8 {
            let c = c as u16;
            c.wrapping_add(87)
                .wrapping_add((c.wrapping_sub(10) >> 8) & !38) as u8
        }

        for v in self.0 {
            f.write_char(enc_nibble(v >> 4) as char)?;
            f.write_char(enc_nibble(v & 0x0f) as char)?;
        }
        Ok(())
    }
}

impl fmt::Debug for Hex<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self}")
    }
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, thiserror::Error)]
#[error("out of space")]
pub struct OutOfSpace;
