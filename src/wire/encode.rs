use buggy::BugExt;

use crate::wire::{types::u24, Error, Result};

/// Encodes the TLS wire format.
pub trait TryEncode {
    /// Writes its encoding to `out`.
    fn try_encode(&self, out: &mut EncBuf<'_>) -> Result<()>;
}

macro_rules! impl_scalar_try_encode {
    ($($name:ident)*) => {
        $(impl TryEncode for $name {
            #[inline]
            fn try_encode(&self, out: &mut EncBuf<'_>) -> Result<()> {
                out.write_fixed(&self.to_be_bytes())
            }
        })*
    };
}
impl_scalar_try_encode!(u8 u16 u24 u32 u64);

impl<T: TryEncode> TryEncode for &T {
    #[inline]
    fn try_encode(&self, out: &mut EncBuf<'_>) -> Result<()> {
        T::try_encode(&**self, out)
    }
}

// TODO(eric): specialize `[u8]`?
impl<T: TryEncode> TryEncode for [T] {
    #[inline]
    fn try_encode(&self, out: &mut EncBuf<'_>) -> Result<()> {
        for item in self {
            item.try_encode(out)?;
        }
        Ok(())
    }
}

impl<const N: usize> TryEncode for [u8; N] {
    #[inline]
    fn try_encode(&self, out: &mut EncBuf<'_>) -> Result<()> {
        out.write_fixed(self)
    }
}

/// An output buffer for writing the TLS wire format.
pub struct EncBuf<'a> {
    buf: &'a mut [u8],
    idx: usize,
}

impl<'a> EncBuf<'a> {
    /// Creates a buffer with backing data.
    pub const fn new(buf: &'a mut [u8]) -> Self {
        Self { buf, idx: 0 }
    }
}

impl EncBuf<'_> {
    /// Returns the remaining space available for writing.
    fn unused(&mut self) -> &mut [u8] {
        self.buf.get_mut(self.idx..).unwrap_or_default()
    }

    pub(crate) const fn len(&self) -> usize {
        self.idx
    }

    /// Writes `data` to the buffer.
    #[inline]
    pub fn write(&mut self, data: &[u8]) -> Result<()> {
        let n = data.len().min(self.unused().len());
        let dst = self
            .unused()
            .get_mut(..n)
            .ok_or(Error::buffer_too_short())?;
        dst[..n].copy_from_slice(&data[..n]);
        self.idx = self
            .idx
            .checked_add(n)
            .assume("`idx + n` should not overflow")?;
        Ok(())
    }

    /// Writes fixed-size data to the buffer.
    #[inline]
    pub fn write_fixed<const N: usize>(&mut self, data: &[u8; N]) -> Result<()> {
        let (dst, _) = self
            .unused()
            .split_first_chunk_mut()
            .ok_or(Error::buffer_too_short())?;
        *dst = *data;
        self.idx = self
            .idx
            .checked_add(data.len())
            .assume("`idx + N` should not overflow")?;
        Ok(())
    }
}
