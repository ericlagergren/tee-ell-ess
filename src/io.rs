use core::{fmt, future::Future};

use crate::{wire::TryParse, Error};

pub trait Read {
    /// Reads up to `buf.len()` bytes into `buf` and returns the
    /// number of bytes read.
    fn try_read(&mut self, buf: &mut [u8]) -> Result<usize, IoError>;

    /// Reads exactly `buf.len()` bytes into `buf`.
    fn read_exact(&mut self, buf: &mut [u8]) -> impl Future<Output = Result<(), IoError>> {
        async {
            let mut nr = 0;
            while nr < buf.len() {
                let n = self.try_read(&mut buf[nr..])?;
                if n == 0 {
                    return Err(IoError::unexpected_eof());
                }
                nr += n;
            }
            Ok(())
        }
    }
}

pub(crate) trait ReadExt: Read {
    fn read_type<'a, T>(&mut self, buf: &'a mut [u8]) -> impl Future<Output = Result<T, Error>>
    where
        T: TryParse<'a>,
    {
        async {
            self.read_exact(buf).await?;
            T::try_parse_all(buf).map_err(Error::wire)
        }
    }
}

impl<T: Read> ReadExt for T {}

pub trait Write {
    /// Writes the entirety of `buf` to `self`.
    fn try_write_all(&mut self, buf: &[u8]) -> Result<(), IoError>;

    /// Writes the entirety of `buf` to `self`.
    fn write_all(&mut self, buf: &[u8]) -> impl Future<Output = Result<(), IoError>>;
}

/// An I/O error.
#[derive(Debug, Eq, PartialEq, thiserror::Error)]
pub struct IoError {
    // TODO
}

impl IoError {
    /// Returns an unexpected EOF error.
    pub const fn unexpected_eof() -> Self {
        Self {
            // TODO
        }
    }
}

impl fmt::Display for IoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "I/O error")
    }
}
