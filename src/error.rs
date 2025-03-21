use core::fmt;

use buggy::Bug;

use crate::{io::IoError, wire::Error as WireError};

/// An error returned by this crate.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
#[error("{kind}")]
pub struct Error {
    kind: ErrorKind,
}

impl Error {
    pub(crate) const fn new(kind: ErrorKind) -> Self {
        Self { kind }
    }

    pub(crate) const fn io(_err: IoError) -> Self {
        Self::new(ErrorKind::Io)
    }

    pub(crate) const fn wire(_err: WireError) -> Self {
        Self::new(ErrorKind::Wire)
    }

    pub(crate) const fn need_handshake() -> Self {
        Self::new(ErrorKind::Wire)
    }
}

impl From<Bug> for Error {
    fn from(_err: Bug) -> Self {
        Self::new(ErrorKind::Bug)
    }
}

impl From<crate::wire::Error> for Error {
    fn from(err: crate::wire::Error) -> Self {
        Error::wire(err)
    }
}

impl From<IoError> for Error {
    fn from(err: IoError) -> Self {
        Error::io(err)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ErrorKind {
    Io,
    Wire,
    NeedHandshake,
    Bug,
}

impl fmt::Display for ErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io => write!(f, "I/O error"),
            Self::Wire => write!(f, "wire error"),
            Self::NeedHandshake => write!(f, "need handshake"),
            Self::Bug => write!(f, "bug"),
        }
    }
}
