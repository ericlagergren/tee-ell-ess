//! Errors.

use core::fmt;

use crate::wire::alert::Alert;
pub use crate::wire::parse::ParseError;

/// TODO
#[derive(Clone, Debug, thiserror::Error)]
pub struct Error {
    #[from]
    alert: Alert,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.alert)
    }
}

impl From<Error> for Alert {
    #[inline]
    fn from(err: Error) -> Self {
        err.alert
    }
}
