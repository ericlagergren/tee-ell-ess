//! Errors.

use core::convert::Infallible;

use buggy::Bug;

use crate::{tls::ext::ExtMask, wire::alert::Alert};

/// The result from parsing or encoding a type.
pub type Result<T, E = Error> = core::result::Result<T, E>;

/// TODO
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
#[error("{alert}: {context}")]
pub struct Error {
    alert: Alert,
    context: &'static str,
}

impl Error {
    pub(crate) const fn new(alert: Alert, context: &'static str) -> Self {
        Self { alert, context }
    }

    pub(crate) const fn todo() -> Self {
        Self::internal_error("TODO")
    }

    pub(crate) const fn decode_error(context: &'static str) -> Self {
        Self::new(Alert::decode_error(), context)
    }

    pub(crate) const fn unsupported_type(context: &'static str) -> Self {
        Self::internal_error(context)
    }

    pub(crate) const fn protocol_version(context: &'static str) -> Self {
        Self::new(Alert::protocol_version(), context)
    }

    pub(crate) const fn unexpected_eof() -> Self {
        Self::decode_error("unexpected EOF")
    }

    pub(crate) const fn buffer_too_short() -> Self {
        Self::internal_error("buffer too short")
    }

    pub(crate) const fn internal_error(context: &'static str) -> Self {
        Self::new(Alert::internal_error(), context)
    }

    pub(crate) const fn record_overflow(context: &'static str) -> Self {
        Self::new(Alert::record_overflow(), context)
    }

    pub(crate) const fn illegal_parameter(context: &'static str) -> Self {
        Self::new(Alert::illegal_parameter(), context)
    }

    pub(crate) const fn unexpected_message(context: &'static str) -> Self {
        Self::new(Alert::unexpected_message(), context)
    }

    pub(crate) const fn missing_extension(context: &'static str) -> Self {
        Self::new(Alert::missing_extension(), context)
    }

    pub(crate) const fn unsupported_extension(_mask: ExtMask) -> Self {
        Self::new(Alert::unsupported_extension(), "")
    }
}

impl From<Error> for Alert {
    #[inline]
    fn from(err: Error) -> Self {
        err.alert
    }
}

impl From<Bug> for Error {
    #[inline]
    fn from(err: Bug) -> Self {
        Self::internal_error(err.msg())
    }
}

impl From<Infallible> for Error {
    #[inline]
    fn from(err: Infallible) -> Self {
        match err {}
    }
}
