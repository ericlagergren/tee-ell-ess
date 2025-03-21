//! The `server_name` extension per [RFC 6066].
//!
//![RFC 6066]: https://tools.ietf.org/html/rfc6066

use core::fmt;

use crate::wire::{sni, Object};

/// A fully qualified DNS name of a server.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct HostName<'a>(&'a str);

impl<'a> HostName<'a> {
    /// Creates a `HostName`.
    ///
    /// It returns `None` if `name`
    ///
    /// - Is not valid ASCII.
    /// - Is not least 1 byte long.
    /// - Is not at most (2^16)-1 bytes long.
    /// - Ends with a dot (`.`).
    #[inline]
    pub const fn new(name: &'a str) -> Option<Self> {
        if name.len() < sni::HostName::SIZE.min()
            || name.len() > sni::HostName::SIZE.max()
            || !name.is_ascii()
            || matches!(name.as_bytes().last(), Some(b'.'))
        {
            None
        } else {
            Some(Self(name))
        }
    }
}

impl<'a> From<HostName<'a>> for sni::HostName<'a> {
    #[inline]
    fn from(name: HostName<'a>) -> Self {
        sni::HostName::new(name.0.as_bytes())
    }
}

impl HostName<'_> {
    /// Returns the host name.
    #[inline]
    pub const fn as_str(&self) -> &str {
        self.0
    }
}

impl PartialEq<str> for HostName<'_> {
    #[inline]
    fn eq(&self, other: &str) -> bool {
        PartialEq::eq(self.0, other)
    }
}

impl PartialEq<&str> for HostName<'_> {
    #[inline]
    fn eq(&self, other: &&str) -> bool {
        PartialEq::eq(self.0, *other)
    }
}

impl fmt::Display for HostName<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}
