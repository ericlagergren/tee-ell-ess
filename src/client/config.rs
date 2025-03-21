use core::fmt;

use crate::{
    crypto::Csprng, tls::ext::sni::HostName, CipherSuite, MaxFragmentLength, Time, Version,
};

/// Configures a [`Conn`][crate::client::Conn].
pub trait ClientConfig: fmt::Debug {
    /// Specifies supported ALPN protocols.
    ///
    /// By default, no ALPN protocols are supported.
    fn alpn(&self) -> &[&'static [u8]] {
        &[]
    }

    /// Specifies the supported cipher suites.
    fn cipher_suites(&self) -> &[CipherSuite];

    /// Returns a cryptographically secure pseudo-random number
    /// generator.
    fn csprng(&self) -> &dyn Csprng;

    /// Reports whether early data is supported.
    ///
    /// By default, early data is not supported.
    fn early_data(&self) -> bool {
        false
    }

    /// Specifies the maximum size of a single fragment.
    ///
    /// By default, the maximum fragment size
    /// [`MaxFragmentSize::MAX`] is used.
    ///
    /// [RFC 8446]: https://datatracker.ietf.org/doc/html/rfc8446#section-5.1
    /// [RFC 6066]: https://datatracker.ietf.org/doc/html/rfc6066#autoid-4
    fn max_fragment_length(&self) -> Option<MaxFragmentLength> {
        None
    }

    /// Specifies the name used to verify the hostname on the
    /// server's certificate.
    fn server_name(&self) -> HostName<'_>;

    /// Returns the supported TLS versions.
    ///
    /// By default, only TLS 1.3 is supported.
    fn supported_versions(&self) -> &[Version] {
        &[Version::Tls13]
    }

    /// Returns the current time.
    fn time(&self) -> &dyn Time;
}
