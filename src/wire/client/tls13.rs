//! TLS 1.3.

use core::{
    fmt,
    iter::{ExactSizeIterator, FusedIterator},
};

use crate::wire::{
    parse::{ParseError, TryParse, Vector},
    tls13::{Extension, Extension2, ProtocolVersion},
};

// // RFC 8446: "In TLS 1.3, the client indicates its
// // version preferences in the "supported_versions"
// // extension (Section 4.2.1) and the legacy_version field
// // MUST be set to 0x0303, which is the version number for
// // TLS 1.2."
// if version != ProtocolVersion::Tls12 {
//     return Err(ParseError::from("unexpected TLS version"));
// }

/// The `ClientHello` message per [RFC 8446].
///
/// [RFC 8446]: https://datatracker.ietf.org/doc/html/rfc8446#section-4.1.2
#[derive(Copy, Clone)]
pub struct ClientHello<'a> {
    version: ProtocolVersion,
    random: &'a [u8; 32],
    legacy_session_id: LegacySessionId<'a>,
    suites: SupportedCipherSuites<'a>,
    legacy_compression_methods: LegacyCompressionMethods<'a>,
    extensions: SupportedExtensions<'a>,
}

impl<'a> ClientHello<'a> {
    /// TODO
    pub const MAX_SIZE: usize = 2
        + 32
        + LegacySessionId::MAX_SIZE
        + SupportedCipherSuites::MAX_SIZE
        + LegacyCompressionMethods::MAX_SIZE
        + SupportedExtensions::MAX_SIZE;

    /// Returns the protocol version.
    pub const fn version(&self) -> ProtocolVersion {
        self.version
    }

    /// Returns the client's 32-byte random nonce.
    pub const fn random(&self) -> &[u8; 32] {
        self.random
    }

    /// Returns the legacy session ID.
    pub const fn legacy_session_id(&self) -> LegacySessionId<'_> {
        self.legacy_session_id
    }

    /// Returns the supported cipher suites.
    pub const fn suites(&self) -> CipherSuites<'_> {
        CipherSuites::new(self.suites)
    }

    /// Returns the legacy compression methods.
    pub const fn legacy_compression_methods(&self) -> LegacyCompressionMethods<'_> {
        self.legacy_compression_methods
    }

    /// Returns the extensions.
    pub const fn extensions(&self) -> Extensions<'_> {
        Extensions::new(self.extensions)
    }
}

impl<'a> TryParse<'a> for ClientHello<'a> {
    fn try_parse(msg: &'a [u8]) -> Result<(Self, &'a [u8]), ParseError> {
        // struct {
        //     ProtocolVersion legacy_version = 0x0303;    /* TLS v1.2 */
        //     Random random;
        //     opaque legacy_session_id<0..32>;
        //     CipherSuite cipher_suites<2..2^16-2>;
        //     opaque legacy_compression_methods<1..2^8-1>;
        //     Extension extensions<8..2^16-1>;
        // } ClientHello;
        let (version, rest) = ProtocolVersion::try_parse(msg)?;
        let (random, rest) = try_parse_random(rest)?;
        let (legacy_session_id, rest) = LegacySessionId::try_parse(rest)?;
        let (suites, rest) = SupportedCipherSuites::try_parse(rest)?;
        let (legacy_compression_methods, rest) = LegacyCompressionMethods::try_parse(rest)?;
        let (extensions, rest) = SupportedExtensions::try_parse(rest)?;
        let hello = Self {
            version,
            random,
            legacy_session_id,
            suites,
            legacy_compression_methods,
            extensions,
        };
        Ok((hello, rest))
    }
}

impl fmt::Debug for ClientHello<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ClientHello")
            .field("version", &self.version())
            .field(
                "random",
                if cfg!(tee_ell_ess_debug) {
                    &self.random
                } else {
                    &"[REDACTED]"
                },
            )
            .field("legacy_session_id", &self.legacy_session_id())
            .field("suites", &self.suites())
            .field(
                "legacy_compression_methods",
                &self.legacy_compression_methods(),
            )
            .field("extensions", &self.extensions())
            .finish_non_exhaustive()
    }
}

#[inline]
fn try_parse_random(data: &[u8]) -> Result<(&[u8; 32], &[u8]), ParseError> {
    let (random, rest) = data
        .split_first_chunk()
        .ok_or(ParseError::unexpected_eof())?;
    Ok((random, rest))
}

/// Legacy session ID.
///
/// ```text
/// opaque legacy_session_id<0..32>;
/// ```
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct LegacySessionId<'a>(Vector<'a, 0, 32>);

impl<'a> LegacySessionId<'a> {
    const MAX_SIZE: usize = 32;
}

impl<'a> TryParse<'a> for LegacySessionId<'a> {
    #[inline]
    fn try_parse(data: &'a [u8]) -> Result<(Self, &'a [u8]), ParseError> {
        let (session_id, rest) = Vector::try_parse(data)?;
        Ok((Self(session_id), rest))
    }
}

/// TLS 1.3 cipher suites.
#[repr(u16)]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum CipherSuite {
    /// TLS_AES_128_GCM_SHA256.
    TlsAes128GcmSha256 = 0x1301,
    /// TLS_AES_256_GCM_SHA384.
    TlsAes256GcmSha384 = 0x1302,
    /// TLS_CHACHA20_POLY1305_SHA256.
    TlsChaCha20Poly1305 = 0x1303,
    /// TLS_AES_128_CCM_SHA256.
    TlsAes128CcmSha256 = 0x1304,
    /// TLS_AES_128_CCM_8_SHA256.
    TlsAes128Ccm8Sha256 = 0x1305,
    /// Unknown.
    Unknown(u16) = 0xffff,
}

impl TryParse<'_> for CipherSuite {
    #[inline]
    fn try_parse(data: &[u8]) -> Result<(Self, &[u8]), ParseError> {
        use CipherSuite::*;

        let ([lo, hi], rest) = data
            .split_first_chunk()
            .ok_or(ParseError::unexpected_eof())?;
        let suite = match u16::from_be_bytes([*lo, *hi]) {
            0x1301 => TlsAes128GcmSha256,
            0x1302 => TlsAes256GcmSha384,
            0x1303 => TlsChaCha20Poly1305,
            0x1304 => TlsAes128CcmSha256,
            0x1305 => TlsAes128Ccm8Sha256,
            v => Unknown(v),
        };
        Ok((suite, rest))
    }
}

impl fmt::Display for CipherSuite {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use CipherSuite::*;
        match self {
            TlsAes128GcmSha256 => write!(f, "TLS_AES_128_GCM_SHA256"),
            TlsAes256GcmSha384 => write!(f, "TLS_AES_256_GCM_SHA384"),
            TlsChaCha20Poly1305 => write!(f, "TLS_CHACHA20_POLY1305_SHA256"),
            TlsAes128CcmSha256 => write!(f, "TLS_AES_128_CCM_SHA256"),
            TlsAes128Ccm8Sha256 => write!(f, "TLS_AES_128_CCM_8_SHA256"),
            Unknown(v) => write!(f, "unknown {v:#x}"),
        }
    }
}

/// An iterator over [`CipherSuite`]s.
#[derive(Clone)]
pub struct CipherSuites<'a> {
    data: &'a [u8],
}

impl<'a> CipherSuites<'a> {
    const fn new(suites: SupportedCipherSuites<'a>) -> Self {
        Self {
            data: suites.0.as_slice(),
        }
    }
}

impl Iterator for CipherSuites<'_> {
    type Item = CipherSuite;

    #[inline]
    fn next(&mut self) -> Option<Self::Item> {
        let (suite, rest) = CipherSuite::try_parse(self.data).ok()?;
        self.data = rest;
        Some(suite)
    }

    #[inline]
    fn count(self) -> usize {
        self.len()
    }

    #[inline]
    fn size_hint(&self) -> (usize, Option<usize>) {
        let n = self.len();
        (n, Some(n))
    }
}

impl ExactSizeIterator for CipherSuites<'_> {
    #[inline]
    fn len(&self) -> usize {
        self.data.len() / 2
    }
}

impl FusedIterator for CipherSuites<'_> {}

impl fmt::Debug for CipherSuites<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_list().entries(self.clone()).finish()
    }
}

/// ```text
/// CipherSuite cipher_suites<2..2^16-2>;
/// ```
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
struct SupportedCipherSuites<'a>(Vector<'a, 2, { (1 << 16) - 2 }>);

impl SupportedCipherSuites<'_> {
    const MAX_SIZE: usize = (1 << 16) - 2;
}

impl<'a> TryParse<'a> for SupportedCipherSuites<'a> {
    #[inline]
    fn try_parse(data: &'a [u8]) -> Result<(Self, &'a [u8]), ParseError> {
        let (suites, rest) = Vector::try_parse(data)?;
        // Each suite is 16 bits.
        if suites.len() % 2 != 0 {
            return Err(ParseError::from("unexpected cipher suite length"));
        }
        for chunk in suites.chunks_exact(2) {
            CipherSuite::try_parse(chunk)?;
        }
        Ok((Self(suites), rest))
    }
}

/// Legacy compression methods.
///
/// ```text
/// opaque legacy_compression_methods<1..2^8-1>;
/// ```
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct LegacyCompressionMethods<'a>(Vector<'a, 1, { (1 << 8) - 1 }>);

impl<'a> LegacyCompressionMethods<'a> {
    const MAX_SIZE: usize = (1 << 8) - 1;
}

impl<'a> TryParse<'a> for LegacyCompressionMethods<'a> {
    #[inline]
    fn try_parse(data: &'a [u8]) -> Result<(Self, &'a [u8]), ParseError> {
        let (session_id, rest) = Vector::try_parse(data)?;
        Ok((Self(session_id), rest))
    }
}

/// An iterator over [`Extension`]s.
#[derive(Clone)]
pub struct Extensions<'a> {
    data: &'a [u8],
}

impl<'a> Extensions<'a> {
    const fn new(exts: SupportedExtensions<'a>) -> Self {
        Self {
            data: exts.data.as_slice(),
        }
    }
}

impl<'a> Iterator for Extensions<'a> {
    type Item = Extension<'a>;

    #[inline]
    fn next(&mut self) -> Option<Self::Item> {
        let (ext, rest) = Extension::try_parse(self.data).ok()?;
        self.data = rest;
        Some(ext)
    }
}

impl fmt::Debug for Extensions<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_list().entries(self.clone()).finish()
    }
}

/// ```text
/// Extension extensions<8..2^16-1>;
/// ```
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
struct SupportedExtensions<'a> {
    data: Vector<'a, 8, { (1 << 16) - 1 }>,
    signature_algorithms: Option<usize>,
    alpn: Option<usize>,
    psk: Option<usize>,
    early_data: Option<usize>,
    supported_versions: Option<usize>,
    psk_modes: Option<usize>,
    key_share: Option<usize>,
}

impl<'a> SupportedExtensions<'a> {
    const MAX_SIZE: usize = (1 << 16) - 1;
}

impl<'a> TryParse<'a> for SupportedExtensions<'a> {
    #[inline]
    fn try_parse(data: &'a [u8]) -> Result<(Self, &'a [u8]), ParseError> {
        let (data, rest) = Vector::try_parse(data)?;
        let mut exts = Self {
            data,
            signature_algorithms: None,
            alpn: None,
            psk: None,
            early_data: None,
            supported_versions: None,
            psk_modes: None,
            key_share: None,
        };
        let mut tmp = &*data;
        while !tmp.is_empty() {
            let (ext, rest) = Extension2::try_parse_client(tmp)?;
            match ext {
                Extension2::SupportedVersions(_) => {
                    if exts.supported_versions.is_some() {
                        return Err(ParseError::from("duplicate supported_versions"));
                    }
                    exts.supported_versions = Some(exts.data.len() - rest.len());
                }
                _ => {}
            }
            tmp = rest;
        }
        Ok((exts, rest))
    }
}

/// TODO
#[derive(Copy, Clone, Eq, PartialEq)]
pub struct SupportedVersions<'a> {
    data: &'a [u8],
    //versions: Vector<'a, 2, 254>,
}

impl<'a> TryParse<'a> for SupportedVersions<'a> {
    #[inline]
    fn try_parse(data: &'a [u8]) -> Result<(Self, &'a [u8]), ParseError> {
        let (versions, rest) = Vector::<'_, 2, 254>::try_parse(data)?;
        Ok((
            Self {
                data: versions.data,
            },
            rest,
        ))
    }
}

impl Iterator for SupportedVersions<'_> {
    type Item = ProtocolVersion;

    #[inline]
    fn next(&mut self) -> Option<Self::Item> {
        let (version, rest) = ProtocolVersion::try_parse(self.data).ok()?;
        self.data = rest;
        Some(version)
    }
}

impl fmt::Debug for SupportedVersions<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_list().entries(self.clone()).finish()
    }
}
