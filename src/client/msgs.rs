use core::fmt;

#[cfg(test)]
use subtle::ConstantTimeEq;

use crate::{
    tls::ext::ExtMask,
    util::Hex,
    wire::{
        self,
        alpn::Alpn,
        sni::ServerNameList,
        tls13::{
            self,
            ext::{
                Cookie, KeyShareClientHello, NamedGroupList, OfferedPsksList, PskKexModesList,
                SupportedVersionsList,
            },
            CipherSuiteId,
        },
        vec::{Iter, SmallVec},
        EncBuf, Error, ExtensionType, Object, ProtocolVersion, Size, TryEncode, TryParse,
    },
    MaxFragmentLength,
};

/// TODO
pub struct HelloBuilder<'a> {
    alpn: &'a [&'a [u8]],
    legacy_session_id: [u8; 32],
    extensions: ExtensionList<'static>,
    suites: Iter<'static, CipherSuiteId>,
}

impl<'a> HelloBuilder<'a> {
    /// TODO
    pub const fn new() -> Self {
        Self {
            alpn: &[],
            legacy_session_id: [0; 32],
            extensions: ExtensionList {
                list: Iter::empty(),
                mask: ExtMask::empty(),
                alpn: None,
                cookie: None,
                early_data: false,
                key_share: None,
                max_fragment_length: None,
                pre_shared_key: None,
                psk_kex_modes: None,
                server_name: None,
                supported_versions: None,
            },
            suites: Iter::empty(),
        }
    }

    pub fn pipe(self, f: impl FnOnce(Self) -> Self) -> Self {
        f(self)
    }

    pub fn pipe_if(self, cond: bool, f: impl FnOnce(Self) -> Self) -> Self {
        if cond {
            f(self)
        } else {
            self
        }
    }

    pub fn with_alpn(mut self, alpn: &'a [&'a [u8]]) -> Self {
        self.alpn = alpn;
        self
    }

    pub fn with_early_data(mut self, early_data: bool) -> Self {
        self.extensions.early_data = early_data;
        self
    }

    pub fn with_extension(self, _ext: Extension<'_>) -> Self {
        self
    }

    pub fn with_legacy_session_id(mut self, id: [u8; 32]) -> Self {
        self.legacy_session_id = id;
        self
    }

    pub fn with_max_fragment_length(mut self, len: MaxFragmentLength) -> Self {
        self.extensions.max_fragment_length = Some(len.0);
        self
    }

    pub fn build(self, _out: &mut [u8]) -> Result<&[u8], Error> {
        // let repr = ClientHelloRepr {
        //     legacy_version: ProtocolVersion::Tls12,
        //     random: self.random,
        //     legacy_session_id: Vector::empty(),
        //     cipher_suites: self.suites,
        //     legacy_compression_methods: [0],
        //     extensions: self.extensions.iter(),
        // };
        // repr.try_encode(out)
        todo!()
    }
}

/// The `ClientHello` message per [RFC 8446].
///
/// [RFC 8446]: https://datatracker.ietf.org/doc/html/rfc8446#section-4.1.2
#[derive(Clone)]
pub struct ClientHello<'a> {
    random: [u8; 32],
    legacy_session_id: SmallVec<u8, 0, 32>,
    suites: Iter<'a, CipherSuiteId>,
    extensions: ExtensionList<'a>,
}

impl ClientHello<'_> {
    /// Returns the protocol version.
    #[inline]
    pub const fn version(&self) -> ProtocolVersion {
        // RFC 8446: "In TLS 1.3, the client indicates its
        // version preferences in the "supported_versions"
        // extension (Section 4.2.1) and the legacy_version field
        // MUST be set to 0x0303, which is the version number for
        // TLS 1.2."
        ProtocolVersion::Tls12
    }

    /// Returns the client's 32-byte random nonce.
    #[inline]
    pub const fn random(&self) -> &[u8; 32] {
        &self.random
    }

    /// Returns the legacy session ID.
    #[inline]
    pub const fn legacy_session_id(&self) -> &[u8] {
        self.legacy_session_id.as_slice()
    }

    /// Returns the supported cipher suites.
    #[inline]
    pub const fn suites(&self) -> Iter<'_, CipherSuiteId> {
        self.suites.const_clone()
    }

    /// Returns the extensions.
    #[inline]
    pub const fn extensions(&self) -> &ExtensionList<'_> {
        &self.extensions
    }
}

impl Object for ClientHello<'_> {
    const SIZE: Size = tls13::ClientHello::SIZE;
}

impl<'de: 'a, 'a> TryParse<'de> for ClientHello<'a> {
    #[inline]
    fn try_parse(data: &'de [u8]) -> Result<(Self, &'de [u8]), Error> {
        let (repr, rest) = tls13::ClientHello::try_parse(data)?;

        // RFC 8446: "In TLS 1.3, the client indicates its
        // version preferences in the "supported_versions"
        // extension (Section 4.2.1) and the legacy_version field
        // MUST be set to 0x0303, which is the version number for
        // TLS 1.2."
        if repr.legacy_version != ProtocolVersion::Tls12.to_repr() {
            return Err(Error::protocol_version("`legacy_version` must be TLS 1.2"));
        }

        // RFC 8446: "For every TLS 1.3 ClientHello, this vector
        // MUST contain exactly one byte, set to zero, which
        // corresponds to the "null" compression method in prior
        // versions of TLS. If a TLS 1.3 ClientHello is received
        // with any other value in this field, the server MUST
        // abort the handshake with an "illegal_parameter"
        // alert."
        if repr.legacy_compression_methods != [0] {
            return Err(Error::illegal_parameter(
                "`legacy_compression_methods` must be `[0]`",
            ));
        }

        let hello = Self {
            random: repr.random,
            legacy_session_id: repr.legacy_session_id,
            suites: repr.cipher_suites.map().into_iter(),
            extensions: ExtensionList::new(repr.extensions.map().into_iter())?,
        };
        Ok((hello, rest))
    }
}

#[cfg(test)]
impl Eq for ClientHello<'_> {}

#[cfg(test)]
impl PartialEq for ClientHello<'_> {
    fn eq(&self, other: &Self) -> bool {
        bool::from(self.random.ct_eq(&other.random))
            && self.legacy_session_id == other.legacy_session_id
            && self.suites.clone().eq(other.suites.clone())
            && self.extensions.iter().eq(other.extensions.iter())
    }
}

impl fmt::Debug for ClientHello<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ClientHello")
            .field(
                "random",
                if cfg!(tee_ell_ess_debug) {
                    &self.random
                } else {
                    &"[REDACTED]"
                },
            )
            .field("legacy_session_id", &Hex(self.legacy_session_id.as_slice()))
            .field("suites", &self.suites())
            .field("extensions", &self.extensions)
            .finish_non_exhaustive()
    }
}

/// TLS extensions.
#[derive(Clone)]
pub struct ExtensionList<'a> {
    list: Iter<'a, Extension<'a>>,
    mask: ExtMask,
    len: usize,

    alpn: Option<Alpn<'a>>,
    cookie: Option<Cookie<'a>>,
    early_data: bool,
    key_share: Option<KeyShareClientHello<'a>>,
    max_fragment_length: Option<wire::MaxFragmentLength>,
    pre_shared_key: Option<OfferedPsksList<'a>>,
    psk_kex_modes: Option<PskKexModesList<'a>>,
    server_name: Option<ServerNameList<'a>>,
    supported_versions: Option<SupportedVersionsList<'a>>,
}

impl<'a> ExtensionList<'a> {
    const fn empty() -> Self {
        Self {
            list: Iter::empty(),
            mask: ExtMask::empty(),
            len: 0,
            alpn: None,
            cookie: None,
            early_data: false,
            key_share: None,
            max_fragment_length: None,
            pre_shared_key: None,
            psk_kex_modes: None,
            server_name: None,
            supported_versions: None,
        }
    }

    fn new(list: Iter<'a, Extension<'a>>) -> Result<Self, Error> {
        let mut exts = Self::empty();
        exts.list = list.clone();

        use Extension::*;
        for ext in list {
            let bit = ext.mask_bit();
            // RFC 8446: "If an implementation receives an
            // extension which it recognizes and which is not
            // specified for the message in which it appears, it
            // MUST abort the handshake with an
            // "illegal_parameter" alert."
            if !bit.contains(ExtMask::CH) {
                return Err(Error::illegal_parameter(
                    "extension not allowed in `ClientHello`",
                ));
            }
            // RFC 8446: "There MUST NOT be more than one
            // extension of the same type in a given extension
            // block."
            if exts.mask.contains(bit) {
                return Err(Error::illegal_parameter("duplicate extension"));
            }
            exts.mask |= bit;

            exts.len += 1;

            println!("ext = {:?}", ext);
            match ext {
                Alpn(alpn) => exts.alpn = Some(alpn),
                Cookie(cookie) => exts.cookie = Some(cookie),
                EarlyData => exts.early_data = true,
                KeyShare(ks) => exts.key_share = Some(ks),
                MaxFragmentLength(len) => exts.max_fragment_length = Some(len),
                PreSharedKey(psk) => exts.pre_shared_key = Some(psk),
                PskKexModes(modes) => exts.psk_kex_modes = Some(modes),
                ServerName(names) => exts.server_name = Some(names),
                SupportedVersions(vers) => exts.supported_versions = Some(vers),
                _ => {}
            }
        }

        Ok(exts)
    }

    /// Returns an iterator over the extensions in the order they
    /// were received.
    #[inline]
    pub const fn iter(&self) -> Iter<'_, Extension<'_>> {
        self.list.const_clone()
    }

    /// Returns the number of extensions in the list.
    ///
    /// It's cheaper than calling `self.iter().count()`.
    #[inline]
    pub const fn len(&self) -> usize {
        self.len
    }

    /// Returns the extension mask.
    #[inline]
    pub const fn mask(&self) -> ExtMask {
        self.mask
    }

    /// Returns the `application_layer_protocol_negotiation`
    /// extension, if present.
    #[inline]
    pub const fn alpn(&self) -> Option<Alpn<'a>> {
        self.alpn
    }

    /// Returns the `cookie` extension, if present.
    #[inline]
    pub const fn cookie(&self) -> Option<Cookie<'a>> {
        self.cookie
    }

    /// Returns the `early_data` extension, if present.
    #[inline]
    pub const fn early_data(&self) -> bool {
        self.early_data
    }

    /// Returns the `max_fragment_lenth` extension, if present.
    #[inline]
    pub const fn max_fragment_length(&self) -> Option<MaxFragmentLength> {
        match self.max_fragment_length {
            Some(len) => Some(MaxFragmentLength(len)),
            None => None,
        }
    }

    /// Returns the `key_share` extension, if present.
    #[inline]
    pub const fn key_share(&self) -> Option<KeyShareClientHello<'a>> {
        self.key_share
    }

    /// Returns the `pre_shared_key` extension, if present.
    #[inline]
    pub const fn pre_shared_key(&self) -> Option<OfferedPsksList<'a>> {
        self.pre_shared_key
    }

    /// Returns the `psk_key_exchange_modes` extension, if
    /// present.
    #[inline]
    pub const fn psk_kex_modes(&self) -> Option<PskKexModesList<'a>> {
        self.psk_kex_modes
    }

    /// Returns the `server_name` extension, if present.
    #[inline]
    pub const fn server_name(&self) -> Option<ServerNameList<'a>> {
        self.server_name
    }

    /// Returns the `supported_versions` extension, if present.
    #[inline]
    pub const fn supported_versions(&self) -> Option<SupportedVersionsList<'a>> {
        self.supported_versions
    }
}

impl<'a> IntoIterator for &'a ExtensionList<'a> {
    type Item = Extension<'a>;
    type IntoIter = Iter<'a, Extension<'a>>;

    #[inline]
    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

impl fmt::Debug for ExtensionList<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_list().entries(self.iter()).finish()
    }
}

/// An extension found in a `ClientHello`.
#[derive(Copy, Clone, Debug)]
#[cfg_attr(test, derive(Eq, PartialEq))]
pub enum Extension<'a> {
    /// The `server_name` extension.
    ServerName(ServerNameList<'a>),
    /// The `max_fragment_length` extension.
    MaxFragmentLength(wire::MaxFragmentLength),
    /// TODO
    StatusRequest,
    /// The `supported_groups` extension.
    SupportedGroups(NamedGroupList<'a>),
    /// TODO
    SignatureAlgorithms,
    /// TODO
    UseSrtp,
    /// TODO
    Heartbeat,
    /// The `application_layer_protocol_negotiation` extension.
    Alpn(Alpn<'a>),
    /// TODO
    Sct,
    /// TODO
    ClientCertificateType,
    /// TODO
    ServerCertificateType,
    /// TODO
    Padding,
    /// The `pre_shared_key` extension.
    PreSharedKey(OfferedPsksList<'a>),
    /// The `early_data` extension.
    EarlyData,
    /// The `supported_versions` in a `ClientHello`.
    SupportedVersions(SupportedVersionsList<'a>),
    /// The `cookie` extension.
    Cookie(Cookie<'a>),
    /// The `psk_key_exchange_modes` extension.
    PskKexModes(PskKexModesList<'a>),
    /// TODO
    CertificateAuthorities,
    /// TODO
    OidFilters,
    /// TODO
    PostHandshakeAuth,
    /// TODO
    SignatureAlgorithmsCert,
    /// The `key_share` extension.
    KeyShare(KeyShareClientHello<'a>),
    /// An unknown extension.
    Unknown(wire::Extension<'a>),
}

impl Extension<'_> {
    const fn ty(&self) -> ExtensionType {
        use ExtensionType::*;

        match self {
            Self::ServerName(_) => ServerName,
            Self::MaxFragmentLength(_) => MaxFragmentLength,
            Self::StatusRequest => StatusRequest,
            Self::SupportedGroups(_) => SupportedGroups,
            Self::SignatureAlgorithms => SignatureAlgorithms,
            Self::UseSrtp => UseSrtp,
            Self::Heartbeat => Heartbeat,
            Self::Alpn(_) => Alpn,
            Self::Sct => Sct,
            Self::ClientCertificateType => ClientCertificateType,
            Self::ServerCertificateType => ServerCertificateType,
            Self::Padding => Padding,
            Self::PreSharedKey(_) => PreSharedKey,
            Self::EarlyData => EarlyData,
            Self::SupportedVersions(_) => SupportedVersions,
            Self::Cookie(_) => Cookie,
            Self::PskKexModes(_) => PskKexModes,
            Self::CertificateAuthorities => CertificateAuthorities,
            Self::OidFilters => OidFilters,
            Self::PostHandshakeAuth => PostHandshakeAuth,
            Self::SignatureAlgorithmsCert => SignatureAlgorithmsCert,
            Self::KeyShare(_) => KeyShare,
            Self::Unknown(ext) => ext.extension_type,
        }
    }

    const fn mask_bit(&self) -> ExtMask {
        self.ty().flag()
    }
}

impl Object for Extension<'_> {
    const SIZE: Size = wire::Extension::SIZE;
}

impl<'de: 'a, 'a> TryParse<'de> for Extension<'a> {
    #[inline(always)]
    fn try_skip(data: &'de [u8]) -> Result<&'de [u8], Error> {
        wire::Extension::try_skip(data)
    }

    #[inline]
    fn try_parse(data: &'de [u8]) -> Result<(Self, &'de [u8]), Error> {
        use ExtensionType::*;

        // println!("# Extension");
        // println!("data = {:x?}", data);
        let (ext, rest) = wire::Extension::try_parse(data)?;
        // println!("data = {:x?}", data);
        // println!("rest = {:x?}", rest);

        let ext = match ext.extension_type {
            ServerName => ext.try_parse_data().map(Self::ServerName)?,
            MaxFragmentLength => ext.try_parse_data().map(Self::MaxFragmentLength)?,
            StatusRequest => Self::StatusRequest,
            SupportedGroups => ext.try_parse_data().map(Self::SupportedGroups)?,
            SignatureAlgorithms => Self::SignatureAlgorithms,
            UseSrtp => Self::UseSrtp,
            Heartbeat => Self::Heartbeat,
            Alpn => ext.try_parse_data().map(Self::Alpn)?,
            Sct => Self::Sct,
            ClientCertificateType => Self::ClientCertificateType,
            ServerCertificateType => Self::ServerCertificateType,
            Padding => Self::Padding,
            PreSharedKey => ext.try_parse_data().map(Self::PreSharedKey)?,
            EarlyData => ext.try_parse_data().map(|()| Self::EarlyData)?,
            SupportedVersions => ext.try_parse_data().map(Self::SupportedVersions)?,
            Cookie => ext.try_parse_data().map(Self::Cookie)?,
            PskKexModes => ext.try_parse_data().map(Self::PskKexModes)?,
            CertificateAuthorities => Self::CertificateAuthorities,
            OidFilters => Self::OidFilters,
            PostHandshakeAuth => Self::PostHandshakeAuth,
            SignatureAlgorithmsCert => Self::SignatureAlgorithmsCert,
            KeyShare => ext.try_parse_data().map(Self::KeyShare)?,
            _ => Self::Unknown(ext),
        };
        Ok((ext, rest))
    }
}

impl TryEncode for Extension<'_> {
    #[inline]
    fn try_encode(&self, _out: &mut EncBuf<'_>) -> Result<(), Error> {
        todo!()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    macro_rules! hex {
        ($($s:literal)*) => {
            &::hex_literal::hex!($($s)*)
        }
    }

    #[test]
    fn test_client_hello() {
        let data = hex!(
            "03030001020304"
            "05060708090a0b0c0d0e0f1011121314"
            "15161718191a1b1c1d1e1f20e0e1e2e3"
            "e4e5e6e7e8e9eaebecedeeeff0f1f2f3"
            "f4f5f6f7f8f9fafbfcfdfeff00081302"
            "1303130100ff010000a3000000180016"
            "0000136578616d706c652e756c666865"
            "696d2e6e6574000b000403000102000a"
            "00160014001d0017001e001900180100"
            "01010102010301040023000000160000"
            "00170000000d001e001c040305030603"
            "080708080809080a080b080408050806"
            "040105010601002b0003020304002d00"
            "020101003300260024001d0020358072"
            "d6365880d1aeea329adf9121383851ed"
            "21a28e3b75e965d0d2cd166254"
        );
        let got = ClientHello::try_parse_all(data).unwrap();
        println!("{got:#?}");

        let mut out = [0; 1 << 16];
        let want = HelloBuilder::new()
            .with_supported_versions(&[ProtocolVersion::Tls13])
            // .with_extension(Extension::SupportedVersions(SupportedVersionsList {
            //     data: todo!(),
            // }))
            .build(&mut out)
            .unwrap();

        let want = ClientHello {
            random: hex!(
                "000102030405060708090a0b0c0d0e0f"
                "101112131415161718191a1b1c1d1e1f"
            ),
            legacy_session_id: &[0],
            suites: Iter::empty(),
            // suites: Iter::new(&[
            //     CipherSuite::TlsAes128GcmSha256,
            //     CipherSuite::TlsAes256GcmSha384,
            // ]),
            extensions: ExtensionList::empty(),
        };
        assert_eq!(got, want);
    }
}
