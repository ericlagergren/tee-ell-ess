use core::fmt;

use crate::{
    wire::{
        self,
        alpn::Alpn,
        tls13::{
            self,
            ext::{Cookie, KeyShareServerHello, NamedGroupList, OfferedPsksList, PskKexModesList},
        },
        vec::Iter,
        EncBuf, Error, ExtensionType, Object, ProtocolVersion, Size, TryEncode, TryParse,
    },
    MaxFragmentLength,
};

pub(crate) type ServerHello = tls13::ServerHello;

/// TLS extensions.
#[derive(Clone)]
pub struct ServerHelloExtensions<'a> {
    list: Iter<'a, Extension<'a>>,

    alpn: Option<Alpn<'a>>,
    cookie: Option<Cookie<'a>>,
    early_data: bool,
    key_share: Option<KeyShareServerHello<'a>>,
    max_fragment_length: Option<wire::MaxFragmentLength>,
    pre_shared_key: Option<OfferedPsksList<'a>>,
    server_name: bool,
    selected_version: Option<ProtocolVersion>,
}

impl<'a> ServerHelloExtensions<'a> {
    const fn empty() -> Self {
        Self {
            list: Iter::empty(),
            alpn: None,
            cookie: None,
            early_data: false,
            key_share: None,
            max_fragment_length: None,
            pre_shared_key: None,
            server_name: false,
            selected_version: None,
        }
    }

    fn new(list: Iter<'a, Extension<'a>>) -> Result<Self, Error> {
        let mut exts = Self::empty();
        exts.list = list.clone();

        use Extension::*;
        for ext in list {
            match ext {
                Alpn(alpn) => exts.alpn = Some(alpn),
                Cookie(cookie) => exts.cookie = Some(cookie),
                EarlyData => exts.early_data = true,
                KeyShare(ks) => exts.key_share = Some(ks),
                MaxFragmentLength(len) => exts.max_fragment_length = Some(len),
                PreSharedKey(psk) => exts.pre_shared_key = Some(psk),
                ServerName => exts.server_name = true,
                SupportedVersions(vers) => exts.selected_version = Some(vers.into()),
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
    pub const fn key_share(&self) -> Option<KeyShareServerHello<'a>> {
        self.key_share
    }

    /// Returns the `pre_shared_key` extension, if present.
    #[inline]
    pub const fn pre_shared_key(&self) -> Option<OfferedPsksList<'a>> {
        self.pre_shared_key
    }

    /// Returns the `server_name` extension, if present.
    #[inline]
    pub const fn server_name(&self) -> bool {
        self.server_name
    }

    /// Returns the `supported_versions` extension, if present.
    #[inline]
    pub const fn selected_version(&self) -> Option<ProtocolVersion> {
        self.selected_version
    }
}

impl<'a> IntoIterator for &'a ServerHelloExtensions<'a> {
    type Item = Extension<'a>;
    type IntoIter = Iter<'a, Extension<'a>>;

    #[inline]
    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

impl Object for ServerHelloExtensions<'_> {
    const SIZE: Size = tls13::ServerHelloExtensions::SIZE;
}

impl<'de> TryParse<'de> for ServerHelloExtensions<'de> {
    #[inline]
    fn try_parse(data: &'de [u8]) -> Result<(Self, &'de [u8]), Error> {
        let (list, rest) = tls13::ServerHelloExtensions::try_parse(data)?;
        let exts = Self::new(list.map().into_iter())?;
        Ok((exts, rest))
    }
}

impl fmt::Debug for ServerHelloExtensions<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_list().entries(self.iter()).finish()
    }
}

/// An extension found in a `ServerHello`.
#[derive(Copy, Clone, Debug)]
#[cfg_attr(test, derive(Eq, PartialEq))]
pub enum Extension<'a> {
    /// The `server_name` extension.
    ServerName,
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
    /// The `supported_versions` in a `ServerHello`.
    SupportedVersions(ProtocolVersion),
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
    KeyShare(KeyShareServerHello<'a>),
    /// An unknown extension.
    Unknown(wire::Extension<'a>),
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

        let ext = match ext.ty() {
            ServerName => Self::ServerName,
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
