use crate::wire::{
    macros::{define_scalar_enum, define_struct},
    types::opaque,
    Error, TryParse,
};

define_struct! {
    /// An extension.
    #[derive(Debug)]
    #[cfg_attr(test, derive(Eq, PartialEq))]
    pub struct {
        ExtensionType extension_type;
        opaque extension_data<0..2^16-1>;
    } Extension<'a>;
}

impl Extension<'_> {
    /// Returns the extension type.
    #[inline]
    pub const fn ty(&self) -> ExtensionType {
        self.extension_type
    }

    /// Returns the opaque extension data.
    ///
    /// Note that this does not include the vector length.
    #[inline]
    pub const fn data(&self) -> &[u8] {
        self.extension_data.as_slice()
    }
}

impl<'a> Extension<'a> {
    #[inline]
    pub(crate) fn try_parse_data<T>(&self) -> Result<T, Error>
    where
        T: TryParse<'a>,
    {
        T::try_parse_all(self.extension_data.into_slice())
    }

    // #[inline]
    // pub(crate) fn try_encode_data<'b, T>(dst: &'b mut [u8], data: &T) -> Result<&'b mut [u8], Error>
    // where
    //     T: TryEncode,
    // {
    //     const MIN: usize = Extension {
    //         extension_type: ExtensionType::ServerName,
    //         extension_data: Vector::empty(),
    //     }
    //     .extension_data
    //     .min_size();
    //     const MAX: usize = Extension {
    //         extension_type: ExtensionType::ServerName,
    //         extension_data: Vector::empty(),
    //     }
    //     .extension_data
    //     .max_size();

    //     todo!()
    // }
}

define_scalar_enum! {
    /// TLS extension types.
    #[repr(u16)]
    pub enum ExtensionType {
        #[doc(alias = "server_name")]
        ServerName = 0,
        #[doc(alias = "max_fragment_length")]
        MaxFragmentLength = 1,
        #[doc(alias = "status_request")]
        StatusRequest = 5,
        #[doc(alias = "supported_groups")]
        #[doc(alias = "elliptic_curves")]
        SupportedGroups = 10,
        #[doc(alias = "signature_algorithms")]
        SignatureAlgorithms = 13,
        #[doc(alias = "use_srtp")]
        UseSrtp = 14,
        #[doc(alias = "heartbeat")]
        Heartbeat = 15,
        #[doc(alias = "application_layer_protocol_negotiation")]
        Alpn = 16,
        #[doc(alias = "signed_certificate_timestamp")]
        Sct = 18,
        #[doc(alias = "client_certificate_type")]
        ClientCertificateType = 19,
        #[doc(alias = "server_certificate_type")]
        ServerCertificateType = 20,
        #[doc(alias = "padding")]
        Padding = 21,
        #[doc(alias = "pre_shared_key")]
        PreSharedKey = 41,
        #[doc(alias = "early_data")]
        EarlyData = 42,
        #[doc(alias = "supported_versions")]
        SupportedVersions = 43,
        #[doc(alias = "cookie")]
        Cookie = 44,
        #[doc(alias = "psk_key_exchange_modes")]
        PskKexModes = 45,
        #[doc(alias = "certificate_authorities")]
        CertificateAuthorities = 47,
        #[doc(alias = "oid_filters")]
        OidFilters = 48,
        #[doc(alias = "post_handshake_auth")]
        PostHandshakeAuth = 49,
        #[doc(alias = "signature_algorithms_cert")]
        SignatureAlgorithmsCert = 50,
        #[doc(alias = "key_share")]
        KeyShare = 51,
    }
}

define_scalar_enum! {
    /// The `max_fragment_length` extension per [RFC 6066].
    ///
    /// [RFC 6066]: https://datatracker.ietf.org/doc/html/rfc6066#autoid-4
    #[repr(u8)]
    #[strict(illegal_parameter("invalid max fragment length"))]
    pub enum MaxFragmentLength {
        _512 = 1,
        _1024 = 2,
        _2048 = 3,
        _4096 = 4,
    }
}

impl MaxFragmentLength {
    /// Returns the maximum fragment length.
    pub const fn length(self) -> usize {
        match self {
            Self::_512 => 1 << 9,
            Self::_1024 => 1 << 10,
            Self::_2048 => 1 << 11,
            Self::_4096 => 1 << 12,
        }
    }
}
