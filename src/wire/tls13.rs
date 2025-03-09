//! TODO

use core::fmt;

use crate::wire::{
    client::tls13::{ClientHello, SupportedVersions},
    parse::{u24, ParseError, TryParse, Vector},
};

/// A TLS record.
#[derive(Copy, Clone, Debug)]
pub struct Record<'a> {
    ct: ContentType,
    version: ProtocolVersion,
    length: usize,
    data: Vector<'a, 0, { 1 << 14 }>,
}

impl Record<'_> {
    /// TODO
    #[inline]
    pub const fn content_type(&self) -> ContentType {
        self.ct
    }

    /// TODO
    #[inline]
    pub const fn version(&self) -> ProtocolVersion {
        self.version
    }

    /// TODO
    #[inline]
    pub const fn length(&self) -> usize {
        self.length
    }

    /// TODO
    #[inline]
    pub const fn data(&self) -> &[u8] {
        self.data.as_slice()
    }
}

impl<'a> TryParse<'a> for Record<'a> {
    #[inline]
    fn try_parse(data: &'a [u8]) -> Result<(Self, &'a [u8]), ParseError> {
        // struct {
        //     ContentType type;
        //     ProtocolVersion version;
        //     uint16 length;
        //     opaque fragment[TLSPlaintext.length];
        // } TLSPlaintext;
        let (ct, rest) = ContentType::try_parse(data)?;
        let (version, rest) = ProtocolVersion::try_parse(rest)?;
        let (length, rest) = {
            let (length, rest) = u16::try_parse(rest)?;
            if length > 1 << 14 {
                return Err(ParseError::from("length not in [0, 2^14]"));
            }
            (usize::from(length), rest)
        };
        let (data, rest) = Vector::try_parse(rest)?;
        let record = Self {
            ct,
            version,
            length,
            data,
        };
        Ok((record, rest))
    }
}

/// The TLS protocol version per [RFC 8446].
///
/// ```text
/// uint16 ProtocolVersion;
/// ```
///
/// [RFC 8446]: https://datatracker.ietf.org/doc/html/rfc8446#section-4.1.2
#[repr(u16)]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum ProtocolVersion {
    /// TLS v1.0.
    Tls10 = 0x0301,
    /// TLS v1.1.
    Tls11 = 0x0302,
    /// TLS v1.2.
    Tls12 = 0x0303,
    /// TLS v1.3.
    Tls13 = 0x0304,
    /// Unknown.
    Unknown(u16) = 0xffff,
}

impl TryParse<'_> for ProtocolVersion {
    #[inline]
    fn try_parse(data: &[u8]) -> Result<(Self, &[u8]), ParseError> {
        use ProtocolVersion::*;

        let ([lo, hi], rest) = data
            .split_first_chunk()
            .ok_or(ParseError::unexpected_eof())?;
        let version = match u16::from_be_bytes([*lo, *hi]) {
            0x0304 => Self::Tls13,
            0x0303 => Self::Tls12,
            0x0302 => Self::Tls11,
            0x0301 => Self::Tls10,
            v => Unknown(v),
        };
        Ok((version, rest))
    }
}

impl fmt::Display for ProtocolVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use ProtocolVersion::*;
        match self {
            Tls10 => write!(f, "TLS 1.0"),
            Tls11 => write!(f, "TLS 1.1"),
            Tls12 => write!(f, "TLS 1.2"),
            Tls13 => write!(f, "TLS 1.3"),
            Unknown(v) => write!(f, "unknown {v:#x}"),
        }
    }
}

/// Record content type.
#[repr(u8)]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[allow(missing_docs)] // TODO
pub enum ContentType {
    Invalid = 0,
    ChangeCipherSpec = 20,
    Alert = 21,
    Handshake = 22,
    ApplicationData = 23,
    Heartbeat = 24,
    Unknown(u8) = 255,
}

impl TryParse<'_> for ContentType {
    #[inline]
    fn try_parse(data: &[u8]) -> Result<(Self, &[u8]), ParseError> {
        use ContentType::*;

        let (v, rest) = data.split_first().ok_or(ParseError::unexpected_eof())?;
        let ct = match v {
            20 => ChangeCipherSpec,
            21 => Alert,
            22 => Handshake,
            23 => ApplicationData,
            24 => Heartbeat,
            v => Unknown(*v),
        };
        Ok((ct, rest))
    }
}

impl fmt::Display for ContentType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use ContentType::*;

        match self {
            Invalid => write!(f, "Invalid"),
            ChangeCipherSpec => write!(f, "ChangeCipherSpec"),
            Alert => write!(f, "Alert"),
            Handshake => write!(f, "Handshake"),
            ApplicationData => write!(f, "ApplicationData"),
            Heartbeat => write!(f, "Heartbeat"),
            Unknown(v) => write!(f, "ContentType({v:#02x})"),
        }
    }
}

/// Handshake type.
#[repr(u8)]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[allow(missing_docs)] // TODO
pub enum HandshakeType {
    HelloRequest = 0, // reserved
    ClientHello = 1,
    ServerHello = 2,
    HelloVerifyRequest = 3, // reserved
    NewSessionTicket = 4,
    EndOfEarlyData = 5,
    HelloRetryRequest = 6, // reserved
    EncryptedExtensions = 8,
    Certificate = 11,
    ServerKeyExchange = 12, // reserved
    CertificateRequest = 13,
    ServerHelloDone = 14, // reserved
    CertificateVerify = 15,
    ClientKeyExchange = 16, // reserved
    Finished = 20,
    CertificateUrl = 21,    // reserved
    CertificateStatus = 22, // reserved
    SupplementalData = 23,  // reserved
    KeyUpdate = 24,
    MessageHash = 254,
    Unknown(u8) = 255,
}

impl TryParse<'_> for HandshakeType {
    #[inline]
    fn try_parse(data: &[u8]) -> Result<(Self, &[u8]), ParseError> {
        use HandshakeType::*;

        let (v, rest) = data.split_first().ok_or(ParseError::unexpected_eof())?;
        let ty = match v {
            0 => HelloRequest,
            1 => ClientHello,
            2 => ServerHello,
            3 => HelloVerifyRequest,
            4 => NewSessionTicket,
            5 => EndOfEarlyData,
            6 => HelloRetryRequest,
            8 => EncryptedExtensions,
            11 => Certificate,
            12 => ServerKeyExchange,
            13 => CertificateRequest,
            14 => ServerHelloDone,
            15 => CertificateVerify,
            16 => ClientKeyExchange,
            20 => Finished,
            21 => CertificateUrl,
            22 => CertificateStatus,
            23 => SupplementalData,
            24 => KeyUpdate,
            254 => MessageHash,
            v => Unknown(*v),
        };
        Ok((ty, rest))
    }
}

impl fmt::Display for HandshakeType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use HandshakeType::*;

        match self {
            HelloRequest => write!(f, "HelloRequest"),
            ClientHello => write!(f, "ClientHello"),
            ServerHello => write!(f, "ServerHello"),
            HelloVerifyRequest => write!(f, "HelloVerifyRequest"),
            NewSessionTicket => write!(f, "NewSessionTicket"),
            EndOfEarlyData => write!(f, "EndOfEarlyData"),
            HelloRetryRequest => write!(f, "HelloRetryRequest"),
            EncryptedExtensions => write!(f, "EncryptedExtensions"),
            Certificate => write!(f, "Certificate"),
            ServerKeyExchange => write!(f, "ServerKeyExchange"),
            CertificateRequest => write!(f, "CertificateRequest"),
            ServerHelloDone => write!(f, "ServerHelloDone"),
            CertificateVerify => write!(f, "CertificateVerify"),
            ClientKeyExchange => write!(f, "ClientKeyExchange"),
            Finished => write!(f, "Finished"),
            CertificateUrl => write!(f, "CertificateUrl"),
            CertificateStatus => write!(f, "CertificateStatus"),
            SupplementalData => write!(f, "SupplementalData"),
            KeyUpdate => write!(f, "KeyUpdate"),
            MessageHash => write!(f, "MessageHash"),
            Unknown(v) => write!(f, "HandshakeType({v:#02x})"),
        }
    }
}

#[repr(u8)]
#[derive(Copy, Clone, Debug)]
#[allow(missing_docs)] // TODO
pub enum Handshake<'a> {
    ClientHello(ClientHello<'a>),
    ServerHello,
    EncryptedExtensions,
    Certificate,
    CertificateRequest,
    Finished,
}

impl<'a> TryParse<'a> for Handshake<'a> {
    #[inline]
    fn try_parse(data: &'a [u8]) -> Result<(Self, &'a [u8]), ParseError> {
        // struct {
        //     HandshakeType msg_type;    /* handshake type */
        //     uint24 length;             /* bytes in message */
        //     select (Handshake.msg_type) {
        //         case client_hello:          ClientHello;
        //         case server_hello:          ServerHello;
        //         case end_of_early_data:     EndOfEarlyData;
        //         case encrypted_extensions:  EncryptedExtensions;
        //         case certificate_request:   CertificateRequest;
        //         case certificate:           Certificate;
        //         case certificate_verify:    CertificateVerify;
        //         case finished:              Finished;
        //         case new_session_ticket:    NewSessionTicket;
        //         case key_update:            KeyUpdate;
        //     };
        // } Handshake;

        let (ty, rest) = HandshakeType::try_parse(data)?;
        let (length, rest) = u24::try_parse(rest)?;
        let (data, rest) = rest
            .split_at_checked(length)
            .ok_or(ParseError::unexpected_eof())?;
        let (handshake, rest) = match ty {
            HandshakeType::ClientHello => {
                ClientHello::try_parse(data).map(|(v, rest)| (Self::ClientHello(v), rest))?
            }
            HandshakeType::ServerHello => (Self::ServerHello, rest),
            HandshakeType::EncryptedExtensions => (Self::EncryptedExtensions, rest),
            HandshakeType::Certificate => (Self::Certificate, rest),
            HandshakeType::CertificateRequest => (Self::CertificateRequest, rest),
            HandshakeType::Finished => (Self::Finished, rest),
            _ => return Err(ParseError::from("unexpected handshake type")),
        };
        Ok((handshake, rest))
    }
}

/// TODO
#[derive(Copy, Clone, Debug)]
#[allow(missing_docs)] // TODO
pub enum Extension2<'a> {
    ServerName,                               /* RFC 6066 */
    MaxFragmentLength,                        /* RFC 6066 */
    StatusRequest,                            /* RFC 6066 */
    SupportedGroups,                          /* RFC 8422, 7919 */
    SignatureAlgorithms,                      /* RFC 8446 */
    UseSrtp,                                  /* RFC 5764 */
    Heartbeat,                                /* RFC 6520 */
    Alpn,                                     /* RFC 7301 */
    Sct,                                      /* RFC 6962 */
    ClientCertificateType,                    /* RFC 7250 */
    ServerCertificateType,                    /* RFC 7250 */
    Padding,                                  /* RFC 7685 */
    PreSharedKey,                             /* RFC 8446 */
    EarlyData,                                /* RFC 8446 */
    SupportedVersions(SupportedVersions<'a>), /* RFC 8446 */
    SupportedVersion(ProtocolVersion),        /* RFC 8446 */
    Cookie,                                   /* RFC 8446 */
    PskKexModes,                              /* RFC 8446 */
    CertificateAuthorities,                   /* RFC 8446 */
    OidFilters,                               /* RFC 8446 */
    PostHandshakeAuth,                        /* RFC 8446 */
    SignatureAlgorithmsCert,                  /* RFC 8446 */
    KeyShare,                                 /* RFC 8446 */
    Unknown(u16),
}

impl<'a> Extension2<'a> {
    #[inline]
    pub(crate) fn try_parse_client(data: &'a [u8]) -> Result<(Self, &'a [u8]), ParseError> {
        let (v, rest) = data
            .split_first_chunk()
            .ok_or(ParseError::unexpected_eof())?;
        let ty = match u16::from_be_bytes(*v) {
            0 => Self::ServerName,
            1 => Self::MaxFragmentLength,
            5 => Self::StatusRequest,
            10 => Self::SupportedGroups,
            13 => Self::SignatureAlgorithms,
            14 => Self::UseSrtp,
            15 => Self::Heartbeat,
            16 => Self::Alpn,
            18 => Self::Sct,
            19 => Self::ClientCertificateType,
            20 => Self::ServerCertificateType,
            21 => Self::Padding,
            41 => Self::PreSharedKey,
            42 => Self::EarlyData,
            43 => Self::SupportedVersions(SupportedVersions::try_parse(rest)?.0),
            44 => Self::Cookie,
            45 => Self::PskKexModes,
            47 => Self::CertificateAuthorities,
            48 => Self::OidFilters,
            49 => Self::PostHandshakeAuth,
            50 => Self::SignatureAlgorithmsCert,
            51 => Self::KeyShare,
            v => Self::Unknown(v),
        };
        Ok((ty, rest))
    }

    #[inline]
    fn try_parse_server(data: &'a [u8]) -> Result<(Self, &'a [u8]), ParseError> {
        let (v, rest) = data
            .split_first_chunk()
            .ok_or(ParseError::unexpected_eof())?;
        let ty = match u16::from_be_bytes(*v) {
            0 => Self::ServerName,
            1 => Self::MaxFragmentLength,
            5 => Self::StatusRequest,
            10 => Self::SupportedGroups,
            13 => Self::SignatureAlgorithms,
            14 => Self::UseSrtp,
            15 => Self::Heartbeat,
            16 => Self::Alpn,
            18 => Self::Sct,
            19 => Self::ClientCertificateType,
            20 => Self::ServerCertificateType,
            21 => Self::Padding,
            41 => Self::PreSharedKey,
            42 => Self::EarlyData,
            43 => Self::SupportedVersion(ProtocolVersion::try_parse(rest)?.0),
            44 => Self::Cookie,
            45 => Self::PskKexModes,
            47 => Self::CertificateAuthorities,
            48 => Self::OidFilters,
            49 => Self::PostHandshakeAuth,
            50 => Self::SignatureAlgorithmsCert,
            51 => Self::KeyShare,
            v => Self::Unknown(v),
        };
        Ok((ty, rest))
    }
}

pub struct Alpn<'a> {
    names: Vector<'a, 0, { (1 << 16) - 1 }>,
}
type ProtocolName<'a> = Vector<'a, 0, { (1 << 8) - 1 }>;

/// TODO
#[derive(Copy, Clone, Debug)]
pub struct Extension<'a> {
    ty: ExtensionType,
    data: Vector<'a, 0, { (1 << 16) - 1 }>,
}

impl Extension<'_> {
    /// Returns the extension type.
    #[inline]
    pub fn ty(&self) -> ExtensionType {
        self.ty
    }

    /// Returns the opaque extension data.
    #[inline]
    pub fn data(&self) -> &[u8] {
        self.data.as_slice()
    }
}

impl<'a> TryParse<'a> for Extension<'a> {
    #[inline]
    fn try_parse(data: &'a [u8]) -> Result<(Self, &'a [u8]), ParseError> {
        let (ty, rest) = ExtensionType::try_parse(data)?;
        let (data, rest) = Vector::try_parse(rest)?;
        Ok((Self { ty, data }, rest))
    }
}

/// TLS extension types.
#[repr(u16)]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[allow(missing_docs)] // TODO
pub enum ExtensionType {
    ServerName = 0,               /* RFC 6066 */
    MaxFragmentLength = 1,        /* RFC 6066 */
    StatusRequest = 5,            /* RFC 6066 */
    SupportedGroups = 10,         /* RFC 8422, 7919 */
    SignatureAlgorithms = 13,     /* RFC 8446 */
    UseSrtp = 14,                 /* RFC 5764 */
    Heartbeat = 15,               /* RFC 6520 */
    Alpn = 16,                    /* RFC 7301 */
    Sct = 18,                     /* RFC 6962 */
    ClientCertificateType = 19,   /* RFC 7250 */
    ServerCertificateType = 20,   /* RFC 7250 */
    Padding = 21,                 /* RFC 7685 */
    PreSharedKey = 41,            /* RFC 8446 */
    EarlyData = 42,               /* RFC 8446 */
    SupportedVersions = 43,       /* RFC 8446 */
    Cookie = 44,                  /* RFC 8446 */
    PskKexModes = 45,             /* RFC 8446 */
    CertificateAuthorities = 47,  /* RFC 8446 */
    OidFilters = 48,              /* RFC 8446 */
    PostHandshakeAuth = 49,       /* RFC 8446 */
    SignatureAlgorithmsCert = 50, /* RFC 8446 */
    KeyShare = 51,                /* RFC 8446 */
    Unknown(u16) = 65535,
}

impl TryParse<'_> for ExtensionType {
    #[inline]
    fn try_parse(data: &[u8]) -> Result<(Self, &[u8]), ParseError> {
        use ExtensionType::*;

        let (v, rest) = data
            .split_first_chunk()
            .ok_or(ParseError::unexpected_eof())?;
        let ty = match u16::from_be_bytes(*v) {
            0 => ServerName,
            1 => MaxFragmentLength,
            5 => StatusRequest,
            10 => SupportedGroups,
            13 => SignatureAlgorithms,
            14 => UseSrtp,
            15 => Heartbeat,
            16 => Alpn,
            18 => Sct,
            19 => ClientCertificateType,
            20 => ServerCertificateType,
            21 => Padding,
            41 => PreSharedKey,
            42 => EarlyData,
            43 => SupportedVersions,
            44 => Cookie,
            45 => PskKexModes,
            47 => CertificateAuthorities,
            48 => OidFilters,
            49 => PostHandshakeAuth,
            50 => SignatureAlgorithmsCert,
            51 => KeyShare,
            v => Unknown(v),
        };
        Ok((ty, rest))
    }
}

#[cfg(test)]
mod tests {
    use hex_literal::hex;

    use super::*;

    #[test]
    fn test_client_hello() {
        let data = hex!(
            "010000c00303cb34ecb1e78163"
            "ba1c38c6dacb196a6dffa21a8d9912ec18a2ef6283"
            "024dece7000006130113031302010000910000000b"
            "0009000006736572766572ff01000100000a001400"
            "12001d001700180019010001010102010301040023"
            "0000003300260024001d002099381de560e4bd43d2"
            "3d8e435a7dbafeb3c06e51c13cae4d5413691e529a"
            "af2c002b0003020304000d0020001e040305030603"
            "020308040805080604010501060102010402050206"
            "020202002d00020101001c00024001"
        );
        let (record, rest) = Handshake::try_parse(&data).unwrap();
        println!("{record:#?}");
        assert!(rest.is_empty());
        assert!(false);
    }
}
