//! TLS alerts.

use core::fmt;

use crate::wire::parse::ParseError;

/// A TLS alert.
#[derive(Copy, Clone, Debug, Eq, PartialEq, thiserror::Error)]
#[error("alert: {level} {desc}")]
pub struct Alert {
    level: AlertLevel,
    desc: AlertDesc,
}

impl Alert {
    /// Creates an `Alert`.
    pub const fn new(desc: AlertDesc) -> Self {
        use AlertDesc::*;
        match desc {
            CloseNotify | UserCanceled => Self {
                level: AlertLevel::Warning,
                desc,
            },
            _ => Self {
                level: AlertLevel::Fatal,
                desc,
            },
        }
    }

    pub(crate) const fn decode_error() -> Self {
        Self::new(AlertDesc::DecodeDrror)
    }

    pub(crate) fn try_parse(data: &[u8]) -> Result<(Self, &[u8]), ParseError> {
        let (level, rest) = AlertLevel::try_parse(data)?;
        let (desc, rest) = AlertDesc::try_parse(rest)?;
        Ok((Self { level, desc }, rest))
    }
}

/// TLS alert level.
#[repr(u8)]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[allow(missing_docs)] // TODO
pub enum AlertLevel {
    Warning = 1,
    Fatal = 2,
    Unknown(u8) = 255,
}

impl AlertLevel {
    pub(crate) fn try_parse(data: &[u8]) -> Result<(Self, &[u8]), ParseError> {
        use AlertLevel::*;

        let (v, rest) = data.split_first().ok_or(ParseError::unexpected_eof())?;
        let level = match v {
            1 => Warning,
            2 => Fatal,
            level => Unknown(*level),
        };
        Ok((level, rest))
    }
}

impl fmt::Display for AlertLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use AlertLevel::*;

        match self {
            Warning => write!(f, "warning"),
            Fatal => write!(f, "fatal"),
            Unknown(v) => write!(f, "AlertLevel({v:#02x})"),
        }
    }
}

#[repr(u8)]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[allow(missing_docs)]
pub enum AlertDesc {
    CloseNotify = 0,
    UnexpectedMessage = 10,
    BadRecordMac = 20,
    DecryptionFailed = 21, // reserved
    RecordOverflow = 22,
    DecompressionFailure = 30, // reserved
    HandshakeFailure = 40,
    BadCertificate = 42,
    UnsupportedCertificate = 43,
    CertificateRevoked = 44,
    CertificateExpired = 45,
    CertificateUnknown = 46,
    IllegalParameter = 47,
    UnknownCA = 48,
    AccessDenied = 49,
    DecodeDrror = 50,
    DecryptError = 51,
    ExportRestriction = 60, // reserved
    ProtocolVersion = 70,
    InsufficientSecurity = 71,
    InternalError = 80,
    InappropriateFallback = 86,
    UserCanceled = 90,
    MissingExtension = 109,
    UnsupportedExtension = 110,
    CertificateUnobtainable = 111, // reserved
    UnrecognizedName = 112,
    BadCertificateStatusResponse = 113,
    BadCertificateHashValue = 114, // reserved
    UnknownPskIdentity = 115,
    CertificateRequired = 116,
    NoApplicationProtocol = 120,
    Unknown(u8) = 255,
}

impl AlertDesc {
    pub(crate) fn try_parse(data: &[u8]) -> Result<(Self, &[u8]), ParseError> {
        use AlertDesc::*;

        let (v, rest) = data.split_first().ok_or(ParseError::unexpected_eof())?;
        let desc = match v {
            10 => UnexpectedMessage,
            20 => BadRecordMac,
            21 => DecryptionFailed,
            22 => RecordOverflow,
            30 => DecompressionFailure,
            40 => HandshakeFailure,
            42 => BadCertificate,
            43 => UnsupportedCertificate,
            44 => CertificateRevoked,
            45 => CertificateExpired,
            46 => CertificateUnknown,
            47 => IllegalParameter,
            48 => UnknownCA,
            49 => AccessDenied,
            50 => DecodeDrror,
            51 => DecryptError,
            60 => ExportRestriction,
            70 => ProtocolVersion,
            71 => InsufficientSecurity,
            80 => InternalError,
            86 => InappropriateFallback,
            90 => UserCanceled,
            109 => MissingExtension,
            110 => UnsupportedExtension,
            111 => CertificateUnobtainable,
            112 => UnrecognizedName,
            113 => BadCertificateStatusResponse,
            114 => BadCertificateHashValue, // reserved
            115 => UnknownPskIdentity,
            116 => CertificateRequired,
            120 => NoApplicationProtocol,
            desc => Unknown(*desc),
        };
        Ok((desc, rest))
    }
}

impl fmt::Display for AlertDesc {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use AlertDesc::*;

        match self {
            CloseNotify => write!(f, "close notify"),
            UnexpectedMessage => write!(f, "unexpected message"),
            BadRecordMac => write!(f, "bad record mac"),
            DecryptionFailed => write!(f, "decryption failed"),
            RecordOverflow => write!(f, "record overflow"),
            DecompressionFailure => write!(f, "decompression failure"),
            HandshakeFailure => write!(f, "handshake failure"),
            BadCertificate => write!(f, "bad certificate"),
            UnsupportedCertificate => write!(f, "unsupported certificate"),
            CertificateRevoked => write!(f, "certificate revoked"),
            CertificateExpired => write!(f, "certificate expired"),
            CertificateUnknown => write!(f, "certificate unknown"),
            IllegalParameter => write!(f, "illegal parameter"),
            UnknownCA => write!(f, "unknown ca"),
            AccessDenied => write!(f, "access denied"),
            DecodeDrror => write!(f, "decode error"),
            DecryptError => write!(f, "decrypt error"),
            ExportRestriction => write!(f, "export restriction"),
            ProtocolVersion => write!(f, "protocol version"),
            InsufficientSecurity => write!(f, "insufficient security"),
            InternalError => write!(f, "internal error"),
            InappropriateFallback => write!(f, "inappropriate fallback"),
            UserCanceled => write!(f, "user canceled"),
            MissingExtension => write!(f, "missing extension"),
            UnsupportedExtension => write!(f, "unsupported extension"),
            CertificateUnobtainable => write!(f, "certificate unobtainable"),
            UnrecognizedName => write!(f, "unrecognized name"),
            BadCertificateStatusResponse => write!(f, "bad certificate status response"),
            BadCertificateHashValue => write!(f, "bad certificate hash value"), // reserved
            UnknownPskIdentity => write!(f, "unknown psk identity"),
            CertificateRequired => write!(f, "certificate required"),
            NoApplicationProtocol => write!(f, "no application protocol"),
            Unknown(v) => write!(f, "AlertDesc({v:#02x})"),
        }
    }
}
