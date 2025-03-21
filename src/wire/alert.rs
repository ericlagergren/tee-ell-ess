//! TLS alerts.

use crate::wire::{
    macros::{define_scalar_enum, define_struct},
    Object,
};

define_struct! {
    /// A TLS alert.
    #[derive(Debug, Eq, PartialEq, thiserror::Error)]
    #[error("alert: {level} {desc}")]
    pub struct {
        AlertLevel level;
        AlertDescription desc;
    } Alert;
}

type AlertDescription = AlertDesc;

impl Alert {
    pub(crate) const SIZE: usize = <Self as Object>::SIZE.fixed().unwrap();

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

    pub(crate) const fn internal_error() -> Self {
        Self::new(AlertDesc::InternalError)
    }

    pub(crate) const fn record_overflow() -> Self {
        Self::new(AlertDesc::RecordOverflow)
    }

    pub(crate) const fn protocol_version() -> Self {
        Self::new(AlertDesc::ProtocolVersion)
    }

    pub(crate) const fn illegal_parameter() -> Self {
        Self::new(AlertDesc::IllegalParameter)
    }

    pub(crate) const fn unexpected_message() -> Self {
        Self::new(AlertDesc::UnexpectedMessage)
    }

    pub(crate) const fn missing_extension() -> Self {
        Self::new(AlertDesc::MissingExtension)
    }
}

define_scalar_enum! {
    /// TLS alert level.
    #[repr(u8)]
    pub enum AlertLevel {
        Warning = 1,
        Fatal = 2,
    }
}

define_scalar_enum! {
    #[repr(u8)]
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
    }
}
