//! TLS extensions.

pub mod psk;
pub mod sni;

use core::ops::BitOrAssign;

use crate::wire::ExtensionType;

bitflags::bitflags! {
    /// Bitmask for all supported extenions.
    #[allow(missing_docs)]
    #[derive(Copy, Clone, Debug, Eq, PartialEq)]
    pub struct ExtMask: u64 {
        /// The extension can appear in `ClientHello`.
        const CH = 1 << 0;
        /// The extension can appear in `ServerHello`.
        const SH = 1 << 1;
        /// The extension can appear in `EncryptedExtensions`.
        const EE = 1 << 2;
        /// The extension can appear in `Certificate`.
        const CT = 1 << 3;
        /// The extension can appear in `CertificateRequest`.
        const CR = 1 << 4;
        /// The extension can appear in `CertificateVerify`.
        const NST = 1 << 5;
        /// The extension can appear in `HelloRetryRequest`.
        const HRR = 1 << 6;

        const SERVER_NAME = 1 << 7 | CH | EE;
        const MAX_FRAGMENT_LENGTH = 1 << 8 | CH | EE;
        const STATUS_REQUEST = 1 << 9 | CH | CR | CT;
        const SUPPORTED_GROUPS = 1 << 10 | CH | EE;
        const SIGNATURE_ALGORITHMS = 1 << 11 | CH | CR;
        const USE_SRTP = 1 << 12 | CH | EE;
        const HEARTBEAT = 1 << 13 | CH | EE;
        const ALPN = 1 << 14 | CH | EE;
        const SCT = 1 << 15 | CH | CR | CT;
        const CLIENT_CERTIFICATE_TYPE = 1 << 16 | CH | EE;
        const SERVER_CERTIFICATE_TYPE = 1 << 17 | CH | EE;
        const PADDING = 1 << 18 | CH;
        const KEY_SHARE = 1 << 19 | CH | SH | HRR;
        const PRE_SHARED_KEY = 1 << 20| CH | SH;
        const PSK_KEX_MODES = 1 << 21 | CH;
        const EARLY_DATA = 1 << 22 | CH | EE | NST;
        const SUPPORTED_VERSIONS = 1 << 23 | CH | SH | HRR;
        const COOKIE = 1 << 24 | CH | HRR;
        const CERTIFICATE_AUTHORITIES = 1 << 25 | CH | CR;
        const OID_FILTERS = 1 << 26 | CR;
        const POST_HANDSHAKE_AUTH = 1 << 27 | CH;
        const SIGNATURE_ALGORITHMS_CERT = 1 << 28 | CH | CR;
    }
}

impl BitOrAssign<ExtensionType> for ExtMask {
    #[inline]
    fn bitor_assign(&mut self, rhs: ExtensionType) {
        *self |= rhs.flag();
    }
}

impl ExtensionType {
    pub(crate) const fn flag(self) -> ExtMask {
        use ExtensionType::*;

        match self {
            ServerName => ExtMask::SERVER_NAME,
            MaxFragmentLength => ExtMask::MAX_FRAGMENT_LENGTH,
            StatusRequest => ExtMask::STATUS_REQUEST,
            SupportedGroups => ExtMask::SUPPORTED_GROUPS,
            SignatureAlgorithms => ExtMask::SIGNATURE_ALGORITHMS,
            UseSrtp => ExtMask::USE_SRTP,
            Heartbeat => ExtMask::HEARTBEAT,
            Alpn => ExtMask::ALPN,
            Sct => ExtMask::SCT,
            ClientCertificateType => ExtMask::CLIENT_CERTIFICATE_TYPE,
            ServerCertificateType => ExtMask::SERVER_CERTIFICATE_TYPE,
            Padding => ExtMask::PADDING,
            PreSharedKey => ExtMask::PRE_SHARED_KEY,
            EarlyData => ExtMask::EARLY_DATA,
            SupportedVersions => ExtMask::SUPPORTED_VERSIONS,
            Cookie => ExtMask::COOKIE,
            PskKexModes => ExtMask::PSK_KEX_MODES,
            CertificateAuthorities => ExtMask::CERTIFICATE_AUTHORITIES,
            OidFilters => ExtMask::OID_FILTERS,
            PostHandshakeAuth => ExtMask::POST_HANDSHAKE_AUTH,
            SignatureAlgorithmsCert => ExtMask::SIGNATURE_ALGORITHMS_CERT,
            KeyShare => ExtMask::KEY_SHARE,
            Unknown(_) => ExtMask::empty(),
        }
    }
}

const CH: u64 = ExtMask::CH.bits();
const SH: u64 = ExtMask::SH.bits();
const EE: u64 = ExtMask::EE.bits();
const CT: u64 = ExtMask::CT.bits();
const CR: u64 = ExtMask::CR.bits();
const NST: u64 = ExtMask::NST.bits();
const HRR: u64 = ExtMask::HRR.bits();
