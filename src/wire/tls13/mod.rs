//! TODO

pub mod ext;

use subtle::ConstantTimeEq;

use crate::wire::{
    macros::{define_scalar_enum, define_struct, define_type_alias},
    types::{opaque, uint16, uint8},
    Extension,
};

define_type_alias! {
    pub uint16 ProtocolVersion;
}

define_type_alias! {
    pub uint8 CipherSuite[2];
}

define_type_alias! {
    pub opaque Random[32];
}

define_struct! {
    /// The `ClientHello` message per [RFC 8446].
    ///
    /// [RFC 8446]: https://datatracker.ietf.org/doc/html/rfc8446#section-4.1.2
    #[derive(Debug)]
    pub struct {
        ProtocolVersion legacy_version = 0x0303;
        Random random;
        opaque legacy_session_id<0..32>;
        CipherSuite cipher_suites<2..2^16-2>;
        opaque legacy_compression_methods<1..2^8-1> = [0];
        Extension<'a> extensions<8..2^16-1>;
    } ClientHello<'a>;
}

define_struct! {
    /// The `ServerHello` message per [RFC 8446].
    ///
    /// [RFC 8446]: https://datatracker.ietf.org/doc/html/rfc8446#section-4.14.
    #[derive(Debug)]
    pub struct {
        ProtocolVersion legacy_version = 0x0303;
        Random random;
        opaque legacy_session_id_echo<0..32>;
        CipherSuite cipher_suite;
        uint8 legacy_compression_method = 0;
        // Extensions are parsed separately.
        // Extension<'a> extensions<6..2^16-1>;
    } ServerHello;
}

impl ServerHello {
    /// Returns the cipher suite ID.
    #[inline]
    pub fn cipher_suite(&self) -> CipherSuiteId {
        self.cipher_suite.into()
    }

    /// Reports whether this is actuall a `HelloRetryRequest`.
    #[inline]
    pub fn is_hello_retry_request(&self) -> bool {
        // RFC 8446: "For reasons of backward compatibility with
        // middleboxes (see Appendix D.4), the HelloRetryRequest
        // message uses the same structure as the ServerHello,
        // but with Random set to the special value of the
        // SHA-256 of "HelloRetryRequest":
        //   CF 21 AD 74 E5 9A 61 11 BE 1D 8C 02 1E 65 B8 91
        //   C2 A2 11 16 7A BB 8C 5E 07 9E 09 E2 C8 A8 33 9C"
        const HRR_RANDOM: [u8; 32] = [
            0xCF, 0x21, 0xAD, 0x74, 0xE5, 0x9A, 0x61, 0x11, 0xBE, 0x1D, 0x8C, 0x02, 0x1E, 0x65,
            0xB8, 0x91, 0xC2, 0xA2, 0x11, 0x16, 0x7A, 0xBB, 0x8C, 0x5E, 0x07, 0x9E, 0x09, 0xE2,
            0xC8, 0xA8, 0x33, 0x9C,
        ];
        self.random.ct_eq(&HRR_RANDOM).into()
    }
}

define_type_alias! {
    pub Extension<'x> ServerHelloExtensions<6..2^16-1>;
}

define_scalar_enum! {
    /// TLS 1.3 cipher suites.
    #[repr(u16)]
    pub enum CipherSuiteId {
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
    }
}

impl From<CipherSuite> for CipherSuiteId {
    #[inline]
    fn from(suite: CipherSuite) -> Self {
        match u16::from_be_bytes(suite).try_into() {
            Ok(id) => id,
            Err(err) => match err {},
        }
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
            "010000f403030001020304"
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
        let got = Handshake::try_parse_all(data).unwrap();
        println!("{got:#?}");
        // assert!(false);
    }
}
