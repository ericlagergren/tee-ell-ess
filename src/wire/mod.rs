//! TLS  wire format.

pub mod alert;
pub mod alpn;
mod encode;
mod error;
mod ext;
mod macros;
mod parse;
mod size;
pub mod sni;
pub mod tls13;
mod types;
pub mod vec;

pub(crate) use crate::wire::{
    encode::{EncBuf, TryEncode},
    parse::TryParse,
    size::{Object, Size},
};
pub use crate::wire::{
    error::{Error, Result},
    ext::{Extension, ExtensionType, MaxFragmentLength},
    types::uint24,
};
use crate::wire::{
    macros::{define_scalar_enum, define_struct},
    types::uint16,
};

define_struct! {
    pub struct {
        ContentType type_;
        ProtocolVersion legacy_record_version;
        uint16 length;
        // We have to parse a TLS record in two steps, so exclude
        // the fragment from the definition here.
        //
        // opaque fragment[TLSPlaintext.length];
    } TLSPlaintext;
}

define_scalar_enum! {
    /// The TLS protocol version per [RFC 8446].
    ///
    /// [RFC 8446]: https://datatracker.ietf.org/doc/html/rfc8446#section-4.1.2
    #[repr(u16)]
    #[strict(protocol_version("invalid protocol version"))]
    pub enum ProtocolVersion {
        /// TLS v1.0.
        Tls10 = 0x0301,
        /// TLS v1.1.
        Tls11 = 0x0302,
        /// TLS v1.2.
        Tls12 = 0x0303,
        /// TLS v1.3.
        Tls13 = 0x0304,
    }
}

define_scalar_enum! {
    /// Identifies the content in a TLS record.
    #[repr(u8)]
    #[strict(unexpected_message("unknown content type"))]
    pub enum ContentType {
        Invalid = 0,
        ChangeCipherSpec = 20,
        Alert = 21,
        Handshake = 22,
        ApplicationData = 23,
        Heartbeat = 24,
    }
}

define_scalar_enum! {
    /// Handshake type.
    #[repr(u8)]
    #[strict(decode_error("unexpected handshake type"))]
    pub enum HandshakeType {
        ClientHello = 1,
        ServerHello = 2,
        NewSessionTicket = 4,
        EndOfEarlyData = 5,
        EncryptedExtensions = 8,
        Certificate = 11,
        CertificateRequest = 13,
        CertificateVerify = 15,
        Finished = 20,
        KeyUpdate = 24,
        MessageHash = 254,
    }
}

define_struct! {
    #[derive(Debug)]
    pub struct {
        HandshakeType msg_type;
        uint24 length;
        // Excluding the message itself.
    } HandshakeHeader;
}

#[cfg(test)]
mod tests {
    use hex_literal::hex;

    use super::*;
    use crate::wire::tls13;

    #[test]
    fn test_client_hello() {
        let data = hex!(
            "16030100f8010000f40303000102030405060708090a0b0c0d"
            "0e0f101112131415161718191a1b1c1d1e1f20e0e1e2e3e4e5"
            "e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfe"
            "ff000813021303130100ff010000a300000018001600001365"
            "78616d706c652e756c666865696d2e6e6574000b0004030001"
            "02000a00160014001d0017001e001900180100010101020103"
            "0104002300000016000000170000000d001e001c0403050306"
            "03080708080809080a080b080408050806040105010601002b"
            "0003020304002d00020101003300260024001d0020358072d6"
            "365880d1aeea329adf9121383851ed21a28e3b75e965d0d2cd"
            "166254"
        );
        let (record, rest) = Record::try_parse(&data).unwrap();
        assert!(rest.is_empty());

        let (hs, rest) = tls13::Handshake::try_parse(record.data()).unwrap();
        assert!(rest.is_empty());
        println!("hs = {hs:#?}");

        assert!(false);
    }
}
