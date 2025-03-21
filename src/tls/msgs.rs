//! TODO

use buggy::BugExt;

use crate::wire::{
    self, ContentType, HandshakeType, Object, ProtocolVersion, Size, TLSPlaintext, TryParse,
};

// let version = match version {
//     ProtocolVersion::Tls13 => ProtocolVersion::Tls12,
//     v => v,
// };

pub(crate) struct RecordHeader {
    pub content_type: ContentType,
    pub legacy_record_version: ProtocolVersion,
    pub length: usize,
}

impl RecordHeader {
    pub(crate) const SIZE: usize = <Self as Object>::SIZE.fixed().unwrap();
}

impl Object for RecordHeader {
    const SIZE: Size = TLSPlaintext::SIZE;
}

impl<'de> TryParse<'de> for RecordHeader {
    #[inline]
    fn try_parse(data: &'de [u8]) -> wire::Result<(Self, &'de [u8])> {
        let v = TLSPlaintext::try_parse_all(data)?;

        // RFC 8446: "length: The length (in bytes) of the
        // following TLSPlaintext.fragment. The length MUST NOT
        // exceed 2^14 bytes. An endpoint that receives a record
        // that exceeds this length MUST terminate the connection
        // with a "record_overflow" alert."
        //
        // RFC 5246: "length The length (in bytes) of the
        // following TLSPlaintext.fragment. The length MUST NOT
        // exceed 2^14."
        //
        // TODO(eric): TLS 1.2 allows 2^14 + 1024 if the record
        // is compressed.
        if v.length > 1 << 14 {
            return Err(wire::Error::record_overflow("length not in [0, 2^14]").into());
        }

        let hdr = RecordHeader {
            content_type: v.type_,
            legacy_record_version: v.legacy_record_version,
            length: usize::from(v.length),
        };
        Ok((hdr, &[]))
    }
}

pub(crate) struct HandshakeHeader {
    pub msg_type: HandshakeType,
    // Is in [0, (2^24)-1].
    pub length: usize,
}

impl HandshakeHeader {
    pub(crate) const SIZE: usize = <Self as Object>::SIZE.fixed().unwrap();
}

impl Object for HandshakeHeader {
    const SIZE: Size = wire::HandshakeHeader::SIZE;
}

impl<'de> TryParse<'de> for HandshakeHeader {
    #[inline]
    fn try_parse(data: &'de [u8]) -> wire::Result<(Self, &'de [u8])> {
        let v = wire::HandshakeHeader::try_parse_all(data)?;

        // TODO(eric): This is not true on 16-bit machines.
        let length = v.length.try_into().assume("`u24` should fit in `usize`")?;
        let hdr = HandshakeHeader {
            msg_type: v.msg_type,
            length,
        };
        Ok((hdr, &[]))
    }
}
