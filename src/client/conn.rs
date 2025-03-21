use core::ops::Deref;

use subtle::ConstantTimeEq;

use crate::{
    client::{config::ClientConfig, msgs::HelloBuilder},
    error::Error,
    io::{Read, Write},
    server::msgs::{ServerHello, ServerHelloExtensions},
    tls::{
        msgs::{HandshakeHeader, RecordHeader},
        MAX_HANDSHAKE_SIZE,
    },
    util::Buffer,
    wire::{self, alert::Alert, ContentType, HandshakeType, ProtocolVersion, TryEncode, TryParse},
    CipherSuite, Version,
};

/// A TLS connection.
pub struct Conn<'a> {
    cfg: Config<'a>,
}

impl<'a> Conn<'a> {
    /// Creates a TLS connection.
    pub fn new(cfg: &'a dyn ClientConfig) -> NeedHandshake<'a> {
        NeedHandshake {
            cfg: Config(cfg),
            send: SendBuf::new(),
            recv: RecvBuf::new(),
        }
    }
}

/// A TLS connection before the handshake has been completed.
#[derive(Debug)]
pub struct NeedHandshake<'a> {
    cfg: Config<'a>,
    send: SendBuf,
    recv: RecvBuf,
}

impl<'a> NeedHandshake<'a> {
    /// Performs the TLS handshake.
    pub async fn handshake<R, W>(self, read: &mut R, write: &mut W) -> Result<Conn<'a>, Error>
    where
        R: Read,
        W: Write,
    {
        match self.do_handshake(read, write).await {
            Ok(conn) => Ok(conn),
            Err(err) => {
                // TODO: send alert
                //self.send.send_alert(Alert::from(err)).ok();
                Err(err)
            }
        }
    }

    /// Performs the TLS handshake.
    async fn do_handshake<R, W>(mut self, read: &mut R, write: &mut W) -> Result<Conn<'a>, Error>
    where
        R: Read,
        W: Write,
    {
        let ctx = self.send_client_hello(write).await?;
        self.recv_server_hello_or_hrr(&ctx, read, write).await?;

        Ok(Conn { cfg: self.cfg })
    }

    /// Sends the `ClientHello` to the server.
    async fn send_client_hello<W: Write>(&mut self, w: &mut W) -> Result<SentClientHello, Error> {
        let mut buf = [0; MAX_HANDSHAKE_SIZE];

        let id = {
            let mut id = [0; 32];
            self.cfg.csprng().fill_bytes(&mut id);
            id
        };

        let hello = HelloBuilder::new()
            .with_alpn(self.cfg.alpn())
            .with_early_data(self.cfg.early_data())
            .with_legacy_session_id(id)
            .pipe(|b| match self.cfg.max_fragment_length() {
                Some(len) => b.with_max_fragment_length(len),
                None => b,
            })
            .build(&mut buf)?;
        w.write_all(hello).await?;

        Ok(SentClientHello { session_id: id })
    }

    /// Receives the `ServerHello` or `HelloRetryRequest` from
    /// the server.
    ///
    /// If necessary, it sends a second `ClientHello` to the
    /// server.
    async fn recv_server_hello_or_hrr<R: Read, W: Write>(
        &mut self,
        ctx: &SentClientHello,
        r: &mut R,
        w: &mut W,
    ) -> Result<(), Error> {
        let hdr = self.read_hs_msg(r).await?;
        if hdr.msg_type != HandshakeType::ServerHello {
            return Err(wire::Error::unexpected_message("expected `ServerHello`").into());
        }

        let mut hello = self.recv.read_type::<ServerHello>()?;

        // RFC 8446: "Upon receiving a message with type
        // server_hello, implementations MUST first examine the
        // Random value and, if it matches [the HRR constant],
        // process it as described in Section 4.1.4)."
        let mut hrr_vers = None;
        if hello.is_hello_retry_request() {
            // RFC 8446: "Upon receipt of a HelloRetryRequest,
            // the client MUST check the legacy_version,
            // legacy_session_id_echo, cipher_suite, and
            // legacy_compression_method as specified in Section
            // 4.1.3 and then process the extensions, starting
            // with determining the version using
            // "supported_versions"."
            self.check_server_hello(ctx, &hello)?;

            self.send_dummy_ccs(w).await?;

            let exts = self.recv.read_type::<ServerHelloExtensions<'_>>()?;

            // RFC 8446: "The server's extensions MUST contain
            // "supported_versions"."
            hrr_vers = exts.selected_version();
            if hrr_vers.is_none() {
                return Err(wire::Error::missing_extension("supported_versions").into());
            }
            self.send_client_hello(w).await?;

            let hdr = self.read_hs_msg(r).await?;
            if hdr.msg_type != HandshakeType::ServerHello {
                return Err(wire::Error::unexpected_message("expected `ServerHello`").into());
            }

            hello = self.recv.read_type()?;
            if hello.is_hello_retry_request() {
                // RFC 8446: "If a client receives a second
                // HelloRetryRequest in the same connection
                // (i.e., where the ClientHello was itself in
                // response to a HelloRetryRequest), it MUST
                // abort the handshake with an
                // "unexpected_message" alert."
                return Err(wire::Error::unexpected_message(
                    "received multiple `HelloRetryRequest`",
                )
                .into());
            }
        }
        self.check_server_hello(ctx, &hello)?;

        let exts = self.recv.read_type::<ServerHelloExtensions<'_>>()?;

        let _version = {
            // RFC 8446: "The value of selected_version in the
            // HelloRetryRequest "supported_versions" extension
            // MUST be retained in the ServerHello, and a client
            // MUST abort the handshake with an
            // "illegal_parameter" alert if the value changes."
            let version = exts.selected_version();
            if version != hrr_vers {
                return Err(wire::Error::illegal_parameter("version changed after HRR").into());
            }

            // TODO(eric): support renegotiation.
            let Some(version) = version else {
                return Err(wire::Error::missing_extension("supported_versions").into());
            };

            let version = Version::from_wire(version)
                .ok_or_else(|| wire::Error::illegal_parameter("unsupported version"))?;

            // RFC 8446: "If the "supported_versions" extension
            // in the ServerHello contains a version not offered
            // by the client or contains a version prior to TLS
            // 1.3, the client MUST abort the handshake with an
            // "illegal_parameter" alert."
            if !self.cfg.supported_versions().contains(&version) {
                return Err(
                    wire::Error::illegal_parameter("server selected unsupported version").into(),
                );
            }
            version
        };

        Ok(())
    }

    fn check_server_hello(&self, ctx: &SentClientHello, hello: &ServerHello) -> Result<(), Error> {
        // RFC 8446: "In TLS 1.3, the TLS server indicates its
        // version using the "supported_versions" extension
        // (Section 4.2.1), and the legacy_version field MUST be
        // set to 0x0303, which is the version number for TLS
        // 1.2."
        if hello.legacy_version != ProtocolVersion::Tls12.to_repr() {
            return Err(wire::Error::protocol_version("`legacy_version` must be TLS 1.2").into());
        }

        // RFC 8446: "legacy_compression_method: A single byte
        // which MUST have the value 0."
        if hello.legacy_compression_method != 0 {
            return Err(
                wire::Error::illegal_parameter("`legacy_compression_method` must be `0`").into(),
            );
        }

        // RFC 8446: "A client which receives a cipher suite that
        // was not offered MUST abort the handshake with an
        // "illegal_parameter" alert."
        if !self
            .cfg
            .cipher_suites()
            .iter()
            .filter_map(|cs| match cs {
                CipherSuite::Tls13(cs) => Some(cs),
            })
            .any(|cs| cs.id == hello.cipher_suite())
        {
            return Err(wire::Error::illegal_parameter("invalid cipher suite").into());
        }

        // RFC 8446: "A client which receives
        // a legacy_session_id_echo field that does not match
        // what it sent in the ClientHello MUST abort the
        // handshake with an "illegal_parameter" alert."
        if hello
            .legacy_session_id_echo
            .as_slice()
            .ct_ne(&ctx.session_id)
            .into()
        {
            return Err(wire::Error::illegal_parameter("invalid session id").into());
        }

        Ok(())
    }

    /// See RFC 8446 Appendix D.4.
    async fn send_dummy_ccs<W: Write>(&mut self, w: &mut W) -> Result<(), Error> {
        // TODO: send this once.
        self.send
            .write_record(ContentType::ChangeCipherSpec, None, &[1])?;
        w.write_all(self.send.buf.as_bytes()).await?;
        self.send.buf.clear();
        Ok(())
    }

    /// Sends a retried `ClientHello` to the server.
    async fn send_second_client_hello<W: Write>(
        &mut self,
        ctx: &SentClientHello,
        w: &mut W,
    ) -> Result<(), Error> {
        let mut buf = [0; MAX_HANDSHAKE_SIZE];

        let hello = HelloBuilder::new()
            .with_alpn(self.cfg.alpn())
            .with_early_data(self.cfg.early_data())
            .with_legacy_session_id(ctx.session_id)
            .pipe(|b| match self.cfg.max_fragment_length() {
                Some(len) => b.with_max_fragment_length(len),
                None => b,
            })
            .build(&mut buf)?;
        w.write_all(hello).await?;

        Ok(())
    }

    /// Reads a handshake message from `rd`.
    async fn read_hs_msg<R: Read>(&mut self, rd: &mut R) -> Result<HandshakeHeader, Error> {
        self.read_hs_bytes_from(rd, HandshakeHeader::SIZE).await?;

        let hdr = self.recv.read_type::<HandshakeHeader>()?;
        self.read_hs_bytes_from(rd, hdr.length).await?;

        Ok(hdr)
    }

    /// Reads `n` handshake bytes from `rd`.
    async fn read_hs_bytes_from<R: Read>(&mut self, rd: &mut R, n: usize) -> Result<(), Error> {
        while self.recv.len() < n {
            let hdr = self.recv.read_record_from(rd).await?;
            match hdr.content_type {
                ContentType::Handshake => {}
                ContentType::ChangeCipherSpec => {
                    // RFC 8446: "An implementation may receive
                    // an unencrypted record of type
                    // change_cipher_spec consisting of the
                    // single byte value 0x01 at any time after
                    // the first ClientHello message has been
                    // sent or received and before the peer's
                    // Finished message has been received and
                    // MUST simply drop it without further
                    // processing."
                    if hdr.length == 1 {
                        self.recv.read_exact_from(rd, 1).await?;
                        if self.recv.as_bytes().last() == Some(&0x01) {
                            self.recv.useless += 1;
                            continue;
                        }
                    }
                    // RFC 8446: "An implementation which
                    // receives any other change_cipher_spec
                    // value or which receives a protected
                    // change_cipher_spec record MUST abort the
                    // handshake with an "unexpected_message"
                    // alert."
                    return Err(
                        wire::Error::unexpected_message("invalid `ChangeCipherSpec`").into(),
                    );
                }
                _ => {
                    // RFC 8446: "Handshake messages MUST NOT be
                    // interleaved with other record types. That
                    // is, if a handshake message is split over
                    // two or more records, there MUST NOT be any
                    // other records between them."
                    return Err(wire::Error::unexpected_message(
                        "non-handshake message during handshake",
                    )
                    .into());
                }
            }

            if hdr.length == 0 {
                // RFC 8446: "Implementations MUST NOT send
                // zero-length fragments of Handshake types, even
                // if those fragments contain padding."
                return Err(wire::Error::decode_error("zero-length handshake fragment").into());
            }
        }
        Ok(())
    }
}

impl Conn<'_> {
    /// Decrypt a record from `rd`, returning the ciphertext if
    /// the record is application data.
    pub async fn decrypt<R: Read>(&mut self, _rd: &mut R) -> Result<Option<&[u8]>, Error> {
        todo!()
    }
}

// TODO
struct HalfConn<'a> {
    cfg: &'a dyn ClientConfig,
    seq: u64,
}

struct SentClientHello {
    session_id: [u8; 32],
}

#[derive(Copy, Clone, Debug)]
struct SendBuf {
    buf: Buffer<MAX_HANDSHAKE_SIZE>,
}

impl SendBuf {
    const fn new() -> Self {
        Self { buf: Buffer::new() }
    }

    const fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }

    /// Sends an alert to the peer.
    fn send_alert(&mut self, alert: Alert) -> Result<(), Error> {
        self.write_record(ContentType::Alert, None, alert)
    }

    /// Writes a record.
    fn write_record<T>(
        &mut self,
        _ct: ContentType,
        vers: Option<ProtocolVersion>,
        _data: T,
    ) -> Result<(), Error>
    where
        T: TryEncode,
    {
        // Some servers reject records with a version other than
        // TLS 1.0 in the ClientHello.
        let _vers = vers.unwrap_or(ProtocolVersion::Tls10);
        // let hdr = Record::new(ct, vers, data);
        // hdr.try_encode(&mut self.send).map(|_| ())?;
        Ok(())
    }
}

#[derive(Copy, Clone, Debug)]
struct RecvBuf {
    // Scratch space for reading record headers.
    hdr: Buffer<{ RecordHeader::SIZE }>,
    // Contains N record fragments.
    buf: Buffer<MAX_HANDSHAKE_SIZE>,
    // The number of consecutive useless records we've read.
    useless: usize,
}

impl RecvBuf {
    const fn new() -> Self {
        Self {
            hdr: Buffer::new(),
            buf: Buffer::new(),
            useless: 0,
        }
    }

    /// Returns the length of the unread portion of the buffer.
    const fn len(&self) -> usize {
        self.buf.len()
    }

    /// Returns the unread portion of the buffer.
    const fn as_bytes(&self) -> &[u8] {
        self.buf.as_bytes()
    }

    /// Reads a `T` from the buffer.
    fn read_type<'a, T>(&'a mut self) -> Result<T, Error>
    where
        T: TryParse<'a>,
    {
        self.buf.read_type::<T>()
    }

    /// Reads exactly `n` bytes from `rd` and writes the bytes to
    /// the buffer.
    async fn read_exact_from<R: Read>(&mut self, rd: &mut R, n: usize) -> Result<(), Error> {
        self.buf.read_exact_from(rd, n).await
    }

    /// Reads a record from `rd`.
    async fn read_record_from<R: Read>(&mut self, rd: &mut R) -> Result<RecordHeader, Error> {
        const MAX_USELESS_RECORDS: usize = 16;
        if self.useless > MAX_USELESS_RECORDS {
            return Err(wire::Error::unexpected_message("too many useless records").into());
        }

        self.hdr.clear();
        self.hdr.read_exact_from(rd, RecordHeader::SIZE).await?;
        let hdr = self.hdr.peek_type::<RecordHeader>()?;

        match hdr.content_type {
            ContentType::Alert => {
                // RFC 8446: "Alert messages (Section 6) MUST NOT
                // be fragmented across records, and multiple
                // alert messages MUST NOT be coalesced into
                // a single TLSPlaintext record. In other words,
                // a record with an Alert type MUST contain
                // exactly one message."
                return if hdr.length > Alert::SIZE {
                    Err(wire::Error::decode_error("alert larger than one alert").into())
                } else {
                    Err(wire::Error::decode_error("alert must not be fragmented").into())
                };
            }
            // CCS might be useless if we're in a handshake.
            ContentType::ChangeCipherSpec => {}
            // Other message types aren't useless.
            _ => self.useless = 0,
        }

        self.buf.read_exact_from(rd, hdr.length).await?;
        Ok(hdr)
    }
}

#[derive(Copy, Clone, Debug)]
struct Config<'a>(&'a dyn ClientConfig);

impl<'a> Deref for Config<'a> {
    type Target = &'a dyn ClientConfig;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
