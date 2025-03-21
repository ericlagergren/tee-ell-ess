//! TLS 1.3 per [RFC 8446].
//!
//! [RFC 8446]: https://datatracker.ietf.org/doc/html/rfc8446

#![cfg_attr(docsrs, feature(doc_cfg))]
//#![cfg_attr(not(any(test, doctest, feature = "std")), no_std)]
#![cfg_attr(not(any(feature = "std", test)), deny(clippy::std_instead_of_core))]

pub mod client;
pub mod crypto;
mod error;
mod io;
pub mod server;
mod tls;
pub mod tls13;
mod util;
pub mod wire;

pub use error::Error;
pub use tls::{ext::sni::HostName, CipherSuite, MaxFragmentLength, Time, Version};
