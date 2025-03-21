//! The `server_name` extension per [RFC 6066].
//!
//![RFC 6066]: https://tools.ietf.org/html/rfc6066

use crate::wire::{
    macros::{define_enum_struct, define_list, define_scalar_enum, define_type_alias},
    types::opaque,
};

define_list! {
    /// The `server_name` extension per [RFC 6066].
    ///
    /// [RFC 6066]: https://tools.ietf.org/html/rfc6066
    #[doc(alias = "server_name")]
    #[derive(Eq, PartialEq)]
    pub struct {
        ServerName<'a> server_name_list<1..2^16-1>
    } ServerNameList;
}

define_enum_struct! {
    /// A specific server name.
    ///
    /// ```text
    /// struct {
    ///     NameType name_type;
    ///     select (name_type) {
    ///         case host_name: HostName;
    ///     } name;
    /// } ServerName;
    /// ```
    #[repr(NameType)]
    #[derive(Eq, PartialEq)]
    pub enum ServerName<'a> {
        /// A host name.
        HostName(HostName<'a>),
    }
}

define_scalar_enum! {
    /// The type of [`ServerName`].
    #[repr(u8)]
    pub enum NameType {
        /// A host name.
        HostName = 0,
    }
}

define_type_alias! {
    /// A fully qualified DNS name of a server.
    pub opaque HostName<1..2^16-1>;
}
