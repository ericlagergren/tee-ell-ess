//! The `application_layer_protocol_negotiation` extension.

use crate::wire::{
    macros::{define_list, define_type_alias},
    types::opaque,
};

/// The `application_layer_protocol_negotiation` extension.
#[doc(alias = "application_layer_protocol_negotiation")]
pub type Alpn<'a> = ProtocolNameList<'a>;

define_list! {
    /// The `application_layer_protocol_negotiation` extension.
    #[doc(alias = "application_layer_protocol_negotiation")]
    #[derive(Eq, PartialEq)]
    pub struct {
       #[iter(name = names)] // TODO
       ProtocolName<'a> protocol_name_list<2..2^16-1>
    } ProtocolNameList;
}

define_type_alias! {
    /// An ALPN protocol name.
    pub opaque ProtocolName<1..2^8-1>;
}
