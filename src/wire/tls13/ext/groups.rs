//! The `supported_groups` extension.

use crate::wire::macros::{define_list, define_scalar_enum};

define_list! {
    /// The [supported_groups][0] extension.
    ///
    /// [0]: https://datatracker.ietf.org/doc/html/rfc8446#section-4.2.7
    #[doc(alias = "elliptic_curves")]
    #[derive(Eq, PartialEq)]
    pub struct {
        NamedGroup named_curve_list<2..2^16-1>
    } NamedGroupList;
}

define_scalar_enum! {
    /// A [named group][0].
    ///
    /// [0]: https://datatracker.ietf.org/doc/html/rfc8446#section-4.2.7
    #[repr(u16)]
    pub enum NamedGroup {
        Secp256r1 = 0x0017,
        Secp384r1 = 0x0018,
        Secp521r1 = 0x0019,
        X25519 = 0x001d,
        X448 = 0x001e,
        Ffdhe2048 = 0x0100,
        Ffdhe3072 = 0x0101,
        Ffdhe4096 = 0x0102,
        Ffdhe6144 = 0x0103,
        Ffdhe8192 = 0x0104,
    }
}
