//! The `key_share` extension.

use crate::{
    util::Hex,
    wire::{
        macros::{define_list, define_struct},
        tls13::ext::NamedGroup,
        types::opaque,
        vec::Vector,
        EncBuf, Error, Object, Size, TryEncode, TryParse,
    },
};

define_list! {
    /// The `key_share` extension for the `ClientHello`.
    #[derive(Eq, PartialEq)]
    pub struct {
        KeyShare<'a> client_shares<0..2^16-1>;
    } KeyShareClientHello;
}

define_struct! {
    /// The `key_share` extension for the `HelloRetryRequest`.
    #[doc(alias = "key_share")]
    #[derive(Debug)]
    pub struct {
        NamedGroup selected_group;
    } KeyShareHelloRetryRequest;
}

impl KeyShareHelloRetryRequest {
    /// Returns the selected named group.
    #[inline]
    pub const fn group(&self) -> NamedGroup {
        self.selected_group
    }
}

define_struct! {
    /// The `key_share` extension for the `ServerHello`.
    #[doc(alias = "key_share")]
    #[derive(Debug, Eq, PartialEq)]
    pub struct {
        KeyShare<'a> server_share;
    } KeyShareServerHello<'a>;
}

impl KeyShareServerHello<'_> {
    /// Returns the server's selected [`KeyShareEntry`].
    #[inline]
    pub const fn share(&self) -> KeyShare<'_> {
        self.server_share
    }
}

define_struct! {
    /// A `KeyShareEntry`.
    #[derive(Debug, Eq, PartialEq)]
    pub struct {
        NamedGroup group;
        opaque key_exchange<1..2^16-1>;
    } KeyShareEntry<'a>;
}

impl KeyShareEntry<'_> {
    /// Returns the named group.
    #[inline]
    pub const fn group(&self) -> NamedGroup {
        self.group
    }

    /// Returns the key exchange data.
    #[inline]
    pub const fn kex(&self) -> &[u8] {
        self.key_exchange.as_slice()
    }
}

impl<'a> KeyShareEntry<'a> {
    #[inline]
    fn parse_kex_data<T>(&self) -> Result<T, Error>
    where
        T: TryParse<'a>,
    {
        T::try_parse_all(self.key_exchange.into_slice())
    }
}

/// A known [`KeyShareEntry`].
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum KeyShare<'a> {
    /// NIST P-256.
    Secp256r1(Secp256r1<'a>),
    /// NIST P-384.
    Secp384r1(Secp384r1<'a>),
    /// NIST P-521.
    Secp521r1(Secp521r1<'a>),
    /// X25519.
    X25519(X25519<'a>),
    /// X448.
    X448(X448<'a>),
    /// An unknown key share type.
    Unknown(KeyShareEntry<'a>),
}

impl KeyShare<'_> {
    /// Returns the named group.
    #[inline]
    pub const fn group(&self) -> NamedGroup {
        use NamedGroup::*;

        match self {
            Self::Secp256r1(_) => Secp256r1,
            Self::Secp384r1(_) => Secp384r1,
            Self::Secp521r1(_) => Secp521r1,
            Self::X25519(_) => X25519,
            Self::X448(_) => X448,
            Self::Unknown(v) => v.group,
        }
    }
}

impl Object for KeyShare<'_> {
    const SIZE: Size = KeyShareEntry::SIZE;
}

impl<'de: 'a, 'a> TryParse<'de> for KeyShare<'a> {
    #[inline]
    fn try_parse(data: &'de [u8]) -> Result<(Self, &'de [u8]), Error> {
        let (entry, rest) = KeyShareEntry::try_parse(data)?;
        let share = KeyShare::try_from(entry)?;
        Ok((share, rest))
    }
}

impl TryEncode for KeyShare<'_> {
    #[inline]
    fn try_encode(&self, out: &mut EncBuf<'_>) -> Result<(), Error> {
        let data: &[u8] = match self {
            Self::Secp256r1(share) => share.data(),
            Self::Secp384r1(share) => share.data(),
            Self::Secp521r1(share) => share.data(),
            Self::X25519(share) => share.data(),
            Self::X448(share) => share.data(),
            Self::Unknown(share) => return share.try_encode(out),
        };
        KeyShareEntry {
            group: self.group(),
            key_exchange: Vector::try_new(data)?,
        }
        .try_encode(out)
    }
}

impl<'a> TryFrom<KeyShareEntry<'a>> for KeyShare<'a> {
    type Error = Error;

    #[inline]
    fn try_from(share: KeyShareEntry<'a>) -> Result<Self, Self::Error> {
        use NamedGroup::*;

        match share.group {
            Secp256r1 => share.parse_kex_data().map(Self::Secp256r1),
            Secp384r1 => share.parse_kex_data().map(Self::Secp384r1),
            Secp521r1 => share.parse_kex_data().map(Self::Secp521r1),
            X25519 => share.parse_kex_data().map(Self::X25519),
            X448 => share.parse_kex_data().map(Self::X448),
            _ => Ok(Self::Unknown(share)),
        }
    }
}

macro_rules! impl_uncompressed_point_repr {
    (
        @nist;
        $name:ident,
        $length:expr,
        $curve:expr $(,)?
    ) => {
        /// `UncompressedPointRepresentation` for the
        #[doc = concat!($curve, " curve.")]
        #[doc(alias = "UncompressedPointRepresentation")]
        #[derive(Copy, Clone, Eq, PartialEq)]
        pub struct $name<'a> {
            // struct {
            //     uint8 _legacy_form = 4;
            //     opaque x[$length];
            //     opaque y[$length];
            // } Repr<'a>;
            data: &'a [u8; 1 + (2 * $length)],
        }

        impl<'a> $name<'a> {
            /// Returns the underlying data in the form
            ///
            /// ```text
            /// 0x4 || x || y
            /// ````
            #[inline]
            pub const fn data(&self) -> &[u8; 1 + (2 * $length)] {
                self.data
            }

            /// Returns the public key ((x, y) coordinates).
            #[inline]
            pub const fn pk(&self) -> (&[u8; $length], &[u8; $length]) {
                // The compiler can prove that these do not
                // panic.
                let (_, rest) = self.data.split_first().unwrap();
                let (x, rest) = rest.split_first_chunk().unwrap();
                let (y, _) = rest.split_first_chunk().unwrap();
                (x, y)
            }
        }

        #[automatically_derived]
        impl Object for $name<'_> {
            const SIZE: Size = {
                let n = 1 + (2 * $length);
                Size::new(n, n)
            };
        }

        #[automatically_derived]
        impl<'a> TryParse<'a> for $name<'a> {
            #[inline]
            fn try_parse(data: &'a [u8]) -> Result<(Self, &'a [u8]), Error> {
                let (data, rest) = <&[u8; { 1 + (2 * $length) }]>::try_parse(data)?;
                if data[0] != 0x4 {
                    return Err(Error::illegal_parameter("invalid constant"));
                }
                Ok((Self { data }, rest))
            }
        }

        #[automatically_derived]
        impl TryEncode for $name<'_> {
            #[inline]
            fn try_encode(&self, out: &mut EncBuf<'_>) -> Result<(), Error> {
                self.data.try_encode(out)
            }
        }

        #[automatically_derived]
        impl ::core::fmt::Debug for $name<'_> {
            fn fmt(&self, f: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
                f.debug_struct(stringify!($name))
                    .field("data", &Hex(&*self.data))
                    .finish()
            }
        }
    };
    (
        @other;
        $name:ident,
        $length:expr,
        $curve:expr $(,)?
    ) => {
        /// `UncompressedPointRepresentation` for the
        #[doc = concat!($curve, " curve.")]
        #[doc(alias = "UncompressedPointRepresentation")]
        #[derive(Copy, Clone, Eq, PartialEq)]
        pub struct $name<'a> {
            pk: &'a [u8; $length],
        }

        impl<'a> $name<'a> {
            /// Returns the underlying data.
            pub const fn data(&self) -> &[u8; $length] {
                self.pk
            }

            /// Returns the public key.
            pub const fn pk(&self) -> &[u8; $length] {
                self.pk
            }
        }

        #[automatically_derived]
        impl Object for $name<'_> {
            const SIZE: Size = Size::new($length, $length);
        }

        #[automatically_derived]
        impl<'a> TryParse<'a> for $name<'a> {
            #[inline]
            fn try_parse(data: &'a [u8]) -> Result<(Self, &'a [u8]), Error> {
                let (pk, rest) = <&[u8; $length]>::try_parse(data)?;
                Ok((Self { pk }, rest))
            }
        }

        #[automatically_derived]
        impl TryEncode for $name<'_> {
            #[inline]
            fn try_encode(&self, out: &mut EncBuf<'_>) -> Result<(), Error> {
                self.pk.try_encode(out)
            }
        }

        impl ::core::fmt::Debug for $name<'_> {
            fn fmt(&self, f: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
                f.debug_tuple(stringify!($name))
                    .field(&Hex(&*self.pk))
                    .finish()
            }
        }
    };
}

// RFC 8446: "For P-256, this means that each of X and Y use
// 32 octets, padded on the left by zeros if necessary. For
// P-384, they take 48 octets each. For P-521, they take 66
// octets each."
impl_uncompressed_point_repr!(@nist; Secp256r1, 32, "NIST P-256");
impl_uncompressed_point_repr!(@nist; Secp384r1, 48, "NIST P-384");
impl_uncompressed_point_repr!(@nist; Secp521r1, 66, "NIST P-521");

// RFC 8446: "For X25519 and X448, the contents of the public
// value are the byte string inputs and outputs of the
// corresponding functions defined in RFC 7748: 32 bytes for
// X25519 and 56 bytes for X448."
impl_uncompressed_point_repr!(@other; X25519, 32, "X25519");
impl_uncompressed_point_repr!(@other; X448, 56, "X448");

#[cfg(test)]
mod tests {
    use super::*;

    macro_rules! hex {
        ($($s:literal)*) => {
            &::hex_literal::hex!($($s)*)
        }
    }

    #[test]
    fn test_key_share_entry() {
        let tests: &[(&[u8], KeyShare<'static>)] = &[
            (
                hex!(
                    "001d"
                    "0020"
                    "358072d6365880d1aeea329adf912138"
                    "3851ed21a28e3b75e965d0d2cd166254"
                ),
                KeyShare::X25519(X25519 {
                    pk: hex!(
                        "358072d6365880d1aeea329adf912138"
                        "3851ed21a28e3b75e965d0d2cd166254"
                    ),
                }),
            ),
            (
                hex!(
                    "0017"
                    "0041"
                    "04"
                    "11111111111111111111111111111111"
                    "11111111111111111111111111111111"
                    "22222222222222222222222222222222"
                    "22222222222222222222222222222222"
                ),
                KeyShare::Secp256r1(Secp256r1 {
                    _legacy_form: 4,
                    x: &[0x11; 32],
                    y: &[0x22; 32],
                }),
            ),
        ];
        for (i, (data, want)) in tests.iter().enumerate() {
            println!("want = {want:?}");
            let got = KeyShare::try_parse_all(data).unwrap();
            assert_eq!(got, *want, "#{i}");
        }
    }
}
