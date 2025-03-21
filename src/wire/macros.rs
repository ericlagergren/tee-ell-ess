macro_rules! gen_vector_macros {
    ($d:tt $($len:tt)*) => {
        /// Expands to either `SmallVec` or `Vector` depending
        /// on the maximum length.
        macro_rules! vector_ty {
            $(($ty:ty; $min:literal .. $len) => {
                $crate::wire::vec::SmallVec<$ty, $min, $len>
            };)*

            ($ty:ident; $min:literal .. $max:literal) => {
                $crate::wire::vec::Vector<'a, $ty, $min, $max>
            };
            ($ty:ident<$lt:lifetime>; $min:literal .. $max:literal) => {
                $crate::wire::vec::Vector<$lt, $ty<$lt>, $min, $max>
            };

            ($ty:ident; $min:literal .. 2^$shift:literal-$sub:literal) => {
                $crate::wire::vec::Vector<'a, $ty, $min, { (1<<$shift)-$sub }>
            };
            ($ty:ident<$lt:lifetime>; $min:literal .. 2^$shift:literal-$sub:literal) => {
                $crate::wire::vec::Vector<$lt, $ty<$lt>, $min, { (1<<$shift)-$sub }>
            };
        }
        pub(crate) use vector_ty;

        /// Expands to a type alias for a vector type.
        macro_rules! define_vec_type_alias {
            $((
                $d (#[$meta:meta])*
                $vis:vis type $name:ident $d (<$lt:lifetime>)? = [$ty:ty; $min:literal .. $len];
            ) => {
                $d (#[$meta])*
                $vis type $name $d (<$lt>)? = $crate::wire::vec::SmallVec<$ty, $min, $len>;
            };)*

            // E.g., `pub type Foo = [Bar; 0 .. 44]`
            (
                $d (#[$meta:meta])*
                $vis:vis type $name:ident = [$ty:ty; $min:literal .. $max:literal];
            ) => {
                $d (#[$meta])*
                $vis type $name<'a> = $crate::wire::vec::Vector<'a, $ty, $min, $max>;
            };
            // E.g., `pub type Foo<'a> = [Bar<'a>; 0 .. 44]`
            (
                $d (#[$meta:meta])*
                $vis:vis type $name:ident<$lt:lifetime> = [$ty:ty; $min:literal .. $max:literal];
            ) => {
                $d (#[$meta])*
                $vis type $name<$lt> = $crate::wire::vec::Vector<$lt, $ty, $min, $max>;
            };

            // E.g., `pub type Foo = [Bar; 0 .. 2^16-1]`
            (
                $d (#[$meta:meta])*
                $vis:vis type $name:ident = [$ty:ty; $min:literal .. 2^$shift:literal-$sub:literal];
            ) => {
                $d (#[$meta])*
                $vis type $name<'a> = $crate::wire::vec::Vector<'a, $ty, $min, { (1<<$shift)-$sub }>;
            };
            // E.g., `pub type Foo<'a> = [Bar<'a>; 0 .. 2^16-1]`
            (
                $d (#[$meta:meta])*
                $vis:vis type $name:ident<$lt:lifetime> = [$ty:ty; $min:literal .. 2^$shift:literal-$sub:literal];
            ) => {
                $d (#[$meta])*
                $vis type $name<$lt> = $crate::wire::vec::Vector<$lt, $ty, $min, { (1<<$shift)-$sub }>;
            };
        }
        pub(crate) use define_vec_type_alias;
    };
}
gen_vector_macros! { $
    0 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16
    17 18 19 20 21 22 23 24 25 26 27 28 29 30 31
    32
}

/// Parse a struct with a discriminant and data fields.
///
/// For example:
///
/// ```text
/// struct {
///     ExtensionType extension_type;
///     opaque extension_data<0..2^16-1>;
/// } Extension;
/// ```
macro_rules! define_enum_struct {
    (
        $(#[doc = $doc:expr])*
        #[repr($repr:ident)]
        $(#[default($default:ty)])?
        $(#[derive($($derive:ident),*)])*
        $vis:vis enum $name:ident<$($lt:lifetime)?> {
            $(
                $(#[doc = $var_doc:expr])*
                $variant:ident($ty:ty),
            )*
        }
    ) => {
        $(#[doc = $doc])*
        #[derive(Copy, Clone, Debug)]
        $(#[derive($($derive),*)])*
        $vis enum $name<$($lt)?> {
            $(
                $(#[doc = $var_doc])*
                $variant($ty),
            )*
            $(
                /// Unknown variant.
                Unknown($default),
            )?
        }

        $crate::wire::macros::impl_try_parse_enum_struct! {
            [$($lt)?],
            $name,
            $repr,
            $($default)?,
            variants = $($variant($ty)),*
        }
    };
}
pub(crate) use define_enum_struct;

macro_rules! impl_try_parse_enum_struct {
    // @struct is the lifetime for `$name`
    (
        @struct = $($struct:lifetime)?,
        $name:ident,
        $repr:ident,
        variants = $($variant:ident($ty:ty)),*
    ) => {
        #[automatically_derived]
        impl<$($struct)?> $crate::wire::Object for $name<$($struct)?> {
            const SIZE: $crate::wire::Size = $crate::wire::Size::sum(&[
                $(<$ty as $crate::wire::Object>::SIZE),*
            ]);
        }

        #[automatically_derived]
        impl<'de $(: $struct, $struct)?> $crate::wire::TryParse<'de> for $name<$($struct)?> {
            #[inline]
            fn try_parse(data: &'de [u8]) -> $crate::wire::Result<(Self, &'de [u8])> {
                println!("{}", stringify!($name));
                println!("data: {:x?}", data);
                let (discriminant, rest) = <$repr as $crate::wire::TryParse>::try_parse(data)?;
                println!("discriminant: {:?}", discriminant);
                println!("rest: {:x?}", rest);
                match discriminant {
                    $($repr::$variant => {
                        let (v, rest) = <$ty as $crate::wire::TryParse>::try_parse(rest)?;
                        println!("v: {:?}", v);
                        println!("rest: {:x?}", rest);
                        Ok((Self::$variant(v), rest))
                    })*
                    #[allow(unreachable_patterns)]
                    _ => Err($crate::wire::Error::decode_error("unexpected enum variant")),
                }
            }
        }

        #[automatically_derived]
        impl<$($struct)?> $crate::wire::TryEncode for $name<$($struct)?> {
            #[inline]
            fn try_encode(&self, out: &mut $crate::wire::EncBuf<'_>) -> $crate::wire::Result<()> {
                match self {
                    $(Self::$variant(v) => {
                        <$repr as $crate::wire::TryEncode>::try_encode(&<$repr>::$variant, out)?;
                        <$ty as $crate::wire::TryEncode>::try_encode(v, out)?;
                    })*
                }
                Ok(())
            }
        }
    };
    (
        [],
        $name:ident,
        $repr:ident,
        $($default:ty)?,
        variants = $($variant:ident($ty:ty)),*
    ) => {
        $crate::wire::macros::impl_try_parse_enum_struct! {
            @struct = ,
            $name,
            $repr,
            variants = $($variant($ty)),* $($default,)?
        }
    };
    (
        [$lt:lifetime],
        $name:ident,
        $repr:ident,
        $($default:ty)?,
        variants = $($variant:ident($ty:ty)),*
    ) => {
        $crate::wire::macros::impl_try_parse_enum_struct! {
            @struct = $lt,
            $name,
            $repr,
            variants = $($variant($ty)),* $($default,)?
        }
    };
}
pub(crate) use impl_try_parse_enum_struct;

/// Defines a "list" type.
///
/// A list type is a `struct` with one single field that contains
/// a series of items. For example:
///
/// ```text
/// struct {
///     KeyShareEntry client_shares<0..2^16-1>;
/// } KeyShareClientHello;
/// struct {
///     PskKeyExchangeMode ke_modes<1..255>;
/// } PskKeyExchangeModesList;
/// ```
///
/// List types must also implement `IntoIterator` and have an
/// `iter` method.
macro_rules! define_list {
    (
        @impl
        $(#[$meta:meta])*
        vis = $vis:vis,
        name = $name:ident,
        min = $min:expr,
        max = $max:expr,
        item = $item:ty,
    ) => {
        $(#[$meta])*
        #[derive(Copy, Clone)]
        $vis struct $name<'a> {
            data: $crate::wire::vec::Vector<'a, $item, { $min }, { $max }>,
        }

        impl<'a> $name<'a> {
            /// Returns an iteratover over the list's data.
            #[inline]
            #[allow(dead_code, reason = "Some lists are not `pub`")]
            $vis const fn iter(&self) -> $crate::wire::vec::Iter<'_, $item> {
                self.data.iter()
            }
        }

        #[automatically_derived]
        impl<'a> $crate::wire::Object for $name<'a> {
            const SIZE: $crate::wire::Size = $crate::wire::Size::new($min, $max);
        }

        #[automatically_derived]
        impl<'de: 'a, 'a> $crate::wire::TryParse<'de> for $name<'a> {
            #[inline]
            fn try_parse(data: &'de [u8]) -> $crate::wire::Result<(Self, &'de [u8])> {
                let (data, rest) = <$crate::wire::vec::Vector<'_, $item, { $min }, { $max }>
                    as $crate::wire::TryParse>::try_parse(data)?;
                Ok((Self { data }, rest))
            }
        }

        #[automatically_derived]
        impl $crate::wire::TryEncode for $name<'_> {
            #[inline]
            fn try_encode(&self, out: &mut $crate::wire::EncBuf<'_>) -> $crate::wire::Result<()> {
                $crate::wire::TryEncode::try_encode(&self.data, out)
            }
        }

        #[automatically_derived]
        impl<'a> IntoIterator for $name<'a> {
            type Item = $item;
            type IntoIter = $crate::wire::vec::Iter<'a, $item>;

            #[inline]
            fn into_iter(self) -> Self::IntoIter {
                self.data.into_iter()
            }
        }

        impl ::core::fmt::Debug for $name<'_> {
            fn fmt(&self, f: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
                f.debug_list().entries(self.iter()).finish()
            }
        }
    };

    (
        $(#[$meta:meta])*
        $vis:vis struct {
            $item:ident $(<$lt:lifetime>)? $field:ident<$min:literal .. $max:literal> $(;)?
        } $name:ident $(<'a>)?;
    ) => {
        $crate::wire::macros::define_list! {
            @impl
            $(#[$meta])*
            vis = $vis,
            name = $name,
            min = $min,
            max = $max,
            item = $item $(<$lt>)?,
        }
    };

    (
        $(#[$meta:meta])*
        $vis:vis struct {
            $(#[iter(name = $iter:ident)])?
            $item:ident $(<$lt:lifetime>)? $field:ident<$min:literal .. 2^$shift:literal-$sub:literal> $(;)?
        } $name:ident $(<'a>)?;
    ) => {
        $crate::wire::macros::define_list! {
            @impl
            $(#[$meta])*
            vis = $vis,
            name = $name,
            min = $min,
            max = { (1<<$shift)-$sub },
            item = $item $(<$lt>)?,
        }
    };
}
pub(crate) use define_list;

/// Defines an enumeration where each variant is an integer.
macro_rules! define_scalar_enum {
    (@base
        name = $name:ident,
        repr = $repr:ident,
        variants = $($variant:ident),*,
    ) => {
        impl $name {
            /// Returns the enumeration as a string.
            pub const fn to_str(self) -> &'static str {
                match self {
                    $($name::$variant => stringify!($variant),)*
                    #[allow(unreachable_patterns)]
                    _ => "unknown",
                }
            }
        }

        #[automatically_derived]
        impl $crate::wire::Object for $name {
            const SIZE: $crate::wire::Size = <$repr as $crate::wire::Object>::SIZE;
        }

        #[automatically_derived]
        impl<'de> $crate::wire::TryParse<'de> for $name {
            #[inline]
            fn try_parse(data: &'de [u8]) -> $crate::wire::Result<(Self, &'de [u8])> {
                let (repr, rest) = <$repr as $crate::wire::TryParse>::try_parse(data)?;
                Ok((repr.try_into()?, rest))
            }
        }

        #[automatically_derived]
        impl $crate::wire::TryEncode for $name {
            #[inline]
            fn try_encode(&self, out: &mut $crate::wire::EncBuf<'_>) -> $crate::wire::Result<()> {
                $crate::wire::TryEncode::try_encode(&self.to_repr(), out)
            }
        }

        impl From<$name> for $repr {
            #[inline]
            fn from(v: $name) -> Self {
                v.to_repr()
            }
        }
    };

    (
        $(#[doc = $doc:expr])*
        $(#[doc(alias = $alias:expr)])?
        #[repr($repr:ident)]
        #[strict($error:ident($error_msg:expr))]
        $vis:vis enum $name:ident {
            $(
                $(#[doc = $var_doc:expr])*
                $(#[doc(alias = $var_alias:expr)])*
                $variant:ident = $value:expr,
            )*
        }
    ) => {
        $(#[doc = $doc])*
        $(#[doc(alias = $alias)])*
        #[repr($repr)]
        #[derive(Copy, Clone, Debug, Eq, PartialEq)]
        #[allow(missing_docs)]
        $vis enum $name {
            $(
                $(#[doc = $var_doc])*
                $(#[doc(alias = $var_alias)])*
                $variant = $value,
            )*
        }
        $crate::wire::macros::define_scalar_enum! {
            @base
            name = $name,
            repr = $repr,
            variants = $($variant),*,
        }

        impl $name {
            /// Converts the enumeration to its repr.
            #[inline]
            pub const fn to_repr(self) -> $repr {
                match self {
                    $($name::$variant => $value,)*
                }
            }

            /// Attempts to create the enumeration from its repr.
            #[inline]
            pub const fn try_from_repr(repr: $repr) -> $crate::wire::Result<Self> {
                let v = match repr {
                    $($value => Self::$variant),*,
                    _ => return Err($crate::wire::Error::$error($error_msg)),
                };
                Ok(v)
            }
        }

        impl TryFrom<$repr> for $name {
            type Error = $crate::wire::Error;

            #[inline]
            fn try_from(repr: $repr) -> Result<Self, Self::Error> {
                Self::try_from_repr(repr)
            }
        }

        impl ::core::fmt::Display for $name {
            fn fmt(&self, f: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
                match self {
                    $(Self::$variant => write!(f, stringify!($variant)),)*
                }
            }
        }
    };

    (
        $(#[doc = $doc:expr])*
        $(#[doc(alias = $alias:expr)])?
        #[repr($repr:ident)]
        $vis:vis enum $name:ident {
            $(
                $(#[doc = $var_doc:expr])*
                $(#[doc(alias = $var_alias:expr)])*
                $variant:ident = $value:expr,
            )*
            $(
                #[default]
                $unknown:ident,
            )?
        }
    ) => {
        $(#[doc = $doc])*
        $(#[doc(alias = $alias)])*
        #[repr($repr)]
        #[derive(Copy, Clone, Debug, Eq, PartialEq)]
        #[allow(missing_docs)]
        $vis enum $name {
            $(
                $(#[doc = $var_doc])*
                $(#[doc(alias = $var_alias)])*
                $variant = $value,
            )*
            Unknown($repr) = <$repr>::MAX,
        }
        $crate::wire::macros::define_scalar_enum! {
            @base
            name = $name,
            repr = $repr,
            variants = $($variant),*,
        }

        impl $name {
            /// Converts the enumeration to its repr.
            #[inline]
            pub const fn to_repr(self) -> $repr {
                match self {
                    $($name::$variant => $value,)*
                    Self::Unknown(v) => v,
                }
            }

            /// Attempts to create the enumeration from its repr.
            #[inline]
            pub const fn try_from_repr(repr: $repr) -> $crate::wire::Result<Self, ::core::convert::Infallible> {
                let v = match repr {
                    $($value => Self::$variant),*,
                    repr => Self::Unknown(repr),
                };
                Ok(v)
            }
        }

        impl TryFrom<$repr> for $name {
            type Error = ::core::convert::Infallible;

            #[inline]
            fn try_from(repr: $repr) -> Result<Self, Self::Error> {
                Self::try_from_repr(repr)
            }
        }

        impl ::core::fmt::Display for $name {
            fn fmt(&self, f: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
                match self {
                    $(Self::$variant => write!(f, stringify!($variant)),)*
                    Self::Unknown(v) => {
                        write!(f, "{v:#0$x}", <Self as $crate::wire::Object>::SIZE.max() * 2)
                    }
                }
            }
        }
    };
}
pub(crate) use define_scalar_enum;

/// Defines a "struct" type.
///
/// For example:
///
/// ```text
/// struct {
///     KeyShareEntry client_shares<0..2^16-1>;
/// } KeyShareClientHello;
/// struct {
///     opaque identity<1..2^16-1>;
///     uint32 obfuscated_ticket_age;
/// } PskIdentity;
/// ```
macro_rules! define_struct {
    // All done!
    (
        @munch () -> {
            $(#[$meta:meta])*
            $vis:vis struct $name:ident $(<$lt:lifetime>)?
            $(($field:ident: $ty:ty $(= $const:expr)?))*
        }
    ) => {
        $(#[$meta])*
        #[derive(Copy, Clone)]
        #[allow(missing_docs)]
        $vis struct $name $(<$lt>)? {
            $(#[allow(missing_docs)] pub $field: $ty),*
        }
        $crate::wire::macros::impl_try_parse_struct! {
            [$($lt)?],
            $name,
            fields = $($field : $ty $(= $const)?),*
        }
    };

    // E.g., `opaque identity<1..2^16-1>;`
    (
        @munch (
            $ty:ident $(<$lt:lifetime>)? $field:ident <$min:literal .. 2^$shift:literal-$sub:literal> $(= $const:expr)?;
        ) -> { $($output:tt)* }
    ) => {
        $crate::wire::macros::define_struct! {
            @munch () -> {
                $($output)*
                ($field: $crate::wire::vec::Vector<'a, $ty $(<$lt>)?, $min, { (1<<$shift)-$sub }> $(= $const)?)
            }
        }
    };
    (
        @munch (
            $ty:ident $(<$lt:lifetime>)? $field:ident <$min:literal .. 2^$shift:literal-$sub:literal> $(= $const:expr)?;
            $($next:tt)*
        ) -> { $($output:tt)* }
    ) => {
        $crate::wire::macros::define_struct! {
            @munch ($($next)*) -> {
                $($output)*
                ($field: $crate::wire::vec::Vector<'a, $ty $(<$lt>)?, $min, { (1<<$shift)-$sub }> $(= $const)?)
            }
        }
    };

    // E.g., `opaque identity<1..254>;`
    (@munch ($ty:ident $field:ident <$min:literal .. $max:tt> $(= $const:expr)?;) -> {
        $($output:tt)*
    }) => {
        $crate::wire::macros::define_struct! {
            @munch () -> {
                $($output)*
                ($field: $crate::wire::macros::vector_ty![$ty; $min..$max] $(= $const)?)
            }
        }
    };
    (@munch ($ty:ident $field:ident <$min:literal .. $max:tt> $(= $const:expr)?; $($next:tt)*) -> {
        $($output:tt)*
    }) => {
        $crate::wire::macros::define_struct! {
            @munch ($($next)*) -> {
                $($output)*
                ($field: $crate::wire::macros::vector_ty![$ty; $min..$max] $(= $const)?)
            }
        }
    };

    // E.g., `opaque X[length];`
    (@munch ($ty:ident $field:ident [$length:expr]) -> { $($output:tt)* }) => {
        $crate::wire::macros::define_struct! {
            @munch () -> { $($output)* ($field: &'a [$ty; $length]) }
        }
    };
    (@munch ($ty:ident $field:ident [$length:expr]; $($next:tt)*) -> {
        $($output:tt)*
    }) => {
        $crate::wire::macros::define_struct! {
            @munch ($($next)*) -> {
                $($output)*
                ($field: &'a [$ty; $length])
            }
        }
    };

    // E.g., `Random<'a> random;`
    (@munch ($ty:ident <$($lt:tt),+> $field:ident $(= $const:expr)?;) -> { $(output:tt)* }) => {
        $crate::wire::macros::define_struct! {
            @munch () -> {
                $($output)*
                ($field: $ty<$($lt),+> $(= $const)?)
            }
        }
    };
    (
        @munch (
            $ty:ident <$($lt:tt),+> $field:ident $(= $const:expr)?;
            $($next:tt)*
        ) -> { $($output:tt)* }
    ) => {
        $crate::wire::macros::define_struct! {
            @munch ($($next)*) -> {
                $($output)*
                ($field: $ty <$($lt),+> $(= $const)?)
            }
        }
    };

    // E.g., `uint32 obfuscated_ticket_age;`
    (@munch ($ty:ident $field:ident $(= $const:expr)?;) -> { $(output:tt)* }) => {
        $crate::wire::macros::define_struct! {
            @munch () -> {
                $($output)*
                ($field: $ty $(= $const)?)
            }
        }
    };
    (
        @munch (
            $ty:ident $field:ident $(= $const:expr)?;
            $($next:tt)*
        ) -> { $($output:tt)* }
    ) => {
        $crate::wire::macros::define_struct! {
            @munch ($($next)*) -> {
                $($output)*
                ($field: $ty $(= $const)?)
            }
        }
    };

    (
        $(#[$meta:meta])*
        $vis:vis struct {
            $($fields:tt)*
        } $name:ident $(<$lt:lifetime>)? ;
    ) => {
        $crate::wire::macros::define_struct! {
            @munch ($($fields)*) -> {
                $(#[$meta])*
                $vis struct $name $(<$lt>)?
            }
        }
    };
}
pub(crate) use define_struct;

macro_rules! impl_try_parse_struct {
    // @struct is the lifetime for `$name`
    (
        @struct = $($struct:lifetime)?,
        $name:ident,
        fields = $($field:ident : $ty:ty $(= $const:expr)?),*
    ) => {
        #[automatically_derived]
        impl<$($struct)?> $crate::wire::Object for $name<$($struct)?> {
            const SIZE: $crate::wire::Size = $crate::wire::Size::sum(&[
                $(<$ty as $crate::wire::Object>::SIZE),*
            ]);
        }

        #[automatically_derived]
        impl<'de $(: $struct, $struct)?> $crate::wire::TryParse<'de> for $name<$($struct)?> {
            #[inline]
            fn try_parse(data: &'de [u8]) -> $crate::wire::Result<(Self, &'de [u8])> {
                let rest = data;
                $(
                    let ($field, rest) = <$ty as $crate::wire::TryParse>::try_parse(rest)?;
                    $(if $field != $const {
                        return Err($crate::wire::Error::illegal_parameter("invalid constant"));
                    })?
                )*
                let v = Self { $($field),* };
                Ok((v, rest))
            }

            #[inline]
            fn try_skip(data: &'de [u8]) -> $crate::wire::Result<&'de [u8]> {
                let rest = data;
                $( let rest = <$ty as $crate::wire::TryParse>::try_skip(rest)?; )*
                Ok(rest)
            }
        }

        #[automatically_derived]
        impl<$($struct)?> $crate::wire::TryEncode for $name<$($struct)?> {
            #[inline]
            fn try_encode(&self, out: &mut $crate::wire::EncBuf<'_>) -> $crate::wire::Result<()> {
                $(
                    $(if self.$field != $const {
                        return Err($crate::wire::Error::internal_error("invalid constant"));
                    })?
                    $crate::wire::TryEncode::try_encode(&self.$field, out)?;
                )*
                Ok(())
            }
        }
    };
    (
        [],
        $name:ident,
        fields = $($field:ident : $ty:ty $(= $const:expr)?),*
    ) => {
        $crate::wire::macros::impl_try_parse_struct! {
            @struct = ,
            $name,
            fields = $($field : $ty $(= $const)?),*
        }
    };
    (
        [$lt:lifetime],
        $name:ident,
        fields = $($field:ident : $ty:ty $(= $const:expr)?),*
    ) => {
        $crate::wire::macros::impl_try_parse_struct! {
            @struct = $lt,
            $name,
            fields = $($field : $ty $(= $const)?),*
        }
    };
}
pub(crate) use impl_try_parse_struct;

/// Defines a plain type.
///
/// For example:
///
/// ```text
/// opaque PskBinderEntry<32..255>;
/// opaque Random[32];
/// uint8 CipherSuite[2];
/// ```
macro_rules! define_type_alias {
    // E.g., `uint8 Foo[2]`
    (
        $(#[$meta:meta])*
        $vis:vis $ty:ident $name:ident [$length:literal];
    ) => {
        $(#[$meta])*
        #[allow(missing_docs)]
        $vis type $name = [$ty; $length];

        const _: () = {
            assert!(<$ty as $crate::wire::Object>::SIZE.is_fixed());
        };
    };

    // E.g., `opaque Foo<1..2^16-1>;`
    (
        $(#[$meta:meta])*
        $vis:vis $ty:ident $(<$lt:lifetime>)? $name:ident <$min:literal .. 2^$shift:literal-$sub:literal>;
    ) => {
        $crate::wire::macros::define_vec_type_alias! {
            $(#[$meta])*
            #[allow(missing_docs)]
            $vis type $name $(<$lt>)? = [$ty $(<$lt>)?; $min..2^$shift-$sub];
        }
    };

    // E.g., `opaque Foo<1..254>;`
    (
        $(#[$meta:meta])*
        $vis:vis $ty:ident $(<$lt:lifetime>)? $name:ident <$min:literal .. $max:tt>;
    ) => {
        $crate::wire::macros::define_vec_type_alias! {
            $(#[$meta])*
            #[allow(missing_docs)]
            $vis type $name $(<$lt>)? = [$ty $(<$lt>)?; $min..$max];
        }
    };

    // E.g., `uint32 MyUint32;`
    (
        $(#[$meta:meta])*
        $vis:vis $ty:ident $(<$lt:lifetime>)? $name:ident;
    ) => {
        $(#[$meta])*
        #[allow(missing_docs)]
        $vis type $name $(<$lt>)? = $ty $(<$lt>)?;
    };
}
pub(crate) use define_type_alias;
