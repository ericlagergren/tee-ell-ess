use core::marker::PhantomData;

use crate::wire::types::u24;

/// An object in the TLS wire format.
pub trait Object {
    /// The size minimum and maximum size in bytes of the object.
    const SIZE: Size;
}

impl<T: Object> Object for &T {
    const SIZE: Size = T::SIZE;
}

impl Object for () {
    const SIZE: Size = Size::zero();
}

macro_rules! impl_scalar_object {
    ($($ty:ty)*) => {
        $( impl Object for $ty {
            const SIZE: Size = Size::new(
                <$ty>::MAX.to_be_bytes().len(),
                <$ty>::MAX.to_be_bytes().len(),
            );
        } )*
    };
}
impl_scalar_object!(u8 u16 u24 u32 u64);

impl<T: Object, const N: usize> Object for [T; N] {
    const SIZE: Size = Size::new(N * T::SIZE.min(), N * T::SIZE.max());
}

impl<T: Object> Object for PhantomData<T> {
    const SIZE: Size = T::SIZE;
}

/// The size of an object.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct Size {
    min: usize,
    max: usize,
}

impl Size {
    /// Returns the zero value.
    #[inline]
    pub const fn zero() -> Self {
        Self::new(0, 0)
    }

    /// Creates a `Size`.
    #[inline]
    pub const fn new(min: usize, max: usize) -> Self {
        assert!(min <= max);

        Self { min, max }
    }

    /// Returns `Some(size)` if the size is fixed.
    #[inline]
    pub const fn fixed(self) -> Option<usize> {
        if self.is_fixed() {
            Some(self.min)
        } else {
            None
        }
    }

    /// Reports whether the size is fixed.
    #[inline]
    pub const fn is_fixed(self) -> bool {
        self.min == self.max
    }

    /// Returns the lower bound.
    #[inline]
    pub const fn min(self) -> usize {
        self.min
    }

    /// Returns the upper bound.
    #[inline]
    pub const fn max(self) -> usize {
        self.max
    }

    /// Returns the sum of the sizes.
    #[inline]
    pub const fn sum(sizes: &[Self]) -> Self {
        let mut sum = Self::zero();
        let mut i = 0;
        while i < sizes.len() {
            sum = sum.add(sizes[i]);
            i += 1;
        }
        sum
    }

    /// Returns `self + other`.
    #[inline]
    pub const fn add(self, other: Self) -> Self {
        Self::new(self.min + other.min, self.max + other.max)
    }
}

impl Default for Size {
    #[inline]
    fn default() -> Self {
        Self::zero()
    }
}
