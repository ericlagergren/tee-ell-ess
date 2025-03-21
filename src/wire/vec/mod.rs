//! Variable length vectors.

mod large;
mod small;

use buggy::{bug, BugExt};

pub use crate::wire::vec::{
    large::{Iter, TryIter, Vector},
    small::{IntoIter, SmallVec, TryIntoIter},
};
use crate::wire::{types::u24, EncBuf, Error};

#[inline]
pub(crate) fn write_length<const MIN: usize, const MAX: usize>(
    out: &mut EncBuf<'_>,
    n: usize,
) -> Result<(), Error> {
    let length_size = {
        let bits = usize::BITS - MAX.leading_zeros();
        ((bits + 7) / 8) as usize
    };
    macro_rules! write_length {
        ($($size:literal => $ty:ty),* $(,)?) => {{
            // NB: The compiler should DCE the unused
            // patterns.
            match length_size {
                $($size => {
                    let length = <$ty>::try_from(n)
                        .assume("`len` is an invalid length")?
                        .to_be_bytes();
                    out.write_fixed(&length)?
                })*
                _ => bug!("unreachable pattern"),
            }
        }};
    }
    write_length! {
        1 => u8,
        2 => u16,
        3 => u24,
        4 => u32,
        8 => u64,
    };

    Ok(())
}
