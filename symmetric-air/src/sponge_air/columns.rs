use core::borrow::{Borrow, BorrowMut};
use core::mem::size_of;

/// Columns for the sponge AIR which hashes an arbitrary-length input.
#[repr(C)]
pub struct SpongeCols<T, const RATE: usize, const CAPACITY: usize> {
    // Flag to clear the capacity, which will clear the state.
    // Preprocessed.
    pub reset: T,
    // When set to 1, the rate is overwritten by external input.
    // When set to 0, the rate is copied from the previous row.
    // Preprocessed.
    pub absorb: T,

    pub input_addresses: [T; RATE],

    pub rate: [T; RATE],

    pub capacity: [T; CAPACITY],
}

pub const fn num_cols<const RATE: usize, const CAPACITY: usize>() -> usize {
    size_of::<SpongeCols<u8, RATE, CAPACITY>>()
}

impl<T, const RATE: usize, const CAPACITY: usize> Borrow<SpongeCols<T, RATE, CAPACITY>> for [T] {
    fn borrow(&self) -> &SpongeCols<T, RATE, CAPACITY> {
        let (prefix, shorts, suffix) = unsafe { self.align_to::<SpongeCols<T, RATE, CAPACITY>>() };
        debug_assert!(prefix.is_empty(), "Alignment should match");
        debug_assert!(suffix.is_empty(), "Alignment should match");
        debug_assert_eq!(shorts.len(), 1);
        &shorts[0]
    }
}

impl<T, const RATE: usize, const CAPACITY: usize> BorrowMut<SpongeCols<T, RATE, CAPACITY>>
    for [T]
{
    fn borrow_mut(&mut self) -> &mut SpongeCols<T, RATE, CAPACITY> {
        let (prefix, shorts, suffix) =
            unsafe { self.align_to_mut::<SpongeCols<T, RATE, CAPACITY>>() };
        debug_assert!(prefix.is_empty(), "Alignment should match");
        debug_assert!(suffix.is_empty(), "Alignment should match");
        debug_assert_eq!(shorts.len(), 1);
        &mut shorts[0]
    }
}
