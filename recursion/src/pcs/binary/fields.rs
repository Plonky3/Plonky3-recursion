//! Native fields whose raw coordinates embed in the 128-bit Wiedemann tower.

use p3_binary_field::{
    BinaryField8, BinaryField16, BinaryField32, BinaryField64, BinaryField128, TowerLevel,
};
use p3_challenger::fs::TranscriptField;

mod sealed {
    pub trait Tower {}
    pub trait Challenge {}
}

/// Released byte-aligned Wiedemann tower fields supported by the recursive PCS.
/// This sealed contract pins both native transcript encoding and zero-extension
/// into the 128-bit arithmetic basis. Polynomial and AES bases use other adapters.
pub trait RecursiveBinaryTowerField: TowerLevel + TranscriptField + sealed::Tower {
    const RAW_BITS: usize;
    fn raw_coordinates(self) -> u128;
}

/// Tower challenge widths priced by the released binary PCS security model.
pub trait RecursiveBinaryChallengeField: RecursiveBinaryTowerField + sealed::Challenge {}

macro_rules! field {
    ($field:ty, $bits:literal) => {
        impl sealed::Tower for $field {}
        impl RecursiveBinaryTowerField for $field {
            const RAW_BITS: usize = $bits;
            fn raw_coordinates(self) -> u128 {
                self.to_repr() as u128
            }
        }
    };
}

field!(BinaryField8, 8);
field!(BinaryField16, 16);
field!(BinaryField32, 32);
field!(BinaryField64, 64);
field!(BinaryField128, 128);
impl sealed::Challenge for BinaryField64 {}
impl sealed::Challenge for BinaryField128 {}
impl RecursiveBinaryChallengeField for BinaryField64 {}
impl RecursiveBinaryChallengeField for BinaryField128 {}
