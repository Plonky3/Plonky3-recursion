//! Native binary-field hashing: byte-hash commitments and transcripts over the binary tower,
//! and the characteristic-2 Keccak-f and BLAKE3 AIRs Plonky3 0.8 proves hash computations with.

use p3_blake3_air::Blake3BinaryAir;
use p3_challenger::{CanObserve, CanSample, CanSampleBits};
use p3_commit::Mmcs;
use p3_field::{Field, PrimeCharacteristicRing};
use p3_keccak_air::KeccakBinaryAir;
use p3_matrix::Matrix;
use p3_matrix::dense::RowMajorMatrix;
use p3_test_utils::air_satisfaction::{assert_air_rejects, assert_air_satisfies};
use p3_test_utils::binary_field_params::{
    BinaryField32, BinaryField128, F, TowerLevel, blake3, keccak,
};

/// A deterministic matrix whose entries use every byte of the element.
fn matrix<L: TowerLevel>(height: usize, width: usize, salt: u8) -> RowMajorMatrix<L> {
    let values = (0..height * width)
        .map(|i| {
            L::from_le_byte_iter(
                (0..L::NUM_BYTES).map(|j| (i as u8).wrapping_mul(31).wrapping_add(j as u8) ^ salt),
            )
        })
        .collect();
    RowMajorMatrix::new(values, width)
}

macro_rules! mmcs_suite {
    ($($name:ident => $params:ident),* $(,)?) => {$(
        mod $name {
            use super::*;

            fn roundtrip<L: TowerLevel>() {
                let mmcs = $params::level_mmcs::<L>();
                // Two heights, so the tree injects the shorter matrix partway up.
                let tall = matrix::<L>(8, 3, 1);
                let short = matrix::<L>(4, 5, 2);
                let (commitment, data) = mmcs.commit(vec![tall.clone(), short.clone()]);
                let dims = [tall.dimensions(), short.dimensions()];
                for index in 0..8 {
                    let opening = mmcs.open_batch(index, &data);
                    mmcs.verify_batch(&commitment, &dims, index, (&opening).into())
                        .expect("an honest binary opening verifies");

                    let mut tampered = opening.clone();
                    tampered.opened_values[0][0] += L::ONE;
                    assert!(mmcs
                        .verify_batch(&commitment, &dims, index, (&tampered).into())
                        .is_err());
                }
            }

            #[test]
            fn commitment_roundtrips_over_gf_2_128() {
                roundtrip::<BinaryField128>();
            }

            #[test]
            fn commitment_roundtrips_over_gf_2_32() {
                roundtrip::<BinaryField32>();
            }

            #[test]
            fn transcript_is_deterministic_and_binds_observations() {
                let mut first = $params::challenger();
                let mut second = $params::challenger();
                let mut diverged = $params::challenger();
                let a = F::from_le_bytes([7; 16]);
                first.observe(a);
                second.observe(a);
                diverged.observe(a + F::ONE);

                let x: F = first.sample();
                assert_eq!(x, second.sample());
                assert_ne!(x, diverged.sample());

                for bits in [1, 8, 20] {
                    assert!(first.sample_bits(bits) < 1 << bits);
                }
            }
        }
    )*};
}

mmcs_suite! {
    keccak_mmcs => keccak,
    blake3_mmcs => blake3,
}

#[test]
fn keccak_and_blake3_commit_and_sample_differently() {
    let data = matrix::<F>(4, 2, 9);
    let (keccak_root, _) = keccak::mmcs().commit_matrix(data.clone());
    let (blake3_root, _) = blake3::mmcs().commit_matrix(data);
    assert_ne!(keccak_root.roots(), blake3_root.roots());

    let mut keccak_ch = keccak::challenger();
    let mut blake3_ch = blake3::challenger();
    let a: F = keccak_ch.sample();
    let b: F = blake3_ch.sample();
    assert_ne!(a, b);
}

/// The trace with one first-row cell flipped (`x -> x + 1`).
fn flip_first_row_cell<F: Field>(trace: &RowMajorMatrix<F>, column: usize) -> RowMajorMatrix<F> {
    let mut tampered = trace.clone();
    tampered.values[column] += F::ONE;
    tampered
}

#[test]
fn keccak_f_binary_air_accepts_its_trace_and_rejects_tampering() {
    let air = KeccakBinaryAir::default();
    let trace = air.generate_random_trace_rows::<F>(1, 0);
    assert_air_satisfies::<F, F, _>(&air, &trace);

    // A non-bit cell breaks booleanity; a flipped bit breaks the round map.
    let mut non_bit = trace.clone();
    non_bit.values[0] = F::GENERATOR;
    assert_air_rejects::<F, F, _>(&air, &non_bit);
    assert_air_rejects::<F, F, _>(&air, &flip_first_row_cell(&trace, trace.width() - 1));
}

#[test]
fn blake3_binary_air_accepts_its_trace_and_rejects_tampering() {
    let air = Blake3BinaryAir::default();
    let trace = air.generate_random_trace_rows::<F>(4, 0);
    assert_air_satisfies::<F, F, _>(&air, &trace);

    let mut non_bit = trace.clone();
    non_bit.values[0] = F::GENERATOR;
    assert_air_rejects::<F, F, _>(&air, &non_bit);
    assert_air_rejects::<F, F, _>(&air, &flip_first_row_cell(&trace, trace.width() - 1));
}
