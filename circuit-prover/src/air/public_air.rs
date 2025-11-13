//! [`PublicAir`] stores public inputs either in the base field or the extension field (of extension degree `D`).
//!
//! # Columns:
//!
//! The AIR has `D + 1` columns:
//!
//! - `D` columns for the constant value,
//! - 1 column for the index of the constant within the witness table.
//!
//! # Constraints
//!
//! The AIR has no constraints.
//!
//! # Global Interactions
//!
//! There is one interaction with the witness bus:
//! - send (index, value)

use alloc::vec::Vec;
use core::marker::PhantomData;

use p3_air::{Air, AirBuilder, BaseAir};
use p3_circuit::tables::PublicTrace;
use p3_circuit::utils::pad_to_power_of_two;
use p3_field::{BasedVectorSpace, Field};
use p3_matrix::dense::RowMajorMatrix;

/// PublicAir: vector-valued public input binding with generic extension degree D.
/// Layout per row: [value[0..D-1], index] → width = D + 1
#[derive(Debug, Clone)]
pub struct PublicAir<F, const D: usize = 1> {
    pub height: usize,
    _phantom: PhantomData<F>,
}

impl<F: Field, const D: usize> PublicAir<F, D> {
    pub const fn new(height: usize) -> Self {
        Self {
            height,
            _phantom: PhantomData,
        }
    }

    /// Flatten a PublicTrace over an extension into a base-field matrix with D limbs + index.
    pub fn trace_to_matrix<ExtF: BasedVectorSpace<F>>(
        trace: &PublicTrace<ExtF>,
    ) -> RowMajorMatrix<F> {
        let height = trace.values.len();
        assert_eq!(
            height,
            trace.index.len(),
            "PublicTrace column length mismatch"
        );
        let width = D + 1;

        let mut values = Vec::with_capacity(height * width);
        for i in 0..height {
            let coeffs = trace.values[i].as_basis_coefficients_slice();
            assert_eq!(
                coeffs.len(),
                D,
                "extension degree mismatch for PublicTrace value"
            );
            values.extend_from_slice(coeffs);
            values.push(F::from_u32(trace.index[i].0));
        }

        // Pad to power of two by repeating last row
        pad_to_power_of_two(&mut values, width, height);

        RowMajorMatrix::new(values, width)
    }
}

impl<F: Field, const D: usize> BaseAir<F> for PublicAir<F, D> {
    fn width(&self) -> usize {
        D + 1
    }
}

impl<AB: AirBuilder, const D: usize> Air<AB> for PublicAir<AB::F, D>
where
    AB::F: Field,
{
    fn eval(&self, _builder: &mut AB) {
        // No constraints for public inputs in Stage 1
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec;

    use p3_baby_bear::BabyBear;
    use p3_circuit::WitnessId;
    use p3_field::PrimeCharacteristicRing;
    use p3_field::extension::BinomialExtensionField;
    use p3_matrix::Matrix;
    use p3_uni_stark::{prove, verify};

    use super::*;
    use crate::air::test_utils::build_test_config;

    type F = BabyBear;
    type EF = BinomialExtensionField<F, 4>;

    #[test]
    fn test_public_air_base_field() {
        let n = 8usize;
        let values: Vec<F> = (1..=n as u64).map(F::from_u64).collect();
        let indices: Vec<WitnessId> = (0..n as u32).map(WitnessId).collect();

        let trace = PublicTrace {
            values,
            index: indices,
        };
        let matrix = PublicAir::<F, 1>::trace_to_matrix(&trace);

        // Verify matrix dimensions
        assert_eq!(matrix.width(), 2); // D + 1 = 1 + 1 = 2

        // Check first row (scope the borrow)
        {
            let row0 = matrix.row_slice(0).unwrap();
            assert_eq!(row0[0], F::from_u64(1)); // value
            assert_eq!(row0[1], F::from_u64(0)); // index
        }

        // Check last original row (scope the borrow)
        {
            let last_original_row = n - 1;
            let row_last = matrix.row_slice(last_original_row).unwrap();
            assert_eq!(row_last[0], F::from_u64(n as u64)); // value
            assert_eq!(row_last[1], F::from_u64(last_original_row as u64)); // index
        }

        let config = build_test_config();
        let air = PublicAir::<F, 1>::new(n);
        let pis: Vec<F> = vec![];

        let proof = prove(&config, &air, matrix, &pis);
        verify(&config, &air, &proof, &pis).expect("PublicAir base field verification failed");
    }

    #[test]
    fn test_public_air_extension_field() {
        let a = EF::from_basis_coefficients_slice(&[
            F::from_u64(1),
            F::from_u64(2),
            F::from_u64(3),
            F::from_u64(4),
        ])
        .unwrap();

        let b = EF::from_basis_coefficients_slice(&[
            F::from_u64(5),
            F::from_u64(6),
            F::from_u64(7),
            F::from_u64(8),
        ])
        .unwrap();

        let values = vec![a, b];
        let indices = vec![WitnessId(10), WitnessId(20)];

        let trace = PublicTrace {
            values,
            index: indices,
        };
        let matrix = PublicAir::<F, 4>::trace_to_matrix(&trace);

        // Verify matrix dimensions
        assert_eq!(matrix.width(), 5); // D + 1 = 4 + 1 = 5

        // Check first row - extension field coefficients (scope the borrow)
        {
            let row0 = matrix.row_slice(0).unwrap();
            let a_coeffs = a.as_basis_coefficients_slice();
            assert_eq!(&row0[0..4], a_coeffs);
            assert_eq!(row0[4], F::from_u64(10)); // index
        }

        // Check second row (scope the borrow)
        {
            let row1 = matrix.row_slice(1).unwrap();
            let b_coeffs = b.as_basis_coefficients_slice();
            assert_eq!(&row1[0..4], b_coeffs);
            assert_eq!(row1[4], F::from_u64(20)); // index
        }

        let config = build_test_config();
        let air = PublicAir::<F, 4>::new(2);
        let pis: Vec<F> = vec![];

        let proof = prove(&config, &air, matrix, &pis);
        verify(&config, &air, &proof, &pis).expect("PublicAir extension field verification failed");
    }

    #[test]
    #[should_panic]
    fn test_public_air_mismatched_lengths() {
        let values = vec![F::from_u64(1), F::from_u64(2)];
        let indices = vec![WitnessId(0)]; // Wrong length

        let trace = PublicTrace {
            values,
            index: indices,
        };
        PublicAir::<F, 1>::trace_to_matrix(&trace);
    }
}
