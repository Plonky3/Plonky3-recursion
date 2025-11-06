//! [`ConstAir`] stores constants either in the base field or the extension field (of extension degree `D`).
//!
//!  # Columns
//!
//! The AIR has `D + 1` columns:
//!
//! - 1 column for the index of the constant within the witness table,
//! - `D` columns for the constant value.
//!
//! # Constraints
//!
//! The AIR has no constraints.
//!
//! # Global Interactions
//!
//! There is one interaction with the witness bus:
//! - send (index, value)

#![allow(clippy::needless_range_loop)]
use alloc::vec::Vec;

use p3_air::{Air, AirBuilder, BaseAir};
use p3_circuit::tables::ConstTrace;
use p3_circuit::utils::pad_to_power_of_two;
use p3_field::{BasedVectorSpace, Field};
use p3_matrix::dense::RowMajorMatrix;

/// ConstAir: vector-valued constant binding with generic extension degree D.
///
/// This chip exposes preprocessed constants that don't need to be committed during proving.
/// It serves as the source of truth for constant values in the system, with each row
/// representing a (value, index) pair where the index corresponds to a WitnessId.
///
/// Layout per row: [value[0..D-1], index] → width = D + 1
/// - value[0..D-1]: Extension field value represented as D base field coefficients
/// - index: Preprocessed WitnessId that this constant binds to
#[derive(Debug, Clone)]
pub struct ConstAir<F, const D: usize = 1> {
    pub height: usize,
    _phantom: core::marker::PhantomData<F>,
}

impl<F: Field, const D: usize> ConstAir<F, D> {
    pub const fn new(height: usize) -> Self {
        Self {
            height,
            _phantom: core::marker::PhantomData,
        }
    }

    /// Flatten a ConstTrace over an extension into a base-field matrix with D limbs + index.
    pub fn trace_to_matrix<ExtF: BasedVectorSpace<F>>(
        trace: &ConstTrace<ExtF>,
    ) -> RowMajorMatrix<F> {
        let height = trace.values.len();
        assert_eq!(
            height,
            trace.index.len(),
            "ConstTrace column length mismatch"
        );
        let width = D + 1;

        let mut values = Vec::with_capacity(height * width);
        for i in 0..height {
            let coeffs = trace.values[i].as_basis_coefficients_slice();
            assert_eq!(
                coeffs.len(),
                D,
                "extension degree mismatch for ConstTrace value"
            );
            values.extend_from_slice(coeffs);
            values.push(F::from_u32(trace.index[i].0));
        }

        // Pad to power of two by repeating last row
        pad_to_power_of_two(&mut values, width, height);

        RowMajorMatrix::new(values, width)
    }
}

impl<F: Field, const D: usize> BaseAir<F> for ConstAir<F, D> {
    fn width(&self) -> usize {
        D + 1
    }
}

impl<AB: AirBuilder, const D: usize> Air<AB> for ConstAir<AB::F, D>
where
    AB::F: Field,
{
    fn eval(&self, _builder: &mut AB) {
        // No constraints for constants in Stage 1
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
    fn test_const_air_base_field() {
        // Create a CONST trace with several constant values
        // Toy example used: assert(37 * x - 111 = 0)
        let const_values = vec![
            F::from_u64(37),  // CONST 1 37
            F::from_u64(111), // CONST 3 111
            F::from_u64(0),   // CONST 4 0
        ];
        // Witness IDs these constants bind to
        let const_indices = vec![WitnessId(1), WitnessId(3), WitnessId(4)];

        let trace = ConstTrace {
            index: const_indices,
            values: const_values.clone(),
        };

        // Convert to matrix using the ConstAir
        let matrix = ConstAir::<F, 1>::trace_to_matrix(&trace);

        // Verify matrix dimensions
        //
        // D + 1 = 1 + 1 = 2 (value + index)
        assert_eq!(matrix.width(), 2);

        // Height should be next power of two >= 3
        let height = matrix.height();
        assert_eq!(height, 4);

        // Verify the data layout: [value, index] per row
        let data = &matrix.values;

        // First row: value=37, index=1
        assert_eq!(data[0], F::from_u64(37));
        assert_eq!(data[1], F::from_u64(1));

        // Second row: value=111, index=3
        assert_eq!(data[2], F::from_u64(111));
        assert_eq!(data[3], F::from_u64(3));

        // Third row: value=0, index=4
        assert_eq!(data[4], F::from_u64(0));
        assert_eq!(data[5], F::from_u64(4));

        // Test that we can prove and verify (should succeed since no constraints)
        let config = build_test_config();
        // No public inputs for CONST chip
        let pis: Vec<F> = vec![];

        let air = ConstAir::<F, 1>::new(height);
        let proof = prove(&config, &air, matrix, &pis);
        verify(&config, &air, &proof, &pis).expect("CONST chip verification failed");
    }

    #[test]
    fn test_const_air_extension_field() {
        // Create extension field constants with all non-zero coefficients
        let const1 = EF::from_basis_coefficients_slice(&[
            F::from_u64(1), // a0
            F::from_u64(2), // a1
            F::from_u64(3), // a2
            F::from_u64(4), // a3
        ])
        .unwrap();

        let const2 = EF::from_basis_coefficients_slice(&[
            F::from_u64(5), // b0
            F::from_u64(6), // b1
            F::from_u64(7), // b2
            F::from_u64(8), // b3
        ])
        .unwrap();

        let const_values = vec![const1, const2];
        let const_indices = vec![WitnessId(10), WitnessId(20)];

        let trace = ConstTrace {
            index: const_indices,
            values: const_values,
        };

        // Convert to matrix for D=4 extension field
        let matrix: RowMajorMatrix<F> = ConstAir::<F, 4>::trace_to_matrix(&trace);

        // Verify matrix dimensions: D + 1 = 4 + 1 = 5 (4 value coefficients + 1 index)
        assert_eq!(matrix.width(), 5);
        let height = matrix.height();
        assert_eq!(height, 2);

        let data = &matrix.values;

        // First row: [a0, a1, a2, a3, index] = [1, 2, 3, 4, 10]
        assert_eq!(data[0], F::from_u64(1));
        assert_eq!(data[1], F::from_u64(2));
        assert_eq!(data[2], F::from_u64(3));
        assert_eq!(data[3], F::from_u64(4));
        assert_eq!(data[4], F::from_u64(10));

        // Second row: [b0, b1, b2, b3, index] = [5, 6, 7, 8, 20]
        assert_eq!(data[5], F::from_u64(5));
        assert_eq!(data[6], F::from_u64(6));
        assert_eq!(data[7], F::from_u64(7));
        assert_eq!(data[8], F::from_u64(8));
        assert_eq!(data[9], F::from_u64(20));

        // Test proving and verification for extension field
        let config = build_test_config();
        let pis: Vec<F> = vec![];

        let air = ConstAir::<F, 4>::new(height);
        let proof = prove(&config, &air, matrix, &pis);
        verify(&config, &air, &proof, &pis).expect("Extension field CONST verification failed");
    }
}
