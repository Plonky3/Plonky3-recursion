//! [`ConstAir`] stores constants either in the base field or the extension field (of extension degree `D`).
//!
//! # Column layout
//!
//! The AIR is generic over an extension degree `D`.
//! For each constant entry, we allocate `D + 1` base-field columns.
//!
//! - `D` columns for the constant value (basis coefficients),
//! - `1` column for the `index`: the witness-bus index of the constant.
//!
//! The layout for a single row is:
//!
//! ```text
//!     [value[0], value[1], ..., value[D-1], index]
//! ```
//!
//! # Constraints
//!
//! The AIR has no constraints.
//!
//! # Global Interactions
//!
//! There is one interaction with the global witness bus:
//!
//! - send (index, value)

use alloc::vec::Vec;
use core::marker::PhantomData;

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
    /// Total number of constants defined in this trace.
    pub height: usize,
    /// Preprocessed values, corresponding to the indices in the trace.
    pub preprocessed: Vec<F>,
    /// Marker tying this AIR to its base field.
    _phantom: PhantomData<F>,
}

impl<F: Field, const D: usize> ConstAir<F, D> {
    /// Construct a new `ConstAir` instance.
    ///
    /// - `height`: The number of constant values to be exposed.
    pub const fn new(height: usize) -> Self {
        Self {
            height,
            preprocessed: Vec::new(),
            _phantom: PhantomData,
        }
    }

    pub const fn new_with_preprocessed(height: usize, preprocessed: Vec<F>) -> Self {
        Self {
            height,
            preprocessed,
            _phantom: PhantomData,
        }
    }

    /// Convert a `ConstTrace` into a `RowMajorMatrix` suitable for the STARK prover.
    ///
    /// This function is responsible for:
    ///
    /// 1. Decomposing each extension element in the trace into `D` basis coordinates.
    /// 2. Padding the trace to have a power-of-two number of rows.
    pub fn trace_to_matrix<ExtF: BasedVectorSpace<F>>(
        trace: &ConstTrace<ExtF>,
    ) -> RowMajorMatrix<F> {
        let height = trace.values.len();
        assert_eq!(
            height,
            trace.index.len(),
            "ConstTrace column length mismatch: values vs indices"
        );
        let width = D;

        let mut values = Vec::with_capacity(height * width);

        // Iterate over values and indices, populating the flat vector.
        for i in 0..height {
            // Extract basis coefficients.
            let coeffs = trace.values[i].as_basis_coefficients_slice();
            assert_eq!(
                coeffs.len(),
                D,
                "extension degree mismatch for ConstTrace value"
            );
            // Copy coefficients into the first D columns.
            values.extend_from_slice(coeffs);
        }

        // Pad to power of two by repeating last row
        pad_to_power_of_two(&mut values, width, height);

        RowMajorMatrix::new(values, width)
    }

    pub fn prep_from_trace<ExtF: BasedVectorSpace<F>>(trace: &ConstTrace<ExtF>) -> Vec<F> {
        trace
            .index
            .iter()
            .map(|widx| F::from_u64(widx.0 as u64))
            .collect()
    }
}

impl<F: Field, const D: usize> BaseAir<F> for ConstAir<F, D> {
    fn width(&self) -> usize {
        D
    }

    fn preprocessed_trace(&self) -> Option<RowMajorMatrix<F>> {
        let mut prep_values = self.preprocessed.clone();
        pad_to_power_of_two(&mut prep_values, 1, self.preprocessed.len());

        Some(RowMajorMatrix::new(
            prep_values,
            1, // single preprocessed column for indices
        ))
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
    use p3_uni_stark::{prove_with_preprocessed, setup_preprocessed, verify_with_preprocessed};
    use p3_util::log2_ceil_usize;

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
        let num_const_indices = const_indices.len();

        let prep_values = const_indices
            .clone()
            .iter()
            .map(|idx| F::from_u64(idx.0 as u64))
            .collect::<Vec<_>>();

        let trace = ConstTrace {
            index: const_indices.clone(),
            values: const_values,
        };

        // Convert to matrix using the ConstAir
        let matrix = ConstAir::<F, 1>::trace_to_matrix(&trace);

        // Verify matrix dimensions
        //
        // D + 1 = 1 + 1 = 2 (value + index)
        assert_eq!(matrix.width(), 1);

        // Height should be next power of two >= 3
        let height = matrix.height();
        assert_eq!(height, 4);

        // Verify the data layout: [value, index] per row
        let data = &matrix.values;

        // First row: value=37, index=1
        assert_eq!(data[0], F::from_u64(37));

        // Second row: value=111, index=3
        assert_eq!(data[1], F::from_u64(111));

        // Third row: value=0, index=4
        assert_eq!(data[2], F::from_u64(0));

        // Test that we can prove and verify (should succeed since no constraints)
        let config = build_test_config();
        // No public inputs for CONST chip
        let pis: Vec<F> = vec![];

        let air = ConstAir::<F, 1>::new_with_preprocessed(height, prep_values);

        let prep_matrix = air.preprocessed_trace().unwrap();

        for i in 0..num_const_indices {
            let row = prep_matrix.row_slice(i).unwrap();
            assert_eq!(row[0], F::from_u32(const_indices[i].0));
        }

        let (prover_data, verifier_data) =
            setup_preprocessed(&config, &air, log2_ceil_usize(height)).unwrap();
        let proof = prove_with_preprocessed(&config, &air, matrix, &pis, Some(&prover_data));
        verify_with_preprocessed(&config, &air, &proof, &pis, Some(&verifier_data))
            .expect("CONST chip verification failed");
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
        let prep_values = const_indices
            .iter()
            .map(|idx| F::from_u64(idx.0 as u64))
            .collect::<Vec<_>>();

        let trace = ConstTrace {
            index: const_indices,
            values: const_values,
        };

        // Convert to matrix for D=4 extension field
        let matrix: RowMajorMatrix<F> = ConstAir::<F, 4>::trace_to_matrix(&trace);

        // Verify matrix dimensions: D = 4 (4 value coefficients)
        assert_eq!(matrix.width(), 4);
        let height = matrix.height();
        assert_eq!(height, 2);

        let data = &matrix.values;

        // First row: [a0, a1, a2, a3] = [1, 2, 3, 4]
        assert_eq!(data[0], F::from_u64(1));
        assert_eq!(data[1], F::from_u64(2));
        assert_eq!(data[2], F::from_u64(3));
        assert_eq!(data[3], F::from_u64(4));

        // Second row: [b0, b1, b2, b3] = [5, 6, 7, 8]
        assert_eq!(data[4], F::from_u64(5));
        assert_eq!(data[5], F::from_u64(6));
        assert_eq!(data[6], F::from_u64(7));
        assert_eq!(data[7], F::from_u64(8));

        // Test proving and verification for extension field
        let config = build_test_config();
        let pis: Vec<F> = vec![];

        let air = ConstAir::<F, 4>::new_with_preprocessed(height, prep_values);
        let prep_matrix = air.preprocessed_trace().unwrap();
        let row0 = prep_matrix.row_slice(0).unwrap();
        assert_eq!(row0[0], F::from_u64(10));
        let last_row = prep_matrix.row_slice(height - 1).unwrap();
        assert_eq!(last_row[0], F::from_u64(20));
        let (prover_data, verifier_data) =
            setup_preprocessed(&config, &air, log2_ceil_usize(height)).unwrap();
        let proof = prove_with_preprocessed(&config, &air, matrix, &pis, Some(&prover_data));
        verify_with_preprocessed(&config, &air, &proof, &pis, Some(&verifier_data))
            .expect("Extension field CONST verification failed");
    }
}
