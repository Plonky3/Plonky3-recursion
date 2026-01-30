//! [`PublicAir`] stores public inputs either in the base field or the extension field (of extension degree `D`).
//!
//! # Columns:
//!
//! The AIR has a total of `D + 1` columns:
//!
//! - `D` main columns for the constant value,
//! - 1 preprocessed column for the index of the constant within the witness table.
//!
//! # Constraints
//!
//! The AIR has no constraints.
//!
//! # Global Interactions
//!
//! There is one interaction with the witness bus:
//! - send (index, value)

use alloc::string::ToString;
use alloc::vec;
use alloc::vec::Vec;
use core::marker::PhantomData;

use p3_air::{Air, AirBuilder, AirBuilderWithPublicValues, BaseAir, PermutationAirBuilder};
use p3_circuit::tables::PublicTrace;
use p3_field::{BasedVectorSpace, Field};
use p3_lookup::lookup_traits::{Direction, Kind, Lookup};
use p3_matrix::Matrix;
use p3_matrix::dense::RowMajorMatrix;
use p3_uni_stark::SymbolicAirBuilder;

use crate::air::utils::get_index_lookups;

/// PublicAir: vector-valued public input binding with generic extension degree D.
/// Layout per row: [value[0..D-1], index] → width = D + 1
#[derive(Debug, Clone)]
pub struct PublicAir<F, const D: usize = 1> {
    /// Height of the trace, i.e., number of public inputs.
    pub height: usize,
    /// Preprocessed witness indices for the public inputs.
    pub preprocessed: Vec<F>,
    _phantom: PhantomData<F>,
}

impl<F: Field, const D: usize> PublicAir<F, D> {
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

    /// Number of preprocessed columns: multiplicity + index
    pub const fn preprocessed_width() -> usize {
        2 // One column for multiplicity, one for index
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
        let width = D;

        let mut values = Vec::with_capacity(height * width);
        for i in 0..height {
            let coeffs = trace.values[i].as_basis_coefficients_slice();
            assert_eq!(
                coeffs.len(),
                D,
                "extension degree mismatch for PublicTrace value"
            );
            values.extend_from_slice(coeffs);
        }

        // Pad to power of two by repeating last row
        let mut mat = RowMajorMatrix::new(values, width);
        mat.pad_to_power_of_two_height(F::ZERO);

        mat
    }

    pub fn trace_to_preprocessed<ExtF: BasedVectorSpace<F>>(trace: &PublicTrace<ExtF>) -> Vec<F> {
        trace
            .index
            .iter()
            .map(|widx| F::from_u64(widx.0 as u64))
            .collect()
    }
}

impl<F: Field, const D: usize> BaseAir<F> for PublicAir<F, D> {
    fn width(&self) -> usize {
        D
    }

    fn preprocessed_trace(&self) -> Option<RowMajorMatrix<F>> {
        let preprocessed_values = self
            .preprocessed
            .iter()
            .flat_map(|v| [F::ONE, *v])
            .collect::<Vec<F>>();
        let mut mat = RowMajorMatrix::new(preprocessed_values, 2);
        mat.pad_to_power_of_two_height(F::ZERO);

        Some(mat)
    }
}

impl<AB: AirBuilder, const D: usize> Air<AB> for PublicAir<AB::F, D>
where
    AB::F: Field,
{
    fn eval(&self, _builder: &mut AB) {
        // No constraints for public inputs in Stage 1
    }

    fn add_lookup_columns(&mut self) -> Vec<usize> {
        // There is only one lookup to register in this AIR.
        vec![0]
    }

    fn get_lookups(&mut self) -> Vec<Lookup<<AB>::F>>
    where
        AB: PermutationAirBuilder + AirBuilderWithPublicValues,
    {
        // Create symbolic air builder to access symbolic variables
        let symbolic_air_builder = SymbolicAirBuilder::<AB::F>::new(
            Self::preprocessed_width(),
            BaseAir::<AB::F>::width(self),
            0,
            1,
            0,
        );

        let symbolic_main = symbolic_air_builder.main();
        let symbolic_main_local = symbolic_main.row_slice(0).unwrap();

        let preprocessed = symbolic_air_builder
            .preprocessed()
            .expect("Expected preprocessed columns");
        let preprocessed_local = preprocessed.row_slice(0).unwrap();

        let lookup_inps = get_index_lookups::<AB, D>(
            0,
            0,
            1,
            &symbolic_main_local,
            &preprocessed_local,
            Direction::Send,
        );

        assert!(lookup_inps.len() == 1);
        let lookup = <Self as Air<AB>>::register_lookup(
            self,
            Kind::Global("WitnessChecks".to_string()),
            &lookup_inps,
        );

        vec![lookup]
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
    fn test_public_air_base_field() {
        let n = 8usize;
        let values: Vec<F> = (1..=n as u64).map(F::from_u64).collect();
        let indices: Vec<WitnessId> = (0..n as u32).map(WitnessId).collect();

        // Get preprocessed index values.
        let preprocessed_values = indices
            .iter()
            .map(|idx| F::from_u64(idx.0 as u64))
            .collect::<Vec<_>>();

        let trace = PublicTrace {
            values,
            index: indices,
        };

        let matrix = PublicAir::<F, 1>::trace_to_matrix(&trace);

        // Verify matrix dimensions
        assert_eq!(matrix.width(), 1); // D = 1

        // Check first row (scope the borrow)
        {
            let row0 = matrix.row_slice(0).unwrap();
            assert_eq!(row0[0], F::from_u64(1)); // value
        }

        // Check last original row (scope the borrow)
        {
            let last_original_row = n - 1;
            let row_last = matrix.row_slice(last_original_row).unwrap();
            assert_eq!(row_last[0], F::from_u64(n as u64)); // value
        }

        let config = build_test_config();
        let air = PublicAir::<F, 1>::new_with_preprocessed(n, preprocessed_values);
        let (prover_data, verifier_data) =
            setup_preprocessed(&config, &air, log2_ceil_usize(matrix.height())).unwrap();

        // Check the correctness of preprocessed values.
        let preprocessed = air.preprocessed_trace().unwrap();
        let row0 = preprocessed.row_slice(0).unwrap();
        let last_row = preprocessed.row_slice(n - 1).unwrap();
        // The multiplicity is 1 for active rows.
        assert_eq!(row0[0], F::from_u64(1)); // first index
        assert_eq!(last_row[0], F::from_u64(1)); // last index
        // Check the witness indices.
        assert_eq!(row0[1], F::from_u64(0)); // first index
        assert_eq!(last_row[1], F::from_u64((n - 1) as u64)); // last index

        let pis: Vec<F> = vec![];

        let proof = prove_with_preprocessed(&config, &air, matrix, &pis, Some(&prover_data));
        verify_with_preprocessed(&config, &air, &proof, &pis, Some(&verifier_data))
            .expect("PublicAir base field verification failed");
    }

    #[test]
    fn test_public_air_padding() {
        let n = 5usize;
        let values: Vec<F> = (1..=n as u64).map(F::from_u64).collect();
        let indices: Vec<WitnessId> = (0..n as u32).map(WitnessId).collect();

        // Get preprocessed index values.
        let preprocessed_values = indices
            .iter()
            .map(|idx| F::from_u64(idx.0 as u64))
            .collect::<Vec<_>>();

        let trace = PublicTrace {
            values,
            index: indices,
        };

        let matrix = PublicAir::<F, 1>::trace_to_matrix(&trace);

        // Verify matrix dimensions
        assert_eq!(matrix.width(), 1); // D = 1
        assert_eq!(matrix.height(), 8); // Padded to next power of two

        // Check first row (scope the borrow)
        {
            let row0 = matrix.row_slice(0).unwrap();
            assert_eq!(row0[0], F::from_u64(1)); // value
        }

        // Check last original row (scope the borrow)
        {
            let last_original_row = n - 1;
            let row_last = matrix.row_slice(last_original_row).unwrap();
            assert_eq!(row_last[0], F::from_u64(n as u64)); // value
        }
        // Check padded rows (scope the borrow)
        {
            for i in n..matrix.height() {
                let row = matrix.row_slice(i).unwrap();
                assert_eq!(row[0], F::ZERO); // value
            }
        }

        let config = build_test_config();
        let air = PublicAir::<F, 1>::new_with_preprocessed(n, preprocessed_values);
        let (prover_data, verifier_data) =
            setup_preprocessed(&config, &air, log2_ceil_usize(matrix.height())).unwrap();

        // Check the correctness of preprocessed values.
        let preprocessed = air.preprocessed_trace().unwrap();
        assert!(preprocessed.height() == 8);
        for i in 0..n {
            let row = preprocessed.row_slice(i).unwrap();
            // The multiplicity is 1 for active rows.
            assert_eq!(row[0], F::from_u64(1)); // first index
            // Check the witness indices.
            assert_eq!(row[1], F::from_u64(i as u64)); // first index
        }
        for i in n..preprocessed.height() {
            let row = preprocessed.row_slice(i).unwrap();
            // The multiplicity is 0 for padded rows.
            assert_eq!(row[0], F::ZERO); // first index
            // Check the witness indices.
            assert_eq!(row[1], F::ZERO); // last original index
        }

        let pis: Vec<F> = vec![];

        let proof = prove_with_preprocessed(&config, &air, matrix, &pis, Some(&prover_data));
        verify_with_preprocessed(&config, &air, &proof, &pis, Some(&verifier_data))
            .expect("PublicAir base field verification failed");
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
        let preprocessed_values = indices
            .iter()
            .map(|idx| F::from_u64(idx.0 as u64))
            .collect();

        let trace = PublicTrace {
            values,
            index: indices,
        };
        let matrix = PublicAir::<F, 4>::trace_to_matrix(&trace);

        // Verify matrix dimensions
        assert_eq!(matrix.width(), 4); // D = 4

        // Check first row - extension field coefficients (scope the borrow)
        {
            let row0 = matrix.row_slice(0).unwrap();
            let a_coeffs = a.as_basis_coefficients_slice();
            assert_eq!(&row0[0..4], a_coeffs);
        }

        // Check second row (scope the borrow)
        {
            let row1 = matrix.row_slice(1).unwrap();
            let b_coeffs = b.as_basis_coefficients_slice();
            assert_eq!(&row1[0..4], b_coeffs);
        }

        let config = build_test_config();
        let air = PublicAir::<F, 4>::new_with_preprocessed(2, preprocessed_values);
        let (prover_data, verifier_data) =
            setup_preprocessed(&config, &air, log2_ceil_usize(matrix.height())).unwrap();

        let prep = air.preprocessed_trace().unwrap();
        // Check the correctness of preprocessed values.
        let row0 = prep.row_slice(0).unwrap();
        let last_row = prep.row_slice(1).unwrap();
        // The multiplicity is 1 for active rows.
        assert_eq!(row0[0], F::from_u64(1)); // first index
        assert_eq!(last_row[0], F::from_u64(1)); // last index
        // Check the witness indices.
        assert_eq!(row0[1], F::from_u64(10)); // first index
        assert_eq!(last_row[1], F::from_u64(20)); // last index

        let pis: Vec<F> = vec![];

        let proof = prove_with_preprocessed(&config, &air, matrix, &pis, Some(&prover_data));
        verify_with_preprocessed(&config, &air, &proof, &pis, Some(&verifier_data))
            .expect("PublicAir extension field verification failed");
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

    #[test]
    fn test_air_constraint_degree() {
        let air = PublicAir::<F, 1>::new_with_preprocessed(8, vec![F::ZERO; 8]);
        p3_test_utils::assert_air_constraint_degree!(air, "PublicAir");
    }
}
