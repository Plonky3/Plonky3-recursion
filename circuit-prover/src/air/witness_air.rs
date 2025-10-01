#![allow(clippy::needless_range_loop)]
use alloc::vec::Vec;

use p3_air::{Air, AirBuilder, BaseAir};
use p3_circuit::tables::WitnessTrace;
use p3_field::{BasedVectorSpace, Field, PrimeCharacteristicRing};
use p3_matrix::Matrix;
use p3_matrix::dense::RowMajorMatrix;

use super::utils::pad_witness_to_power_of_two;

/// WitnessAir: enforces preprocessed index column monotonicity.
/// Layout per row: [value[0..D-1], index]
/// Constraints:
///  - index[0] = 0
///  - for all i>0: index[i] = index[i-1] + 1
#[derive(Debug, Clone)]
pub struct WitnessAir<F, const D: usize = 1> {
    pub height: usize,
    _phantom: core::marker::PhantomData<F>,
}

impl<F: Field, const D: usize> WitnessAir<F, D> {
    pub const fn new(height: usize) -> Self {
        Self {
            height,
            _phantom: core::marker::PhantomData,
        }
    }

    /// Convert WitnessTrace to RowMajorMatrix for proving with generic extension degree D
    /// Layout: [value[0..D-1], index]
    pub fn trace_to_matrix<ExtF: BasedVectorSpace<F>>(
        trace: &WitnessTrace<ExtF>,
    ) -> RowMajorMatrix<F> {
        let height = trace.values.len();
        assert_eq!(
            height,
            trace.index.len(),
            "WitnessTrace column length mismatch"
        );
        let width = D + 1;

        let mut values = Vec::with_capacity(height * width);
        for i in 0..height {
            let coeffs = trace.values[i].as_basis_coefficients_slice();
            assert_eq!(
                coeffs.len(),
                D,
                "Extension field degree mismatch for witness value"
            );
            values.extend_from_slice(coeffs);
            values.push(F::from_u64(trace.index[i].0 as u64));
        }

        // Pad to power of two with monotonic index continuation
        pad_witness_to_power_of_two(&mut values, width, height);

        RowMajorMatrix::new(values, width)
    }
}

impl<F: Field, const D: usize> BaseAir<F> for WitnessAir<F, D> {
    fn width(&self) -> usize {
        D + 1
    }
}

impl<AB: AirBuilder, const D: usize> Air<AB> for WitnessAir<AB::F, D>
where
    AB::F: Field,
{
    fn eval(&self, builder: &mut AB) {
        // First row: index == 0
        {
            let main = builder.main();
            let local = main.row_slice(0).expect("non-empty");
            let index0 = local[D].clone();
            builder.when_first_row().assert_zero(index0);
        }

        // Transitions: next_index - cur_index - 1 == 0
        // Use builder scoping to avoid borrow conflicts
        {
            let mut b = builder.when_transition();
            let main = b.main();
            let cur = main.row_slice(0).expect("non-empty");
            let nxt = main.row_slice(1).expect("has next row");
            let idx_cur = cur[D].clone();
            let idx_next = nxt[D].clone();
            b.assert_zero(idx_next - idx_cur - AB::Expr::from(AB::F::ONE));
        }
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec;

    use p3_baby_bear::BabyBear as Val;
    use p3_circuit::WitnessId;
    use p3_field::PrimeCharacteristicRing;
    use p3_matrix::Matrix;
    use p3_uni_stark::{prove, verify};

    use super::*;
    use crate::air::test_utils::build_test_config;

    #[test]
    fn prove_verify_witness_index_monotone() {
        let n = 8usize;
        // Use D=1; values can be arbitrary (unused by constraints)
        let values: Vec<Val> = vec![Val::from_u64(123); n];
        let indices: Vec<WitnessId> = (0..n as u32).map(WitnessId).collect();

        let trace = WitnessTrace {
            values,
            index: indices,
        };
        let matrix = WitnessAir::<Val, 1>::trace_to_matrix(&trace);
        assert_eq!(matrix.height(), n);
        assert_eq!(matrix.width(), 2);

        let config = build_test_config();
        let air = WitnessAir::<Val, 1>::new(n);
        let pis: Vec<Val> = vec![];

        let proof = prove(&config, &air, matrix, &pis);
        verify(&config, &air, &proof, &pis).expect("verification failed");
    }

    #[test]
    fn test_witness_air_extension_field() {
        use p3_field::BasedVectorSpace;
        use p3_field::extension::BinomialExtensionField;

        type Ext4 = BinomialExtensionField<Val, 4>;

        let a = Ext4::from_basis_coefficients_slice(&[
            Val::from_u64(1),
            Val::from_u64(2),
            Val::from_u64(3),
            Val::from_u64(4),
        ])
        .unwrap();

        let b = Ext4::from_basis_coefficients_slice(&[
            Val::from_u64(5),
            Val::from_u64(6),
            Val::from_u64(7),
            Val::from_u64(8),
        ])
        .unwrap();

        let values = vec![a, b];
        let indices = vec![WitnessId(0), WitnessId(1)];

        let trace = WitnessTrace {
            values,
            index: indices,
        };
        let matrix = WitnessAir::<Val, 4>::trace_to_matrix(&trace);

        // Verify dimensions: D + 1 = 4 + 1 = 5 columns
        assert_eq!(matrix.width(), 5);
        assert_eq!(matrix.height(), 2);

        // Check first row layout: [a_coeffs[0..3], index]
        {
            let row0 = matrix.row_slice(0).unwrap();
            let a_coeffs = a.as_basis_coefficients_slice();
            assert_eq!(&row0[0..4], a_coeffs);
            assert_eq!(row0[4], Val::from_u64(0)); // index
        }

        let config = build_test_config();
        let air = WitnessAir::<Val, 4>::new(2);
        let pis: Vec<Val> = vec![];

        let proof = prove(&config, &air, matrix, &pis);
        verify(&config, &air, &proof, &pis).expect("Extension field verification failed");
    }

    #[test]
    fn test_witness_air_single_element() {
        let values = vec![Val::from_u64(42)];
        let indices = vec![WitnessId(0)];

        let trace = WitnessTrace {
            values,
            index: indices,
        };
        let matrix = WitnessAir::<Val, 1>::trace_to_matrix(&trace);

        // Should be padded to power of two
        assert!(matrix.height().is_power_of_two());
        assert_eq!(matrix.width(), 2);

        // Check the single element
        {
            let row0 = matrix.row_slice(0).unwrap();
            assert_eq!(row0[0], Val::from_u64(42)); // value
            assert_eq!(row0[1], Val::from_u64(0)); // index = 0
        }

        let config = build_test_config();
        let air = WitnessAir::<Val, 1>::new(1);
        let pis: Vec<Val> = vec![];

        let proof = prove(&config, &air, matrix, &pis);
        verify(&config, &air, &proof, &pis).expect("Single element verification failed");
    }

    #[test]
    fn test_witness_air_matrix_padding() {
        let n = 3; // Not a power of two
        let values: Vec<Val> = (1..=n as u64).map(Val::from_u64).collect();
        let indices: Vec<WitnessId> = (0..n as u32).map(WitnessId).collect();

        let trace = WitnessTrace {
            values,
            index: indices,
        };
        let matrix = WitnessAir::<Val, 1>::trace_to_matrix(&trace);

        // Should be padded to next power of two (4)
        assert_eq!(matrix.height(), 4);
        assert!(matrix.height().is_power_of_two());

        // Original rows should be preserved
        for i in 0..n {
            let row = matrix.row_slice(i).unwrap();
            assert_eq!(row[0], Val::from_u64((i + 1) as u64)); // value
            assert_eq!(row[1], Val::from_u64(i as u64)); // index
        }

        // Padded row should continue monotonic sequence
        {
            let last_row = matrix.row_slice(3).unwrap();
            assert_eq!(last_row[0], Val::from_u64(3)); // last value repeated
            assert_eq!(last_row[1], Val::from_u64(3)); // index continues: 2 + 1 = 3
        }

        let config = build_test_config();
        let air = WitnessAir::<Val, 1>::new(3);
        let pis: Vec<Val> = vec![];

        let proof = prove(&config, &air, matrix, &pis);
        verify(&config, &air, &proof, &pis).expect("Padding verification failed");
    }
}
