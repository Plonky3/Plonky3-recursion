use p3_air::{Air, AirBuilder, BaseAir};
use p3_field::{BasedVectorSpace, Field, PrimeCharacteristicRing};
use p3_matrix::{dense::RowMajorMatrix, Matrix};
use p3_program::tables::WitnessTrace;

use super::utils::pad_witness_to_power_of_two;

/// WitnessAir: enforces transparent index column monotonicity.
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
    pub fn new(height: usize) -> Self {
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
            for j in 0..D {
                values.push(coeffs[j]);
            }
            values.push(F::from_u64(trace.index[i] as u64));
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
    use super::*;
    use crate::air::test_utils::build_test_config;
    use p3_baby_bear::BabyBear as Val;
    use p3_field::PrimeCharacteristicRing;
    use p3_uni_stark::{prove, verify};

    #[test]
    fn prove_verify_witness_index_monotone() {
        let n = 8usize;
        // Use D=1; values can be arbitrary (unused by constraints)
        let values: Vec<Val> = vec![Val::from_u64(123); n];
        let indices: Vec<u32> = (0..n as u32).collect();

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
}
