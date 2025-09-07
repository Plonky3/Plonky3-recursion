use p3_air::{Air, AirBuilder, BaseAir};
use p3_field::{Field, PrimeCharacteristicRing};
use p3_matrix::{dense::RowMajorMatrix, Matrix};

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

    /// Build a matrix from limb values and indices (already flattened to base field limbs).
    /// values_lims: row-major [value[0..D-1]] limbs per row
    pub fn trace_to_matrix(values_limbs: &[F], indices: &[u32]) -> RowMajorMatrix<F> {
        let height = indices.len();
        assert_eq!(
            values_limbs.len(),
            height * D,
            "values_limbs must be height*D"
        );
        let width = D + 1;
        let mut v = Vec::with_capacity(height * width);
        for i in 0..height {
            let base = i * D;
            for j in 0..D {
                v.push(values_limbs[base + j]);
            }
            v.push(F::from_u64(indices[i] as u64));
        }

        // Pad to power of two with monotonic index continuation
        pad_witness_to_power_of_two(&mut v, width, height);

        RowMajorMatrix::new(v, width)
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
        let matrix = WitnessAir::<Val, 1>::trace_to_matrix(&values, &indices);
        assert_eq!(matrix.height(), n);
        assert_eq!(matrix.width(), 2);

        let config = build_test_config();
        let air = WitnessAir::<Val, 1>::new(n);
        let pis: Vec<Val> = vec![];

        let proof = prove(&config, &air, matrix, &pis);
        verify(&config, &air, &proof, &pis).expect("verification failed");
    }
}
