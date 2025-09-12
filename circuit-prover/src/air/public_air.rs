#![allow(clippy::needless_range_loop)]
use alloc::vec::Vec;

use p3_air::{Air, AirBuilder, BaseAir};
use p3_circuit::tables::PublicTrace;
use p3_field::{BasedVectorSpace, Field};
use p3_matrix::dense::RowMajorMatrix;

use super::utils::pad_to_power_of_two;

/// PublicAir: vector-valued public input binding with generic extension degree D.
/// Layout per row: [value[0..D-1], index] → width = D + 1
#[derive(Debug, Clone)]
pub struct PublicAir<F, const D: usize = 1> {
    pub height: usize,
    _phantom: core::marker::PhantomData<F>,
}

impl<F: Field, const D: usize> PublicAir<F, D> {
    pub fn new(height: usize) -> Self {
        Self {
            height,
            _phantom: core::marker::PhantomData,
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
            values.push(F::from_u64(trace.index[i] as u64));
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
