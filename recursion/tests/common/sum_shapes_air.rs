//! Binary AIRs whose constraints are sums of products and addends: the BLAKE3 carry chain, and
//! one constraint per shape that a native characteristic-two fold takes as fused gates or
//! evaluates node by node.

use core::ops::{Add, Mul};

use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_field::PrimeCharacteristicRing;

/// Columns of [`SumShapesAir`].
pub(crate) const SUM_SHAPE_COLUMNS: usize = 16;

/// The majority of three bits, `(x + z) * (y + z) + z` in characteristic two, as the BLAKE3 AIR
/// states it.
fn maj<E: Clone + Add<Output = E> + Mul<Output = E>>(x: E, y: E, z: E) -> E {
    (x + z.clone()) * (y + z.clone()) + z
}

/// One constraint per shape, over distinct columns unless a shape shares a node on purpose:
/// - a product, its addend and a second addend: majority plus carry, then the other operand
///   orders;
/// - a product and one addend, in both orders;
/// - a sum of two columns, and of a column and a constant;
/// - a sum that the next constraint also reads;
/// - a product that two sums read;
/// - a product alone;
/// - a majority plus carry stated twice.
pub(crate) struct SumShapesAir;
impl<F> BaseAir<F> for SumShapesAir {
    fn width(&self) -> usize {
        SUM_SHAPE_COLUMNS
    }
    fn main_next_row_columns(&self) -> Vec<usize> {
        vec![]
    }
}
impl<AB: AirBuilder> Air<AB> for SumShapesAir {
    fn eval(&self, b: &mut AB) {
        let main = b.main();
        let columns: Vec<AB::Expr> = main.current_slice().iter().map(|&c| c.into()).collect();
        let c = |i: usize| columns[i].clone();
        b.assert_zero(maj(c(0), c(1), c(2)) + c(3));
        b.assert_zero(c(4) + maj(c(5), c(6), c(7)));
        b.assert_zero((c(8) + c(9) * c(10)) + c(11));
        b.assert_zero(c(12) + (c(13) + c(14) * c(15)));
        b.assert_zero(c(0) * c(5) + c(10));
        b.assert_zero(c(15) + c(1) * c(6));
        b.assert_zero(c(2) + c(7));
        b.assert_zero(c(11) + AB::Expr::ONE);
        let shared = c(3) + c(12);
        b.assert_zero(shared.clone());
        b.assert_zero(shared * c(8) + c(13));
        let product = c(4) * c(9);
        b.assert_zero(product.clone() + c(14));
        b.assert_zero(product + c(0) + c(1));
        b.assert_zero(c(6) * c(11));
        for _ in 0..2 {
            b.assert_zero(maj(c(8), c(9), c(10)) + c(12));
        }
    }
}

/// The BLAKE3 AIR's check of `sum = x + y` on `bits`-bit words, over columns `x`, `y` and `sum`.
/// The carry into bit `i + 1` is `sum_i + x_i + y_i`: the first is zero and each next one is the
/// majority of the previous bit's operands and carry. With `addend_first`, each majority is
/// stated as `z + (x + z) * (y + z)`, its product the second operand of its sum.
pub(crate) struct CarryAir {
    pub(crate) bits: usize,
    pub(crate) addend_first: bool,
}
impl<F> BaseAir<F> for CarryAir {
    fn width(&self) -> usize {
        3 * self.bits
    }
    fn main_next_row_columns(&self) -> Vec<usize> {
        vec![]
    }
}
impl<AB: AirBuilder> Air<AB> for CarryAir {
    fn eval(&self, b: &mut AB) {
        let main = b.main();
        let row = main.current_slice();
        let (x, rest) = row.split_at(self.bits);
        let (y, sum) = rest.split_at(self.bits);
        let carries: Vec<AB::Expr> = (0..self.bits)
            .map(|i| sum[i].into() + x[i] + y[i])
            .collect();
        b.assert_zero(carries[0].clone());
        for i in 0..self.bits - 1 {
            let carry = carries[i].clone();
            let (x, y): (AB::Expr, AB::Expr) = (x[i].into(), y[i].into());
            let majority = if self.addend_first {
                carry.clone() + (x + carry.clone()) * (y + carry)
            } else {
                maj(x, y, carry)
            };
            b.assert_zero(majority + carries[i + 1].clone());
        }
    }
}
