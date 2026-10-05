//! Native cubic challenge arithmetic over `Poly64` circuit cells.

use p3_binary_field::Poly64;
use p3_field::PrimeCharacteristicRing;

use crate::{CircuitBuilder, ExprId};

/// `a0 + a1*y + a2*y²`, with native Poly64 coefficients and `y³ = y + 1`.
///
/// Every cell is already in Poly64, so no coefficient membership hint is needed.
/// IDs and targets must belong to the builder graph that uses them.
#[derive(Clone, Debug)]
pub struct NativePoly192Target {
    coefficients: [ExprId; 3],
}

impl NativePoly192Target {
    pub const fn coefficients(&self) -> &[ExprId; 3] {
        &self.coefficients
    }
}

impl CircuitBuilder<Poly64> {
    pub const fn native_poly192_from_coefficients(
        &self,
        coefficients: [ExprId; 3],
    ) -> NativePoly192Target {
        NativePoly192Target { coefficients }
    }

    /// Raw polynomial coefficients, rather than integer ring embeddings.
    pub fn native_poly192_constant(&mut self, raw: [u64; 3]) -> NativePoly192Target {
        NativePoly192Target {
            coefficients: raw.map(|x| self.define_const(Poly64::new(x))),
        }
    }

    pub fn native_poly192_add(
        &mut self,
        a: &NativePoly192Target,
        b: &NativePoly192Target,
    ) -> NativePoly192Target {
        NativePoly192Target {
            coefficients: core::array::from_fn(|i| self.add(a.coefficients[i], b.coefficients[i])),
        }
    }

    pub fn native_poly192_mul(
        &mut self,
        a: &NativePoly192Target,
        b: &NativePoly192Target,
    ) -> NativePoly192Target {
        let products: [[ExprId; 3]; 3] = core::array::from_fn(|i| {
            core::array::from_fn(|j| self.mul(a.coefficients[i], b.coefficients[j]))
        });
        let z1 = self.add(products[0][1], products[1][0]);
        let z2_cross = self.add(products[0][2], products[2][0]);
        let z2 = self.add(z2_cross, products[1][1]);
        let z3 = self.add(products[1][2], products[2][1]);
        // y³ = y + 1 and y⁴ = y² + y.
        let out0 = self.add(products[0][0], z3);
        let out1_cross = self.add(z1, z3);
        let out1 = self.add(out1_cross, products[2][2]);
        let out2 = self.add(z2, products[2][2]);
        NativePoly192Target {
            coefficients: [out0, out1, out2],
        }
    }

    pub fn native_poly192_square(&mut self, value: &NativePoly192Target) -> NativePoly192Target {
        let [a0, a1, a2] = value.coefficients.map(|a| self.mul(a, a));
        let high = self.add(a1, a2);
        NativePoly192Target {
            coefficients: [a0, a2, high],
        }
    }

    /// Checks a caller-supplied inverse; zero has no satisfying candidate.
    pub fn assert_native_poly192_inverse(
        &mut self,
        value: &NativePoly192Target,
        candidate: &NativePoly192Target,
    ) {
        let product = self.native_poly192_mul(value, candidate);
        let one = self.define_const(Poly64::ONE);
        self.connect(product.coefficients[0], one);
        self.assert_zero(product.coefficients[1]);
        self.assert_zero(product.coefficients[2]);
    }
}
