//! Bit tensors for Boolean ring switching over the native Tower128 carrier.
//!
//! An element of `F tensor F` over `F_2`, with `F` the native Tower128 field,
//! is held by rows as in [`super::BinaryTowerTensorTarget`]: row `u` is the
//! second-leg element paired with raw coordinate basis vector `beta_u` of the
//! first leg, and column `v` collects bit `v` of every row.
//!
//! The closing weight is read through the Chinese remainder split of the
//! tensor algebra. `F/F_2` is Galois of degree 128, so
//!
//! ```text
//!     F tensor F  ->  F^128,    psi_j(x tensor y) = x^(2^j) * y
//! ```
//!
//! is an isomorphism of `F`-algebras. The row reading at a batching point is
//! `L tensor id`, where `L(x) = sum_u eq(batch, u) * coord_u(x)`. With
//! `delta_u` the trace-dual of `beta_u`, `coord_u(x) = Tr(delta_u * x)`, so
//!
//! ```text
//!     L(x) = sum_j c_j * x^(2^j),    c_j = sum_u eq(batch, u) * delta_u^(2^j)
//! ```
//!
//! and the row reading of any tensor `T` is `sum_j c_j * psi_j(T)`. Each
//! `psi_j` is a ring map, so `psi_j(T)` follows the tensor's own recurrence in
//! plain field arithmetic with every first-leg quantity raised to `2^j`.

use alloc::vec::Vec;
use alloc::{format, vec};

use p3_binary_field::{BinaryField128, TowerLevel};
use p3_circuit::ops::NativeTower128Target;
use p3_circuit::ops::binary_native::BinaryCoordinateExtractor;
use p3_circuit::{CircuitBuilder, CircuitBuilderError, ExprId};
use p3_field::PrimeCharacteristicRing;

/// Raw coordinates of one Tower128 element, and so the tensor's side length.
const DIMENSION: usize = 128;
/// Coordinates of a point indexing one row or column of the tensor.
const LOG_DIMENSION: usize = 7;

/// An element of `F tensor F` over the bit field, held by its 128 rows.
///
/// Row `u`'s raw coordinate `v` is the coefficient of `beta_u tensor beta_v`.
/// Column readings decompose every row once, with the checked coordinate
/// gadget, and keep those bits and the columns formed from them. For an
/// isolated column, [`Self::trace_column`] avoids decomposing all coordinates.
#[derive(Clone, Debug)]
pub struct NativeBitTensorTarget {
    rows: Vec<NativeTower128Target>,
    bits: Option<Vec<[ExprId; DIMENSION]>>,
    columns: Vec<Option<NativeTower128Target>>,
}

impl NativeBitTensorTarget {
    /// Checks the row count. Native carrier targets are always field elements,
    /// so no constraint is added. Targets must belong to the builder that later
    /// reads this tensor.
    pub fn from_rows(rows: Vec<NativeTower128Target>) -> Result<Self, CircuitBuilderError> {
        check_len("NativeBitTensorRows", rows.len(), DIMENSION)?;
        Ok(Self {
            rows,
            bits: None,
            columns: vec![None; DIMENSION],
        })
    }

    pub fn rows(&self) -> &[NativeTower128Target] {
        &self.rows
    }

    /// Reads the row multilinear extension, `sum_u eq(point, u) * row_u`.
    /// Points use big-endian variable order, as in
    /// [`super::BinaryTowerTensorTarget::evaluate_rows`]: adjacent pairs fold
    /// under the point's last coordinate first.
    pub fn evaluate_rows(
        &self,
        b: &mut CircuitBuilder<BinaryField128>,
        point: &[NativeTower128Target],
    ) -> Result<NativeTower128Target, CircuitBuilderError> {
        check_len("NativeBitTensorPoint", point.len(), LOG_DIMENSION)?;
        Ok(fold(b, &self.rows, point))
    }

    /// Column `v`, `sum_u bit_v(row_u) * beta_u`.
    ///
    /// The bits come from the checked decomposition of every row, which
    /// constrains them Boolean and recomposes each row from them. The column is
    /// a constant-weighted sum of those bits and adds no Boolean check.
    pub fn column(
        &mut self,
        b: &mut CircuitBuilder<BinaryField128>,
        v: usize,
    ) -> Result<NativeTower128Target, CircuitBuilderError> {
        if v >= DIMENSION {
            return Err(CircuitBuilderError::NonPrimitiveOpArity {
                op: "NativeBitTensorColumn",
                expected: format!("column index below {DIMENSION}"),
                got: v,
            });
        }
        if let Some(column) = self.columns[v] {
            return Ok(column);
        }
        if self.bits.is_none() {
            let bits = self
                .rows
                .iter()
                .map(|row| b.native_tower128_to_bits(row))
                .collect::<Result<Vec<_>, _>>()?;
            self.bits = Some(bits);
        }
        let bits = self.bits.as_ref().expect("rows decomposed above");
        // beta_0 is one, so row 0's bit enters unweighted.
        let mut sum = bits[0][v];
        for (u, row) in bits.iter().enumerate().skip(1) {
            let weight = b.define_const(BinaryField128::from_repr(1 << u));
            sum = b.mul_add(row[v], weight, sum);
        }
        b.check_construction_limits()?;
        let column = b.native_tower128_from_expr(sum);
        self.columns[v] = Some(column);
        Ok(column)
    }

    /// Read one column using a checked trace-coordinate witness per row.
    /// Each coordinate costs at most four ALU operations, plus the column's
    /// constant-weighted sum. Reuses a previously read column or decomposed rows.
    pub fn trace_column(
        &mut self,
        b: &mut CircuitBuilder<BinaryField128>,
        v: usize,
    ) -> Result<NativeTower128Target, CircuitBuilderError> {
        if v >= DIMENSION {
            return Err(CircuitBuilderError::NonPrimitiveOpArity {
                op: "NativeBitTensorColumn",
                expected: format!("column index below {DIMENSION}"),
                got: v,
            });
        }
        if self.bits.is_some() || self.columns[v].is_some() {
            return self.column(b, v);
        }
        let extractor = BinaryCoordinateExtractor::new(v)?;
        let mut sum = ExprId::ZERO;
        for (u, row) in self.rows.iter().enumerate() {
            let bit = extractor.extract(b, row.as_expr())?;
            let weight = b.define_const(BinaryField128::from_repr(1 << u));
            sum = b.mul_add(bit, weight, sum);
        }
        b.check_construction_limits()?;
        let column = b.native_tower128_from_expr(sum);
        self.columns[v] = Some(column);
        Ok(column)
    }

    /// Reads the column multilinear extension, `sum_v eq(point, v) * column_v`,
    /// in the same variable order as [`Self::evaluate_rows`]. This is the
    /// incoming claim of a bit ring switch whose absorbed coordinates are
    /// `point`.
    pub fn evaluate_columns(
        &mut self,
        b: &mut CircuitBuilder<BinaryField128>,
        point: &[NativeTower128Target],
    ) -> Result<NativeTower128Target, CircuitBuilderError> {
        check_len("NativeBitTensorPoint", point.len(), LOG_DIMENSION)?;
        let columns = (0..DIMENSION)
            .map(|v| self.column(b, v))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(fold(b, &columns, point))
    }

    /// Reads the successor claim of a bit ring switch that sends carry and
    /// last tensors:
    ///
    /// ```text
    ///     sum_{v >= 1} eq(point, v - 1) * column_v(self)
    ///       + eq(point, 127) * (column_0(carry) + column_127(last))
    /// ```
    ///
    /// This is one column reading of the columns shifted down by one, with the
    /// ripple term in the last place.
    pub fn successor_reading(
        &mut self,
        b: &mut CircuitBuilder<BinaryField128>,
        point: &[NativeTower128Target],
        carry: &mut Self,
        last: &mut Self,
    ) -> Result<NativeTower128Target, CircuitBuilderError> {
        check_len("NativeBitTensorPoint", point.len(), LOG_DIMENSION)?;
        let mut shifted = (1..DIMENSION)
            .map(|v| self.column(b, v))
            .collect::<Result<Vec<_>, _>>()?;
        let carry = carry.trace_column(b, 0)?;
        let last = last.trace_column(b, DIMENSION - 1)?;
        shifted.push(b.native_tower128_add(&carry, &last));
        Ok(fold(b, &shifted, point))
    }
}

/// Closes a native bit ring-switch reduction at its surviving point, with the
/// contract of [`super::binary_tensor_closing_weight`]: `survivor` has one
/// coordinate per `high` coordinate, and `batch` has seven. A successor
/// sending carry and last tensors provides `(kept_row_variables, alpha)`.
///
/// The weight is the row reading at `batch` of the equality tensor plus alpha
/// times the successor carry tensor plus alpha squared times the repeated-last
/// tensor. It is computed as `sum_j c_j * psi_j(T)` (see the module
/// documentation): each `psi_j(T)` runs the tensor recurrence with every
/// `high` quantity raised to `2^j`, while the `survivor` and alpha quantities
/// are shared by all 128 maps. An empty high point batches the identity
/// tensor. Targets must belong to this builder.
pub fn closing_weight_native(
    b: &mut CircuitBuilder<BinaryField128>,
    high: &[NativeTower128Target],
    survivor: &[NativeTower128Target],
    batch: &[NativeTower128Target],
    successor: Option<(usize, &NativeTower128Target)>,
) -> Result<NativeTower128Target, CircuitBuilderError> {
    check_len("NativeTensorSurvivor", survivor.len(), high.len())?;
    check_len("NativeTensorBatch", batch.len(), LOG_DIMENSION)?;
    if let Some((kept, _)) = successor
        && (kept == 0 || kept > high.len())
    {
        return Err(CircuitBuilderError::NonPrimitiveOpArity {
            op: "NativeTensorSuccessor",
            expected: format!("1..={} kept row variables", high.len()),
            got: kept,
        });
    }
    let one = b.define_const(BinaryField128::ONE);
    let not_survivor: Vec<ExprId> = survivor.iter().map(|y| b.add(one, y.as_expr())).collect();
    // twisted[j][i] = high[i]^(2^j), the high point as psi_j reads it.
    let mut twisted: Vec<Vec<ExprId>> = Vec::with_capacity(DIMENSION);
    twisted.push(high.iter().map(NativeTower128Target::as_expr).collect());
    for _ in 1..DIMENSION {
        let previous = twisted.last().expect("the untwisted point is present");
        let next = previous.iter().map(|&a| b.mul(a, a)).collect();
        twisted.push(next);
        b.check_construction_limits()?;
    }
    let selector = successor.map_or(high.len(), |(kept, _)| high.len() - kept);
    // Second-leg successor factors, folded from the last kept coordinate up.
    let successor_legs = successor.map(|(_, alpha)| {
        let mut b_complement = alpha.as_expr();
        let mut b_product = one;
        let mut rights = Vec::with_capacity(high.len() - selector);
        for i in (selector..high.len()).rev() {
            let next_complement = b.mul(b_complement, not_survivor[i]);
            rights.push(b.add(b_complement, next_complement));
            b_complement = next_complement;
            b_product = b.mul(b_product, survivor[i].as_expr());
        }
        let alpha_squared = b.mul(alpha.as_expr(), alpha.as_expr());
        (rights, b.mul(alpha_squared, b_product))
    });
    let mut images = Vec::with_capacity(DIMENSION);
    for twisted_high in &twisted {
        // psi_j(1 + a tensor 1 + 1 tensor y) = 1 + a^(2^j) + y.
        let mut image = one;
        if let Some((rights, last_right)) = &successor_legs {
            let mut a_product = one;
            let kept = twisted_high[selector..]
                .iter()
                .zip(&not_survivor[selector..]);
            for ((&a, &not_b), &right) in kept.rev().zip(rights) {
                let factor = b.add(a, not_b);
                image = b.mul(image, factor);
                let next_a = b.mul(a_product, a);
                let left = b.add(a_product, next_a);
                image = b.mul_add(left, right, image);
                a_product = next_a;
            }
            image = b.mul_add(a_product, *last_right, image);
        }
        let prefix = twisted_high[..selector]
            .iter()
            .zip(&not_survivor[..selector]);
        for (&a, &not_b) in prefix {
            let factor = b.add(a, not_b);
            image = b.mul(image, factor);
        }
        images.push(image);
        b.check_construction_limits()?;
    }
    let coefficients = closing_coefficients(b, batch)?;
    let mut weight = ExprId::ZERO;
    for (coefficient, image) in coefficients.into_iter().zip(images) {
        weight = b.mul_add(coefficient, image, weight);
        b.check_construction_limits()?;
    }
    Ok(b.native_tower128_from_expr(weight))
}

/// The absolute trace-dual factors through the seven quadratic extensions.
/// For `X_k² + alpha_k X_k + 1 = 0`, the relative duals of `1, X_k` are
/// `d0 = 1 + X_k / alpha_k` and `d1 = 1 / alpha_k`. Thus
/// `c_j = product_k (d0^(2^j) + r_k (d0 + d1)^(2^j))`.
/// Each partial product has Frobenius period `2^(k + 1)`, so compute it
/// once per period. The batching point indexes the raw basis most-significant-bit first.
fn closing_coefficients(
    b: &mut CircuitBuilder<BinaryField128>,
    batch: &[NativeTower128Target],
) -> Result<Vec<ExprId>, CircuitBuilderError> {
    let mut coefficients = vec![b.define_const(BinaryField128::ONE)];
    for k in 0..LOG_DIMENSION {
        let (mut d0, mut d1) = if k == 0 {
            (BinaryField128::from_repr(3), BinaryField128::ONE)
        } else {
            // alpha_k = X_(k-1), whose inverse is X_(k-1) + alpha_(k-1).
            let top = 1usize << k;
            let alpha = 1usize << (k - 1);
            let beta = if k == 1 { 0 } else { 1usize << (k - 2) };
            (
                BinaryField128::from_repr(1 | (1u128 << (top + alpha)) | (1u128 << (top + beta))),
                BinaryField128::from_repr((1u128 << alpha) | (1u128 << beta)),
            )
        };
        let period = 1usize << (k + 1);
        let mut next = Vec::with_capacity(period);
        for j in 0..period {
            let intercept = b.define_const(d0);
            let slope = b.define_const(d0 + d1);
            let factor = b.mul_add(batch[LOG_DIMENSION - 1 - k].as_expr(), slope, intercept);
            next.push(b.mul(coefficients[j % coefficients.len()], factor));
            d0 = d0.square();
            d1 = d1.square();
        }
        coefficients = next;
        b.check_construction_limits()?;
    }
    Ok(coefficients)
}

/// The trace-dual of the raw Tower128 coordinate basis, `beta_w` being the
/// element with raw value `1 << w`: `Tr(dual[u] * beta_w) = [u = w]`, hence
/// raw coordinate `u` of any `x` is `Tr(dual[u] * x)`. `Tr` is the absolute
/// trace to `F_2`.
///
/// Computed by inverting the 128 x 128 `F_2` matrix of the trace form
/// `Tr(beta_u * beta_w)`, which is nondegenerate because `F/F_2` is separable.
pub fn binary128_trace_dual_basis() -> Vec<BinaryField128> {
    let basis = |u: usize| BinaryField128::from_repr(1 << u);
    // The trace is F_2-linear, so the traces of the basis vectors give a mask
    // whose parity against a raw value is that value's trace.
    let trace_mask = (0..DIMENSION).fold(0u128, |mask, k| {
        if absolute_trace(basis(k)) {
            mask | 1 << k
        } else {
            mask
        }
    });
    let mut form: Vec<u128> = (0..DIMENSION)
        .map(|u| {
            (0..DIMENSION).fold(0u128, |row, w| {
                let product = (basis(u) * basis(w)).to_repr();
                row | u128::from((product & trace_mask).count_ones() & 1) << w
            })
        })
        .collect();
    // Gauss-Jordan on (form | identity) leaves the inverse on the right. Row u
    // of the inverse is the raw value of dual[u].
    let mut inverse: Vec<u128> = (0..DIMENSION).map(|u| 1 << u).collect();
    for column in 0..DIMENSION {
        let pivot = (column..DIMENSION)
            .find(|&row| form[row] >> column & 1 == 1)
            .expect("the trace form of a separable extension is nondegenerate");
        form.swap(column, pivot);
        inverse.swap(column, pivot);
        for row in 0..DIMENSION {
            if row != column && form[row] >> column & 1 == 1 {
                form[row] ^= form[column];
                inverse[row] ^= inverse[column];
            }
        }
    }
    inverse.into_iter().map(BinaryField128::from_repr).collect()
}

fn absolute_trace(x: BinaryField128) -> bool {
    let mut power = x;
    let mut sum = x;
    for _ in 1..DIMENSION {
        power = power.square();
        sum += power;
    }
    sum == BinaryField128::ONE
}

/// `sum_x eq(point, x) * values[x]`, with the point's first coordinate as the
/// most significant index bit.
fn fold(
    b: &mut CircuitBuilder<BinaryField128>,
    values: &[NativeTower128Target],
    point: &[NativeTower128Target],
) -> NativeTower128Target {
    let mut values: Vec<ExprId> = values.iter().map(|value| value.as_expr()).collect();
    for coordinate in point.iter().rev() {
        values = values
            .as_chunks::<2>()
            .0
            .iter()
            .map(|&[low, high]| {
                let slope = b.add(low, high);
                b.mul_add(coordinate.as_expr(), slope, low)
            })
            .collect();
    }
    b.native_tower128_from_expr(values[0])
}

/// `eq(point, x)` for every `x`, with the point's first coordinate as the most
/// significant index bit.
pub(super) fn equality_table(
    b: &mut CircuitBuilder<BinaryField128>,
    point: &[NativeTower128Target],
) -> Vec<ExprId> {
    let mut table = vec![b.define_const(BinaryField128::ONE)];
    for coordinate in point {
        table = table
            .iter()
            .flat_map(|&weight| {
                let set = b.mul(weight, coordinate.as_expr());
                [b.add(weight, set), set]
            })
            .collect();
    }
    table
}

fn check_len(op: &'static str, got: usize, expected: usize) -> Result<(), CircuitBuilderError> {
    if got == expected {
        Ok(())
    } else {
        Err(CircuitBuilderError::NonPrimitiveOpArity {
            op,
            expected: format!("{expected} coordinates"),
            got,
        })
    }
}
