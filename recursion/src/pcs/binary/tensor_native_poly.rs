//! Bit tensors for Boolean ring switching over the native Poly64 carrier.
//!
//! The packed values are `Poly64` elements and the challenges `Poly192`
//! elements, `EF = Poly64[y] / (y^3 + y + 1)`. An element of
//! `EF tensor Poly64` over `F_2` is held by its 192 rows: row `u` is the
//! `Poly64` element paired with coordinate basis vector `beta_u` of `EF`, and
//! column `v` collects bit `v` of every row as an element of `EF`. Coordinate
//! `u = 64 * k + i` is bit `i` of limb `k`, so `beta_u = x^i * y^k`.
//!
//! One packed element absorbs six point coordinates, which index a column,
//! while the batching point names eight, which index a row: the 64 indices
//! past the 192 rows weigh nothing.
//!
//! The closing weight is read through the Chinese remainder split of the
//! tensor algebra. `EF/F_2` is Galois and cyclic of degree 192, so
//!
//! ```text
//!     EF tensor EF  ->  EF^192,    psi_j(x tensor y) = x^(2^j) * y
//! ```
//!
//! is an isomorphism of `EF`-algebras. The row reading at a batching point is
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
//!
//! `y` is a root of an irreducible cubic over `F_2`, so `K = F_2(y)` is `F_8`
//! and `EF = Poly64 tensor K`. Both the basis and its dual factor: with
//! `delta_i` the dual of `x^i` under the trace of `Poly64` and `epsilon_k` the
//! dual of `y^k` under the trace of `K`, `delta_(64k + i) = delta_i * epsilon_k`.
//! Raising to `2^j` acts on `Poly64` through `j mod 64` and on `K` through
//! `j mod 3`, and both residues together name `j`. Splitting the batching
//! point as `eq(batch, 64k + i) = e_k * f_i`,
//!
//! ```text
//!     c_j = g_(j mod 64) * h_(j mod 3)
//!     g_m = sum_i f_i * delta_i^(2^m)        constants in Poly64
//!     h_r = sum_k e_k * epsilon_k^(2^r)      constants in K, additions only
//! ```
//!
//! and `x^(2^j)` is the limbs each raised to `2^(j mod 64)`, recombined over
//! `y^(2^(j mod 3))`, which is a permutation of the limbs and one addition.

use alloc::vec::Vec;
use alloc::{format, vec};

use p3_binary_field::{Poly64, Poly192};
use p3_circuit::ops::NativePoly192Target;
use p3_circuit::{CircuitBuilder, CircuitBuilderError, ExprId};
use p3_field::PrimeCharacteristicRing;

/// Rows of the tensor: the coordinates of one Poly192 element.
const ROWS: usize = 192;
/// Columns of the tensor: the coordinates of one Poly64 element.
const COLUMNS: usize = 64;
/// Point coordinates one packed Poly64 element absorbs, indexing a column.
const ABSORBED: usize = 6;
/// Batching coordinates, indexing a row; `2^8 - 192` indices weigh nothing.
const BATCHED: usize = 8;
/// Poly64 limbs of one Poly192 element, and the degree of `K` over `F_2`.
const LIMBS: usize = 3;

/// Low-first Poly64 limbs of one Poly192 element.
type Limbs = [ExprId; LIMBS];

/// An element of `EF tensor Poly64` over the bit field, held by its 192 rows.
///
/// Row `u`'s coordinate `v` is the coefficient of `beta_u tensor x^v`.
/// Column readings decompose every row once, with the checked coordinate
/// gadget, and keep those bits and the columns formed from them.
#[derive(Clone, Debug)]
pub struct NativePolyBitTensorTarget {
    rows: Vec<ExprId>,
    bits: Option<Vec<Vec<ExprId>>>,
    columns: Vec<Option<NativePoly192Target>>,
}

impl NativePolyBitTensorTarget {
    /// Checks the row count. Native Poly64 cells are always field elements,
    /// so no constraint is added. Targets must belong to the builder that
    /// later reads this tensor.
    pub fn from_rows(rows: Vec<ExprId>) -> Result<Self, CircuitBuilderError> {
        check_len("NativePolyBitTensorRows", rows.len(), ROWS)?;
        Ok(Self {
            rows,
            bits: None,
            columns: vec![None; COLUMNS],
        })
    }

    pub fn rows(&self) -> &[ExprId] {
        &self.rows
    }

    /// Reads the rows at an eight-coordinate batching point,
    /// `sum_(u < 192) eq(batch, u) * row_u`, with the point's first coordinate
    /// as the most significant index bit. The indices from 192 up have no row
    /// and weigh nothing, as in the released reduction.
    ///
    /// The weight factors as `eq(batch[..2], k) * eq(batch[2..], i)` for row
    /// `64 * k + i`, so the six-coordinate table is read once per limb block.
    /// Both tables depend on `batch` alone and are shared, through common
    /// subexpressions, by every reading and closing weight at the same point.
    pub fn evaluate_rows(
        &self,
        b: &mut CircuitBuilder<Poly64>,
        batch: &[NativePoly192Target],
    ) -> Result<NativePoly192Target, CircuitBuilderError> {
        check_len("NativePolyBitTensorBatch", batch.len(), BATCHED)?;
        let (limb_weights, weights) = batch_tables(b, batch);
        let mut sum = [ExprId::ZERO; LIMBS];
        for (block, &limb_weight) in self.rows.chunks(COLUMNS).zip(&limb_weights) {
            let mut partial = [ExprId::ZERO; LIMBS];
            for (&row, weight) in block.iter().zip(&weights) {
                for (sum, &weight) in partial.iter_mut().zip(weight) {
                    *sum = fma(b, weight, row, *sum);
                }
            }
            sum = mul_add3(b, limb_weight, partial, sum);
        }
        b.check_construction_limits()?;
        Ok(b.native_poly192_from_coefficients(sum))
    }

    /// Column `v`, `sum_u bit_v(row_u) * beta_u`: limb `k` is
    /// `sum_i bit_v(row_(64k + i)) * x^i`.
    ///
    /// The bits come from the checked decomposition of every row, which
    /// constrains them Boolean and recomposes each row from them. The column is
    /// a constant-weighted sum of those bits and adds no Boolean check.
    pub fn column(
        &mut self,
        b: &mut CircuitBuilder<Poly64>,
        v: usize,
    ) -> Result<NativePoly192Target, CircuitBuilderError> {
        if v >= COLUMNS {
            return Err(CircuitBuilderError::NonPrimitiveOpArity {
                op: "NativePolyBitTensorColumn",
                expected: format!("column index below {COLUMNS}"),
                got: v,
            });
        }
        if let Some(column) = &self.columns[v] {
            return Ok(column.clone());
        }
        if self.bits.is_none() {
            let bits = self
                .rows
                .iter()
                .map(|&row| b.binary_decompose_coordinates(row, COLUMNS))
                .collect::<Result<Vec<_>, _>>()?;
            self.bits = Some(bits);
        }
        let bits = self.bits.as_ref().expect("rows decomposed above");
        let mut limbs = [ExprId::ZERO; LIMBS];
        for (limb, block) in limbs.iter_mut().zip(bits.chunks(COLUMNS)) {
            // x^0 is one, so the block's first bit enters unweighted.
            let mut sum = block[0][v];
            for (i, row) in block.iter().enumerate().skip(1) {
                let weight = b.define_const(Poly64::new(1 << i));
                sum = fma(b, row[v], weight, sum);
            }
            *limb = sum;
        }
        b.check_construction_limits()?;
        let column = b.native_poly192_from_coefficients(limbs);
        self.columns[v] = Some(column.clone());
        Ok(column)
    }

    /// Reads the column multilinear extension, `sum_v eq(point, v) * column_v`,
    /// with the point's first coordinate as the most significant index bit.
    /// This is the incoming claim of a bit ring switch whose six absorbed
    /// coordinates are `point`.
    pub fn evaluate_columns(
        &mut self,
        b: &mut CircuitBuilder<Poly64>,
        point: &[NativePoly192Target],
    ) -> Result<NativePoly192Target, CircuitBuilderError> {
        check_len("NativePolyBitTensorPoint", point.len(), ABSORBED)?;
        let columns = (0..COLUMNS)
            .map(|v| self.column(b, v).map(|column| *column.coefficients()))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(fold(b, columns, point))
    }

    /// Reads the successor claim of a bit ring switch that sends carry and
    /// last tensors:
    ///
    /// ```text
    ///     sum_{v >= 1} eq(point, v - 1) * column_v(self)
    ///       + eq(point, 63) * (column_0(carry) + column_63(last))
    /// ```
    ///
    /// This is one column reading of the columns shifted down by one, with the
    /// ripple term in the last place.
    pub fn successor_reading(
        &mut self,
        b: &mut CircuitBuilder<Poly64>,
        point: &[NativePoly192Target],
        carry: &mut Self,
        last: &mut Self,
    ) -> Result<NativePoly192Target, CircuitBuilderError> {
        check_len("NativePolyBitTensorPoint", point.len(), ABSORBED)?;
        let mut shifted = (1..COLUMNS)
            .map(|v| self.column(b, v).map(|column| *column.coefficients()))
            .collect::<Result<Vec<_>, _>>()?;
        let carry = carry.column(b, 0)?;
        let last = last.column(b, COLUMNS - 1)?;
        shifted.push(add3(b, *carry.coefficients(), *last.coefficients()));
        Ok(fold(b, shifted, point))
    }
}

/// Closes a native Poly64 bit ring-switch reduction at its surviving point:
/// the closing weight of `BitRingSwitchBatch::<Poly64, Poly192>` for a claim
/// whose kept coordinates are `high`, every sumcheck round run. `survivor` has
/// one coordinate per `high` coordinate and `batch` has eight. A successor
/// sending carry and last tensors provides `(kept_row_variables, alpha)`.
///
/// The weight is the row reading at `batch` of the equality tensor plus alpha
/// times the successor carry tensor plus alpha squared times the repeated-last
/// tensor. It is computed as `sum_j c_j * psi_j(T)` (see the module
/// documentation): each `psi_j(T)` runs the tensor recurrence with every
/// first-leg quantity raised to `2^j`, while the `survivor` and alpha
/// quantities are shared by all 192 maps. The first-leg quantities are the
/// `high` coordinates and the successor's left factors, whose `2^j` powers
/// come from 63 squarings per limb. An empty high point batches the identity
/// tensor. Targets must belong to this builder.
pub fn closing_weight_native_poly(
    b: &mut CircuitBuilder<Poly64>,
    high: &[NativePoly192Target],
    survivor: &[NativePoly192Target],
    batch: &[NativePoly192Target],
    successor: Option<(usize, &NativePoly192Target)>,
) -> Result<NativePoly192Target, CircuitBuilderError> {
    check_len("NativePolyTensorSurvivor", survivor.len(), high.len())?;
    check_len("NativePolyTensorBatch", batch.len(), BATCHED)?;
    if let Some((kept, _)) = successor
        && (kept == 0 || kept > high.len())
    {
        return Err(CircuitBuilderError::NonPrimitiveOpArity {
            op: "NativePolyTensorSuccessor",
            expected: format!("1..={} kept row variables", high.len()),
            got: kept,
        });
    }
    let one = one(b);
    let high: Vec<Limbs> = high.iter().map(|a| *a.coefficients()).collect();
    let survivor: Vec<Limbs> = survivor.iter().map(|y| *y.coefficients()).collect();
    let not_survivor: Vec<Limbs> = survivor.iter().map(|&y| add3(b, one, y)).collect();
    let selector = successor.map_or(high.len(), |(kept, _)| high.len() - kept);
    let legs = successor.map(|(_, alpha)| {
        let kept = selector..high.len();
        successor_legs(
            b,
            &high[kept.clone()],
            &survivor[kept.clone()],
            &not_survivor[kept],
            alpha,
        )
    });
    b.check_construction_limits()?;
    let twisted_high = high
        .iter()
        .map(|&a| Twists::new(b, a))
        .collect::<Result<Vec<_>, _>>()?;
    let twisted_lefts = legs
        .as_ref()
        .map(|legs| {
            legs.lefts
                .iter()
                .map(|&left| Twists::new(b, left))
                .collect::<Result<Vec<_>, _>>()
        })
        .transpose()?;

    let (limb_weights, weights) = batch_tables(b, batch);
    b.check_construction_limits()?;
    let g = poly64_coefficients(b, &weights)?;
    let h = subfield_coefficients(b, &limb_weights[..LIMBS]);
    // The pair (m, r) is the map j with j mod 64 = m and j mod 3 = r, so the
    // pairs run over all 192 maps, and c_j = g_m * h_r.
    let mut weight = [ExprId::ZERO; LIMBS];
    for (r, &h) in h.iter().enumerate() {
        let mut sum = [ExprId::ZERO; LIMBS];
        for (m, &g) in g.iter().enumerate() {
            let mut image = one;
            if let (Some(legs), Some(lefts)) = (&legs, &twisted_lefts) {
                // The kept block from its last coordinate up, as the carry
                // recurrence folds it: image is psi_j of the kept block's
                // equality tensor plus alpha times its carry tensor, and then
                // plus alpha squared times its repeated-last tensor.
                let kept = twisted_high[selector..]
                    .iter()
                    .zip(&not_survivor[selector..])
                    .rev();
                for (((a, &not_b), left), &right) in kept.zip(lefts).zip(&legs.rights) {
                    let a = a.at(b, m, r);
                    let factor = add3(b, a, not_b);
                    image = mul3(b, image, factor);
                    let left = left.at(b, m, r);
                    image = mul_add3(b, left, right, image);
                }
                let product = lefts
                    .last()
                    .expect("the kept product follows the left factors");
                let product = product.at(b, m, r);
                image = mul_add3(b, product, legs.last_right, image);
            }
            let prefix = twisted_high[..selector]
                .iter()
                .zip(&not_survivor[..selector]);
            for (a, &not_b) in prefix {
                let a = a.at(b, m, r);
                let factor = add3(b, a, not_b);
                image = mul3(b, image, factor);
            }
            sum = mul_add3(b, g, image, sum);
            b.check_construction_limits()?;
        }
        weight = mul_add3(b, h, sum, weight);
    }
    b.check_construction_limits()?;
    Ok(b.native_poly192_from_coefficients(weight))
}

/// The successor's per-coordinate factors over the kept block, walked from its
/// last coordinate up as `BitTensor::successor_element` walks it.
struct SuccessorLegs {
    /// First-leg factors `prod_(s < t) a_s * (1 + a_t)` in walk order, then the
    /// whole product `prod a`; each is raised to `2^j` under `psi_j`.
    lefts: Vec<Limbs>,
    /// Second-leg factors `alpha * prod_(s < t) (1 + b_s) * b_t` in walk order.
    rights: Vec<Limbs>,
    /// `alpha^2 * prod b`, the repeated-last tensor's second leg.
    last_right: Limbs,
}

fn successor_legs(
    b: &mut CircuitBuilder<Poly64>,
    high: &[Limbs],
    survivor: &[Limbs],
    not_survivor: &[Limbs],
    alpha: &NativePoly192Target,
) -> SuccessorLegs {
    let one = one(b);
    let alpha = *alpha.coefficients();
    let mut a_product = one;
    let mut b_complement = alpha;
    let mut b_product = one;
    let mut lefts = Vec::with_capacity(high.len() + 1);
    let mut rights = Vec::with_capacity(high.len());
    let kept = high.iter().zip(survivor).zip(not_survivor).rev();
    for ((&a, &y), &not_y) in kept {
        let next_a = mul3(b, a_product, a);
        lefts.push(add3(b, a_product, next_a));
        a_product = next_a;
        let next_complement = mul3(b, b_complement, not_y);
        rights.push(add3(b, b_complement, next_complement));
        b_complement = next_complement;
        b_product = mul3(b, b_product, y);
    }
    lefts.push(a_product);
    let alpha_squared = mul3(b, alpha, alpha);
    SuccessorLegs {
        lefts,
        rights,
        last_right: mul3(b, alpha_squared, b_product),
    }
}

/// The `2^j` powers of one Poly192 target, `j < 192`.
struct Twists {
    /// The limbs raised to `2^m`, for `m < 64`.
    powers: Vec<Limbs>,
}

impl Twists {
    fn new(b: &mut CircuitBuilder<Poly64>, value: Limbs) -> Result<Self, CircuitBuilderError> {
        let mut powers = Vec::with_capacity(COLUMNS);
        powers.push(value);
        for _ in 1..COLUMNS {
            let previous = *powers.last().expect("the value itself is present");
            powers.push(previous.map(|limb| b.mul(limb, limb)));
        }
        b.check_construction_limits()?;
        Ok(Self { powers })
    }

    /// `value^(2^j)` for the `j` with `j mod 64 = m` and `j mod 3 = r`.
    ///
    /// The limbs `a_k` are raised to `2^m`, and `Y = y^(2^j) = y^(2^r)` is
    /// `y`, `y^2` or `y^2 + y`, so `a_0 + a_1 Y + a_2 Y^2` recombines as a
    /// permutation of the limbs with one addition.
    fn at(&self, b: &mut CircuitBuilder<Poly64>, m: usize, r: usize) -> Limbs {
        let [x0, x1, x2] = self.powers[m];
        match r {
            0 => [x0, x1, x2],
            1 => [x0, x2, b.add(x1, x2)],
            _ => [x0, b.add(x1, x2), x1],
        }
    }
}

/// `eq(batch[..2], k)` for `k < 4` and `eq(batch[2..], i)` for `i < 64`, whose
/// products weigh row `64 * k + i`.
fn batch_tables(
    b: &mut CircuitBuilder<Poly64>,
    batch: &[NativePoly192Target],
) -> (Vec<Limbs>, Vec<Limbs>) {
    let (outer, inner) = batch.split_at(BATCHED - ABSORBED);
    (equality_table(b, outer), equality_table(b, inner))
}

/// `g_m = sum_i f_i * delta_i^(2^m)` for `m < 64`, with `f` the inner batching
/// table and `delta` the Poly64 trace-dual basis.
fn poly64_coefficients(
    b: &mut CircuitBuilder<Poly64>,
    weights: &[Limbs],
) -> Result<Vec<Limbs>, CircuitBuilderError> {
    let mut duals = poly64_trace_dual_basis();
    let mut coefficients = Vec::with_capacity(COLUMNS);
    for _ in 0..COLUMNS {
        let mut coefficient = [ExprId::ZERO; LIMBS];
        for (weight, dual) in weights.iter().zip(&mut duals) {
            let constant = b.define_const(*dual);
            for (sum, &weight) in coefficient.iter_mut().zip(weight) {
                *sum = fma(b, weight, constant, *sum);
            }
            // Advance delta_i^(2^m) to the next power's constant.
            *dual = dual.square();
        }
        coefficients.push(coefficient);
        b.check_construction_limits()?;
    }
    Ok(coefficients)
}

/// `h_r = sum_k e_k * epsilon_k^(2^r)` for `r < 3`, with `e` the outer
/// batching weights of the three limbs and `epsilon` the trace-dual basis of
/// `1, y, y^2` in `K = F_8`. For `kappa` in `K`, every `kappa * y^s` lies in
/// `K`, the `F_2`-span of `1, y, y^2`, so each limb of a product by `kappa`
/// is a sum of limbs.
fn subfield_coefficients(b: &mut CircuitBuilder<Poly64>, limb_weights: &[Limbs]) -> [Limbs; LIMBS] {
    let mut duals = subfield_trace_dual_basis();
    core::array::from_fn(|_| {
        let mut coefficient = [ExprId::ZERO; LIMBS];
        for (&weight, dual) in limb_weights.iter().zip(&mut duals) {
            coefficient = add_subfield_multiple(b, coefficient, weight, *dual);
            *dual = dual.square();
        }
        coefficient
    })
}

/// `sum + kappa * value` for `kappa` in `K`. Column `s` of the product by
/// `kappa` is `kappa * y^s`, whose limbs are bits.
fn add_subfield_multiple(
    b: &mut CircuitBuilder<Poly64>,
    mut sum: Limbs,
    value: Limbs,
    kappa: Poly192,
) -> Limbs {
    for (s, &limb) in value.iter().enumerate() {
        let column = kappa * subfield_basis(s);
        for (sum, coefficient) in sum.iter_mut().zip(column.coefficients()) {
            let bit = coefficient.to_bits();
            assert!(
                bit <= 1,
                "K is closed under products, so its limbs are bits"
            );
            if bit == 1 {
                *sum = b.add(*sum, limb);
            }
        }
    }
    sum
}

/// The trace-dual of the Poly64 coordinate basis, `beta_w = x^w`:
/// `Tr(dual[u] * beta_w) = [u = w]`, hence coordinate `u` of any `x` is
/// `Tr(dual[u] * x)`. `Tr` is the absolute trace to `F_2`.
///
/// Computed by inverting the 64 x 64 `F_2` matrix of the trace form
/// `Tr(beta_u * beta_w)`, which is nondegenerate because the extension is
/// separable.
pub fn poly64_trace_dual_basis() -> Vec<Poly64> {
    let basis = |u: usize| Poly64::new(1 << u);
    // The trace is F_2-linear, so the traces of the basis vectors give a mask
    // whose parity against a raw value is that value's trace.
    let trace_mask = (0..COLUMNS).fold(0u64, |mask, k| {
        if poly64_trace(basis(k)) == Poly64::ONE {
            mask | 1 << k
        } else {
            mask
        }
    });
    let inverse = invert_trace_form(COLUMNS, |u, w| {
        ((basis(u) * basis(w)).to_bits() & trace_mask).count_ones() & 1 == 1
    });
    inverse.into_iter().map(Poly64::new).collect()
}

/// The trace-dual of `1, y, y^2` in `K = F_8`, under the trace of `K` over
/// `F_2`: `y^k + (y^k)^2 + (y^k)^4` summed against the basis.
fn subfield_trace_dual_basis() -> Vec<Poly192> {
    let trace = |x: Poly192| {
        let square = x.square();
        let value = x + square + square.square();
        assert!(
            value == Poly192::ZERO || value == Poly192::ONE,
            "the trace of K lands in F_2"
        );
        value == Poly192::ONE
    };
    let inverse = invert_trace_form(LIMBS, |u, w| trace(subfield_basis(u) * subfield_basis(w)));
    inverse
        .into_iter()
        .map(|mask| {
            (0..LIMBS)
                .filter(|&w| mask >> w & 1 == 1)
                .map(subfield_basis)
                .sum()
        })
        .collect()
}

/// `y^k` as a Poly192 constant.
fn subfield_basis(k: usize) -> Poly192 {
    Poly192::new(core::array::from_fn(|limb| {
        if limb == k { Poly64::ONE } else { Poly64::ZERO }
    }))
}

fn poly64_trace(x: Poly64) -> Poly64 {
    let mut power = x;
    let mut sum = x;
    for _ in 1..COLUMNS {
        power = power.square();
        sum += power;
    }
    sum
}

/// Inverts the `dimension x dimension` `F_2` matrix `form` by Gauss-Jordan on
/// `(form | identity)`. Row `u` of the inverse is returned as a mask over the
/// basis, which is the dual of basis vector `u` for a trace form.
fn invert_trace_form(dimension: usize, form: impl Fn(usize, usize) -> bool) -> Vec<u64> {
    let mut rows: Vec<u64> = (0..dimension)
        .map(|u| (0..dimension).fold(0u64, |row, w| row | u64::from(form(u, w)) << w))
        .collect();
    let mut inverse: Vec<u64> = (0..dimension).map(|u| 1 << u).collect();
    for column in 0..dimension {
        let pivot = (column..dimension)
            .find(|&row| rows[row] >> column & 1 == 1)
            .expect("the trace form of a separable extension is nondegenerate");
        rows.swap(column, pivot);
        inverse.swap(column, pivot);
        for row in 0..dimension {
            if row != column && rows[row] >> column & 1 == 1 {
                rows[row] ^= rows[column];
                inverse[row] ^= inverse[column];
            }
        }
    }
    inverse
}

/// `sum_x eq(point, x) * values[x]`, with the point's first coordinate as the
/// most significant index bit.
fn fold(
    b: &mut CircuitBuilder<Poly64>,
    mut values: Vec<Limbs>,
    point: &[NativePoly192Target],
) -> NativePoly192Target {
    for coordinate in point.iter().rev() {
        let coordinate = *coordinate.coefficients();
        values = values
            .as_chunks::<2>()
            .0
            .iter()
            .map(|&[low, high]| {
                let slope = add3(b, low, high);
                mul_add3(b, coordinate, slope, low)
            })
            .collect();
    }
    b.native_poly192_from_coefficients(values[0])
}

/// `eq(point, x)` for every `x`, with the point's first coordinate as the most
/// significant index bit.
pub(super) fn equality_table(
    b: &mut CircuitBuilder<Poly64>,
    point: &[NativePoly192Target],
) -> Vec<Limbs> {
    let mut table = vec![one(b)];
    for coordinate in point {
        let coordinate = *coordinate.coefficients();
        table = table
            .iter()
            .flat_map(|&weight| {
                let set = mul3(b, weight, coordinate);
                [add3(b, weight, set), set]
            })
            .collect();
    }
    table
}

fn one(b: &mut CircuitBuilder<Poly64>) -> Limbs {
    [b.define_const(Poly64::ONE), ExprId::ZERO, ExprId::ZERO]
}

/// `x * y + acc` as one fused row, skipping the zero constant.
fn fma(b: &mut CircuitBuilder<Poly64>, x: ExprId, y: ExprId, acc: ExprId) -> ExprId {
    if acc == ExprId::ZERO {
        b.mul(x, y)
    } else if x == ExprId::ZERO || y == ExprId::ZERO {
        acc
    } else {
        b.mul_add(x, y, acc)
    }
}

fn add3(b: &mut CircuitBuilder<Poly64>, x: Limbs, y: Limbs) -> Limbs {
    core::array::from_fn(|k| b.add(x[k], y[k]))
}

/// The Poly192 product, reduced by `y^3 = y + 1` and `y^4 = y^2 + y`:
///
/// ```text
///     out_0 = a0 b0 + z3
///     out_1 = a0 b1 + a1 b0 + z3 + a2 b2
///     out_2 = a0 b2 + a1 b1 + a2 b0 + a2 b2,    z3 = a1 b2 + a2 b1
/// ```
///
/// Nine products in ten rows: `z3` and `a2 b2` are shared, every other product
/// is fused into its sum.
fn mul3(b: &mut CircuitBuilder<Poly64>, x: Limbs, y: Limbs) -> Limbs {
    let [a0, a1, a2] = x;
    let [b0, b1, b2] = y;
    let z3 = b.mul(a1, b2);
    let z3 = fma(b, a2, b1, z3);
    let top = b.mul(a2, b2);
    let out0 = fma(b, a0, b0, z3);
    let out1 = fma(b, a0, b1, z3);
    let out1 = fma(b, a1, b0, out1);
    let out1 = b.add(out1, top);
    let out2 = fma(b, a0, b2, top);
    let out2 = fma(b, a1, b1, out2);
    let out2 = fma(b, a2, b0, out2);
    [out0, out1, out2]
}

/// `x * y + acc` over Poly192, every product fused into its output's sum.
fn mul_add3(b: &mut CircuitBuilder<Poly64>, x: Limbs, y: Limbs, acc: Limbs) -> Limbs {
    if acc == [ExprId::ZERO; LIMBS] {
        return mul3(b, x, y);
    }
    let [a0, a1, a2] = x;
    let [b0, b1, b2] = y;
    let [c0, c1, c2] = acc;
    [
        add_products(b, c0, &[(a0, b0), (a1, b2), (a2, b1)]),
        add_products(b, c1, &[(a0, b1), (a1, b0), (a1, b2), (a2, b1), (a2, b2)]),
        add_products(b, c2, &[(a0, b2), (a1, b1), (a2, b0), (a2, b2)]),
    ]
}

/// `sum + sum_t x_t * y_t`, one fused row per product.
fn add_products(
    b: &mut CircuitBuilder<Poly64>,
    sum: ExprId,
    products: &[(ExprId, ExprId)],
) -> ExprId {
    products.iter().fold(sum, |sum, &(x, y)| fma(b, x, y, sum))
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
