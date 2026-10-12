//! Additive WHIR uses coefficient selectors and ordinary multilinear row folds.

use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use core::hash::Hash;

use p3_binary_field::BinaryField128;
use p3_circuit::ops::BinaryTower128Target;
use p3_circuit::{CircuitBuilder, CircuitBuilderError, ExprId};
use p3_field::Field;

use super::RecursiveBinaryTowerField;
use crate::verifier::binary_field_policy::{BinaryRelationPolicy, BinaryWhirPolicy, TowerRelation};

/// Direct coefficient-selector weight `prod(1 + r * (s + 1))` used by
/// released additive WHIR. Both points use the native big-endian coordinate
/// order. The empty product is one. Targets must belong to this builder.
pub fn binary128_select_eval<EF: Field + Eq + Hash>(
    circuit: &mut CircuitBuilder<EF>,
    point: &[BinaryTower128Target],
    row: &[BinaryTower128Target],
) -> Result<BinaryTower128Target, CircuitBuilderError> {
    select_eval_using::<TowerRelation<BinaryField128, BinaryField128>, EF>(circuit, point, row)
}
pub(crate) fn select_eval_using<P, CF>(
    circuit: &mut CircuitBuilder<CF>,
    point: &[P::ChallengeTarget],
    row: &[P::ChallengeTarget],
) -> Result<P::ChallengeTarget, CircuitBuilderError>
where
    CF: Field + Eq + Hash,
    P: BinaryRelationPolicy<CF>,
{
    if point.len() != row.len() {
        return Err(arity("BinaryWhirSelect", point.len(), row.len()));
    }
    let one = P::constant(circuit, 1)?;
    let mut weight = one.clone();
    for (s, r) in point.iter().zip(row) {
        let shifted = P::add(circuit, s, &one);
        let product = P::mul(circuit, r, &shifted);
        let factor = P::add(circuit, &one, &product);
        weight = P::mul(circuit, &weight, &factor);
        circuit.check_construction_limits()?;
    }
    Ok(weight)
}

/// Evaluates a coefficient table at direct additive-domain coordinates. The
/// native coefficient order folds adjacent entries by `lo + r * hi`, from
/// the last coordinate to the first. Targets must belong to this builder.
pub fn binary128_eval_coefficients<EF: Field + Eq + Hash>(
    circuit: &mut CircuitBuilder<EF>,
    coefficients: &[BinaryTower128Target],
    point: &[BinaryTower128Target],
) -> Result<BinaryTower128Target, CircuitBuilderError> {
    eval_coefficients_using::<TowerRelation<BinaryField128, BinaryField128>, EF>(
        circuit,
        coefficients,
        point,
    )
}
pub(crate) fn eval_coefficients_using<P, CF>(
    circuit: &mut CircuitBuilder<CF>,
    coefficients: &[P::ChallengeTarget],
    point: &[P::ChallengeTarget],
) -> Result<P::ChallengeTarget, CircuitBuilderError>
where
    CF: Field + Eq + Hash,
    P: BinaryRelationPolicy<CF>,
{
    eval_table_using::<P, CF>(circuit, coefficients, point, false)
}

/// Evaluates a multilinear evaluation table, as required for authenticated
/// WHIR rows and its closing polynomial. Adjacent entries fold by
/// `lo + r * (hi + lo)`, from the last coordinate to the first. The caller
/// reverses the sumcheck point first for a suffix binding strategy.
pub fn binary128_eval_multilinear<EF: Field + Eq + Hash>(
    circuit: &mut CircuitBuilder<EF>,
    evaluations: &[BinaryTower128Target],
    point: &[BinaryTower128Target],
) -> Result<BinaryTower128Target, CircuitBuilderError> {
    eval_multilinear_using::<TowerRelation<BinaryField128, BinaryField128>, EF>(
        circuit,
        evaluations,
        point,
    )
}
pub(crate) fn eval_multilinear_using<P, CF>(
    circuit: &mut CircuitBuilder<CF>,
    evaluations: &[P::ChallengeTarget],
    point: &[P::ChallengeTarget],
) -> Result<P::ChallengeTarget, CircuitBuilderError>
where
    CF: Field + Eq + Hash,
    P: BinaryRelationPolicy<CF>,
{
    eval_table_using::<P, CF>(circuit, evaluations, point, true)
}

/// Powers of one base element, each built once from repeated squares of the
/// base and shared by every later request.
pub(crate) struct Powers<T> {
    one: T,
    squares: Vec<T>,
    cache: BTreeMap<usize, T>,
}

impl<T: Clone> Powers<T> {
    pub(crate) fn new<P, CF>(
        circuit: &mut CircuitBuilder<CF>,
        base: &T,
    ) -> Result<Self, CircuitBuilderError>
    where
        CF: Field + Eq + Hash,
        P: BinaryWhirPolicy<CF, ChallengeTarget = T>,
    {
        Ok(Self {
            one: P::constant(circuit, 1)?,
            squares: alloc::vec![base.clone()],
            cache: BTreeMap::new(),
        })
    }

    /// `base^exponent`: the power of the exponent's lower bits times
    /// `base^(2^j)` for its highest set bit `j`.
    pub(crate) fn get<P, CF>(&mut self, circuit: &mut CircuitBuilder<CF>, exponent: usize) -> T
    where
        CF: Field + Eq + Hash,
        P: BinaryWhirPolicy<CF, ChallengeTarget = T>,
    {
        if exponent == 0 {
            return self.one.clone();
        }
        if let Some(power) = self.cache.get(&exponent) {
            return power.clone();
        }
        let high = exponent.ilog2() as usize;
        while self.squares.len() <= high {
            let square = P::square(circuit, self.squares.last().expect("base square"));
            self.squares.push(square);
        }
        let rest = exponent ^ (1 << high);
        let power = if rest == 0 {
            self.squares[high].clone()
        } else {
            let low = self.get::<P, CF>(circuit, rest);
            P::mul(circuit, &low, &self.squares[high])
        };
        self.cache.insert(exponent, power.clone());
        power
    }
}

/// Position of the constant one among a power table's partial folds.
const UNIT: usize = 0;

/// One fold of a power table's entries. `Both(lo, hi, a, b)` folds
/// `t_lo * base^(m + a)` with `t_hi * base^(m + b)`, where one of `a` and
/// `b` is zero.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum PowerFold {
    Low(usize),
    High(usize),
    Both(usize, usize, usize, usize),
}

/// Evaluates at `point` the multilinear table holding `base^k` at index
/// `indices[k]`, summed over repeated indices, and zero elsewhere. Indices
/// use the order of [`eval_multilinear_using`]: the last coordinate pairs
/// adjacent entries.
///
/// Every partial fold is kept as `t * base^m` for a shared target `t`.
/// Folding `t_lo * base^m` with `t_hi * base^(m + d)` at coordinate `r`
/// gives `base^m * (t_lo + r * (t_lo + t_hi * base^d))`, which depends on
/// the pair only through `(t_lo, t_hi, d)`. Consecutive powers at
/// consecutive indices therefore fold with a few operations per coordinate,
/// however many indices they span. Targets must belong to this builder.
pub(crate) fn eval_power_table_using<P, CF>(
    circuit: &mut CircuitBuilder<CF>,
    indices: &[usize],
    point: &[P::ChallengeTarget],
    powers: &mut Powers<P::ChallengeTarget>,
) -> Result<P::ChallengeTarget, CircuitBuilderError>
where
    CF: Field + Eq + Hash,
    P: BinaryWhirPolicy<CF>,
{
    let size = u32::try_from(point.len())
        .ok()
        .and_then(|bits| 1usize.checked_shl(bits));
    if let Some(&index) = indices
        .iter()
        .find(|&&index| size.is_some_and(|size| index >= size))
    {
        return Err(CircuitBuilderError::NonPrimitiveOpArity {
            op: "BinaryWhirPowerTable",
            expected: alloc::format!("indices below 2^{}", point.len()),
            got: index,
        });
    }
    circuit.check_construction_limits()?;
    let mut targets = alloc::vec![powers.one.clone()];
    // (index, target, m) stands for `targets[target] * base^m` at `index`.
    let mut entries: Vec<(usize, usize, usize)> = indices
        .iter()
        .enumerate()
        .map(|(exponent, &index)| (index, UNIT, exponent))
        .collect();
    entries.sort_by_key(|&(index, _, _)| index);
    let mut layer: Vec<(usize, usize, usize)> = Vec::with_capacity(entries.len());
    for (index, target, exponent) in entries {
        match layer.last_mut() {
            Some(last) if last.0 == index => {
                let low = last.2.min(exponent);
                let lo = scaled::<P, CF>(circuit, powers, &targets, last.1, last.2 - low);
                let hi = scaled::<P, CF>(circuit, powers, &targets, target, exponent - low);
                targets.push(P::add(circuit, &lo, &hi));
                *last = (index, targets.len() - 1, low);
            }
            _ => layer.push((index, target, exponent)),
        }
    }
    for coordinate in point.iter().rev() {
        let mut memo = BTreeMap::new();
        let mut complement = None;
        let mut next = Vec::with_capacity(layer.len().div_ceil(2));
        let mut entries = layer.into_iter().peekable();
        while let Some((index, target, exponent)) = entries.next() {
            let partner = if index & 1 == 0 {
                entries.next_if(|&(other, _, _)| other == index | 1)
            } else {
                None
            };
            let (fold, low) = match partner {
                Some((_, other, other_exponent)) => {
                    let low = exponent.min(other_exponent);
                    let fold = PowerFold::Both(target, other, exponent - low, other_exponent - low);
                    (fold, low)
                }
                None if index & 1 == 0 => (PowerFold::Low(target), exponent),
                None => (PowerFold::High(target), exponent),
            };
            let folded = if let Some(&folded) = memo.get(&fold) {
                folded
            } else {
                let value = match fold {
                    PowerFold::Low(target) => {
                        let complement = complement
                            .get_or_insert_with(|| P::add(circuit, &powers.one, coordinate))
                            .clone();
                        if target == UNIT {
                            complement
                        } else {
                            P::mul(circuit, &targets[target], &complement)
                        }
                    }
                    PowerFold::High(UNIT) => coordinate.clone(),
                    PowerFold::High(target) => P::mul(circuit, &targets[target], coordinate),
                    PowerFold::Both(lo, hi, lo_shift, hi_shift) => {
                        let lo = scaled::<P, CF>(circuit, powers, &targets, lo, lo_shift);
                        let hi = scaled::<P, CF>(circuit, powers, &targets, hi, hi_shift);
                        let slope = P::add(circuit, &lo, &hi);
                        let product = P::mul(circuit, coordinate, &slope);
                        P::add(circuit, &lo, &product)
                    }
                };
                targets.push(value);
                memo.insert(fold, targets.len() - 1);
                circuit.check_construction_limits()?;
                targets.len() - 1
            };
            next.push((index >> 1, folded, low));
        }
        layer = next;
    }
    match layer.first() {
        None => P::constant(circuit, 0),
        Some(&(_, target, exponent)) => {
            Ok(scaled::<P, CF>(circuit, powers, &targets, target, exponent))
        }
    }
}

/// `targets[target] * base^exponent`.
fn scaled<P, CF>(
    circuit: &mut CircuitBuilder<CF>,
    powers: &mut Powers<P::ChallengeTarget>,
    targets: &[P::ChallengeTarget],
    target: usize,
    exponent: usize,
) -> P::ChallengeTarget
where
    CF: Field + Eq + Hash,
    P: BinaryWhirPolicy<CF>,
{
    if exponent == 0 {
        return targets[target].clone();
    }
    let power = powers.get::<P, CF>(circuit, exponent);
    if target == UNIT {
        power
    } else {
        P::mul(circuit, &targets[target], &power)
    }
}

fn eval_table_using<P, CF>(
    circuit: &mut CircuitBuilder<CF>,
    values: &[P::ChallengeTarget],
    point: &[P::ChallengeTarget],
    multilinear: bool,
) -> Result<P::ChallengeTarget, CircuitBuilderError>
where
    CF: Field + Eq + Hash,
    P: BinaryRelationPolicy<CF>,
{
    let expected = u32::try_from(point.len())
        .ok()
        .and_then(|bits| 1usize.checked_shl(bits));
    if expected != Some(values.len()) {
        return Err(CircuitBuilderError::NonPrimitiveOpArity {
            op: "BinaryWhirEvaluation",
            expected: alloc::format!("2^{} table entries", point.len()),
            got: values.len(),
        });
    }
    circuit.check_construction_limits()?;
    let mut layer = values.to_vec();
    for coordinate in point.iter().rev() {
        layer = layer
            .as_chunks::<2>()
            .0
            .iter()
            .map(|pair| {
                let slope = if multilinear {
                    P::add(circuit, &pair[0], &pair[1])
                } else {
                    pair[1].clone()
                };
                let product = P::mul(circuit, coordinate, &slope);
                let value = P::add(circuit, &pair[0], &product);
                circuit.check_construction_limits()?;
                Ok(value)
            })
            .collect::<Result<_, CircuitBuilderError>>()?;
    }
    Ok(layer[0].clone())
}

/// Reconstructs released tower-domain WHIR query coordinates
/// `[W_(n-1)(x), ..., W_0(x)]` from little-endian index bits, with
/// `x = domain_point(index)` in the alphabet's own Cantor basis. The Cantor
/// recurrence makes each coordinate the linear map of `index >> j`.
/// Every index bit is constrained even when the coordinate point is empty.
/// Targets must belong to this builder.
pub fn binary_whir_query_point<F, EF>(
    circuit: &mut CircuitBuilder<EF>,
    index_bits: &[ExprId],
    num_variables: usize,
) -> Result<Vec<BinaryTower128Target>, CircuitBuilderError>
where
    F: RecursiveBinaryTowerField,
    EF: Field + Eq + Hash,
{
    if index_bits.len() > F::RAW_BITS || num_variables > F::RAW_BITS {
        return Err(CircuitBuilderError::NonPrimitiveOpArity {
            op: "BinaryWhirQueryPoint",
            expected: alloc::format!("at most {} alphabet coordinates", F::RAW_BITS),
            got: index_bits.len().max(num_variables),
        });
    }
    // The constructor checks the carrier characteristic even for empty points.
    let zero = circuit.binary128_constant(0)?.bits()[0];
    for &bit in index_bits {
        circuit.assert_bool(bit);
    }
    let columns = (0..index_bits.len())
        .map(|i| F::cantor_basis(i).raw_coordinates())
        .collect::<Vec<_>>();
    (0..num_variables)
        .rev()
        .map(|shift| {
            let bits = core::array::from_fn(|out| {
                let mut terms = index_bits
                    .iter()
                    .skip(shift)
                    .zip(&columns)
                    .filter_map(|(&bit, &basis)| (basis >> out & 1 != 0).then_some(bit));
                terms.next().map_or(zero, |first| {
                    terms.fold(first, |sum, bit| {
                        let difference = circuit.sub(sum, bit);
                        circuit.mul(difference, difference)
                    })
                })
            });
            circuit.binary128_from_bits(bits)
        })
        .collect()
}

fn arity(op: &'static str, expected: usize, got: usize) -> CircuitBuilderError {
    CircuitBuilderError::NonPrimitiveOpArity {
        op,
        expected: alloc::format!("{expected} point coordinates"),
        got,
    }
}

#[cfg(test)]
mod construction_tests {
    use p3_binary_field::TowerLevel;
    use p3_circuit::CircuitConstructionLimits;
    use p3_circuit::ops::NativeTower128Target;

    use super::*;
    use crate::verifier::binary_field_policy::{BinaryProtocolPolicy, NativeTower128Relation};

    #[test]
    fn native_whir_fold_checks_each_pair_in_a_large_layer() {
        let mut b =
            CircuitBuilder::<BinaryField128>::with_construction_limits(CircuitConstructionLimits {
                max_expression_nodes: 15,
                max_pending_connects: 1024,
                max_non_primitive_calls: 1024,
                max_non_primitive_slots: 1024,
            })
            .unwrap();
        let mut scalar = || {
            let value = b.alloc_private_input("fold field");
            b.native_tower128_from_expr(value)
        };
        let values = (0..8).map(|_| scalar()).collect::<Vec<_>>();
        let point = (0..3).map(|_| scalar()).collect::<Vec<_>>();
        assert!(matches!(
            eval_multilinear_using::<NativeTower128Relation, BinaryField128>(
                &mut b, &values, &point
            ),
            Err(CircuitBuilderError::ConstructionLimitExceeded { .. })
        ));
        assert!(b.construction_usage().unwrap().expression_nodes <= 18);
        assert!(b.build().is_err());
    }

    type Native = NativeTower128Relation;

    fn scalar(b: &mut CircuitBuilder<BinaryField128>) -> NativeTower128Target {
        let value = b.alloc_private_input("power table field");
        b.native_tower128_from_expr(value)
    }

    /// The dense table holding `base^(k + shift)` at `indices[k]`, built
    /// with an explicit power chain.
    fn dense_power_table(
        b: &mut CircuitBuilder<BinaryField128>,
        indices: &[usize],
        point: &[NativeTower128Target],
        base: &NativeTower128Target,
        shift: usize,
    ) -> NativeTower128Target {
        let zero = Native::constant(b, 0).unwrap();
        let mut table = alloc::vec![zero; 1 << point.len()];
        let mut power = Native::constant(b, 1).unwrap();
        for _ in 0..shift {
            power = Native::mul(b, &power, base);
        }
        for &index in indices {
            table[index] = Native::add(b, &table[index], &power);
            power = Native::mul(b, &power, base);
        }
        eval_multilinear_using::<Native, BinaryField128>(b, &table, point).unwrap()
    }

    /// Folding powers as shared partial products is a re-association of the
    /// dense table of explicit powers: the two agree on contiguous runs at
    /// unaligned offsets, scattered and repeated slots, descending slots, an
    /// empty table and an empty point, and a table of shifted powers differs.
    #[test]
    fn power_tables_evaluate_the_dense_table_of_explicit_powers() {
        let cases: [(usize, &[usize]); 8] = [
            (0, &[]),
            (0, &[0]),
            (0, &[0, 0, 0]),
            (2, &[]),
            (3, &[2, 3, 4, 5]),
            (4, &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13]),
            (4, &[9, 3, 12, 3, 0, 15, 14]),
            (5, &[31, 30, 29, 28, 7]),
        ];
        for (variables, indices) in cases {
            for shift in [0, 1] {
                let mut b = CircuitBuilder::<BinaryField128>::new();
                let base = scalar(&mut b);
                let point: Vec<_> = (0..variables).map(|_| scalar(&mut b)).collect();
                let mut powers = Powers::new::<Native, BinaryField128>(&mut b, &base).unwrap();
                let folded = eval_power_table_using::<Native, BinaryField128>(
                    &mut b,
                    indices,
                    &point,
                    &mut powers,
                )
                .unwrap();
                let dense = dense_power_table(&mut b, indices, &point, &base, shift);
                Native::assert_equal(&mut b, &folded, &dense);
                let inputs: Vec<_> = (0..=variables as u128)
                    .map(|i| {
                        BinaryField128::from_repr(
                            0x9e37_79b9_7f4a_7c15_f39c_c060_5ced_c834 ^ (i << 7),
                        )
                    })
                    .collect();
                let circuit = b.build().unwrap();
                let mut runner = circuit.runner();
                runner.set_private_inputs(&inputs).unwrap();
                let agrees = runner.run().is_ok();
                assert_eq!(
                    agrees,
                    shift == 0 || indices.is_empty(),
                    "{variables} variables, slots {indices:?}, shift {shift}"
                );
            }
        }
    }

    /// Consecutive powers at a run of consecutive slots cost a bounded
    /// number of operations per selector coordinate, not per slot.
    #[test]
    fn a_run_of_consecutive_slots_folds_per_coordinate() {
        let mut b = CircuitBuilder::<BinaryField128>::new();
        let base = scalar(&mut b);
        let point: Vec<_> = (0..11).map(|_| scalar(&mut b)).collect();
        let mut powers = Powers::new::<Native, BinaryField128>(&mut b, &base).unwrap();
        let slots: Vec<_> = (37..37 + 1602).collect();
        let before = b.construction_usage().unwrap().expression_nodes;
        eval_power_table_using::<Native, BinaryField128>(&mut b, &slots, &point, &mut powers)
            .unwrap();
        let added = b.construction_usage().unwrap().expression_nodes - before;
        assert!(added <= 12 * point.len(), "{added} expression nodes");
    }
}
