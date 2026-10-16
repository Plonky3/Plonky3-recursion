//! Sparse raw-coordinate extraction over a native binary field.

use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec::Vec;
use alloc::{format, vec};

use super::BinaryCoordinateField;
use crate::ops::HintExecutor;
use crate::{CircuitBuilder, CircuitBuilderError, CircuitError, ExprId, WitnessId};

/// Reusable constants for reading one raw coordinate without decomposing a field element.
///
/// If `delta` is the trace-dual of coordinate `i` and `Tr(kappa) = 1`, then
/// Boolean `t` is coordinate `i` of `x` exactly when some `z` satisfies
/// `z² + z = delta * x + kappa * t`. Tracing this equality proves the claim.
/// The hint chooses a root with raw coordinate zero cleared; both roots are valid.
///
/// Construction derives and checks the constants in the field's own encoding.
/// Reuse an extractor across rows: its witness lookup tables are shared by `Arc`.
#[derive(Clone, Debug)]
pub struct BinaryCoordinateExtractor<F> {
    column: usize,
    dual: F,
    trace_one: F,
    roots: Arc<[[F; 16]]>,
}

impl<F: BinaryCoordinateField> BinaryCoordinateExtractor<F> {
    /// Prepare the trace coordinate and a linear Artin–Schreier witness map.
    pub fn new(column: usize) -> Result<Self, CircuitBuilderError> {
        let n = F::COORDINATE_BITS;
        if column >= n {
            return Err(CircuitBuilderError::BinaryDecompositionTooManyBits {
                expected: n,
                n_bits: column.saturating_add(1),
            });
        }
        let raw = |value| F::from_raw_coordinates(value).expect("a field-width raw coordinate");
        assert_eq!(raw(1), F::ONE, "coordinate zero must represent one");
        let trace_mask = (0..n).fold(0u128, |mask, i| {
            let value = absolute_trace(raw(1u128 << i));
            assert!(value == F::ZERO || value == F::ONE, "trace lands in GF(2)");
            mask | (u128::from(value == F::ONE) << i)
        });
        assert_ne!(trace_mask, 0, "the absolute trace is nonzero");
        let trace_one = raw(1u128 << trace_mask.trailing_zeros());
        let pairing =
            |a: F, b: F| ((a * b).to_raw_coordinates() & trace_mask).count_ones() & 1 != 0;
        // Solve the nondegenerate trace form G * dual = e_column over GF(2).
        let mut form: Vec<u128> = (0..n)
            .map(|i| {
                (0..n).fold(0, |row, j| {
                    row | (u128::from(pairing(raw(1u128 << i), raw(1u128 << j))) << j)
                })
            })
            .collect();
        let mut rhs: Vec<bool> = (0..n).map(|i| i == column).collect();
        for j in 0..n {
            let pivot = (j..n)
                .find(|&i| form[i] >> j & 1 != 0)
                .expect("the trace form is nondegenerate");
            form.swap(j, pivot);
            rhs.swap(j, pivot);
            for i in 0..n {
                if i != j && form[i] >> j & 1 != 0 {
                    form[i] ^= form[j];
                    rhs[i] ^= rhs[j];
                }
            }
        }
        let dual = raw(rhs
            .iter()
            .enumerate()
            .fold(0, |value, (i, &bit)| value | (u128::from(bit) << i)));
        for i in 0..n {
            assert_eq!(pairing(dual, raw(1u128 << i)), i == column);
        }
        assert_eq!(absolute_trace(trace_one), F::ONE);

        // On the span of beta_1,...,beta_(n-1), z -> z²+z is an isomorphism
        // onto the trace-zero subspace: its full kernel is {0,1}.
        let mut pivots = vec![0u128; n];
        let mut solutions = vec![0u128; n];
        for i in 1..n {
            let x = raw(1u128 << i);
            let mut image = (x.square() + x).to_raw_coordinates();
            let mut solution = 1u128 << i;
            for bit in (0..n).rev() {
                if image >> bit & 1 == 0 {
                    continue;
                }
                if pivots[bit] == 0 {
                    pivots[bit] = image;
                    solutions[bit] = solution;
                    image = 0;
                    break;
                }
                image ^= pivots[bit];
                solution ^= solutions[bit];
            }
            assert_eq!(image, 0);
        }
        assert_eq!(pivots.iter().filter(|&&pivot| pivot != 0).count(), n - 1);
        // Tables are indexed by x, not by an arbitrary right-hand side.
        // Each delta*beta_i + kappa*[i=column] already has trace zero.
        let matrix: Vec<F> = (0..n)
            .map(|i| {
                let value = dual * raw(1u128 << i) + trace_one * F::from_bool(i == column);
                let mut image = value.to_raw_coordinates();
                let mut solution = 0u128;
                for bit in (0..n).rev() {
                    if image >> bit & 1 != 0 {
                        assert_ne!(pivots[bit], 0, "the coordinate RHS has trace zero");
                        image ^= pivots[bit];
                        solution ^= solutions[bit];
                    }
                }
                assert_eq!(image, 0);
                let root = raw(solution);
                assert_eq!(root.square() + root, value);
                root
            })
            .collect();
        let roots: Vec<[F; 16]> = (0..n.div_ceil(4))
            .map(|limb| {
                core::array::from_fn(|value| {
                    (0..4)
                        .filter(|&bit| 4 * limb + bit < n && value >> bit & 1 != 0)
                        .fold(F::ZERO, |sum, bit| sum + matrix[4 * limb + bit])
                })
            })
            .collect();
        Ok(Self {
            column,
            dual,
            trace_one,
            roots: roots.into(),
        })
    }

    /// Read the checked coordinate with at most four ALU operations.
    /// Constants and previously decomposed coordinates reuse their checked values.
    /// IDs must belong to `b`. This does not constrain any other coordinate of `value`.
    pub fn extract(
        &self,
        b: &mut CircuitBuilder<F>,
        value: ExprId,
    ) -> Result<ExprId, CircuitBuilderError> {
        b.check_construction_limits()?;
        if let Some(constant) = b.constant_value(value) {
            let bit = b.define_const(F::from_bool(
                constant.to_raw_coordinates() >> self.column & 1 != 0,
            ));
            b.check_construction_limits()?;
            return Ok(bit);
        }
        if let Some(bits) = b.native_coordinates(value) {
            // A cached prefix includes a reconstruction constraint, so higher bits are zero.
            return Ok(bits.get(self.column).copied().unwrap_or(ExprId::ZERO));
        }
        if F::COORDINATE_BITS == 1 {
            return Ok(value);
        }
        let outputs = b
            .push_unconstrained_op(
                vec![vec![value]],
                2,
                CoordinateHint {
                    column: self.column,
                    roots: self.roots.clone(),
                },
                "binary_extract_coordinate",
            )
            .2
            .into_iter()
            .collect::<Option<Vec<_>>>()
            .ok_or(CircuitBuilderError::MissingOutput)?;
        let [bit, root] = outputs.as_slice() else {
            return Err(CircuitBuilderError::MissingOutput);
        };
        self.constrain(b, value, *bit, *root);
        b.check_construction_limits()?;
        Ok(*bit)
    }

    fn constrain(&self, b: &mut CircuitBuilder<F>, value: ExprId, bit: ExprId, root: ExprId) {
        b.assert_bool(bit);
        let dual = b.define_const(self.dual);
        let trace_one = b.define_const(self.trace_one);
        let scaled = b.mul(value, dual);
        let linear = b.mul_add(bit, trace_one, root);
        let left = b.mul_add(root, root, linear);
        b.connect(left, scaled);
    }
}

fn absolute_trace<F: BinaryCoordinateField>(x: F) -> F {
    let mut power = x;
    let mut sum = x;
    for _ in 1..F::COORDINATE_BITS {
        power = power.square();
        sum += power;
    }
    sum
}

#[derive(Clone, Debug)]
struct CoordinateHint<F> {
    column: usize,
    roots: Arc<[[F; 16]]>,
}

impl<F: BinaryCoordinateField> HintExecutor<F> for CoordinateHint<F> {
    fn execute(
        &self,
        inputs: &[WitnessId],
        outputs: &[WitnessId],
        witness: &mut [Option<F>],
    ) -> Result<(), CircuitError> {
        if inputs.len() != 1 {
            return Err(CircuitError::UnconstrainedOpInputLengthMismatch {
                op: "CoordinateHint".into(),
                expected: 1,
                got: inputs.len(),
            });
        }
        // Only extract() constructs this private hint, with two outputs.
        assert_eq!(outputs.len(), 2);
        let input = inputs[0];
        let raw = witness
            .get(input.0 as usize)
            .ok_or(CircuitError::WitnessIdOutOfBounds { witness_id: input })?
            .ok_or(CircuitError::WitnessNotSet { witness_id: input })?
            .to_raw_coordinates();
        let bit = F::from_bool(raw >> self.column & 1 != 0);
        let root = self
            .roots
            .iter()
            .enumerate()
            .fold(F::ZERO, |sum, (i, table)| {
                sum + table[(raw >> (4 * i)) as usize & 15]
            });
        for (&output, value) in outputs.iter().zip([bit, root]) {
            let slot = witness
                .get_mut(output.0 as usize)
                .ok_or(CircuitError::WitnessIdOutOfBounds { witness_id: output })?;
            if let Some(existing) = slot {
                if *existing != value {
                    return Err(CircuitError::WitnessConflict {
                        witness_id: output,
                        existing: format!("{existing:?}"),
                        new: format!("{value:?}"),
                        expr_ids: vec![],
                    });
                }
            } else {
                *slot = Some(value);
            }
        }
        Ok(())
    }

    fn boxed(&self) -> Box<dyn HintExecutor<F>> {
        Box::new(self.clone())
    }
}

#[cfg(test)]
mod tests {
    use p3_binary_field::{BinaryField128, Ghash128, Poly64};

    use super::*;

    fn check_constraints<F: BinaryCoordinateField>() {
        let extractor = BinaryCoordinateExtractor::<F>::new(3).unwrap();
        let mut b = CircuitBuilder::<F>::new();
        let x = b.public_input();
        let bit = b.public_input();
        let root = b.public_input();
        extractor.constrain(&mut b, x, bit, root);
        let circuit = b.build().unwrap();
        let accepts = |values: &[F]| {
            let mut runner = circuit.runner();
            runner
                .set_public_inputs(values)
                .and_then(|()| runner.run())
                .is_ok()
        };
        let raw = 0b1011u128;
        let x = F::from_raw_coordinates(raw).unwrap();
        let z = extractor.roots[0][raw as usize];
        assert!(accepts(&[x, F::ONE, z]));
        assert!(accepts(&[x, F::ONE, z + F::ONE]));
        assert!(!accepts(&[x, F::ZERO, z]));
        let non_boolean = F::from_raw_coordinates(2).unwrap();
        assert!(!accepts(&[x, F::ONE, z + non_boolean]));
    }

    #[test]
    fn sparse_coordinate_constraints_bind_the_bit_and_allow_both_roots() {
        check_constraints::<BinaryField128>();
        check_constraints::<Ghash128>();
        check_constraints::<Poly64>();
    }
}
