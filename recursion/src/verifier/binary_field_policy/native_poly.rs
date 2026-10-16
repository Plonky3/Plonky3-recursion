//! Native Poly64 cells and the released cubic Poly192 challenge basis.

use alloc::vec::Vec;

use p3_circuit::ops::NativePoly192Target;

use super::*;
use crate::pcs::binary::BinaryPolyNonzeroChallengeTailOutput;

/// Captured Poly64 domain seeds use raw little-endian transcript bytes.
pub(crate) fn poly_seed_bytes_with_host<H, CF>(
    b: &mut CircuitBuilder<CF>,
    seed: &[Poly64],
) -> Result<Vec<ExprId>, CircuitBuilderError>
where
    CF: Field + Eq + Hash,
    H: BinaryCircuitHost<CF>,
{
    seed.iter()
        .flat_map(|value| value.to_bits().to_le_bytes())
        .map(|byte| Ok(b.define_const(H::encode_u16(u16::from(byte))?)))
        .collect()
}

pub(crate) fn poly_observe_seed_with_host<H, CF>(
    b: &mut CircuitBuilder<CF>,
    ch: &mut BinaryTower128Challenger,
    seed: &[Poly64],
) -> Result<(), VerificationError>
where
    CF: Field + Eq + Hash,
    H: BinaryCircuitHost<CF>,
{
    let bytes = poly_seed_bytes_with_host::<H, CF>(b, seed)?;
    Ok(ch.observe_bytes_with_host::<H, CF>(b, &bytes)?)
}

/// Uniform coefficient blocks; callers derive the exact cell count from their
/// trusted schedule, including any base-field grinding witnesses.
pub(crate) fn poly_native_values(
    limbs: &[u16],
    cells: usize,
) -> Result<Vec<Poly64>, VerificationError> {
    let expected = cells
        .checked_mul(4)
        .ok_or(VerificationError::ResourceArithmeticOverflow {
            component: "native polynomial coefficient limbs",
        })?;
    if limbs.len() != expected {
        return Err(VerificationError::InvalidProofShape(
            "native polynomial coefficient count mismatch".into(),
        ));
    }
    Ok(limbs
        .as_chunks::<4>()
        .0
        .iter()
        .map(|limbs| {
            let raw = limbs
                .iter()
                .enumerate()
                .fold(0u64, |raw, (i, &limb)| raw | (u64::from(limb) << (16 * i)));
            Poly64::new(raw)
        })
        .collect())
}

/// Preserves direct coefficient scaling in the shared interpolation kernel.
pub(crate) trait BinaryPolyPolicy<CF: Field + Eq + Hash>:
    BinaryRelationPolicy<CF, Base = Poly64, Challenge = Poly192>
{
    fn challenge_bits(
        b: &mut CircuitBuilder<CF>,
        value: &Self::ChallengeTarget,
    ) -> Result<[ExprId; 192], CircuitBuilderError>;
    /// Draws `count` nonzero challenges within `max_draws`, the
    /// `following_count` draws after them and the continuation after those.
    fn sample_nonzero<H: BinaryCircuitHost<CF>>(
        b: &mut CircuitBuilder<CF>,
        ch: BinaryTower128Challenger,
        count: usize,
        max_draws: usize,
        following_count: usize,
    ) -> Result<BinaryPolyNonzeroChallengeTailOutput<Self::ChallengeTarget>, VerificationError>;
    fn observe_base<H: BinaryCircuitHost<CF>>(
        b: &mut CircuitBuilder<CF>,
        ch: &mut BinaryTower128Challenger,
        values: &[Self::BaseTarget],
    ) -> Result<(), VerificationError>;
    fn scale_base_constant(
        b: &mut CircuitBuilder<CF>,
        value: &Self::ChallengeTarget,
        raw: u64,
    ) -> Result<Self::ChallengeTarget, CircuitBuilderError>;
}

impl<CF: Field + Eq + Hash> BinaryPolyPolicy<CF> for Poly64Relation {
    fn challenge_bits(
        _b: &mut CircuitBuilder<CF>,
        value: &BinaryPoly192Target,
    ) -> Result<[ExprId; 192], CircuitBuilderError> {
        Ok(core::array::from_fn(|i| {
            value.coefficients()[i / 64].bits()[i % 64]
        }))
    }
    fn sample_nonzero<H: BinaryCircuitHost<CF>>(
        b: &mut CircuitBuilder<CF>,
        ch: BinaryTower128Challenger,
        count: usize,
        max_draws: usize,
        following_count: usize,
    ) -> Result<BinaryPolyNonzeroChallengeTailOutput, VerificationError> {
        crate::pcs::binary::sample_nonzero_bits::<H, CF>(b, ch, count, max_draws, following_count)
    }
    fn observe_base<H: BinaryCircuitHost<CF>>(
        b: &mut CircuitBuilder<CF>,
        ch: &mut BinaryTower128Challenger,
        values: &[BinaryPoly64Target],
    ) -> Result<(), VerificationError> {
        let bytes = values
            .iter()
            .flat_map(|value| value.bits().as_chunks::<8>().0.iter())
            .map(|bits| H::recompose_word(b, bits))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(ch.observe_bytes_with_host::<H, CF>(b, &bytes)?)
    }
    fn scale_base_constant(
        b: &mut CircuitBuilder<CF>,
        value: &BinaryPoly192Target,
        raw: u64,
    ) -> Result<BinaryPoly192Target, CircuitBuilderError> {
        let constant = b.binary_poly64_constant(raw)?;
        Ok(b.binary_poly192_scale(value, &constant))
    }
}

pub(crate) struct NativePoly64Relation;
impl sealed::Relation for NativePoly64Relation {}
impl BinaryRelationPolicy<Poly64> for NativePoly64Relation {
    type Base = Poly64;
    type Challenge = Poly192;
    type BaseTarget = ExprId;
    type ChallengeTarget = NativePoly192Target;
    const FUSES_AIR_SUMS: bool = true;
    const SCALAR_INTERPOLATION: bool = true;

    fn constant(
        b: &mut CircuitBuilder<Poly64>,
        raw: u128,
    ) -> Result<NativePoly192Target, CircuitBuilderError> {
        let raw = u64::try_from(raw).map_err(|_| {
            CircuitBuilderError::BinaryDecompositionTooManyBits {
                expected: 64,
                n_bits: (128 - raw.leading_zeros()) as usize,
            }
        })?;
        Ok(b.native_poly192_constant([raw, 0, 0]))
    }
    fn lift(
        b: &mut CircuitBuilder<Poly64>,
        value: &ExprId,
    ) -> Result<NativePoly192Target, CircuitBuilderError> {
        Ok(b.native_poly192_from_coefficients([*value, ExprId::ZERO, ExprId::ZERO]))
    }
    fn constrain_base(
        _b: &mut CircuitBuilder<Poly64>,
        _value: &ExprId,
    ) -> Result<(), CircuitBuilderError> {
        Ok(())
    }
    fn constrain_challenge(_b: &mut CircuitBuilder<Poly64>, _value: &NativePoly192Target) {}
    fn add(
        b: &mut CircuitBuilder<Poly64>,
        a: &NativePoly192Target,
        c: &NativePoly192Target,
    ) -> NativePoly192Target {
        b.native_poly192_add(a, c)
    }
    fn mul(
        b: &mut CircuitBuilder<Poly64>,
        a: &NativePoly192Target,
        c: &NativePoly192Target,
    ) -> NativePoly192Target {
        b.native_poly192_mul(a, c)
    }
    /// The product of `native_poly192_mul`, reduced by `y³ = y + 1` and
    /// `y⁴ = y² + y`, with every sum folded into a multiply-add: each
    /// coefficient of `d` joins the gate that takes that coefficient's last
    /// partial product.
    fn mul_add(
        b: &mut CircuitBuilder<Poly64>,
        a: &NativePoly192Target,
        c: &NativePoly192Target,
        d: &NativePoly192Target,
    ) -> NativePoly192Target {
        let [a0, a1, a2] = *a.coefficients();
        let [c0, c1, c2] = *c.coefficients();
        let [d0, d1, d2] = *d.coefficients();
        // The y³ and y⁴ coefficients of the product.
        let cross = b.mul(a1, c2);
        let cross = b.mul_add(a2, c1, cross);
        let high = b.mul(a2, c2);
        let out0 = char2_mul_add_add(b, a0, c0, cross, d0);
        let out1 = char2_mul_add_add(b, a0, c1, cross, high);
        let out1 = char2_mul_add_add(b, a1, c0, out1, d1);
        let out2 = b.mul_add(a0, c2, high);
        let out2 = b.mul_add(a1, c1, out2);
        let out2 = char2_mul_add_add(b, a2, c0, out2, d2);
        b.native_poly192_from_coefficients([out0, out1, out2])
    }
    /// [`Self::mul_add`] with the second addend `e` in one more operation, the
    /// sum `d₂ + e₂`. `e₀` joins the shared `y³` terms and `e₀ + e₁` the shared
    /// `y⁴` term, which give `e₀` to the constant coefficient and `e₁` to the
    /// linear one. The quadratic coefficient cancels the `e₀ + e₁` it receives
    /// in its two free addend slots.
    fn mul_add_add(
        b: &mut CircuitBuilder<Poly64>,
        a: &NativePoly192Target,
        c: &NativePoly192Target,
        d: &NativePoly192Target,
        e: &NativePoly192Target,
    ) -> NativePoly192Target {
        let zero = [ExprId::ZERO; 3];
        if *a.coefficients() == zero || *c.coefficients() == zero {
            return b.native_poly192_add(d, e);
        }
        let [a0, a1, a2] = *a.coefficients();
        let [c0, c1, c2] = *c.coefficients();
        let [d0, d1, d2] = *d.coefficients();
        let [e0, e1, e2] = *e.coefficients();
        let cross = b.mul_add(a1, c2, e0);
        let cross = b.mul_add(a2, c1, cross);
        let high = char2_mul_add_add(b, a2, c2, e0, e1);
        let out0 = char2_mul_add_add(b, a0, c0, cross, d0);
        let out1 = char2_mul_add_add(b, a0, c1, cross, high);
        let out1 = char2_mul_add_add(b, a1, c0, out1, d1);
        let out2 = char2_mul_add_add(b, a0, c2, high, e0);
        let out2 = char2_mul_add_add(b, a1, c1, out2, e1);
        let tail = b.add(d2, e2);
        let out2 = char2_mul_add_add(b, a2, c0, out2, tail);
        b.native_poly192_from_coefficients([out0, out1, out2])
    }
}

impl BinaryPolyPolicy<Poly64> for NativePoly64Relation {
    fn challenge_bits(
        b: &mut CircuitBuilder<Poly64>,
        value: &NativePoly192Target,
    ) -> Result<[ExprId; 192], CircuitBuilderError> {
        b.native_poly192_to_bits(value)
    }
    fn sample_nonzero<H: BinaryCircuitHost<Poly64>>(
        b: &mut CircuitBuilder<Poly64>,
        ch: BinaryTower128Challenger,
        count: usize,
        max_draws: usize,
        following_count: usize,
    ) -> Result<BinaryPolyNonzeroChallengeTailOutput<NativePoly192Target>, VerificationError> {
        crate::pcs::binary::sample_nonzero_cells::<H>(b, ch, count, max_draws, following_count)
    }
    fn observe_base<H: BinaryCircuitHost<Poly64>>(
        b: &mut CircuitBuilder<Poly64>,
        ch: &mut BinaryTower128Challenger,
        values: &[ExprId],
    ) -> Result<(), VerificationError> {
        // The refill that hashes these words range-checks each one.
        let mut words = Vec::with_capacity(4 * values.len());
        for &value in values {
            words.extend(b.native_poly64_unchecked_words(value, 4)?);
        }
        Ok(ch.observe_words_with_host::<H, Poly64>(b, &words)?)
    }
    fn scale_base_constant(
        b: &mut CircuitBuilder<Poly64>,
        value: &NativePoly192Target,
        raw: u64,
    ) -> Result<NativePoly192Target, CircuitBuilderError> {
        let constant = b.define_const(Poly64::new(raw));
        let coefficients = value
            .coefficients()
            .map(|coefficient| b.mul(coefficient, constant));
        Ok(b.native_poly192_from_coefficients(coefficients))
    }
}

impl BinaryProtocolPolicy<Poly64> for NativePoly64Relation {
    fn observe<H: BinaryCircuitHost<Poly64>>(
        b: &mut CircuitBuilder<Poly64>,
        ch: &mut BinaryTower128Challenger,
        values: &[NativePoly192Target],
    ) -> Result<(), VerificationError> {
        // The refill that hashes these words range-checks each one.
        let words = native_words(b, values)?;
        Ok(ch.observe_words_with_host::<H, Poly64>(b, &words)?)
    }
    fn observe_after_queries<H: BinaryCircuitHost<Poly64>>(
        b: &mut CircuitBuilder<Poly64>,
        token: crate::BinaryQueryContinuation,
        values: &[NativePoly192Target],
    ) -> Result<BinaryTower128Challenger, VerificationError> {
        // The refill of the draw that follows range-checks each word.
        let words = native_words(b, values)?;
        Ok(token.resume_with_words_with_host::<H, Poly64>(b, &words)?)
    }
    fn sample<H: BinaryCircuitHost<Poly64>>(
        b: &mut CircuitBuilder<Poly64>,
        ch: &mut BinaryTower128Challenger,
    ) -> Result<NativePoly192Target, VerificationError> {
        // Each coefficient reads eight drawn bytes as one little-endian cell,
        // packed from four drawn words without decomposing them.
        let words = ch.sample_words_with_host::<H, Poly64>(b, 12)?;
        let mut coefficients = [ExprId::ZERO; 3];
        for (coefficient, words) in coefficients.iter_mut().zip(words.as_chunks::<4>().0) {
            *coefficient = b.native_poly64_from_unchecked_words(*words)?;
        }
        Ok(b.native_poly192_from_coefficients(coefficients))
    }
    fn assert_equal(
        b: &mut CircuitBuilder<Poly64>,
        a: &NativePoly192Target,
        c: &NativePoly192Target,
    ) {
        for (&a, &c) in a.coefficients().iter().zip(c.coefficients()) {
            let difference = b.sub(a, c);
            b.assert_zero(difference);
        }
    }
    fn eq_eval(
        b: &mut CircuitBuilder<Poly64>,
        a: &[NativePoly192Target],
        c: &[NativePoly192Target],
    ) -> Result<NativePoly192Target, CircuitBuilderError> {
        assert_eq!(a.len(), c.len(), "binary equality point lengths differ");
        let one = b.native_poly192_constant([1, 0, 0]);
        let mut weight = one.clone();
        for (a, c) in a.iter().zip(c) {
            let sum = b.native_poly192_add(a, c);
            let equal = b.native_poly192_add(&one, &sum);
            weight = b.native_poly192_mul(&weight, &equal);
        }
        Ok(weight)
    }
}

/// The twelve low-first sixteen-bit words of each value's 24 codec bytes,
/// which only a refill that hashes them range-checks. The codec emits
/// coefficient 0, then 1, then 2, each as eight little-endian bytes.
fn native_words(
    b: &mut CircuitBuilder<Poly64>,
    values: &[NativePoly192Target],
) -> Result<Vec<ExprId>, CircuitBuilderError> {
    let mut words = Vec::with_capacity(12 * values.len());
    for value in values {
        for &coefficient in value.coefficients() {
            words.extend(b.native_poly64_unchecked_words(coefficient, 4)?);
        }
    }
    Ok(words)
}

#[cfg(test)]
mod tests {
    use p3_binary_field::BinaryChallenger;
    use p3_challenger::{CanObserve, CanSampleBits, FieldChallenger, HashChallenger};
    use p3_circuit::ops::ByteHash;
    use p3_circuit::ops::binary_encoding::{BinaryCircuitEncoding, NativeBinaryEncoding};
    use p3_field::PrimeCharacteristicRing;
    use p3_keccak::Keccak256Hash;
    use p3_symmetric::Hash as Digest;
    use rand::rngs::SmallRng;
    use rand::{RngExt, SeedableRng};

    use super::*;

    type H = NativeBinaryEncoding;
    type P = NativePoly64Relation;

    #[derive(Clone, Copy, Debug)]
    enum Operand {
        /// Three public coefficients.
        Public,
        /// One public coefficient over two constant zeros, as a lifted base value.
        Lifted,
        /// The constant zero.
        Zero,
    }

    /// Every assignment of operand kinds to `a`, `c` and `d`.
    fn operand_kinds() -> impl Iterator<Item = [Operand; 3]> {
        const KINDS: [Operand; 3] = [Operand::Public, Operand::Lifted, Operand::Zero];
        (0..27).map(|i| [i % 3, i / 3 % 3, i / 9].map(|k| KINDS[k]))
    }

    /// The target of `operand`, allocating its public coefficients.
    fn operand(b: &mut CircuitBuilder<Poly64>, operand: Operand) -> NativePoly192Target {
        match operand {
            Operand::Public => {
                let coefficients = b.alloc_public_input_array::<3>("operand");
                b.native_poly192_from_coefficients(coefficients)
            }
            Operand::Lifted => {
                let coefficient = b.public_input();
                b.native_poly192_from_coefficients([coefficient, ExprId::ZERO, ExprId::ZERO])
            }
            Operand::Zero => b.native_poly192_constant([0; 3]),
        }
    }

    /// The part of `value` that `operand` can hold.
    fn restrict(operand: Operand, value: Poly192) -> Poly192 {
        let [c0, ..] = value.coefficients();
        match operand {
            Operand::Public => value,
            Operand::Lifted => Poly192::new([c0, Poly64::ZERO, Poly64::ZERO]),
            Operand::Zero => Poly192::ZERO,
        }
    }

    /// Binds `P::mul_add(a, c, d)` when `fused`, else `P::mul(a, c) + d`, to
    /// three public expected coefficients, allocated after the operands'
    /// public coefficients.
    fn mul_add_circuit(operands: [Operand; 3], fused: bool) -> p3_circuit::Circuit<Poly64> {
        let mut b = CircuitBuilder::<Poly64>::new();
        let [a, c, d] = operands.map(|kind| operand(&mut b, kind));
        let expected = b.alloc_public_input_array::<3>("a * c + d");
        let expected = b.native_poly192_from_coefficients(expected);
        let value = if fused {
            P::mul_add(&mut b, &a, &c, &d)
        } else {
            let product = P::mul(&mut b, &a, &c);
            P::add(&mut b, &product, &d)
        };
        P::assert_equal(&mut b, &value, &expected);
        b.build().unwrap()
    }

    /// Whether `circuit` accepts the operands' `values` with `expected`.
    fn mul_add_runs<const N: usize>(
        circuit: &p3_circuit::Circuit<Poly64>,
        operands: [Operand; N],
        values: [Poly192; N],
        expected: Poly192,
    ) -> bool {
        let mut public = Vec::new();
        for (operand, value) in operands.into_iter().zip(values) {
            let coefficients = value.coefficients();
            match operand {
                Operand::Public => public.extend(coefficients),
                Operand::Lifted => public.push(coefficients[0]),
                Operand::Zero => {}
            }
        }
        public.extend(expected.coefficients());
        let mut runner = circuit.runner();
        runner
            .set_public_inputs(&public)
            .and_then(|()| runner.run())
            .is_ok()
    }

    /// The native multiply-add computes the Poly192 `a * c + d`, as the
    /// in-circuit product and sum do, for public, lifted and constant zero
    /// operands. Its gates enforce each of the four reductions of the y³ and y⁴
    /// coefficients and keep the addend out of the product: neither `d * c + a`
    /// nor `a * d + c` is accepted.
    #[test]
    fn native_poly_mul_add_is_the_product_plus_the_addend() {
        let mut rng = SmallRng::seed_from_u64(17);
        let random: [Poly192; 3] = core::array::from_fn(|_| {
            Poly192::new(core::array::from_fn(|_| Poly64::new(rng.random())))
        });
        for operands in operand_kinds() {
            let circuit = mul_add_circuit(operands, true);
            let reference = mul_add_circuit(operands, false);
            let values: [Poly192; 3] = core::array::from_fn(|i| restrict(operands[i], random[i]));
            let [a, c, d] = values;
            let expected = a * c + d;
            for circuit in [&circuit, &reference] {
                assert!(
                    mul_add_runs(circuit, operands, values, expected),
                    "{operands:?}"
                );
            }
            let wrong = expected + Poly192::new([Poly64::ZERO, Poly64::ONE, Poly64::ZERO]);
            assert!(!mul_add_runs(&circuit, operands, values, wrong));
        }
        let operands = [Operand::Public; 3];
        let circuit = mul_add_circuit(operands, true);
        let reference = mul_add_circuit(operands, false);
        let [a, c, d] = random;
        let expected = a * c + d;
        assert!(!mul_add_runs(&circuit, operands, random, d * c + a));
        assert!(!mul_add_runs(&circuit, operands, random, a * d + c));
        let [_, a1, a2] = a.coefficients();
        let [_, c1, c2] = c.coefficients();
        let cross = a1 * c2 + a2 * c1;
        let high = a2 * c2;
        let zero = Poly64::ZERO;
        for dropped in [
            [cross, zero, zero],
            [zero, cross, zero],
            [zero, high, zero],
            [zero, zero, high],
        ] {
            let unreduced = expected - Poly192::new(dropped);
            assert!(!mul_add_runs(&circuit, operands, random, unreduced));
        }
        for i in 0..3 {
            let mut values = random;
            values[i] = Poly192::ZERO;
            let [a, c, d] = values;
            for circuit in [&circuit, &reference] {
                assert!(
                    mul_add_runs(circuit, operands, values, a * c + d),
                    "zero value {i}"
                );
            }
        }
    }

    /// The fused multiply-add never adds more expression nodes than the product
    /// and sum it replaces, and saves four of the thirteen for public operands.
    #[test]
    fn native_poly_mul_add_never_costs_more_than_the_product_and_sum() {
        let added = |operands: [Operand; 3], fused: bool| {
            let mut b = CircuitBuilder::<Poly64>::new();
            let [a, c, d] = operands.map(|kind| operand(&mut b, kind));
            let before = b.construction_usage().unwrap().expression_nodes;
            if fused {
                P::mul_add(&mut b, &a, &c, &d);
            } else {
                let product = P::mul(&mut b, &a, &c);
                P::add(&mut b, &product, &d);
            }
            b.construction_usage().unwrap().expression_nodes - before
        };
        for operands in operand_kinds() {
            assert!(
                added(operands, true) <= added(operands, false),
                "{operands:?}"
            );
        }
        let public = [Operand::Public; 3];
        assert_eq!(added(public, true), 9);
        assert_eq!(added(public, false), 13);
    }

    /// Binds `P::mul_add_add(a, c, d, e)` when `fused`, else `P::mul(a, c) + d + e`, to three
    /// public expected coefficients, allocated after the operands' public coefficients.
    fn mul_add_add_circuit(operands: [Operand; 4], fused: bool) -> p3_circuit::Circuit<Poly64> {
        let mut b = CircuitBuilder::<Poly64>::new();
        let [a, c, d, e] = operands.map(|kind| operand(&mut b, kind));
        let expected = b.alloc_public_input_array::<3>("a * c + d + e");
        let expected = b.native_poly192_from_coefficients(expected);
        let value = if fused {
            P::mul_add_add(&mut b, &a, &c, &d, &e)
        } else {
            let product = P::mul(&mut b, &a, &c);
            let partial = P::add(&mut b, &product, &d);
            P::add(&mut b, &partial, &e)
        };
        P::assert_equal(&mut b, &value, &expected);
        b.build().unwrap()
    }

    /// Every assignment of operand kinds to `a`, `c`, `d` and `e`.
    fn four_operand_kinds() -> impl Iterator<Item = [Operand; 4]> {
        operand_kinds().flat_map(|[a, c, d]| {
            [Operand::Public, Operand::Lifted, Operand::Zero].map(|e| [a, c, d, e])
        })
    }

    /// The native multiply-add with two addends computes the Poly192 `a * c + d + e`, as the
    /// in-circuit product and sums do, for public, lifted and constant zero operands. Its
    /// circuit binds that value: the value plus `y` is refused.
    #[test]
    fn native_poly_mul_add_add_is_the_product_plus_both_addends() {
        let mut rng = SmallRng::seed_from_u64(23);
        let random: [Poly192; 4] = core::array::from_fn(|_| {
            Poly192::new(core::array::from_fn(|_| Poly64::new(rng.random())))
        });
        for operands in four_operand_kinds() {
            let circuit = mul_add_add_circuit(operands, true);
            let reference = mul_add_add_circuit(operands, false);
            let values: [Poly192; 4] = core::array::from_fn(|i| restrict(operands[i], random[i]));
            let [a, c, d, e] = values;
            let expected = a * c + d + e;
            for circuit in [&circuit, &reference] {
                assert!(
                    mul_add_runs(circuit, operands, values, expected),
                    "{operands:?}"
                );
            }
            let wrong = expected + Poly192::new([Poly64::ZERO, Poly64::ONE, Poly64::ZERO]);
            assert!(!mul_add_runs(&circuit, operands, values, wrong));
        }
        let operands = [Operand::Public; 4];
        let circuit = mul_add_add_circuit(operands, true);
        for i in 0..4 {
            let mut values = random;
            values[i] = Poly192::ZERO;
            let [a, c, d, e] = values;
            assert!(
                mul_add_runs(&circuit, operands, values, a * c + d + e),
                "zero value {i}"
            );
        }
    }

    /// The multiply-add with two addends never adds more expression nodes than the product and
    /// sums it replaces, and takes ten of their sixteen for public operands: one more than the
    /// multiply-add with one addend.
    #[test]
    fn native_poly_mul_add_add_takes_one_operation_more_than_the_multiply_add() {
        let added = |operands: [Operand; 4], fused: bool| {
            let mut b = CircuitBuilder::<Poly64>::new();
            let [a, c, d, e] = operands.map(|kind| operand(&mut b, kind));
            let before = b.construction_usage().unwrap().expression_nodes;
            if fused {
                P::mul_add_add(&mut b, &a, &c, &d, &e);
            } else {
                let product = P::mul(&mut b, &a, &c);
                let partial = P::add(&mut b, &product, &d);
                P::add(&mut b, &partial, &e);
            }
            b.construction_usage().unwrap().expression_nodes - before
        };
        for operands in four_operand_kinds() {
            assert!(
                added(operands, true) <= added(operands, false),
                "{operands:?}"
            );
        }
        let public = [Operand::Public; 4];
        assert_eq!(added(public, true), 10);
        assert_eq!(added(public, false), 16);
    }

    #[test]
    fn native_poly_constants_reject_truncation_before_graph_mutation() {
        let mut b = CircuitBuilder::<Poly64>::new();
        let before = b.private_input_count();
        assert!(P::constant(&mut b, 1u128 << 64).is_err());
        assert_eq!(b.private_input_count(), before);
        let value = P::constant(&mut b, u64::MAX as u128).unwrap();
        let expected = b.native_poly192_constant([u64::MAX, 0, 0]);
        P::assert_equal(&mut b, &value, &expected);
        b.build().unwrap().runner().run().unwrap();
    }

    #[test]
    fn native_poly_transcript_preserves_partial_refills_and_continuations() {
        let initial = [1u8, 219, 37, 129, 3];
        let mut native =
            BinaryChallenger::<Poly64, HashChallenger<u8, Keccak256Hash, 32>>::from_hasher(
                initial.to_vec(),
                Keccak256Hash,
            );
        let mut b = CircuitBuilder::<Poly64>::new();
        b.enable_native_keccak_f1600().unwrap();
        let initial = initial.map(|byte| b.define_const(H::encode_u16(u16::from(byte)).unwrap()));
        let mut ch = BinaryTower128Challenger::with_initial_bytes_with_host::<H, Poly64>(
            &mut b,
            ByteHash::Keccak256,
            &initial,
        )
        .unwrap();
        let bind = |b: &mut CircuitBuilder<Poly64>,
                    actual: &NativePoly192Target,
                    expected: Poly192| {
            let expected = b.native_poly192_constant(expected.coefficients().map(Poly64::to_bits));
            P::assert_equal(b, actual, &expected);
        };
        for _ in 0..5 {
            let expected = native.sample_algebra_element::<Poly192>();
            let actual = P::sample::<H>(&mut b, &mut ch).unwrap();
            bind(&mut b, &actual, expected);
        }
        let mut public = Vec::new();
        for (iteration, bits) in [7, 31, 63, 0].into_iter().enumerate() {
            let expected = native.sample_bits(bits);
            let actual = ch.sample_bits_with_host::<H, Poly64>(&mut b, bits).unwrap();
            for (i, bit) in actual.into_iter().enumerate() {
                let value = b.define_const(Poly64::from_bool(expected >> i & 1 != 0));
                let difference = b.sub(bit, value);
                b.assert_zero(difference);
            }
            let observed = Poly192::new([
                Poly64::new(0x80123456789abcde),
                Poly64::new(0x57a983b1de021365),
                Poly64::new(0xfefdfcfbfaf9f8f7),
            ]);
            let coefficients = b.alloc_public_input_array::<3>("observed native Poly192");
            let target = b.native_poly192_from_coefficients(coefficients);
            public.extend(observed.coefficients());
            for coefficient in observed.coefficients() {
                native.observe(coefficient);
            }
            if iteration % 2 == 0 {
                let (hash, digest) = ch.retained_query_digest().unwrap();
                ch = P::observe_after_queries::<H>(
                    &mut b,
                    crate::BinaryQueryContinuation::from_digest(hash, digest),
                    &[target],
                )
                .unwrap();
            } else {
                P::observe::<H>(&mut b, &mut ch, &[target]).unwrap();
            }
            let expected = native.sample_algebra_element::<Poly192>();
            let actual = P::sample::<H>(&mut b, &mut ch).unwrap();
            bind(&mut b, &actual, expected);
        }
        let circuit = b.build().unwrap();
        let mut runner = circuit.runner();
        runner.set_public_inputs(&public).unwrap();
        runner.run().unwrap();
        for index in [0, 1, 2, public.len() - 1] {
            let mut wrong = public.clone();
            wrong[index] += Poly64::ONE;
            let mut runner = circuit.runner();
            assert!(
                runner
                    .set_public_inputs(&wrong)
                    .and_then(|()| runner.run())
                    .is_err()
            );
        }
    }

    /// A value observed after a query draw costs exactly a live observation:
    /// its unchecked word split, which the next refill range-checks as Keccak
    /// lanes.
    #[test]
    fn native_poly_after_query_observations_cost_a_live_observation() {
        let mut b = CircuitBuilder::<Poly64>::new();
        b.enable_native_keccak_f1600().unwrap();
        let coefficients = b.alloc_public_input_array::<9>("observed coefficients");
        let values: Vec<_> = coefficients
            .as_chunks::<3>()
            .0
            .iter()
            .map(|&coefficients| b.native_poly192_from_coefficients(coefficients))
            .collect();
        let mut ch = BinaryTower128Challenger::new(ByteHash::Keccak256);
        P::observe::<H>(&mut b, &mut ch, &values[..1]).unwrap();
        P::sample::<H>(&mut b, &mut ch).unwrap();
        let (hash, digest) = ch.retained_query_digest().unwrap();
        let start = b.construction_usage().unwrap();
        P::observe::<H>(&mut b, &mut ch, &values[1..2]).unwrap();
        let live = b.construction_usage().unwrap();
        P::observe_after_queries::<H>(
            &mut b,
            crate::BinaryQueryContinuation::from_digest(hash, digest),
            &values[2..],
        )
        .unwrap();
        let resumed = b.construction_usage().unwrap();
        let added = |from: p3_circuit::CircuitConstructionUsage,
                     to: p3_circuit::CircuitConstructionUsage| {
            (
                to.expression_nodes - from.expression_nodes,
                to.pending_connects - from.pending_connects,
                to.non_primitive_calls - from.non_primitive_calls,
            )
        };
        assert_eq!(added(live, resumed), added(start, live));
    }

    /// Poly64 and Poly192 values observed as words sample like the native
    /// transcript: in an odd-length input, word-aligned after a refill, at
    /// odd offsets between single bytes, and across a two-block input. A
    /// changed coefficient changes the draws.
    #[test]
    fn native_poly_word_observations_match_the_native_transcript() {
        const BYTE: u8 = 201;
        let initial = [3u8, 251, 7];
        let raw: [u64; 30] = core::array::from_fn(|i| {
            0x8123_4567_89ab_cdefu64.rotate_left(11 * i as u32) ^ i as u64
        });
        let mut native =
            BinaryChallenger::<Poly64, HashChallenger<u8, Keccak256Hash, 32>>::from_hasher(
                initial.to_vec(),
                Keccak256Hash,
            );
        let mut b = CircuitBuilder::<Poly64>::new();
        b.enable_native_keccak_f1600().unwrap();
        let initial = initial.map(|byte| b.define_const(H::encode_u16(u16::from(byte)).unwrap()));
        let byte = [b.define_const(H::encode_u16(u16::from(BYTE)).unwrap())];
        let base = b.alloc_public_input_array::<6>("base values");
        let coefficients = b.alloc_public_input_array::<24>("extension coefficients");
        let wide: Vec<_> = coefficients
            .as_chunks::<3>()
            .0
            .iter()
            .map(|&coefficients| b.native_poly192_from_coefficients(coefficients))
            .collect();
        let mut ch = BinaryTower128Challenger::with_initial_bytes_with_host::<H, Poly64>(
            &mut b,
            ByteHash::Keccak256,
            &initial,
        )
        .unwrap();
        // (byte before, base values, extension values, byte after)
        let phases = [
            (false, 0..2, 0..0, false),
            (false, 2..2, 0..1, false),
            (true, 2..3, 1..2, true),
            (false, 3..6, 2..8, false),
        ];
        for (before, bases, wides, after) in phases {
            if before {
                native.observe(Digest::<Poly64, u8, 1>::from([BYTE]));
                ch.observe_bytes_with_host::<H, Poly64>(&mut b, &byte)
                    .unwrap();
            }
            for i in bases.clone() {
                native.observe(Poly64::new(raw[i]));
            }
            P::observe_base::<H>(&mut b, &mut ch, &base[bases]).unwrap();
            for i in wides.clone() {
                native.observe_algebra_element(Poly192::new(core::array::from_fn(|k| {
                    Poly64::new(raw[6 + 3 * i + k])
                })));
            }
            P::observe::<H>(&mut b, &mut ch, &wide[wides]).unwrap();
            if after {
                native.observe(Digest::<Poly64, u8, 1>::from([BYTE]));
                ch.observe_bytes_with_host::<H, Poly64>(&mut b, &byte)
                    .unwrap();
            }
            let expected = native.sample_algebra_element::<Poly192>();
            let actual = P::sample::<H>(&mut b, &mut ch).unwrap();
            let expected = b.native_poly192_constant(expected.coefficients().map(Poly64::to_bits));
            P::assert_equal(&mut b, &actual, &expected);
            let expected = native.sample_bits(13);
            for (i, bit) in ch
                .sample_bits_with_host::<H, Poly64>(&mut b, 13)
                .unwrap()
                .into_iter()
                .enumerate()
            {
                let value = b.define_const(Poly64::from_bool(expected >> i & 1 != 0));
                b.connect(bit, value);
            }
        }
        let circuit = b.build().unwrap();
        let runs = |public: &[Poly64]| {
            let mut runner = circuit.runner();
            runner
                .set_public_inputs(public)
                .and_then(|()| runner.run())
                .is_ok()
        };
        let public = raw.map(Poly64::new);
        assert!(runs(&public));
        for changed in [0, 2, 5, 6, 10, 29] {
            let mut wrong = public;
            wrong[changed] += Poly64::new(1 << 37);
            assert!(!runs(&wrong), "changed observed coefficient {changed}");
        }
    }
}
