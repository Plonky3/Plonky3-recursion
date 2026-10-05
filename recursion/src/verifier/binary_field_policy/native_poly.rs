//! Native Poly64 cells and the released cubic Poly192 challenge basis.

use alloc::vec::Vec;

use p3_circuit::ops::NativePoly192Target;

use super::*;

/// Preserves direct coefficient scaling in the shared interpolation kernel.
pub(crate) trait BinaryPolyPolicy<CF: Field + Eq + Hash>:
    BinaryRelationPolicy<CF, Base = Poly64, Challenge = Poly192>
{
    fn scale_base_constant(
        b: &mut CircuitBuilder<CF>,
        value: &Self::ChallengeTarget,
        raw: u64,
    ) -> Result<Self::ChallengeTarget, CircuitBuilderError>;
}

impl<CF: Field + Eq + Hash> BinaryPolyPolicy<CF> for Poly64Relation {
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
}

impl BinaryPolyPolicy<Poly64> for NativePoly64Relation {
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
        let bytes = native_bytes::<H>(b, values)?;
        Ok(ch.observe_bytes_with_host::<H, Poly64>(b, &bytes)?)
    }
    fn observe_after_queries<H: BinaryCircuitHost<Poly64>>(
        b: &mut CircuitBuilder<Poly64>,
        token: crate::BinaryQueryContinuation,
        values: &[NativePoly192Target],
    ) -> Result<BinaryTower128Challenger, VerificationError> {
        let bytes = native_bytes::<H>(b, values)?;
        Ok(token.resume_with_observation_with_host::<H, Poly64>(b, &bytes)?)
    }
    fn sample<H: BinaryCircuitHost<Poly64>>(
        b: &mut CircuitBuilder<Poly64>,
        ch: &mut BinaryTower128Challenger,
    ) -> Result<NativePoly192Target, VerificationError> {
        let value = ch.sample_poly192_with_host::<H, Poly64>(b)?;
        let bits = core::array::from_fn(|i| value.coefficients()[i / 64].bits()[i % 64]);
        Ok(b.native_poly192_from_bits(bits)?)
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

fn native_bytes<H: BinaryCircuitHost<Poly64>>(
    b: &mut CircuitBuilder<Poly64>,
    values: &[NativePoly192Target],
) -> Result<Vec<ExprId>, CircuitBuilderError> {
    let mut bytes = Vec::new();
    for value in values {
        // The codec emits coefficient 0, then 1, then 2: exactly 24 bytes.
        let bits = b.native_poly192_to_bits(value)?;
        for byte in bits.chunks_exact(8) {
            bytes.push(H::recompose_word(b, byte)?);
        }
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use p3_binary_field::BinaryChallenger;
    use p3_challenger::{CanObserve, CanSampleBits, FieldChallenger, HashChallenger};
    use p3_circuit::ops::{
        ByteHash,
        binary_encoding::{BinaryCircuitEncoding, NativeBinaryEncoding},
    };
    use p3_field::PrimeCharacteristicRing;
    use p3_keccak::Keccak256Hash;

    type H = NativeBinaryEncoding;
    type P = NativePoly64Relation;
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
}
