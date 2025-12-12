use alloc::string::ToString;
use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;
use core::iter;

use p3_baby_bear::BabyBear;
use p3_field::{ExtensionField, Field};
use p3_symmetric::Permutation;

use crate::op::HashSqueezeHint;
use crate::ops::PoseidonPermCall;
use crate::{
    CircuitBuilder, CircuitBuilderError, CircuitError, ExprId, NonPrimitiveOpType, PoseidonPermOps,
};

/// Configuration parameters for hash operations.
pub struct HashConfig<F> {
    /// Rate (number of elements absorbed/squeezed per operation)
    pub rate: usize,
    /// Width of the permutation
    pub width: usize,
    /// The permutation function used in this configuration
    pub permutation: Arc<PermutationFn<F>>,
}

type PermutationFn<F> = dyn Fn(&[F]) -> Result<Vec<F>, CircuitError>;

impl<F> Clone for HashConfig<F> {
    fn clone(&self) -> Self {
        Self {
            rate: self.rate,
            width: self.width,
            permutation: Arc::clone(&self.permutation),
        }
    }
}

impl<F> HashConfig<F> {
    /// New hash configuration using Babybear and poseidon2 permutation.
    pub fn babybear_poseidon2_16() -> Self
    where
        F: ExtensionField<BabyBear>,
    {
        use p3_baby_bear::default_babybear_poseidon2_16;
        let permutation = default_babybear_poseidon2_16();
        Self {
            rate: 2,
            width: 4,
            permutation: Arc::new(move |input: &[F]| {
                let bf_input = input
                    .iter()
                    .flat_map(|e| e.as_basis_coefficients_slice().to_vec())
                    .collect::<Vec<BabyBear>>()
                    .try_into()
                    .map_err(|_| CircuitError::IncorrectNonPrimitiveOpInputSize {
                        op: NonPrimitiveOpType::PoseidonPerm,
                        expected: 4.to_string(),
                        got: input.len(),
                    })?;
                let output = permutation.permute(bf_input);
                output
                    .chunks(F::DIMENSION)
                    .map(|coeffs| {
                        F::from_basis_coefficients_slice(coeffs).ok_or_else(|| {
                            CircuitError::IncorrectNonPrimitiveOpInputSize {
                                op: NonPrimitiveOpType::PoseidonPerm,
                                expected: F::DIMENSION.to_string(),
                                got: coeffs.len(),
                            }
                        })
                    })
                    .collect::<Result<Vec<F>, CircuitError>>()
            }),
        }
    }
}

impl<F> alloc::fmt::Debug for HashConfig<F> {
    fn fmt(&self, f: &mut alloc::fmt::Formatter<'_>) -> alloc::fmt::Result {
        f.debug_struct("HashConfig")
            .field("rate", &self.rate)
            .field("width", &self.width)
            .field("permutation", &"<dyn Fn(&[F]) -> Vec<F>>")
            .finish()
    }
}

impl<F> PartialEq for HashConfig<F> {
    fn eq(&self, other: &Self) -> bool {
        // Intentional: only compare rate, not the closure
        self.rate == other.rate && self.width == other.width
    }
}

impl<F> Eq for HashConfig<F> {}

impl<F> core::hash::Hash for HashConfig<F> {
    fn hash<H: core::hash::Hasher>(&self, state: &mut H) {
        // Same idea: hash only rate
        self.rate.hash(state);
    }
}

impl<F: Clone> Default for HashConfig<F> {
    fn default() -> Self {
        Self {
            rate: 0,
            width: 0,
            // Default permutation: identity over the slice (clones elements)
            permutation: Arc::new(|_| Ok(vec![])),
        }
    }
}

pub fn add_hash_squeeze<F: Field>(
    builder: &mut CircuitBuilder<F>,
    hash_config: &HashConfig<F>,
    state_id: &str,
    inputs: &[ExprId],
    reset: bool,
) -> Result<Vec<ExprId>, CircuitBuilderError> {
    let filler = HashSqueezeHint::new(
        state_id.to_string(),
        inputs.to_vec(),
        hash_config.clone(),
        reset,
    );
    let outputs = builder.alloc_witness_hints(filler, "hash squeeze");

    let chunks = inputs.chunks(4);
    let last_idx = chunks.len() - 1;
    for (i, input) in chunks.enumerate() {
        let is_first = i == 0;
        let is_last = i == last_idx;
        let _ = builder.add_poseidon_perm(PoseidonPermCall {
            new_start: if is_first { reset } else { false },
            merkle_path: false,
            mmcs_bit: None,
            inputs: input
                .iter()
                .cloned()
                .map(Some)
                .chain(iter::repeat(None))
                .take(4)
                .collect::<Vec<_>>()
                .try_into()
                .expect("We have already taken 4 elements"),
            outputs: if is_last {
                outputs
                    .iter()
                    .cloned()
                    .map(Some)
                    .chain(iter::repeat(None))
                    .take(2)
                    .collect::<Vec<_>>()
                    .try_into()
                    .expect("We have already taken 2 elements")
            } else {
                [None, None]
            },
            mmcs_index_sum: None,
        })?;
    }

    Ok(outputs)
}

#[cfg(test)]
mod tests {
    use alloc::vec;
    use alloc::vec::Vec;

    use p3_baby_bear::{BabyBear, Poseidon2BabyBear, default_babybear_poseidon2_16};
    use p3_field::extension::BinomialExtensionField;
    use p3_field::{BasedVectorSpace, PrimeCharacteristicRing};
    use p3_poseidon2_circuit_air::BabyBearD4Width16;
    use p3_symmetric::{CryptographicHasher, PaddingFreeSponge};

    use crate::CircuitBuilder;
    use crate::ops::hash::{HashConfig, add_hash_squeeze};
    use crate::tables::{Poseidon2Params, generate_poseidon2_trace};

    impl Poseidon2Params for BabyBearD4Width16 {
        type BaseField = BabyBear;
        const D: usize = 4;
        const WIDTH: usize = 16;
        const RATE_EXT: usize = 2;
        const CAPACITY_EXT: usize = 2;
        const SBOX_DEGREE: u64 = 7;
        const SBOX_REGISTERS: usize = 1;
        const HALF_FULL_ROUNDS: usize = 4;
        const PARTIAL_ROUNDS: usize = 13;
    }

    #[test]
    fn test_add_hash_squeeze() {
        type F = BabyBear;
        type CF = BinomialExtensionField<BabyBear, 4>;

        let mut circuit_builder = CircuitBuilder::<CF>::new();
        circuit_builder.enable_poseidon_perm::<BabyBearD4Width16>(
            generate_poseidon2_trace::<CF, BabyBearD4Width16>,
        );

        let inputs = vec![
            circuit_builder.add_const(CF::ZERO),
            circuit_builder.add_const(CF::ONE),
        ];

        let hash_config = HashConfig::babybear_poseidon2_16();
        let digest =
            add_hash_squeeze(&mut circuit_builder, &hash_config, "state_0", &inputs, true).unwrap();

        // Add a constant wires with the expected results.
        let permutation = default_babybear_poseidon2_16();
        let hasher = PaddingFreeSponge::<Poseidon2BabyBear<16>, 16, 8, 8>::new(permutation);

        let expected_digest: [F; 8] = hasher.hash_iter_slices([
            CF::ZERO.as_basis_coefficients_slice(),
            CF::ONE.as_basis_coefficients_slice(),
        ]);
        let expected_digest: Vec<_> = expected_digest
            .chunks(4)
            .map(|chunk| {
                circuit_builder.add_const(CF::from_basis_coefficients_slice(chunk).unwrap())
            })
            .collect();

        for (&val, expected_val) in digest.iter().zip(expected_digest) {
            circuit_builder.connect(val, expected_val);
        }

        let circuit = circuit_builder.build().unwrap();
        circuit.runner().run().unwrap();
    }

    #[test]
    fn test_hash_squeeze_with_state() {
        type F = BabyBear;
        type CF = BinomialExtensionField<BabyBear, 4>;

        let mut circuit_builder = CircuitBuilder::<CF>::new();
        circuit_builder.enable_poseidon_perm::<BabyBearD4Width16>(
            generate_poseidon2_trace::<CF, BabyBearD4Width16>,
        );

        let zero = circuit_builder.add_const(CF::ZERO);
        let one = circuit_builder.add_const(CF::ONE);
        let input = [zero, one];
        let repeated_input = [zero, one, zero, one];

        let hash_config = HashConfig::babybear_poseidon2_16();

        // Compute the digest with a single squeeze
        let digest = add_hash_squeeze(
            &mut circuit_builder,
            &hash_config,
            "state_0",
            &repeated_input,
            true,
        )
        .unwrap();

        // Now compute the same output with two calls to squeeze, without reseting the state
        // in the second one.
        let intermediate_digest =
            add_hash_squeeze(&mut circuit_builder, &hash_config, "state_0", &input, true).unwrap();
        // Squeeze again without resetting the state
        let another_digest =
            add_hash_squeeze(&mut circuit_builder, &hash_config, "state_0", &input, false).unwrap();

        let hasher = PaddingFreeSponge::<_, 16, 8, 8>::new(default_babybear_poseidon2_16());

        // Verify intermediate digest
        let expected_intermediate_digest: [F; 8] = hasher.hash_iter_slices([
            CF::ZERO.as_basis_coefficients_slice(),
            CF::ONE.as_basis_coefficients_slice(),
        ]);
        for (chunk, value) in expected_intermediate_digest
            .chunks(4)
            .zip(intermediate_digest)
        {
            let expected =
                circuit_builder.add_const(CF::from_basis_coefficients_slice(chunk).unwrap());
            circuit_builder.connect(expected, value);
        }

        // Verify the two sets of wires computing the digest
        let expected_digest: [F; 8] = hasher.hash_iter_slices([
            CF::ZERO.as_basis_coefficients_slice(),
            CF::ONE.as_basis_coefficients_slice(),
            CF::ZERO.as_basis_coefficients_slice(),
            CF::ONE.as_basis_coefficients_slice(),
        ]);
        for ((chunk, value), another_value) in
            expected_digest.chunks(4).zip(digest).zip(another_digest)
        {
            let expected =
                circuit_builder.add_const(CF::from_basis_coefficients_slice(chunk).unwrap());
            circuit_builder.connect(expected, value);
            circuit_builder.connect(expected, another_value);
        }

        let circuit = circuit_builder.build().unwrap();
        circuit.runner().run().unwrap();
    }
}
