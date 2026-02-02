use alloc::string::ToString;
use alloc::vec::Vec;
use core::iter;

use p3_field::Field;

use crate::op::Poseidon2Config;
use crate::ops::Poseidon2PermCall;
use crate::ops::poseidon2_perm::Poseidon2PermOps;
use crate::{CircuitBuilder, CircuitBuilderError, ExprId, NonPrimitiveOpId};

pub fn add_hash_slice<F: Field>(
    builder: &mut CircuitBuilder<F>,
    poseidon2_config: &Poseidon2Config,
    inputs: &[ExprId],
    reset: bool,
) -> Result<Vec<ExprId>, CircuitBuilderError> {
    let chunks = inputs.chunks(poseidon2_config.rate_ext());
    let last_idx = chunks.len() - 1;
    let mut outputs = [None, None, None, None];
    let mut last_op_id = NonPrimitiveOpId(0);
    for (i, input) in chunks.enumerate() {
        let is_first = i == 0;
        let is_last = i == last_idx;
        let (op_id, maybe_outputs) = builder.add_poseidon2_perm(Poseidon2PermCall {
            config: *poseidon2_config,
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
            out_ctl: [is_last, is_last],
            return_all_outputs: false,
            mmcs_index_sum: None,
        })?;
        outputs = maybe_outputs;
        last_op_id = op_id;
    }

    // Only return outputs 0-1 (rate elements) for hashing
    [outputs[0], outputs[1]]
        .into_iter()
        .map(|o| {
            o.ok_or_else(|| CircuitBuilderError::MalformedNonPrimitiveOutputs {
                op_id: last_op_id,
                details: "".to_string(),
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use alloc::vec::Vec;
    use core::iter;

    use itertools::Itertools;
    use p3_baby_bear::{BabyBear, Poseidon2BabyBear, default_babybear_poseidon2_16};
    use p3_field::extension::BinomialExtensionField;
    use p3_field::{BasedVectorSpace, PrimeCharacteristicRing};
    use p3_symmetric::{CryptographicHasher, PaddingFreeSponge};

    use super::add_hash_slice;
    use crate::ops::{Poseidon2Config, Poseidon2Params, generate_poseidon2_trace};
    use crate::{CircuitBuilder, ExprId};

    type F = BabyBear;
    type CF = BinomialExtensionField<F, 4>;
    type Perm = Poseidon2BabyBear<16>;
    type MyHash = PaddingFreeSponge<Perm, 16, 8, 8>;

    struct DummyParams;

    impl Poseidon2Params for DummyParams {
        type BaseField = F;
        const CONFIG: Poseidon2Config = Poseidon2Config::BabyBearD4Width16;
    }

    #[test]
    fn test_hash_squeeze() {
        let perm = default_babybear_poseidon2_16();
        let hasher = MyHash::new(perm.clone());

        for len in [4, 8, 12, 16, 32, 64] {
            let base_inputs = (0..len)
                .map(|i| F::from_u64(i as u64 + 1))
                .collect::<Vec<_>>();
            let expected = hasher.hash_iter(base_inputs.clone());

            let mut builder = CircuitBuilder::<CF>::new();
            builder.enable_poseidon2_perm::<DummyParams, _>(
                generate_poseidon2_trace::<CF, DummyParams>,
                perm.clone(),
            );

            let input_exprs: Vec<ExprId> = (0..base_inputs.len())
                .chunks(<CF as BasedVectorSpace<F>>::DIMENSION)
                .into_iter()
                .map(|_| builder.add_public_input())
                .collect();

            let outputs = add_hash_slice(
                &mut builder,
                &Poseidon2Config::BabyBearD4Width16,
                &input_exprs,
                true,
            )
            .unwrap();

            let out0_pi = builder.add_public_input();
            let out1_pi = builder.add_public_input();
            builder.connect(outputs[0], out0_pi);
            builder.connect(outputs[1], out1_pi);

            let circuit = builder.build().unwrap();
            let mut runner = circuit.runner();
            let mut public_inputs = base_inputs // Pad to multiple of 4
                .chunks(<CF as BasedVectorSpace<F>>::DIMENSION)
                .map(|chunk| {
                    let chunk: Vec<F> = chunk
                        .iter()
                        .cloned()
                        .chain(iter::repeat(F::ZERO))
                        .take(<CF as BasedVectorSpace<F>>::DIMENSION)
                        .collect();
                    CF::from_basis_coefficients_slice(&chunk).unwrap()
                })
                .collect::<Vec<_>>();
            let expected_limb0 = CF::from_basis_coefficients_slice(&expected[0..4]).unwrap();
            let expected_limb1 = CF::from_basis_coefficients_slice(&expected[4..8]).unwrap();
            public_inputs.push(expected_limb0);
            public_inputs.push(expected_limb1);
            runner.set_public_inputs(&public_inputs).unwrap();

            runner.run().unwrap();
        }
    }
}
