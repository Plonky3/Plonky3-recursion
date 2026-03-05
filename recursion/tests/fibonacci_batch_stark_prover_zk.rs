mod common;

use p3_air::{Air, AirBuilder, BaseAir};
use p3_batch_stark::{ProverData, StarkInstance, prove_batch, verify_batch};
use p3_circuit::ops::generate_poseidon2_trace;
use p3_circuit::{CircuitBuilder, Op};
use p3_field::Field;
use p3_fri::{HidingFriPcs, create_test_fri_params};
use p3_koala_bear::default_koalabear_poseidon2_16;
use p3_lookup::logup::LogUpGadget;
use p3_matrix::Matrix;
use p3_matrix::dense::RowMajorMatrix;
use p3_poseidon2_circuit_air::KoalaBearD4Width16;
use p3_recursion::pcs::fri::{
    FriVerifierParams, HidingFriProofTargets, InputProofTargets, MerkleCapTargets,
    RecExtensionValMmcs, RecValMmcs, Witness,
};
use p3_recursion::{
    BatchStarkVerifierInputsBuilder, Poseidon2Config, VerificationError, verify_batch_circuit,
};
use p3_uni_stark::StarkConfig;
use rand::SeedableRng;
use rand::rngs::SmallRng;

use crate::common::koala_bear_params::{
    Challenge, ChallengeMmcs, Challenger, DIGEST_ELEMS, Dft, F, MyCompress, MyHash, RATE, ValMmcs,
    WIDTH,
};

type MyPcsZk = HidingFriPcs<F, Dft, ValMmcs, ChallengeMmcs, SmallRng>;
type MyConfigZk = StarkConfig<MyPcsZk, Challenge, Challenger>;
type InnerFriZk = HidingFriProofTargets<
    F,
    Challenge,
    RecExtensionValMmcs<
        F,
        Challenge,
        DIGEST_ELEMS,
        RecValMmcs<F, DIGEST_ELEMS, MyHash, MyCompress>,
    >,
    InputProofTargets<F, Challenge, RecValMmcs<F, DIGEST_ELEMS, MyHash, MyCompress>>,
    Witness<F>,
>;

#[derive(Clone, Copy)]
struct AddAir;

impl<Val: Field> BaseAir<Val> for AddAir {
    fn width(&self) -> usize {
        3
    }
}

impl<AB: AirBuilder> Air<AB> for AddAir
where
    AB::F: Field,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let row = main.row_slice(0).expect("main row must exist");
        builder.assert_zero(row[0] + row[1] - row[2]);
    }
}

fn generate_add_trace<Val: Field>(rows: usize) -> RowMajorMatrix<Val> {
    let width = 3;
    let mut values = Val::zero_vec(rows * width);
    for row in 0..rows {
        let idx = row * width;
        let a = Val::from_usize(row);
        let b = Val::from_usize(row + 1);
        values[idx] = a;
        values[idx + 1] = b;
        values[idx + 2] = a + b;
    }
    RowMajorMatrix::new(values, width)
}

#[test]
fn test_batch_verifier_zk_hiding_fri() -> Result<(), VerificationError> {
    let air = AddAir;
    eprintln!(
        "main_next_cols={}, prep_next_cols={}",
        <AddAir as p3_air::BaseAir<F>>::main_next_row_columns(&air).len(),
        <AddAir as p3_air::BaseAir<F>>::preprocessed_next_row_columns(&air).len()
    );
    let trace = generate_add_trace::<F>(1 << 6);
    let pvs = vec![vec![]];

    let perm = default_koalabear_poseidon2_16();
    let hash = MyHash::new(perm.clone());
    let compress = MyCompress::new(perm.clone());
    let val_mmcs = ValMmcs::new(hash, compress, 0);
    let challenge_mmcs = ChallengeMmcs::new(val_mmcs.clone());
    let dft = Dft::default();
    let fri_params = create_test_fri_params(challenge_mmcs, 0);
    let pcs_proving = MyPcsZk::new(dft, val_mmcs, fri_params, 2, SmallRng::seed_from_u64(1));
    let challenger_proving = Challenger::new(perm);
    let config_proving = MyConfigZk::new(pcs_proving, challenger_proving);

    let instance = StarkInstance {
        air: &air,
        trace,
        public_values: pvs[0].clone(),
        lookups: Vec::new(),
    };
    let instances = vec![instance];
    let prover_data = ProverData::from_instances(&config_proving, &instances);
    let common = &prover_data.common;
    let batch_stark_proof = prove_batch(&config_proving, &instances, &prover_data);

    verify_batch(&config_proving, &[air], &batch_stark_proof, &pvs, common).unwrap();

    let perm2 = default_koalabear_poseidon2_16();
    let hash2 = MyHash::new(perm2.clone());
    let compress2 = MyCompress::new(perm2.clone());
    let val_mmcs2 = ValMmcs::new(hash2, compress2, 0);
    let challenge_mmcs2 = ChallengeMmcs::new(val_mmcs2.clone());
    let dft2 = Dft::default();
    let fri_params2 = create_test_fri_params(challenge_mmcs2, 0);
    let fri_verifier_params = FriVerifierParams::from(&fri_params2);
    let pcs_verif = MyPcsZk::new(dft2, val_mmcs2, fri_params2, 2, SmallRng::seed_from_u64(2));
    let challenger_verif = Challenger::new(perm2.clone());
    let config = MyConfigZk::new(pcs_verif, challenger_verif);

    let mut circuit_builder = CircuitBuilder::new();
    circuit_builder.enable_poseidon2_perm::<KoalaBearD4Width16, _>(
        generate_poseidon2_trace::<Challenge, KoalaBearD4Width16>,
        perm2,
    );

    let lookup_gadget = LogUpGadget::new();
    let air_public_counts = vec![0usize; batch_stark_proof.opened_values.instances.len()];
    let verifier_inputs = BatchStarkVerifierInputsBuilder::<
        MyConfigZk,
        MerkleCapTargets<F, DIGEST_ELEMS>,
        InnerFriZk,
    >::allocate(
        &mut circuit_builder,
        &batch_stark_proof,
        common,
        &air_public_counts,
    );
    let mmcs_op_ids = verify_batch_circuit::<_, _, _, _, _, _, _, WIDTH, RATE>(
        &config,
        &[air],
        &mut circuit_builder,
        &verifier_inputs.proof_targets,
        &verifier_inputs.air_public_targets,
        &fri_verifier_params,
        &verifier_inputs.common_data,
        &lookup_gadget,
        Poseidon2Config::KoalaBearD4Width16,
    )?;

    let verification_circuit = circuit_builder.build().unwrap();
    let public_inputs = verifier_inputs.pack_values(&pvs, &batch_stark_proof, common);
    assert_eq!(public_inputs.len(), verification_circuit.public_flat_len);
    {
        use std::collections::HashMap;
        let mut first_seen: HashMap<u32, usize> = HashMap::new();
        for (i, w) in verification_circuit.public_rows.iter().enumerate() {
            if let Some(prev) = first_seen.insert(w.0, i) {
                assert_eq!(
                    public_inputs[prev], public_inputs[i],
                    "conflicting public inputs assigned to same witness {} at positions {} and {}",
                    w.0, prev, i
                );
            }
        }
    }

    for (i, op) in verification_circuit.ops.iter().enumerate() {
        match op {
            Op::Const { out, val } if out.0 == 0 => {
                eprintln!("op[{i}] writes w0 as Const({val:?})");
            }
            Op::Public { out, public_pos } if out.0 == 0 => {
                eprintln!("op[{i}] writes w0 as Public(pos={public_pos})");
            }
            Op::Alu { out, kind, .. } if out.0 == 0 => {
                eprintln!("op[{i}] writes w0 as Alu({kind:?})");
            }
            Op::Hint { outputs, .. } if outputs.iter().any(|w| w.0 == 0) => {
                eprintln!("op[{i}] writes w0 as Hint");
            }
            Op::NonPrimitiveOpWithExecutor { outputs, .. }
                if outputs.iter().flatten().any(|w| w.0 == 0) =>
            {
                eprintln!("op[{i}] writes w0 as NonPrimitive");
            }
            _ => {}
        }
    }

    let mut verification_runner = verification_circuit.runner();
    verification_runner
        .set_public_inputs(&public_inputs)
        .unwrap();
    assert!(mmcs_op_ids.is_empty());

    let _verification_traces = verification_runner.run().unwrap();
    Ok(())
}
