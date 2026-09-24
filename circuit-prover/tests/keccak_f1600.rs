//! End-to-end proofs of circuits that call Keccak-f[1600].

use std::panic::{AssertUnwindSafe, catch_unwind};

use p3_circuit::ops::{
    KECCAK_LANES, KECCAK_STATE_LIMBS, KeccakF1600Trace, NpoTypeId, keccak_state_to_limbs,
};
use p3_circuit::tables::Traces;
use p3_circuit::{Circuit, CircuitBuilder, ExprId};
use p3_circuit_prover::batch_stark_prover::{
    BatchStarkProver, CircuitProverData, KeccakF1600AirBuilder, KeccakF1600Preprocessor,
    KeccakF1600Prover, TablePacking,
};
use p3_circuit_prover::common::{NpoAirBuilder, NpoPreprocessor, get_airs_and_degrees_with_prep};
use p3_circuit_prover::{ConstraintProfile, config};
use p3_field::PrimeCharacteristicRing;
use p3_keccak::KeccakF;
use p3_symmetric::Permutation;
use p3_test_utils::baby_bear_params::{BabyBear, BinomialExtensionField};

type EF = BinomialExtensionField<BabyBear, 4>;
const D: usize = 4;

fn sample_state(seed: u64) -> [u64; KECCAK_LANES] {
    core::array::from_fn(|i| {
        (seed ^ 0xa076_1d64_78bd_642f)
            .wrapping_mul(2 * i as u64 + 1)
            .rotate_left(i as u32 * 3)
    })
}

fn limbs(state: &[u64; KECCAK_LANES]) -> Vec<EF> {
    keccak_state_to_limbs(state)
        .iter()
        .map(|&limb| EF::from_u16(limb))
        .collect()
}

/// Two chained calls whose final state is connected to public inputs, so the table both reads
/// limbs another call created and creates limbs the public table also provides.
fn chained_circuit() -> Circuit<EF> {
    let mut builder = CircuitBuilder::<EF>::new();
    builder.enable_keccak_f1600::<BabyBear>();
    let input: Vec<ExprId> = (0..KECCAK_STATE_LIMBS)
        .map(|_| builder.public_input())
        .collect();
    let expected: Vec<ExprId> = (0..KECCAK_STATE_LIMBS)
        .map(|_| builder.public_input())
        .collect();
    let once = builder.add_keccak_f1600(&input).unwrap();
    let twice = builder.add_keccak_f1600(&once).unwrap();
    for (&out, &want) in twice.iter().zip(&expected) {
        builder.connect(out, want);
    }
    builder.build().unwrap()
}

fn public_values(state: [u64; KECCAK_LANES]) -> Vec<EF> {
    let mut expected = state;
    KeccakF.permute_mut(&mut expected);
    KeccakF.permute_mut(&mut expected);
    let mut values = limbs(&state);
    values.extend(limbs(&expected));
    values
}

/// Prepares the circuit, runs `edit` on its traces, then proves and verifies.
fn prove_and_verify(
    circuit: &Circuit<EF>,
    public: &[EF],
    edit: impl FnOnce(&mut Traces<EF>),
) -> Result<(), String> {
    let preprocessors: Vec<Box<dyn NpoPreprocessor<BabyBear>>> =
        vec![Box::new(KeccakF1600Preprocessor)];
    let air_builders: Vec<Box<dyn NpoAirBuilder<config::BabyBearConfig, D>>> =
        vec![Box::new(KeccakF1600AirBuilder::<D>)];
    let packing = TablePacking::default();
    let (airs_degrees, primitive, non_primitive) =
        get_airs_and_degrees_with_prep::<config::BabyBearConfig, _, D>(
            circuit,
            &packing,
            &preprocessors,
            &air_builders,
            ConstraintProfile::Standard,
        )
        .map_err(|e| format!("prepare: {e:?}"))?;

    let mut runner = circuit.runner();
    runner
        .set_public_inputs(public)
        .map_err(|e| format!("inputs: {e:?}"))?;
    let mut traces = runner.run().map_err(|e| format!("run: {e:?}"))?;
    edit(&mut traces);

    let cfg = config::baby_bear();
    let (airs, degrees): (Vec<_>, Vec<_>) = airs_degrees.into_iter().unzip();
    let prover_data = p3_batch_stark::ProverData::from_airs_and_degrees(&cfg, &airs, &degrees)
        .map_err(|e| format!("setup: {e:?}"))?;
    let prepared = CircuitProverData::new(prover_data, primitive, non_primitive);
    let mut prover = BatchStarkProver::new(cfg).with_table_packing(packing);
    prover.register_table_prover(Box::new(KeccakF1600Prover::<D>));
    let proof = prover
        .prove_all_tables(&traces, &prepared)
        .map_err(|e| format!("prove: {e:?}"))?;

    let entry = proof
        .non_primitives
        .iter()
        .find(|entry| entry.op_type == NpoTypeId::keccak_f1600())
        .ok_or("no Keccak-f table in the proof")?;
    assert_eq!(entry.rows, 2);
    assert_eq!(entry.lanes, 1);

    prover
        .verify_all_tables::<EF>(&proof)
        .map_err(|e| format!("verify: {e:?}"))
}

#[test]
fn chained_keccak_f_calls_prove_and_verify() {
    let circuit = chained_circuit();
    prove_and_verify(&circuit, &public_values(sample_state(1)), |_| {})
        .expect("an honest Keccak-f circuit proves and verifies");
}

/// A Keccak-f table whose first call permutes a different state than the witness table holds
/// cannot balance the witness bus, whatever the prover does with it.
#[test]
fn a_keccak_f_trace_that_disagrees_with_the_witnesses_is_rejected() {
    let circuit = chained_circuit();
    let result = catch_unwind(AssertUnwindSafe(|| {
        prove_and_verify(&circuit, &public_values(sample_state(2)), |traces| {
            let op_type = NpoTypeId::keccak_f1600();
            let honest = traces
                .non_primitive_trace::<KeccakF1600Trace>(&op_type)
                .expect("the run records a Keccak-f trace");
            let mut forged = honest.clone();
            forged.operations[0].input[0] ^= 1;
            let mut permuted = forged.operations[0].input;
            KeccakF.permute_mut(&mut permuted);
            forged.operations[0].output = permuted;
            traces
                .non_primitive_traces
                .insert(op_type, Box::new(forged));
        })
    }));
    // Debug builds check every lookup while proving and panic on the unbalanced bus; release
    // builds produce a proof the verifier rejects.
    match result {
        Ok(Ok(())) => panic!("a forged Keccak-f trace must not verify"),
        Ok(Err(stage)) => assert!(
            stage.starts_with("prove:") || stage.starts_with("verify:"),
            "rejected before proving: {stage}"
        ),
        Err(payload) => {
            let message = payload
                .downcast_ref::<String>()
                .cloned()
                .or_else(|| payload.downcast_ref::<&str>().map(|s| (*s).to_string()))
                .unwrap_or_default();
            assert!(
                message.contains("Lookup mismatch") && message.contains("WitnessChecks"),
                "unexpected panic: {message}"
            );
        }
    }
}

/// The trusted path prepares the Keccak-f table once, with row metadata matching the proof.
#[test]
fn a_prepared_keccak_f_circuit_proves_and_verifies() {
    let circuit = chained_circuit();
    let preprocessors: Vec<Box<dyn NpoPreprocessor<BabyBear>>> =
        vec![Box::new(KeccakF1600Preprocessor)];
    let air_builders: Vec<Box<dyn NpoAirBuilder<config::BabyBearConfig, D>>> =
        vec![Box::new(KeccakF1600AirBuilder::<D>)];
    let mut prover = BatchStarkProver::new(config::baby_bear());
    prover.register_table_prover(Box::new(KeccakF1600Prover::<D>));
    let prepared = prover
        .prepare_circuit::<EF, D>(
            &circuit,
            &preprocessors,
            &air_builders,
            ConstraintProfile::Standard,
        )
        .expect("the Keccak-f table has trusted metadata");

    for seed in [3, 4] {
        let mut runner = circuit.runner();
        runner
            .set_public_inputs(&public_values(sample_state(seed)))
            .unwrap();
        let traces = runner.run().unwrap();
        let proof = prepared
            .prove(&traces)
            .expect("a prepared Keccak-f circuit proves");
        prepared
            .verifier()
            .verify(&proof, &[])
            .expect("a prepared Keccak-f proof verifies");
    }
}

/// A Keccak-256 Merkle node compression proves against the native digest.
#[test]
fn a_keccak256_compression_proves_against_the_native_digest() {
    use p3_circuit::ops::{KECCAK256_DIGEST_LIMBS, bytes_to_limbs};
    use p3_keccak::Keccak256Hash;
    use p3_symmetric::{CompressionFunctionFromHasher, PseudoCompressionFunction};

    let left: [u8; 32] = core::array::from_fn(|i| i as u8 * 3 + 1);
    let right: [u8; 32] = core::array::from_fn(|i| 255 - i as u8);
    let parent = CompressionFunctionFromHasher::<Keccak256Hash, 2, 32>::new(Keccak256Hash)
        .compress([left, right]);

    let mut builder = CircuitBuilder::<EF>::new();
    builder.enable_keccak_f1600::<BabyBear>();
    let mut digest = || -> Vec<ExprId> {
        (0..KECCAK256_DIGEST_LIMBS)
            .map(|_| builder.public_input())
            .collect()
    };
    let (l, r, expected) = (digest(), digest(), digest());
    let out = builder.keccak256_compress(&l, &r).unwrap();
    for (&got, &want) in out.iter().zip(&expected) {
        builder.connect(got, want);
    }
    let circuit = builder.build().unwrap();

    let public: Vec<EF> = [left, right, parent]
        .iter()
        .flat_map(|d| bytes_to_limbs(d))
        .map(EF::from_u16)
        .collect();
    let preprocessors: Vec<Box<dyn NpoPreprocessor<BabyBear>>> =
        vec![Box::new(KeccakF1600Preprocessor)];
    let air_builders: Vec<Box<dyn NpoAirBuilder<config::BabyBearConfig, D>>> =
        vec![Box::new(KeccakF1600AirBuilder::<D>)];
    let mut prover = BatchStarkProver::new(config::baby_bear());
    prover.register_table_prover(Box::new(KeccakF1600Prover::<D>));
    let prepared = prover
        .prepare_circuit::<EF, D>(
            &circuit,
            &preprocessors,
            &air_builders,
            ConstraintProfile::Standard,
        )
        .unwrap();
    let mut runner = circuit.runner();
    runner.set_public_inputs(&public).unwrap();
    let traces = runner
        .run()
        .expect("the native digest satisfies the circuit");
    let proof = prepared.prove(&traces).unwrap();
    prepared.verifier().verify(&proof, &[]).unwrap();
}
