# Low-Level API

For fine-grained control over the verification circuit, you can bypass the unified API and build the pipeline manually.

## Manual uni-STARK verification

```rust,ignore
use p3_recursion::verifier::verify_p3_uni_proof_circuit;
use p3_recursion::public_inputs::StarkVerifierInputsBuilder;
use p3_circuit::CircuitBuilder;

let mut circuit_builder = CircuitBuilder::new();

// Enable Poseidon2 for MMCS verification
circuit_builder.enable_poseidon2_perm::<MyPoseidon2Config, _>(trace_generator, perm);

// Allocate public input targets and build verification constraints
let verifier_inputs = StarkVerifierInputsBuilder::allocate(
    &mut circuit_builder, &proof, preprocessed_commit.as_ref(), num_public_values,
);

let op_ids = verify_p3_uni_proof_circuit::<
    MyAir, MyConfig, CommitTargets, InputProofTargets, OpeningProofTargets,
    WIDTH, RATE,
>(
    &config, &air, &mut circuit_builder,
    &verifier_inputs.proof_targets,
    &verifier_inputs.air_public_targets,
    &verifier_inputs.preprocessed_commit,
    &fri_verifier_params,
    poseidon2_config,
)?;

// Build and run
let circuit = circuit_builder.build()?;
let mut runner = circuit.runner();

let public_inputs = verifier_inputs.pack_values(&pis, &proof, &preprocessed_commit);
runner.set_public_inputs(&public_inputs)?;

set_fri_mmcs_private_data(&mut runner, &op_ids, &proof.opening_proof)?;

let traces = runner.run()?;
```

## Manual batch-STARK verification

```rust,ignore
use p3_recursion::verifier::verify_p3_batch_proof_circuit;

let mut circuit_builder = CircuitBuilder::new();
circuit_builder.enable_poseidon2_perm::<MyPoseidon2Config, _>(trace_generator, perm);

let lookup_gadget = LogUpGadget::new();

let (verifier_inputs, op_ids) = verify_p3_batch_proof_circuit::<
    MyConfig, CommitTargets, InputProofTargets, OpeningProofTargets, LogUpGadget,
    WIDTH, RATE, TRACE_D,
>(
    &config, &mut circuit_builder, &batch_proof,
    &fri_verifier_params, &common_data, &lookup_gadget, poseidon2_config,
)?;

let circuit = circuit_builder.build()?;
let mut runner = circuit.runner();

let public_inputs = verifier_inputs.pack_values(
    &table_public_inputs, &batch_proof.proof, &common_data,
);
runner.set_public_inputs(&public_inputs)?;

set_fri_mmcs_private_data(&mut runner, &op_ids, &batch_proof.proof.opening_proof)?;

let traces = runner.run()?;
```

## Proving the verification circuit

Once you have traces, prove them with `BatchStarkProver`:

```rust,ignore
use p3_circuit_prover::{BatchStarkProver, CircuitProverData};
use p3_circuit_prover::common::get_airs_and_degrees_with_prep;

let (airs_degrees, preprocessed) = get_airs_and_degrees_with_prep::<SC, EF, D>(
    &circuit, table_packing, &[Box::new(Poseidon2Prover::new(
        poseidon2_config,
        ConstraintProfile::Standard,
    ))],
)?;

let (mut airs, degrees): (Vec<_>, Vec<_>) = airs_degrees.into_iter().unzip();
let prover_data = ProverData::from_airs_and_degrees(&config, &mut airs, &degrees);
let circuit_prover_data = CircuitProverData::new(prover_data, preprocessed);

let mut prover = BatchStarkProver::new(config.clone())
    .with_table_packing(table_packing);
prover.register_poseidon2_table(poseidon2_config);

let proof = prover.prove_all_tables(&traces, &circuit_prover_data)?;
```

## When to use the low-level API

- You need to inspect or modify the circuit between building and proving
- You want to share a single `CircuitBuilder` across multiple verification circuits (custom aggregation patterns beyond 2-to-1)
- You need to inject additional constraints into the verification circuit
- You want to separate circuit construction from execution for caching or serialization
