# Public Inputs

Public inputs are the values the verifier knows — they connect the circuit to the proof being verified. In recursive verification, the previous proof's commitments, opened values, and challenges become public inputs to the recursive circuit.

## How public inputs flow

When a verifier circuit is built, it allocates public input targets in a specific order. At proving time, concrete values must be packed in **exactly the same order**. If the order doesn't match, the proof will fail.

```
Base proof (commitments, openings, challenges)
         │
         ▼
┌─────────────────────────┐
│   pack_public_inputs()  │  ← extracts values from the proof in allocation order
└─────────────────────────┘
         │
         ▼
   runner.set_public_inputs(&packed_values)
```

## Automatic packing via the unified API

When using `prove_next_layer` or `build_and_prove_next_layer`, public input packing is handled automatically. The `VerifierCircuitResult::pack_public_inputs` method extracts values from the `RecursionInput` in the correct order.

You don't need to interact with the builders directly unless you're using the [low-level API](./low_level_api.md).

## Manual packing (low-level API)

If building the verification circuit manually, use the dedicated builders:

### `StarkVerifierInputsBuilder` (uni-STARK)

Returned by `verify_p3_uni_proof_circuit`. Packs values from a `Proof<SC>`:

```rust,ignore
let public_inputs = verifier_inputs.pack_values(
    &air_public_inputs,
    &proof,
    &preprocessed_commit,
);
runner.set_public_inputs(&public_inputs)?;
```

### `BatchStarkVerifierInputsBuilder` (batch-STARK)

Returned by `verify_p3_batch_proof_circuit`. Packs values from a `BatchProof<SC>` and `CommonData<SC>`:

```rust,ignore
let public_inputs = verifier_inputs.pack_values(
    &table_public_inputs,
    &batch_proof,
    &common_data,
);
runner.set_public_inputs(&public_inputs)?;
```

### `PublicInputBuilder` (generic)

For custom circuits (not recursive verification), use the generic builder:

```rust,ignore
let mut builder = PublicInputBuilder::new();
builder
    .add_proof_values(proof_values)
    .add_challenge(alpha)
    .add_challenges(betas);
let public_inputs = builder.build();
```

## Public inputs in aggregation

For aggregation circuits, public inputs from both verifications are concatenated — left first, then right. This is handled automatically by `prove_aggregation_layer`:

```rust,ignore
let mut public_inputs = left_result.pack_public_inputs(&left)?;
public_inputs.extend(right_result.pack_public_inputs(&right)?);
```
