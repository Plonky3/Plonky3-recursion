# Unified Recursion API

The library exposes a unified API that handles both uni-STARK and batch-STARK proofs through a single set of entry points.

## Core types

### `RecursionInput`

Wraps the proof to verify at each recursion step:

```rust,ignore
pub enum RecursionInput<'a, SC, A> {
    /// A single-instance STARK proof (e.g. from p3-uni-stark).
    UniStark {
        proof: &'a Proof<SC>,
        air: &'a A,
        public_inputs: Vec<Val<SC>>,
        preprocessed_commit: Option<<SC::Pcs as Pcs<SC::Challenge, SC::Challenger>>::Commitment>,
    },
    /// A batch STARK proof (e.g. from p3-batch-stark or circuit-prover).
    BatchStark {
        proof: &'a BatchStarkProof<SC>,
        common_data: &'a CommonData<SC>,
        table_public_inputs: Vec<Vec<Val<SC>>>,
    },
}
```

Use `UniStark` when verifying an external Plonky3 proof (e.g. Keccak AIR). Use `BatchStark` when verifying a proof produced by this library's own prover.

### `RecursionOutput`

The output of one recursion step:

```rust,ignore
pub struct RecursionOutput<SC>(pub BatchStarkProof<SC>, pub Rc<CircuitProverData<SC>>);
```

Contains the batch-STARK proof and the prover data (reference-counted for cheap cloning) needed for further chaining. Convert it to a `RecursionInput` for the next layer:

```rust,ignore
let next_input = output.into_recursion_input::<BatchOnly>();
```

The `BatchOnly` marker type satisfies the `RecursiveAir` bound without carrying any AIR data — it's a no-op used when the next layer only needs to verify the recursive batch proof.

### `ProveNextLayerParams`

Controls the proving pipeline:

```rust,ignore
pub struct ProveNextLayerParams {
    pub table_packing: TablePacking,
    pub constraint_profile: ConstraintProfile,
}
```

- `table_packing`: How to distribute operations across table lanes. See [Configuration](./configuration.md#table-packing).
- `constraint_profile`: Which AIR variants the prover uses for this layer (`ConstraintProfile::Standard` for normal use).

The default is `TablePacking::new(1, 4)` with `ConstraintProfile::Standard`.

## Entry points

### `build_and_prove_next_layer`

The simplest way to prove one recursion step. Builds the verifier circuit, runs it, and proves it in one call:

```rust,ignore
let output = build_and_prove_next_layer::<SC, A, B, D>(
    &input, &config, &backend, &params,
)?;
```

### `PreparedLayer` (repeated proving)

For repeated invocations, let an owner capture the native input contract and retain the verifier circuit, configuration, and prepared proving data together:

```rust,ignore
let owner = PreparedLayer::<SC, A, B, D>::new(
    PreparedSource::UniStark { air, proof, public_inputs, preprocessed_commit },
    config,
    backend,
    params,
)?;

// Check the native contract before each repeated proof.
owner.check_input(&input)?;
let output = owner.prove(input)?;
```

`PreparedLayer` owns the committed preprocessed columns and prover, and rejects malformed or incompatible native inputs before proving. Use a new owner when the native contract changes.

This compatibility check is shape-only: a prepared owner is not a portable trusted relation
verifier and does not bind child proving keys, recursion statements, or public claims. Later
trust-boundary work must pin those relations before an owner can be reused across such changes.

### `build_and_prove_aggregation_layer`

Verifies two proofs in a single circuit. The two inputs can be different `RecursionInput` variants:

```rust,ignore
let output = build_and_prove_aggregation_layer::<SC, A1, A2, B, D>(
    &left, &right, &config, &backend, &params,
)?;
```

### `PreparedAggregation` (repeated aggregation)

For repeated aggregation at one compatible level, retain both verifier results and prepared
proving data in an owner. Check both borrowed inputs before each reuse; construct a new owner when
either native contract changes:

```rust,ignore
let owner = PreparedAggregation::new(
    PreparedSource::batch(&left_proof, &left_common_data, &left_table_public_inputs),
    PreparedSource::batch(&right_proof, &right_common_data, &right_table_public_inputs),
    config,
    backend,
    params,
)?;

let left = PreparedInput::BatchStark {
    proof: &left_proof,
    common_data: &left_common_data,
    table_public_inputs: &left_table_public_inputs,
};
let right = PreparedInput::BatchStark {
    proof: &right_proof,
    common_data: &right_common_data,
    table_public_inputs: &right_table_public_inputs,
};
owner.check_inputs(&left, &right)?;
let output = owner.prove(left, right)?;
```

As with `PreparedLayer`, this owner checks native shape compatibility only. It does not itself
bind child keys or statements, so relation and claim changes require explicit trust-boundary
policy rather than owner reuse.

### `prove_aggregation_layer`

The split build/prove variant for aggregation. The circuit builder is private; use `prove_aggregation_layer` with a pre-built circuit when you need to re-prove the same aggregation shape:

```rust,ignore
let output = prove_aggregation_layer::<SC, A1, A2, B, D>(
    &left, &right, &left_result, &right_result,
    circuit, &config, &backend, &params,
)?;
```

See the source of `build_and_prove_aggregation_layer` for how to obtain `left_result`, `right_result`, and `circuit` when splitting manually.

## Recursion loop pattern

A typical recursion loop looks like this:

```rust,ignore
let backend = FriRecursionBackend::<16, 8>::new(Poseidon2Config::KoalaBearD4Width16);

// Layer 1: verify the base proof
let input = RecursionInput::UniStark { proof: &base_proof, air: &my_air, .. };
let mut output = build_and_prove_next_layer::<_, _, _, 4>(&input, &config, &backend, &params)?;

// Layers 2..N: verify the previous recursive proof
for _ in 2..=num_layers {
    let input = output.into_recursion_input::<BatchOnly>();
    output = build_and_prove_next_layer::<_, _, _, 4>(&input, &config, &backend, &params)?;
}
```

After enough layers, the recursive proof reaches a steady-state size — further layers don't meaningfully change the proof dimensions.

## Type parameter `D`

The const generic `D` is the extension field degree. For binomial extensions (BabyBear, KoalaBear), use `D = 4`. A quintic variant (`D = 5`, KoalaBear only) is supported via `FriRecursionBackendD5`.

## FriRecursionBackend

The `FriRecursionBackend<WIDTH, RATE, C>` implements `PcsRecursionBackend` for FRI-based configs. It handles:

- Preparing the circuit for verification (enabling the challenger permutation and NPOs)
- Building the verifier circuit (delegating to `verify_p3_uni_proof_circuit` or `verify_p3_batch_proof_circuit`)
- Packing public inputs
- Setting Merkle path private data

`WIDTH` and `RATE` are the permutation parameters (typically 16 and 8 for 32-bit fields). `C` is the challenger permutation config (defaults to `Poseidon2Config`).

```rust,ignore
// Standard Poseidon2 backend
let backend = FriRecursionBackend::<16, 8>::new(Poseidon2Config::KoalaBearD4Width16);

// With an extra Poseidon2 table config for proofs that use a wider MMCS hash
let backend = FriRecursionBackend::<16, 8>::new(Poseidon2Config::KoalaBearD4Width16)
    .with_extra_poseidon2_table(Poseidon2Config::KoalaBearD4Width24);
```

`FriRecursionBackendD5` is a type alias for the quintic (`D = 5`) variant and `FriRecursionBackendForExt` covers mixed-degree scenarios.
