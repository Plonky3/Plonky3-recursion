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
        preprocessed_commit: Option<Commitment>,
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
pub struct RecursionOutput<SC>(pub BatchStarkProof<SC>, pub CircuitProverData<SC>);
```

Contains the batch-STARK proof and the prover data needed for further chaining. Convert it to a `RecursionInput` for the next layer:

```rust,ignore
let next_input = output.into_recursion_input::<BatchOnly>();
```

The `BatchOnly` marker type satisfies the `RecursiveAir` bound without carrying any AIR data — it's a no-op used when the next layer only needs to verify the recursive batch proof.

### `ProveNextLayerParams`

Controls the proving pipeline:

```rust,ignore
pub struct ProveNextLayerParams {
    pub table_packing: TablePacking,
    pub use_poseidon2_in_circuit: bool,
}
```

- `table_packing`: How to distribute operations across table lanes. See [Configuration](./configuration.md#table-packing).
- `use_poseidon2_in_circuit`: Whether to register the Poseidon2 non-primitive table. Should be `true` for FRI verification.

## Entry points

### `build_and_prove_next_layer`

The simplest way to prove one recursion step. Builds the verifier circuit, runs it, and proves it in one call:

```rust,ignore
let output = build_and_prove_next_layer::<SC, A, B, D>(
    &input, &config, &backend, &params,
)?;
```

### `prove_next_layer`

For better performance in production, separate circuit building from proving. The circuit only needs to be built once if the proof shape doesn't change between invocations:

```rust,ignore
// Build once
let (circuit, verifier_result) = build_next_layer_circuit(&input, &config, &backend)?;

// Prove (can be called multiple times with different inputs of the same shape)
let output = prove_next_layer::<SC, A, B, D>(
    &input, circuit, &verifier_result, &config, &backend, &params,
)?;
```

### `build_and_prove_aggregation_layer`

Verifies two proofs in a single circuit. The two inputs can be different `RecursionInput` variants:

```rust,ignore
let output = build_and_prove_aggregation_layer::<SC, A1, A2, B, D>(
    &left, &right, &config, &backend, &params,
)?;
```

### `prove_aggregation_layer`

The split build/prove variant for aggregation:

```rust,ignore
let (circuit, (left_result, right_result)) =
    build_aggregation_layer_circuit(&left, &right, &config, &backend)?;

let output = prove_aggregation_layer::<SC, A1, A2, B, D>(
    &left, &right, &left_result, &right_result,
    circuit, &config, &backend, &params,
)?;
```

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

The const generic `D` is the extension field degree. For all currently supported fields (BabyBear, KoalaBear), use `D = 4`.

## FriRecursionBackend

The `FriRecursionBackend<WIDTH, RATE>` implements `PcsRecursionBackend` for FRI-based configs. It handles:

- Enabling Poseidon2 on the circuit builder
- Building the verifier circuit (delegating to `verify_p3_uni_proof_circuit` or `verify_p3_batch_proof_circuit`)
- Packing public inputs
- Setting Merkle path private data

Create one with:

```rust,ignore
let backend = FriRecursionBackend::<16, 8>::new(Poseidon2Config::KoalaBearD4Width16);
```

`WIDTH` and `RATE` are the Poseidon2 permutation parameters (typically 16 and 8 for 32-bit fields).
