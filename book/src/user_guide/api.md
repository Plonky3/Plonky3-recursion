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
pub struct RecursionOutput<SC>(pub BatchStarkProof<SC>, pub Arc<CircuitProverData<SC>>);
```

Contains the batch-STARK proof and prover data in an `Arc`. The latter is a
compatibility handle, not independent verifier authority. Convert to an expert
`RecursionInput` using proof-attached table public values:

```rust,ignore
let next_input = output.into_recursion_input::<BatchOnly>();
```

For trusted chaining, retain a `CircuitVerifier` separately and call
`output.into_trusted_recursion_input::<BatchOnly>(&verifier, &expected_statement)`.
That method derives the per-table public vectors from the verifier's retained relation.

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

This compatibility check is shape-only: a prepared owner does not bind child proving keys,
recursion statements, or public claims. Use `TrustedPreparedLayer` when the verifier relation
must be fixed independently of each proof. Its `TrustedPreparedSource::UniStark` retains the
trusted native config, AIR and preprocessing commitment; its `BatchStark` source retains a
`CircuitVerifier`. `TrustedPreparedInput` supplies only a proof and caller-expected statement.
The owner can export an independently retained verifier for its output. See the
[compiled prelude example](https://github.com/Plonky3/Plonky3-recursion/blob/main/recursion/src/prelude.rs) and
[trusted layer tests](https://github.com/Plonky3/Plonky3-recursion/blob/main/recursion/tests/prepared_layer.rs).

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

As with `PreparedLayer`, this owner checks native shape compatibility only. Use
`TrustedPreparedAggregation` to retain both child authorities and their left/right statement
layout. Supply each child's expected statement on every proof attempt; see the
[trusted aggregation tests](https://github.com/Plonky3/Plonky3-recursion/blob/main/recursion/tests/prepared_aggregation.rs).

### `prove_aggregation_layer`

The split build/prove variant is an expert API. Follow the checked
[`build_aggregation_layer_circuit` and `prove_aggregation_layer` signatures](https://github.com/Plonky3/Plonky3-recursion/blob/main/recursion/src/recursion.rs)
if you need to manage the circuit and verifier results directly.

## Recursion loop pattern

A typical recursion loop looks like this:

```rust,ignore
let backend = FriRecursionBackend::<16, 8>::new(Poseidon2Config::KOALA_BEAR_D4_W16)
    .for_extension_degree::<4>();

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

The const generic `D` is the extension field degree. Built-in BabyBear and
KoalaBear binomial suites use `D = 4`; Goldilocks uses `D = 2`. KoalaBear
quintic FRI uses `D = 5` through `FriRecursionBackendD5`, with a base-field
(`D1`) challenger permutation. The built-in WHIR suites use `D = 4`.

## FriRecursionBackend

`FriRecursionBackend::for_extension_degree::<D>()` returns a degree-tagged backend that
implements `PcsRecursionBackend` for the matching FRI-based config. It handles:

- Preparing the circuit for verification (enabling the challenger permutation and NPOs)
- Building the verifier circuit (delegating to `verify_p3_uni_proof_circuit` or `verify_p3_batch_proof_circuit`)
- Packing public inputs
- Setting Merkle path private data

`WIDTH` and `RATE` describe the challenger permutation: 16 and 8 for
BabyBear/KoalaBear, or 8 and 4 for Goldilocks. `C` is the challenger config
(`Poseidon1Config` or `Poseidon2Config`); use `_` in the type arguments to
infer it from `new`.

```rust,ignore
// Standard Poseidon2 backend
let backend = FriRecursionBackend::<16, 8>::new(Poseidon2Config::KOALA_BEAR_D4_W16)
    .for_extension_degree::<4>();

// Quaternary FRI: narrow challenger, wider Poseidon2 MMCS table
let quaternary = FriRecursionBackend::<16, 8, _>::new(Poseidon2Config::KOALA_BEAR_D4_W16)
    .with_extra_poseidon2_table(Poseidon2Config::KOALA_BEAR_D4_W32)
    .for_extension_degree::<4>();

// KoalaBear quintic FRI: the challenger uses D1 base-field Poseidon lanes
let quintic = FriRecursionBackend::<16, 8, _>::new_d5(
    Poseidon2Config::KOALA_BEAR_D1_W16,
);
```

`FriRecursionBackendD5` handles the supported quintic (`D = 5`) variant;
`FriRecursionBackendForExt<D>` tags binomial extension degrees such as 2 and 4.
For Poseidon1 suites, select the matching `p3_recursion::ops::Poseidon1Config`
constant in `new` or `new_d5`. Quaternary built-ins use Poseidon2 and require
the matching wide table; binary and hiding FRI do not add one. See
[built-in backend selection](./configuration.md#choosing-a-built-in-recursion-backend)
for the suite map and FRI table shapes.

## WhirRecursionBackend

The BabyBear and KoalaBear built-in WHIR suites use a Poseidon2 challenger,
binary commitments, and a degree-4 extension:

```rust,ignore
let backend = p3_recursion::backend::whir::WhirRecursionBackend::<16, 8>::new(
    Poseidon2Config::BABY_BEAR_D4_W16,
).for_extension_degree::<4>();
```

Choose recursively admissible WHIR geometry as described in
[Configuration](./configuration.md#choosing-a-built-in-recursion-backend).
