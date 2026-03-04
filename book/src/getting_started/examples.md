# Examples

This section walks through the three provided examples to illustrate common recursion patterns.

## Recursive Keccak — verifying a uni-STARK proof

**Source**: `recursion/examples/recursive_keccak.rs`

This example starts from a standard Plonky3 uni-STARK proof of the Keccak AIR, then recursively verifies it through multiple layers.

**Flow:**

1. Generate a Keccak trace and prove it with `p3_uni_stark::prove`.
2. Wrap the resulting `Proof<SC>` in a `RecursionInput::UniStark`.
3. Call `build_and_prove_next_layer` — this builds a verification circuit that checks the Keccak proof, runs it, and produces a batch-STARK proof.
4. For subsequent layers, convert the output with `output.into_recursion_input::<BatchOnly>()` and repeat.

The key point: the first recursive layer handles a **uni-STARK** proof (potentially large, depending on the AIR width). After that, every layer verifies the previous layer's **batch-STARK** proof, which has a predictable, smaller structure. This is why layer 1 is typically slower than layers 2+.

```bash
cargo run --release --example recursive_keccak -- \
    --field koala-bear --num-hashes 1000 --num-recursive-layers 3
```

## Recursive Fibonacci — verifying a batch-STARK proof

**Source**: `recursion/examples/recursive_fibonacci.rs`

This example builds a Fibonacci circuit from scratch using `CircuitBuilder`, proves it with `BatchStarkProver`, then recurses.

**Flow:**

1. Build the circuit: `CircuitBuilder::new()`, add constants, public inputs, arithmetic, `connect`, `build`.
2. Run and prove the base circuit with `BatchStarkProver`.
3. Wrap the output in `RecursionOutput` (since it's already a batch proof), then use `into_recursion_input::<BatchOnly>()`.
4. Call `build_and_prove_next_layer` in a loop for each recursive layer.

This example demonstrates how to use the `CircuitBuilder` for your own computations and then feed the resulting proof into the recursion pipeline.

```bash
cargo run --release --example recursive_fibonacci -- \
    --field koala-bear --n 10000 --num-recursive-layers 3
```

## Recursive Aggregation — 2-to-1 proof merging

**Source**: `recursion/examples/recursive_aggregation.rs`

This example produces multiple independent base proofs and aggregates them pairwise in a binary tree.

**Flow:**

1. Produce `2^depth` independent base proofs (each proving a different constant).
2. At each tree level, pair up proofs and call `build_and_prove_aggregation_layer` on each pair.
3. Repeat until a single root proof remains.

The aggregation circuit verifies **two** proofs in a single circuit — left and right children — producing one output proof. The two inputs may be different kinds of `RecursionInput` (e.g., one `UniStark` and one `BatchStark`), though in this example they are all `BatchStark`.

```bash
# 4 base proofs, 2 aggregation levels
cargo run --release --example recursive_aggregation -- \
    --field koala-bear --num-recursive-layers 2
```

## Common patterns across examples

All three examples share the same setup pattern:

1. **Config wrapper**: A `ConfigWithFriParams` struct that wraps a `StarkConfig` and adds `FriVerifierParams`. It implements `StarkGenericConfig` (by delegating) and `FriRecursionConfig`.

2. **Backend creation**: `FriRecursionBackend::<WIDTH, RATE>::new(poseidon2_config)`.

3. **Table packing**: Adjusted per layer — the first layer may need different packing than subsequent layers because the verification circuit has a different shape.

4. **Verification after proving**: Each example verifies the proof it just produced, using `BatchStarkProver::verify_all_tables`.

See the [Integration Guide](./integration.md) for how to adapt this pattern to your own project.
