# Quick Start

## Requirements

- Rust stable (edition 2024)
- For best performance: `RUSTFLAGS="-Ctarget-cpu=native"`

## Add the dependency

Plonky3-recursion is not yet published on crates.io. Add it as a git dependency:

```toml
[dependencies]
p3-recursion = { git = "https://github.com/Plonky3/Plonky3-recursion", package = "p3-recursion" }
```

You will also need Plonky3 crates for fields, STARKs, and hashing. The recursion library re-exports what it needs, but your base prover setup will require direct Plonky3 dependencies.

## Minimal example

The fastest way to verify a proof recursively:

```rust,ignore
use p3_recursion::{
    FriRecursionBackend, ProveNextLayerParams, RecursionInput,
    build_and_prove_next_layer, BatchOnly, Poseidon2Config,
};

// 1. You already have a Plonky3 STARK proof (uni-stark or batch-stark).
//    Wrap it in a RecursionInput.
let input = RecursionInput::UniStark {
    proof: &base_proof,
    air: &my_air,
    public_inputs: public_values.clone(),
    preprocessed_commit: None,
};

// 2. Create the FRI backend with a Poseidon2 config matching your field.
let backend = FriRecursionBackend::<16, 8>::new(Poseidon2Config::KoalaBearD4Width16);

// 3. Prove. This builds the verifier circuit, runs it, and produces a batch-STARK proof.
let params = ProveNextLayerParams::default();
let output = build_and_prove_next_layer::<_, _, _, 4>(
    &input, &config, &backend, &params,
)?;

// 4. Chain further layers by converting the output back to an input.
let next_input = output.into_recursion_input::<BatchOnly>();
let output_2 = build_and_prove_next_layer::<_, _, _, 4>(
    &next_input, &config, &backend, &params,
)?;
```

The config (`&config`) must implement `FriRecursionConfig`. See the [Integration Guide](./integration.md) for how to set this up, or the [Examples](./examples.md) for complete working code.

## Running the examples

Three examples ship with the library:

```bash
# Recursive Keccak (uni-STARK base proof)
cargo run --release --example recursive_keccak -- --field koala-bear --num-hashes 100

# Recursive Fibonacci (batch-STARK base proof built with CircuitBuilder)
cargo run --release --example recursive_fibonacci -- --field koala-bear --n 1000

# 2-to-1 aggregation (binary tree of proofs)
cargo run --release --example recursive_aggregation -- --field koala-bear
```

Add `--features parallel` and `RUSTFLAGS="-Ctarget-cpu=native"` for production-level performance.
