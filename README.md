# Plonky3-recursion

Plonky3 native support for recursive STARK verification, enabling proof composition and multi-layer recursion.

## Overview

This library provides a **fixed recursive verifier** for Plonky3 STARK (both `p3-uni-stark` and `p3-batch-stark` proofs), allowing you to verify proofs inside circuits and compose proofs recursively. The recursive verifier is implemented as a circuit itself, which can be proven and verified in subsequent layers.

### Key Features

- **Recursive STARK Verification**: Verify Plonky3 STARK proofs inside circuits
- **Batch STARK Support**: Verify multiple proofs in a single batch
- **Modular Circuit Builder**: Build circuits with primitive operations (add, mul, etc.) and non-primitive operations (Poseidon2)
- **FRI-based PCS**: Full support for FRI (Fast Reed-Solomon Interactive) polynomial commitment scheme verification in-circuit

## Production Use

**⚠️ This codebase is under active development and hasn't been audited yet.** As such, we do not recommend its use in any production software.

[![Coverage](https://github.com/Plonky3/Plonky3-recursion/actions/workflows/coverage.yml/badge.svg)](https://plonky3.github.io/Plonky3-recursion/coverage/) (_updated weekly_)

## Quick Start

### Unified recursion API

For most use cases, use the **unified API**: a single entry point works for both uni-stark (e.g. Keccak) and batch-stark (e.g. Fibonacci) proofs. Implement [`FriRecursionConfig`] for your config (or a wrapper that holds FRI verifier params), then call [`prove_next_layer`] in a loop.

[`FriRecursionConfig`]: https://docs.rs/p3-recursion/latest/p3_recursion/trait.FriRecursionConfig.html
[`prove_next_layer`]: https://docs.rs/p3-recursion/latest/p3_recursion/fn.prove_next_layer.html

```rust
use p3_recursion::{
    FriRecursionBackend, FriRecursionConfig, ProveNextLayerParams, RecursionInput, RecursionOutput,
    prove_next_layer,
};

// First layer: recurse on a uni-stark proof (e.g. Keccak)
let input = RecursionInput::UniStark {
    proof: &base_proof,
    air: &keccak_air,
    public_inputs: pis.clone(),
    preprocessed_commit: None,
};
let backend = FriRecursionBackend::new(poseidon2_config);
let params = ProveNextLayerParams { table_packing, use_poseidon2_in_circuit: true };
let output = prove_next_layer(&input, &config, &backend, &params)?;

// Next layers: recurse on the previous batch proof
let input = output.into_recursion_input::<BatchOnly>();
let output = prove_next_layer(&input, &config, &backend, &params)?;
```

`RecursionOutput` is `(BatchStarkProof, CircuitProverData)`; use `into_recursion_input::<BatchOnly>()` to chain further layers.

### Low-level API

For fine-grained control, you can build the verification circuit and run the prover pipeline yourself via `verify_p3_recursion_proof_circuit` (batch) or `verify_circuit` (uni-stark):

```rust
use p3_recursion::verifier::verify_p3_recursion_proof_circuit;
use p3_recursion::public_inputs::BatchStarkVerifierInputsBuilder;
use p3_circuit::CircuitBuilder;

// Build a verification circuit
let mut circuit_builder = CircuitBuilder::new();
circuit_builder.enable_poseidon2_perm::<Config, _>(trace_generator, poseidon2_perm);

let (verifier_inputs, mmcs_op_ids) = verify_p3_recursion_proof_circuit::<
    MyConfig,
    HashTargets<F, DIGEST_ELEMS>,
    InputProofTargets<F, Challenge, RecValMmcs<...>>,
    InnerFri,
    LogUpGadget,
    WIDTH,
    RATE,
    TRACE_D,
>(
    &config,
    &mut circuit_builder,
    &batch_stark_proof,
    &fri_verifier_params,
    common_data,
    &lookup_gadget,
    Poseidon2Config::BabyBearD4Width16,
)?;

// Build and run the circuit
let circuit = circuit_builder.build()?;
let mut runner = circuit.runner();

// Pack public inputs using the builder
let public_inputs = verifier_inputs.pack_values(&pis, &batch_proof, common_data);
runner.set_public_inputs(&public_inputs)?;

// Set MMCS private data (Merkle paths)
set_fri_mmcs_private_data(&mut runner, &mmcs_op_ids, &proof.opening_proof)?;

let traces = runner.run()?;
```

### Examples

Both examples use the unified API (`prove_next_layer`, `RecursionInput`, `FriRecursionBackend`):

- **`recursive_fibonacci.rs`**: Base layer is a batch-stark circuit (Fibonacci); recursive layers use `into_recursion_input::<BatchOnly>()` and `prove_next_layer`.
  ```bash
  cargo run --release --example recursive_fibonacci -- --field koala-bear --n 1000 --num-recursive-layers 5
  ```

- **`recursive_keccak.rs`**: Base layer is a uni-stark Keccak proof; layer 1 uses `RecursionInput::UniStark`, then further layers use `into_recursion_input::<BatchOnly>()` and `prove_next_layer`.
  ```bash
  cargo run --release --example recursive_keccak -- --field koala-bear --n 100 --num-recursive-layers 5
  ```


## API Overview

### Circuit Builder

The `CircuitBuilder<F>` provides a modular API for building circuits:

**Primitive Operations** (always available):
- `add_const(val)` - Add a constant
- `add_public_input()` - Allocate a public input
- `mul(a, b)` - Multiply two expressions
- `add(a, b)` / `sub(a, b)` - Arithmetic operations
- `connect(a, b)` - Constrain two expressions to be equal

**Non-primitive Operations** (require explicit enablement):
- `enable_poseidon2_perm()` - Enable Poseidon2 permutation operations
- Operations are controlled by a runtime policy (`DefaultProfile` disables all, `AllowAllProfile` enables all)

### Public Inputs

Public inputs must be provided in the **exact order** the circuit allocated them. Use the builder APIs to ensure correctness:

```rust
use p3_recursion::public_inputs::PublicInputBuilder;

let mut builder = PublicInputBuilder::new();
builder
    .add_proof_values(proof_values)
    .add_challenge(alpha)
    .add_challenges(betas);
let public_inputs = builder.build();
```

For batch verification, use `BatchStarkVerifierInputsBuilder::pack_values()` which handles the packing automatically.

## Architecture

### Components

1. **Circuit Builder** (`p3_circuit`): Expression graph builder with primitive and non-primitive operations
2. **Circuit Prover** (`p3_circuit_prover`): Generates STARK proofs for circuits
3. **Recursive Verifier** (`p3_recursion::verifier`): Verifies STARK proofs inside circuits
4. **FRI PCS** (`p3_recursion::pcs::fri`): FRI polynomial commitment scheme verification in-circuit

### Recursion Flow

1. **Base Layer**: Prove a computation using Plonky3 STARK
2. **Recursive Layer**: Build a verification circuit that checks the base proof
3. **Prove Recursive Layer**: Prove the verification circuit itself
4. **Repeat**: Continue recursion for additional layers

Each recursive layer verifies the previous layer's proof, creating a chain of proofs.

## Performance Considerations

### Table Packing

The `TablePacking` configuration significantly impacts performance.
Choose lane counts that fit best your circuit size:

```rust
TablePacking::new(8, 2, 5)  // witness, public, alu lanes
```

### FRI Parameters

FRI parameters affect proof size and verification cost:
- `log_blowup`: LDE blowup factor (typically 3)
- `max_log_arity`: Maximum folding arity (typically 4)
- `log_final_poly_len`: Final polynomial size (typically 5)
- `query_pow_bits`: PoW bits for query phase (typically 16)

For intermediate recursive layers, consider relaxed parameters (fewer queries, higher PoW bits).

### Known Optimizations

- **Merkle Caps**: Not yet implemented; could reduce Poseidon2 rows by ~10%
- **Dedicated FRI Fold Table**: Could offload ~30K operations to a specialized AIR
- **Removing the Witness bus**: Could remove the entire table at the cost of extra CTLs
- **Switch to base field indexing**: Would remove the overhead of decomposing / recomposing 
- **Optimization passes**: Additional optimizations at circuit building time to prune unused nodes.

## Current Limitations

- **ZK Mode**: Currently only supports non-ZK STARKs (`config.is_zk() == 0`)
- **Fixed Configurations**: Poseidon2 currently requires D=4, WIDTH=16 for extension fields

## Documentation

Documentation is still incomplete and will be improved over time.

- **[Plonky3 Recursion Book](https://Plonky3.github.io/Plonky3-recursion/)**: Comprehensive walkthrough of the recursion approach
- **API Documentation**: `cargo doc --open` for full API reference
- **Examples**: See `recursion/examples/` for working code

## Modular Circuit Builder & Runtime Policy

The `CircuitBuilder<F>` uses a runtime policy to control which non-primitive operations (MMCS, FRI, etc.) are allowed. Primitive ops like `Const`, `Public`, `Add` are always available.

By default, all non-primitive ops are disabled with `DefaultProfile`. Define a custom policy to enable them, or use `AllowAllProfile` to activate them all.

Trying to access an op not supported by the selected policy in the circuit builder will result in a runtime error.

## License

Licensed under either of

* Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
* MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in the work by you, as defined in the Apache-2.0 license, shall be dual licensed as above, without any additional terms or conditions.
