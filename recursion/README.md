# p3-recursion

Recursive proof verification for Plonky3 STARKs: build a circuit that verifies a
uni-stark or batch-stark proof, so proofs can be aggregated layer by layer.

Key items:

- `prove_next_layer` / `build_and_prove_next_layer` / `build_and_prove_aggregation_layer` — the unified recursion entry points
- `FriRecursionBackend` / `FriRecursionConfig` — the FRI PCS backend for the recursion API
- `verify_batch_circuit`, `verify_p3_uni_proof_circuit` — in-circuit proof verifiers
- `CircuitChallenger` — in-circuit Fiat–Shamir transcript
- `Recursive`, `RecursiveAir`, `RecursivePcs`, `RecursiveMmcs` — the recursion trait family
- `StarkVerifierInputs` / `PublicInputBuilder` and the `*InputsBuilder` types — verifier public-input assembly

Part of [Plonky3-recursion](https://github.com/Plonky3/Plonky3-recursion), dual-licensed under MIT and Apache 2.0.
