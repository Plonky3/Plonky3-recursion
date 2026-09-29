# p3-recursion

Recursive proof verification for Plonky3 STARKs: build a circuit that verifies a
uni-stark or batch-stark proof, so proofs can be aggregated layer by layer.

Key items:

- `build_and_prove_next_layer` / `build_and_prove_aggregation_layer` — one-shot unified recursion entry points
- `PreparedLayer` / `PreparedAggregation` — reusable owners with native shape checks
- `TrustedPreparedLayer` / `TrustedPreparedAggregation` — reusable owners that retain child relation authority and accept caller-expected statements
- `TrustedPreparedAggregation::new_state_transition` — compose trusted `[initial state, final state, count]` statements into a compact transition statement
- `FriRecursionBackendForExt` / `FriRecursionConfig` — degree-tagged FRI backend and config contract
- `verify_batch_circuit`, `verify_p3_uni_proof_circuit` — expert in-circuit proof verifiers
- `CircuitChallenger` — in-circuit Fiat–Shamir transcript
- `Recursive`, `RecursiveAir`, `RecursivePcs`, `RecursiveMmcs` — the recursion trait family
- `StarkVerifierInputs` / `PublicInputBuilder` and the `*InputsBuilder` types — verifier public-input assembly

Part of [Plonky3-recursion](https://github.com/Plonky3/Plonky3-recursion), dual-licensed under MIT and Apache 2.0.

See the [compiled trusted-owner example](src/prelude.rs),
[unified API guide](../book/src/user_guide/api.md), and
[built-in FRI configs](src/builtin_config/fri.rs) for current signatures.

The [aggregation guide](../book/src/user_guide/aggregation.md#composing-state-transitions)
explains transition count bounds, prepared reuse, and independent root verification.
