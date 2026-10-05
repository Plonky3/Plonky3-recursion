# p3-recursion

Recursive proof verification for Plonky3 STARKs: build a circuit that verifies a
uni-stark or batch-stark proof, so proofs can be aggregated layer by layer.

Key items:

- `build_and_prove_next_layer` / `build_and_prove_aggregation_layer` — one-shot unified recursion entry points
- `PreparedLayer` / `PreparedAggregation` — reusable owners with native shape checks
- `TrustedPreparedLayer` / `TrustedPreparedAggregation` — reusable owners that retain child relation authority and accept caller-expected statements
- `TrustedPreparedAggregation::new_state_transition` — compose trusted `[initial state, final state, count]` statements into a compact transition statement
- `TypedArtifactVerifier` / `VerifiedArtifactProof` — import serialized proofs against an independently pinned verifier and caller-expected statement for trusted prepared recursion
- `FriRecursionBackendForExt` / `FriRecursionConfig` and `WhirRecursionBackendForExt` / `WhirRecursionConfig` — direct recursion for the registered FRI and WHIR built-in suites with matching backends
- `verify_batch_circuit`, `verify_p3_uni_proof_circuit` — expert in-circuit proof verifiers
- `CircuitChallenger` — in-circuit Fiat–Shamir transcript
- `BinaryTower128Challenger` — non-native Keccak-256/BLAKE3 byte transcript over the binary tower
- `Recursive`, `RecursiveAir`, `RecursivePcs`, `RecursiveMmcs` — the recursion trait family
- `StarkVerifierInputs` / `PublicInputBuilder` and the `*InputsBuilder` types — verifier public-input assembly

Part of [Plonky3-recursion](https://github.com/Plonky3/Plonky3-recursion), dual-licensed under MIT and Apache 2.0.

See the [compiled trusted-owner example](src/prelude.rs),
[unified API guide](../book/src/user_guide/api.md), and
[built-in FRI configs](src/builtin_config/fri.rs) for current signatures.

The [aggregation guide](../book/src/user_guide/aggregation.md#composing-state-transitions)
explains transition count bounds, prepared reuse, and independent root verification.
The [integration guide](../book/src/user_guide/integration.md#import-portable-artifacts-into-trusted-recursion)
explains typed artifact import and application-supplied configuration.
The [configuration guide](../book/src/user_guide/configuration.md#choosing-a-built-in-recursion-backend)
maps built-in suites to backends and describes recursive parameter limits.
The [binary-field guide](../book/src/advanced_topics/binary_fields.md)
describes the separate binary byte-hash challenger and its proof-table registration.
The [binary prover example](examples/binary_prover.rs) proves successive Poly64
squarings with native WHIR, then proves and verifies a BabyBear recursion layer:
`cargo run -p p3-recursion --release --example binary_prover`.

The [native binary recursion example](examples/native_binary_recursion.rs) proves
and verifies a Tower128 verifier circuit over Tower128 again, using native Keccak,
product-bus wiring and additive WHIR:
`cargo run -p p3-recursion --profile optimized --features parallel --example native_binary_recursion -- --layers 1`.
`prepared::PreparedNativeBinaryWhirLayer` retains the trusted child authority and
binds the recursive proof to the caller's original expected public values. Its
output authority can prepare another binary layer. The example uses development
security parameters, non-hiding proofs and explicit allocation limits; deeper
layers currently grow substantially with dense Keccak openings.
