# Integration Guide

This section explains how to connect a native Plonky3 prover to recursive verification.

## Choose a native config

For a supported field, hash, PCS, and extension degree, start with the
[checked built-in FRI factories](../../../recursion/src/builtin_config/fri.rs). They retain
native FRI metadata and the matching `FriVerifierParams` together. The
[concrete `FriRecursionConfig` implementation](../../../recursion/src/builtin_config/fri/recursion.rs)
shows how the built-in suite prepares the circuit and supplies opening witnesses.

For a custom PCS setup, implement [`FriRecursionConfig`](../../../recursion/src/backend/fri.rs)
on a `StarkGenericConfig` wrapper. It must supply the verifier target types, matching
FRI parameters, circuit preparation, and opening witness restoration. In particular,
`set_fri_private_data` receives the config and an `OpeningTranscript`; restore each query's
Merkle path from the proof's pruned multiproof before calling `set_fri_mmcs_private_data`.
The trait's rustdoc and the built-in implementation show the current signature and transcript
steps. Match the native prover parameters, including query count and MMCS permutation.

## Verify your AIR

AIRs implementing Plonky3's `Air` trait get a blanket `RecursiveAir` implementation from
the symbolic constraint system. If your AIR needs a manual implementation, follow the
[current `RecursiveAir` trait](../../../recursion/src/traits/air.rs), including its trace-length
and lookup-aware quotient-degree calculation. For trusted prepared uni-STARK verification,
`expected_public_input_count` must identify the fixed public-input width.

Wrap a native proof in `RecursionInput::UniStark` for one-shot recursion, or construct
`TrustedPreparedSource::UniStark` with the trusted config, AIR, and preprocessing commitment
for repeated verification. See the [compiled prelude example](../../../recursion/src/prelude.rs)
and [trusted layer tests](../../../recursion/tests/prepared_layer.rs) for the prepared contract.
Use `FriRecursionBackend::new(challenger_config).for_extension_degree::<D>()` for a
matching binomial extension, or the D5 backend for a supported quintic suite.

## Custom non-primitive chips

Custom non-primitive operations must be enabled on the `CircuitBuilder` before use. They
need matching trace generation, preprocessing, AIR builders, and table provers. The
[prepared recursion backend interface](../../../recursion/src/prepared/mod.rs) owns these
registrations for a prepared layer.

## Integration checklist

1. Choose a checked built-in suite or implement the native and recursive FRI contract together.
2. Supply an AIR with a `RecursiveAir` implementation and fixed public-input width when using a trusted owner.
3. Choose a backend with the matching field, permutation, and extension degree.
4. Use a prepared owner for reuse; choose a trusted prepared owner when relation and statement authority must be fixed.
5. Verify output against an independently retained `CircuitVerifier` and caller-expected statement.
