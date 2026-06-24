# p3-test-utils

Internal test utilities shared across the Plonky3 recursion crates. Not
published to crates.io.

Key items:

- `TestFriScalars` / `test_fri_scalars` — the canonical FRI test parameters, read back from `FriParameters::new_testing` so test configs never drift
- `LiftPermToQuintic` — lifts a base-field permutation to quintic-extension-field lanes
- re-exports of the common config building blocks (`StarkConfig`, `TwoAdicFriPcs`, `MerkleTreeMmcs`, `DuplexChallenger`, …) used to assemble test configs

Part of [Plonky3-recursion](https://github.com/Plonky3/Plonky3-recursion), dual-licensed under MIT and Apache 2.0.
