# p3-poseidon-circuit-cols

Shared column and preprocessed-row layout for the Poseidon circuit AIRs. The
outer circuit-column wrapper and the preprocessed-row encoding are identical for
every Poseidon backend, so they live here and are wrapped by backend-specific
aliases in each circuit-AIR crate.

Key items:

- `PoseidonCircuitCols` — the outer circuit-column wrapper shared across backends
- `PoseidonPreprocessedRow`, `PoseidonPrepInputLimb`, `PoseidonPrepOutputLimb` — the preprocessed-row encoding
- `num_cols`, `poseidon_preprocessed_row_width*`, `poseidon_uses_compact_d1_preprocessed` — `const` layout-size helpers

The inner permutation columns, round constants and constraint evaluation stay
per-backend, in `p3-poseidon1-circuit-air` and `p3-poseidon2-circuit-air`.

Part of [Plonky3-recursion](https://github.com/Plonky3/Plonky3-recursion), dual-licensed under MIT and Apache 2.0.
