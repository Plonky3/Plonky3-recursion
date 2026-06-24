# p3-circuit-prover

A batch-STARK prover and verifier for circuits built with `p3-circuit`, generic
over the base field and cryptographic permutation. Each circuit table is proven
as an AIR under a single shared commitment.

Key items:

- `BatchStarkProver` — proves and verifies all circuit tables from a `p3-circuit` runner's `Traces`
- `config::{babybear_config, koalabear_config, goldilocks_config}` — field-specific `StarkConfig` builders
- `air` — the per-table AIRs (Const, Public, ALU, Poseidon, …)
- `ConstraintProfile` — per-table constraint-degree accounting

Part of [Plonky3-recursion](https://github.com/Plonky3/Plonky3-recursion), dual-licensed under MIT and Apache 2.0.
