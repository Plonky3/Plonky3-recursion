# p3-circuit-prover

A batch-STARK prover and verifier for circuits built with `p3-circuit`, generic
over the base field and cryptographic permutation. Each circuit table is proven
as an AIR under a single shared commitment.

Key items:

- `BatchStarkProver::prepare_circuit` — finalizes a circuit relation and preprocessing once
- `PreparedCircuitProver::prove` / `CircuitVerifier::verify` — prove runner traces and verify against an independently retained relation and expected statement
- `config::{baby_bear, koala_bear, goldilocks}` — field-specific `StarkConfig` builders
- `air` — the per-table AIRs (Const, Public, ALU, Poseidon, …)
- `ConstraintProfile` — per-table constraint-degree accounting

Part of [Plonky3-recursion](https://github.com/Plonky3/Plonky3-recursion), dual-licensed under MIT and Apache 2.0.

The [executable BabyBear example](src/lib.rs) shows statement export, preparation,
proving, and trusted verification together.
