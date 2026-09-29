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

With `parallel` enabled, hiding batch proofs run in a private one-worker Rayon
pool. This contains a deadlock in the pinned `p3-fri 0.8.0`, which holds its
hiding RNG lock across nested parallel FFT work. Hidden proofs therefore lose
native batch parallelism until an upstream guard-scope fix is adopted;
non-hiding proofs retain the usual parallel path. If another dependency enables
`p3-maybe-rayon/parallel` while this crate's `parallel` feature is off, hiding
proving returns an early error asking for `p3-circuit-prover/parallel`.
Custom configurations used with `parallel` must be `Sync`, and their batch
proofs must be `Send`; feature-off builds retain the original serial generic
requirements and `no_std` support.
