# Plonky3 Recursion

This book is the user guide for **Plonky3 recursion**, an independent project providing native recursive STARK verification for [Plonky3](https://github.com/Plonky3/Plonky3).

The library lets you verify Plonky3 STARK proofs inside circuits, chain recursive layers to compress proof size, and aggregate independent proofs into a single attestation. It is built entirely on Plonky3's own STARK primitives — no separate plonkish SNARK wrapper.

## What this book covers

- **[Getting Started](./getting_started/introduction.md)** — Motivation, design philosophy, and a quick start guide with working examples.
- **[User Guide](./user_guide/api.md)** — The unified recursion API, aggregation, configuration, public inputs, integration into your project, and the low-level API for advanced use cases.
- **[Architecture & Internals](./architecture_and_internals/construction.md)** — How the fixed recursive verifier is built: the execution IR, witness table, operation-specific chips, circuit building pipeline, trace generation, and Poseidon2-based hashing.
- **[Advanced Topics](./advanced_topics/scaling.md)** — Scaling strategies for variable-length inputs, performance tuning, soundness considerations, and debugging tools.
- **[Appendix](./appendix/benchmark.md)** — Benchmarks, roadmap, and glossary.

## Quick links

- **Source**: [github.com/Plonky3/Plonky3-recursion](https://github.com/Plonky3/Plonky3-recursion)
- **API docs**: `cargo doc --open`
- **Examples**: `recursion/examples/` — recursive Fibonacci, Keccak, and 2-to-1 aggregation
- **License**: Dual MIT / Apache-2.0
