# Roadmap

This page tracks planned improvements and known optimization opportunities.

## Soundness

- **ZK mode**: Support zero-knowledge STARKs (trace randomization). Currently only non-ZK mode is supported.

## Performance

- **Eliminate decompose/recompose round-trips**: Base field values are currently lifted to extension field targets and then repacked before MMCS verification, which decomposes them again. Keeping values in base coefficient form throughout would eliminate ~15-20% of circuit operations.
- **Dedicated FRI AIR table**: A specialized non-primitive chip for Lagrange interpolation during FRI folding would offload ~30K primitive operations to a compact AIR.
- **Additional optimization passes**: More aggressive dead-node pruning, common subexpression elimination, and chain fusion in the circuit optimizer.

## Flexibility

- **Configurable WIDTH/RATE**: Currently fixed at `WIDTH=16`, `RATE=8` for 32-bit fields, `WIDTH=8`, `RATE=4` for Goldilocks.
Making these configurable would support wider permutations and different security/performance trade-offs.
- **Multi-shape FRI verification**: A single verifier circuit that can handle proofs with different trace sizes, reducing the need for proof lifting.
