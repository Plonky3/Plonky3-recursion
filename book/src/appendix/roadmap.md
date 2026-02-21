# Roadmap

This page tracks planned improvements and known optimization opportunities.

## Soundness

- **ZK mode**: Support zero-knowledge STARKs (trace randomization). Currently only non-ZK mode is supported.

## Performance

- **Eliminate decompose/recompose round-trips**: Base field values are currently lifted to extension field targets and then repacked before MMCS verification, which decomposes them again. Keeping values in base coefficient form throughout would eliminate ~15-20% of circuit operations.
- **Dedicated FRI AIR table**: A specialized non-primitive chip for Lagrange interpolation during FRI folding would offload ~30K primitive operations to a compact AIR.
- **Remove the Witness bus**: Since the verifier program is fixed and deterministic, the global Witness table can be replaced with direct inter-chip lookups, eliminating an entire table.
- **Additional optimization passes**: More aggressive dead-node pruning, common subexpression elimination, and chain fusion in the circuit optimizer.

## Flexibility

- **Configurable WIDTH/RATE**: Currently fixed at `WIDTH=16`, `RATE=8` for 32-bit fields. Making these configurable would support wider permutations and different security/performance trade-offs.
- **Goldilocks support**: Full testing and optimization for the 64-bit Goldilocks field.
- **Multi-shape FRI verification**: A single verifier circuit that can handle proofs with different trace sizes, reducing the need for proof lifting.
