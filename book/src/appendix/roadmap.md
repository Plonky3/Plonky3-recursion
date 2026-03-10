# Roadmap

This page tracks planned improvements and known optimization opportunities.

## Performance

- **Additional optimization passes**: More aggressive dead-node pruning, common subexpression elimination, and chain fusion in the circuit optimizer.

## Flexibility

- **Configurable WIDTH/RATE**: Currently fixed at `WIDTH=16`, `RATE=8` for 32-bit fields, `WIDTH=8`, `RATE=4` for Goldilocks.
Making these configurable would support wider permutations and different security/performance trade-offs.
- **Multi-shape FRI verification**: A single verifier circuit that can handle proofs with different trace sizes, reducing the need for proof lifting.
