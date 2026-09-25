# Roadmap

This page tracks planned improvements and known optimization opportunities.

## Performance

- **Additional optimization passes**: More aggressive dead-node pruning, common subexpression elimination, and chain fusion in the circuit optimizer.

## Flexibility

- **Configurable WIDTH/RATE**: Currently fixed at `WIDTH=16`, `RATE=8` for 32-bit fields, `WIDTH=8`, `RATE=4` for Goldilocks.
Making these configurable would support wider permutations and different security/performance trade-offs.
- **Multi-shape FRI verification**: A single verifier circuit that can handle proofs with different trace sizes, reducing the need for proof lifting.
- **Binary fields**: Circuits already run over the Plonky3 binary tower, and binary hash configurations are in `p3-test-utils` (see [Binary Fields and Binary Hashes](../advanced_topics/binary_fields.md)).
In-circuit Keccak-f\[1600\], the Keccak-256 sponge, digest compression and field-element leaf hashing are available.
In-circuit BLAKE3 (one chunk) and single-matrix Keccak-256 and BLAKE3 Merkle paths are available too.
Keccak-256 and BLAKE3 MMCS batch openings (mixed heights, multi-root caps) and recursion over proofs containing these tables are available too.
The remaining steps are the BLAKE3 chunk tree, proving binary-field circuits with the binary PCS, and recursively verifying binary proofs.
