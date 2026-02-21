# Scaling Strategies

The fixed recursive verifier supports only predetermined programs. This section describes strategies for handling computations of varying size or complexity.

## Tree-style recursion for variable-length inputs

Split a large computation into chunks and prove each chunk independently using a fixed inner circuit. Then aggregate the proofs in a binary tree, where each leaf corresponds to a portion of the computation. The tree root yields a single proof attesting to the entire computation.

This approach is naturally parallelizable: all leaf proofs are independent, and each tree level can be processed in parallel across pairs.

A formal description of tree-style recursion for STARKs can be found in [zkTree](https://eprint.iacr.org/2023/208). See also the [Aggregation](./aggregation.md) chapter for the API.

## Flexible FRI verification

To support proofs with different FRI shapes (different trace sizes), two techniques apply:

### Proof lifting

**Lift** smaller proofs to a larger domain, as described in [Lifting Plonky3](https://hackmd.io/HkfET6x1Qh-yNvm4fKc7zA). Lifting projects a smaller domain into a larger one, reusing the original LDE and commitments. This lets a fixed circuit verify proofs from a range of trace sizes without recomputation.

### Multi-shape FRI verification

Instead of fixing a single proof size per verifier circuit, extend the FRI verifier to handle a **range** of sizes within the same circuit, at minimal overhead. A related approach is implemented in Plonky2 recursion ([PR #1635](https://github.com/0xPolygonZero/plonky2/pull/1635)).
