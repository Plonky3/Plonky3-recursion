# Handling arbitrary programs

The fixed recursive verifier described in this book supports only fixed, predetermined programs.  
This design choice maximizes performance but raises the question: **how can one prove statements of varying size or complexity?**

We highlight below two distinct approaches to alleviate this limitation and allow for arbitrary recursion

## Tree-style recursion for variable-length inputs

One can split a large computation into chunks and prove each piece using a fixed inner circuit in parallel.
These proofs can then be *recursively aggregated* in a tree structure, where each leaf of the tree corresponds to a prover portion of the computation. The tree root yields a single proof attesting to the validity of the entire computation.

A formal description of this tree-style recursion for STARKs can be seen in [zkTree](https://eprint.iacr.org/2023/208).

## Flexible FRI verification

To support proofs with different FRI shapes, one can:

* **Lift the proofs** to a larger domain, as described in [Lifting plonky3](https://hackmd.io/HkfET6x1Qh-yNvm4fKc7zA).  
  Lifting allows a fixed circuit to efficiently verify proofs of varying trace sizes
  by projecting smaller domains into larger ones, reusing the original LDE and commitments without recomputation.

* **Verify distinct proof shapes together** inside a fixed FRI verifier circuit. Instead of having a single proof
  size that can be verified by a given FRI verifier circuit, one can extend it over a range of sizes instead at a minimal overhead cost. See a related implementation in `plonky2` recursion: ([Plonky2 PR #1635](https://github.com/0xPolygonZero/plonky2/pull/1635)) for more details.
