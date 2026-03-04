# Glossary

**AIR** — Algebraic Intermediate Representation. A set of polynomial constraints that define the validity of an execution trace. Each row of the trace must satisfy the AIR's constraints.

**ALU** — Arithmetic Logic Unit. In this library, the primitive chip that handles `add`, `mul`, `sub`, `div`, `bool_check`, and `mul_add` operations via selector columns.

**CTL** — Cross-Table Lookup. A mechanism to enforce consistency between different AIR tables by proving that multisets of tuples match across tables. Uses the LogUp argument.

**D** — Extension field degree. The recursion stack uses degree-4 extensions (`D = 4`), meaning each extension field element is represented by 4 base field elements.

**FRI** — Fast Reed-Solomon Interactive Oracle Proof. The polynomial commitment scheme used by Plonky3. Proves that a committed function is close to a low-degree polynomial via iterative folding and random queries.

**IR** — Intermediate Representation. The deterministic sequence of operations (constants, public inputs, arithmetic, non-primitives) that defines a circuit's computation.

**LDE** — Low-Degree Extension. Evaluating a polynomial on a domain larger than its degree, used to create redundancy for FRI queries. The blowup factor controls the domain expansion ratio.

**LogUp** — Logarithmic derivative lookup argument. The specific lookup protocol used to enforce CTL relations between tables. Based on [Ulrich Haböck's construction](https://eprint.iacr.org/2022/1530).

**MMCS** — Mixed Matrix Commitment Scheme. Plonky3's abstraction for committing to matrices of field elements. Typically instantiated with Merkle trees over Poseidon2 hashes.

**PCS** — Polynomial Commitment Scheme. A cryptographic primitive that allows committing to a polynomial and later proving evaluations at chosen points. FRI is the PCS used here.

**Poseidon2** — An algebraic hash function optimized for arithmetic circuits. Used for Merkle tree hashing and Fiat-Shamir challenges. Parameterized by WIDTH (number of state elements) and RATE (elements absorbed per permutation).

**RAP** — Randomized AIR with Preprocessing. An extension of AIR that supports preprocessed columns (known to the verifier before the proof) and randomized columns (computed after an initial commitment round).

**STARK** — Scalable Transparent Argument of Knowledge. A proof system based on polynomial IOPs and hash functions (no trusted setup). Plonky3 implements uni-STARKs (single AIR) and batch-STARKs (multiple AIRs with shared FRI).

**Target** — An identifier for a value in the circuit's expression graph. Each `Target` (also called `ExprId`) refers to either a constant, a public input, or the output of an operation.

**WitnessId** — An index into the global Witness table. After circuit compilation, each `Target` is assigned a `WitnessId` that identifies its slot in the witness memory bus.
