# Recursion Approach and Construction

## High-level architecture

Recursion in zero-knowledge proofs means using one proof to verify another: an (outer) prover will generate a proof 
to assert validity of an (inner) STARK proof. By applying this recursively, one obtains a (possibly compact) outer proof that attests to arbitrarily deep chains of computation.

Our approach to recursion for Plonky3 differs from a traditional zkVM approach: there is **no program counter, instruction set, or branching logic**. Instead, a fixed program is chosen, and the verifier circuit is specialized to this program only.

## Why fixing the program shape?

- **Performance**: without program counter logic, branching, or instruction decoding,
  the verifier’s constraints are much lighter.

- **Recursion efficiency**: since the shape of the trace is predetermined,
  the recursion circuit can be aggressively optimized.

- **Simplicity**: all inputs follow the same structural pattern, which keeps
  implementation complexity low.

By fixing the program to execute, in particular here proving the correct verification of some *known* AIR(s) program(s), prover and verifier can agree on the integral execution flow of the program.
As such, each step corresponds to an instruction **known at compile-time** with operands either known at compile-time in the case of constants, or defined by the prover at runtime. This removes all the
overhead of handling arbitrary control flow, and makes the resulting AIR(s) statement(s) effectively tailored for the program they represent, as opposed to regular VMs.

## Limitations

- **Rigidity**: only the supported program(s) can be proven.

- **No variable-length traces**: input size must fit the circuit’s predefined structure.

- **Reusability**: adapting to a new program requires a new circuit.

The rest of this book explains how this approach is built, [how to soften its rigidity](extensions.md#strategies),
and why it provides a powerful foundation for recursive proof systems.

## Execution IR

An **Execution IR** (intermediate representation) is defined to describe the steps of the verifier.
This IR is *not itself proved*, but will be used as source of truth between prover and verifier to guide trace population.
The actual soundness comes from the constraints inside the operation-specific STARK chips along with an aggregated lookup argument ensuring consistency of the common values they operate on.
The lookups can be seen as representing the `READ`/`WRITE` operations from/to the witness table.

The example below represents the (fixed) IR associated to the statement `37.x - 111 = 0`, where `x` is a public input. It can be reproduced by running

```bash
cargo test --package p3-circuit --lib -- tables::tests::test_toy_example_37_times_x_minus_111 --exact --show-output
```

A given row of the represented IR contains an operation and its associated operands. 

```bash
=== CIRCUIT PRIMITIVE OPERATIONS ===
0: Const { out: WitnessId(0), val: 0 }
1: Const { out: WitnessId(1), val: 37 }
2: Const { out: WitnessId(2), val: 111 }
3: Public { out: WitnessId(3), public_pos: 0 }
4: Mul { a: WitnessId(1), b: WitnessId(3), out: WitnessId(4) }
5: Add { a: WitnessId(2), b: WitnessId(0), out: WitnessId(4) }
```

i.e. operation 4 performs `w[4] <- w[1] * w[3]`, and operation 5 encodes the subtraction check as an addition `w[2] + w[0] = w[4]` (verifying `37 * x - 111 = 0`).


## Witness Table

The `Witness` table can be seen as a central memory bus that stores values shared across all operations. It is represented as pairs `(index, value)`, where indices are  that will be accessed by 
the different chips via lookups to enforce consistency.

- The index column is *preprocessed*, or *preprocessed* [@@rap]: it is known to both prover and verifier in advance, requiring no online commitment.[^1]
- The Witness table values are represented as extension field elements directly (where base field elements are padded with 0 on higher coordinates) for addressing efficiency.

From the fixed IR of the example above, we can deduce an associated `Witness` table as follows:

```bash
=== WITNESS TRACE ===
Row 0: WitnessId(w0) = 0
Row 1: WitnessId(w1) = 37
Row 2: WitnessId(w2) = 111
Row 3: WitnessId(w3) = 3
Row 4: WitnessId(w4) = 111
```

Note that the initial version of the recursion machine, for the sake of simplicity and ease of iteration, contains a `Witness` table. However, because the verifier effectively knows the order of
each operation and the interaction between them, the `Witness` table can be entirely removed, and global consistency can still be enforced at the cost of additional (smaller) lookups between the different chips.


## Operation-specific STARK Chips

Each operation family (e.g. addition, multiplication, Merkle path verification, FRI folding) has its own chip.

A chip contains:

- Local columns for its variables.
- Lookup ports into the witness table.
- An AIR that enforces its semantics.

We distinguish two kind of chips: those representing native, i.e. primitive operations, and additional non-primitive ones, defined at runtime, that serve as precompiles to optimize certain operations.
The recursion machine contains 4 primitive chips: `CONST` / `PUBLIC_INPUT` / `ADD` and `MUL`, with `SUB` and `DIV` being emulated via the `ADD` and `MUL` chips. This library aims at providing a certain
number of non-primary chips so that projects can natively inherit from full recursive verifiers, which implies chips for FRI, Merkle paths verification, etc. Specific applications can also build their own
non-primitive chips and plug them at runtime.

Going back to the previous example, prover and verifier can agree on the following logic for each chip:

```bash
=== CONST TRACE ===
Row 0: WitnessId(w0) = 0
Row 1: WitnessId(w1) = 37
Row 2: WitnessId(w2) = 111

=== PUBLIC TRACE ===
Row 0: WitnessId(w3) = 3

=== MUL TRACE ===
Row 0: WitnessId(w1) * WitnessId(w3) -> WitnessId(w4) | 37 * 3 -> 111

=== ADD TRACE ===
Row 0: WitnessId(w2) + WitnessId(w0) -> WitnessId(w4) | 111 + 0 -> 111
```

Note that because we started from a known, fixed program that has been lowered to a deterministic IR, we can have the `CONST` chip's table entirely preprocessed
(i.e. known to the verifier), as well as all `index` columns of the other primitive chips.



## Lookups

All chips interactions are performed via a lookup argument. Enforcing multiset equality between all chip ports and the `Witness` table entries ensures correctness without proving the execution order of the entire IR itself. Lookups can be seen as `READ`/`WRITE` or `RECEIVE`/`SEND` interactions between tables which allow global consistency over local AIRs.

Cross-table lookups (CTLs) ensure that **every** chip interaction happens through the Witness table: producers write a `(index, value)` pair into Witness and consumers read the same pair back. No chip talks directly to any other chip; the aggregated LogUp argument enforces multiset equality between the writes and reads.

For the toy example the CTL relations are:

```bash
(index 0, value 0)   : CONST → Witness ← ADD
(index 1, value 37)  : CONST → Witness ← MUL
(index 2, value 111) : CONST → Witness ← ADD
(index 3, value 3)   : PUBLIC → Witness ← MUL
(index 4, value 111) : MUL → Witness ← ADD (duplicate writes enforce equality)
```


[^1]: Preprocessed columns / polynomials can be reconstructed manually by the verifier, removing the need for a prover to commit to them and later perform the FRI protocol on them. However, the verifier needs $O(n)$ work when these columns are not structured, as it still needs to interpolate them. To alleviate this, the Plonky3 recursion stack performs *offline* commitment of unstructured preprocessed columns, so that we need only one instance of the FRI protocol to verify all preprocessed columns evaluations. 

[^2]: The `ADD` and `MUL` tables both issue CTL writes of their outputs to the same Witness row. Because the Witness table is a *read-only* / *write-once* memory bus, the aggregated lookup forces those duplicate writes `w4 = 111` to agree, which is exactly the constraint `37 * 3 = 111 = 0 + 111`.
