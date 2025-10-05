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

The example below represents the (fixed) IR associated to the statement `37.x - 111 = 0`, where `x` is a public input.
A given row of the represented IR contains an operation and its associated operands, i.e.:

- `MUL 0 1 2` corresponds to `W[2] <- W[0].W[1]`, where `W[i]` represents the value stored at index `i`
of the associated Witness table / Memory bus
- `CONST 4 0` corresponds to `W[4] <- 0`

```bash
         OP  X  Y  Z
----------------------
PUBLIC_INPUT 0
       CONST 1 37
       CONST 3 111
       CONST 4  0
        MUL  0  1  2
        SUB  2  3  4
```


## Witness Table

The `Witness` table can be seen as a central memory bus that stores values shared across all operations. It is represented as pairs `(index, value)`, where indices are  that will be accessed by 
the different chips via lookups to enforce consistency.

- The index column is *preprocessed*, or *preprocessed* [@@rap]: it is known to both prover and verifier in advance, requiring no online commitment.[^1]
- The Witness table values are represented as extension field elements directly (where base field elements are padded with 0 on higher coordinates) for addressing efficiency.

From the fixed IR of the example above, we can deduce an associated `Witness` table as follows:

```bash
IDX: VAL
  0:  3     // public input x
  1: 37     // constant
  2: 111    // p = 37 * x
  3: 111    // constant
  4:  0     // constant (y = p - 111)
```

Note that the initial version of the recursion machine, for the sake of simplicity and ease of iteration, contains a `Witness` table. However, because the verifier effectively knows the order of
each operation and the interaction between them, the `Witness` table can be entirely removed, and global consistency can still be enforced at the cost of additional (smaller) lookups between the different chips.


## Operation-specific STARK Chips

Each operation family (e.g. addition, multiplication, Merkle path verification, FRI folding) has its own chip.

A chip contains:

- Local columns for its variables.
- Lookup ports into the witness table.
- An AIR that enforces its semantics.

We distinguish two kind of chips: those representive native, i.e. primitive operations, and additional non-primitive ones, defined at runtime, that serve as precompiles to optimize certain operations.
The recursion machine contains 4 primitive chips: `CONST` / `PUBLIC_INPUT` / `ADD` and `MUL`, with `SUB` and `DIV` being emulated via the `ADD` and `MUL` chips. This library aims at providing a certain
number of non-primary chips so that projects can natively inherit from full recursive verifiers, which implies chips for FRI, Merkle paths verification, etc. Specific applications can also build their own
non-primitive chips and plug them at runtime.

Going back to the previous example, prover and verifier can agree on the following logic for each chip:

- `PublicInput` chip (`index` preprocessed)
  - **Purpose**: bind index=0 to the declared public input x.
  - **Lookup**: (0, x) must appear in the `Witness` table; also exposed as a public value.

- `CONST` chip (Fully preprocessed)
  - Preprocessed rows: `(1, 37), (3, 111), (4, 0)`
  - **Lookup**: each preprocessed pair must be present in the `Witness` table.

- `MUL` chip (`index` preprocessed)
  - **Lookup**: `(0, x)`, `(1, 37)` as inputs; `(2, p)` as output.
  - **AIR**: x * 37 = p.

- `ADD` chip (`index` preprocessed)
  - **Lookup**: `(4, y)`, `(3, 111)` as inputs; `(2, p)` as output.
  - **AIR**: y + 111 = p (corresponding to p - 111 = y)

Having the `CONST` chip entirely preprocessed (i.e. known to the verifier), as well as all `index` columns of the chips directly stems from the fact that we started
from a known, fixed program that has been lowered to an IR.


## Lookups

All chips interactions are performed via a lookup argument against the central `Witness` table. Enforcing multiset equality between chip ports and the `Witness` table entries ensures correctness without proving the execution order of the entire IR itself. Lookups can be seen as `READ`/`WRITE` or `RECEIVE`/`SEND` interactions between tables which allow global consistency over local AIRs.

Using the terms `SEND` and `RECEIVE`, we can go back to the previous example and illustrate the interactions between all the chips and the central `Witness` table[^2]:

```bash
  0:  3     // RECEIVE from PublicInput table, SEND to MUL table
  1: 37     // RECEIVE from CONST table, SEND to MUL table
  2: 111    // RECEIVE from ADD and MUL tables
  3: 111    // RECEIVE from CONST table, SEND to ADD table
  4:  0     // RECEIVE from CONST table, SEND to ADD table
```


[^1]: Preprocessed columns / polynomials can be reconstructed manually by the verifier, removing the need for a prover to commit to them and later perform the FRI protocol on them. However, the verifier needs $O(n)$ work when these columns are not structured, as it still needs to interpolate them. To alleviate this, the Plonky3 recursion stack performs *offline* commitment of unstructured preprocessed columns, so that we need only one instance of the FRI protocol to verify all preprocessed columns evaluations. 

[^2]: We can see that both `ADD` and `MUL` tables are *writing* the output of one of their operations at the *same* location of the `Witness` table.
As the latter can be seen as a *read-only* / *write-once* memory bus, having two identical lookup entries `(2, 111)` against the `Witness` table
effectively enforces equality on both outputs sharing the same witness location, which translates in our example to `37.3 = 111 = 0 + 111`