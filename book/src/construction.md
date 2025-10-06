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

## Limitations

- **Rigidity**: only the supported program(s) can be proven.

- **No variable-length traces**: input size must fit the circuit’s predefined structure.

- **Reusability**: adapting to a new program requires a new circuit.

The rest of this book explains how this approach is built, [how to soften its rigidity](extensions.md#strategies),
and why it provides a powerful foundation for recursive proof systems.

## Execution IR

An **Execution IR** (intermediate representation) is defined to describe the steps of the verifier.
This IR is *not proved itself*; it only guides trace population.
The actual soundness comes from the constraints inside the operation-specific STARK chips along with their lookups into the central `Witness` table.

In the IR, we differentiate between *primitive* and *nonprimitive operations*. 

Primitive operations represent the core of the verification computation, and will always be available when building a recursive verifier, regardless of the sub-protocols and parameterization:

- `Constant` -- for constants,
- `Public` -- for public inputs,
- `Add` -- for both addition and subtraction,
- `Mul` -- for both multiplication and division. 

Given only the primitive operations, one should be able to carry out most operations necessary in circuit verification. Primitive operations have the following properties:

- They operate on elements of the `Witness` table, through their `WitnessId` (index within the `Witness` table).
- The representation can be heavily optimized. For example, every time a constant is added to the IR, we either create a new `WitnessId` or return an already existing one. We could also carry out common subexpression elimination.
- They are executed in topological order during the circuit evaluation, and
- they form a directed acyclic graph of dependencies.

But relying only on primitive operations for the entire verification would lead to the introduction of many temporary values in the IR. In turn, this would lead to enlarged `Witness` and primitive tables. To reduce the overall surface area of our AIRs, we can introduce *nonprimitive* specialized chips that carry out specific (nonprimitive) operations. We can offload repeated computations to these nonprimitive chips to optimize the overall proving flow.

These nonprimitive operations use not only `Witness` table elements (including public inputs), but may also require the use of *private data*. For example, when verifying a Merkle path, hash outputs are not stored in the `Witness` table. 

In order to generate the IR, the first step is to create all operations symbolically.

In the symbolic executor, the computation is represented as a graph where nodes are called either `ExprId` (since they represent the index of an expression) or `Target` in the code. Each `Target` (expression) can be:

- a constant, 
- a public input, 
- the output of a primitive operation. 

Nonprimitive operations can use `Target`s, but they do not introduce new ones. 

We then need to lower these `Target`s to the IR, thus allocating actual slots in the `Witness` table. Slot allocation cannot be carried out beforehand, as some `Target`s are connected through expressions and should therefore share the same slot in the `Witness` table.

The computation graph that represents all primitive and nonprimitive operations in the IR is called `circuit`. 

A `circuit_builder` provides convenient helper functions and macros for representing and defining operations within this graph. See section "Building Circuits" for more details on how to build a circuit.

## Witness Table

The `Witness` table is a central bus that stores values shared across operations. It gathers the pairs `(index, value)` that will be accessed by 
the different chips via lookups to enforce consistency.

- The index column is *preprocessed* [@@rap]: it is known to both prover and verifier in advance, requiring no online commitment.[^1]
- The `Witness` table values are represented as extension field elements directly (where base field elements are padded with 0 on higher coordinates) for addressing efficiency.


## Operation-specific STARK Chips

Each operation family (e.g. addition, multiplication, Merkle path verification, FRI folding) has its own chip.

A chip contains:

- Local columns for its variables.
- Lookup ports into the `Witness` table.
- An AIR that enforces its semantics.

## Lookups

All chips interactions are performed via a lookup argument against the central `Witness` table. Enforcing multiset equality between chip ports and the `Witness` table entries ensures correctness without proving the execution order of the entire IR itself.

Below is a representation of the interactions between the main `Witness` table and the different chips.

```mermaid
%%{init: {'theme':'dark',"flowchart":{"htmlLabels":true}}}%%
flowchart TB
    subgraph P[PI Chip]
      P1["• Purpose: bind index=0 to the declared public input x."]
      P2["• Lookup: (0, x) must appear in Witness; also exposed as a public value."]
    end

    subgraph C[CONST Chip]
      C1["• Preprocessed rows: (1, 37), (3, 111), (4, 0)"]
      C2["• Lookup: preprocessed pairs must be present in Witness (aggregated lookup)."]
    end

    subgraph W[Witness Table]
      W0["0: 3 // &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;public input x"]
      W1["1: 37 &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;// constant"]
      W2["2: 111 &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;// p = 37 * x"]
      W3["3: 111 &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;// constant"]
      W4["4: 0 // const (y = p - 111)"]
    end

    subgraph M[MUL chip]
      M1["• Ports: (0, x), (1, 37) → inputs; (2, p) → output."]
      M2["• AIR: x * 37 = p."]
    end

    subgraph S [ SUB Chip ]
      S1["• Ports: (2, p), (3, 111) → inputs; (4, y) → output."]
      S2["• AIR: p - 111 = y."]
    end

    W --- P
    W --- C
    W --- M
    W --- S
```


[^1]: Preprocessed columns / polynomials can be reconstructed manually by the verifier, removing the need for a prover to commit to them and later perform the FRI protocol on them. However, the verifier needs $O(n)$ work when these columns are not structured, as it still needs to interpolate them. To alleviate this, the Plonky3 recursion stack performs *offline* commitment of unstructured preprocessed columns, so that we need only one instance of the FRI protocol to verify all preprocessed columns evaluations. 