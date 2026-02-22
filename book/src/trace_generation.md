# Trace Generation Pipeline

After building a circuit, the next step is execution: running the program with concrete inputs and generating the execution traces needed for proving. This section describes the complete flow from a static `Circuit` specification to the final `Traces` structure.

## Overview

The trace generation pipeline consists of three distinct phases:

1. **Circuit compilation** — Transform high-level circuit expressions into a fixed intermediate representation.
2. **Circuit execution** — Populate the witness table by evaluating operations with concrete input values.
3. **Trace extraction** — Generate operation-specific traces from the populated witness table.

Each phase has a clear responsibility and produces well-defined outputs that feed into the next stage.

## Phase 1: Circuit Compilation

Circuit compilation happens when calling `builder.build()`. This phase translates circuit expressions into a deterministic sequence of primitive and non-primitive operations.

The compilation process is described in detail in the [Circuit Building](./circuit_building.md#building-pipeline) section. In summary, it performs three successive passes to lower expressions to primitives, handle non-primitive operations, and optimize the resulting graph.

The output is a `Circuit<F>` containing the primitive operations in topological order, non-primitive operation specifications, and witness allocation metadata. This circuit is a static, serializable specification that can be executed multiple times with different inputs.

## Phase 2: Circuit Execution

Circuit execution happens when calling `runner.run()`. This phase populates the witness table by evaluating each operation with concrete field element values.

The runner is initialized with a `Circuit<F>` and receives:
- Public input values via `runner.set_public_inputs()`
- Private data for non-primitive operations via `runner.set_private_data()`

The runner iterates through primitive operations in topological order, executing each one to populate witness slots. Operations can run in **forward mode** (computing outputs from inputs) or **backward mode** (inferring missing inputs from outputs), allowing bidirectional constraint solving.

The output is a fully populated witness table where every slot contains a concrete field element. Any unset witness triggers a `WitnessNotSet` error.

## Phase 3: Trace Extraction

Trace extraction happens internally within `runner.run()` after execution completes. This phase delegates to specialized trace builders that transform the populated witness table into operation-specific trace tables.

Each primitive operation has a dedicated builder that extracts its operations from the IR and produces trace columns:

- **WitnessTraceBuilder** — Generates the central [witness table](./construction.md#witness-table) with sequential `(index, value)` pairs
- **ConstTraceBuilder** — Extracts constants (both columns preprocessed)
- **PublicTraceBuilder** — Extracts public inputs (index preprocessed, values at runtime)
- **AddTraceBuilder** — Extracts additions with six columns: `(lhs_index, lhs_value, rhs_index, rhs_value, result_index, result_value)`
- **MulTraceBuilder** — Extracts multiplications with the same six-column structure

Non-primitive operations require custom trace builders. For example, **MmcsTraceBuilder** validates and extracts MMCS path verification traces. Custom trace builders follow the same pattern, operating independently in a single pass to produce isolated trace tables. All index columns are preprocessed since the IR is fixed and known to the verifier.

The output is a `Traces<F>` structure containing all execution traces needed by the prover to generate STARK proofs for each [operation-specific chip](./construction.md#operation-specific-stark-chips).

## Example: Fibonacci Circuit

Consider a simple Fibonacci circuit computing `F(5)`:

```rust,ignore
let mut builder = CircuitBuilder::new();

let expected = builder.public_input();
let mut a = builder.define_const(F::ZERO);
let mut b = builder.define_const(F::ONE);

for _ in 2..=5 {
    let next = builder.add(a, b);
    a = b;
    b = next;
}

builder.connect(b, expected);
let circuit = builder.build()?;
```

**Phase 1: Compilation** produces:
```text
primitive_ops: [
  Const { out: w0, val: 0 },
  Const { out: w1, val: 1 },
  Public { out: w2, public_pos: 0 },
  Add { a: w0, b: w1, out: w3 },  // F(2) = 0 + 1
  Add { a: w1, b: w3, out: w4 },  // F(3) = 1 + 1
  Add { a: w3, b: w4, out: w5 },  // F(4) = 1 + 2
  Add { a: w4, b: w5, out: w2 },  // F(5) = 2 + 3 (connects to expected)
]
witness_count: 6
```

**Phase 2: Execution** with `runner.set_public_inputs(&[F::from(5)])`:
```text
witness[0] = Some(0)
witness[1] = Some(1)
witness[2] = Some(5)
witness[3] = Some(1)
witness[4] = Some(2)
witness[5] = Some(3)
```

**Phase 3: Trace Extraction** produces:
```text
const_trace: [(w0, 0), (w1, 1)]
public_trace: [(w2, 5)]
add_trace: [
  (w0, 0, w1, 1, w3, 1),
  (w1, 1, w3, 1, w4, 2),
  (w3, 1, w4, 2, w5, 3),
  (w4, 2, w5, 3, w2, 5),
]
mul_trace: []
```

The witness table acts as the central bus, with each operation table containing [lookups](./construction.md#lookups) into it. The aggregated lookup argument enforces that all these lookups are consistent.

## Key Properties

**Determinism** — Given the same circuit and inputs, trace generation is completely deterministic, ensuring reproducible proofs.

**Separation of concerns** — Each phase has a single responsibility: compilation handles expression lowering, execution populates concrete values, and trace builders format data for proving.

**Builder pattern efficiency** — Trace builders operate in a single pass using only the data they need. No builder depends on another's output, enabling future parallelization.

**Preprocessed columns** — All index columns in operation traces are preprocessed. Since the IR is fixed, the verifier can reconstruct these columns without online commitments, significantly reducing proof size.
