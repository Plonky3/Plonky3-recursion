# p3-circuit

An arithmetic-circuit frontend: build a circuit from public/private inputs and
operations, then run it to produce the per-table execution traces consumed by
`p3-circuit-prover`.

Key items:

- `CircuitBuilder` — the frontend for declaring inputs, operations and assertions
- `Circuit` / `PreprocessedColumns` — the built circuit and its preprocessed data
- `CircuitRunner` / `Traces` — witness generation and the resulting per-table traces
- `Op`, `AluOpKind`, `NpoTypeId` — primitive and non-primitive operation descriptors
- `Expr`, `ExprId`, `WitnessId`, `CircuitError` — value handles and typed errors

Enable `p3-circuit/debugging` to retain builder allocation labels, scopes, and
source expressions through compilation. A runner failure can then be inspected
without a tracing subscriber:

```rust,ignore
use p3_baby_bear::BabyBear;
use p3_circuit::{CircuitBuilder, CircuitError};

let mut builder = CircuitBuilder::<BabyBear>::new();
builder.push_scope("inputs");
let _amount = builder.alloc_public_input("amount");
builder.pop_scope();
let circuit = builder.build().unwrap();
let diagnostic = circuit.runner().run_with_diagnostics().unwrap_err();
assert!(matches!(diagnostic.error(), CircuitError::PublicInputNotSet { .. }));
println!("{diagnostic}");
let original: CircuitError = diagnostic.into_error();
```

`run()` still returns `CircuitError` directly. For setter errors, call
`circuit.diagnose_error(error)`; the report includes only context the error can
identify. `Circuit::provenance()` gives read-only access to the compiled source
mapping, including original `ExprId`s, source allocations, and canonical witness
aliases. The report owns its context and survives the circuit being dropped.
`Display` shows at most eight items per repeated section and caps the whole
message, including the original error text, at 4,096 Unicode characters plus
an omission suffix. Structured accessors and `error()` keep the full data.
`profiling` includes `debugging`.

See the [debugging guide](../book/src/advanced_topics/debugging.md) for source
versus compiled IDs, optimization behavior, and provenance limits. Diagnostics
describe runner errors; a successful trace run does not prove AIR constraints.

Part of [Plonky3-recursion](https://github.com/Plonky3/Plonky3-recursion), dual-licensed under MIT and Apache 2.0.
