# Debugging

The `CircuitBuilder` provides debugging tools to identify wiring and runner execution errors.

## Compile features

The workspace exposes several opt-in compile features that activate extra instrumentation. They are disabled by default to keep production binaries lean.

| Crate | Feature | What it enables |
|-------|---------|-----------------|
| `p3-circuit` | `debugging` | Expression allocation logging and compiled-circuit provenance. Exposes `AllocationLog`, `AllocationEntry`, `AllocationType`, `CircuitProvenance`, and owned `CircuitDiagnostic` reports for runner errors. |
| `p3-circuit` | `profiling` | Operation-count profiling (implies `debugging`): the builder tracks how many `add`, `mul`, `const`, `public`, `horner_acc`, `bool_check`, `mul_add`, and per-NPO-type operations were allocated, both globally and per named scope. Exposes `OpCounts` and `ProfilingState`. |
| `p3-circuit-prover` | `parallel` | Enables multi-threaded trace generation via Rayon (`p3-maybe-rayon/parallel`). Strongly recommended for benchmarking and production workloads. |

Enable a feature by passing `--features <feature>` (or `--features parallel` for the prover sub-crate) to Cargo:

```bash
# Enable allocation logging and circuit diagnostics
cargo test -p p3-circuit --features debugging

# Enable profiling (includes debugging)
cargo test -p p3-circuit --features profiling

# Enable parallel trace generation
cargo run --example recursive_fibonacci --features parallel
```

## Build profiles

Two custom workspace profiles complement the features above:

| Profile | Inherits | Extra flags | Purpose |
|---------|----------|-------------|---------|
| `profiling` | `release` | `debug = true` | Keeps DWARF symbols in an otherwise-optimised binary so that tools like `perf`, Instruments, or `samply` can map samples back to source lines. Use this together with the `profiling` crate feature. |
| `optimized` | `release` | `lto = "thin"`, `codegen-units = 1`, `opt-level = 3` | Maximum-performance binary. All benchmarks and the provided examples are run under this profile. |

```bash
# Profile-guided performance measurement (symbols + optimisation)
cargo run --profile profiling --example recursive_fibonacci --features parallel

# Maximum-performance binary (examples, benchmarks)
cargo run --profile optimized --example recursive_fibonacci --features parallel
```

## Allocation Logging

The `CircuitBuilder` supports an allocation logger during circuit building that logs allocations being performed.
These logs can then be analyzed at runtime and leveraged to detect issues in circuit constructions.

> **Requirement**: allocation logging requires the `debugging` compile feature to be enabled on `p3-circuit`.

### Enabling Debug Logging

Allocation logging is active whenever the `debugging` feature is compiled in.
`builder.dump_allocation_log()` emits tracing events. Install a tracing subscriber that accepts
`DEBUG` events to see them; the chosen subscriber controls where they are written.

### Allocation Log Format

By default, the `CircuitBuilder` automatically logs all allocations with no specific labels.
You can attach descriptive labels to make failures easier to locate:

```rust,ignore
let mut builder = CircuitBuilder::<F>::new();

// Allocating with custom labels
let input_a = builder.alloc_public_input("input_a");
let input_b = builder.alloc_public_input("input_b");
let input_c = builder.alloc_public_input("input_c");

let b_times_c = builder.alloc_mul(input_b, input_c, "b_times_c");
let a_plus_bc = builder.alloc_add(input_a, b_times_c, "a_plus_bc");
let a_minus_bc = builder.alloc_sub(input_a, b_times_c, "a_minus_bc");

// Default allocation
let x = builder.public_input(); // unlabelled
let y = builder.add(x, z);          // unlabelled
```

The `CircuitBuilder` also allows nested scopes. Each allocation records the **innermost** active
scope name, not a full path through all parent scopes:

```rust,ignore
fn complex_function(builder: &mut CircuitBuilder) {
    builder.push_scope("complex function");

    // Do something
    inner_function(builder); // <- this will create a nested scope within the inner function

    builder.pop_scope();
}

fn inner_function(builder: &mut CircuitBuilder) {
    builder.push_scope("inner function");

    // Do something else

    builder.pop_scope();
}
```

An allocation records its source `ExprId`, type, label, scope, and direct dependency groups in
operand order. Private inputs have `AllocationType::PrivateInput`; code that exhaustively matches
the debugging-only `AllocationType` enum must handle this variant. The zero expression is
preallocated without an allocation record. Constant pooling, arithmetic simplification, and
expression-level common-subexpression reuse may return an existing `ExprId`; in that case its
first allocation's label and scope remain the recorded ones.

## Diagnosing runner errors

`debugging` also retains immutable source information on a circuit built by `CircuitBuilder`.
Call `run_with_diagnostics()` to receive an owned `CircuitDiagnostic` when the runner returns an
error. It works without a tracing subscriber and can outlive the runner and circuit:

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
println!("{diagnostic}"); // Includes the input's label and scope.
for source in diagnostic.operation_origins() {
    if let Some(allocation) = &source.allocation {
        println!("source {}: {}", source.expr_id, allocation.label);
    }
}
let original_error: CircuitError = diagnostic.into_error();
```

The underlying `CircuitError` stays available through `error()`, `into_error()`, and the standard
error `source()` method. Existing `run()` and input setters still return `CircuitError` directly.
For an error from a setter, use `circuit.diagnose_error(error)`; this reports the caller phase and
only context that can be established from the error. It cannot infer which operation would later
execute. For example:

```rust,ignore
let mut runner = circuit.runner();
let error = runner.set_public_inputs(&[]).unwrap_err();
let diagnostic = circuit.diagnose_error(error);
println!("{diagnostic}");
```

The reported **compiled operation index** is a zero-based position in `Circuit::ops`. It is
different from both the original builder `ExprId` and a `NonPrimitiveOpId`. An operation's source
list may contain more than one expression: exact duplicate operations merge during optimization,
and an actual multiply-add fusion retains the source multiply and add. Subtraction and division
can lower to backward arithmetic operations; a division error may therefore identify a compiled
multiply while showing the original labeled `Div` expression and its numerator/denominator
dependencies. A non-primitive or hint call can be the source even when it has no output witness.

Witness aliases are related but distinct from the source of the failing operation. Several
expressions connected to one canonical witness can be listed as aliases. The diagnostic keeps
the failing operation's origins in `operation_origins()` separate from an implicated witness's
`witness_aliases()`. Each `DiagnosticSource` has an `expr_id`, an optional `allocation`, and
`dependencies` grouped in the original operand order. These dependencies are one level deep;
the report does not walk the whole expression graph. `phase()` and `compiled_operation()` provide
the failure stage and actual compiled operation when known. `Circuit::provenance()` exposes the
builder-produced snapshot through `allocation(expr_id)`,
`operation_origins(compiled_op_index)`, and `witness_origins(canonical_witness_id)`. Missing
individual records remain missing; the API does not invent labels or scopes.

`CircuitDiagnostic` formats at most eight items per repeated section, marking skipped items with
`… (+N more)`. Its whole `Display`, including the original error text, is capped at 4,096 Unicode
characters followed by `… (+N characters omitted)` if truncated. Its structured accessors and
`error()` retain the complete recorded data. A circuit created directly with `Circuit::new` has
no builder provenance; its diagnostic can still report the typed error and available compiled
operation context. Provenance describes the compiled snapshot: changing the public `Circuit::ops`
or expression-to-witness mapping after build can invalidate source-to-operation correspondence.
A same-length mutation cannot be detected automatically. Debug metadata is kept outside compiled
operations, preprocessed data, trace values, and proof/artifact identity. Diagnostics do not
collect source file locations or stack traces.

## Debugging constraints

Diagnostics enrich errors actually returned by the circuit runner; they do not add new runtime
constraint checks. In particular, the runner's `BoolCheck` execution does not universally reject
a non-boolean witness value. A successful trace run does not establish that every AIR constraint
is satisfied. Plonky3's `check_constraints` feature can help check AIR constraints during proving
in debug builds.
