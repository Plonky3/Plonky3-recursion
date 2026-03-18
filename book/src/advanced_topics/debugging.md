# Debugging

The `CircuitBuilder` provides built-in debugging tools to help identify wiring issues and unsatisfied constraints.

## Compile features

The workspace exposes several opt-in compile features that activate extra instrumentation. They are disabled by default to keep production binaries lean.

| Crate | Feature | What it enables |
|-------|---------|-----------------|
| `p3-circuit` | `debugging` | Allocation logging: every witness slot records the operation type, optional label, and call-site scope that allocated it. Exposes `AllocationLog`, `AllocationEntry`, and `AllocationType` in the public API. |
| `p3-circuit` | `profiling` | Operation-count profiling (implies `debugging`): the builder tracks how many `add`, `mul`, `const`, `public`, `horner_acc`, `bool_check`, `mul_add`, and per-NPO-type operations were allocated, both globally and per named scope. Exposes `OpCounts` and `ProfilingState`. |
| `p3-circuit-prover` | `parallel` | Enables multi-threaded trace generation via Rayon (`p3-maybe-rayon/parallel`). Strongly recommended for benchmarking and production workloads. |

Enable a feature by passing `--features <feature>` (or `--features parallel` for the prover sub-crate) to Cargo:

```bash
# Enable allocation logging
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
Logs can be dumped to `stdout` when calling `builder.dump_allocation_log()`, if logging level is set to `DEBUG` or lower.

### Allocation Log Format

By default, the `CircuitBuilder` automatically logs all allocations with no specific labels.
One can decide to attach a specific descriptive to ease debugging, like so:

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

The `CircuitBuilder` also allows for nested scoping of allocation logs, so that users can debug
a specific context within a larger circuit. Scoping can be defined arbitrarily by users as follows:


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

## Debugging constraints

When debugging constraint satisfaction issues, the system relies on Plonky3's internal `check_constraints`
feature to evaluate AIR constraints, available in debug mode.
This ensures that all constraints are properly satisfied before proceeding to the next proving phases.
