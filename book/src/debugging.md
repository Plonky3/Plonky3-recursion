# Debugging

The `CircuitBuilder` provides built-in debugging tools to help identify wiring issues and unsatisfied constraints.

## Allocation Logging

The `CircuitBuilder` supports an allocation logger during circuit building that logs allocations being performed.
These logs can then be analyzed at runtime and leveraged to detect issues in circuit constructions.

### Enabling Debug Logging

Allocation logging is automatically enabled in debug builds (or moe generally if `debug_assertions` are enabled).
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
let x = builder.add_public_input(); // unlabelled
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
