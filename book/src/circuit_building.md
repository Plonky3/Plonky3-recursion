# Building Circuits

This section explains how the `CircuitBuilder` allows to build a concrete `Circuit` for a given program.
We’ll use a simple Fibonacci example throughout this page to ground the ideas behind circuit building:

```rust
let mut builder = CircuitBuilder::<F>::new();

// Public input: expected F(n)
let expected_result = builder.add_public_input();

// Compute F(n) iteratively
let mut a = builder.add_const(F::ZERO); // F(0)
let mut b = builder.add_const(F::ONE);  // F(1)

for _i in 2..=n {
    let next = builder.add(a, b); // F(N) <- F(N-1) + F(N-2)
    a = b;
    b = next;
}

// Assert computed F(n) equals expected result
builder.connect(b, expected_result);

let circuit = builder.build()?;
let mut runner = circuit.runner();
```


## Building Pipeline

In what follows, we call `WitnessId` what serves as identifier for values in the global Witness storage bus, and
`ExprId` position identifiers in the `ExpressionGraph` (with the hardcoded constant `ZERO` always stored at position 0).

Building a circuit works in 4 successive steps:

### Stage 1 — Lower to primitives

This stage will go through the `ExpressionGraph` in successive passes and emit primitive operations.

  - when going through emitted `Const` nodes, the builder ensures no identical constants appear in distinct nodes of the circuit, seen as a DAG (Directed Acyclic Graph), by performing witness aliasing, i.e. looking at node equivalence classes. This allows to prune duplicated `Const` nodes by replacing further references with the single equivalence class representative that will be part of the DAG. This allows to enforce equality constraints are **structurally**, without requiring extra gates.

  - public inputs and arithmetic operations may also reuse pre-allocated slots if connected to some existing node.

### Stage 2 — Lower non-primitives

This stage translates the `ExprId` of logged non-primitive operations inputs (from the set of non-primitive operations allowed at runtime) to `WitnessId`s similarly to Stage 1.

### Stage 3 — Optimize primitives

This stage aims at optimizing the generated circuit by removing or optimizing redundant operations within the graph.
For instance, if the output of a primitive operation is never used elsewhere in the circuit, its associated node can
be pruned away from the graph, and the operation removed.

Once all the nodes have been assigned, and the circuit has been fully optimized, we output it.

## Proving

Calling `circuit.runner()` will return a instance of `CircuitRunner` allowing to execute the
represented program and generate associated execution traces needed for proving:

```rust
let mut runner = circuit.runner();

// Set public input
let expected_fib = compute_fibonacci_classical(n);
runner.set_public_inputs(&[expected_fib])?;

// Instantiate prover instance
let config = build_standard_config_koalabear();
let multi_prover = MultiTableProver::new(config).with_table_packing(table_packing);

// Generate traces
let traces = runner.run()?;

// Prove the program
let proof = multi_prover.prove_all_tables(&traces)?;
```

## Key takeaways

* **“Free” equality constraints:** by leveraging **witness aliasing**, we obtain essentially free equality constraints for the prover, removing the need for additional arithmetic constraints.

* **Deterministic layout:** The ordered primitive lowering combined with equivalence class allocation yields predictable `WitnessId`s.

* **Minimal primitive set:** With `Sub`/`Div` being effectively translated as equivalent `Add`/`Mul` operations, the IR stays extremely lean, consisting only of `Const`, `Public`, `Add` and `Mul`, simplifying the design and implementation details.
