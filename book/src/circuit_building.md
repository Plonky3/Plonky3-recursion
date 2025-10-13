# Building Circuits

This section explains how the `CircuitBuilder` allows to build a concrete `Circuit` for a given program.
We’ll use a simple Fibonacci example throughout this page to ground the ideas behind circuit building:

```rust,ignore
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

## Building recursive AIR constraints

In order to recursively verify an AIR, its constraints need to be added to the circuit and folded together. In Plonky3, we can get an AIR's constraints in symbolic form. Since our primitive chips (see section [Execution IR](./construction.md#execution-ir)) encompass the various entries in the symbolic representation, we can simply map each symbolic operation to its circuit counterpart. The `symbolic_to_circuit` function does exactly that for a given symbolic constraint. 

We can consider a small example to show how operations are mapped. Given public inputs `a` and `b`, and a constant `c`, we have the following symbolic constraint: `Mul{ a, Sub {b, Const{ c }}}` (which corresponds to: `a * (b - c)`).

```rust,ignore
// We get the `ExprId` corresponding to Const{ c } by adding a constant to the circuit.
let x = builder.add_const(c);
// We use the previously computed `x` to compute the subtraction in the circuit.
let y = builder.sub(b, x);
// We use the previously computed `y` to compute the multiplication in the circuit.
let z = builder.mul(a, y);
```
`z` is then the output `ExprId` of the constraint in the circuit.

Using this function, we have implemented, for all AIRs, the automatic translation from their set of symbolic constraints to the circuit version of the folded constraints:

```rust,ignore
// Transforms an AIR's symbolic constraints into its counterpart circuit version, 
// and folds all the constraints in the circuit using the challenge `alpha`.
fn eval_folded_circuit(
        // The AIR at hand.
        &self,
        builder: &mut CircuitBuilder<F>,
        // Circuit version of Langrange selectors.
        sels: &RecursiveLagrangeSelectors,
        // Folding challenge.
        alpha: &ExprId,
        // All kind of columns that could be involved in constraints.
        columns: ColumnsTargets,
    ) -> Target {
        // Get all the constraints in symbolic form.
        let symbolic_constraints = 
            get_symbolic_constraints(self, 0, columns.public_values.len());

        // Fold all the constraints using the folding challenge.
        let mut acc = builder.add_const(F::ZERO);
        for s_c in symbolic_constraints {
            let mul_prev = builder.mul(acc, *alpha);

            // Get the current constraint in circuit form.
            let constraints = 
                symbolic_to_circuit(sels.row_selectors, &columns, &s_c, builder);

            // Fold the current constraint with the previous value.
            acc = builder.add(mul_prev, constraints);
        }

        acc
    }
```

This facilitates the integration of *any* AIR verification into our circuit. 

## Proving

Calling `circuit.runner()` will return a instance of `CircuitRunner` allowing to execute the
represented program and generate associated execution traces needed for proving:

```rust,ignore
let mut runner = circuit.runner();

// Set public input
let expected_fib = compute_fibonacci_classical(n);
runner.set_public_inputs(&[expected_fib])?;

// Instantiate prover instance
let config = build_standard_config_koalabear();
let multi_prover = MultiTableProver::new(config);

// Generate traces
let traces = runner.run()?;

// Prove the program
let proof = multi_prover.prove_all_tables(&traces)?;
```

## Key takeaways

* **“Free” equality constraints:** by leveraging **witness aliasing**, we obtain essentially free equality constraints for the prover, removing the need for additional arithmetic constraints.

* **Deterministic layout:** The ordered primitive lowering combined with equivalence class allocation yields predictable `WitnessId`s.

* **Minimal primitive set:** With `Sub`/`Div` being effectively translated as equivalent `Add`/`Mul` operations, the IR stays extremely lean, consisting only of `Const`, `Public`, `Add` and `Mul`, simplifying the design and implementation details.
