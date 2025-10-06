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

## Building recursive AIR constraints

In order to recursively verify an AIR, its constraints need to be added to the circuit and folded together. In our Fibonacci example, we had to add the constraints manually, one by one. But in reality, it is possible to automatically deduce the circuit constraints from its original set of constraints by leveraging Plonky3's symbolic constraint representation.

In plonky3, the method `get_symbolic_constraints` for Airs returns a symbolic representation of constraints. Since our primitive chips (see section "Execution IR") encompass the various entries in the symbolic representation, we can map the operations to their circuit equivalent automatically. The `symbolic_to_circuit` function does exactly that. 

We can explain in more details how the automated deduction of constraints and folding work. Assume we have a circuit builder `builder`, an `ExprId` for folding challenge `alpha`, and `ExprId`s for the local row (`local`) and the next row (`next`) of a `FibonacciAir`. `FibonacciAir`'s constraints for public inputs `a`, `b` and `output` are the following:
(1) `is_first_row * (local.left - a)`
(2) `is_first_row * (local.right - b)`
(3) `is_transition * (local.right - next.left)`
(4) `is_transition * (local.left + local.right - next.right)`

Plonky3's `get_symbolic_constraints` gives us this list of constraints in the symbolic form. For instance, the first constraint is given as: `Mul{ is_first_row, Sub {local.left, Const{ a }}}`. We call `symbolic_to_circuit` on it:

- `Mul {x, y}` is turned into `builder.mul(x, y)`. Thus:
  - we call `symbolic_to_circuit` on `Sub {local.left, Const { a }}` to get `y`
  - we return `builder.mul(is_first_row, y)`
- `Sub {x, y}` is turned into `builder.sub(x, y)`. Thus:
  - we call `symbolic_to_circuit` on `Const { a }` to get `y`
  - we return `builder.sub(local.left, y)`
- `Const { a }`: we return the constant `ExprId`: `builder.add_const(a)`.

We can get the circuit constraints this way for each constraint `c`. 
Once we have the circuit version of each constraint, we can fold them together. We introduce an accumulator `acc`:
```
let mut acc = circuit.add_const(0);
```
Then, for each deduced circuit constraint `c`, we do:
```
let mul = builder.mul(acc, alpha);
acc = builder.add(mul, c);
```

Thanks to this automatic transformation of constraints into a circuit, we can easily integrate *any* AIR verification into our circuit. We implement a newly introduced `RecursiveAir` trait for all `Air<SymbolicAirBuilder<F>>`. This trait includes all the methods necessary to the AIR's recursive verification.

Let us assume, for example, that we have at hand the Plonky3-defined `FibonacciAir`. Let us also assume we have:

- a circuit builder `builder`, 
- a set of `ExprId`s for the Lagrange selectors `sels`,
- an `ExprId` for the challenge `alpha`,
- a set of `ExprId` for all the columns possibly involved in the symbolic constraints, `columns`.

Then, in order to obtain `Fibonacci`'s constraints, we simply have to create an instance `air = FibonacciAir` and call:
```
let folded_constraints = air.eval_folded_circuit(builder, sels, alpha, columns);
```
to fold all the `air`'s constraints in the circuit using the challenge `alpha`.

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
