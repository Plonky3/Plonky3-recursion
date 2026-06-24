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

Part of [Plonky3-recursion](https://github.com/Plonky3/Plonky3-recursion), dual-licensed under MIT and Apache 2.0.
