# Low-Level API

Use the low-level API when you need to add constraints to a verifier circuit or control its
construction and execution. The [unified API](./api.md) handles the usual recursion flow;
prepared owners retain the circuit and prover setup for repeated proving.

## Build a verifier circuit

The expert entry points are
[`verify_p3_uni_proof_circuit` and `verify_batch_circuit`](https://github.com/Plonky3/Plonky3-recursion/blob/main/recursion/src/verifier/mod.rs).
Their target, config, and lookup parameters depend on the native PCS. The
[`FriRecursionBackend` implementation](https://github.com/Plonky3/Plonky3-recursion/blob/main/recursion/src/backend/fri.rs) is the checked
reference for allocating targets, enabling the permutation tables, and building a FRI
verifier circuit. Keep the circuit's permutation and FRI parameters aligned with the native
proof's suite.

## Supply opening witnesses

A FRI proof carries pruned multiproofs; the MMCS circuit needs a path for each query. Replay
the opening transcript and call
[`restore_fri_query_paths`](https://github.com/Plonky3/Plonky3-recursion/blob/main/recursion/src/pcs/mmcs.rs) before
[`set_fri_mmcs_private_data`](https://github.com/Plonky3/Plonky3-recursion/blob/main/recursion/src/pcs/mmcs.rs). The
[built-in config implementation](https://github.com/Plonky3/Plonky3-recursion/blob/main/recursion/src/builtin_config/fri/recursion.rs)
shows the current `set_fri_private_data(config, runner, op_ids, opening_proof, transcript)`
contract and the required opened-value observation. A hiding PCS also needs its random
openings merged into the transcript at the same point as native verification.

## Prove and verify the circuit

`BatchStarkProver::prepare_circuit` finalizes the relation and preprocessing once, then
returns a `PreparedCircuitProver`. Feed runner traces to `prepared.prove(&traces)` and verify
with the independently retained `prepared.verifier()` and a caller-supplied expected
statement. The [executable BabyBear example](https://github.com/Plonky3/Plonky3-recursion/blob/main/circuit-prover/src/lib.rs) uses this
path, including a public statement export.

For ordinary repeated recursion, `PreparedLayer` and `PreparedAggregation` also check the
native input's shape before reuse. `TrustedPreparedLayer` and `TrustedPreparedAggregation`
retain child authority and check statements as described in the [API guide](./api.md).
