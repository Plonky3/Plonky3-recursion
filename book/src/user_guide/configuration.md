# Configuration

This section covers the parameters you need to choose when setting up recursive verification.

## Field selection

Native FRI factories include these base fields:

| Field | Modulus | Bits | Native factory |
|-------|---------|------|----------------|
| **KoalaBear** | `0x7F000001` | 31 | Available |
| **BabyBear** | `0x78000001` | 31 | Available |
| **Goldilocks** | `0xFFFFFFFF00000001` | 64 | Available with a degree-2 challenge extension |

BabyBear and KoalaBear have degree-4 binomial suites. KoalaBear also has a degree-5
quintic suite. These [native factories](https://github.com/Plonky3/Plonky3-recursion/blob/main/recursion/src/builtin_config/fri.rs) validate
their own parameters. Of these, only `KoalaBearD4Poseidon2BinaryConfig` directly implements
`FriRecursionConfig` for the unified recursion API. For the other factories, provide a local
`StarkGenericConfig` wrapper with a matching `FriRecursionConfig` implementation; see the
[integration guide](./integration.md).

## Built-in native configuration suites

The [V1 suite registry](https://github.com/Plonky3/Plonky3-recursion/blob/main/recursion/src/builtin_config/registry.rs) defines the following
21 native suites. `D` is the challenge extension degree; arity is the commitment tree arity.
Every row is constructed by its typed native
[FRI](https://github.com/Plonky3/Plonky3-recursion/blob/main/recursion/src/builtin_config/fri.rs) or
[WHIR](https://github.com/Plonky3/Plonky3-recursion/blob/main/recursion/src/builtin_config/whir.rs) factory
and proves and verifies a bounded Fibonacci trace in
[`builtin_config_proofs.rs`](https://github.com/Plonky3/Plonky3-recursion/blob/main/recursion/tests/builtin_config_proofs.rs).

| Suite | Field | D | Hash | Arity | Hiding |
|-------|-------|---|------|-------|--------|
| Ordinary FRI, binary | BabyBear | 4 | Poseidon2 | 2 | None |
| Ordinary FRI, binary | BabyBear | 4 | Poseidon1 | 2 | None |
| Ordinary FRI, binary | KoalaBear | 4 | Poseidon2 | 2 | None |
| Ordinary FRI, binary | KoalaBear | 4 | Poseidon1 | 2 | None |
| Ordinary FRI, binary | Goldilocks | 2 | Poseidon2 | 2 | None |
| Ordinary FRI, binary | Goldilocks | 2 | Poseidon1 | 2 | None |
| Ordinary FRI, binary | KoalaBear | 5 | Poseidon2 | 2 | None |
| Ordinary FRI, binary | KoalaBear | 5 | Poseidon1 | 2 | None |
| Ordinary FRI, quaternary | BabyBear | 4 | Poseidon2 | 4 | None |
| Ordinary FRI, quaternary | KoalaBear | 4 | Poseidon2 | 4 | None |
| Ordinary FRI, quaternary | Goldilocks | 2 | Poseidon2 | 4 | None |
| Ordinary FRI, quaternary | KoalaBear | 5 | Poseidon2 | 4 | None |
| Random-codeword FRI | BabyBear | 4 | Poseidon2 | 2 | Random codeword |
| Random-codeword FRI | BabyBear | 4 | Poseidon1 | 2 | Random codeword |
| Random-codeword FRI | KoalaBear | 4 | Poseidon2 | 2 | Random codeword |
| Random-codeword FRI | KoalaBear | 4 | Poseidon1 | 2 | Random codeword |
| Random-codeword FRI | Goldilocks | 2 | Poseidon2 | 2 | Random codeword |
| Random-codeword FRI | Goldilocks | 2 | Poseidon1 | 2 | Random codeword |
| Salted FRI | KoalaBear | 4 | Poseidon2 | 2 | Salted commitments and random codeword |
| WHIR | BabyBear | 4 | Poseidon2 | 2 | None |
| WHIR | KoalaBear | 4 | Poseidon2 | 2 | None |

[`builtin_config_native.rs`](https://github.com/Plonky3/Plonky3-recursion/blob/main/recursion/tests/builtin_config_native.rs) additionally checks
that each factory retains its descriptor and native parameters. The ordinary FRI proof tests use
8-row traces, the hiding FRI tests use 32-row traces, and the WHIR tests use 64-row traces.
The hiding tests use independent seeded proving and verifying RNGs and check that verification
draws no RNG. These small parameters establish factory interoperability, not a production
security level; choose security parameters for your application.

Native factory support does not mean every suite has direct recursion or artifact integration.
Only `KoalaBearD4Poseidon2BinaryConfig` directly implements `FriRecursionConfig` for the
unified recursion API; [custom recursion configurations](https://github.com/Plonky3/Plonky3-recursion/blob/main/recursion/tests/common/mod.rs)
and the [integration guide](./integration.md) show the separate wrapper route.
Broader custom tests exercise a [Goldilocks recursive verifier](https://github.com/Plonky3/Plonky3-recursion/blob/main/recursion/tests/goldilocks.rs),
[KoalaBear quintic recursive proving](https://github.com/Plonky3/Plonky3-recursion/blob/main/recursion/tests/fibonacci_batch_stark_prover_quintic.rs),
[quaternary MMCS verification](https://github.com/Plonky3/Plonky3-recursion/blob/main/recursion/tests/recursive_arity4_mmcs.rs), and
[hiding FRI recursive verification](https://github.com/Plonky3/Plonky3-recursion/blob/main/recursion/tests/fibonacci_batch_stark_prover_zk.rs).
Those tests use their own configurations; they do not establish recursion support for every
factory combination in the table.
The [artifact round-trip tests](https://github.com/Plonky3/Plonky3-recursion/blob/main/recursion/tests/artifact_roundtrip.rs) cover
representative native suites, while the
[recursive artifact round-trip](https://github.com/Plonky3/Plonky3-recursion/blob/main/recursion/tests/artifact_recursive_roundtrip.rs)
uses that KoalaBear binary suite. [Binary-field foundations](../advanced_topics/binary_fields.md)
are partial and are outside this native suite matrix.

The [PR CI matrix](https://github.com/Plonky3/Plonky3-recursion/blob/main/.github/workflows/ci.yml) runs workspace tests with default and
all features, each with and without AVX2. It therefore runs these bounded factory proof tests
on every PR. The [weekly assurance workflow](https://github.com/Plonky3/Plonky3-recursion/blob/main/.github/workflows/assurance.yml)
runs a separate bounded seeded verifier corpus; it does not replace the 21-suite native
factory checks.

## FRI parameters

FRI parameters control the trade-off between proof size, verifier cost, and security level.

| Parameter | Typical value | Effect |
|-----------|---------------|--------|
| `log_blowup` | 3 | LDE blowup factor (`2^log_blowup`). Higher = more redundancy, fewer queries needed. |
| `max_log_arity` | 4 | Maximum folding factor per FRI round (`2^max_log_arity`). Controls how quickly polynomial degree reduces. |
| `log_final_poly_len` | 5 | Degree of the final polynomial after folding. Smaller = more folding rounds but simpler final check. |
| `query_pow_bits` | 16 | Proof-of-work bits during the query phase. Higher = fewer queries needed for same security. |
| `commit_pow_bits` | 0 | Proof-of-work bits during the commit phase. Usually 0. |
| `cap_height` | 0 | Height at which Merkle trees are truncated for commitments. 0 = single root hash. |

### Security level

The number of FRI queries is derived as:

```
num_queries = (target_security_bits - query_pow_bits) / log_blowup
```

With default parameters (`target = 100 bits`, `query_pow_bits = 16`, `log_blowup = 3`):

```
num_queries = (100 - 16) / 3 = 28
```

See related section in the **[Soundness and Security](./../advanced_topics/soundness.md)** chapter for a
more thorough analysis of the security estimate in the light of recent findings against the underlying
assumptions used in these heuristics.

### Intermediate layer relaxation

For intermediate recursive layers (not the final one), soundness requirements compose, so relaxed parameters can be used:

- `query_pow_bits = 20`, `num_queries = 26` — saves 2 queries worth of in-circuit work
- `query_pow_bits = 24`, `num_queries = 25` — more aggressive, suitable for deeply nested layers

The outermost (final) layer should use full-strength parameters.

### FriVerifierParams

The recursion circuit uses `FriVerifierParams` to know the FRI structure without accessing the native `FriParameters` directly:

```rust,ignore
let fri_verifier_params = FriVerifierParams::try_with_mmcs(
    log_blowup,
    log_final_poly_len,
    max_log_arity,
    commit_pow_bits,
    query_pow_bits,
    num_queries,
    poseidon2_config,
)?;
```

This is stored in your config wrapper and returned via `FriRecursionConfig::pcs_verifier_params()`.

## Poseidon2 configuration

`Poseidon2Config` provides named constants for in-circuit permutation parameters:

| Config | Field | D | WIDTH | RATE |
|--------|-------|---|-------|------|
| `BABY_BEAR_D4_W16` | BabyBear | 4 | 16 | 8 |
| `BABY_BEAR_D1_W16` | BabyBear | 1 | 16 | 8 |
| `BABY_BEAR_D4_W24` | BabyBear | 4 | 24 | 12 |
| `KOALA_BEAR_D4_W16` | KoalaBear | 4 | 16 | 8 |
| `KOALA_BEAR_D1_W16` | KoalaBear | 1 | 16 | 8 |
| `KOALA_BEAR_D4_W24` | KoalaBear | 4 | 24 | 12 |
| `GOLDILOCKS_D2_W8` | Goldilocks | 2 | 8 | 4 |

For a degree-4 suite using width 16, select the `D4_W16` constant matching your field.
Choose the backend degree tag to match the circuit extension, for example
`FriRecursionBackend::new(Poseidon2Config::KOALA_BEAR_D4_W16).for_extension_degree::<4>()`
for trusted prepared recursion.

The `Poseidon2Config` must be consistent between:
- The `FriRecursionBackend` constructor
- The `FriVerifierParams`
- The Poseidon2 permutation enabled on the `CircuitBuilder`

## Table packing

`TablePacking` controls how circuit operations are distributed across table lanes. Each lane adds columns to a table; more lanes means shorter (fewer rows) but wider (more columns) tables.

```rust,ignore
TablePacking::new(public_lanes, alu_lanes)
```

| Parameter | Controls | Trade-off |
|-----------|----------|-----------|
| `public_lanes` | Public input table width | Often the bottleneck for row count |
| `alu_lanes` | ALU (add/mul) table width | Most operations land here |

The total row count of each table is `ceil(num_ops / num_lanes)`, padded to the next power of two. The **maximum table height** across all tables determines the FRI polynomial degree and dominates proving cost.

### Choosing packing values

The goal is to balance table heights so no single table forces a large power-of-two padding.

**Example** — a recursive verification circuit with ~43K public ops and ~60K ALU ops
(columns are `public_lanes, alu_lanes`):

| Packing | Max height | Notes |
|---------|-----------|-------|
| `(1, 1)` | 2^16 = 65,536 | Public table (43K/1 = 43K rows) forces 2^16 |
| `(2, 1)` | 2^15 = 32,768 | Public drops to 21.5K, halving the max |
| `(3, 2)` | 2^15 = 32,768 | Public at 14.3K, ALU at 30K — both fit in 2^15 |
| `(4, 4)` | 2^14 = 16,384 | Everything fits, but tables are very wide |

Halving the max table height cuts FRI proving time by roughly 40-50% (one fewer folding round, half the polynomial size).

Use `.with_fri_params(log_final_poly_len, log_blowup)` to set minimum row counts:

```rust,ignore
let packing = TablePacking::new(2, 3)
    .with_fri_params(log_final_poly_len, log_blowup);
```

### Layer-specific packing

The first recursive layer (verifying the original proof) often has a different operation distribution than subsequent layers. It's common to use different packing per layer:

```rust,ignore
let packing = if layer == 1 {
    TablePacking::new(1, 1)
} else {
    TablePacking::new(1, 3)
}.with_fri_params(log_final_poly_len, log_blowup);
```
