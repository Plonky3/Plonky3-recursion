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
quintic suite. All 19 registered [FRI configuration aliases](https://github.com/Plonky3/Plonky3-recursion/blob/main/recursion/src/builtin_config/fri.rs)
implement `FriRecursionConfig`; both registered [WHIR aliases](https://github.com/Plonky3/Plonky3-recursion/blob/main/recursion/src/builtin_config/whir.rs)
implement `WhirRecursionConfig`. Their factories validate native parameters, while
recursive proving also requires a matching backend and admissible proof geometry.
For the seven generic random-codeword and salted FRI aliases, recursion and typed
artifact import additionally require `R: CryptoRng + SeedableRng + Send + Sync + 'static`;
the native factories require only `CryptoRng + SeedableRng`.
See the [integration guide](./integration.md) for custom configurations.

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

The [binary FRI](https://github.com/Plonky3/Plonky3-recursion/blob/main/recursion/tests/builtin_fri_recursion_binary.rs),
[quaternary FRI](https://github.com/Plonky3/Plonky3-recursion/blob/main/recursion/tests/builtin_fri_recursion_quaternary.rs),
[hiding FRI](https://github.com/Plonky3/Plonky3-recursion/blob/main/recursion/tests/builtin_fri_recursion_hiding.rs), and
[WHIR](https://github.com/Plonky3/Plonky3-recursion/blob/main/recursion/tests/builtin_whir_recursion.rs)
lifecycle tests cover the 21 concrete aliases: prepared reuse, typed artifact
reentry, a second recursive layer, and portable verification against independent
expected statements. The typed importer uses the application-supplied native
configuration, including its hiding RNG setup; a separate output configuration
is supplied to the recursive owner. [Custom recursion configurations](https://github.com/Plonky3/Plonky3-recursion/blob/main/recursion/tests/common/mod.rs)
remain an extension route for setups outside the registered aliases.
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

## Choosing a built-in recursion backend

Choose the backend from the native suite's *challenger* permutation. For binary
FRI, random-codeword FRI, and salted FRI, its MMCS uses the same permutation
width. The four registered quaternary suites all use Poseidon2: they keep the
narrower challenger backend and register the wider MMCS table separately with
`with_extra_poseidon2_table`:

| Suite family | Challenger backend | Additional quaternary MMCS table |
|-------------|--------------------|----------------------------------|
| BabyBear/KoalaBear D4 Poseidon1 or Poseidon2 FRI | `FriRecursionBackend::<16, 8, _>::new(...).for_extension_degree::<4>()` with matching `*_D4_W16` | Poseidon2 `*_D4_W32` for quaternary suites |
| Goldilocks D2 Poseidon1 or Poseidon2 FRI | `FriRecursionBackend::<8, 4, _>::new(...).for_extension_degree::<2>()` with matching `GOLDILOCKS_D2_W8` | Poseidon2 `GOLDILOCKS_D2_W16` for quaternary |
| KoalaBear D5 Poseidon1 or Poseidon2 FRI | `FriRecursionBackend::<16, 8, _>::new_d5(...)` with matching `KOALA_BEAR_D1_W16` | Poseidon2 `KOALA_BEAR_D1_W32` for quaternary |
| BabyBear/KoalaBear D4 Poseidon2 WHIR | `WhirRecursionBackend::<16, 8>::new(...).for_extension_degree::<4>()` with matching `*_D4_W16` | None; binary commitments |

The two D5 FRI challengers use a quintic extension for proof challenges but
base-field (`D1`) Poseidon lanes. `new_d5` requires a D1 challenger config;
the quaternary D5 MMCS table is also D1. Match Poseidon1 versus Poseidon2 as
well as the field, width, rate, extension degree, and native Merkle arity.
Keep `input_cap_height` and `commit_cap_height` distinct when choosing FRI
parameters; the built-in configuration retains both for path restoration.
For hiding suites, provide the native proving RNGs through the application
configuration; typed import retains it. Salted FRI path restoration constructs
private, fixed-seed MMCS helpers for verification only. Those helpers never
commit or draw randomness and do not replace the retained proving config.

Both WHIR aliases use Poseidon2, D4, and binary Merkle commitments. The
built-in `WhirConfigV1` descriptor still specifies one constant folding factor.
For a custom `WhirUniPcs` and `WhirUniVerifierParams`, the recursive verifier
supports native `FoldingFactor::Constant`, `ConstantFromSecondRound`, and
`PerRound` with positive factors, canonical Prefix or Suffix variable order,
unstratified query sampling, and binary commitments. The first fold controls table padding;
the complete strategy is retained for native WHIR configuration and transcript
seeding. Every commitment's stacked arity must fit that strategy exactly.
In particular, a `PerRound` vector must supply exactly the factors used at
each commitment arity, so one vector may not fit both leaf and recursive
trace sizes. An explicit round-rate schedule must likewise match the
intermediate round count derived from each commitment's stacked arity; use
`WhirRateModeV1::Auto` when leaf and recursive trace sizes differ. In any
intermediate or final phase where the raw configured query count reaches or
exceeds `domain_size >> folding_factor`, the verifier opens the entire folded
domain in ascending order and makes no query-index challenger draws. The
effective opening count is the minimum of the raw count and folded domain
size; the raw count remains part of the canonical security configuration.
The public low-level `WhirVerifierParams::from_config` and
`verify_whir_circuit` path accepts canonical, unstratified Prefix and Suffix
variable orders. Its query-index circuit currently consumes one base-field
sample per unsaturated query, so native uniform-bit rejection or resampling
is outside the supported transcript cases. Custom univariate recursion supports
the two native canonical layouts, including prepared proof production under a
custom Suffix configuration. Arbitrary layouts with independent selector and
fold-order settings are outside this adapter's contract. The registered V1
aliases and descriptors remain Prefix with Constant folding; no portable
Suffix artifact format is registered. The WHIR descriptor's cap height is
retained when restoring paths.

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
| `BABY_BEAR_D4_W32` | BabyBear | 4 | 32 | 24 |
| `KOALA_BEAR_D4_W16` | KoalaBear | 4 | 16 | 8 |
| `KOALA_BEAR_D1_W16` | KoalaBear | 1 | 16 | 8 |
| `KOALA_BEAR_D4_W24` | KoalaBear | 4 | 24 | 12 |
| `KOALA_BEAR_D4_W32` | KoalaBear | 4 | 32 | 24 |
| `KOALA_BEAR_D1_W32` | KoalaBear | 1 | 32 | 24 |
| `GOLDILOCKS_D2_W8` | Goldilocks | 2 | 8 | 4 |
| `GOLDILOCKS_D2_W16` | Goldilocks | 2 | 16 | 12 |

For a degree-4 suite using width 16, select the `D4_W16` constant matching your field.
The wider W16/W32 entries above describe quaternary MMCS tables; the backend
`WIDTH` and `RATE` type parameters still describe the narrow challenger.
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
