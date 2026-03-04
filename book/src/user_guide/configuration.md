# Configuration

This section covers the parameters you need to choose when setting up recursive verification.

## Field selection

The library currently supports two base fields:

| Field | Modulus | Bits | Status |
|-------|---------|------|--------|
| **KoalaBear** | `0x7F000001` | 31 | Recommended |
| **BabyBear** | `0x78000001` | 31 | Fully supported |

All fields support degree-4 binomial extensions (`BinomialExtensionField<F, 4>`), which is a currently
fixed parameter for the recursion stack, with plans to lift it to a runtime parameter in the future.

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
let fri_verifier_params = FriVerifierParams::with_mmcs(
    log_blowup,
    log_final_poly_len,
    commit_pow_bits,
    query_pow_bits,
    poseidon2_config,
);
```

This is stored in your config wrapper and returned via `FriRecursionConfig::pcs_verifier_params()`.

## Poseidon2 configuration

The `Poseidon2Config` enum selects the hash function parameters for in-circuit hashing (MMCS verification and Fiat-Shamir):

| Config | Field | D | WIDTH | RATE |
|--------|-------|---|-------|------|
| `BabyBearD4Width16` | BabyBear | 4 | 16 | 8 |
| `BabyBearD1Width16` | BabyBear | 1 | 16 | 8 |
| `BabyBearD4Width24` | BabyBear | 4 | 24 | 12 |
| `KoalaBearD4Width16` | KoalaBear | 4 | 16 | 8 |
| `KoalaBearD1Width16` | KoalaBear | 1 | 16 | 8 |
| `KoalaBearD4Width24` | KoalaBear | 4 | 24 | 12 |

For standard recursive verification, use the `D4Width16` variant matching your field. The `D1` variants use base field challenges (lower overhead per duplexing, but different security trade-offs). The `Width24` variants use a wider permutation for more efficient hashing.

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

**Example** — a recursive verification circuit with ~65K witness ops, ~43K public ops, ~60K ALU ops:

| Packing | Max height | Notes |
|---------|-----------|-------|
| `(5, 1, 3)` | 2^16 = 65,536 | Public table (43K/1 = 43K rows) forces 2^16 |
| `(5, 2, 3)` | 2^15 = 32,768 | Public drops to 21.5K, halving the max |
| `(5, 3, 3)` | 2^15 = 32,768 | Public at 14.3K, ALU at 20K — both fit in 2^15 |
| `(8, 4, 4)` | 2^14 = 16,384 | Everything fits, but tables are very wide |

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
