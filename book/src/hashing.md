# Hashing and Fiat-Shamir in Recursion

This section explains how cryptographic hashing, specifically Poseidon2, is used in recursive verification,
and how the Fiat-Shamir challenger is implemented to maintain transcript compatibility with native Plonky3.

## Overview

Recursive verification requires two distinct uses of the permutation used by the selected prover configuration:

1. **Fiat-Shamir Challenger**: Derives random challenges from the transcript (commitments, opened values, etc.)
2. **MMCS/Merkle Verification**: Verifies Merkle tree opening proofs for commitments

Both operations use the same underlying Poseidon2 permutation, but they interact with it differently:

```
┌─────────────────────────────────────────────────────────────────────┐
│                    Poseidon2 Permutation (WIDTH=16)                 │
├──────────────────────────────┬──────────────────────────────────────┤
│     Fiat-Shamir Challenger   │        MMCS/Merkle Hashing           │
├──────────────────────────────┼──────────────────────────────────────┤
│ • Duplex sponge construction │ • Compression function               │
│ • Absorb/squeeze pattern     │ • Hash two siblings → parent         │
│ • ~20 calls per verification │ • Hundreds of calls per verification │
│ • Transcript-sensitive       │ • Position-sensitive                 │
└──────────────────────────────┴──────────────────────────────────────┘
```

## The Poseidon2 Permutation

In this implementation, we use the Poseidon2 permutation with:

- **WIDTH = 16**: The permutation operates on 16 field elements
- **RATE = 8**: In sponge mode, 8 elements are absorbed/squeezed per permutation

**Note**: These parameters (WIDTH=16, RATE=8) are currently fixed and tailored to 32-bit fields.
Future versions will make them configurable to support a wider range of applications.

### Base Field vs Extension Field Views

The same Poseidon2 permutation can be viewed in two equivalent ways:

**D=1 View (Base Field)**
```
Input:  [f₀, f₁, f₂, ..., f₁₅]     ← 16 base field elements
Output: [g₀, g₁, g₂, ..., g₁₅]     ← 16 base field elements
```

**D=4 View (Extension Field)**
```
Input:  [E₀, E₁, E₂, E₃]           ← 4 extension field elements
Output: [F₀, F₁, F₂, F₃]           ← 4 extension field elements

where each Eᵢ = fᵢ₀ + fᵢ₁·ω + fᵢ₂·ω² + fᵢ₃·ω³
```

Both views represent the same Poseidon2 permutation over the base field. The difference is purely representational:
- D=1: Direct representation as 16 base field elements
- D=4: Packed representation as 4 degree-4 extension field elements

## The Fiat-Shamir Challenger

### Native Plonky3 Behavior

Plonky3's native `DuplexChallenger` maintains internal state as **base field elements**:

```rust
struct DuplexChallenger<F, Permutation, const WIDTH: usize, const RATE: usize> {
    sponge_state: [F; WIDTH],        // 16 base field elements
    input_buffer: Vec<F>,            // Pending observations (0..RATE)
    output_buffer: Vec<F>,           // Available samples (0..RATE)
}
```

The challenger implements a duplex sponge construction as follows:

```
┌────────────────────────────────────────────────────────────────┐
│                     Duplex Sponge Operation                    │
├────────────────────────────────────────────────────────────────┤
│                                                                │
│   observe(value):                                              │
│     1. Clear output_buffer (any pending outputs are invalid)   │
│     2. Push value to input_buffer                              │
│     3. If input_buffer.len() == RATE:                          │
│        • Overwrite state[0..RATE] with input_buffer            │
│        • Apply Poseidon2 permutation                           │
│        • Fill output_buffer from state[0..RATE]                │
│        • Clear input_buffer                                    │
│                                                                │
│   sample():                                                    │
│     1. If input_buffer not empty OR output_buffer empty:       │
│        • Trigger duplexing (same as step 3 above)              │
│     2. Pop and return from output_buffer                       │
│                                                                │
└────────────────────────────────────────────────────────────────┘
```

### Circuit Challenger Design

The recursive circuit operates over extension field elements, but must produce **identical transcripts** to the native challenger. This requires careful state management.

The `CircuitChallenger` maintains state as **coefficient-level targets**:

```rust
struct CircuitChallenger<const WIDTH: usize, const RATE: usize> {
    state: Vec<Target>,           // Targets, (base field coefficients)
    input_buffer: Vec<Target>,    // Pending observations
    output_buffer: Vec<Target>,   // Available samples
    poseidon2_config: Poseidon2Config,
}
```

Each target in `state` represents a base field element embedded in the extension field (i.e., only the constant coefficient is non-zero).

### Duplexing in the Circuit

When the circuit challenger needs to permute, it must bridge between coefficient-level state and the Poseidon2 permutation:

```
    16 coefficient targets                4 extension targets
    [c₀, c₁, c₂, ..., c₁₅]    ────►     [E₀, E₁, E₂, E₃]
                               recompose
                                  │
                                  ▼
                          ┌─────────────┐
                          │  Poseidon2  │
                          │ Permutation │
                          └─────────────┘
                                  │
                                  ▼
    [c'₀, c'₁, c'₂, ..., c'₁₅]  ◄────   [F₀, F₁, F₂, F₃]
                               decompose
```

**Recomposition** (16 coefficients → 4 extension elements):
```
E₀ = c₀ + c₁·ω + c₂·ω² + c₃·ω³
E₁ = c₄ + c₅·ω + c₆·ω² + c₇·ω³
E₂ = c₈ + c₉·ω + c₁₀·ω² + c₁₁·ω³
E₃ = c₁₂ + c₁₃·ω + c₁₄·ω² + c₁₅·ω³
```

**Decomposition** (4 extension elements → 16 coefficients):
The inverse operation, extracting basis coefficients from each extension element.

### Row Overhead

The recomposition/decomposition unfortunately adds overhead in the primitive tables:

| Operation | Mul Rows | Add Rows | Witness Rows |
|-----------|----------|----------|--------------|
| Recompose (4 ext) | 16 | 12 | 0 |
| Decompose (4 ext) | 16 | 12 | 16 |
| **Total per duplexing** | **32** | **24** | **16** |

This adds a total of approximately **70** rows over the different primitive tables per challenger duplexing.

> **Optimization Note**: When using D=1 configuration (base field challenges), no recomposition/decomposition
is needed as the state maps directly to the Poseidon2 inputs, eliminating this overhead.

## Coexistence on a Single Trace

Both D=1 and D=4 views share the **same Poseidon2 AIR trace**.
The AIR constrains the Poseidon2 permutation over the base field regardless of how inputs/outputs are packed:

```
┌───────────────────────────────────────────────────────────────────────────────────┐
│                          Poseidon2 AIR Trace (WIDTH=16)                           │
├───────────────────────────────────────────────────────────────────────────────────┤
│                                                                                   │
│  Each row: [s₀, s₁, s₂, s₃, s₄, s₅, s₆, s₇, s₈, s₉, s₁₀, s₁₁, s₁₂, s₁₃, s₁₄, s₁₅] │
│                                                                                   │
│  The AIR constraints enforce the Poseidon2 round function:                        │
│     • S-box application                                                           │
│     • Linear layer (MDS matrix multiplication)                                    │
│     • Round constant addition                                                     │
│                                                                                   │
│  These constraints are identical whether the caller interprets the 16 columns as: │
│     • 16 individual base field elements (D=1), or                                 │
│     • 4 extension field elements of degree 4 (D=4)                                │
│                                                                                   │
└───────────────────────────────────────────────────────────────────────────────────┘
```

## Transcript Compatibility

For recursive verification to be sound, the circuit challenger must produce **identical challenge values** to the native challenger given the same inputs. This requires:

1. **Same observation order**: Values must be absorbed in the exact same sequence
2. **Same duplexing triggers**: Permutation must occur at the same points
3. **Same output buffer management**: Samples must come from the same buffer positions

### Extension Field Operations

The native challenger provides methods for extension field values:

| Native Method | Circuit Method | Behavior |
|---------------|----------------|----------|
| `observe_algebra_element(ext)` | `observe_ext(target)` | Decompose to D coefficients, observe each |
| `sample_algebra_element()` | `sample_ext()` | Sample D base elements, recompose |

These methods ensure that extension field observations/samples are transcript-compatible.

In addition, when observing opened values in batch verification, we must ensure to respect
the order the native verifier performed for the recursive circuit to be able to satisfy the
associated constraints.

## Soundness Considerations

### Current: Witness Hints

Currently, the Poseidon2 permutation for the challenger is computed via **witness hints**:

```rust
// Prover provides the permutation output as a witness hint
let outputs = circuit.add_poseidon2_perm_for_challenger(config, inputs);
```

The prover computes the correct Poseidon2 output natively and provides it as a witness. The circuit then constrains consistency between inputs and outputs.

### Future: Cross-Table Lookups (CTLs)

For full soundness, each challenger Poseidon2 call should be connected to the Poseidon2 AIR table via CTLs. This cryptographically enforces that the permutation was computed correctly:

```
Challenger Circuit              Poseidon2 AIR Table
──────────────────              ──────────────────────
[in₀, in₁, in₂, in₃]  ──CTL──►  Row with matching
[out₀, out₁, out₂, out₃] ◄─────  inputs/outputs
```

The CTL proves that the (input, output) pair appears in the Poseidon2 table, ensuring the permutation wasn't forged by the prover.

## Configuration

The challenger is configured with a `Poseidon2Config` that specifies the field and extension degree:

| Config | Field | D | WIDTH | Use Case |
|--------|-------|---|-------|----------|
| `BabyBearD4Width16` | BabyBear | 4 | 16 | Standard recursive verification |
| `BabyBearD1Width16` | BabyBear | 1 | 16 | Base field challenges (lower overhead) |
| `BabyBearD4Width24` | BabyBear | 4 | 24 | Wider configuration, efficient hashing |
| `KoalaBearD4Width16` | KoalaBear | 4 | 16 | Alternative field |
| `KoalaBearD1Width16` | KoalaBear | 1 | 16 | Base field challenges (lower overhead) |
| `KoalaBearD4Width24` | KoalaBear | 4 | 24 | Wider configuration, efficient hashing |

The challenger is in charge to validate at runtime that the config matches the extension field being used.
