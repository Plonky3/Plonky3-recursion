# RFC 0003: Dynamic-Degree AIR Profiles for Recursion

---

- **Author(s):** @Nashtare
- **DRI:** @Nashtare
- **Status:** Draft
- **Created:** 2026-02-10
- **Tracking issue:** #254

## 1. Summary

From preliminary benchmarks, recursive layers will most likely use **higher FRI blowup factors** than base layers, but all AIRs are still designed for degree 3 constraint degrees (i.e. blowup factor 2). This leaves quotient-degree capacity underutilised and forces us to pay for more rows and columns than necessary, which could be compressed into fewer, higher-degree constraints.

This RFC proposes introducing a small set of **AIR profiles** whose **maximum constraint degree and table designs depend on the chosen blowup / recursion profile**. The aim is to:

- Reduce **trace heights** and/or **table widths** in recursion-heavy layers (especially for Poseidon2Perm and ALU (cf #267) tables),
- While keeping the rest of the protocol unchanged and preserving soundness.

The core idea is to use the extra quotient-degree budget that high blowup affords to:

- Define **higher-degree constraints** (e.g. degree 5 or 9) for selected tables, (e.g. multiple Poseidon2 rounds or fused ALU operations),
- And keep a small, well-specified family of configurations so that prover, verifier, and recursive circuits agree on the same AIRs.

## 2. Motivation / Problem Statement

### 2.1 Underused quotient-degree budget in recursion

For each AIR instance, the PCS/FRI parameters determine:

- The **trace degree** \(T = 2^{\text{degree\_bits}}\),
- The **LDE blowup** (via `log_blowup`),
- The **quotient degree**, derived from `get_log_num_quotient_chunks`, which depends on:
  - The AIR’s **maximum constraint degree**,
  - The number of lookups and public values,
  - ZK tweaks (for the future).

In recursive verification, we would typically use `log_blowup = 3` because of the price of each FRI query for the verifier, which means:

- The LDE domain is significantly larger than the base trace domain.
- The quotient polynomial can have degree noticeably higher than the underlying trace without incurring noticeable slowdown on the PCS or FRI.

However, all of our AIRs are still constrained to low degrees at most 3, for historical or simplicity reasons. This means:

- We are **not using** all of the quotient-degree capacity available in recursion layers.
- We pay for extra **rows** (height) and sometimes **columns** (width) that could be compressed into fewer high-degree constraints, especially when the logic being enforced is naturally higher-degree (e.g. multiple S-box applications or multi-step arithmetic).

### 2.2 High-impact tables in recursion

Profiling and performance logs from the last recursive run in two configurations (DEBUG logs) give concrete backing for these claims. All numbers below are from a single steady-state recursion layer (KoalaBear, `Poseidon2Perm(KoalaBearD4Width16)`). The first set uses **default (narrow) TablePacking**; see §2.3 for **wide** TablePacking.

**Add+Mul profile** (separate Add and Mul as primitive tables; basic packing):

| Table       | Rows    | % of total rows |
|------------|--------:|----------------:|
| Witness    | 107,774 | 34.9%           |
| Add        |  82,341 | 26.7%           |
| Mul        |  95,313 | 30.9%           |
| Public     |  15,966 |  5.2%           |
| Poseidon2  |   6,835 |  2.2%           |
| Const      |     347 |  0.1%           |
| **Total**  | 308,576 | 100%            |

Primitive tables (Witness, Const, Public, Add, Mul) account for **97.8%** of all rows; Poseidon2 is **2.2%**. `prove_all_tables` for this layer: **1.37 s**.

**ALU profile** (single ALU table; basic packing):

| Table       | Rows    | % of total rows |
|------------|--------:|----------------:|
| ALU        | 120,088 | 49.5%           |
| Witness    |  99,675 | 41.1%           |
| Public     |  15,567 |  6.4%           |
| Poseidon2  |   6,656 |  2.7%           |
| Const      |     363 |  0.15%          |
| **Total**  | 242,349 | 100%            |

Primitive tables account for **97.3%** of rows; Poseidon2 is **2.7%**. `prove_all_tables` for this layer: **1.22 s**.

**Comparison:**

- **Total rows**: 308,576 (Add+Mul) vs 242,349 (ALU) → **21.5% fewer rows** with the ALU table.
- **Primitive rows**: 301,741 vs 235,693 → **21.9% fewer** primitive rows with ALU.
- **Prove time** for this layer: 1.37 s → 1.22 s → **~11% faster** with ALU.

So:

- **Poseidon2 permutation tables** (used by MMCS and challengers) are a small share of rows in this snapshot (~2–3%) but are a significant share of proof time (hashing, commitments). Reducing Poseidon2 rows (e.g. via higher-degree, multi-round-per-row variants) still pays off.
- **Primitive tables** (Witness, Add/Mul or ALU, Public) dominate row count (≥97%). Fusing Add+Mul into an ALU table already cuts total rows by >20% and speeds up proving; further fusion or dedicated high-degree tables (e.g. FRI fold) can compound these gains.
- Protocol-specific algebra (e.g. **FRI fold**) is expanded through these primitive tables; a dedicated fold table would remove a large block of Add/Mul (or ALU) and Witness rows in recursion.

### 2.3 Wide TablePacking

The same recursion layer was profiled with **wide** `TablePacking` (more lanes per row, so fewer rows per table). Sources: `perf_add_mul2.txt` (Add+Mul) and `perf_alu2.txt` (ALU).

**Add+Mul profile, wide packing** (`perf_add_mul2.txt`):

| Table       | Rows   | % of total rows |
|------------|-------:|----------------:|
| Witness    | 32,268 | 27.1%           |
| Add        | 30,783 | 25.8%           |
| Mul        | 31,072 | 26.1%           |
| Public     | 15,601 | 13.1%           |
| Poseidon2  |  9,070 |  7.6%           |
| Const      |    343 |  0.3%           |
| **Total**  |119,137| 100%            |

`prove_all_tables`: **838 ms**.

**ALU profile, wide packing** (`perf_alu2.txt`):

| Table       | Rows   | % of total rows |
|------------|-------:|----------------:|
| ALU        | 31,834 | 35.8%           |
| Witness    | 31,429 | 35.3%           |
| Public     | 15,421 | 17.3%           |
| Poseidon2  |  8,963 | 10.1%           |
| Const      |    356 |  0.4%           |
| **Total**  | 89,003 | 100%            |

`prove_all_tables`: **923 ms**.

**Effect of wide packing (default → wide, same op profile):**

| Profile   | Default total | Wide total | Row reduction | Default prove | Wide prove |
|-----------|---------------|------------|---------------|---------------|------------|
| Add+Mul   | 308,576       | 119,137    | **61.4%**     | 1.37 s        | 838 ms     |
| ALU       | 242,349       |  89,003    | **63.3%**     | 1.22 s        | 923 ms     |

Wide packing cuts total rows by **~61–63%** and speeds up Add+Mul proving (**~39%** faster: 1.37 s → 838 ms). For ALU, wide packing also cuts rows by **63%** but prove time in this snapshot is slightly higher than wide Add+Mul (923 ms vs 838 ms), likely due to higher constraint degree / quotient cost in the ALU table.

**Add+Mul vs ALU at fixed packing:**

- **Default packing:** ALU has 21.5% fewer total rows and ~11% faster prove time than Add+Mul.
- **Wide packing:** ALU has **25.2% fewer** total rows (89,003 vs 119,137) than Add+Mul; prove time is ~10% higher for ALU (923 ms vs 838 ms).

So **wide TablePacking** is a major lever: it reduces row count and (for Add+Mul) prove time substantially. Combining wide packing with ALU further reduces rows; the trade-off between row count and per-row cost (ALU vs Add+Mul) depends on the chosen packing and FRI parameters.

The key observation is that some of these tables have **natural high-degree structure**:

- For **KoalaBear** Poseidon2, the S-box is \(x \mapsto x^3\), so composing two S-box layers yields degree \(3^2 = 9\).
- For **ALU-style arithmetic**, multi-step patterns (e.g. `a*b + c*d + e`) are naturally degree 3–5 in the inputs but are currently expanded into multiple low-degree constraints and tables.

We can exploit this by allowing **profile-dependent constraint degrees**, especially in recursion layers where `log_blowup` is already large.

## 3. Goals and Non-goals

### 3.1 Goals

- **Use quotient-degree budget in recursion more efficiently**:
  - Raise the maximum constraint degree for selected tables (e.g. up to 5 or 9 depending on selected blowup factor),
  - Encode more work per row (multi-round Poseidon2, fused ALU operations).

- **Define a small set of AIR “profiles”**:
  - Each profile is a coherent set of:
    - FRI parameters (already present),
    - `TablePacking` settings,
    - AIR variants for key tables (Poseidon2, ALU/Add/Mul, and possibly FRI fold).
  - Profiles are fixed per **proof shape** or recursion layer and known to both prover and verifier.

- **Preserve soundness and PCS/FRI configuration**:
  - No changes to the underlying PCS/FRI algorithms or security assumptions.
  - AIR variants must have **explicitly bounded degrees** that are compatible with the existing FRI parameters.

- **Start with a small, high-impact subset of tables**:
  - Poseidon2 permutation (especially for KoalaBear),
  - ALU / Add / Mul,
  - Optionally, a dedicated FRI fold table.

### 3.2 Non-goals

- It is **not** a goal to:
- allow arbitrary, per-proof AIR customisation. All AIR variants must be:
  - Pre-defined,
  - Versioned,
  - And selected via a small set of profiles.

- redesign or replace the FRI / PCS back end.

- fully specify here or implement each new AIR variant. Instead, this RFC will:
  - Identify where higher-degree AIRs are promising,
  - Specify how profiles are selected and enforced,
  - And outline the design constraints and integration points.

## 4. Design Overview

### 4.1 Profiles: Standard vs Recursion-Optimized

We introduce a small, explicit set of **constraint profiles** that describe how AIRs are instantiated for a given recursion layer:

- **Standard**:
  - Existing behaviour:
    - Current Poseidon2 AIR via `p3_poseidon2_air::Poseidon2Air`,
    - Current primitive tables (`Witness`, `Add`, `Mul`, `Public`),
    - Existing ALU/CTL behaviour.

- **RecursionOptimizedBabyBear** (example name):
  - Same FRI parameters as Standard.
  - Changes limited to:
    - Allowing slightly higher-degree gating (products of a few booleans) in recursion-specific tables (e.g. Poseidon2 permutation table),
    - Potentially enabling a modestly more fused ALU variant (degree up to 5–7).

- **RecursionOptimizedKoalaBear** (example name):
  - For KoalaBear-based recursion.
  - With `log_blowup` sufficiently high (e.g. 3), select:
    - Higher-degree Poseidon2 permutation AIR (max degree \(\le 9\)),
    - Optionally a more aggressive ALU variant, and/or a dedicated FRI fold table.

Profiles are selected **per recursion layer** at configuration time (e.g. in the recursion examples) and must be the same for:

- Circuit construction,
- Native batch prover,
- Recursive verifier.

### 4.2 AIR Variants per Table

For each logical table type, we distinguish between:

- A **baseline AIR**, used in Standard profile(s),
- One or more **optimized variants**, used only in selected profiles.

#### Poseidon2 permutation table

- **Baseline**:
  - Uses `p3_poseidon2_air::Poseidon2Air` inside `poseidon2-circuit-air`:
    - BabyBear: S-box degree 7,
    - KoalaBear: S-box degree 3.
  - Recursion-specific logic (chaining, MMCS index sum accumulator, CTL gating) is layered on top.

- **KoalaBearOptimizedDeg9 (candidate)**:
  - KoalaBear-specific variant with:
    - **Two Poseidon2 rounds per row**, using S-box degree 3 twice (composed degree 9),
    - No intermediate Poseidon2 state columns in the trace (state after two rounds enforced directly).
  - Expected effect:
    - Approximate **2× reduction in Poseidon2 rows** in recursion layers using KoalaBear,
    - Max constraint degree \(\le 9\), compatible with higher blowup.

- **BabyBearOptimized (candidate)**:
  - BabyBear’s S-box degree is 7, so we cannot safely compose two S-box layers under degree 9.
  - We can, however:
    - Relax degree-minimisation tricks (e.g. selector columns) in the recursion wrapper,
    - Allow richer boolean gating directly (products of a few booleans),
    - Possibly fold some recursion-specific logic (e.g. MMCS/CTL) into single constraints while staying under the degree bound.

#### ALU / Add / Mul tables

- **Baseline**:
  - `AddAir` and `MulAir` with low-degree constraints and separate rows per operation.
  - ALU-style fusion exists at the circuit level (e.g. `mul_add`), but ultimately expands into separate Add/Mul operations.

- **FusedDeg5 / FusedDeg9 (candidates)**:
  - New ALU variants for recursion layers, with constraints of degree up to 5 or 9, that can encode:
    - Simple fused patterns like `res = a * b + c` or `res = a * b + c * d + e`,
    - Or small, fixed multi-step patterns (e.g. pieces of the FRI fold polynomial).
  - Trade-offs:
    - Fewer rows and potentially fewer witness indices,
    - More complex quotient polynomials (more chunks), which recursion layers can tolerate thanks to higher blowup.

#### FRI fold / protocol-specific tables

- **Baseline**:
  - FRI fold polynomial evaluation and related logic are expanded into primitive operations (Add/Mul/Witness).

- **Dedicated fold table (candidate)**:
  - A specialized table whose AIR enforces:
    - The full FRI fold formula at a point, in one or a few high-degree constraints (degree up to 9).
  - Expected benefits:
    - Removes a large number of Add/Mul/Witness ops specific to FRI,
    - Shrinks primitive tables and centralises protocol logic.

### 4.3 Configuration Flow

At recursion layer setup time (e.g. in `recursive_fibonacci.rs` / `recursive_keccak.rs`):

1. Choose FRI parameters:
   - `LOG_BLOWUP`, `LOG_FINAL_POLY_LEN`, arity schedule, etc.
2. Set `TablePacking`:
   - `witness_lanes`, `public_lanes`, `add_lanes`, `mul_lanes`, `min_trace_height`.
3. Select a **ConstraintProfile**:
   - E.g. `Standard` or `RecursionOptimizedKoalaBear`.
4. The profile determines, per table:
   - Which AIR type/variant is used,
   - The expected max degree (used for validation and documentation),
   - Any additional preprocessing or trace-generation behaviour.

All downstream code paths (circuit builder, batch prover, recursive verifier) must use the same profile to ensure they share the same AIRs, degrees, and quotient layouts.

## 5. Soundness and Compatibility Considerations

### 5.1 Soundness

For each AIR variant, we must ensure:

- Constraints correctly encode the intended semantics (e.g. two Poseidon2 rounds, FRI fold formula).
- Maximum degree is **explicitly bounded** and propagated to:
  - `get_log_num_quotient_chunks`,
  - Quotient degree computation,
  - Recursive verifier logic.
- All AIRs used in a profile are **publicly documented** and stable.

Switching profiles must be done at a **protocol boundary** (e.g. per recursion layer), not per proof instance within the same protocol, unless the profile selection itself is part of the public input / statement being proved.

### 5.2 PCS / FRI compatibility

Higher-degree AIRs increase `quotient_degree` and thus:

- The size of the quotient domain,
- The number of quotient chunks to open and verify.

For each profile, we must check that:

- For all included AIR variants, the maximum quotient degree implied by their constraints **fits into the FRI/PCS domains** with the chosen `log_blowup` and `log_final_poly_len`.
- The recursion verifier’s domain calculations (e.g. in `recursion/src/verifier/stark.rs` and `batch_stark.rs`) remain valid.

In practice, profiles like `RecursionOptimizedKoalaBear` would:

- Be limited to max degrees (e.g. \(\le 9\)) that are compatible with existing FRI parameters,
- Possibly reuse the same `LOG_BLOWUP` and `LOG_FINAL_POLY_LEN` as Standard, but with different `get_log_num_quotient_chunks` outcomes.

## 6. Implementation Plan

### 6.1 Phase 1 – Analysis and Measurement

1. Instrument and/or summarise existing perf logs for recursion examples to extract:
   - Per-layer table row counts (Poseidon2, Witness, Add, Mul, Public, dynamic tables),
   - Approximate max constraint degrees (via `get_log_num_quotient_chunks`),
   - Quotient degrees and sizes of quotient domains.
2. Identify 1–2 **highest-impact tables** where raising max degree could significantly reduce rows:
   - Poseidon2 KoalaBear,
   - A subset of ALU / Add / Mul patterns,
   - FRI fold logic.

### 6.2 Phase 2 – First Optimised Variant and Profile

1. Design and implement a **single AIR variant** in isolation, for example:
   - Poseidon2 KoalaBear variant with a higher-degree but more compressed constraint set.
2. Introduce a minimal **ConstraintProfile** enum / struct:
   - Wire it through:
     - AIR construction in `poseidon2-circuit-air`,
     - Batch prover setup,
     - Recursive verifier AIR wrappers (e.g. `Poseidon2VerifierAir`).
3. Add tests to ensure:
   - Native proofs using the new variant verify successfully,
   - Recursive proofs using the new profile match native behaviour.

### 6.3 Phase 3 – Broader Profiles and Documentation

1. If the first variant shows clear benefits:
   - Add additional variants for ALU / Add / Mul or FRI fold,
   - Fold them into one or more **RecursionOptimized** profiles.
2. Document:
   - Which profiles exist,
   - Which AIR variants they use,
   - Their security and performance characteristics.
3. Update the book / documentation to:
   - Explain how to select profiles for different applications,
   - Provide guidance on when to use Standard vs RecursionOptimized profiles.

## 7. Open Questions

- **Per-layer vs global profiles**:
  - Should we allow different profiles per recursion layer (e.g. base, mid, top), or require a single profile for the whole recursion stack?

- **How many profiles do we want to support?**
  - Likely 2–3 carefully curated profiles, rather than many ad-hoc combinations.

- **What is the best “unit” of optimisation?**
  - Per-field (e.g. KoalaBear only),
  - Per-table (Poseidon2 only),
  - Or per logical subsystem (e.g. “FRI-optimised profile” affecting fold and MMCS tables together)?

- **Tooling for degree and quotient analysis**:
  - Do we want lightweight tooling to automatically verify degree bounds and quotient-domain compatibility for each profile, rather than relying on manual reasoning?

These questions should be resolved (or at least scoped) before committing to a specific set of profiles in the main branch.
