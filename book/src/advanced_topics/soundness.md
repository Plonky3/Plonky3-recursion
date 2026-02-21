# Soundness and Security

This section describes the security model, current guarantees, and known limitations.

## What is proven

A recursive proof attests that:

1. The original computation (base layer) was executed correctly according to the AIR constraints.
2. Each intermediate STARK verification was performed correctly: commitments were checked, FRI queries were sampled from the transcript, Merkle paths were verified, and polynomial evaluations matched.
3. The Fiat-Shamir transcript was computed consistently — the circuit challenger produces identical challenges to the native Plonky3 challenger given the same observations.

## Security parameters

FRI soundness depends on several parameters working together. However, it is not generally correct to model security as
“`num_queries × log_blowup` bits”. That heuristic relied on strong proximity-gap / correlated-agreement assumptions
that are no longer believed to hold in full generality. See for instance:

- https://eprint.iacr.org/2025/2010
- https://eprint.iacr.org/2025/2046

Instead, the soundness error must be derived from a *proven bound* for the specific FRI variant and parameter regime
being used.

| Parameter | Role |
|-----------|------|
| `log_blowup` | Sets the Reed–Solomon code rate (blowup factor). This affects the code distance and proximity gap, but does **not** directly translate into a fixed number of “bits per query”. |
| `num_queries` | Number of independent FRI consistency checks. Increasing this reduces soundness error according to the *actual* FRI soundness bound being used. |
| `query_pow_bits` | Proof-of-work grinding. Adds `query_pow_bits` bits of security independently of the code-theoretic soundness term. |

Let:

    ε_FRI = soundness error derived from the relevant FRI theorem/bound
            (depends on blowup, proximity parameter δ, domain size,
             field size, and list-decodability/proximity-gap behavior)

Then the security level should be expressed as:

    security ≈ -log2(ε_FRI) + query_pow_bits

Crucially, `-log2(ε_FRI)` must be computed from a proven soundness bound for the specific FRI configuration.
It should not be replaced by `num_queries × log_blowup` unless an additional (explicitly stated)
conjectural assumption is being made.

With defaults (`num_queries = 28`, `log_blowup = 3`, `query_pow_bits = 16`),
the correct security level depends on the concrete bound used to evaluate ε_FRI.
The value “100 bits” cannot be justified purely from 28 × 3 + 16 without further assumptions.

## Cryptographic components verified in-circuit

### Merkle tree verification

Every MMCS opening proof (Merkle path) is verified in-circuit via Poseidon2 hashing. The circuit:
- Hashes sibling pairs up the tree
- Checks that the reconstructed root matches the committed root (a public input)
- Handles position-dependent ordering (left vs right sibling)

### FRI verification

The circuit performs the full FRI verification protocol:
- Samples folding challenges (beta) from the transcript
- Samples query indices from the transcript
- Verifies proof-of-work witnesses
- Checks the fold chain: at each FRI round, verifies that the folded polynomial evaluations are consistent with the committed Merkle trees
- Evaluates and checks the final polynomial

### Fiat-Shamir challenger

The circuit challenger implements a duplex sponge construction identical to Plonky3's native `DuplexChallenger`. It absorbs commitments and opened values in the same order as the native verifier, producing identical challenges. See [Hashing and Fiat-Shamir](./hashing.md) for details on transcript compatibility.

## Current limitations

### Non-ZK mode only

The library currently supports only non-ZK STARKs (`config.is_zk() == 0`). The recursive verifier does not handle zero-knowledge randomization of traces.

### Challenger Poseidon2: witness hints

The Fiat-Shamir challenger's Poseidon2 permutations are currently computed via **witness hints**: the prover provides the correct output as a witness, and the circuit constrains input/output consistency.

This is sound **only if** the witness is honestly generated. For full cryptographic soundness, each challenger Poseidon2 call should be connected to the Poseidon2 AIR table via cross-table lookups (CTLs), which would enforce that the permutation was actually computed by the Poseidon2 chip. This is planned but not yet implemented.

The MMCS Poseidon2 calls (Merkle verification) *are* connected to the Poseidon2 AIR via CTLs.

### Fixed Poseidon2 parameters

The recursion stack currently requires `WIDTH = 16` and `RATE = 8` for 32-bit fields with degree-4 extensions. Future versions will support configurable parameters.

## Verifier trust model

| Component | How it's verified |
|-----------|------------------|
| Commitment openings | Merkle path verification (Poseidon2, CTL-enforced) |
| FRI fold chain | Algebraic consistency checks in-circuit |
| FRI query indices | Sampled in-circuit from transcript |
| Proof-of-work | Verified in-circuit |
| Fiat-Shamir challenges | Circuit challenger (witness hints, CTLs planned) |
| AIR constraint satisfaction | Evaluated in-circuit via symbolic-to-circuit translation |
| Lookup argument | LogUp verification in-circuit |
