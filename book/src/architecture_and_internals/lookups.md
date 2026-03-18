# Lookups and Cross-Table Lookup (CTL) Spec

This page specifies how multiset equality is enforced across all operation-specific chips via a shared witness bus, how each chip participates in the lookup argument, and how the recursive verifier checks the resulting proof data.

## The WitnessChecks bus

All chips in the recursion machine communicate through a single **virtual bus** named `WitnessChecks`. There is no physical table for this bus — it exists only as the aggregate of each chip's lookup contributions. The bus carries tuples of the form `(index, value)`, where:

- `index` is a `WitnessId` scaled by the extension degree `D` (i.e. `WitnessId * D`),
- `value` is a `D`-element extension field value (the basis coefficients of the witness slot).

A chip **sends** a tuple to the bus when it creates a witness value, and **receives** a tuple from the bus when it consumes one. The lookup argument enforces that every sent tuple is received the correct number of times, without requiring a shared table to be committed to.

## The LogUp argument

The system uses the **LogUp** accumulation scheme. For a random challenge `α` drawn after all trace commitments are observed, define the compressed row for a tuple `(idx, v[0], ..., v[D-1])` as:

```
compressed = α^0 * idx + α^1 * v[0] + ... + α^D * v[D-1]
```

Each chip row contributes a rational term `mult / (β - compressed)` to a running accumulator, where `β` is a second random challenge and `mult` is the signed multiplicity for that row:

- **Positive multiplicity** means the row is a *sender* (it writes a value onto the bus).
- **Negative multiplicity** means the row is a *receiver* (it reads a value from the bus).

The lookup argument is satisfied when the sum of all contributions across all chips and all rows equals zero:

```
Σ_{chip} Σ_{row} mult_row / (β - compressed_row) = 0
```

This is equivalent to asserting multiset equality between the multiset of all sent `(index, value)` tuples and the multiset of all received `(index, value)` tuples.

In practice, the prover computes a **permutation polynomial** (the running cumulative sum) for each lookup, commits to it, and the verifier checks the boundary condition at the last row. The permutation columns are opened during the FRI query phase alongside the main trace.

## Multiplicities and preprocessed columns

Because the circuit's IR is fixed at compile time, the `WitnessId` index for every operation is known before proving begins. This means **all index and multiplicity columns are preprocessed** — they require no online commitment and can be reconstructed by the verifier.

Each chip encodes its multiplicities differently:

### ConstAir

`ConstAir` has two preprocessed columns per row: `[multiplicity, index]`. Both the index and the value are fully preprocessed (the entire constant table is known before proving). Each row **sends** `(index, value)` with the preprocessed multiplicity, which equals the number of times that constant slot is read by other chips.

### PublicAir

`PublicAir` has two preprocessed columns per lane: `[multiplicity, index]`. For active rows the multiplicity is `+1`; for padding rows it is `0`. Each lane **sends** `(index, value)` once.

### AluAir

`AluAir` has 13 preprocessed columns per lane (see `PREP_*` constants). The lookup-relevant ones are:

| Column | Name | Value |
|--------|------|-------|
| 0 | `mult_a` | `-1` (active reader) or `0` (pad) |
| 5–8 | `a_idx`, `b_idx`, `c_idx`, `out_idx` | Preprocessed `WitnessId * D` |
| 9 | `mult_b` | `-1` (active reader) or `0` (pad) |
| 10 | `mult_out` | `+1` (active writer) or `0` (pad) |
| 11 | `a_is_reader` | `1` if `a` participates in the bus |
| 12 | `c_is_reader` | `1` if `c` participates in the bus |

Each ALU row contributes four tuples to the `WitnessChecks` bus:

- `a`: received with effective multiplicity `mult_a * a_is_reader`
- `b`: received with multiplicity `mult_b`
- `c`: received with effective multiplicity `mult_a * c_is_reader`
- `out`: sent with multiplicity `mult_out`

The `add` operation does not use `c` (it is aliased to the zero witness slot), while `mul_add` and `horner_acc` use all four operands. Double-step HornerAcc rows additionally contribute two extra lookups (`a1`, `c1`) via five global extra preprocessed columns.

### Non-primitive operations (NPOs)

Non-primitive chips such as Poseidon2 and MMCS can expose their own input/output ports on the `WitnessChecks` bus via CTL. The `out_ctl` flag on a `Poseidon2PermCall` controls which output limbs are made visible on the bus, allowing subsequent operations to read the hash outputs without committing them to the main witness table.

## The `global_lookup_data` proof field

The `BatchProof` carries a field `global_lookup_data: Vec<Vec<LookupData<F>>>`, with one inner `Vec` per table instance. Each `LookupData` entry contains:

```rust
pub struct LookupData<F> {
    /// Unique name identifying the lookup (e.g. "WitnessChecks").
    pub name: String,
    /// Index of the auxiliary permutation column for this lookup.
    pub aux_idx: usize,
    /// The expected final value of the running accumulator (committed to as a public input).
    pub expected_cumulated: F,
}
```

The `expected_cumulated` value is the boundary check: after the prover runs the LogUp accumulation to the last row, the result must match this value. The verifier checks this in circuit. Because it is committed as a **public input** of the recursive circuit, tampering with it is caught immediately during circuit execution — a `WitnessConflict` error is raised (see `test_wrong_expected_cumulated`).

The `name` field determines how the random permutation challenges (`α`, `β`) are derived from the Fiat-Shamir transcript. Changing the name of a lookup while keeping the same proof is detected as an inconsistency between the challenge generation and the opened permutation values (see `test_inconsistent_lookup_name`).

## Challenge generation

Lookup challenges are derived from the Fiat-Shamir transcript after the main trace commitment is absorbed. The generation follows this sequence:

1. Observe the main trace commitment.
2. For each named lookup, squeeze two extension field challenges (`α`, `β`) from the transcript using the lookup's `name` as domain-separation context.
3. The prover builds the permutation columns using these challenges and commits to them.
4. Observe the permutation commitment.
5. The `expected_cumulated` value is included as a public input to the recursive circuit, binding the proof to the correct permutation boundary.

The ordering of `LookupData` entries within each instance must be sorted by `aux_idx` (see `test_inconsistent_lookup_order_shape`). Mismatches in count or order cause `InvalidProofShape` errors before the recursive circuit is even built.

## Recursive verification of lookups

During recursive verification, the circuit:

1. Allocates a public input target for each `expected_cumulated` value from `global_lookup_data`.
2. Evaluates the LogUp constraint at the opened permutation values `(perm_local, perm_next)` using the lookup challenges derived in-circuit via the circuit challenger.
3. Checks that the final running sum matches the committed `expected_cumulated` value via `connect`.

Because the permutation columns are opened through the same FRI batch as the main trace, their evaluations are private inputs to the recursive circuit. The `expected_cumulated` values, being public inputs, are visible to the outer proof.

## CTL example: the toy circuit revisited

For the `37 * x - 111 = 0` example from the [Construction](./construction.md#lookups) section, the full set of `WitnessChecks` contributions is:

| Chip | Row | Tuple | mult |
|------|-----|-------|------|
| CONST | 0 | `(w0, 0)` | `+1` |
| CONST | 1 | `(w1, 37)` | `+1` |
| CONST | 2 | `(w2, 111)` | `+1` |
| PUBLIC | 0 | `(w3, x)` | `+1` |
| ALU (mul) | 0 | `(w1, 37)` | `-1` (reads `a`) |
| ALU (mul) | 0 | `(w3, x)` | `-1` (reads `b`) |
| ALU (mul) | 0 | `(w4, 111)` | `+1` (writes `out`) |
| ALU (add) | 1 | `(w2, 111)` | `-1` (reads `a`) |
| ALU (add) | 1 | `(w0, 0)` | `-1` (reads `b`) |
| ALU (add) | 1 | `(w4, 111)` | `-1` (reads `out` as final check) |

The `c` operand of the ALU `add` row reads `w4 = 111` rather than producing it, closing the constraint `37 * x = 111 + 0`. The net sum across all entries is zero iff multiset equality holds.
