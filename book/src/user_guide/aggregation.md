# Aggregation

The library supports 2-to-1 recursive aggregation: verifying two proofs inside a single circuit and producing one output proof. This enables binary tree aggregation of independent computations.

## How it works

An aggregation circuit contains two verifier sub-circuits sharing the same `CircuitBuilder`. Both verifications use the same Poseidon2 table and primitive chips. The combined circuit is then proved as a single batch-STARK.

```
       ┌────────────────────────┐
       │   Aggregation Circuit  │
       │                        │
       │  ┌──────┐  ┌──────┐   │
       │  │Verify│  │Verify│   │
       │  │ left │  │right │   │
       │  └──────┘  └──────┘   │
       │                        │
       └────────────────────────┘
                  │
            One batch-STARK
               proof out
```

The left and right inputs are independent — they can be different `RecursionInput` variants (e.g., one `UniStark` and one `BatchStark`), and they can verify different AIRs entirely.

## API

```rust,ignore
use p3_recursion::{
    build_and_prove_aggregation_layer, RecursionInput, BatchOnly,
    FriRecursionBackend, ProveNextLayerParams, Poseidon2Config,
};

let left = RecursionInput::UniStark {
    proof: &proof_a, air: &air_a, public_inputs: pis_a.clone(), preprocessed_commit: None,
};
let right = RecursionInput::UniStark {
    proof: &proof_b, air: &air_b, public_inputs: pis_b.clone(), preprocessed_commit: None,
};

let backend = FriRecursionBackend::<16, 8>::new(Poseidon2Config::KOALA_BEAR_D4_W16)
    .for_extension_degree::<4>();
let params = ProveNextLayerParams::default();

let output = build_and_prove_aggregation_layer::<_, _, _, _, 4>(
    &left, &right, &config, &backend, &params,
)?;
```

The output is a regular `RecursionOutput` and can be fed into further aggregation or recursion
layers via `into_recursion_input::<BatchOnly>()`. That helper carries proof-attached values;
use `TrustedPreparedAggregation` with independently retained child verifier authority and
caller-expected statements when aggregating trusted relations.

## Composing state transitions

Use `TrustedPreparedAggregation::new_state_transition` when each trusted child proves a
transition with the exact statement schema `state_schema || state_schema || [Base]`.
Its values are ordered `[initial_state coefficients, final_state coefficients, count]`.
The constructor takes the same left and right `TrustedPreparedSource`s, output config,
backend, and parameters as `new`, plus a `StateTransitionLayout`:

```rust,ignore
use p3_circuit::StateTransitionLayout;
use p3_recursion::TrustedPreparedAggregation;

let layout = StateTransitionLayout::base(2, 4)?; // two Base state coefficients; 4 count bits
let owner = TrustedPreparedAggregation::new_state_transition(
    left_source, right_source, output_config, backend, params, layout.clone(),
)?;
let output = owner.prove(left_input, right_input)?;
```

For example, `[10, 20, 13, 26, 3]` followed by `[13, 26, 20, 40, 7]`
produces `[10, 20, 20, 40, 10]`. The merger connects **every** left final-state
coefficient to the corresponding right initial-state coefficient, adds the two
counts, and exports the left initial state, right final state, and sum. All child
schemas must equal the layout exactly, including semantic `StatementField`
boundaries. Use `StateTransitionLayout::try_new(state_schema, count_bits)` for a
state schema containing extension fields.

Counts are canonical nonnegative integers from `0` through `2^b - 1`, where
`b = count_bits`. The layout requires `2 * (2^b - 1) < p` for the base-field
modulus `p`; each child count and their sum must also fit in `b` bits. These
checks make addition an ordinary integer sum without field wraparound. Zero is
allowed; the authorized leaf relation defines what a zero-count transition means
and what the count measures. The merger only adds the counts asserted by those
child relations.

The prepared owner can prove multiple compatible pairs with different states and
counts. At each level, supply each child's proof and caller-expected statement;
retain the child verifier authority independently. The application should also
retain its own expected root statement and verify the final proof against it,
including when using a portable verifier. The same concrete base-field type is
supported across the input and output configurations of a prepared owner. The
FRI and WHIR backends each support this constructor with that field type.

`TrustedPreparedAggregation::new` still exports the ordered concatenation of
its child statements. Transition composition exports a compact statement of the
same width as one child, and its verifier has no concat-specific
`aggregation_statement_layout()` metadata. The compiled verifier relation enforces
the transition rules. See the [layout implementation](https://github.com/Plonky3/Plonky3-recursion/blob/main/circuit/src/statement.rs),
[prepared constructor](https://github.com/Plonky3/Plonky3-recursion/blob/main/recursion/src/prepared/trusted.rs),
and [two-level FRI transition test](https://github.com/Plonky3/Plonky3-recursion/blob/main/recursion/tests/artifact_recursive_roundtrip.rs)
for the API, prepared reuse, and portable root verification.

When child proofs arrive as serialized artifacts, [typed import](./integration.md#import-portable-artifacts-into-trusted-recursion)
checks each proof against an independently pinned verifier and caller-expected
statement before its `as_source()` or `as_input()` view enters a prepared owner.

## Tree aggregation

To aggregate N independent proofs, arrange them as leaves of a binary tree and aggregate pairwise, bottom up:

```
Level 0 (leaves):  P0   P1   P2   P3
                    \  /      \  /
Level 1:           Agg01    Agg23
                      \    /
Level 2 (root):      Root
```

At each level, every pair is aggregated independently — this is embarrassingly parallel.

```rust,ignore
let mut proofs: Vec<RecursionOutput<SC>> = base_proofs;

while proofs.len() > 1 {
    let mut next = Vec::new();
    for pair in proofs.chunks(2) {
        let left = pair[0].into_recursion_input::<BatchOnly>();
        let right = pair[1].into_recursion_input::<BatchOnly>();
        let out = build_and_prove_aggregation_layer::<_, _, _, _, 4>(
            &left, &right, &config, &backend, &params,
        )?;
        next.push(out);
    }
    proofs = next;
}
// proofs[0] is the root proof
```

## Cost

An aggregation circuit is roughly twice the size of a single-verification circuit (two verifiers in one circuit). The Poseidon2 table is shared, so the overhead is less than 2x for hash-heavy proofs.

Adjust `TablePacking` for aggregation circuits — they produce wider traces than single-verification circuits. See [Configuration](./configuration.md#table-packing) for guidance.
