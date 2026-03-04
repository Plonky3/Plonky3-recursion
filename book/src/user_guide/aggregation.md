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

let backend = FriRecursionBackend::<16, 8>::new(Poseidon2Config::KoalaBearD4Width16);
let params = ProveNextLayerParams::default();

let output = build_and_prove_aggregation_layer::<_, _, _, _, 4>(
    &left, &right, &config, &backend, &params,
)?;
```

The output is a regular `RecursionOutput` and can be fed into further aggregation or recursion layers via `into_recursion_input::<BatchOnly>()`.

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
