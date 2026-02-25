# Integration Guide

This section explains how to wire Plonky3-recursion into your own project.

## Implementing `FriRecursionConfig`

The unified API requires your STARK config to implement `FriRecursionConfig`. This trait bridges your native Plonky3 config with the recursive verifier's type system.

The typical pattern is a wrapper struct that holds both the native config and the `FriVerifierParams`:

```rust,ignore
use p3_recursion::{
    FriRecursionConfig, FriVerifierParams, Poseidon2Config,
    RecursionInput, RecursiveAir, pcs::*,
};

#[derive(Clone)]
struct MyRecursionConfig {
    config: Arc<MyStarkConfig>,
    fri_verifier_params: FriVerifierParams,
}
```

### Delegate `StarkGenericConfig`

The wrapper must implement `StarkGenericConfig` by delegating to the inner config:

```rust,ignore
impl StarkGenericConfig for MyRecursionConfig {
    type Challenge = Challenge;
    type Challenger = Challenger;
    type Pcs = MyPcs;

    fn pcs(&self) -> &MyPcs { self.config.pcs() }
    fn initialise_challenger(&self) -> Challenger { self.config.initialise_challenger() }
}
```

### Implement `FriRecursionConfig`

The trait requires five associated types and four methods:

```rust,ignore
impl FriRecursionConfig for MyRecursionConfig {
    type Commitment = MerkleCapTargets<F, DIGEST_ELEMS>;
    type InputProof = InputProofTargets<F, Challenge, RecValMmcs<F, DIGEST_ELEMS, MyHash, MyCompress>>;
    type OpeningProof = FriProofTargets<...>;
    type RawOpeningProof = <MyPcs as Pcs<Challenge, Challenger>>::Proof;
    const DIGEST_ELEMS: usize = 8;

    fn with_fri_opening_proof<'a, A, R>(
        prev: &RecursionInput<'a, Self, A>,
        f: impl FnOnce(&Self::RawOpeningProof) -> R,
    ) -> R {
        match prev {
            RecursionInput::UniStark { proof, .. } => f(&proof.opening_proof),
            RecursionInput::BatchStark { proof, .. } => f(&proof.proof.opening_proof),
        }
    }

    fn enable_poseidon2_on_circuit(
        &self,
        circuit: &mut CircuitBuilder<Challenge>,
    ) -> Result<(), VerificationError> {
        let perm = default_poseidon2_perm();
        circuit.enable_poseidon2_perm::<MyPoseidon2CircuitConfig, _>(
            generate_poseidon2_trace::<Challenge, MyPoseidon2CircuitConfig>,
            perm,
        );
        Ok(())
    }

    fn pcs_verifier_params(&self) -> &FriVerifierParams {
        &self.fri_verifier_params
    }

    fn set_fri_private_data(
        runner: &mut CircuitRunner<Challenge>,
        op_ids: &[NonPrimitiveOpId],
        opening_proof: &Self::RawOpeningProof,
    ) -> Result<(), &'static str> {
        set_fri_mmcs_private_data::<F, Challenge, ChallengeMmcs, ValMmcs, MyHash, MyCompress, DIGEST_ELEMS>(
            runner, op_ids, opening_proof,
        )
    }
}
```

The concrete types (`MyHash`, `MyCompress`, `ValMmcs`, etc.) must match your native Plonky3 prover setup. See the examples for complete implementations.

## Verifying your own AIR

To recursively verify a proof produced by a custom AIR, implement `RecursiveAir` for your AIR type:

```rust,ignore
impl RecursiveAir<F, EF, LogUpGadget> for MyAir {
    fn width(&self) -> usize {
        // Number of main trace columns in your AIR
        MY_AIR_WIDTH
    }

    fn eval_folded_circuit(
        &self,
        builder: &mut CircuitBuilder<EF>,
        sels: &RecursiveLagrangeSelectors,
        alpha: &Target,
        lookup_metadata: &LookupMetadata<'_, F>,
        columns: ColumnsTargets<'_>,
        lookup_gadget: &LogUpGadget,
    ) -> Target {
        // Convert your AIR's symbolic constraints to circuit form
        // and fold them with alpha.
        // Use `symbolic_to_circuit` or build manually.
    }

    fn get_log_num_quotient_chunks(
        &self,
        preprocessed_width: usize,
        contexts: &[Lookup<F>],
        lookup_data: &[LookupData<usize>],
        is_zk: usize,
        lookup_gadget: &LogUpGadget,
    ) -> usize {
        // log2 of the number of quotient polynomial chunks.
        // Must match what the native prover uses.
    }
}
```

For AIRs built with Plonky3's `Air` trait, the symbolic constraint extraction and folding can be done generically using `get_symbolic_constraints` and `symbolic_to_circuit`, as described in [Circuit Building](./circuit_building.md#building-recursive-air-constraints).

Then wrap your proof in `RecursionInput::UniStark`:

```rust,ignore
let input = RecursionInput::UniStark {
    proof: &my_proof,
    air: &my_air,
    public_inputs: my_public_values.clone(),
    preprocessed_commit: Some(preprocessed_commitment),  // if your AIR has preprocessed columns
};
```

## Custom non-primitive chips

The circuit builder supports registering custom non-primitive operations beyond Poseidon2. These are operations that are too expensive to express purely in primitives and benefit from dedicated AIR tables.

Non-primitive operations:
- Are controlled by a runtime policy (`DefaultProfile` disables all, `AllowAllProfile` enables all)
- Require a custom trace builder for trace generation
- Interact with the witness table via lookups, and may additionally use private data

To enable a non-primitive operation, call the appropriate `enable_*` method on the `CircuitBuilder` before building. Attempting to use a non-primitive operation that hasn't been enabled will result in a runtime error.

## End-to-end integration checklist

1. Set up your Plonky3 prover config (field, hash, PCS, FRI params)
2. Create a config wrapper implementing `FriRecursionConfig`
3. If verifying a custom AIR: implement `RecursiveAir`
4. Create a `FriRecursionBackend` with matching `Poseidon2Config`
5. Choose `TablePacking` values (start with defaults, tune later)
6. Call `build_and_prove_next_layer` or the split build/prove variant
7. Chain layers with `into_recursion_input::<BatchOnly>()`
8. Verify the final proof with `BatchStarkProver::verify_all_tables`
