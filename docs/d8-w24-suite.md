# Experimental KoalaBear D8 W24 suite

Status: experimental implementation. Correctness tests do not establish security approval, performance feasibility or suitability for a deployed protocol. The suite has a distinct registry identifier and must not be substituted for an existing suite.

## Configuration

`ExperimentalKoalaBearD8Poseidon2W24RandomCodewordFri` uses degree-eight KoalaBear extension challenges, the standard width-24 Poseidon2 permutation, rate twelve, and twelve base-field digest elements. Registry identifier `0xF824` is experimental. The native random-codeword factory is `experimental_koala_bear_d8_poseidon2_w24_random_codeword`.

The recursive permutation uses 24 scalar circuit values embedded in the degree-eight extension. The witness bus constrains every extension coefficient; scalar values have seven zero coefficients. Binary compression absorbs all 24 scalar inputs and returns twelve designated scalar outputs. This representation does not permit the existing unsupported three-lane packed W24 geometry.

The challenger has a dedicated table binding its initial capacity and squeeze chain. Ordinary MMCS permutations use a separate table. Interleaved MMCS work must not alter the challenger state. Descriptor and proof artifacts preserve all twelve external digest scalars and their canonical extension encoding. Existing built-in AIR wire tags remain unchanged; scalar W24 and its challenger variant append at `0x0215` and `0x0216`. Unregistered following tags are rejected.

## Opening-batch proof of work

`FriConfigV1::with_batch_pow_bits` carries batch-work difficulty through native configuration, the recursive verifier parameters, prepared runtime witnesses and portable artifacts. Difficulty is bound into the PCS transcript seed. Proof work is checked before sampling the opening-batch challenge, with identical native and circuit transcript order. A zero-difficulty configuration requires its canonical zero witness and preserves the legacy zero-work descriptor encoding. Query and commitment work remain separate parameters. This compatibility covers native proof and descriptor encoding, not regenerated recursive circuit, verification-key or prepared-artifact identities. Rebuilding may add nonce and zero-work constraints even at zero difficulty; regenerate and freeze the resulting circuits, keys and artifact hashes instead of assuming identity with an earlier verifier.

Security analysis must justify credit for each enforced work site under the selected classical and quantum model. This implementation does not provide such approval or a composition theorem.

## Source and review boundary

The implementation builds on Plonky3 `0.9.0-rc.2`, including its existing KoalaBear degree-eight field, standard W24 permutation and native FRI batch-work implementation. The source delta is in Plonky3-recursion. Review must cover scalar coefficients, witness buses, capacity and output geometry, transcript order and domain separation, noncanonical proof rejection, suite/key/artifact binding, batch-work soundness and all full/prepared paths. Protocol-specific AIRs and parameters require separate review.

No existing suite is automatically upgraded. Consumers must pin a complete source revision and dependency lock graph, freeze the selected descriptor and verification artifacts, and run application rejection tests before selecting this suite.

## Focused regression commands

```sh
cargo test --locked --release -p p3-recursion --lib batch_pow
cargo test --locked --release -p p3-recursion --test d8_scalar_w24
cargo test --locked --release -p p3-poseidon2-circuit-air --lib scalar_w24_d8_challenger_air_binds_initial_capacity_and_squeeze_chain
cargo test --locked --release -p p3-recursion --test prepared_recursion positive_opening_batch_grinding_full_and_prepared_recursion
```

The D8 integration group covers native/circuit transcript agreement, interleaved MMCS operations, both compression directions, suite identity, base/extension statement exports, full/prepared positive-work proofs, modified witnesses and opening claims, and nonconstant scalar coefficients. Run the complete upstream required checks in addition to these focused groups.

## Hiding proof worker policy

`BatchStarkProver::with_hiding_workers` selects `HidingProofWorkers::One` or `HidingProofWorkers::Two`. Serial isolation remains the default. Two workers require the `parallel` feature; requesting them without support is rejected. The isolated pool preserves tracing context, and non-hiding proofs retain the caller's pool. The policy changes execution only and does not alter verification parameters. Any opt-in parallel hiding use requires independent review of RNG derivation and native proving code.
