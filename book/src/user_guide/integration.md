# Integration Guide

This section explains how to connect a native Plonky3 prover to recursive verification.

## Choose a native config

The 19 [built-in FRI aliases](https://github.com/Plonky3/Plonky3-recursion/blob/main/recursion/src/builtin_config/fri.rs)
implement `FriRecursionConfig`, and the two [built-in WHIR aliases](https://github.com/Plonky3/Plonky3-recursion/blob/main/recursion/src/builtin_config/whir.rs)
implement `WhirRecursionConfig`. Use a matching backend and parameters that
the recursive verifier accepts; native factory validation alone does not
establish recursive admissibility. The [built-in FRI integration](https://github.com/Plonky3/Plonky3-recursion/blob/main/recursion/src/builtin_config/fri/recursion.rs)
and [WHIR integration](https://github.com/Plonky3/Plonky3-recursion/blob/main/recursion/src/builtin_config/whir/recursion.rs)
show how each family prepares the circuit and restores opening witnesses.
For generic random-codeword and salted FRI configs, recursion and typed import
require `R: CryptoRng + SeedableRng + Send + Sync + 'static`; native factory
construction itself requires only `CryptoRng + SeedableRng`.

For a custom PCS setup outside those aliases, implement
[`FriRecursionConfig`](https://github.com/Plonky3/Plonky3-recursion/blob/main/recursion/src/backend/fri.rs)
or [`WhirRecursionConfig`](https://github.com/Plonky3/Plonky3-recursion/blob/main/recursion/src/backend/whir.rs)
on a `StarkGenericConfig` wrapper. The FRI contract supplies verifier target types, matching
FRI parameters, circuit preparation, and opening witness restoration. In particular,
`set_fri_private_data` receives the config and an `OpeningTranscript`; restore each query's
Merkle path from the proof's pruned multiproof before calling `set_fri_mmcs_private_data`.
The trait's rustdoc and the built-in implementation show the current signature and transcript
steps. Match the native prover parameters, including query count and MMCS permutation.

## Verify your AIR

AIRs implementing Plonky3's `Air` trait get a blanket `RecursiveAir` implementation from
the symbolic constraint system. If your AIR needs a manual implementation, follow the
[current `RecursiveAir` trait](https://github.com/Plonky3/Plonky3-recursion/blob/main/recursion/src/traits/air.rs), including its trace-length
and lookup-aware quotient-degree calculation. For trusted prepared uni-STARK verification,
`expected_public_input_count` must identify the fixed public-input width.

Wrap a native proof in `RecursionInput::UniStark` for one-shot recursion, or construct
`TrustedPreparedSource::UniStark` with the trusted config, AIR, and preprocessing commitment
for repeated verification. See the [compiled prelude example](https://github.com/Plonky3/Plonky3-recursion/blob/main/recursion/src/prelude.rs)
and [trusted layer tests](https://github.com/Plonky3/Plonky3-recursion/blob/main/recursion/tests/prepared_layer.rs) for the prepared contract.
Use `FriRecursionBackend::new(challenger_config).for_extension_degree::<D>()` for a
matching binomial extension, `FriRecursionBackend::new_d5` for a KoalaBear
quintic suite, or `WhirRecursionBackend::new(...).for_extension_degree::<D>()`
for WHIR, where D is 2 or 4 and matches the input's actual challenge dimension.
See [backend selection](./configuration.md#choosing-a-built-in-recursion-backend).

## Import portable artifacts into trusted recursion

Use `TypedArtifactVerifier<SC>` when a serialized verifier and proof must enter a
`TrustedPreparedLayer` or `TrustedPreparedAggregation`. Provision the expected
verifier bytes through an independent trusted channel, choose the matching
application-owned native `SC` configuration, and set `ArtifactLimits`. The
candidate verifier must match the pinned bytes exactly and its complete built-in
configuration descriptor must match the supplied configuration; matching only
the field or suite is insufficient. The sealed `PortableArtifactImport` trait
exposes this import for supported built-in configurations. The
[typed importer](https://github.com/Plonky3/Plonky3-recursion/blob/main/recursion/src/artifact/mod.rs)
keeps that configuration and those limits for subsequent proof imports.

```rust,ignore
use p3_recursion::artifact::{
    ArtifactLimits, CanonicalStatement, ExpectedVerifierArtifact,
    PortableArtifactImport, TypedArtifactVerifier,
};

let authority = TypedArtifactVerifier::<Config>::decode_with_config(
    app_config,
    candidate_verifier_bytes,
    ExpectedVerifierArtifact::from_trusted_bytes(pinned_verifier_bytes),
    ArtifactLimits::default(),
)?;
let verified = authority.import_proof(
    proof_bytes,
    CanonicalStatement::new(expected_statement_bytes, statement_width),
)?;
```

Encode expected values as canonical base-field coefficients in schema order:
little-endian 4-byte words for BabyBear/KoalaBear or 8-byte words for
Goldilocks, with `statement_width == authority.schema().base_len()`. The
`CanonicalStatement` bytes have no length prefix.

The application supplies `expected_statement_bytes` independently of the proof
attachment. `import_proof` decodes under the retained limits and verifies the
native proof against that expected statement before returning a
`VerifiedArtifactProof<SC>`. Its `statement()` and `trusted_identity_bytes()`
accessors report the checked statement and pinned identity. `as_source()` supplies
the retained verifier authority and a representative proof when preparing a
trusted owner; `as_input()` supplies a proof and expected statement for a
compatible prepared owner's `prove` call. The destination owner still checks
its own retained relation and input contract. Imported proofs own their native
data and remain usable after the input byte buffers and importer are dropped.

The caller-supplied configuration matters for hiding suites: typed import
retains its application-controlled RNG setup. Salted FRI path restoration may
construct a private, fixed-seed MMCS helper for verification; it draws no
randomness and is not exposed as the proving configuration. `PortableVerifier`
can verify encoded proofs but does not expose a native configuration or proving
authority. Typed import supports the library's built-in artifact codecs; the
19 FRI and two WHIR aliases have
corresponding direct recursion integrations for admissible parameters. An output proving
configuration and backend are selected separately when constructing the trusted
prepared owner. See [configuration support](./configuration.md#built-in-native-configuration-suites)
and [transition aggregation](./aggregation.md#composing-state-transitions).

The [portable aggregation example](https://github.com/Plonky3/Plonky3-recursion/blob/main/recursion/examples/portable_aggregation.rs)
runs trusted setup, proof production, aggregation, and final verification in
separate processes:

```sh
cargo run --locked --release -p p3-recursion --example portable_aggregation -- setup --trusted-dir ./demo-auth
cargo run --locked --release -p p3-recursion --example portable_aggregation -- produce --out-dir ./demo-children
cargo run --locked --release -p p3-recursion --example portable_aggregation -- aggregate --trusted-dir ./demo-auth --children-dir ./demo-children --out-dir ./demo-root
cargo run --locked --release -p p3-recursion --example portable_aggregation -- verify --trusted-dir ./demo-auth --root-dir ./demo-root --expected 10,20,20,40,10
```

Run with fresh output directories. Setup provisions `demo-auth/leaf.verifier`
and `demo-auth/root.verifier` from a separate valid fixture, before the producer
artifacts are consumed; it does not produce the root proof. The producer writes
`demo-children/leaf.verifier` and four `leaf-0.proof` through `leaf-3.proof`
payloads. Aggregation checks the child verifier against the trusted leaf pin,
imports all four proofs with independently specified statements, reuses one
prepared owner for both first-level pairs, and checks its emitted
`demo-root/root.verifier` against the trusted root pin. Verification reads
`demo-root/root.proof` and uses the `--expected` state and count supplied by
the caller. The producer's verifier and attached proof statements are payload
data; neither establishes the trusted identity or expected root. The example's
small FRI settings are for demonstration and testing. Production parameters
require separately provisioned trusted verifier artifacts.

## Custom non-primitive chips

Custom non-primitive operations must be enabled on the `CircuitBuilder` before use. They
need matching trace generation, preprocessing, AIR builders, and table provers. The
[`PcsRecursionBackend` interface](https://github.com/Plonky3/Plonky3-recursion/blob/main/recursion/src/recursion.rs) supplies the
preprocessor, AIR-builder, and table-prover registration hooks. Prepared owners reuse that
backend through the [prepared contract](https://github.com/Plonky3/Plonky3-recursion/blob/main/recursion/src/prepared/mod.rs).

## Integration checklist

1. Choose a directly integrated built-in suite and matching backend, or implement the recursive PCS contract for a custom config.
2. Supply an AIR with a `RecursiveAir` implementation and fixed public-input width when using a trusted owner.
3. Choose a backend with the matching field, permutation, and extension degree.
4. Use a prepared owner for reuse; choose a trusted prepared owner when relation and statement authority must be fixed.
5. Verify output against an independently retained `CircuitVerifier` and caller-expected statement.
