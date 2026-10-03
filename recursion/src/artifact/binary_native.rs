//! Factory-owned native binary proof authority with a frozen recursive relation.

pub(crate) mod codec;
mod boolean;
mod boolean_whir;
pub use boolean::{
    BinaryNativeBooleanTraceAuthority, BinaryNativeBooleanTraceProver,
    VerifiedBinaryNativeBooleanTraceProof,
};
pub use boolean_whir::{
    BinaryNativeBooleanWhirTraceAuthority, BinaryNativeBooleanWhirTraceProver,
    VerifiedBinaryNativeBooleanWhirTraceProof,
};
mod config;
mod family;
mod grouped;
mod grouped_boolean;
pub use grouped::{
    BinaryNativeGroupedAuthority, BinaryNativeGroupedPcsParameters, BinaryNativeGroupedProver,
    BinaryNativeGroupedVerifierSpec, VerifiedBinaryNativeGroupedProof,
};
pub use grouped_boolean::{
    BinaryNativeGroupedBooleanTraceAuthority, BinaryNativeGroupedBooleanTraceProver,
    VerifiedBinaryNativeGroupedBooleanTraceProof,
};
mod lifecycle;
mod whir;
pub use whir::{BinaryNativeWhirAuthority, BinaryNativeWhirProver, VerifiedBinaryNativeWhirProof};
pub use codec::CanonicalBinaryStatement;
use family::{NativeFamily, RawFamily};
use lifecycle::State;

use alloc::sync::Arc;
use alloc::vec::Vec;

use p3_binary_dft::EncodableLevel;
use p3_binary_pcs::{BinaryPcsConfig, ChallengeField, FoldAlphabet};
use p3_circuit::ops::ByteHash;
use p3_field::{ExtensionField, PackedValue};
use p3_matrix::dense::RowMajorMatrix;
use p3_merkle_tree::MerkleCap;
use p3_multi_stark::folder::{ProverAir, VerifierAir};
use p3_multi_stark::{MultiStarkProof, ProvingKey};

use super::wire::{Writer, encode_framed};
use super::{ArtifactError, ArtifactKind, ArtifactLimits};
use crate::pcs::binary::{RecursiveBinaryChallengeField, RecursiveBinaryTowerField};
use crate::verifier::{
    BinaryMultiStarkPreprocessing, BinaryMultiStarkVerifier, InputResourceUsage,
    NativeBinaryMultiStarkInput, VerificationError, VerifierLimits,
};
pub use config::{
    BinaryNativeBooleanWhirTraceConfig,
    BinaryNativeBooleanTraceConfig, BinaryNativeChallenger, BinaryNativeConfig, BinaryNativeGroupedBooleanTraceConfig,
    BinaryNativeGroupedConfig, BinaryNativeHash,
    BinaryNativeWhirConfig, BinaryNativeWhirLayout, BinaryNativeWhirPcsParameters,
};
use config::{NativeMmcs, tree};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BinaryNativePcsParameters {
    pub config: BinaryPcsConfig,
    pub hash: ByteHash,
    pub cap_height: usize,
    pub max_query_draws: usize,
}

/// Trusted cryptographic choices, exact transcript prefix and finite sampling
/// budgets. `security_bits` is the minimum for the entire native AIR statement,
/// including its reductions, both opening sites and the closed hashes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BinaryNativeVerifierSpec<P = BinaryNativePcsParameters> {
    pub main: P,
    pub preprocessed: Option<P>,
    pub transcript_hash: ByteHash,
    pub initial_bytes: Vec<u8>,
    pub sumcheck_pow_bits: usize,
    pub max_tau_draws: usize,
    pub security_bits: usize,
}

/// Owned trusted AIRs, matched native verifying key, closed cryptography and
/// frozen recursive plan. Construction receives no representative proof.
pub struct BinaryNativeAuthority<F, E, A>
where
    F: RecursiveBinaryTowerField + EncodableLevel + FoldAlphabet<E> + PackedValue<Value = F>,
    E: RecursiveBinaryChallengeField
        + ExtensionField<F>
        + ChallengeField<F>
        + FoldAlphabet<E>
        + PackedValue<Value = E>,
{
    state: Arc<State<F, E, A>>,
}

impl<F, E, A> Clone for BinaryNativeAuthority<F, E, A>
where
    F: RecursiveBinaryTowerField + EncodableLevel + FoldAlphabet<E> + PackedValue<Value = F>,
    E: RecursiveBinaryChallengeField
        + ExtensionField<F>
        + ChallengeField<F>
        + FoldAlphabet<E>
        + PackedValue<Value = E>,
{
    fn clone(&self) -> Self {
        Self {
            state: self.state.clone(),
        }
    }
}

pub struct BinaryNativeProver<F, E, A>
where
    F: RecursiveBinaryTowerField + EncodableLevel + FoldAlphabet<E> + PackedValue<Value = F>,
    E: RecursiveBinaryChallengeField
        + ExtensionField<F>
        + ChallengeField<F>
        + FoldAlphabet<E>
        + PackedValue<Value = E>,
{
    state: Arc<State<F, E, A>>,
    key: ProvingKey<BinaryNativeConfig<F, E>>,
}

/// Created only after bounded replay and complete native verification under
/// retained authority. Its statement is the independently supplied statement.
pub struct VerifiedBinaryNativeProof<F, E>
where
    F: RecursiveBinaryTowerField,
    E: RecursiveBinaryChallengeField,
{
    pub(crate) identity: Arc<[u8]>,
    pub(crate) input: NativeBinaryMultiStarkInput<F, E>,
    pub(crate) public: Vec<Vec<F>>,
}

impl<F: RecursiveBinaryTowerField, E: RecursiveBinaryChallengeField>
    VerifiedBinaryNativeProof<F, E>
{
    pub fn canonical_verifier_bytes(&self) -> &[u8] {
        &self.identity
    }
    pub fn native_input(&self) -> &NativeBinaryMultiStarkInput<F, E> {
        &self.input
    }
    pub fn public_values(&self) -> &[Vec<F>] {
        &self.public
    }
}

impl<F, E, A> BinaryNativeAuthority<F, E, A>
where
    F: RecursiveBinaryTowerField + EncodableLevel + FoldAlphabet<E> + PackedValue<Value = F>,
    E: RecursiveBinaryChallengeField
        + ExtensionField<F>
        + ChallengeField<F>
        + FoldAlphabet<E>
        + PackedValue<Value = E>,
    A: VerifierAir<F, E>,
{
    pub fn setup(
        airs: Vec<A>,
        heights: Vec<usize>,
        spec: BinaryNativeVerifierSpec,
        limits: &VerifierLimits,
    ) -> Result<(BinaryNativeProver<F, E, A>, Self), VerificationError> {
        Self::setup_with_artifact_limits(
            airs,
            heights,
            spec,
            ArtifactLimits {
                verifier: *limits,
                ..ArtifactLimits::default()
            },
        )
    }

    pub fn setup_with_artifact_limits(
        airs: Vec<A>,
        heights: Vec<usize>,
        spec: BinaryNativeVerifierSpec,
        limits: ArtifactLimits,
    ) -> Result<(BinaryNativeProver<F, E, A>, Self), VerificationError> {
        let (state, proving) = lifecycle::setup::<F, E, A, RawFamily>(airs, heights, spec, limits)?;
        Ok((
            BinaryNativeProver {
                state: state.clone(),
                key: proving,
            },
            Self { state },
        ))
    }

    pub fn canonical_verifier_bytes(&self) -> &[u8] {
        &self.state.identity
    }
    pub(crate) fn shared_identity(&self) -> Arc<[u8]> {
        self.state.identity.clone()
    }
    pub fn artifact_limits(&self) -> &ArtifactLimits {
        &self.state.limits
    }
    pub fn recursive_verifier(&self) -> &BinaryMultiStarkVerifier<F, E> {
        &self.state.binary
    }
    pub fn transcript_hash(&self) -> ByteHash {
        self.state.spec.transcript_hash
    }
    pub fn initial_bytes(&self) -> &[u8] {
        &self.state.spec.initial_bytes
    }

    /// The independent statement is checked before bounded replay. Only after
    /// replay succeeds can the full native verifier invoke its unbounded query
    /// sampler; identical transcript state has already fit the retained budget.
    pub fn verify_native(
        &self,
        proof: &MultiStarkProof<BinaryNativeConfig<F, E>>,
        expected: &[Vec<F>],
    ) -> Result<VerifiedBinaryNativeProof<F, E>, VerificationError> {
        let input = self.state.verify_native(proof, expected)?;
        Ok(VerifiedBinaryNativeProof {
            identity: self.state.identity.clone(),
            input,
            public: expected.to_vec(),
        })
    }
}

impl<F, E, A> BinaryNativeProver<F, E, A>
where
    F: RecursiveBinaryTowerField + EncodableLevel + FoldAlphabet<E> + PackedValue<Value = F>,
    E: RecursiveBinaryChallengeField
        + ExtensionField<F>
        + ChallengeField<F>
        + FoldAlphabet<E>
        + PackedValue<Value = E>,
    A: ProverAir<F, E>,
    E::ExtensionPacking: From<E> + From<F::Packing>,
{
    /// Trace matrices have ordinary row-major AIR order. Shape checks precede
    /// transpose, commitment, grinding or any transcript mutation.
    pub fn prove(
        &self,
        public: &[Vec<F>],
        traces: Vec<RowMajorMatrix<F>>,
    ) -> Result<MultiStarkProof<BinaryNativeConfig<F, E>>, VerificationError> {
        self.state.prove(&self.key, public, traces)
    }
}

fn write_hash(w: &mut Writer, hash: ByteHash) -> Result<(), ArtifactError> {
    w.write_u8(match hash {
        ByteHash::Keccak256 => 1,
        ByteHash::Blake3 => 2,
    })
}
fn write_pcs(w: &mut Writer, pcs: BinaryNativePcsParameters) -> Result<(), ArtifactError> {
    for count in [
        pcs.config.num_variables(),
        pcs.config.log_inv_rate(),
        pcs.config.log_folding_factor(),
        pcs.config.pow_bits(),
        pcs.config.security_level(),
        pcs.config.num_queries(),
        pcs.cap_height,
        pcs.max_query_draws,
    ] {
        w.write_count("binary native PCS parameters", count)?;
    }
    write_hash(w, pcs.hash)
}
fn field_suite<F: RecursiveBinaryTowerField, E: RecursiveBinaryChallengeField>() -> u16 {
    let f_tag = match F::RAW_BITS {
        8 => 1,
        16 => 2,
        32 => 3,
        64 => 4,
        128 => 5,
        _ => unreachable!("sealed tower field"),
    };
    let e_tag = match E::RAW_BITS {
        64 => 1,
        128 => 2,
        _ => unreachable!("sealed challenge field"),
    };
    0xb000 | (f_tag << 4) | e_tag
}
fn identity<F, E, K>(
    binary: &K::Recursive,
    spec: &BinaryNativeVerifierSpec<K::Parameters>,
    limits: &ArtifactLimits,
) -> Result<Vec<u8>, ArtifactError>
where
    F: RecursiveBinaryTowerField + EncodableLevel + FoldAlphabet<E> + PackedValue<Value = F>,
    E: RecursiveBinaryChallengeField
        + ExtensionField<F>
        + ChallengeField<F>
        + FoldAlphabet<E>
        + PackedValue<Value = E>,
    K: NativeFamily<F, E>,
{
    encode_framed(
        ArtifactKind::Verifier,
        K::suite(),
        limits.max_verifier_bytes,
        |w| {
            w.write_u16(1)?; // Binary relation revision, including native 0.8 transcript/layout rules.
            K::write_parameters(w, &spec.main)?;
            w.write_bool(spec.preprocessed.is_some())?;
            if let Some(pp) = &spec.preprocessed {
                K::write_parameters(w, pp)?;
            }
            write_hash(w, spec.transcript_hash)?;
            w.write_vec(
                "binary native initial transcript",
                &spec.initial_bytes,
                |w, &byte| w.write_u8(byte),
            )?;
            for count in [
                spec.sumcheck_pow_bits,
                spec.max_tau_draws,
                spec.security_bits,
            ] {
                w.write_count("binary native reduction parameters", count)?;
            }
            let policy = limits.verifier;
            for count in [
                policy.max_instances,
                policy.max_rounds,
                policy.max_queries_per_round,
                policy.max_log_domain_or_degree,
                policy.max_matrix_width,
                policy.max_final_poly_evaluations,
                policy.max_cap_roots,
                policy.max_total_scalar_elements,
                policy.max_metadata_entries,
                policy.max_metadata_string_bytes,
                policy.max_compressed_frontier_hashes,
                policy.max_restored_authentication_path_hashes,
            ] {
                w.write_u64(u64::try_from(count).map_err(|_| ArtifactError::LengthOverflow)?)?;
            }
            K::write_shape(w, binary)
        },
    )
}
fn identity_error(error: ArtifactError) -> VerificationError {
    match error {
        ArtifactError::DecodeLimitExceeded {
            component,
            actual,
            limit,
        } => VerificationError::ResourceLimitExceeded {
            component,
            actual,
            limit,
        },
        ArtifactError::LengthOverflow => VerificationError::ResourceArithmeticOverflow {
            component: "binary native verifier identity",
        },
        _ => invalid("binary native verifier identity allocation failed"),
    }
}
fn invalid(message: &'static str) -> VerificationError {
    VerificationError::InvalidProofShape(message.into())
}
