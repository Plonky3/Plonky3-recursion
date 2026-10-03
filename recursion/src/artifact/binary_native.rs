//! Factory-owned native binary proof authority with a frozen recursive relation.

pub(crate) mod codec;
mod config;
pub use codec::CanonicalBinaryStatement;

use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;

use p3_binary_dft::EncodableLevel;
use p3_binary_pcs::{BinaryPcs, BinaryPcsConfig, ChallengeField, FoldAlphabet};
use p3_circuit::ops::ByteHash;
use p3_field::{ExtensionField, PackedValue};
use p3_matrix::{Matrix, dense::RowMajorMatrix};
use p3_merkle_tree::MerkleCap;
use p3_multi_stark::folder::{ProverAir, VerifierAir};
use p3_multi_stark::{
    MultiStarkProof, ProverInstance, ProverInstances, ProvingKey, VerifierInstance,
    VerifierInstances, VerifyingKey,
};
use p3_sumcheck::layout::Table;

use super::wire::{Writer, encode_framed};
use super::{ArtifactError, ArtifactKind, ArtifactLimits};
use crate::pcs::binary::{RecursiveBinaryChallengeField, RecursiveBinaryTowerField};
use crate::verifier::{
    BinaryMultiStarkPreprocessing, BinaryMultiStarkVerifier, InputResourceUsage,
    NativeBinaryMultiStarkInput, VerificationError, VerifierLimits,
};
pub use config::{BinaryNativeChallenger, BinaryNativeConfig, BinaryNativeHash};
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
pub struct BinaryNativeVerifierSpec {
    pub main: BinaryNativePcsParameters,
    pub preprocessed: Option<BinaryNativePcsParameters>,
    pub transcript_hash: ByteHash,
    pub initial_bytes: Vec<u8>,
    pub sumcheck_pow_bits: usize,
    pub max_tau_draws: usize,
    pub security_bits: usize,
}

struct State<F, E, A>
where
    F: RecursiveBinaryTowerField + EncodableLevel + FoldAlphabet<E> + PackedValue<Value = F>,
    E: RecursiveBinaryChallengeField
        + ExtensionField<F>
        + ChallengeField<F>
        + FoldAlphabet<E>
        + PackedValue<Value = E>,
{
    config: BinaryNativeConfig<F, E>,
    airs: Box<[A]>,
    heights: Box<[usize]>,
    key: VerifyingKey<BinaryNativeConfig<F, E>>,
    pub(super) binary: BinaryMultiStarkVerifier<F, E>,
    spec: BinaryNativeVerifierSpec,
    identity: Arc<[u8]>,
    limits: ArtifactLimits,
    base: NativeMmcs<F>,
    round: NativeMmcs<E>,
    preprocessed: Option<(NativeMmcs<F>, NativeMmcs<E>)>,
    decode: codec::MultiDecode,
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
        let mut usage = InputResourceUsage::default();
        usage.add_instances(&limits.verifier, airs.len())?;
        usage.add_metadata_entries(&limits.verifier, spec.initial_bytes.len())?;
        if spec.security_bits == 0 || spec.security_bits > 128 {
            return Err(invalid(
                "binary native security target must be within 1..=128",
            ));
        }
        let grind_limit = F::RAW_BITS
            .min(64)
            .saturating_sub(8)
            .min(usize::BITS as usize - 1);
        for bits in core::iter::once(spec.sumcheck_pow_bits)
            .chain(core::iter::once(spec.main.config.pow_bits()))
            .chain(spec.preprocessed.iter().map(|pp| pp.config.pow_bits()))
        {
            if bits > grind_limit {
                return Err(VerificationError::ResourceLimitExceeded {
                    component: "binary native grinding bits",
                    actual: bits,
                    limit: grind_limit,
                });
            }
        }
        let refs = airs.iter().collect::<Vec<_>>();
        let roots = if let Some(pp) = spec.preprocessed {
            if pp.cap_height >= usize::BITS as usize {
                return Err(invalid("binary native preprocessing cap shift is invalid"));
            }
            let roots = 1usize << pp.cap_height;
            usage.add_cap_roots(&limits.verifier, roots)?;
            usage.add_scalar_elements(
                &limits.verifier,
                roots
                    .checked_mul(16)
                    .ok_or(VerificationError::ResourceArithmeticOverflow {
                        component: "binary native preprocessing cap",
                    })?,
            )?;
            roots
        } else {
            0
        };
        let main = spec.main;
        let mut binary = if let Some(pp) = spec.preprocessed {
            BinaryMultiStarkVerifier::with_preprocessing(
                &refs,
                &heights,
                main.config,
                main.hash,
                main.cap_height,
                spec.sumcheck_pow_bits,
                spec.max_tau_draws,
                main.max_query_draws,
                BinaryMultiStarkPreprocessing {
                    config: pp.config,
                    hash: pp.hash,
                    cap_height: pp.cap_height,
                    max_query_draws: pp.max_query_draws,
                    commitment: MerkleCap::new(vec![[0; 32]; roots]),
                },
                &limits.verifier,
            )?
        } else {
            BinaryMultiStarkVerifier::with_limits(
                &refs,
                &heights,
                main.config,
                main.hash,
                main.cap_height,
                spec.sumcheck_pow_bits,
                spec.max_tau_draws,
                main.max_query_draws,
                &limits.verifier,
            )?
        };
        let mut total_usage = binary.input_resource_usage();
        total_usage.add_metadata_entries(&limits.verifier, spec.initial_bytes.len())?;
        // Setup's public native entry panics on a missing preprocessing table.
        // Validate the trusted tables and heights before invoking that entry.
        for (air, &height) in airs.iter().zip(&heights) {
            if air.preprocessed_width() != 0 {
                let trace = air.preprocessed_trace().ok_or_else(|| {
                    invalid("binary native AIR is missing its preprocessed trace")
                })?;
                if trace.width() != air.preprocessed_width() || trace.height() != 1usize << height {
                    return Err(invalid("binary native preprocessed trace shape mismatch"));
                }
            }
        }
        let base = tree(main.hash, main.cap_height);
        let round = tree(main.hash, main.cap_height);
        let preprocessed = spec
            .preprocessed
            .map(|pp| (tree(pp.hash, pp.cap_height), tree(pp.hash, pp.cap_height)));
        let config = BinaryNativeConfig {
            main: BinaryPcs::new(main.config, base.clone(), round.clone())
                .map_err(|_| invalid("binary native main PCS configuration rejected"))?,
            preprocessed: spec
                .preprocessed
                .zip(preprocessed.as_ref())
                .map(|(pp, (base, round))| {
                    BinaryPcs::new(pp.config, base.clone(), round.clone()).map_err(|_| {
                        invalid("binary native preprocessing PCS configuration rejected")
                    })
                })
                .transpose()?,
        };
        let mut setup_ch = BinaryNativeChallenger::for_setup(roots, spec.transcript_hash);
        let (proving, verifying) = p3_multi_stark::setup(&config, &refs, &mut setup_ch)
            .map_err(|_| invalid("binary native setup rejected"))?;
        if let Some(cap) = setup_ch.finish_setup(roots)? {
            binary.bind_native_preprocessing_cap(cap)?;
        }
        let public = binary
            .input_shape()
            .public_value_counts()
            .map(|count| vec![F::ZERO; count])
            .collect::<Vec<_>>();
        let instances = VerifierInstances::new(
            airs.iter()
                .zip(&heights)
                .zip(&public)
                .map(|((air, &height), public)| {
                    VerifierInstance::new(air, &verifying, height, public)
                })
                .collect(),
        );
        p3_multi_stark::security_report(&config, &instances)
            .and_then(|report| report.require_security(spec.security_bits))
            .map_err(|_| invalid("binary native statement security target is not met"))?;
        let identity = identity::<F, E>(&binary, &spec, &limits)
            .map_err(identity_error)?
            .into_boxed_slice();
        let decode = binary.input_shape().native_decode_shape();
        let state = Arc::new(State {
            config,
            airs: airs.into_boxed_slice(),
            heights: heights.into_boxed_slice(),
            key: verifying,
            binary,
            spec,
            identity: Arc::from(identity),
            limits,
            base,
            round,
            preprocessed,
            decode,
        });
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
        self.state.check_public(expected)?;
        let input = self.state.binary.import_native_with_preprocessing(
            &self.state.base,
            &self.state.round,
            self.state
                .preprocessed
                .as_ref()
                .map(|(base, round)| (base, round)),
            expected,
            proof,
            &mut self.state.challenger(),
        )?;
        let instances = VerifierInstances::new(
            self.state
                .airs
                .iter()
                .zip(self.state.heights.iter())
                .zip(expected)
                .map(|((air, &height), public)| {
                    VerifierInstance::new(air, &self.state.key, height, public)
                })
                .collect(),
        );
        p3_multi_stark::verify_with_security(
            &self.state.config,
            instances,
            proof,
            self.state.spec.sumcheck_pow_bits,
            self.state.spec.security_bits,
            &mut self.state.challenger(),
        )
        .map_err(|_| invalid("binary native proof verification rejected"))?;
        Ok(VerifiedBinaryNativeProof {
            identity: self.state.identity.clone(),
            input,
            public: expected.to_vec(),
        })
    }
}

impl<F, E, A> State<F, E, A>
where
    F: RecursiveBinaryTowerField + EncodableLevel + FoldAlphabet<E> + PackedValue<Value = F>,
    E: RecursiveBinaryChallengeField
        + ExtensionField<F>
        + ChallengeField<F>
        + FoldAlphabet<E>
        + PackedValue<Value = E>,
{
    fn challenger(&self) -> BinaryNativeChallenger<F> {
        BinaryNativeChallenger::fresh(self.spec.initial_bytes.clone(), self.spec.transcript_hash)
    }
    fn check_public(&self, public: &[Vec<F>]) -> Result<(), VerificationError> {
        let shape = self.binary.input_shape();
        if public.len() != self.airs.len()
            || public
                .iter()
                .zip(shape.public_value_counts())
                .any(|(values, count)| values.len() != count)
        {
            return Err(invalid(
                "binary native independent statement shape mismatch",
            ));
        }
        Ok(())
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
        self.state.check_public(public)?;
        if traces.len() != self.state.airs.len()
            || traces
                .iter()
                .zip(self.state.airs.iter())
                .zip(self.state.heights.iter())
                .any(|((trace, air), &height)| {
                    trace.width() != air.width() || trace.height() != 1usize << height
                })
        {
            return Err(invalid("binary native main trace shape mismatch"));
        }
        let instances = ProverInstances::new(
            traces
                .into_iter()
                .zip(self.state.airs.iter())
                .zip(public)
                .map(|((trace, air), values)| {
                    ProverInstance::new(air, Table::new(trace.transpose()), &self.key, values)
                })
                .collect(),
        );
        p3_multi_stark::prove_with_security(
            &self.state.config,
            instances,
            self.state.spec.sumcheck_pow_bits,
            self.state.spec.security_bits,
            &mut self.state.challenger(),
        )
        .map_err(|_| invalid("binary native proof generation rejected"))
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
fn identity<F, E>(
    binary: &BinaryMultiStarkVerifier<F, E>,
    spec: &BinaryNativeVerifierSpec,
    limits: &ArtifactLimits,
) -> Result<Vec<u8>, ArtifactError>
where
    F: RecursiveBinaryTowerField,
    E: RecursiveBinaryChallengeField + ExtensionField<F>,
{
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
    encode_framed(
        ArtifactKind::Verifier,
        0xb000 | (f_tag << 4) | e_tag,
        limits.max_verifier_bytes,
        |w| {
            w.write_u16(1)?; // Binary relation revision, including native 0.8 transcript/layout rules.
            write_pcs(w, spec.main)?;
            w.write_bool(spec.preprocessed.is_some())?;
            if let Some(pp) = spec.preprocessed {
                write_pcs(w, pp)?;
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
            binary.input_shape().write_identity(w)
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
