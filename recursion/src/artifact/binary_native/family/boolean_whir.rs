//! Private closed Boolean WHIR trace family behind native setup.
use p3_binary_field::BinaryField128;
use p3_binary_pcs::BooleanTraceCommitment;
use p3_binary_pcs::whir::{BinaryWhirDomain, BooleanWhirPcs};
use p3_sumcheck::layout::SuffixProver;
use p3_whir::{FoldingFactor, WhirProver};

use super::super::config::{
    BinaryNativeBooleanWhirTraceConfig, BinaryNativeWhirPcsParameters, NativeBooleanWhirTracePcs,
};
use super::*;
use crate::verifier::{
    BinaryBooleanWhirTraceMultiStarkPreprocessing, BinaryBooleanWhirTraceMultiStarkVerifier,
    NativeBinaryBooleanWhirTraceMultiStarkInput,
};
type E = BinaryField128;
pub(in crate::artifact::binary_native) struct BooleanWhirTraceFamily;
impl NativeFamily<E, E> for BooleanWhirTraceFamily {
    type Parameters = BinaryNativeWhirPcsParameters<E>;
    type Pcs = NativeBooleanWhirTracePcs;
    type Config = BinaryNativeBooleanWhirTraceConfig;
    type Recursive = BinaryBooleanWhirTraceMultiStarkVerifier;
    type Input = NativeBinaryBooleanWhirTraceMultiStarkInput;
    type Decode = codec::MultiDecode<codec::BooleanTraceDecode<codec::WhirDecode>>;
    fn hash(p: &Self::Parameters) -> ByteHash {
        p.hash
    }
    fn cap_height(p: &Self::Parameters) -> usize {
        p.cap_height
    }
    fn pow_bits(p: &Self::Parameters) -> usize {
        p.config.max_pow_bits()
    }
    fn build_recursive<A: VerifierAir<E, E>>(
        airs: &[&A],
        heights: &[usize],
        spec: &BinaryNativeVerifierSpec<Self::Parameters>,
        roots: usize,
        limits: &VerifierLimits,
    ) -> Result<Self::Recursive, VerificationError> {
        let mut parameters_usage = InputResourceUsage::default();
        for p in core::iter::once(&spec.main).chain(spec.preprocessed.iter()) {
            parameters_usage
                .add_metadata_entries(limits, p.config.params().round_log_inv_rates.len())?;
            if let FoldingFactor::PerRound(factors) = &p.config.params().folding_factor {
                parameters_usage.add_metadata_entries(limits, factors.len())?;
            }
        }
        let main = &spec.main;
        let mut recursive = if let Some(pp) = &spec.preprocessed {
            BinaryBooleanWhirTraceMultiStarkVerifier::with_preprocessing(
                airs,
                heights,
                &main.config,
                main.hash,
                main.cap_height,
                spec.sumcheck_pow_bits,
                spec.max_tau_draws,
                BinaryBooleanWhirTraceMultiStarkPreprocessing {
                    config: pp.config.clone(),
                    hash: pp.hash,
                    cap_height: pp.cap_height,
                    commitment: MerkleCap::new(vec![[0; 32]; roots]),
                },
                limits,
            )?
        } else {
            BinaryBooleanWhirTraceMultiStarkVerifier::with_limits(
                airs,
                heights,
                &main.config,
                main.hash,
                main.cap_height,
                spec.sumcheck_pow_bits,
                spec.max_tau_draws,
                limits,
            )?
        };
        recursive.retain_native_parameter_metadata(parameters_usage.metadata_entries, limits)?;
        Ok(recursive)
    }
    fn build_config(
        spec: &BinaryNativeVerifierSpec<Self::Parameters>,
        base: &NativeMmcs<E>,
        _round: &NativeMmcs<E>,
        preprocessed: Option<&(NativeMmcs<E>, NativeMmcs<E>)>,
    ) -> Result<Self::Config, VerificationError> {
        Ok(BinaryNativeBooleanWhirTraceConfig {
            main: build_pcs(&spec.main, base)?,
            main_parameters: spec.main.clone(),
            preprocessed_parameters: spec.preprocessed.clone(),
            preprocessed: spec
                .preprocessed
                .as_ref()
                .zip(preprocessed)
                .map(|(pp, (base, _))| build_pcs(pp, base))
                .transpose()?,
        })
    }
    fn bind_preprocessing(
        recursive: &mut Self::Recursive,
        cap: Vec<[u8; 32]>,
    ) -> Result<(), VerificationError> {
        recursive.bind_native_preprocessing_cap(cap)
    }
    fn usage(recursive: &Self::Recursive) -> InputResourceUsage {
        recursive.input_resource_usage()
    }
    fn public_counts(decode: &Self::Decode) -> &[usize] {
        &decode.public_counts
    }
    fn decode_shape(recursive: &Self::Recursive) -> Self::Decode {
        recursive.input_shape().native_decode_shape()
    }
    fn import_native(
        recursive: &Self::Recursive,
        config: &Self::Config,
        base: &NativeMmcs<E>,
        _round: &NativeMmcs<E>,
        preprocessed: Option<&(NativeMmcs<E>, NativeMmcs<E>)>,
        public: &[Vec<E>],
        proof: &MultiStarkProof<Self::Config>,
        ch: &mut BinaryNativeChallenger<E>,
    ) -> Result<Self::Input, VerificationError> {
        recursive.import_native_with_preprocessing(
            &config.main_parameters.config,
            base,
            config
                .preprocessed_parameters
                .as_ref()
                .zip(preprocessed)
                .map(|(pcs, (base, _))| (&pcs.config, base)),
            public,
            proof,
            ch,
        )
    }
    fn write_parameters(w: &mut Writer, p: &Self::Parameters) -> Result<(), ArtifactError> {
        <WhirFamily<SuffixProver<E, E>> as NativeFamily<E, E>>::write_parameters(w, p)
    }
    fn write_shape(w: &mut Writer, recursive: &Self::Recursive) -> Result<(), ArtifactError> {
        recursive.input_shape().write_identity(w)
    }
    fn suite() -> u16 {
        field_suite::<E, E>() | 0x500
    }
}

fn build_pcs(
    p: &BinaryNativeWhirPcsParameters<E>,
    base: &NativeMmcs<E>,
) -> Result<NativeBooleanWhirTracePcs, VerificationError> {
    let bit_arity = p.config.num_variables().checked_add(7).ok_or(
        VerificationError::ResourceArithmeticOverflow {
            component: "binary native Boolean WHIR bit arity",
        },
    )?;
    let inner = WhirProver::<E, E, _, _, BinaryNativeChallenger<E>, SuffixProver<E, E>>::new(
        p.config.clone(),
        BinaryWhirDomain::<E>::default(),
        base.clone(),
    );
    let boolean = BooleanWhirPcs::new(inner, bit_arity)
        .map_err(|_| invalid("binary native Boolean WHIR bit configuration rejected"))?;
    Ok(BooleanTraceCommitment::from_commitment(boolean))
}
