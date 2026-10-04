//! Closed additive WHIR family behind the retained native setup lifecycle.
use p3_binary_field::{Poly64, Poly192};
use p3_binary_pcs::whir::BinaryWhirDomain;
use p3_whir::{FoldingFactor, SecurityAssumption, WhirProver};

use super::super::config::{
    BinaryNativePolyWhirConfig, BinaryNativePolyWhirLayout, BinaryNativePolyWhirPcsParameters,
    NativePolyWhirPcs,
};
use super::*;
use crate::verifier::{
    BinaryPolyWhirMultiStarkPreprocessing, BinaryPolyWhirMultiStarkVerifier,
    NativeBinaryPolyWhirMultiStarkInput,
};

pub(in crate::artifact::binary_native) struct PolyWhirFamily<L>(core::marker::PhantomData<L>);
impl<L> NativeFamily<Poly64, Poly192> for PolyWhirFamily<L>
where
    L: BinaryNativePolyWhirLayout,
{
    type Parameters = BinaryNativePolyWhirPcsParameters;
    type Pcs = NativePolyWhirPcs<L>;
    type Config = BinaryNativePolyWhirConfig<L>;
    type Recursive = BinaryPolyWhirMultiStarkVerifier;
    type Input = NativeBinaryPolyWhirMultiStarkInput;
    type Decode = codec::MultiDecode<codec::WhirDecode>;
    fn hash(p: &Self::Parameters) -> ByteHash {
        p.hash
    }
    fn cap_height(p: &Self::Parameters) -> usize {
        p.cap_height
    }
    fn pow_bits(p: &Self::Parameters) -> usize {
        p.config.max_pow_bits()
    }
    fn build_recursive<A: VerifierAir<Poly64, Poly192>>(
        airs: &[&A],
        heights: &[usize],
        spec: &BinaryNativeVerifierSpec<Self::Parameters>,
        roots: usize,
        limits: &VerifierLimits,
    ) -> Result<Self::Recursive, VerificationError> {
        let first = spec.main.config.round_folding_factor(0);
        if heights.iter().any(|&height| height < first) {
            return Err(invalid(
                "binary native WHIR trace height is below its initial folding factor",
            ));
        }
        if spec
            .preprocessed
            .as_ref()
            .is_some_and(|pp| pp.config.round_folding_factor(0) != first)
        {
            return Err(invalid(
                "binary native WHIR main and preprocessing initial folding factors differ",
            ));
        }
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
            BinaryPolyWhirMultiStarkVerifier::with_preprocessing(
                airs,
                heights,
                &main.config,
                L::variable_order(),
                main.hash,
                main.cap_height,
                spec.sumcheck_pow_bits,
                spec.max_tau_draws,
                BinaryPolyWhirMultiStarkPreprocessing {
                    config: pp.config.clone(),
                    order: L::variable_order(),
                    hash: pp.hash,
                    cap_height: pp.cap_height,
                    commitment: MerkleCap::new(vec![[0; 32]; roots]),
                },
                limits,
            )?
        } else {
            BinaryPolyWhirMultiStarkVerifier::with_limits(
                airs,
                heights,
                &main.config,
                L::variable_order(),
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
        base: &NativeMmcs<Poly64>,
        _round: &NativeMmcs<Poly192>,
        preprocessed: Option<&(NativeMmcs<Poly64>, NativeMmcs<Poly192>)>,
    ) -> Result<Self::Config, VerificationError> {
        Ok(BinaryNativePolyWhirConfig {
            main: WhirProver::new(
                spec.main.config.clone(),
                BinaryWhirDomain::<Poly64>::default(),
                base.clone(),
            ),
            preprocessed: spec
                .preprocessed
                .as_ref()
                .zip(preprocessed)
                .map(|(pp, (base, _))| {
                    WhirProver::new(
                        pp.config.clone(),
                        BinaryWhirDomain::<Poly64>::default(),
                        base.clone(),
                    )
                }),
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
        base: &NativeMmcs<Poly64>,
        _round: &NativeMmcs<Poly192>,
        preprocessed: Option<&(NativeMmcs<Poly64>, NativeMmcs<Poly192>)>,
        public: &[Vec<Poly64>],
        proof: &MultiStarkProof<Self::Config>,
        ch: &mut BinaryNativeChallenger<Poly64>,
    ) -> Result<Self::Input, VerificationError> {
        recursive.import_native_with_preprocessing(
            &config.main,
            base,
            config
                .preprocessed
                .as_ref()
                .zip(preprocessed)
                .map(|(pcs, (base, _))| (&**pcs, base)),
            public,
            proof,
            ch,
        )
    }
    fn write_parameters(w: &mut Writer, p: &Self::Parameters) -> Result<(), ArtifactError> {
        let params = p.config.params();
        for value in [
            p.config.num_variables(),
            params.starting_log_inv_rate,
            params.security_level,
            params.pow_bits,
            p.cap_height,
        ] {
            w.write_count("binary native WHIR parameters", value)?;
        }
        w.write_vec(
            "binary native WHIR rates",
            &params.round_log_inv_rates,
            |w, &rate| w.write_count("binary native WHIR rate", rate),
        )?;
        match &params.folding_factor {
            FoldingFactor::Constant(factor) => {
                w.write_u8(0)?;
                w.write_count("binary native WHIR factor", *factor)?;
            }
            FoldingFactor::ConstantFromSecondRound(first, later) => {
                w.write_u8(1)?;
                w.write_count("binary native WHIR factor", *first)?;
                w.write_count("binary native WHIR factor", *later)?;
            }
            FoldingFactor::PerRound(factors) => {
                w.write_u8(2)?;
                w.write_vec("binary native WHIR factors", factors, |w, &factor| {
                    w.write_count("binary native WHIR factor", factor)
                })?;
            }
        }
        w.write_u8(match params.soundness_type {
            SecurityAssumption::UniqueDecoding => 0,
            SecurityAssumption::JohnsonBound => 1,
            SecurityAssumption::CapacityBound => 2,
        })?;
        write_hash(w, p.hash)
    }
    fn write_shape(w: &mut Writer, recursive: &Self::Recursive) -> Result<(), ArtifactError> {
        recursive.input_shape().write_identity(w)
    }
    fn suite() -> u16 {
        0xba01
    }
}
