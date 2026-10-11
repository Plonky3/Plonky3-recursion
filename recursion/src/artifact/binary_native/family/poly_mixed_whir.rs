//! Private closed family of a dense Poly64 WHIR commitment beside one packed-bit table
//! commitment.
use p3_binary_field::{Poly64, Poly192};
use p3_sumcheck::layout::SuffixProver;

use super::super::config::{
    BinaryNativePolyMixedWhirConfig, BinaryNativePolyMixedWhirPcsParameters,
    BinaryNativePolyWhirPcsParameters, NativeMixedWhirPcs,
};
use super::mixed_whir::{bits_committed, check_spec, pow_bits, write_parameters};
use super::*;
use crate::pcs::binary::MerkleArity;
use crate::verifier::{
    BinaryPolyMixedWhirMultiStarkPreprocessing, BinaryPolyMixedWhirMultiStarkVerifier,
    NativeBinaryPolyMixedWhirMultiStarkInput,
};

pub(in crate::artifact::binary_native) struct PolyMixedWhirFamily;

/// The recursive verifier, and the WHIR configurations its native import replays.
pub(in crate::artifact::binary_native) struct PolyMixedWhirRecursive {
    pub(in crate::artifact::binary_native) verifier: BinaryPolyMixedWhirMultiStarkVerifier,
    dense: BinaryNativePolyWhirPcsParameters,
    packed: BinaryNativePolyWhirPcsParameters,
    preprocessed: Option<BinaryNativePolyWhirPcsParameters>,
}

impl NativeFamily<Poly64, Poly192> for PolyMixedWhirFamily {
    type Parameters = BinaryNativePolyMixedWhirPcsParameters;
    type Pcs = NativeMixedWhirPcs<Poly64, Poly192>;
    type Config = BinaryNativePolyMixedWhirConfig;
    type Recursive = PolyMixedWhirRecursive;
    type Input = NativeBinaryPolyMixedWhirMultiStarkInput;
    type Decode = codec::MultiDecode<codec::MixedWhirDecode>;
    type Trees = NativeWhirMmcs<Poly64>;
    fn cap_height(p: &Self::Parameters) -> usize {
        p.dense.cap_height
    }
    fn arity(p: &Self::Parameters) -> MerkleArity {
        p.dense.arity
    }
    fn pow_bits(p: &Self::Parameters) -> usize {
        pow_bits(p)
    }
    fn bits_committed(p: &Self::Parameters, table: usize) -> bool {
        bits_committed(p, table)
    }
    fn build_recursive<A: VerifierAir<Poly64, Poly192>>(
        airs: &[&A],
        heights: &[usize],
        spec: &BinaryNativeVerifierSpec<Self::Parameters>,
        roots: usize,
        limits: &VerifierLimits,
    ) -> Result<Self::Recursive, VerificationError> {
        let main = &spec.main;
        let (packed, metadata_entries) = check_spec(airs, heights, spec, limits)?;
        let mut verifier = if let Some(pp) = &spec.preprocessed {
            BinaryPolyMixedWhirMultiStarkVerifier::with_preprocessing(
                airs,
                heights,
                packed.table,
                &main.dense.config,
                &packed.whir.config,
                main.dense.hash,
                main.dense.arity,
                main.dense.cap_height,
                spec.sumcheck_pow_bits,
                spec.max_tau_draws,
                BinaryPolyMixedWhirMultiStarkPreprocessing {
                    config: pp.dense.config.clone(),
                    hash: pp.dense.hash,
                    arity: pp.dense.arity,
                    cap_height: pp.dense.cap_height,
                    commitment: MerkleCap::new(vec![[0; 32]; roots]),
                },
                limits,
            )?
        } else {
            BinaryPolyMixedWhirMultiStarkVerifier::with_limits(
                airs,
                heights,
                packed.table,
                &main.dense.config,
                &packed.whir.config,
                main.dense.hash,
                main.dense.arity,
                main.dense.cap_height,
                spec.sumcheck_pow_bits,
                spec.max_tau_draws,
                limits,
            )?
        };
        verifier.retain_native_parameter_metadata(metadata_entries, limits)?;
        Ok(PolyMixedWhirRecursive {
            verifier,
            dense: main.dense.clone(),
            packed: packed.whir.clone(),
            preprocessed: spec.preprocessed.as_ref().map(|pp| pp.dense.clone()),
        })
    }
    fn trees(p: &Self::Parameters) -> Self::Trees {
        NativeWhirMmcs::new(p.dense.hash, p.dense.arity, p.dense.cap_height)
    }
    fn build_config(
        spec: &BinaryNativeVerifierSpec<Self::Parameters>,
        _main: &Self::Trees,
        _preprocessed: Option<&Self::Trees>,
    ) -> Result<Self::Config, VerificationError> {
        // Each commitment builds its trees from its dense parameters' hash, tree arity and cap
        // height, the trees the lifecycle passes in and its native import replays.
        let pcs = |p: &BinaryNativePolyMixedWhirPcsParameters| {
            NativeMixedWhirPcs::from_parameters(
                &p.dense,
                p.packed
                    .as_ref()
                    .map(|packed| (&packed.whir, packed.table, packed.bit_variables)),
            )
        };
        BinaryNativePolyMixedWhirConfig::new(
            pcs(&spec.main)?,
            spec.preprocessed.as_ref().map(pcs).transpose()?,
        )
    }
    fn bind_preprocessing(
        recursive: &mut Self::Recursive,
        cap: Vec<[u8; 32]>,
    ) -> Result<(), VerificationError> {
        recursive.verifier.bind_native_preprocessing_cap(cap)
    }
    fn usage(recursive: &Self::Recursive) -> InputResourceUsage {
        recursive.verifier.input_resource_usage()
    }
    fn public_counts(decode: &Self::Decode) -> &[usize] {
        &decode.public_counts
    }
    fn decode_shape(recursive: &Self::Recursive) -> Self::Decode {
        recursive.verifier.input_shape().native_decode_shape()
    }
    fn import_native(
        recursive: &Self::Recursive,
        _config: &Self::Config,
        base: &Self::Trees,
        preprocessed: Option<&Self::Trees>,
        public: &[Vec<Poly64>],
        proof: &MultiStarkProof<Self::Config>,
        ch: &mut BinaryNativeChallenger<Poly64>,
    ) -> Result<Self::Input, VerificationError> {
        recursive.verifier.import_native(
            &recursive.dense.config,
            &recursive.packed.config,
            base,
            recursive
                .preprocessed
                .as_ref()
                .zip(preprocessed)
                .map(|(pp, base)| (&pp.config, base)),
            public,
            proof,
            ch,
        )
    }
    fn write_parameters(w: &mut Writer, p: &Self::Parameters) -> Result<(), ArtifactError> {
        type Whir = PolyWhirFamily<SuffixProver<Poly64, Poly192>>;
        write_parameters(
            w,
            p,
            <Whir as NativeFamily<Poly64, Poly192>>::write_parameters,
        )
    }
    fn write_shape(w: &mut Writer, recursive: &Self::Recursive) -> Result<(), ArtifactError> {
        recursive.verifier.input_shape().write_identity(w)
    }
    fn suite() -> u16 {
        0xba01 | 0x600
    }
}
