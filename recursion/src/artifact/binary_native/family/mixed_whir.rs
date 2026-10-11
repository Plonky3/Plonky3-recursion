//! Private closed family of a dense WHIR commitment beside one packed-bit table commitment.
use p3_air::BaseAir;
use p3_binary_field::BinaryField128;
use p3_challenger::{FieldChallenger, GrindingChallenger};
use p3_sumcheck::layout::SuffixProver;
use p3_whir::FoldingFactor;

use super::super::config::{
    BinaryNativeMixedWhirConfig, BinaryNativeMixedWhirPcsParameters, BinaryNativeWhirPcsParameters,
    MixedWhirPartParameters, MixedWhirPcs, NativeMixedWhirPcsParameters, PackedTableParameters,
};
use super::*;
use crate::pcs::binary::MerkleArity;
use crate::verifier::{
    BinaryMixedWhirMultiStarkPreprocessing, BinaryMixedWhirMultiStarkVerifier,
    NativeBinaryMixedWhirMultiStarkInput,
};
type E = BinaryField128;

pub(in crate::artifact::binary_native) struct MixedWhirFamily;

/// The recursive verifier, and the WHIR configurations its native import replays.
pub(in crate::artifact::binary_native) struct MixedWhirRecursive {
    pub(in crate::artifact::binary_native) verifier: BinaryMixedWhirMultiStarkVerifier,
    dense: BinaryNativeWhirPcsParameters<E>,
    packed: BinaryNativeWhirPcsParameters<E>,
    preprocessed: Option<BinaryNativeWhirPcsParameters<E>>,
}

impl NativeFamily<E, E> for MixedWhirFamily {
    type Parameters = BinaryNativeMixedWhirPcsParameters;
    type Pcs = MixedWhirPcs;
    type Config = BinaryNativeMixedWhirConfig;
    type Recursive = MixedWhirRecursive;
    type Input = NativeBinaryMixedWhirMultiStarkInput;
    type Decode = codec::MultiDecode<codec::MixedWhirDecode>;
    type Trees = NativeWhirMmcs<E>;
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
    fn build_recursive<A: VerifierAir<E, E>>(
        airs: &[&A],
        heights: &[usize],
        spec: &BinaryNativeVerifierSpec<Self::Parameters>,
        roots: usize,
        limits: &VerifierLimits,
    ) -> Result<Self::Recursive, VerificationError> {
        let main = &spec.main;
        let (packed, metadata_entries) = check_spec(airs, heights, spec, limits)?;
        let mut verifier = if let Some(pp) = &spec.preprocessed {
            BinaryMixedWhirMultiStarkVerifier::with_preprocessing(
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
                BinaryMixedWhirMultiStarkPreprocessing {
                    config: pp.dense.config.clone(),
                    hash: pp.dense.hash,
                    arity: pp.dense.arity,
                    cap_height: pp.dense.cap_height,
                    commitment: MerkleCap::new(vec![[0; 32]; roots]),
                },
                limits,
            )?
        } else {
            BinaryMixedWhirMultiStarkVerifier::with_limits(
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
        Ok(MixedWhirRecursive {
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
        let pcs = |p: &BinaryNativeMixedWhirPcsParameters| {
            MixedWhirPcs::from_parameters(
                &p.dense,
                p.packed
                    .as_ref()
                    .map(|packed| (&packed.whir, packed.table, packed.bit_variables)),
            )
        };
        BinaryNativeMixedWhirConfig::new(
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
        public: &[Vec<E>],
        proof: &MultiStarkProof<Self::Config>,
        ch: &mut BinaryNativeChallenger<E>,
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
        type Whir = WhirFamily<SuffixProver<E, E>>;
        write_parameters(w, p, <Whir as NativeFamily<E, E>>::write_parameters)
    }
    fn write_shape(w: &mut Writer, recursive: &Self::Recursive) -> Result<(), ArtifactError> {
        recursive.verifier.input_shape().write_identity(w)
    }
    fn suite() -> u16 {
        field_suite::<E, E>() | 0x600
    }
}

/// The longest grinding of either part.
pub(super) fn pow_bits<P>(p: &NativeMixedWhirPcsParameters<P>) -> usize
where
    P: MixedWhirPartParameters,
    BinaryNativeChallenger<P::Val>: FieldChallenger<P::Val> + GrindingChallenger<Witness = P::Val>,
{
    p.packed
        .as_ref()
        .map_or(0, |packed| packed.whir.whir().max_pow_bits())
        .max(p.dense.whir().max_pow_bits())
}

/// Whether the commitment stores `table` as bits.
pub(super) fn bits_committed<P>(p: &NativeMixedWhirPcsParameters<P>, table: usize) -> bool {
    p.packed
        .as_ref()
        .is_some_and(|packed| packed.table == table)
}

/// The trusted checks of a mixed specification, and the metadata entries its parts' parameters
/// retain. Returns the packed part: the main commitment must bit-commit a table, the
/// preprocessing commitment none, every trace must reach the initial folding factor, and the
/// packed table's bit stack must be its columns padded to a power of two beneath its rows.
pub(super) fn check_spec<'a, P, A>(
    airs: &[&A],
    heights: &[usize],
    spec: &'a BinaryNativeVerifierSpec<NativeMixedWhirPcsParameters<P>>,
    limits: &VerifierLimits,
) -> Result<(&'a PackedTableParameters<P>, usize), VerificationError>
where
    P: MixedWhirPartParameters,
    A: BaseAir<P::Val>,
    BinaryNativeChallenger<P::Val>: FieldChallenger<P::Val> + GrindingChallenger<Witness = P::Val>,
{
    let main = &spec.main;
    let packed = main
        .packed
        .as_ref()
        .ok_or_else(|| invalid("binary native mixed WHIR main commitment has no packed table"))?;
    if spec
        .preprocessed
        .as_ref()
        .is_some_and(|pp| pp.packed.is_some())
    {
        return Err(invalid(
            "binary native mixed WHIR preprocessing commits no packed table",
        ));
    }
    let first = main.dense.whir().round_folding_factor(0);
    if heights.iter().any(|&height| height < first) {
        return Err(invalid(
            "binary native mixed WHIR trace height is below its initial folding factor",
        ));
    }
    if spec
        .preprocessed
        .as_ref()
        .is_some_and(|pp| pp.dense.whir().round_folding_factor(0) != first)
    {
        return Err(invalid(
            "binary native mixed WHIR main and preprocessing initial folding factors differ",
        ));
    }
    // The bit stack holds the table's columns, padded to a power of two, beneath its rows.
    let (air, &height) = airs
        .get(packed.table)
        .zip(heights.get(packed.table))
        .ok_or_else(|| invalid("binary native mixed WHIR packed table index exceeds the AIRs"))?;
    let column_variables = air.width().next_power_of_two().ilog2() as usize;
    if column_variables.checked_add(height) != Some(packed.bit_variables) {
        return Err(invalid(
            "binary native mixed WHIR bit variables do not match the packed table",
        ));
    }
    let mut parameters_usage = InputResourceUsage::default();
    for p in [&main.dense, &packed.whir]
        .into_iter()
        .chain(spec.preprocessed.iter().map(|pp| &pp.dense))
    {
        let params = p.whir().params();
        parameters_usage.add_metadata_entries(limits, params.round_log_inv_rates.len())?;
        if let FoldingFactor::PerRound(factors) = &params.folding_factor {
            parameters_usage.add_metadata_entries(limits, factors.len())?;
        }
    }
    Ok((packed, parameters_usage.metadata_entries))
}

/// The dense part's parameters, then the packed part's table, bit variables and parameters,
/// each part written by `write_part`.
pub(super) fn write_parameters<P>(
    w: &mut Writer,
    p: &NativeMixedWhirPcsParameters<P>,
    write_part: fn(&mut Writer, &P) -> Result<(), ArtifactError>,
) -> Result<(), ArtifactError> {
    write_part(w, &p.dense)?;
    w.write_bool(p.packed.is_some())?;
    if let Some(packed) = &p.packed {
        w.write_count("binary native mixed WHIR packed table", packed.table)?;
        w.write_count(
            "binary native mixed WHIR bit variables",
            packed.bit_variables,
        )?;
        write_part(w, &packed.whir)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests;
