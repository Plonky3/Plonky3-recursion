//! Private closed family of a dense WHIR commitment beside one packed-bit table commitment.
use p3_binary_field::BinaryField128;
use p3_sumcheck::layout::SuffixProver;
use p3_whir::FoldingFactor;

use super::super::config::{
    BinaryNativeMixedWhirConfig, BinaryNativeMixedWhirPcsParameters, BinaryNativeWhirPcsParameters,
    MixedWhirPcs,
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
    fn hash(p: &Self::Parameters) -> ByteHash {
        p.dense.hash
    }
    fn cap_height(p: &Self::Parameters) -> usize {
        p.dense.cap_height
    }
    fn pow_bits(p: &Self::Parameters) -> usize {
        p.packed
            .as_ref()
            .map_or(0, |packed| packed.whir.config.max_pow_bits())
            .max(p.dense.config.max_pow_bits())
    }
    fn bits_committed(p: &Self::Parameters, table: usize) -> bool {
        p.packed
            .as_ref()
            .is_some_and(|packed| packed.table == table)
    }
    fn build_recursive<A: VerifierAir<E, E>>(
        airs: &[&A],
        heights: &[usize],
        spec: &BinaryNativeVerifierSpec<Self::Parameters>,
        roots: usize,
        limits: &VerifierLimits,
    ) -> Result<Self::Recursive, VerificationError> {
        let main = &spec.main;
        let packed = main.packed.as_ref().ok_or_else(|| {
            invalid("binary native mixed WHIR main commitment has no packed table")
        })?;
        if spec
            .preprocessed
            .as_ref()
            .is_some_and(|pp| pp.packed.is_some())
        {
            return Err(invalid(
                "binary native mixed WHIR preprocessing commits no packed table",
            ));
        }
        let first = main.dense.config.round_folding_factor(0);
        if heights.iter().any(|&height| height < first) {
            return Err(invalid(
                "binary native mixed WHIR trace height is below its initial folding factor",
            ));
        }
        if spec
            .preprocessed
            .as_ref()
            .is_some_and(|pp| pp.dense.config.round_folding_factor(0) != first)
        {
            return Err(invalid(
                "binary native mixed WHIR main and preprocessing initial folding factors differ",
            ));
        }
        // The bit stack holds the table's columns, padded to a power of two, beneath its rows.
        let (air, &height) = airs
            .get(packed.table)
            .zip(heights.get(packed.table))
            .ok_or_else(|| {
                invalid("binary native mixed WHIR packed table index exceeds the AIRs")
            })?;
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
            parameters_usage
                .add_metadata_entries(limits, p.config.params().round_log_inv_rates.len())?;
            if let FoldingFactor::PerRound(factors) = &p.config.params().folding_factor {
                parameters_usage.add_metadata_entries(limits, factors.len())?;
            }
        }
        let mut verifier = if let Some(pp) = &spec.preprocessed {
            BinaryMixedWhirMultiStarkVerifier::with_preprocessing(
                airs,
                heights,
                packed.table,
                &main.dense.config,
                &packed.whir.config,
                main.dense.hash,
                MerkleArity::Two,
                main.dense.cap_height,
                spec.sumcheck_pow_bits,
                spec.max_tau_draws,
                BinaryMixedWhirMultiStarkPreprocessing {
                    config: pp.dense.config.clone(),
                    hash: pp.dense.hash,
                    arity: MerkleArity::Two,
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
                MerkleArity::Two,
                main.dense.cap_height,
                spec.sumcheck_pow_bits,
                spec.max_tau_draws,
                limits,
            )?
        };
        verifier.retain_native_parameter_metadata(parameters_usage.metadata_entries, limits)?;
        Ok(MixedWhirRecursive {
            verifier,
            dense: main.dense.clone(),
            packed: packed.whir.clone(),
            preprocessed: spec.preprocessed.as_ref().map(|pp| pp.dense.clone()),
        })
    }
    fn build_config(
        spec: &BinaryNativeVerifierSpec<Self::Parameters>,
        _base: &NativeMmcs<E>,
        _round: &NativeMmcs<E>,
        _preprocessed: Option<&(NativeMmcs<E>, NativeMmcs<E>)>,
    ) -> Result<Self::Config, VerificationError> {
        // Each commitment builds its trees from its dense parameters' hash and cap height, the
        // trees the lifecycle passes in and its native import replays.
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
        base: &NativeMmcs<E>,
        _round: &NativeMmcs<E>,
        preprocessed: Option<&(NativeMmcs<E>, NativeMmcs<E>)>,
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
                .map(|(pp, (base, _))| (&pp.config, base)),
            public,
            proof,
            ch,
        )
    }
    fn write_parameters(w: &mut Writer, p: &Self::Parameters) -> Result<(), ArtifactError> {
        type Whir = WhirFamily<SuffixProver<E, E>>;
        <Whir as NativeFamily<E, E>>::write_parameters(w, &p.dense)?;
        w.write_bool(p.packed.is_some())?;
        if let Some(packed) = &p.packed {
            w.write_count("binary native mixed WHIR packed table", packed.table)?;
            w.write_count(
                "binary native mixed WHIR bit variables",
                packed.bit_variables,
            )?;
            <Whir as NativeFamily<E, E>>::write_parameters(w, &packed.whir)?;
        }
        Ok(())
    }
    fn write_shape(w: &mut Writer, recursive: &Self::Recursive) -> Result<(), ArtifactError> {
        recursive.verifier.input_shape().write_identity(w)
    }
    fn suite() -> u16 {
        field_suite::<E, E>() | 0x600
    }
}

#[cfg(test)]
mod tests;
