//! Private closed-family boundary for matched native binary proof owners.

mod boolean_whir;
pub(super) use boolean_whir::BooleanWhirTraceFamily;
mod poly_whir;
pub(super) use poly_whir::PolyWhirFamily;
mod whir;
use alloc::vec;

use p3_binary_pcs::BinaryPcs;
use p3_sumcheck::PrescribedPointPcs;
pub(super) use whir::WhirFamily;

use super::*;

pub(super) trait NativeFamily<F, E>
where
    F: NativeAlphabet + TranscriptField + PackedValue<Value = F>,
    E: ExtensionField<F> + PackedValue<Value = E>,
{
    type Parameters;
    type Pcs: PrescribedPointPcs<
            E,
            BinaryNativeChallenger<F>,
            Val = F,
            Commitment = MerkleCap<F, [u8; 32]>,
            OpeningProtocol = p3_sumcheck::OpeningProtocol,
        >;
    type Config: p3_multi_stark::config::MultiStarkConfig<
            Val = F,
            Challenge = E,
            Challenger = BinaryNativeChallenger<F>,
            Pcs = Self::Pcs,
        >;
    type Recursive;
    type Input;
    type Decode;

    fn hash(p: &Self::Parameters) -> ByteHash;
    fn cap_height(p: &Self::Parameters) -> usize;
    fn pow_bits(p: &Self::Parameters) -> usize;
    fn build_recursive<A: VerifierAir<F, E>>(
        airs: &[&A],
        heights: &[usize],
        spec: &BinaryNativeVerifierSpec<Self::Parameters>,
        roots: usize,
        limits: &VerifierLimits,
    ) -> Result<Self::Recursive, VerificationError>;
    fn build_config(
        spec: &BinaryNativeVerifierSpec<Self::Parameters>,
        base: &NativeMmcs<F>,
        round: &NativeMmcs<E>,
        preprocessed: Option<&(NativeMmcs<F>, NativeMmcs<E>)>,
    ) -> Result<Self::Config, VerificationError>;
    fn bind_preprocessing(
        recursive: &mut Self::Recursive,
        cap: Vec<[u8; 32]>,
    ) -> Result<(), VerificationError>;
    fn usage(recursive: &Self::Recursive) -> InputResourceUsage;
    fn public_counts(decode: &Self::Decode) -> &[usize];
    fn decode_shape(recursive: &Self::Recursive) -> Self::Decode;
    fn import_native(
        recursive: &Self::Recursive,
        config: &Self::Config,
        base: &NativeMmcs<F>,
        round: &NativeMmcs<E>,
        preprocessed: Option<&(NativeMmcs<F>, NativeMmcs<E>)>,
        public: &[Vec<F>],
        proof: &MultiStarkProof<Self::Config>,
        ch: &mut BinaryNativeChallenger<F>,
    ) -> Result<Self::Input, VerificationError>;
    fn write_parameters(w: &mut Writer, parameters: &Self::Parameters)
    -> Result<(), ArtifactError>;
    fn write_shape(w: &mut Writer, recursive: &Self::Recursive) -> Result<(), ArtifactError>;
    fn suite() -> u16;
}

pub(super) struct RawFamily;

impl<F, E> NativeFamily<F, E> for RawFamily
where
    F: RecursiveBinaryTowerField + EncodableLevel + FoldAlphabet<E> + PackedValue<Value = F>,
    E: RecursiveBinaryChallengeField
        + ExtensionField<F>
        + ChallengeField<F>
        + FoldAlphabet<E>
        + PackedValue<Value = E>,
{
    type Parameters = BinaryNativePcsParameters;
    type Pcs = config::NativePcs<F, E>;
    type Config = BinaryNativeConfig<F, E>;
    type Recursive = BinaryMultiStarkVerifier<F, E>;
    type Input = NativeBinaryMultiStarkInput<F, E>;
    type Decode = codec::MultiDecode;

    fn hash(p: &Self::Parameters) -> ByteHash {
        p.hash
    }
    fn cap_height(p: &Self::Parameters) -> usize {
        p.cap_height
    }
    fn pow_bits(p: &Self::Parameters) -> usize {
        p.config.pow_bits()
    }
    fn build_recursive<A: VerifierAir<F, E>>(
        airs: &[&A],
        heights: &[usize],
        spec: &BinaryNativeVerifierSpec,
        roots: usize,
        limits: &VerifierLimits,
    ) -> Result<Self::Recursive, VerificationError> {
        let main = spec.main;
        if let Some(pp) = spec.preprocessed {
            BinaryMultiStarkVerifier::with_preprocessing(
                airs,
                heights,
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
                limits,
            )
        } else {
            BinaryMultiStarkVerifier::with_limits(
                airs,
                heights,
                main.config,
                main.hash,
                main.cap_height,
                spec.sumcheck_pow_bits,
                spec.max_tau_draws,
                main.max_query_draws,
                limits,
            )
        }
    }
    fn build_config(
        spec: &BinaryNativeVerifierSpec,
        base: &NativeMmcs<F>,
        round: &NativeMmcs<E>,
        preprocessed: Option<&(NativeMmcs<F>, NativeMmcs<E>)>,
    ) -> Result<Self::Config, VerificationError> {
        Ok(BinaryNativeConfig {
            main: BinaryPcs::new(spec.main.config, base.clone(), round.clone())
                .map_err(|_| invalid("binary native main PCS configuration rejected"))?,
            preprocessed: spec
                .preprocessed
                .zip(preprocessed)
                .map(|(pp, (base, round))| {
                    BinaryPcs::new(pp.config, base.clone(), round.clone()).map_err(|_| {
                        invalid("binary native preprocessing PCS configuration rejected")
                    })
                })
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
        _config: &Self::Config,
        base: &NativeMmcs<F>,
        round: &NativeMmcs<E>,
        preprocessed: Option<&(NativeMmcs<F>, NativeMmcs<E>)>,
        public: &[Vec<F>],
        proof: &MultiStarkProof<Self::Config>,
        ch: &mut BinaryNativeChallenger<F>,
    ) -> Result<Self::Input, VerificationError> {
        recursive.import_native_with_preprocessing(
            base,
            round,
            preprocessed.map(|(base, round)| (base, round)),
            public,
            proof,
            ch,
        )
    }
    fn write_parameters(w: &mut Writer, p: &Self::Parameters) -> Result<(), ArtifactError> {
        write_pcs(w, *p)
    }
    fn write_shape(w: &mut Writer, recursive: &Self::Recursive) -> Result<(), ArtifactError> {
        recursive.input_shape().write_identity(w)
    }
    fn suite() -> u16 {
        field_suite::<F, E>()
    }
}

pub(super) struct GroupedFamily;

impl<F, E> NativeFamily<F, E> for GroupedFamily
where
    F: RecursiveBinaryTowerField + EncodableLevel + FoldAlphabet<E> + PackedValue<Value = F>,
    E: RecursiveBinaryChallengeField
        + ExtensionField<F>
        + ChallengeField<F>
        + FoldAlphabet<E>
        + PackedValue<Value = E>,
{
    type Parameters = BinaryNativeGroupedPcsParameters;
    type Pcs = config::NativeGroupedPcs<F, E>;
    type Config = config::BinaryNativeGroupedConfig<F, E>;
    type Recursive = crate::verifier::BinaryGroupedMultiStarkVerifier<F, E>;
    type Input = crate::verifier::NativeBinaryGroupedMultiStarkInput<F, E>;
    type Decode = codec::MultiDecode<codec::PcsDecode<codec::GroupedOracleDecode>>;

    fn hash(p: &Self::Parameters) -> ByteHash {
        p.pcs.hash
    }
    fn cap_height(p: &Self::Parameters) -> usize {
        p.pcs.cap_height
    }
    fn pow_bits(p: &Self::Parameters) -> usize {
        p.pcs.config.pow_bits()
    }
    fn build_recursive<A: VerifierAir<F, E>>(
        airs: &[&A],
        heights: &[usize],
        spec: &BinaryNativeGroupedVerifierSpec,
        roots: usize,
        limits: &VerifierLimits,
    ) -> Result<Self::Recursive, VerificationError> {
        let main = spec.main.pcs;
        if let Some(pp) = spec.preprocessed {
            crate::verifier::BinaryGroupedMultiStarkVerifier::with_preprocessing(
                airs,
                heights,
                main.config,
                main.hash,
                main.cap_height,
                spec.sumcheck_pow_bits,
                spec.max_tau_draws,
                main.max_query_draws,
                spec.main.base_grouping,
                spec.main.round_grouping,
                crate::verifier::BinaryGroupedMultiStarkPreprocessing {
                    config: pp.pcs.config,
                    hash: pp.pcs.hash,
                    cap_height: pp.pcs.cap_height,
                    max_query_draws: pp.pcs.max_query_draws,
                    base_grouping: pp.base_grouping,
                    round_grouping: pp.round_grouping,
                    commitment: MerkleCap::new(vec![[0; 32]; roots]),
                },
                limits,
            )
        } else {
            crate::verifier::BinaryGroupedMultiStarkVerifier::with_limits(
                airs,
                heights,
                main.config,
                main.hash,
                main.cap_height,
                spec.sumcheck_pow_bits,
                spec.max_tau_draws,
                main.max_query_draws,
                spec.main.base_grouping,
                spec.main.round_grouping,
                limits,
            )
        }
    }
    fn build_config(
        spec: &BinaryNativeGroupedVerifierSpec,
        base: &NativeMmcs<F>,
        round: &NativeMmcs<E>,
        preprocessed: Option<&(NativeMmcs<F>, NativeMmcs<E>)>,
    ) -> Result<Self::Config, VerificationError> {
        // Native constructors validate both adapters even when a short PCS
        // never commits an intermediate oracle. Check unused round policies too.
        for p in core::iter::once(&spec.main).chain(spec.preprocessed.iter()) {
            for grouping in [p.base_grouping, p.round_grouping] {
                use crate::pcs::binary::BinaryCodewordGrouping;
                if matches!(grouping,
                    BinaryCodewordGrouping::Codeword(size) | BinaryCodewordGrouping::Message(size)
                        if !size.is_power_of_two())
                {
                    return Err(invalid("binary grouping size must be a power of two"));
                }
            }
        }
        Ok(config::BinaryNativeGroupedConfig {
            main: grouped_pcs(&spec.main, base, round)
                .map_err(|_| invalid("binary native main PCS configuration rejected"))?,
            preprocessed: spec
                .preprocessed
                .as_ref()
                .zip(preprocessed)
                .map(|(pp, (base, round))| {
                    grouped_pcs(pp, base, round).map_err(|_| {
                        invalid("binary native preprocessing PCS configuration rejected")
                    })
                })
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
        _config: &Self::Config,
        base: &NativeMmcs<F>,
        round: &NativeMmcs<E>,
        preprocessed: Option<&(NativeMmcs<F>, NativeMmcs<E>)>,
        public: &[Vec<F>],
        proof: &MultiStarkProof<Self::Config>,
        ch: &mut BinaryNativeChallenger<F>,
    ) -> Result<Self::Input, VerificationError> {
        recursive.import_native_with_preprocessing(
            base,
            round,
            preprocessed.map(|(base, round)| (base, round)),
            public,
            proof,
            ch,
        )
    }
    fn write_parameters(w: &mut Writer, p: &Self::Parameters) -> Result<(), ArtifactError> {
        write_pcs(w, p.pcs)?;
        write_grouping(w, p.base_grouping)?;
        write_grouping(w, p.round_grouping)
    }
    fn write_shape(w: &mut Writer, recursive: &Self::Recursive) -> Result<(), ArtifactError> {
        recursive.input_shape().write_identity(w)
    }
    fn suite() -> u16 {
        field_suite::<F, E>() | 0x100
    }
}

pub(super) struct GroupedBooleanTraceFamily;

impl<E> NativeFamily<E, E> for GroupedBooleanTraceFamily
where
    E: RecursiveBinaryChallengeField
        + EncodableLevel
        + ExtensionField<E>
        + ChallengeField<E>
        + p3_binary_pcs::Coordinates
        + serde::Serialize
        + serde::de::DeserializeOwned
        + FoldAlphabet<E>
        + PackedValue<Value = E>,
{
    type Parameters = BinaryNativeGroupedPcsParameters;
    type Pcs = config::NativeGroupedBooleanTracePcs<E>;
    type Config = config::BinaryNativeGroupedBooleanTraceConfig<E>;
    type Recursive = crate::verifier::BinaryGroupedBooleanTraceMultiStarkVerifier<E>;
    type Input = crate::verifier::NativeBinaryGroupedBooleanTraceMultiStarkInput<E>;
    type Decode = codec::MultiDecode<codec::BooleanTraceDecode>;

    fn hash(p: &Self::Parameters) -> ByteHash {
        p.pcs.hash
    }
    fn cap_height(p: &Self::Parameters) -> usize {
        p.pcs.cap_height
    }
    fn pow_bits(p: &Self::Parameters) -> usize {
        p.pcs.config.pow_bits()
    }
    fn build_recursive<A: VerifierAir<E, E>>(
        airs: &[&A],
        heights: &[usize],
        spec: &BinaryNativeGroupedVerifierSpec,
        roots: usize,
        limits: &VerifierLimits,
    ) -> Result<Self::Recursive, VerificationError> {
        let main = spec.main.pcs;
        if let Some(pp) = spec.preprocessed {
            crate::verifier::BinaryGroupedBooleanTraceMultiStarkVerifier::with_preprocessing(
                airs,
                heights,
                main.config,
                main.hash,
                main.cap_height,
                spec.sumcheck_pow_bits,
                spec.max_tau_draws,
                main.max_query_draws,
                spec.main.base_grouping,
                spec.main.round_grouping,
                crate::verifier::BinaryGroupedBooleanTraceMultiStarkPreprocessing {
                    config: pp.pcs.config,
                    hash: pp.pcs.hash,
                    cap_height: pp.pcs.cap_height,
                    max_query_draws: pp.pcs.max_query_draws,
                    base_grouping: pp.base_grouping,
                    round_grouping: pp.round_grouping,
                    commitment: MerkleCap::new(vec![[0; 32]; roots]),
                },
                limits,
            )
        } else {
            crate::verifier::BinaryGroupedBooleanTraceMultiStarkVerifier::with_limits(
                airs,
                heights,
                main.config,
                main.hash,
                main.cap_height,
                spec.sumcheck_pow_bits,
                spec.max_tau_draws,
                main.max_query_draws,
                spec.main.base_grouping,
                spec.main.round_grouping,
                limits,
            )
        }
    }
    fn build_config(
        spec: &BinaryNativeGroupedVerifierSpec,
        base: &NativeMmcs<E>,
        round: &NativeMmcs<E>,
        preprocessed: Option<&(NativeMmcs<E>, NativeMmcs<E>)>,
    ) -> Result<Self::Config, VerificationError> {
        // Native constructors validate both adapters even when a short PCS
        // never commits an intermediate oracle. Check unused round policies too.
        for p in core::iter::once(&spec.main).chain(spec.preprocessed.iter()) {
            for grouping in [p.base_grouping, p.round_grouping] {
                use crate::pcs::binary::BinaryCodewordGrouping;
                if matches!(grouping,
                    BinaryCodewordGrouping::Codeword(size) | BinaryCodewordGrouping::Message(size)
                        if !size.is_power_of_two())
                {
                    return Err(invalid("binary grouping size must be a power of two"));
                }
            }
        }
        Ok(config::BinaryNativeGroupedBooleanTraceConfig {
            main: grouped_boolean_trace_pcs(&spec.main, base, round)
                .map_err(|_| invalid("binary native main PCS configuration rejected"))?,
            preprocessed: spec
                .preprocessed
                .as_ref()
                .zip(preprocessed)
                .map(|(pp, (base, round))| {
                    grouped_boolean_trace_pcs(pp, base, round).map_err(|_| {
                        invalid("binary native preprocessing PCS configuration rejected")
                    })
                })
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
        _config: &Self::Config,
        base: &NativeMmcs<E>,
        round: &NativeMmcs<E>,
        preprocessed: Option<&(NativeMmcs<E>, NativeMmcs<E>)>,
        public: &[Vec<E>],
        proof: &MultiStarkProof<Self::Config>,
        ch: &mut BinaryNativeChallenger<E>,
    ) -> Result<Self::Input, VerificationError> {
        recursive.import_native_with_preprocessing(
            base,
            round,
            preprocessed.map(|(base, round)| (base, round)),
            public,
            proof,
            ch,
        )
    }
    fn write_parameters(w: &mut Writer, p: &Self::Parameters) -> Result<(), ArtifactError> {
        write_pcs(w, p.pcs)?;
        write_grouping(w, p.base_grouping)?;
        write_grouping(w, p.round_grouping)
    }
    fn write_shape(w: &mut Writer, recursive: &Self::Recursive) -> Result<(), ArtifactError> {
        recursive.input_shape().write_identity(w)
    }
    fn suite() -> u16 {
        field_suite::<E, E>() | 0x200
    }
}

pub(super) struct BooleanTraceFamily;

impl<E> NativeFamily<E, E> for BooleanTraceFamily
where
    E: RecursiveBinaryChallengeField
        + EncodableLevel
        + ExtensionField<E>
        + ChallengeField<E>
        + p3_binary_pcs::Coordinates
        + serde::Serialize
        + serde::de::DeserializeOwned
        + FoldAlphabet<E>
        + PackedValue<Value = E>,
{
    type Parameters = BinaryNativePcsParameters;
    type Pcs = config::NativeBooleanTracePcs<E>;
    type Config = config::BinaryNativeBooleanTraceConfig<E>;
    type Recursive = crate::verifier::BinaryBooleanTraceMultiStarkVerifier<E>;
    type Input = crate::verifier::NativeBinaryBooleanTraceMultiStarkInput<E>;
    type Decode =
        codec::MultiDecode<codec::BooleanTraceDecode<codec::PcsDecode<codec::OracleDecode>>>;

    fn hash(p: &Self::Parameters) -> ByteHash {
        p.hash
    }
    fn cap_height(p: &Self::Parameters) -> usize {
        p.cap_height
    }
    fn pow_bits(p: &Self::Parameters) -> usize {
        p.config.pow_bits()
    }
    fn build_recursive<A: VerifierAir<E, E>>(
        airs: &[&A],
        heights: &[usize],
        spec: &BinaryNativeVerifierSpec,
        roots: usize,
        limits: &VerifierLimits,
    ) -> Result<Self::Recursive, VerificationError> {
        let main = spec.main;
        if let Some(pp) = spec.preprocessed {
            crate::verifier::BinaryBooleanTraceMultiStarkVerifier::with_preprocessing(
                airs,
                heights,
                main.config,
                main.hash,
                main.cap_height,
                spec.sumcheck_pow_bits,
                spec.max_tau_draws,
                main.max_query_draws,
                crate::verifier::BinaryBooleanTraceMultiStarkPreprocessing {
                    config: pp.config,
                    hash: pp.hash,
                    cap_height: pp.cap_height,
                    max_query_draws: pp.max_query_draws,
                    commitment: MerkleCap::new(vec![[0; 32]; roots]),
                },
                limits,
            )
        } else {
            crate::verifier::BinaryBooleanTraceMultiStarkVerifier::with_limits(
                airs,
                heights,
                main.config,
                main.hash,
                main.cap_height,
                spec.sumcheck_pow_bits,
                spec.max_tau_draws,
                main.max_query_draws,
                limits,
            )
        }
    }
    fn build_config(
        spec: &BinaryNativeVerifierSpec,
        base: &NativeMmcs<E>,
        round: &NativeMmcs<E>,
        preprocessed: Option<&(NativeMmcs<E>, NativeMmcs<E>)>,
    ) -> Result<Self::Config, VerificationError> {
        Ok(config::BinaryNativeBooleanTraceConfig {
            main: boolean_trace_pcs(&spec.main, base, round)
                .map_err(|_| invalid("binary native main PCS configuration rejected"))?,
            preprocessed: spec
                .preprocessed
                .as_ref()
                .zip(preprocessed)
                .map(|(pp, (base, round))| {
                    boolean_trace_pcs(pp, base, round).map_err(|_| {
                        invalid("binary native preprocessing PCS configuration rejected")
                    })
                })
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
        _config: &Self::Config,
        base: &NativeMmcs<E>,
        round: &NativeMmcs<E>,
        preprocessed: Option<&(NativeMmcs<E>, NativeMmcs<E>)>,
        public: &[Vec<E>],
        proof: &MultiStarkProof<Self::Config>,
        ch: &mut BinaryNativeChallenger<E>,
    ) -> Result<Self::Input, VerificationError> {
        recursive.import_native_with_preprocessing(
            base,
            round,
            preprocessed.map(|(base, round)| (base, round)),
            public,
            proof,
            ch,
        )
    }
    fn write_parameters(w: &mut Writer, p: &Self::Parameters) -> Result<(), ArtifactError> {
        write_pcs(w, *p)
    }
    fn write_shape(w: &mut Writer, recursive: &Self::Recursive) -> Result<(), ArtifactError> {
        recursive.input_shape().write_identity(w)
    }
    fn suite() -> u16 {
        field_suite::<E, E>() | 0x300
    }
}

fn write_grouping(
    w: &mut Writer,
    p: crate::pcs::binary::BinaryCodewordGrouping,
) -> Result<(), ArtifactError> {
    use crate::pcs::binary::BinaryCodewordGrouping;
    let (tag, size) = match p {
        BinaryCodewordGrouping::Codeword(size) => (1, size),
        BinaryCodewordGrouping::Message(size) => (2, size),
        BinaryCodewordGrouping::Folding => (3, 0),
    };
    w.write_u8(tag)?;
    w.write_count("binary native grouping", size)
}

fn grouped_tree<F: Clone>(
    tree: &NativeMmcs<F>,
    config: &BinaryPcsConfig,
    grouping: crate::pcs::binary::BinaryCodewordGrouping,
) -> p3_binary_pcs::GroupedCodewordMmcs<NativeMmcs<F>> {
    use p3_binary_pcs::GroupedCodewordMmcs;

    use crate::pcs::binary::BinaryCodewordGrouping;
    match grouping {
        BinaryCodewordGrouping::Codeword(size) => GroupedCodewordMmcs::new(tree.clone(), size),
        BinaryCodewordGrouping::Message(size) => {
            GroupedCodewordMmcs::with_group_size(tree.clone(), config, size)
        }
        BinaryCodewordGrouping::Folding => GroupedCodewordMmcs::for_folding(tree.clone(), config),
    }
}

fn grouped_pcs<F, E>(
    p: &BinaryNativeGroupedPcsParameters,
    base: &NativeMmcs<F>,
    round: &NativeMmcs<E>,
) -> Result<config::NativeGroupedPcs<F, E>, p3_binary_pcs::BinaryPcsConfigError>
where
    F: RecursiveBinaryTowerField + EncodableLevel + FoldAlphabet<E> + PackedValue<Value = F>,
    E: RecursiveBinaryChallengeField
        + ExtensionField<F>
        + ChallengeField<F>
        + FoldAlphabet<E>
        + PackedValue<Value = E>,
{
    BinaryPcs::new(
        p.pcs.config,
        grouped_tree(base, &p.pcs.config, p.base_grouping),
        grouped_tree(round, &p.pcs.config, p.round_grouping),
    )
}

fn grouped_boolean_trace_pcs<E>(
    p: &BinaryNativeGroupedPcsParameters,
    base: &NativeMmcs<E>,
    round: &NativeMmcs<E>,
) -> Result<
    config::NativeGroupedBooleanTracePcs<E>,
    p3_binary_pcs::BooleanTraceError<
        E,
        <p3_binary_pcs::GroupedCodewordMmcs<NativeMmcs<E>> as p3_commit::Mmcs<E>>::Error,
    >,
>
where
    E: RecursiveBinaryChallengeField
        + EncodableLevel
        + ExtensionField<E>
        + ChallengeField<E>
        + FoldAlphabet<E>
        + p3_binary_pcs::Coordinates
        + PackedValue<Value = E>,
{
    p3_binary_pcs::BooleanTracePcs::new(
        p.pcs.config,
        grouped_tree(base, &p.pcs.config, p.base_grouping),
        grouped_tree(round, &p.pcs.config, p.round_grouping),
        p.pcs.config.num_variables() + E::RAW_BITS.ilog2() as usize,
    )
}

fn boolean_trace_pcs<E>(
    p: &BinaryNativePcsParameters,
    base: &NativeMmcs<E>,
    round: &NativeMmcs<E>,
) -> Result<
    config::NativeBooleanTracePcs<E>,
    p3_binary_pcs::BooleanTraceError<E, <NativeMmcs<E> as p3_commit::Mmcs<E>>::Error>,
>
where
    E: RecursiveBinaryChallengeField
        + EncodableLevel
        + ExtensionField<E>
        + ChallengeField<E>
        + FoldAlphabet<E>
        + p3_binary_pcs::Coordinates
        + PackedValue<Value = E>,
{
    p3_binary_pcs::BooleanTracePcs::new(
        p.config,
        base.clone(),
        round.clone(),
        p.config.num_variables() + E::RAW_BITS.ilog2() as usize,
    )
}
