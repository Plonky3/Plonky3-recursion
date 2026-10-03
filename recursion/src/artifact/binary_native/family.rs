//! Private closed-family boundary for matched native binary proof owners.

use super::*;
use alloc::vec;
use p3_binary_pcs::BinaryPcs;
use p3_sumcheck::PrescribedPointPcs;

pub(super) trait NativeFamily<F, E>
where
    F: RecursiveBinaryTowerField + EncodableLevel + FoldAlphabet<E> + PackedValue<Value = F>,
    E: RecursiveBinaryChallengeField
        + ExtensionField<F>
        + ChallengeField<F>
        + FoldAlphabet<E>
        + PackedValue<Value = E>,
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
