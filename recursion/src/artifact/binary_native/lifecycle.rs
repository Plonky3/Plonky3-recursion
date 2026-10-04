//! Shared lifecycle for the private, complete native binary proof families.

use alloc::boxed::Box;
use alloc::vec;

use p3_matrix::Matrix;
use p3_multi_stark::config::ProverData;
use p3_multi_stark::{
    ProverInstance, ProverInstances, VerifierInstance, VerifierInstances, VerifyingKey,
};
use p3_sumcheck::layout::Table;

use super::*;

pub(super) struct State<F, E, A, K = RawFamily>
where
    F: NativeAlphabet + TranscriptField + PackedValue<Value = F>,
    E: ExtensionField<F> + PackedValue<Value = E>,
    K: NativeFamily<F, E>,
{
    pub(super) config: K::Config,
    airs: Box<[A]>,
    heights: Box<[usize]>,
    key: VerifyingKey<K::Config>,
    pub(super) binary: K::Recursive,
    pub(super) spec: BinaryNativeVerifierSpec<K::Parameters>,
    pub(super) identity: Arc<[u8]>,
    pub(super) limits: ArtifactLimits,
    base: NativeMmcs<F>,
    round: NativeMmcs<E>,
    preprocessed: Option<(NativeMmcs<F>, NativeMmcs<E>)>,
    pub(super) decode: K::Decode,
}

pub(super) fn setup<F, E, A, K>(
    airs: Vec<A>,
    heights: Vec<usize>,
    spec: BinaryNativeVerifierSpec<K::Parameters>,
    limits: ArtifactLimits,
) -> Result<(Arc<State<F, E, A, K>>, ProvingKey<K::Config>), VerificationError>
where
    F: NativeAlphabet + TranscriptField + PackedValue<Value = F>,
    E: ExtensionField<F> + PackedValue<Value = E>,
    A: VerifierAir<F, E>,
    K: NativeFamily<F, E>,
{
    let mut usage = InputResourceUsage::default();
    usage.add_instances(&limits.verifier, airs.len())?;
    usage.add_metadata_entries(&limits.verifier, spec.initial_bytes.len())?;
    if spec.security_bits == 0 || spec.security_bits > 128 {
        return Err(invalid(
            "binary native security target must be within 1..=128",
        ));
    }
    let grind_limit = (1usize << F::LOG_BITS)
        .min(64)
        .saturating_sub(8)
        .min(usize::BITS as usize - 1);
    for bits in core::iter::once(spec.sumcheck_pow_bits)
        .chain(core::iter::once(K::pow_bits(&spec.main)))
        .chain(spec.preprocessed.iter().map(K::pow_bits))
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
    let roots = if let Some(pp) = &spec.preprocessed {
        let cap_height = K::cap_height(pp);
        if cap_height >= usize::BITS as usize {
            return Err(invalid("binary native preprocessing cap shift is invalid"));
        }
        let roots = 1usize << cap_height;
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
    let mut binary = K::build_recursive(&refs, &heights, &spec, roots, &limits.verifier)?;
    let mut total_usage = K::usage(&binary);
    total_usage.add_metadata_entries(&limits.verifier, spec.initial_bytes.len())?;
    // Native setup panics on a missing preprocessing table. Validate trusted
    // tables after the recursive plan has checked the heights and widths.
    for (air, &height) in airs.iter().zip(&heights) {
        if air.preprocessed_width() != 0 {
            let trace = air
                .preprocessed_trace()
                .ok_or_else(|| invalid("binary native AIR is missing its preprocessed trace"))?;
            if trace.width() != air.preprocessed_width() || trace.height() != 1usize << height {
                return Err(invalid("binary native preprocessed trace shape mismatch"));
            }
        }
    }
    let base = tree(K::hash(&spec.main), K::cap_height(&spec.main));
    let round = tree(K::hash(&spec.main), K::cap_height(&spec.main));
    let preprocessed = spec.preprocessed.as_ref().map(|pp| {
        (
            tree(K::hash(pp), K::cap_height(pp)),
            tree(K::hash(pp), K::cap_height(pp)),
        )
    });
    let config = K::build_config(&spec, &base, &round, preprocessed.as_ref())?;
    let mut setup_ch = BinaryNativeChallenger::for_setup(roots, spec.transcript_hash);
    let (proving, verifying) = p3_multi_stark::setup(&config, &refs, &mut setup_ch)
        .map_err(|_| invalid("binary native setup rejected"))?;
    if let Some(cap) = setup_ch.finish_setup(roots)? {
        K::bind_preprocessing(&mut binary, cap)?;
    }
    let decode = K::decode_shape(&binary);
    let public = K::public_counts(&decode)
        .iter()
        .map(|&count| vec![F::ZERO; count])
        .collect::<Vec<_>>();
    let instances = VerifierInstances::new(
        airs.iter()
            .zip(&heights)
            .zip(&public)
            .map(|((air, &height), public)| VerifierInstance::new(air, &verifying, height, public))
            .collect(),
    );
    p3_multi_stark::security_report(&config, &instances)
        .and_then(|report| report.require_security(spec.security_bits))
        .map_err(|_| invalid("binary native statement security target is not met"))?;
    let identity = identity::<F, E, K>(&binary, &spec, &limits)
        .map_err(identity_error)?
        .into_boxed_slice();
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
    Ok((state, proving))
}

impl<F, E, A, K> State<F, E, A, K>
where
    F: NativeAlphabet + TranscriptField + PackedValue<Value = F>,
    E: ExtensionField<F> + PackedValue<Value = E>,
    K: NativeFamily<F, E>,
{
    fn challenger(&self) -> BinaryNativeChallenger<F> {
        BinaryNativeChallenger::fresh(self.spec.initial_bytes.clone(), self.spec.transcript_hash)
    }
    pub(super) fn check_public(&self, public: &[Vec<F>]) -> Result<(), VerificationError> {
        if public.len() != self.airs.len()
            || public
                .iter()
                .zip(K::public_counts(&self.decode))
                .any(|(values, &count)| values.len() != count)
        {
            return Err(invalid(
                "binary native independent statement shape mismatch",
            ));
        }
        Ok(())
    }
    pub(super) fn verify_native(
        &self,
        proof: &MultiStarkProof<K::Config>,
        expected: &[Vec<F>],
    ) -> Result<K::Input, VerificationError>
    where
        A: VerifierAir<F, E>,
    {
        self.check_public(expected)?;
        let input = K::import_native(
            &self.binary,
            &self.config,
            &self.base,
            &self.round,
            self.preprocessed.as_ref(),
            expected,
            proof,
            &mut self.challenger(),
        )?;
        let instances = VerifierInstances::new(
            self.airs
                .iter()
                .zip(self.heights.iter())
                .zip(expected)
                .map(|((air, &height), public)| {
                    VerifierInstance::new(air, &self.key, height, public)
                })
                .collect(),
        );
        p3_multi_stark::verify_with_security(
            &self.config,
            instances,
            proof,
            self.spec.sumcheck_pow_bits,
            self.spec.security_bits,
            &mut self.challenger(),
        )
        .map_err(|_| invalid("binary native proof verification rejected"))?;
        Ok(input)
    }
    pub(super) fn prove(
        &self,
        key: &ProvingKey<K::Config>,
        public: &[Vec<F>],
        traces: Vec<RowMajorMatrix<F>>,
    ) -> Result<MultiStarkProof<K::Config>, VerificationError>
    where
        A: ProverAir<F, E>,
        E::ExtensionPacking: From<E> + From<F::Packing>,
        ProverData<K::Config>: Clone,
    {
        self.check_public(public)?;
        if traces.len() != self.airs.len()
            || traces
                .iter()
                .zip(self.airs.iter())
                .zip(self.heights.iter())
                .any(|((trace, air), &height)| {
                    trace.width() != air.width() || trace.height() != 1usize << height
                })
        {
            return Err(invalid("binary native main trace shape mismatch"));
        }
        let instances = ProverInstances::new(
            traces
                .into_iter()
                .zip(self.airs.iter())
                .zip(public)
                .map(|((trace, air), values)| {
                    ProverInstance::new(air, Table::new(trace.transpose()), key, values)
                })
                .collect(),
        );
        p3_multi_stark::prove_with_security(
            &self.config,
            instances,
            self.spec.sumcheck_pow_bits,
            self.spec.security_bits,
            &mut self.challenger(),
        )
        .map_err(|_| invalid("binary native proof generation rejected"))
    }
}
