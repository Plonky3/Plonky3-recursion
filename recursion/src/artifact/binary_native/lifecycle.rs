//! Shared lifecycle for the private, complete native binary proof families.

use alloc::boxed::Box;
use alloc::vec;

use p3_air::BaseAir;
use p3_matrix::Matrix;
use p3_multi_stark::config::ProverData;
use p3_multi_stark::{
    ProverInstance, ProverInstances, VerifierInstance, VerifierInstances, VerifyingKey,
};
use p3_sumcheck::layout::Table;

use super::*;

type SetupOutput<F, E, A, K> = (
    Arc<State<F, E, A, K>>,
    ProvingKey<<K as NativeFamily<F, E>>::Config>,
);

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
    /// The statement's composed security, checked against `spec.security_bits` at setup.
    pub(super) security: MultiStarkSecurityReport,
    trees: K::Trees,
    preprocessed_trees: Option<K::Trees>,
    pub(super) decode: K::Decode,
}

pub(super) fn setup<F, E, A, K>(
    airs: Vec<A>,
    heights: Vec<usize>,
    spec: BinaryNativeVerifierSpec<K::Parameters>,
    limits: ArtifactLimits,
) -> Result<SetupOutput<F, E, A, K>, VerificationError>
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
    check_boolean_assumptions::<F, E, A, K>(&airs, &spec.main)?;
    let refs = airs.iter().collect::<Vec<_>>();
    let roots = if let Some(pp) = &spec.preprocessed {
        let roots = K::arity(pp)
            .cap_roots(K::cap_height(pp))
            .ok_or_else(|| invalid("binary native preprocessing cap shift is invalid"))?;
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
    let mut preprocessed_tables = Vec::new();
    for (air, &height) in airs.iter().zip(&heights) {
        if air.preprocessed_width() != 0 {
            let trace = air
                .preprocessed_trace()
                .ok_or_else(|| invalid("binary native AIR is missing its preprocessed trace"))?;
            if trace.width() != air.preprocessed_width() || trace.height() != 1usize << height {
                return Err(invalid("binary native preprocessed trace shape mismatch"));
            }
            preprocessed_tables.push(Table::new(trace.transpose()));
        }
    }
    let trees = K::trees(&spec.main);
    let preprocessed_trees = spec.preprocessed.as_ref().map(K::trees);
    let config = K::build_config(&spec, &trees, preprocessed_trees.as_ref())?;
    let mut setup_ch = BinaryNativeChallenger::for_setup(roots, spec.transcript_hash);
    let (proving, verifying) = p3_multi_stark::setup_with_preprocessed_tables(
        &config,
        &refs,
        preprocessed_tables,
        &mut setup_ch,
    )
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
    let security = p3_multi_stark::security_report(&config, &instances)
        .and_then(|report| report.require_security(spec.security_bits).map(|()| report))
        .map_err(|error| {
            VerificationError::InvalidProofShape(alloc::format!(
                "binary native statement security target is not met: {error}",
            ))
        })?;
    let identity = identity::<F, E, K>(&binary, &spec, &limits)
        .map_err(|error| identity_error(&error))?
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
        security,
        trees,
        preprocessed_trees,
        decode,
    });
    Ok((state, proving))
}

/// Refuses an AIR that declares bit columns unless the family's main commitment stores its
/// table as bits, as [`NativeFamily::bits_committed`] reports.
///
/// Under a commitment to field elements, an AIR that leaves its booleanity to the commitment
/// accepts a trace holding non-bits. The multi-STARK prover and verifier refuse such an AIR
/// outside the commitment's bit region. This check refuses it at setup, and also where a
/// family's bit region covers the table but the family reports no bit-committed table.
pub(super) fn check_boolean_assumptions<F, E, A, K>(
    airs: &[A],
    main: &K::Parameters,
) -> Result<(), VerificationError>
where
    F: NativeAlphabet + TranscriptField + PackedValue<Value = F>,
    E: ExtensionField<F> + PackedValue<Value = E>,
    A: BaseAir<F>,
    K: NativeFamily<F, E>,
{
    if airs
        .iter()
        .enumerate()
        .any(|(table, air)| air.boolean_columns() != 0 && !K::bits_committed(main, table))
    {
        return Err(invalid(
            "binary native AIR declares bit columns its commitment does not store as bits",
        ));
    }
    Ok(())
}

impl<F, E, A, K> State<F, E, A, K>
where
    F: NativeAlphabet + TranscriptField + PackedValue<Value = F>,
    E: ExtensionField<F> + PackedValue<Value = E>,
    K: NativeFamily<F, E>,
{
    /// Changes only the enforced security target. Consuming the matched pair
    /// prevents a retained authority snapshot from being mutated.
    pub(super) fn with_security_bits(
        state: Arc<Self>,
        authority: Arc<Self>,
        bits: usize,
    ) -> Result<Arc<Self>, VerificationError> {
        if !Arc::ptr_eq(&state, &authority) {
            return Err(invalid(
                "binary native security update requires matched keys",
            ));
        }
        if bits == 0 || bits > 128 {
            return Err(invalid(
                "binary native security target must be within 1..=128",
            ));
        }
        state.security.require_security(bits).map_err(|error| {
            VerificationError::InvalidProofShape(alloc::format!(
                "binary native statement security target is not met: {error}",
            ))
        })?;
        drop(authority);
        if state.spec.security_bits == bits {
            return Ok(state);
        }
        let mut state = Arc::try_unwrap(state).map_err(|_| {
            invalid("binary native security update has retained authority snapshots")
        })?;
        state.spec.security_bits = bits;
        state.identity = Arc::from(
            identity::<F, E, K>(&state.binary, &state.spec, &state.limits)
                .map_err(|error| identity_error(&error))?,
        );
        Ok(Arc::new(state))
    }

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
            &self.trees,
            self.preprocessed_trees.as_ref(),
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
        let tables = traces
            .into_iter()
            .map(|trace| Table::new(trace.transpose()))
            .collect();
        self.prove_tables(key, public, tables)
    }
    /// Main tables in AIR order, each of its AIR's width and height. A table may hold field
    /// cells or packed bits; the commitment decides which it accepts.
    pub(super) fn prove_tables(
        &self,
        key: &ProvingKey<K::Config>,
        public: &[Vec<F>],
        tables: Vec<Table<F>>,
    ) -> Result<MultiStarkProof<K::Config>, VerificationError>
    where
        A: ProverAir<F, E>,
        E::ExtensionPacking: From<E> + From<F::Packing>,
        ProverData<K::Config>: Clone,
    {
        self.prove_tables_with_backend::<p3_multi_stark::GenericBackend>(key, public, tables)
    }

    pub(super) fn prove_tables_with_backend<B>(
        &self,
        key: &ProvingKey<K::Config>,
        public: &[Vec<F>],
        tables: Vec<Table<F>>,
    ) -> Result<MultiStarkProof<K::Config>, VerificationError>
    where
        A: ProverAir<F, E>,
        B: p3_multi_stark::ZerocheckBackend<F, E, A>,
        E::ExtensionPacking: From<E> + From<F::Packing>,
        ProverData<K::Config>: Clone,
    {
        self.check_public(public)?;
        if tables.len() != self.airs.len()
            || tables
                .iter()
                .zip(self.airs.iter())
                .zip(self.heights.iter())
                .any(|((table, air), &height)| {
                    table.num_polys() != air.width() || table.num_variables() != height
                })
        {
            return Err(invalid("binary native main table shape mismatch"));
        }
        let instances = ProverInstances::new(
            tables
                .into_iter()
                .zip(self.airs.iter())
                .zip(public)
                .map(|((table, air), values)| ProverInstance::new(air, table, key, values))
                .collect(),
        );
        p3_multi_stark::prove_with_security_and_backend::<K::Config, A, B>(
            &self.config,
            instances,
            self.spec.sumcheck_pow_bits,
            self.spec.security_bits,
            &mut self.challenger(),
        )
        .map_err(|_| invalid("binary native proof generation rejected"))
    }
}
