extern crate std;

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use p3_baby_bear::BabyBear;
use p3_circuit::StatementSchema;
use p3_circuit::builder::CircuitBuilder;
use p3_circuit::ops::poseidon1_perm::{
    KoalaBearD1Width16 as P1KoalaBearD1Width16, Poseidon1PermCallBase,
};
use p3_circuit::ops::poseidon2_perm::{GoldilocksD2Width8, Poseidon2PermCallBase};
use p3_circuit::ops::{
    KoalaBearD1Width16, NpoTypeId, Op, Poseidon1Config, Poseidon2Config, PrimitiveOpType,
    generate_poseidon1_trace, generate_poseidon2_trace, generate_recompose_trace,
};
use p3_circuit::tables::NonPrimitiveTrace;
use p3_commit::{
    CommitmentOpening, ExtensionMmcs, OpeningRequest, Pcs, PeriodicLdeTable, PolynomialSpace,
    UnivariateStarkPcs,
};
use p3_field::PrimeCharacteristicRing;
use p3_field::extension::{BinomialExtensionField, QuinticTrinomialExtensionField};
use p3_fri::{FriParameters, HidingFriPcs};
use p3_goldilocks::{Goldilocks, Poseidon2Goldilocks};
use p3_koala_bear::{KoalaBear, default_koalabear_poseidon1_16, default_koalabear_poseidon2_16};
use p3_matrix::Matrix;
use p3_matrix::dense::RowMajorMatrix;
use p3_merkle_tree::MerkleTreeHidingMmcs;
use p3_symmetric::{CryptographicHasher, PaddingFreeSponge, Permutation};
use p3_test_utils::LiftPermToQuintic;
use p3_test_utils::corpus::{CaseRng, CorpusSpec, derive_family_seed, for_each_case};
use p3_test_utils::koala_bear_params::{
    Challenge, Challenger, DIGEST_ELEMS, Dft, MyCompress, MyHash,
};
#[cfg(debug_assertions)]
use p3_test_utils::rejection_oracle::{DebugRejectionKind, classify_debug_diagnostic};
use p3_uni_stark::StarkConfig;
use rand::SeedableRng;
use rand::rngs::StdRng;

#[derive(Clone)]
struct UnknownNonPrimitiveTrace;

impl NonPrimitiveTrace<BabyBear> for UnknownNonPrimitiveTrace {
    fn op_type(&self) -> NpoTypeId {
        NpoTypeId::new("test/unknown_source")
    }

    fn rows(&self) -> usize {
        1
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn boxed_clone(&self) -> Box<dyn NonPrimitiveTrace<BabyBear>> {
        Box::new(self.clone())
    }
}

use super::*;
use crate::ConstraintProfile;
use crate::batch_stark_prover::packing::MAX_SANE_LANES;
use crate::batch_stark_prover::{
    BABY_BEAR_MODULUS, KOALA_BEAR_MODULUS, Poseidon1Preprocessor, Poseidon2Preprocessor,
    poseidon1_air_builders_d5, poseidon1_table_provers_d5, poseidon2_air_builders,
    poseidon2_air_builders_d5, poseidon2_table_provers_d5, recompose_air_builders,
};
use crate::common::{NpoAirBuilder, NpoPreprocessor, get_airs_and_degrees_with_prep};
use crate::config::{self, BabyBearConfig, GoldilocksConfig, KoalaBearConfig};

const MAX_ASSURANCE_PROOF_CASES: u32 = 8;

fn assurance_proof_corpus_from_env() -> CorpusSpec {
    let start_seed = std::env::var("P3_ASSURANCE_START_SEED")
        .ok()
        .map_or(Ok(0), |raw| {
            raw.parse::<u64>()
                .map_err(|_| format!("P3_ASSURANCE_START_SEED must be a u64, got {raw:?}"))
        })
        .unwrap_or_else(|error| panic!("{error}"));
    let cases = std::env::var("P3_ASSURANCE_PROOF_CASES")
        .ok()
        .map_or(Ok(1), |raw| {
            raw.parse::<u32>().map_err(|_| {
                format!(
                    "P3_ASSURANCE_PROOF_CASES must be a u32 in 1..={MAX_ASSURANCE_PROOF_CASES}, got {raw:?}"
                )
            })
        })
        .unwrap_or_else(|error| panic!("{error}"));
    assert!(
        (1..=MAX_ASSURANCE_PROOF_CASES).contains(&cases),
        "P3_ASSURANCE_PROOF_CASES must be in 1..={MAX_ASSURANCE_PROOF_CASES}, got {cases}"
    );
    CorpusSpec { start_seed, cases }
}

#[derive(Clone)]
struct CountingPcs<P> {
    inner: P,
    preprocessing_commits: Arc<AtomicUsize>,
}

impl<P> CountingPcs<P> {
    fn new(inner: P) -> (Self, Arc<AtomicUsize>) {
        let preprocessing_commits = Arc::new(AtomicUsize::new(0));
        (
            Self {
                inner,
                preprocessing_commits: preprocessing_commits.clone(),
            },
            preprocessing_commits,
        )
    }
}

type DomainVal<P, ChallengeField, Challenger> =
    <<P as Pcs<ChallengeField, Challenger>>::Domain as PolynomialSpace>::Val;

impl<P, ChallengeField, Challenger> Pcs<ChallengeField, Challenger> for CountingPcs<P>
where
    P: Pcs<ChallengeField, Challenger>,
    ChallengeField: p3_field::ExtensionField<<P::Domain as PolynomialSpace>::Val>,
{
    type Domain = P::Domain;
    type Commitment = P::Commitment;
    type ProverData = P::ProverData;
    type Proof = P::Proof;
    type Error = P::Error;
    type ProverError = P::ProverError;

    fn natural_domain_for_degree(&self, degree: usize) -> Self::Domain {
        self.inner.natural_domain_for_degree(degree)
    }

    fn commit(
        &self,
        evaluations: impl IntoIterator<
            Item = (
                Self::Domain,
                RowMajorMatrix<<Self::Domain as PolynomialSpace>::Val>,
            ),
        >,
    ) -> Result<(Self::Commitment, Self::ProverData), Self::ProverError> {
        self.inner.commit(evaluations)
    }

    fn open(
        &self,
        commitment_data_with_opening_points: Vec<
            OpeningRequest<'_, Self::ProverData, ChallengeField>,
        >,
        fiat_shamir_challenger: &mut Challenger,
    ) -> Result<(p3_commit::OpenedValues<ChallengeField>, Self::Proof), Self::ProverError> {
        self.inner
            .open(commitment_data_with_opening_points, fiat_shamir_challenger)
    }

    fn verify(
        &self,
        commitments_with_opening_points: Vec<
            CommitmentOpening<ChallengeField, Self::Commitment, Self::Domain>,
        >,
        proof: &Self::Proof,
        fiat_shamir_challenger: &mut Challenger,
    ) -> Result<(), Self::Error> {
        self.inner.verify(
            commitments_with_opening_points,
            proof,
            fiat_shamir_challenger,
        )
    }
}

impl<P, ChallengeField, Challenger> UnivariateStarkPcs<ChallengeField, Challenger>
    for CountingPcs<P>
where
    P: UnivariateStarkPcs<ChallengeField, Challenger>,
    ChallengeField: p3_field::ExtensionField<<P::Domain as PolynomialSpace>::Val>,
{
    type EvaluationsOnDomain<'a> = P::EvaluationsOnDomain<'a>;

    const ZK: bool = P::ZK;

    fn log_max_trace_height(&self) -> usize {
        self.inner.log_max_trace_height()
    }

    fn log_min_trace_height(&self) -> usize {
        self.inner.log_min_trace_height()
    }

    fn commit_preprocessing(
        &self,
        evaluations: impl IntoIterator<
            Item = (
                Self::Domain,
                RowMajorMatrix<DomainVal<P, ChallengeField, Challenger>>,
            ),
        >,
    ) -> Result<(Self::Commitment, Self::ProverData), Self::ProverError> {
        self.preprocessing_commits.fetch_add(1, Ordering::SeqCst);
        self.inner.commit_preprocessing(evaluations)
    }

    fn commit_quotient(
        &self,
        quotient_domain: Self::Domain,
        quotient_evaluations: RowMajorMatrix<DomainVal<P, ChallengeField, Challenger>>,
        num_chunks: usize,
    ) -> Result<(Self::Commitment, Self::ProverData), Self::ProverError> {
        self.inner
            .commit_quotient(quotient_domain, quotient_evaluations, num_chunks)
    }

    fn get_quotient_ldes(
        &self,
        evaluations: impl IntoIterator<
            Item = (
                Self::Domain,
                RowMajorMatrix<DomainVal<P, ChallengeField, Challenger>>,
            ),
        >,
        num_chunks: usize,
    ) -> Result<Vec<RowMajorMatrix<DomainVal<P, ChallengeField, Challenger>>>, Self::ProverError>
    {
        self.inner.get_quotient_ldes(evaluations, num_chunks)
    }

    fn commit_ldes(
        &self,
        ldes: Vec<RowMajorMatrix<DomainVal<P, ChallengeField, Challenger>>>,
    ) -> Result<(Self::Commitment, Self::ProverData), Self::ProverError> {
        self.inner.commit_ldes(ldes)
    }

    fn get_evaluations_on_domain<'a>(
        &self,
        prover_data: &'a Self::ProverData,
        idx: usize,
        domain: Self::Domain,
    ) -> Self::EvaluationsOnDomain<'a> {
        self.inner
            .get_evaluations_on_domain(prover_data, idx, domain)
    }

    fn get_evaluations_on_domain_no_random<'a>(
        &self,
        prover_data: &'a Self::ProverData,
        idx: usize,
        domain: Self::Domain,
    ) -> Self::EvaluationsOnDomain<'a> {
        self.inner
            .get_evaluations_on_domain_no_random(prover_data, idx, domain)
    }

    fn open_with_preprocessing(
        &self,
        commitment_data_with_opening_points: Vec<
            OpeningRequest<'_, Self::ProverData, ChallengeField>,
        >,
        fiat_shamir_challenger: &mut Challenger,
        preprocessed_commitment: Option<usize>,
    ) -> Result<(p3_commit::OpenedValues<ChallengeField>, Self::Proof), Self::ProverError> {
        self.inner.open_with_preprocessing(
            commitment_data_with_opening_points,
            fiat_shamir_challenger,
            preprocessed_commitment,
        )
    }

    fn verify_with_preprocessing(
        &self,
        rounds: Vec<CommitmentOpening<ChallengeField, Self::Commitment, Self::Domain>>,
        proof: &Self::Proof,
        challenger: &mut Challenger,
        preprocessed_commitment: Option<usize>,
    ) -> Result<(), Self::Error> {
        self.inner
            .verify_with_preprocessing(rounds, proof, challenger, preprocessed_commitment)
    }

    fn get_opt_randomization_poly_commitment(
        &self,
        domain: impl IntoIterator<Item = Self::Domain>,
    ) -> Result<Option<(Self::Commitment, Self::ProverData)>, Self::ProverError> {
        self.inner.get_opt_randomization_poly_commitment(domain)
    }

    fn build_periodic_lde_table(
        &self,
        periodic_cols: &[Vec<DomainVal<P, ChallengeField, Challenger>>],
        trace_domain: Self::Domain,
        quotient_domain: Self::Domain,
    ) -> PeriodicLdeTable<DomainVal<P, ChallengeField, Challenger>>
    where
        Self::Domain: Clone,
        DomainVal<P, ChallengeField, Challenger>: Clone,
    {
        self.inner
            .build_periodic_lde_table(periodic_cols, trace_domain, quotient_domain)
    }
}

fn trusted_relation_circuit(multiplier: u32) -> p3_circuit::Circuit<BabyBear> {
    let mut builder = CircuitBuilder::<BabyBear>::new();
    let input = builder.public_input();
    let multiplier = builder.define_const(BabyBear::from_u32(multiplier));
    let expected = builder.public_input();
    let product = builder.mul(input, multiplier);
    builder.connect(product, expected);
    builder.build().unwrap()
}

#[test]
fn prepare_circuit_preserves_typed_profile_overflow_metadata() {
    let mut builder = CircuitBuilder::<BabyBear>::new();
    for value in 0..10 {
        let _ = builder.define_const(BabyBear::from_u32(value + 2));
    }
    let circuit = builder.build().unwrap();
    let prover = BatchStarkProver::new(config::baby_bear()).with_table_packing(
        TablePacking::new(1, 1)
            .with_min_trace_height(4)
            .with_strict_heights(),
    );

    match prover.prepare_circuit::<BabyBear, 1>(&circuit, &[], &[], ConstraintProfile::Standard) {
        Err(BatchStarkProverError::InvalidMetadata(ProofMetadataError::ProfileOverflow {
            table,
            needed,
            allowed,
        })) => {
            assert_eq!(table, "CONST");
            assert_eq!(needed, 16);
            assert_eq!(allowed, 4);
        }
        Ok(_) => panic!("strict preparation unexpectedly accepted an undersized CONST table"),
        Err(other) => panic!("expected typed profile overflow metadata, got {other}"),
    }
}

fn trusted_relation_proof(
    prepared: &PreparedCircuitProver<BabyBearConfig>,
    circuit: &p3_circuit::Circuit<BabyBear>,
    input: u32,
    output: u32,
) -> BatchStarkProof<BabyBearConfig> {
    let mut runner = circuit.runner();
    runner
        .set_public_inputs(&[BabyBear::from_u32(input), BabyBear::from_u32(output)])
        .unwrap();
    prepared.prove(&runner.run().unwrap()).unwrap()
}

#[test]
fn prepared_prover_rejects_unknown_nonempty_source_trace() {
    let circuit = trusted_relation_circuit(2);
    let prepared = BatchStarkProver::new(config::baby_bear())
        .prepare_circuit::<BabyBear, 1>(&circuit, &[], &[], ConstraintProfile::Standard)
        .unwrap();
    let mut runner = circuit.runner();
    runner
        .set_public_inputs(&[BabyBear::from_u32(3), BabyBear::from_u32(6)])
        .unwrap();
    let mut traces = runner.run().unwrap();
    traces.non_primitive_traces.insert(
        NpoTypeId::new("test/unknown_source"),
        Box::new(UnknownNonPrimitiveTrace),
    );

    assert!(matches!(
        prepared.prove(&traces),
        Err(BatchStarkProverError::MissingTableProver(op))
            if op == NpoTypeId::new("test/unknown_source")
    ));
}

#[test]
fn prepared_prover_rejects_duplicate_source_ownership_before_materialization() {
    let circuit = trusted_relation_circuit(2);
    let mut prover = BatchStarkProver::new(config::baby_bear());
    prover.register_table_prover(Box::new(RecomposeProver::<1>::new(1, false)));
    prover.register_table_prover(Box::new(RecomposeProver::<1>::new(1, false)));
    let prepared = prover
        .prepare_circuit::<BabyBear, 1>(&circuit, &[], &[], ConstraintProfile::Standard)
        .unwrap();
    let mut runner = circuit.runner();
    runner
        .set_public_inputs(&[BabyBear::from_u32(3), BabyBear::from_u32(6)])
        .unwrap();

    assert!(matches!(
        prepared.prove(&runner.run().unwrap()),
        Err(BatchStarkProverError::DuplicateTableSource(op))
            if op == NpoTypeId::recompose()
    ));
}

#[test]
fn default_table_prover_source_declaration_preserves_custom_identity() {
    let schema = StatementSchema::try_new(Vec::new()).unwrap();
    let prover = StatementProver::<1>::new(schema);
    let op_type = TableProver::<BabyBearConfig>::op_type(&prover);
    assert_eq!(
        TableProver::<BabyBearConfig>::source_op_types(&prover),
        vec![op_type]
    );
}

#[test]
fn hiding_trusted_preparation_reuses_one_salted_setup_with_fresh_proof_randomness() {
    const SALT_ELEMS: usize = 4;
    type HidingValMmcs = MerkleTreeHidingMmcs<
        <KoalaBear as p3_field::Field>::Packing,
        <KoalaBear as p3_field::Field>::Packing,
        MyHash,
        MyCompress,
        StdRng,
        2,
        DIGEST_ELEMS,
        SALT_ELEMS,
    >;
    type HidingChallengeMmcs = ExtensionMmcs<KoalaBear, Challenge, HidingValMmcs>;
    type HidingPcs = HidingFriPcs<KoalaBear, Dft, HidingValMmcs, HidingChallengeMmcs, StdRng>;
    type HidingConfig = StarkConfig<CountingPcs<HidingPcs>, Challenge, Challenger>;

    let permutation = default_koalabear_poseidon2_16();
    let value_mmcs = HidingValMmcs::new(
        MyHash::new(permutation.clone()),
        MyCompress::new(permutation.clone()),
        0,
        StdRng::seed_from_u64(11),
    );
    let fri_params = FriParameters::new_testing(HidingChallengeMmcs::new(value_mmcs.clone()), 0);
    let pcs = HidingPcs::new(
        Dft::default(),
        value_mmcs,
        fri_params,
        4,
        StdRng::seed_from_u64(7),
    );
    let (pcs, preprocessing_commits) = CountingPcs::new(pcs);
    let config = HidingConfig::new(pcs, Challenger::new(permutation));

    let mut builder = CircuitBuilder::<KoalaBear>::new();
    let _ = builder.define_const(KoalaBear::TWO);
    let circuit = builder.build().unwrap();
    let traces = circuit.runner().run().unwrap();
    let prepared = BatchStarkProver::new(config)
        .with_table_packing(TablePacking::new(4, 4).with_min_trace_height(32))
        .prepare_circuit::<KoalaBear, 1>(&circuit, &[], &[], ConstraintProfile::Standard)
        .unwrap();
    assert_eq!(preprocessing_commits.load(Ordering::SeqCst), 1);
    let verifier = prepared.verifier();

    let first = prepared.prove(&traces).unwrap();
    assert_eq!(preprocessing_commits.load(Ordering::SeqCst), 1);
    let second = prepared.prove(&traces).unwrap();
    assert_eq!(preprocessing_commits.load(Ordering::SeqCst), 1);
    verifier.verify(&first, &[]).unwrap();
    verifier.verify(&second, &[]).unwrap();

    let setup = &verifier
        .common_data()
        .preprocessed
        .as_ref()
        .unwrap()
        .commitment;
    assert_eq!(
        &first.stark_common.preprocessed.as_ref().unwrap().commitment,
        setup
    );
    assert_eq!(
        &second
            .stark_common
            .preprocessed
            .as_ref()
            .unwrap()
            .commitment,
        setup
    );
    assert_ne!(first.proof.commitments.main, second.proof.commitments.main);
}

#[test]
fn trusted_recompose_descriptor_keeps_raw_operation_rows() {
    let builder = RecomposeAirBuilder::<1>::new(2, false);
    let preprocessed_lane_width =
        crate::air::RecomposeAir::<BabyBear, 1>::preprocessed_lane_width_for(false);
    let preprocessed = vec![BabyBear::ZERO; 3 * preprocessed_lane_width];
    let built = <RecomposeAirBuilder<1> as NpoAirBuilder<BabyBearConfig, 1>>::try_build_trusted(
        &builder,
        &NpoTypeId::recompose(),
        &preprocessed,
        8,
        2,
        ConstraintProfile::Standard,
    )
    .unwrap();

    assert_eq!(built.descriptor.rows(), 3);
    assert_eq!(built.descriptor.lanes(), 2);
    assert_eq!(built.base_degree_bits, 3);
}

/// Independent proofs of one prepared circuit (e.g. the pairs of an aggregation level) are proven
/// from several threads against a single shared preparation.
#[test]
fn prepared_circuit_prover_is_shareable_across_threads() {
    const fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<PreparedCircuitProver<config::BabyBearConfig>>();
    assert_send_sync::<CircuitVerifier<config::BabyBearConfig>>();
    assert_send_sync::<Arc<CircuitProverData<config::BabyBearConfig>>>();
}

#[test]
fn trusted_verifier_outlives_prover_and_ignores_embedded_common() {
    let circuit_a = trusted_relation_circuit(2);
    let prepared_a = BatchStarkProver::new(config::baby_bear())
        .prepare_circuit::<BabyBear, 1>(&circuit_a, &[], &[], ConstraintProfile::Standard)
        .unwrap();
    let verifier_a = prepared_a.verifier();
    let weak_proving_data = Arc::downgrade(&prepared_a.circuit_prover_data);
    let mut proof_a = trusted_relation_proof(&prepared_a, &circuit_a, 4, 8);

    let circuit_b = trusted_relation_circuit(3);
    let prepared_b = BatchStarkProver::new(config::baby_bear())
        .prepare_circuit::<BabyBear, 1>(&circuit_b, &[], &[], ConstraintProfile::Standard)
        .unwrap();
    let proof_b = trusted_relation_proof(&prepared_b, &circuit_b, 4, 12);
    proof_a.stark_common = proof_b.stark_common;

    drop(prepared_a);
    assert!(
        weak_proving_data.upgrade().is_none(),
        "the verifier must not retain CircuitProverData"
    );
    verifier_a.verify(&proof_a, &[]).unwrap();
}

#[test]
fn independently_trusted_builtin_artifact_reconstructs_without_proving_state() {
    let circuit = trusted_relation_circuit(2);
    let prepared = BatchStarkProver::new(config::baby_bear())
        .prepare_circuit::<BabyBear, 1>(&circuit, &[], &[], ConstraintProfile::Standard)
        .unwrap();
    let proof = trusted_relation_proof(&prepared, &circuit, 4, 8);
    let original = prepared.verifier();
    let relation = original.relation();
    assert!(relation.non_primitives().is_empty());
    let parts = crate::TrustedBuiltinArtifactRelation::try_new(
        relation.table_packing().clone(),
        *relation.rows(),
        relation.ext_degree(),
        relation.reduction(),
        relation.alu_variant(),
        relation.constraint_profile(),
        Vec::new(),
        relation.statement_layout().schema().clone(),
        relation.statement_layout().table_instance(),
        relation.aggregation_statement_layout().cloned(),
        relation.trace_degree_bits().to_vec(),
    )
    .unwrap();
    let imported = CircuitVerifier::from_independently_trusted_builtin_artifact(
        original.config().clone(),
        parts,
        clone_common_data(original.common_data()),
    )
    .unwrap();

    drop(original);
    drop(prepared);
    imported.verify(&proof, &[]).unwrap();
}

#[test]
fn independently_trusted_builtin_artifact_rejects_common_routing_substitution() {
    let circuit = trusted_relation_circuit(2);
    let prepared = BatchStarkProver::new(config::baby_bear())
        .prepare_circuit::<BabyBear, 1>(&circuit, &[], &[], ConstraintProfile::Standard)
        .unwrap();
    let original = prepared.verifier();
    let relation = original.relation();
    let parts = crate::TrustedBuiltinArtifactRelation::try_new(
        relation.table_packing().clone(),
        *relation.rows(),
        relation.ext_degree(),
        relation.reduction(),
        relation.alu_variant(),
        relation.constraint_profile(),
        Vec::new(),
        relation.statement_layout().schema().clone(),
        relation.statement_layout().table_instance(),
        relation.aggregation_statement_layout().cloned(),
        relation.trace_degree_bits().to_vec(),
    )
    .unwrap();
    let mut common = clone_common_data(original.common_data());
    common
        .preprocessed
        .as_mut()
        .unwrap()
        .matrix_to_instance
        .swap(0, 1);

    assert!(matches!(
        CircuitVerifier::from_independently_trusted_builtin_artifact(
            original.config().clone(),
            parts,
            common,
        ),
        Err(BatchStarkProverError::RelationMismatch(_))
    ));
}

fn check_trusted_verifier_rejects_seeded_same_shape_foreign_relations(
    corpus: CorpusSpec,
    fixed_input: Option<u32>,
) {
    let circuit_a = trusted_relation_circuit(2);
    let prepared_a = BatchStarkProver::new(config::baby_bear())
        .prepare_circuit::<BabyBear, 1>(&circuit_a, &[], &[], ConstraintProfile::Standard)
        .unwrap();
    let circuit_b = trusted_relation_circuit(3);
    let prepared_b = BatchStarkProver::new(config::baby_bear())
        .prepare_circuit::<BabyBear, 1>(&circuit_b, &[], &[], ConstraintProfile::Standard)
        .unwrap();
    assert_eq!(
        prepared_a.relation(),
        prepared_b.relation(),
        "family=trusted-relation field=BabyBear/D1 mutation=foreign-root setup=same-shape"
    );
    let verifier_a = prepared_a.verifier();
    let verifier_b = prepared_b.verifier();
    let root_a = &verifier_a
        .common_data()
        .preprocessed
        .as_ref()
        .unwrap()
        .commitment;
    let root_b = &verifier_b
        .common_data()
        .preprocessed
        .as_ref()
        .unwrap()
        .commitment;
    assert_ne!(
        root_a, root_b,
        "family=trusted-relation field=BabyBear/D1 mutation=foreign-root setup=distinct-root"
    );

    for_each_case(corpus, |seed| {
        let mut rng = CaseRng::new(derive_family_seed(seed, 0x5452_5553_5445_4452));
        let input = fixed_input.unwrap_or_else(|| 1 + (rng.next_u64() % 1000) as u32);
        let proof_a = trusted_relation_proof(&prepared_a, &circuit_a, input, input * 2);
        let proof_b = trusted_relation_proof(&prepared_b, &circuit_b, input, input * 3);
        assert_eq!(
            &proof_a
                .stark_common
                .preprocessed
                .as_ref()
                .unwrap()
                .commitment,
            root_a,
            "family=trusted-relation field=BabyBear/D1 seed={seed} mutation=honest-a-root expected-stage=setup"
        );
        assert_eq!(
            &proof_b
                .stark_common
                .preprocessed
                .as_ref()
                .unwrap()
                .commitment,
            root_b,
            "family=trusted-relation field=BabyBear/D1 seed={seed} mutation=honest-b-root expected-stage=setup"
        );

        verifier_a.verify(&proof_a, &[]).unwrap_or_else(|error| {
            panic!(
                "family=trusted-relation field=BabyBear/D1 seed={seed} mutation=none expected-stage=native-accept-a error={error:?}"
            )
        });
        verifier_b.verify(&proof_b, &[]).unwrap_or_else(|error| {
            panic!(
                "family=trusted-relation field=BabyBear/D1 seed={seed} mutation=none expected-stage=native-accept-b error={error:?}"
            )
        });

        let error = verifier_a.verify(&proof_b, &[]).unwrap_err();
        assert!(
            matches!(error, BatchStarkProverError::Verify(_)),
            "family=trusted-relation field=BabyBear/D1 seed={seed} mutation=foreign-root expected-stage=native-verify error={error:?}"
        );
    });
}

#[test]
fn trusted_verifier_rejects_a_same_shape_foreign_relation() {
    check_trusted_verifier_rejects_seeded_same_shape_foreign_relations(
        CorpusSpec {
            start_seed: 0,
            cases: 1,
        },
        Some(4),
    );
}

#[test]
fn assurance_trusted_verifier_rejects_seeded_same_shape_foreign_relations() {
    check_trusted_verifier_rejects_seeded_same_shape_foreign_relations(
        assurance_proof_corpus_from_env(),
        None,
    );
}

#[test]
fn trusted_verifier_rejects_empty_present_next_rows_before_native_verification() {
    let circuit = trusted_relation_circuit(2);
    let prepared = BatchStarkProver::new(config::baby_bear())
        .prepare_circuit::<BabyBear, 1>(&circuit, &[], &[], ConstraintProfile::Standard)
        .unwrap();
    let verifier = prepared.verifier();
    let mut proof = trusted_relation_proof(&prepared, &circuit, 4, 8);
    assert!(
        proof.proof.opened_values.instances[1]
            .base_opened_values
            .trace_next
            .is_none()
    );
    assert!(
        proof.proof.opened_values.instances[1]
            .base_opened_values
            .preprocessed_next()
            .is_none()
    );
    verifier.verify(&proof, &[]).unwrap();

    proof.proof.opened_values.instances[1]
        .base_opened_values
        .trace_next = Some(Vec::new());
    assert!(matches!(
        verifier.verify(&proof, &[]),
        Err(BatchStarkProverError::InvalidMetadata(
            ProofMetadataError::UnsupportedEmptyNextRow {
                table: 1,
                kind: NextRowOpeningKind::Trace,
            }
        ))
    ));

    proof.proof.opened_values.instances[1]
        .base_opened_values
        .trace_next = None;
    proof.proof.opened_values.instances[1]
        .base_opened_values
        .preprocessed
        .as_mut()
        .expect("table 1 has preprocessed openings")
        .next = Some(Vec::new());
    assert!(matches!(
        verifier.verify(&proof, &[]),
        Err(BatchStarkProverError::InvalidMetadata(
            ProofMetadataError::UnsupportedEmptyNextRow {
                table: 1,
                kind: NextRowOpeningKind::Preprocessed,
            }
        ))
    ));
    proof.proof.opened_values.instances[1]
        .base_opened_values
        .preprocessed
        .as_mut()
        .expect("table 1 has preprocessed openings")
        .next = None;
    verifier.verify(&proof, &[]).unwrap();
}

#[test]
fn trusted_verifier_rejects_primitive_metadata_and_nonempty_statements() {
    let circuit = trusted_relation_circuit(2);
    let prepared = BatchStarkProver::new(config::baby_bear())
        .prepare_circuit::<BabyBear, 1>(&circuit, &[], &[], ConstraintProfile::Standard)
        .unwrap();
    let verifier = prepared.verifier();
    let mut proof = trusted_relation_proof(&prepared, &circuit, 4, 8);
    verifier.verify(&proof, &[]).unwrap();

    assert!(verifier.verify(&proof, &[BabyBear::ONE]).is_err());

    let packing = proof.table_packing.clone();
    proof.table_packing = packing.clone().with_public_alu_lanes(2, 1);
    assert!(matches!(
        verifier.validate_metadata(&proof),
        Err(BatchStarkProverError::RelationMismatch(_))
    ));
    proof.table_packing = packing;

    let rows = proof.rows;
    proof.rows = RowCounts::new([
        rows[PrimitiveTable::Const] + 1,
        rows[PrimitiveTable::Public],
        rows[PrimitiveTable::Alu],
    ]);
    assert!(verifier.validate_metadata(&proof).is_err());
    proof.rows = rows;

    proof.proof.degree_bits[0] += 1;
    assert!(verifier.validate_metadata(&proof).is_err());
    proof.proof.degree_bits[0] -= 1;

    proof.w_binomial = Some(BabyBear::TWO);
    assert!(verifier.validate_metadata(&proof).is_err());
    proof.w_binomial = None;

    proof.alu_quintic_trinomial = true;
    assert!(verifier.validate_metadata(&proof).is_err());
    proof.alu_quintic_trinomial = false;
    verifier.verify(&proof, &[]).unwrap();

    proof.alu_variant = match proof.alu_variant {
        AirVariant::Baseline => AirVariant::Optimized,
        AirVariant::Optimized => AirVariant::Baseline,
    };
    assert!(verifier.validate_metadata(&proof).is_err());
}

#[test]
fn trusted_preparation_reuses_the_finalized_setup_for_repeated_proofs() {
    let mut builder = CircuitBuilder::<BabyBear>::new();
    let input = builder.public_input();
    let two = builder.define_const(BabyBear::TWO);
    let expected = builder.public_input();
    let doubled = builder.mul(input, two);
    builder.connect(doubled, expected);
    let circuit = builder.build().unwrap();

    let prepared = BatchStarkProver::new(config::baby_bear())
        .with_table_packing(TablePacking::new(4, 4))
        .prepare_circuit::<BabyBear, 1>(&circuit, &[], &[], ConstraintProfile::Standard)
        .unwrap();

    assert_eq!(prepared.relation().table_packing().public_lanes(), 4);
    assert_eq!(prepared.relation().table_packing().alu_lanes(), 1);

    let mut first_runner = circuit.runner();
    first_runner
        .set_public_inputs(&[BabyBear::from_u32(3), BabyBear::from_u32(6)])
        .unwrap();
    let first = prepared.prove(&first_runner.run().unwrap()).unwrap();
    let mut second_runner = circuit.runner();
    second_runner
        .set_public_inputs(&[BabyBear::from_u32(5), BabyBear::from_u32(10)])
        .unwrap();
    let second = prepared.prove(&second_runner.run().unwrap()).unwrap();

    assert_eq!(first.table_packing, *prepared.relation().table_packing());
    assert_eq!(first.rows, *prepared.relation().rows());
    assert_eq!(
        first.proof.degree_bits,
        prepared.relation().trace_degree_bits()
    );
    assert_eq!(second.proof.degree_bits, first.proof.degree_bits);
    assert_eq!(
        first.stark_common.preprocessed.as_ref().unwrap().commitment,
        second
            .stark_common
            .preprocessed
            .as_ref()
            .unwrap()
            .commitment
    );
}

#[derive(Debug)]
enum AlgebraicProofCheckError {
    Prove(BatchStarkProverError),
    Verify(BatchStarkProverError),
    #[cfg(debug_assertions)]
    DebugPanic(DebugRejectionKind),
}

impl core::fmt::Display for AlgebraicProofCheckError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Prove(error) => write!(f, "prover error: {error}"),
            Self::Verify(error) => write!(f, "verifier error: {error}"),
            #[cfg(debug_assertions)]
            Self::DebugPanic(kind) => write!(f, "debug rejection: {kind:?}"),
        }
    }
}

#[cfg(debug_assertions)]
fn run_with_strict_debug_oracle<T>(f: impl FnOnce() -> T) -> Result<T, DebugRejectionKind> {
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(f)) {
        Ok(value) => Ok(value),
        Err(payload) => {
            let message = payload
                .downcast_ref::<alloc::string::String>()
                .map(alloc::string::String::as_str)
                .or_else(|| payload.downcast_ref::<&str>().copied());
            if let Some(kind) = message.and_then(classify_debug_diagnostic) {
                return Err(kind);
            }
            std::panic::resume_unwind(payload)
        }
    }
}

fn assert_algebraic_rejection(result: &Result<(), AlgebraicProofCheckError>, context: &str) {
    #[cfg(debug_assertions)]
    assert!(
        matches!(
            result,
            Err(AlgebraicProofCheckError::DebugPanic(
                DebugRejectionKind::Constraint | DebugRejectionKind::Lookup
            ))
        ),
        "{context}: forged trace must hit a recognized debug rejection, got {result:?}"
    );

    #[cfg(not(debug_assertions))]
    assert!(
        matches!(
            result,
            Err(AlgebraicProofCheckError::Verify(
                BatchStarkProverError::Verify(_)
            ))
        ),
        "{context}: forged trace must prove and reach verifier algebraic rejection, got {result:?}"
    );
}

#[test]
fn test_babybear_batch_stark_base_field() {
    let mut builder = CircuitBuilder::<BabyBear>::new();

    // x + 5*2 - 3 + (-1) == expected
    let x = builder.public_input();
    let expected = builder.public_input();
    let c5 = builder.define_const(BabyBear::from_u64(5));
    let c2 = builder.define_const(BabyBear::from_u64(2));
    let c3 = builder.define_const(BabyBear::from_u64(3));
    let neg_one = builder.define_const(BabyBear::NEG_ONE);

    let mul_result = builder.mul(c5, c2); // 10
    let add_result = builder.add(x, mul_result); // x + 10
    let sub_result = builder.sub(add_result, c3); // x + 7
    let final_result = builder.add(sub_result, neg_one); // x + 6

    let diff = builder.sub(final_result, expected);
    builder.assert_zero(diff);

    let circuit = builder.build().unwrap();
    let cfg = config::baby_bear();
    let (airs_degrees, primitive_columns, non_primitive_columns) =
        get_airs_and_degrees_with_prep::<BabyBearConfig, _, 1>(
            &circuit,
            &TablePacking::default(),
            &[],
            &[],
            ConstraintProfile::Standard,
        )
        .unwrap();
    let (airs, log_degrees): (Vec<_>, Vec<usize>) = airs_degrees.into_iter().unzip();
    let prover_data = ProverData::from_airs_and_degrees(&cfg, &airs, &log_degrees).unwrap();
    let circuit_prover_data =
        CircuitProverData::new(prover_data, primitive_columns, non_primitive_columns);

    let mut runner = circuit.runner();

    let x_val = BabyBear::from_u64(7);
    let expected_val = BabyBear::from_u64(13); // 7 + 10 - 3 - 1 = 13
    runner.set_public_inputs(&[x_val, expected_val]).unwrap();
    let traces = runner.run().unwrap();

    let prover = BatchStarkProver::new(cfg);

    let proof = prover
        .prove_all_tables(&traces, &circuit_prover_data)
        .unwrap();
    assert_eq!(proof.ext_degree, 1);
    assert!(proof.w_binomial.is_none());

    assert!(prover.verify_all_tables::<BabyBear>(&proof).is_ok());

    // Soundness (#1.1): the reduction is bound to the verifier's expected trace field, so
    // verifying this D=1 proof against a D=4 field is rejected up front, before AIR rebuild.
    assert!(matches!(
        prover.verify_all_tables::<BinomialExtensionField<BabyBear, 4>>(&proof),
        Err(BatchStarkProverError::InvalidMetadata(
            ProofMetadataError::ExtDegreeMismatch {
                expected: 4,
                got: 1,
            }
        ))
    ));
}

#[test]
fn prove_all_tables_rejects_below_floor_table_packing_independent_of_prep() {
    // Prep is built with a VALID packing, so `get_airs_and_degrees_with_prep` (and the
    // preprocessed-column commitment it feeds) succeeds normally.
    let mut builder = CircuitBuilder::<BabyBear>::new();
    let x = builder.public_input();
    let expected = builder.public_input();
    let c5 = builder.define_const(BabyBear::from_u64(5));
    let prod = builder.mul(x, c5);
    let diff = builder.sub(prod, expected);
    builder.assert_zero(diff);

    let circuit = builder.build().unwrap();
    let cfg = config::baby_bear();
    let (airs_degrees, primitive_columns, non_primitive_columns) =
        get_airs_and_degrees_with_prep::<BabyBearConfig, _, 1>(
            &circuit,
            &TablePacking::default(),
            &[],
            &[],
            ConstraintProfile::Standard,
        )
        .unwrap();
    let (airs, log_degrees): (Vec<_>, Vec<usize>) = airs_degrees.into_iter().unzip();
    let prover_data = ProverData::from_airs_and_degrees(&cfg, &airs, &log_degrees).unwrap();
    let circuit_prover_data =
        CircuitProverData::new(prover_data, primitive_columns, non_primitive_columns);

    let mut runner = circuit.runner();
    runner
        .set_public_inputs(&[BabyBear::from_u64(7), BabyBear::from_u64(35)])
        .unwrap();
    let traces = runner.run().unwrap();

    // The prover's OWN table packing is invalid (a below-floor override), independent
    // of the packing used to build prep above. `prove_all_tables` must reject it
    // directly -- via `prove`'s own `validate()` call -- rather than silently padding
    // the main trace to a height inconsistent with the already-committed prep.
    let bad_packing = TablePacking::new(1, 1)
        .with_min_trace_height(32)
        .with_alu_min_height(4); // valid power of two, but below the 32 floor
    let prover = BatchStarkProver::new(cfg).with_table_packing(bad_packing);

    let result = prover.prove_all_tables(&traces, &circuit_prover_data);
    assert!(
        matches!(
            &result,
            Err(BatchStarkProverError::InvalidMetadata(
                ProofMetadataError::PerTableHeightBelowFloor { .. }
            ))
        ),
        "expected PerTableHeightBelowFloor, got {result:?}"
    );
}

#[test]
fn test_trace_next_suppressed_for_next_row_free_tables() {
    // Exercises Const, Public, and Alu tables. The Const and Public AIRs have no inter-row
    // constraints (`main_next_row_columns` is empty), so their `trace_next` opening must be
    // suppressed; the Alu AIR accesses the next row, so its `trace_next` is present. The native
    // proof must match each AIR's `main_next_row_columns`, and the prover and verifier must agree
    // on that shape (Fiat-Shamir bit-identity), which the final `verify_all_tables` confirms.
    let mut builder = CircuitBuilder::<BabyBear>::new();
    let x = builder.public_input();
    let expected = builder.public_input();
    let c5 = builder.define_const(BabyBear::from_u64(5));
    let prod = builder.mul(x, c5);
    let diff = builder.sub(prod, expected);
    builder.assert_zero(diff);

    let circuit = builder.build().unwrap();
    let cfg = config::baby_bear();
    let (airs_degrees, primitive_columns, non_primitive_columns) =
        get_airs_and_degrees_with_prep::<BabyBearConfig, _, 1>(
            &circuit,
            &TablePacking::default(),
            &[],
            &[],
            ConstraintProfile::Standard,
        )
        .unwrap();
    let (airs, log_degrees): (Vec<_>, Vec<usize>) = airs_degrees.into_iter().unzip();
    let prover_data = ProverData::from_airs_and_degrees(&cfg, &airs, &log_degrees).unwrap();
    let circuit_prover_data =
        CircuitProverData::new(prover_data, primitive_columns, non_primitive_columns);

    let mut runner = circuit.runner();
    runner
        .set_public_inputs(&[BabyBear::from_u64(7), BabyBear::from_u64(35)])
        .unwrap();
    let traces = runner.run().unwrap();

    let prover = BatchStarkProver::new(cfg);
    let proof = prover
        .prove_all_tables(&traces, &circuit_prover_data)
        .unwrap();

    let (mut any_suppressed, mut any_present) = (false, false);
    for (air, inst) in airs.iter().zip(proof.proof.opened_values.instances.iter()) {
        let expects_next = !p3_air::BaseAir::<BabyBear>::main_next_row_columns(air).is_empty();
        assert_eq!(
            inst.base_opened_values.trace_next.is_some(),
            expects_next,
            "trace_next presence must match the AIR's main_next_row_columns"
        );
        any_suppressed |= !expects_next;
        any_present |= expects_next;
    }
    assert!(
        any_suppressed,
        "Const/Public tables should suppress the trace_next opening"
    );
    assert!(any_present, "the Alu table should open trace_next");

    assert!(prover.verify_all_tables::<BabyBear>(&proof).is_ok());
}

#[test]
fn test_table_lookups() {
    let mut builder = CircuitBuilder::<BabyBear>::new();
    let cfg = config::baby_bear();

    // x + 5*2 - 3 + (-1) == expected
    let x = builder.public_input();
    let expected = builder.public_input();
    let c5 = builder.define_const(BabyBear::from_u64(5));
    let c2 = builder.define_const(BabyBear::from_u64(2));
    let c3 = builder.define_const(BabyBear::from_u64(3));
    let neg_one = builder.define_const(BabyBear::NEG_ONE);

    let mul_result = builder.mul(c5, c2); // 10
    let add_result = builder.add(x, mul_result); // x + 10
    let sub_result = builder.sub(add_result, c3); // x + 7
    let final_result = builder.add(sub_result, neg_one); // x + 6

    let diff = builder.sub(final_result, expected);
    builder.assert_zero(diff);

    let circuit = builder.build().unwrap();
    let default_packing = TablePacking::default();
    let (airs_degrees, primitive_columns, non_primitive_columns) =
        get_airs_and_degrees_with_prep::<BabyBearConfig, _, 1>(
            &circuit,
            &default_packing,
            &[],
            &[],
            ConstraintProfile::Standard,
        )
        .unwrap();
    let (airs, log_degrees): (Vec<_>, Vec<usize>) = airs_degrees.into_iter().unzip();

    let mut runner = circuit.runner();

    let x_val = BabyBear::from_u64(7);
    let expected_val = BabyBear::from_u64(13); // 7 + 10 - 3 - 1 = 13
    runner.set_public_inputs(&[x_val, expected_val]).unwrap();
    let traces = runner.run().unwrap();
    let prover_data = ProverData::from_airs_and_degrees(&cfg, &airs, &log_degrees).unwrap();
    let circuit_prover_data =
        CircuitProverData::new(prover_data, primitive_columns, non_primitive_columns);

    let prover = BatchStarkProver::new(cfg);

    let proof = prover
        .prove_all_tables(&traces, &circuit_prover_data)
        .unwrap();
    assert_eq!(proof.ext_degree, 1);
    assert!(proof.w_binomial.is_none());

    assert!(prover.verify_all_tables::<BabyBear>(&proof).is_ok());

    // Check that the generated lookups are correct and consistent across tables.
    for (air, &log_degree) in airs.iter().zip(log_degrees.iter()) {
        let lookups =
            crate::batch_stark_prover::lookups_for_circuit_table_air(air, 1usize << log_degree, 0);

        match air {
            CircuitTableAir::Const(_) => {
                assert_eq!(lookups.len(), 1, "Const table should have one lookup");
            }
            CircuitTableAir::Public(_) => {
                assert_eq!(lookups.len(), 1, "Public table should have one lookup");
            }
            CircuitTableAir::Alu(_) => {
                // The ALU declares 4 WitnessChecks sends per lane + 2 extra for double-step Horner
                // a1/c1, all on the same global bus. Same-bus packing folds them in pairs up to the
                // degree budget, halving the column count.
                let declared = default_packing.alu_lanes() * 4
                    + 2 * (default_packing.horner_packed_steps() - 1);
                let expected_num_lookups = declared.div_ceil(2);
                assert_eq!(
                    lookups.len(),
                    expected_num_lookups,
                    "ALU table should have {} packed lookups (declared {}), found {}",
                    expected_num_lookups,
                    declared,
                    lookups.len()
                );
            }
            CircuitTableAir::Dynamic(_dynamic_air) => {
                assert!(
                    lookups.is_empty(),
                    "There is no dynamic table in this test, so no lookups expected"
                );
            }
        }
    }
}

#[test]
fn test_extension_field_batch_stark() {
    const D: usize = 4;
    type Ext4 = BinomialExtensionField<BabyBear, D>;
    let cfg = config::baby_bear();

    let mut builder = CircuitBuilder::<Ext4>::new();
    let x = builder.public_input();
    let y = builder.public_input();
    let z = builder.public_input();
    let expected = builder.public_input();
    let xy = builder.mul(x, y);
    let res = builder.add(xy, z);
    let diff = builder.sub(res, expected);
    builder.assert_zero(diff);

    let circuit = builder.build().unwrap();
    let (airs_degrees, primitive_columns, non_primitive_columns) =
        get_airs_and_degrees_with_prep::<BabyBearConfig, _, D>(
            &circuit,
            &TablePacking::default(),
            &[],
            &[],
            ConstraintProfile::Standard,
        )
        .unwrap();
    let (airs, degrees): (Vec<_>, Vec<usize>) = airs_degrees.into_iter().unzip();

    let mut runner = circuit.runner();
    let xv = Ext4::from_basis_coefficients_slice(&[
        BabyBear::from_u64(2),
        BabyBear::from_u64(3),
        BabyBear::from_u64(5),
        BabyBear::from_u64(7),
    ])
    .unwrap();
    let yv = Ext4::from_basis_coefficients_slice(&[
        BabyBear::from_u64(11),
        BabyBear::from_u64(13),
        BabyBear::from_u64(17),
        BabyBear::from_u64(19),
    ])
    .unwrap();
    let zv = Ext4::from_basis_coefficients_slice(&[
        BabyBear::from_u64(23),
        BabyBear::from_u64(29),
        BabyBear::from_u64(31),
        BabyBear::from_u64(37),
    ])
    .unwrap();
    let expected_v = xv * yv + zv;
    runner.set_public_inputs(&[xv, yv, zv, expected_v]).unwrap();
    let traces = runner.run().unwrap();

    let prover_data = ProverData::from_airs_and_degrees(&cfg, &airs, &degrees).unwrap();
    let circuit_prover_data =
        CircuitProverData::new(prover_data, primitive_columns, non_primitive_columns);
    let prover = BatchStarkProver::new(cfg);

    let proof = prover
        .prove_all_tables(&traces, &circuit_prover_data)
        .unwrap();
    assert_eq!(proof.ext_degree, 4);
    // Ensure W was captured
    let expected_w = <Ext4 as ExtractBinomialW<BabyBear>>::extract_w().unwrap();
    assert_eq!(proof.w_binomial, Some(expected_w));
    prover
        .verify_all_tables::<BinomialExtensionField<BabyBear, 4>>(&proof)
        .unwrap();
}

#[test]
fn test_extension_field_table_lookups() {
    const D: usize = 4;
    type Ext4 = BinomialExtensionField<BabyBear, D>;
    let cfg = config::baby_bear();

    let mut builder = CircuitBuilder::<Ext4>::new();
    let x = builder.public_input();
    let y = builder.public_input();
    let z = builder.public_input();
    let expected = builder.public_input();
    let xy = builder.mul(x, y);
    let res = builder.add(xy, z);
    let diff = builder.sub(res, expected);
    builder.assert_zero(diff);

    let circuit = builder.build().unwrap();
    let default_packing = TablePacking::default();
    let mut air_builders_ext4 = poseidon2_air_builders::<BabyBearConfig, 4>();
    air_builders_ext4.extend(recompose_air_builders::<BabyBearConfig, 4>(1, false));
    let (airs_degrees, primitive_columns, non_primitive_columns) =
        get_airs_and_degrees_with_prep::<BabyBearConfig, _, D>(
            &circuit,
            &default_packing,
            &[],
            &air_builders_ext4,
            ConstraintProfile::Standard,
        )
        .unwrap();
    let (airs, log_degrees): (Vec<_>, Vec<usize>) = airs_degrees.into_iter().unzip();

    let mut runner = circuit.runner();

    let xv = Ext4::from_basis_coefficients_slice(&[
        BabyBear::from_u64(2),
        BabyBear::from_u64(3),
        BabyBear::from_u64(5),
        BabyBear::from_u64(7),
    ])
    .unwrap();
    let yv = Ext4::from_basis_coefficients_slice(&[
        BabyBear::from_u64(11),
        BabyBear::from_u64(13),
        BabyBear::from_u64(17),
        BabyBear::from_u64(19),
    ])
    .unwrap();
    let zv = Ext4::from_basis_coefficients_slice(&[
        BabyBear::from_u64(23),
        BabyBear::from_u64(29),
        BabyBear::from_u64(31),
        BabyBear::from_u64(37),
    ])
    .unwrap();
    let expected_v = xv * yv + zv;
    runner.set_public_inputs(&[xv, yv, zv, expected_v]).unwrap();
    let traces = runner.run().unwrap();

    let prover_data = ProverData::from_airs_and_degrees(&cfg, &airs, &log_degrees).unwrap();
    let circuit_prover_data =
        CircuitProverData::new(prover_data, primitive_columns, non_primitive_columns);

    let prover = BatchStarkProver::new(cfg);

    let proof = prover
        .prove_all_tables(&traces, &circuit_prover_data)
        .unwrap();
    assert_eq!(proof.ext_degree, 4);
    // Ensure W was captured
    let expected_w = <Ext4 as ExtractBinomialW<BabyBear>>::extract_w().unwrap();
    assert_eq!(proof.w_binomial, Some(expected_w));

    assert!(
        prover
            .verify_all_tables::<BinomialExtensionField<BabyBear, 4>>(&proof)
            .is_ok()
    );

    // Check that the generated lookups are correct and consistent across tables.
    for (air, &log_degree) in airs.iter().zip(log_degrees.iter()) {
        let lookups =
            crate::batch_stark_prover::lookups_for_circuit_table_air(air, 1usize << log_degree, 0);

        match air {
            CircuitTableAir::Const(_) => {
                assert_eq!(lookups.len(), 1, "Const table should have one lookup");
            }
            CircuitTableAir::Public(_) => {
                assert_eq!(lookups.len(), 1, "Public table should have one lookup");
            }
            CircuitTableAir::Alu(_) => {
                // The ALU declares 4 WitnessChecks sends per lane + 2 extra for double-step Horner
                // a1/c1, all on the same global bus. Same-bus packing folds them in pairs up to the
                // degree budget, halving the column count.
                let declared = default_packing.alu_lanes() * 4
                    + 2 * (default_packing.horner_packed_steps() - 1);
                let expected_num_lookups = declared.div_ceil(2);
                assert_eq!(
                    lookups.len(),
                    expected_num_lookups,
                    "ALU table should have {} packed lookups (declared {}), found {}",
                    expected_num_lookups,
                    declared,
                    lookups.len()
                );
            }
            CircuitTableAir::Dynamic(_dynamic_air) => {
                assert!(
                    lookups.is_empty(),
                    "There is no dynamic table in this test, so no lookups expected"
                );
            }
        }
    }
}

#[test]
fn test_koalabear_batch_stark_base_field() {
    let mut builder = CircuitBuilder::<KoalaBear>::new();
    let cfg = config::koala_bear();

    // a * b + 100 - (-1) == expected
    let a = builder.public_input();
    let b = builder.public_input();
    let expected = builder.public_input();
    let c = builder.define_const(KoalaBear::from_u64(100));
    let d = builder.define_const(KoalaBear::NEG_ONE);

    let ab = builder.mul(a, b);
    let add = builder.add(ab, c);
    let final_res = builder.sub(add, d);
    let diff = builder.sub(final_res, expected);
    builder.assert_zero(diff);

    let circuit = builder.build().unwrap();
    let (airs_degrees, primitive_columns, non_primitive_columns) =
        get_airs_and_degrees_with_prep::<KoalaBearConfig, _, 1>(
            &circuit,
            &TablePacking::default(),
            &[],
            &[],
            ConstraintProfile::Standard,
        )
        .unwrap();
    let (airs, degrees): (Vec<_>, Vec<usize>) = airs_degrees.into_iter().unzip();
    let mut runner = circuit.runner();

    let a_val = KoalaBear::from_u64(42);
    let b_val = KoalaBear::from_u64(13);
    let expected_val = KoalaBear::from_u64(647); // 42*13 + 100 - (-1)
    runner
        .set_public_inputs(&[a_val, b_val, expected_val])
        .unwrap();
    let traces = runner.run().unwrap();

    let prover_data = ProverData::from_airs_and_degrees(&cfg, &airs, &degrees).unwrap();
    let circuit_prover_data =
        CircuitProverData::new(prover_data, primitive_columns, non_primitive_columns);
    let prover = BatchStarkProver::new(cfg);

    let proof = prover
        .prove_all_tables(&traces, &circuit_prover_data)
        .unwrap();
    assert_eq!(proof.ext_degree, 1);
    assert!(proof.w_binomial.is_none());
    prover.verify_all_tables::<KoalaBear>(&proof).unwrap();
}

#[test]
fn test_koalabear_batch_stark_extension_field_d8() {
    const D: usize = 8;
    type KBExtField = BinomialExtensionField<KoalaBear, D>;
    let mut builder = CircuitBuilder::<KBExtField>::new();
    let cfg = config::koala_bear();

    // x * y * z == expected
    let x = builder.public_input();
    let y = builder.public_input();
    let expected = builder.public_input();
    let z = builder.define_const(
        KBExtField::from_basis_coefficients_slice(&[
            KoalaBear::from_u64(1),
            KoalaBear::NEG_ONE,
            KoalaBear::from_u64(2),
            KoalaBear::from_u64(3),
            KoalaBear::from_u64(4),
            KoalaBear::from_u64(5),
            KoalaBear::from_u64(6),
            KoalaBear::from_u64(7),
        ])
        .unwrap(),
    );

    let xy = builder.mul(x, y);
    let xyz = builder.mul(xy, z);
    let diff = builder.sub(xyz, expected);
    builder.assert_zero(diff);

    let circuit = builder.build().unwrap();
    let (airs_degrees, primitive_columns, non_primitive_columns) =
        get_airs_and_degrees_with_prep::<KoalaBearConfig, _, D>(
            &circuit,
            &TablePacking::default(),
            &[],
            &[],
            ConstraintProfile::Standard,
        )
        .unwrap();
    let (airs, degrees): (Vec<_>, Vec<usize>) = airs_degrees.into_iter().unzip();
    let mut runner = circuit.runner();

    let x_val = KBExtField::from_basis_coefficients_slice(&[
        KoalaBear::from_u64(4),
        KoalaBear::from_u64(6),
        KoalaBear::from_u64(8),
        KoalaBear::from_u64(10),
        KoalaBear::from_u64(12),
        KoalaBear::from_u64(14),
        KoalaBear::from_u64(16),
        KoalaBear::from_u64(18),
    ])
    .unwrap();
    let y_val = KBExtField::from_basis_coefficients_slice(&[
        KoalaBear::from_u64(12),
        KoalaBear::from_u64(14),
        KoalaBear::from_u64(16),
        KoalaBear::from_u64(18),
        KoalaBear::from_u64(20),
        KoalaBear::from_u64(22),
        KoalaBear::from_u64(24),
        KoalaBear::from_u64(26),
    ])
    .unwrap();
    let z_val = KBExtField::from_basis_coefficients_slice(&[
        KoalaBear::from_u64(1),
        KoalaBear::NEG_ONE,
        KoalaBear::from_u64(2),
        KoalaBear::from_u64(3),
        KoalaBear::from_u64(4),
        KoalaBear::from_u64(5),
        KoalaBear::from_u64(6),
        KoalaBear::from_u64(7),
    ])
    .unwrap();

    let expected_val = x_val * y_val * z_val;
    runner
        .set_public_inputs(&[x_val, y_val, expected_val])
        .unwrap();
    let traces = runner.run().unwrap();

    let prover_data = ProverData::from_airs_and_degrees(&cfg, &airs, &degrees).unwrap();
    let circuit_prover_data =
        CircuitProverData::new(prover_data, primitive_columns, non_primitive_columns);
    let prover = BatchStarkProver::new(cfg);

    let proof = prover
        .prove_all_tables(&traces, &circuit_prover_data)
        .unwrap();
    assert_eq!(proof.ext_degree, 8);
    let expected_w = <KBExtField as ExtractBinomialW<KoalaBear>>::extract_w().unwrap();
    assert_eq!(proof.w_binomial, Some(expected_w));
    prover
        .verify_all_tables::<BinomialExtensionField<KoalaBear, 8>>(&proof)
        .unwrap();
}

#[test]
fn test_goldilocks_batch_stark_binomial_ext2() {
    const D: usize = 2;
    type Ext2 = BinomialExtensionField<Goldilocks, D>;
    let mut builder = CircuitBuilder::<Ext2>::new();
    let cfg = config::goldilocks();

    // x * y + z == expected
    let x = builder.public_input();
    let y = builder.public_input();
    let z = builder.public_input();
    let expected = builder.public_input();

    let xy = builder.mul(x, y);
    let res = builder.add(xy, z);
    let diff = builder.sub(res, expected);
    builder.assert_zero(diff);

    let circuit = builder.build().unwrap();
    let mut air_builders_ext2 = poseidon2_air_builders::<GoldilocksConfig, 2>();
    air_builders_ext2.extend(recompose_air_builders::<GoldilocksConfig, 2>(1, false));
    let (airs_degrees, primitive_columns, non_primitive_columns) =
        get_airs_and_degrees_with_prep::<GoldilocksConfig, _, D>(
            &circuit,
            &TablePacking::default(),
            &[],
            &air_builders_ext2,
            ConstraintProfile::Standard,
        )
        .unwrap();
    let (airs, degrees): (Vec<_>, Vec<usize>) = airs_degrees.into_iter().unzip();
    let mut runner = circuit.runner();

    let x_val =
        Ext2::from_basis_coefficients_slice(&[Goldilocks::from_u64(3), Goldilocks::NEG_ONE])
            .unwrap();
    let y_val =
        Ext2::from_basis_coefficients_slice(&[Goldilocks::from_u64(7), Goldilocks::from_u64(11)])
            .unwrap();
    let z_val =
        Ext2::from_basis_coefficients_slice(&[Goldilocks::from_u64(13), Goldilocks::from_u64(17)])
            .unwrap();
    let expected_val = x_val * y_val + z_val;

    runner
        .set_public_inputs(&[x_val, y_val, z_val, expected_val])
        .unwrap();
    let traces = runner.run().unwrap();

    let prover_data = ProverData::from_airs_and_degrees(&cfg, &airs, &degrees).unwrap();
    let circuit_prover_data =
        CircuitProverData::new(prover_data, primitive_columns, non_primitive_columns);
    let prover = BatchStarkProver::new(cfg);

    let proof = prover
        .prove_all_tables(&traces, &circuit_prover_data)
        .unwrap();
    assert_eq!(proof.ext_degree, 2);
    let expected_w = <Ext2 as ExtractBinomialW<Goldilocks>>::extract_w().unwrap();
    assert_eq!(proof.w_binomial, Some(expected_w));
    prover
        .verify_all_tables::<BinomialExtensionField<Goldilocks, 2>>(&proof)
        .unwrap();
}

#[test]
fn test_goldilocks_poseidon2_circuit_build_and_run() {
    const D: usize = 2;
    type Ext2 = BinomialExtensionField<Goldilocks, D>;
    let mut rng = <rand::rngs::SmallRng as rand::SeedableRng>::seed_from_u64(0);
    let perm = Poseidon2Goldilocks::<8>::new_from_rng_128(&mut rng);
    let perm_for_hash = perm.clone();
    let mut builder = CircuitBuilder::<Ext2>::new();
    builder.enable_poseidon2_perm_width_8::<GoldilocksD2Width8, _>(
        generate_poseidon2_trace::<Ext2, GoldilocksD2Width8>,
        perm,
    );
    builder.enable_recompose::<Goldilocks>(generate_recompose_trace::<Goldilocks, Ext2>);
    let poseidon2_config = Poseidon2Config::GOLDILOCKS_D2_W8;
    let inputs = [builder.public_input(), builder.public_input()];
    let hash_outputs = builder
        .add_hash_slice(&poseidon2_config, &inputs, true)
        .unwrap();
    let expected0 = builder.public_input();
    let expected1 = builder.public_input();
    let sub0 = builder.sub(hash_outputs[0], expected0);
    builder.assert_zero(sub0);
    let sub1 = builder.sub(hash_outputs[1], expected1);
    builder.assert_zero(sub1);
    let circuit = builder.build().unwrap();
    let mut runner = circuit.runner();
    let in0 =
        Ext2::from_basis_coefficients_slice(&[Goldilocks::from_u64(1), Goldilocks::ZERO]).unwrap();
    let in1 =
        Ext2::from_basis_coefficients_slice(&[Goldilocks::from_u64(2), Goldilocks::ZERO]).unwrap();
    let hasher = PaddingFreeSponge::<Poseidon2Goldilocks<8>, 8, 4, 4>::new(perm_for_hash);
    let base_inputs = [
        Goldilocks::from_u64(1),
        Goldilocks::ZERO,
        Goldilocks::from_u64(2),
        Goldilocks::ZERO,
    ];
    let expected_hash = hasher.hash_iter(base_inputs);
    let out0 = Ext2::from_basis_coefficients_slice(&expected_hash[0..2]).unwrap();
    let out1 = Ext2::from_basis_coefficients_slice(&expected_hash[2..4]).unwrap();
    runner.set_public_inputs(&[in0, in1, out0, out1]).unwrap();
    let _traces = runner.run().unwrap();
}

#[test]
fn test_koalabear_modulus_constant() {
    // Verify KOALA_BEAR_MODULUS matches the actual KoalaBear field modulus.
    // The modulus p satisfies: from_u64(p) == 0 in the field.
    assert_eq!(
        KoalaBear::from_u64(KOALA_BEAR_MODULUS),
        KoalaBear::ZERO,
        "KOALA_BEAR_MODULUS (0x{:x}) does not match KoalaBear's actual modulus",
        KOALA_BEAR_MODULUS
    );

    // Verify the exact hex value (2130706433 = 0x7f000001).
    assert_eq!(KOALA_BEAR_MODULUS, 0x7f000001);
    assert_eq!(KOALA_BEAR_MODULUS, 2130706433);

    // Verify arithmetic at the modulus boundary with hardcoded expected values.
    // (p - 1) + 2 = 1 in the field
    let p_minus_1 = KoalaBear::from_u64(KOALA_BEAR_MODULUS - 1);
    assert_eq!(p_minus_1, KoalaBear::NEG_ONE);
    assert_eq!(p_minus_1 + KoalaBear::TWO, KoalaBear::ONE);

    // (p - 1) * (p - 1) = 1 in the field (since (-1) * (-1) = 1)
    assert_eq!(p_minus_1 * p_minus_1, KoalaBear::ONE);

    // Verify from_u64(p + 1) == 1
    assert_eq!(KoalaBear::from_u64(KOALA_BEAR_MODULUS + 1), KoalaBear::ONE);
}

#[test]
fn test_babybear_modulus_constant() {
    // Verify BABY_BEAR_MODULUS matches the actual BabyBear field modulus.
    assert_eq!(
        BabyBear::from_u64(BABY_BEAR_MODULUS),
        BabyBear::ZERO,
        "BABY_BEAR_MODULUS (0x{:x}) does not match BabyBear's actual modulus",
        BABY_BEAR_MODULUS
    );

    // Verify the exact hex value (2013265921 = 0x78000001).
    assert_eq!(BABY_BEAR_MODULUS, 0x78000001);
    assert_eq!(BABY_BEAR_MODULUS, 2013265921);

    // Verify arithmetic at the modulus boundary.
    let p_minus_1 = BabyBear::from_u64(BABY_BEAR_MODULUS - 1);
    assert_eq!(p_minus_1, BabyBear::NEG_ONE);
    assert_eq!(p_minus_1 + BabyBear::TWO, BabyBear::ONE);
    assert_eq!(BabyBear::from_u64(BABY_BEAR_MODULUS + 1), BabyBear::ONE);
}

#[test]
fn test_mul_only_circuit_padding() {
    // Circuit with only mul operations; ALU table still needs correct padding/lanes handling.
    let mut builder = CircuitBuilder::<BabyBear>::new();
    let cfg = config::baby_bear();

    let x = builder.public_input();
    let y = builder.public_input();

    // Only multiplication, no addition
    builder.mul(x, y);

    let circuit = builder.build().unwrap();
    let (airs_degrees, primitive_columns, non_primitive_columns) =
        get_airs_and_degrees_with_prep::<BabyBearConfig, _, 1>(
            &circuit,
            &TablePacking::default(),
            &[],
            &[],
            ConstraintProfile::Standard,
        )
        .unwrap();
    let (airs, degrees): (Vec<_>, Vec<usize>) = airs_degrees.into_iter().unzip();
    let mut runner = circuit.runner();

    let x_val = BabyBear::from_u64(7);
    let y_val = BabyBear::from_u64(11);
    runner.set_public_inputs(&[x_val, y_val]).unwrap();
    let traces = runner.run().unwrap();

    let prover_data = ProverData::from_airs_and_degrees(&cfg, &airs, &degrees).unwrap();
    let circuit_prover_data =
        CircuitProverData::new(prover_data, primitive_columns, non_primitive_columns);

    let prover = BatchStarkProver::new(cfg);

    let proof = prover
        .prove_all_tables(&traces, &circuit_prover_data)
        .unwrap();
    prover.verify_all_tables::<BabyBear>(&proof).unwrap();
}

#[test]
fn test_add_only_circuit_padding() {
    // Circuit with only add operations; ALU table still needs correct padding/lanes handling.
    let mut builder = CircuitBuilder::<BabyBear>::new();
    let cfg = config::baby_bear();

    let x = builder.public_input();
    let y = builder.public_input();
    let expected = builder.public_input();

    // Only addition, no multiplication
    let sum = builder.add(x, y);
    let diff = builder.sub(sum, expected);
    builder.assert_zero(diff);

    let circuit = builder.build().unwrap();
    let (airs_degrees, primitive_columns, non_primitive_columns) =
        get_airs_and_degrees_with_prep::<BabyBearConfig, _, 1>(
            &circuit,
            &TablePacking::default(),
            &[],
            &[],
            ConstraintProfile::Standard,
        )
        .unwrap();
    let (airs, degrees): (Vec<_>, Vec<usize>) = airs_degrees.into_iter().unzip();
    let mut runner = circuit.runner();

    let x_val = BabyBear::from_u64(42);
    let y_val = BabyBear::from_u64(13);
    let expected_val = x_val + y_val;
    runner
        .set_public_inputs(&[x_val, y_val, expected_val])
        .unwrap();
    let traces = runner.run().unwrap();

    let prover_data = ProverData::from_airs_and_degrees(&cfg, &airs, &degrees).unwrap();
    let circuit_prover_data =
        CircuitProverData::new(prover_data, primitive_columns, non_primitive_columns);

    let prover = BatchStarkProver::new(cfg);

    let proof = prover
        .prove_all_tables(&traces, &circuit_prover_data)
        .unwrap();
    prover.verify_all_tables::<BabyBear>(&proof).unwrap();
}

fn koala_ef5_lift(b: KoalaBear) -> QuinticTrinomialExtensionField<KoalaBear> {
    QuinticTrinomialExtensionField::<KoalaBear>::from_basis_coefficients_slice(&[
        b,
        KoalaBear::ZERO,
        KoalaBear::ZERO,
        KoalaBear::ZERO,
        KoalaBear::ZERO,
    ])
    .expect("basis slice")
}

#[test]
fn test_koalabear_quintic_trinomial_batch_stark_with_poseidon_d1() {
    const D: usize = 5;
    type EF5 = QuinticTrinomialExtensionField<KoalaBear>;

    // Must match KoalaBearD1Width16::round_constants() in poseidon2-circuit-air (not RNG-derived).
    let inner_perm = default_koalabear_poseidon2_16();
    let mut sponge0 = [KoalaBear::ZERO; 16];
    sponge0[0] = KoalaBear::from_u64(11);
    sponge0[1] = KoalaBear::from_u64(13);
    let sponge_out = inner_perm.permute(sponge0);
    let lift_perm = LiftPermToQuintic::new(inner_perm);

    let in0 = koala_ef5_lift(KoalaBear::from_u64(11));
    let in1 = koala_ef5_lift(KoalaBear::from_u64(13));
    let exp0 = koala_ef5_lift(sponge_out[0]);
    let exp1 = koala_ef5_lift(sponge_out[1]);

    let mut builder = CircuitBuilder::<EF5>::new();
    builder.enable_poseidon2_perm_base::<KoalaBearD1Width16, _>(
        generate_poseidon2_trace::<EF5, KoalaBearD1Width16>,
        lift_perm,
    );
    builder.enable_recompose::<KoalaBear>(generate_recompose_trace::<KoalaBear, EF5>);

    let in_a = builder.public_input();
    let in_b = builder.public_input();
    builder
        .decompose_ext_to_base_coeffs::<KoalaBear>(in_a)
        .unwrap();
    let mut perm_inputs: [Option<_>; 16] = [None; 16];
    perm_inputs[0] = Some(in_a);
    perm_inputs[1] = Some(in_b);
    let (_pid, hash_outputs) = builder
        .add_poseidon2_perm_base(&Poseidon2PermCallBase {
            config: Poseidon2Config::KOALA_BEAR_D1_W16,
            new_start: true,
            inputs: perm_inputs,
            // Only CTL-expose rate limbs that are wired into the rest of the circuit; unused
            // exposed outputs would leave WitnessChecks Receive contributions unmatched.
            out_ctl: [true; 8],
            return_all_outputs: false,
            absorb_len: 0,
        })
        .unwrap();
    let e0 = builder.public_input();
    let e1 = builder.public_input();
    let h0_diff = builder.sub(hash_outputs[0].unwrap(), e0);
    let h1_diff = builder.sub(hash_outputs[1].unwrap(), e1);
    builder.assert_zero(h0_diff);
    builder.assert_zero(h1_diff);

    let circuit = builder.build().unwrap();
    let cfg = config::koala_bear();

    let npo_prep: Vec<Box<dyn NpoPreprocessor<KoalaBear>>> = vec![
        Box::new(Poseidon2Preprocessor),
        Box::new(RecomposePreprocessor::new(false)),
    ];
    let mut air_builders = poseidon2_air_builders_d5::<KoalaBearConfig>();
    air_builders.extend(recompose_air_builders::<KoalaBearConfig, D>(1, false));
    let (airs_degrees, primitive_columns, non_primitive_columns) =
        get_airs_and_degrees_with_prep::<KoalaBearConfig, _, D>(
            &circuit,
            &TablePacking::default(),
            &npo_prep,
            &air_builders,
            ConstraintProfile::Standard,
        )
        .unwrap();
    let (airs, degrees): (Vec<_>, Vec<usize>) = airs_degrees.into_iter().unzip();
    let mut runner = circuit.runner();

    runner.set_public_inputs(&[in0, in1, exp0, exp1]).unwrap();
    let traces = runner.run().unwrap();

    let prover_data = ProverData::from_airs_and_degrees(&cfg, &airs, &degrees).unwrap();
    let circuit_prover_data =
        CircuitProverData::new(prover_data, primitive_columns, non_primitive_columns);

    let mut prover = BatchStarkProver::new(cfg);
    for p in poseidon2_table_provers_d5(Poseidon2Config::KOALA_BEAR_D1_W16) {
        prover.register_table_prover(p);
    }
    prover.register_table_prover(Box::new(RecomposeProver::<D>::new(1, false)));

    let proof = prover
        .prove_all_tables(&traces, &circuit_prover_data)
        .unwrap();
    assert_eq!(proof.ext_degree, D);
    assert!(proof.w_binomial.is_none());
    assert!(proof.alu_quintic_trinomial);
    prover
        .verify_all_tables::<QuinticTrinomialExtensionField<KoalaBear>>(&proof)
        .unwrap();

    let mut trusted = BatchStarkProver::new(config::koala_bear());
    for table_prover in poseidon2_table_provers_d5(Poseidon2Config::KOALA_BEAR_D1_W16) {
        trusted.register_table_prover(table_prover);
    }
    trusted.register_table_prover(Box::new(RecomposeProver::<D>::new(1, false)));
    let prepared = trusted
        .prepare_circuit::<EF5, D>(
            &circuit,
            &npo_prep,
            &air_builders,
            ConstraintProfile::Standard,
        )
        .unwrap();
    let mut trusted_proof = prepared.prove(&traces).unwrap();
    let descriptor = &prepared.relation().non_primitives()[0];
    assert_eq!(
        descriptor.op_type(),
        &NpoTypeId::poseidon2_perm(Poseidon2Config::KOALA_BEAR_D1_W16)
    );
    assert_eq!(descriptor.rows(), trusted_proof.non_primitives[0].rows);
    assert_eq!(
        descriptor.rows(),
        1 << prepared.relation().trace_degree_bits()[3],
        "Poseidon descriptors retain the padded table height"
    );
    let verifier = prepared.verifier();
    verifier.verify(&trusted_proof, &[]).unwrap();
    assert_eq!(trusted_proof.non_primitives.len(), 2);

    trusted_proof.alu_quintic_trinomial = false;
    assert!(verifier.validate_metadata(&trusted_proof).is_err());
    trusted_proof.alu_quintic_trinomial = true;
    trusted_proof.w_binomial = Some(KoalaBear::TWO);
    assert!(verifier.validate_metadata(&trusted_proof).is_err());
    trusted_proof.w_binomial = None;
    verifier.verify(&trusted_proof, &[]).unwrap();
    trusted_proof.non_primitives[0].rows += 1;
    assert!(verifier.validate_metadata(&trusted_proof).is_err());
    trusted_proof.non_primitives[0].rows -= 1;
    trusted_proof.non_primitives[0].lanes += 1;
    assert!(verifier.validate_metadata(&trusted_proof).is_err());
    trusted_proof.non_primitives[0].lanes -= 1;
    trusted_proof.non_primitives[0].air_variant = AirVariant::Optimized;
    assert!(verifier.validate_metadata(&trusted_proof).is_err());
    trusted_proof.non_primitives[0].air_variant = AirVariant::Baseline;
    let op_type = trusted_proof.non_primitives[0].op_type.clone();
    trusted_proof.non_primitives[0].op_type = NpoTypeId::new("foreign");
    assert!(verifier.validate_metadata(&trusted_proof).is_err());
    trusted_proof.non_primitives[0].op_type = op_type;
    trusted_proof.non_primitives[0]
        .public_values
        .push(KoalaBear::ONE);
    assert!(verifier.validate_metadata(&trusted_proof).is_err());
    trusted_proof.non_primitives[0].public_values.clear();
    trusted_proof.non_primitives.swap(0, 1);
    assert!(verifier.validate_metadata(&trusted_proof).is_err());
    trusted_proof.non_primitives.swap(0, 1);
    verifier.verify(&trusted_proof, &[]).unwrap();
}

/// Two D=1 Poseidon rows in an EF5 circuit: the second row uses `new_start=false` so the full
/// 16-wide state chains through the compact D=1 preprocessed layout (sponge selectors, not Merkle).
#[test]
fn test_koalabear_quintic_trinomial_batch_stark_poseidon_d1_sponge_chain() {
    const D: usize = 5;
    type EF5 = QuinticTrinomialExtensionField<KoalaBear>;

    let inner_perm = default_koalabear_poseidon2_16();
    let mut sponge0 = [KoalaBear::ZERO; 16];
    sponge0[0] = KoalaBear::from_u64(11);
    sponge0[1] = KoalaBear::from_u64(13);
    let sponge_out0 = inner_perm.permute(sponge0);
    let sponge_out1 = inner_perm.permute(sponge_out0);
    let lift_perm = LiftPermToQuintic::new(inner_perm);

    let in0 = koala_ef5_lift(KoalaBear::from_u64(11));
    let in1 = koala_ef5_lift(KoalaBear::from_u64(13));
    let exp0 = koala_ef5_lift(sponge_out1[0]);
    let exp1 = koala_ef5_lift(sponge_out1[1]);

    let mut builder = CircuitBuilder::<EF5>::new();
    builder.enable_poseidon2_perm_base::<KoalaBearD1Width16, _>(
        generate_poseidon2_trace::<EF5, KoalaBearD1Width16>,
        lift_perm,
    );

    let in_a = builder.public_input();
    let in_b = builder.public_input();
    let mut perm0_inputs: [Option<_>; 16] = [None; 16];
    perm0_inputs[0] = Some(in_a);
    perm0_inputs[1] = Some(in_b);
    let (_pid0, _hash0) = builder
        .add_poseidon2_perm_base(&Poseidon2PermCallBase {
            config: Poseidon2Config::KOALA_BEAR_D1_W16,
            new_start: true,
            inputs: perm0_inputs,
            out_ctl: [false; 8],
            return_all_outputs: false,
            absorb_len: 0,
        })
        .unwrap();

    let perm1_inputs: [Option<_>; 16] = [None; 16];
    let (_pid1, hash1_outputs) = builder
        .add_poseidon2_perm_base(&Poseidon2PermCallBase {
            config: Poseidon2Config::KOALA_BEAR_D1_W16,
            new_start: false,
            inputs: perm1_inputs,
            out_ctl: [true; 8],
            return_all_outputs: false,
            absorb_len: 0,
        })
        .unwrap();
    let e0 = builder.public_input();
    let e1 = builder.public_input();
    let h0_diff = builder.sub(hash1_outputs[0].unwrap(), e0);
    let h1_diff = builder.sub(hash1_outputs[1].unwrap(), e1);
    builder.assert_zero(h0_diff);
    builder.assert_zero(h1_diff);

    let circuit = builder.build().unwrap();
    let cfg = config::koala_bear();

    let npo_prep: Vec<Box<dyn NpoPreprocessor<KoalaBear>>> = vec![Box::new(Poseidon2Preprocessor)];
    let air_builders = poseidon2_air_builders_d5::<KoalaBearConfig>();
    let (airs_degrees, primitive_columns, non_primitive_columns) =
        get_airs_and_degrees_with_prep::<KoalaBearConfig, _, D>(
            &circuit,
            &TablePacking::default(),
            &npo_prep,
            &air_builders,
            ConstraintProfile::Standard,
        )
        .unwrap();
    let (airs, degrees): (Vec<_>, Vec<usize>) = airs_degrees.into_iter().unzip();
    let mut runner = circuit.runner();

    runner.set_public_inputs(&[in0, in1, exp0, exp1]).unwrap();
    let traces = runner.run().unwrap();

    let prover_data = ProverData::from_airs_and_degrees(&cfg, &airs, &degrees).unwrap();
    let circuit_prover_data =
        CircuitProverData::new(prover_data, primitive_columns, non_primitive_columns);

    let mut prover = BatchStarkProver::new(cfg);
    for p in poseidon2_table_provers_d5(Poseidon2Config::KOALA_BEAR_D1_W16) {
        prover.register_table_prover(p);
    }

    let proof = prover
        .prove_all_tables(&traces, &circuit_prover_data)
        .unwrap();
    assert_eq!(proof.ext_degree, D);
    assert!(proof.w_binomial.is_none());
    assert!(proof.alu_quintic_trinomial);
    prover
        .verify_all_tables::<QuinticTrinomialExtensionField<KoalaBear>>(&proof)
        .unwrap();
}

/// Strict mode must reach non-primitive (NPO) tables too, not only the three primitive
/// tables: a Poseidon2 NPO table whose natural row count outgrows its configured
/// `npo_min_height` must be rejected with `ProfileOverflow { table: <the NPO's own
/// type-id string>, .. }`, exactly like the primitive-table case in `common.rs`'s
/// `strict_overflow_tests`.
#[test]
fn strict_packing_reports_npo_table_name_when_it_outgrows_its_configured_height() {
    use alloc::string::ToString;

    // Reuses the D=1 (base-field) Poseidon2 config inside a D=5 (quintic) outer circuit --
    // the only Poseidon2 wiring already proven to compile in this file (see
    // `test_koalabear_quintic_trinomial_batch_stark_poseidon_d1_sponge_chain` above);
    // `Poseidon2AirBuilder<D>` has no impl for outer `D=1`. No witness is ever executed
    // here (only the structural preprocessed-column path is exercised), so the actual
    // permutation values are irrelevant.
    type EF5 = QuinticTrinomialExtensionField<KoalaBear>;
    let inner_perm = default_koalabear_poseidon2_16();
    let lift_perm = LiftPermToQuintic::new(inner_perm);
    let mut builder = CircuitBuilder::<EF5>::new();
    builder.enable_poseidon2_perm_base::<KoalaBearD1Width16, _>(
        generate_poseidon2_trace::<EF5, KoalaBearD1Width16>,
        lift_perm,
    );

    let in_a = builder.public_input();
    let in_b = builder.public_input();
    let mut perm0_inputs: [Option<_>; 16] = [None; 16];
    perm0_inputs[0] = Some(in_a);
    perm0_inputs[1] = Some(in_b);
    builder
        .add_poseidon2_perm_base(&Poseidon2PermCallBase {
            config: Poseidon2Config::KOALA_BEAR_D1_W16,
            new_start: true,
            inputs: perm0_inputs,
            out_ctl: [false; 8],
            return_all_outputs: false,
            absorb_len: 0,
        })
        .unwrap();

    // 3 more chained rows (`new_start=false`), no outputs exposed yet.
    for _ in 0..3 {
        builder
            .add_poseidon2_perm_base(&Poseidon2PermCallBase {
                config: Poseidon2Config::KOALA_BEAR_D1_W16,
                new_start: false,
                inputs: [None; 16],
                out_ctl: [false; 8],
                return_all_outputs: false,
                absorb_len: 0,
            })
            .unwrap();
    }

    // Final row: expose 2 outputs so nothing is left dangling.
    let (_pid, outputs) = builder
        .add_poseidon2_perm_base(&Poseidon2PermCallBase {
            config: Poseidon2Config::KOALA_BEAR_D1_W16,
            new_start: false,
            inputs: [None; 16],
            out_ctl: [true, true, false, false, false, false, false, false],
            return_all_outputs: false,
            absorb_len: 0,
        })
        .unwrap();
    let e0 = builder.public_input();
    let e1 = builder.public_input();
    let h0_diff = builder.sub(outputs[0].unwrap(), e0);
    let h1_diff = builder.sub(outputs[1].unwrap(), e1);
    builder.assert_zero(h0_diff);
    builder.assert_zero(h1_diff);

    let circuit = builder.build().unwrap();

    // 5 Poseidon2 rows -> natural height 8, which exceeds the too-small override below
    // (itself still at or above the global floor, so `validate()` accepts it).
    let poseidon2_op_type =
        p3_circuit::ops::NpoTypeId::poseidon2_perm(Poseidon2Config::KOALA_BEAR_D1_W16);
    let packing = TablePacking::new(1, 1)
        .with_min_trace_height(4) // covers PUBLIC's natural height (4 public inputs)
        .with_npo_min_height(poseidon2_op_type.clone(), 4) // still < Poseidon2's natural (8)
        .with_strict_heights();

    let npo_prep: Vec<Box<dyn NpoPreprocessor<KoalaBear>>> = vec![Box::new(Poseidon2Preprocessor)];
    let air_builders = poseidon2_air_builders_d5::<KoalaBearConfig>();

    let result = get_airs_and_degrees_with_prep::<KoalaBearConfig, _, 5>(
        &circuit,
        &packing,
        &npo_prep,
        &air_builders,
        ConstraintProfile::Standard,
    );

    match result {
        Err(CircuitError::ProfileOverflow { table, .. }) => {
            assert_eq!(table, poseidon2_op_type.to_string());
        }
        Ok(_) => panic!("expected ProfileOverflow on the Poseidon2 NPO table, got Ok"),
        Err(other) => panic!("expected ProfileOverflow, got a different error: {other}"),
    }
}

#[test]
fn test_stark_serialization_round_trip() {
    let mut builder = CircuitBuilder::<BabyBear>::new();

    let x = builder.public_input();
    let expected = builder.public_input();
    let c5 = builder.define_const(BabyBear::from_u64(5));
    let c2 = builder.define_const(BabyBear::from_u64(2));
    let mul_result = builder.mul(c5, c2);
    let add_result = builder.add(x, mul_result);
    let diff = builder.sub(add_result, expected);
    builder.assert_zero(diff);

    let circuit = builder.build().unwrap();
    let cfg = config::baby_bear();
    let (airs_degrees, primitive_columns, non_primitive_columns) =
        get_airs_and_degrees_with_prep::<BabyBearConfig, _, 1>(
            &circuit,
            &TablePacking::default(),
            &[],
            &[],
            ConstraintProfile::Standard,
        )
        .unwrap();
    let (airs, log_degrees): (Vec<_>, Vec<usize>) = airs_degrees.into_iter().unzip();
    let prover_data = ProverData::from_airs_and_degrees(&cfg, &airs, &log_degrees).unwrap();
    let circuit_prover_data =
        CircuitProverData::new(prover_data, primitive_columns, non_primitive_columns);

    let mut runner = circuit.runner();
    let x_val = BabyBear::from_u64(7);
    let expected_val = BabyBear::from_u64(17); // 7 + 5*2 = 17
    runner.set_public_inputs(&[x_val, expected_val]).unwrap();
    let traces = runner.run().unwrap();

    let prover = BatchStarkProver::new(cfg);
    let proof = prover
        .prove_all_tables(&traces, &circuit_prover_data)
        .unwrap();

    let original_preprocessed = proof
        .stark_common
        .preprocessed
        .as_ref()
        .expect("preprocessed binding must be present");
    let original_matrix_to_instance = original_preprocessed.matrix_to_instance.clone();
    let original_instances_len = original_preprocessed.instances.len();

    let bytes = postcard::to_allocvec(&proof).expect("serialize proof");
    let deserialized: BatchStarkProof<BabyBearConfig> =
        postcard::from_bytes(&bytes).expect("deserialize proof");

    let restored_preprocessed = deserialized
        .stark_common
        .preprocessed
        .as_ref()
        .expect("preprocessed binding must survive (de)serialization");
    assert_eq!(
        restored_preprocessed.matrix_to_instance,
        original_matrix_to_instance
    );
    assert_eq!(
        restored_preprocessed.instances.len(),
        original_instances_len
    );

    // Verification must succeed against the deserialized proof, relying only on the
    // proof's own `stark_common` for the preprocessed binding.
    prover
        .verify_all_tables::<BabyBear>(&deserialized)
        .expect("verification uses proof.stark_common");
}

// --- Proof-metadata validation after deserialization ---------------------------
//
// `#[derive(Deserialize)]` bypasses the constructors that enforce structural
// invariants (non-zero row counts, lane clamping, power-of-two minimum height,
// `horner_packed_steps >= 2`). These tests deserialize/construct the invalid
// states a malicious or corrupt serialized proof could carry and assert that
// `validate()` rejects them before verification.

/// Field-compatible mirror of `TablePacking` (same field order/types) used to
/// forge invalid serialized packings. `postcard` is non-self-describing, so a
/// structurally identical struct round-trips into the real `TablePacking`.
#[derive(serde::Serialize)]
struct PackingMirror {
    public_lanes: usize,
    alu_lanes: usize,
    npo_lanes: Vec<(p3_circuit::ops::NpoTypeId, usize)>,
    alu_min_height: Option<usize>,
    public_min_height: Option<usize>,
    const_min_height: Option<usize>,
    npo_min_heights: Vec<(p3_circuit::ops::NpoTypeId, usize)>,
    min_trace_height: usize,
    horner_packed_steps: usize,
    strict: bool,
}

impl PackingMirror {
    fn valid() -> Self {
        Self {
            public_lanes: 1,
            alu_lanes: 1,
            npo_lanes: Vec::new(),
            alu_min_height: None,
            public_min_height: None,
            const_min_height: None,
            npo_min_heights: Vec::new(),
            min_trace_height: 1,
            horner_packed_steps: 2,
            strict: false,
        }
    }

    fn into_table_packing(self) -> TablePacking {
        let bytes = postcard::to_allocvec(&self).expect("serialize packing mirror");
        postcard::from_bytes(&bytes).expect("deserialize into TablePacking")
    }
}

#[test]
fn validate_rejects_zero_serialized_row_count() {
    // A `RowCounts` is a newtype over `[usize; N]`; derived `Deserialize` bypasses
    // `RowCounts::new`'s non-zero assertion.
    let bytes = postcard::to_allocvec(&[0usize, 1, 1]).expect("serialize raw row counts");
    let rows: RowCounts = postcard::from_bytes(&bytes).expect("deserialize RowCounts");
    assert_eq!(rows.validate(), Err(ProofMetadataError::ZeroRowCount));

    let ok = postcard::to_allocvec(&[1usize, 1, 1]).expect("serialize raw row counts");
    let rows: RowCounts = postcard::from_bytes(&ok).expect("deserialize RowCounts");
    assert_eq!(rows.validate(), Ok(()));
}

#[test]
fn validate_rejects_invalid_serialized_table_packing() {
    // Sanity: a valid mirror round-trips and validates.
    assert_eq!(
        PackingMirror::valid().into_table_packing().validate(),
        Ok(())
    );

    let zero_public = PackingMirror {
        public_lanes: 0,
        ..PackingMirror::valid()
    };
    assert_eq!(
        zero_public.into_table_packing().validate(),
        Err(ProofMetadataError::ZeroLanes("public_lanes"))
    );

    let zero_alu = PackingMirror {
        alu_lanes: 0,
        ..PackingMirror::valid()
    };
    assert_eq!(
        zero_alu.into_table_packing().validate(),
        Err(ProofMetadataError::ZeroLanes("alu_lanes"))
    );

    let op = p3_circuit::ops::NpoTypeId::new("test_op");
    let zero_npo = PackingMirror {
        npo_lanes: vec![(op.clone(), 0)],
        ..PackingMirror::valid()
    };
    assert_eq!(
        zero_npo.into_table_packing().validate(),
        Err(ProofMetadataError::ZeroNpoLanes(op))
    );

    let bad_alu_min_height = PackingMirror {
        alu_min_height: Some(24), // not a power of two
        ..PackingMirror::valid()
    };
    assert_eq!(
        bad_alu_min_height.into_table_packing().validate(),
        Err(ProofMetadataError::BadMinTraceHeight(24))
    );

    let op = p3_circuit::ops::NpoTypeId::new("test_op");
    let zero_npo_min_height = PackingMirror {
        npo_min_heights: vec![(op, 0)],
        ..PackingMirror::valid()
    };
    assert_eq!(
        zero_npo_min_height.into_table_packing().validate(),
        Err(ProofMetadataError::BadMinTraceHeight(0))
    );

    let bad_height = PackingMirror {
        min_trace_height: 24, // not a power of two
        ..PackingMirror::valid()
    };
    assert_eq!(
        bad_height.into_table_packing().validate(),
        Err(ProofMetadataError::BadMinTraceHeight(24))
    );

    let zero_height = PackingMirror {
        min_trace_height: 0,
        ..PackingMirror::valid()
    };
    assert_eq!(
        zero_height.into_table_packing().validate(),
        Err(ProofMetadataError::BadMinTraceHeight(0))
    );

    let bad_horner = PackingMirror {
        horner_packed_steps: 1,
        ..PackingMirror::valid()
    };
    assert_eq!(
        bad_horner.into_table_packing().validate(),
        Err(ProofMetadataError::BadHornerPackedSteps(1))
    );
}

#[test]
fn validate_rejects_oversized_serialized_table_packing() {
    // Huge lane counts and horner_packed_steps drive downstream width arithmetic
    // (`lanes * lane_width`) and unbounded loops; a corrupt or malicious serialized
    // proof must be rejected here, not overflow/DoS the trace builder.
    let huge_public = PackingMirror {
        public_lanes: usize::MAX,
        ..PackingMirror::valid()
    };
    assert_eq!(
        huge_public.into_table_packing().validate(),
        Err(ProofMetadataError::LanesTooLarge {
            field: "public_lanes",
            got: usize::MAX,
            max: MAX_SANE_LANES,
        })
    );

    let huge_alu = PackingMirror {
        alu_lanes: usize::MAX,
        ..PackingMirror::valid()
    };
    assert_eq!(
        huge_alu.into_table_packing().validate(),
        Err(ProofMetadataError::LanesTooLarge {
            field: "alu_lanes",
            got: usize::MAX,
            max: MAX_SANE_LANES,
        })
    );

    let op = p3_circuit::ops::NpoTypeId::new("test_op");
    let huge_npo = PackingMirror {
        npo_lanes: vec![(op.clone(), usize::MAX)],
        ..PackingMirror::valid()
    };
    assert_eq!(
        huge_npo.into_table_packing().validate(),
        Err(ProofMetadataError::NpoLanesTooLarge {
            op_type: op,
            got: usize::MAX,
            max: MAX_SANE_LANES,
        })
    );

    let huge_horner = PackingMirror {
        horner_packed_steps: usize::MAX,
        ..PackingMirror::valid()
    };
    assert_eq!(
        huge_horner.into_table_packing().validate(),
        Err(ProofMetadataError::HornerPackedStepsTooLarge(
            usize::MAX,
            MAX_SANE_LANES,
        ))
    );
}

#[test]
fn validate_rejects_zero_lane_npo_entry() {
    // `NonPrimitiveTableEntry` has public fields, so deserialization can produce
    // a zero-lane entry directly.
    let op = p3_circuit::ops::NpoTypeId::new("test_op");
    let entry = NonPrimitiveTableEntry::<BabyBearConfig> {
        op_type: op.clone(),
        rows: 4,
        lanes: 0,
        public_values: Vec::new(),
        air_variant: AirVariant::Baseline,
    };
    assert_eq!(entry.validate(), Err(ProofMetadataError::ZeroNpoLanes(op)));
}

#[test]
fn verify_all_tables_rejects_tampered_serialized_row_counts() {
    // End-to-end: a real proof whose deserialized `rows` metadata was corrupted
    // to a zero count must be rejected before any AIR is reconstructed from it.
    let mut builder = CircuitBuilder::<BabyBear>::new();
    let x = builder.public_input();
    let expected = builder.public_input();
    let c5 = builder.define_const(BabyBear::from_u64(5));
    let c2 = builder.define_const(BabyBear::from_u64(2));
    let mul_result = builder.mul(c5, c2);
    let add_result = builder.add(x, mul_result);
    let diff = builder.sub(add_result, expected);
    builder.assert_zero(diff);

    let circuit = builder.build().unwrap();
    let cfg = config::baby_bear();
    let (airs_degrees, primitive_columns, non_primitive_columns) =
        get_airs_and_degrees_with_prep::<BabyBearConfig, _, 1>(
            &circuit,
            &TablePacking::default(),
            &[],
            &[],
            ConstraintProfile::Standard,
        )
        .unwrap();
    let (airs, log_degrees): (Vec<_>, Vec<usize>) = airs_degrees.into_iter().unzip();
    let prover_data = ProverData::from_airs_and_degrees(&cfg, &airs, &log_degrees).unwrap();
    let circuit_prover_data =
        CircuitProverData::new(prover_data, primitive_columns, non_primitive_columns);

    let mut runner = circuit.runner();
    runner
        .set_public_inputs(&[BabyBear::from_u64(7), BabyBear::from_u64(17)])
        .unwrap();
    let traces = runner.run().unwrap();

    let prover = BatchStarkProver::new(cfg);
    let proof = prover
        .prove_all_tables(&traces, &circuit_prover_data)
        .unwrap();

    // Forge a deserialized proof with a zero primitive row count by serializing
    // raw counts and deserializing into `RowCounts` (a state `RowCounts::new`
    // would have rejected, but derived `Deserialize` accepts).
    let public_rows = proof.rows[PrimitiveTable::Public];
    let alu_rows = proof.rows[PrimitiveTable::Alu];
    let raw =
        postcard::to_allocvec(&[0usize, public_rows, alu_rows]).expect("serialize raw row counts");
    let tampered_rows: RowCounts =
        postcard::from_bytes(&raw).expect("deserialize tampered RowCounts");
    let tampered = BatchStarkProof {
        rows: tampered_rows,
        ..proof
    };

    let err = prover
        .verify_all_tables::<BabyBear>(&tampered)
        .expect_err("tampered row counts must be rejected before verification");
    assert!(
        matches!(
            err,
            BatchStarkProverError::InvalidMetadata(ProofMetadataError::ZeroRowCount)
        ),
        "unexpected error: {err:?}"
    );
}

/// Full prove/verify round-trip of a single D=1 Poseidon1 permutation in an EF5 circuit.
#[test]
fn test_koalabear_quintic_trinomial_batch_stark_with_poseidon1_d1() {
    const D: usize = 5;
    type EF5 = QuinticTrinomialExtensionField<KoalaBear>;

    // Must match `KoalaBearD1Width16::round_constants()` in poseidon1-circuit-air.
    let inner_perm = default_koalabear_poseidon1_16();
    let mut sponge0 = [KoalaBear::ZERO; 16];
    sponge0[0] = KoalaBear::from_u64(11);
    sponge0[1] = KoalaBear::from_u64(13);
    let sponge_out = inner_perm.permute(sponge0);
    let lift_perm = LiftPermToQuintic::new(inner_perm);

    let in0 = koala_ef5_lift(KoalaBear::from_u64(11));
    let in1 = koala_ef5_lift(KoalaBear::from_u64(13));
    let exp0 = koala_ef5_lift(sponge_out[0]);
    let exp1 = koala_ef5_lift(sponge_out[1]);

    let mut builder = CircuitBuilder::<EF5>::new();
    builder.enable_poseidon1_perm_base::<P1KoalaBearD1Width16, _>(
        generate_poseidon1_trace::<EF5, P1KoalaBearD1Width16>,
        lift_perm,
    );

    let in_a = builder.public_input();
    let in_b = builder.public_input();
    let mut perm_inputs: [Option<_>; 16] = [None; 16];
    perm_inputs[0] = Some(in_a);
    perm_inputs[1] = Some(in_b);
    let (_pid, hash_outputs) = builder
        .add_poseidon1_perm_base(&Poseidon1PermCallBase {
            config: Poseidon1Config::KOALA_BEAR_D1_W16,
            new_start: true,
            inputs: perm_inputs,
            out_ctl: [true; 8],
            return_all_outputs: false,
            absorb_len: 0,
        })
        .unwrap();
    let e0 = builder.public_input();
    let e1 = builder.public_input();
    let h0_diff = builder.sub(hash_outputs[0].unwrap(), e0);
    let h1_diff = builder.sub(hash_outputs[1].unwrap(), e1);
    builder.assert_zero(h0_diff);
    builder.assert_zero(h1_diff);

    let circuit = builder.build().unwrap();
    let cfg = config::koala_bear();

    let npo_prep: Vec<Box<dyn NpoPreprocessor<KoalaBear>>> = vec![Box::new(Poseidon1Preprocessor)];
    let air_builders = poseidon1_air_builders_d5::<KoalaBearConfig>();
    let (airs_degrees, primitive_columns, non_primitive_columns) =
        get_airs_and_degrees_with_prep::<KoalaBearConfig, _, D>(
            &circuit,
            &TablePacking::default(),
            &npo_prep,
            &air_builders,
            ConstraintProfile::Standard,
        )
        .unwrap();
    let (airs, degrees): (Vec<_>, Vec<usize>) = airs_degrees.into_iter().unzip();
    let mut runner = circuit.runner();

    runner.set_public_inputs(&[in0, in1, exp0, exp1]).unwrap();
    let traces = runner.run().unwrap();

    let prover_data = ProverData::from_airs_and_degrees(&cfg, &airs, &degrees).unwrap();
    let circuit_prover_data =
        CircuitProverData::new(prover_data, primitive_columns, non_primitive_columns);

    let mut prover = BatchStarkProver::new(cfg);
    for p in poseidon1_table_provers_d5(Poseidon1Config::KOALA_BEAR_D1_W16) {
        prover.register_table_prover(p);
    }

    let proof = prover
        .prove_all_tables(&traces, &circuit_prover_data)
        .unwrap();
    assert_eq!(proof.ext_degree, D);
    assert!(proof.w_binomial.is_none());
    assert!(proof.alu_quintic_trinomial);
    prover
        .verify_all_tables::<QuinticTrinomialExtensionField<KoalaBear>>(&proof)
        .unwrap();
}

/// Minimal non-primitive AIR that reports non-default values for every `BaseAir`
/// method, used to pin that `CircuitTableAir` forwards each method to its `Dynamic`
/// variant instead of silently returning the trait defaults.
#[derive(Clone)]
struct ForwardingProbeAir {
    num_public: usize,
    periodic: Vec<Vec<u64>>,
}

impl<F: PrimeCharacteristicRing> BaseAir<F> for ForwardingProbeAir {
    fn width(&self) -> usize {
        1
    }

    fn num_public_values(&self) -> usize {
        self.num_public
    }

    fn num_periodic_columns(&self) -> usize {
        self.periodic.len()
    }

    fn periodic_columns(&self) -> Cow<'_, [Vec<F>]> {
        Cow::Owned(
            self.periodic
                .iter()
                .map(|col| col.iter().map(|&v| F::from_u64(v)).collect())
                .collect(),
        )
    }
}

impl<AB: p3_air::AirBuilder> Air<AB> for ForwardingProbeAir {
    fn eval(&self, _builder: &mut AB) {}
}

impl BatchAir<BabyBearConfig> for ForwardingProbeAir {}

#[test]
fn circuit_table_air_forwards_base_air_methods_to_dynamic() {
    let probe = ForwardingProbeAir {
        num_public: 2,
        periodic: vec![vec![7, 9], vec![11, 13, 15, 17]],
    };
    let entry = DynamicAirEntry::<BabyBearConfig>::new(Box::new(probe));
    let air: CircuitTableAir<BabyBearConfig, 4> = CircuitTableAir::Dynamic(entry);

    // Without the Dynamic forwarding arm each of these returns the BaseAir default
    // (0 / empty), so they lock the forwarding contract in place.
    assert_eq!(BaseAir::<BabyBear>::num_public_values(&air), 2);
    assert_eq!(BaseAir::<BabyBear>::num_periodic_columns(&air), 2);
    assert_eq!(
        BaseAir::<BabyBear>::periodic_columns(&air),
        vec![
            vec![BabyBear::from_u64(7), BabyBear::from_u64(9)],
            vec![
                BabyBear::from_u64(11),
                BabyBear::from_u64(13),
                BabyBear::from_u64(15),
                BabyBear::from_u64(17),
            ],
        ],
    );
}

#[test]
fn verify_all_tables_rejects_a_forged_constant_value() {
    // Regression test for the constant-binding soundness bug: a circuit's compile-time
    // constant (`alloc_const`) must be part of its committed preprocessing, not a free
    // per-proof witness. Before the fix, a trace generated from a circuit whose constant had
    // been swapped (42 -> 43) verified successfully against the *original* circuit's
    // preprocessed commitment, because `ConstAir`'s preprocessed columns carried only the
    // witness index, never the value.
    let mut builder = CircuitBuilder::<KoalaBear>::new();
    let c = builder.define_const(KoalaBear::from_u32(42));
    let x = builder.public_input();
    builder.connect(c, x);
    let circuit = builder.build().unwrap();

    let cfg = config::koala_bear();
    let (airs_degrees, primitive_columns, non_primitive_columns) =
        get_airs_and_degrees_with_prep::<KoalaBearConfig, _, 1>(
            &circuit,
            &TablePacking::default(),
            &[],
            &[],
            ConstraintProfile::Standard,
        )
        .unwrap();
    let (airs, log_degrees): (Vec<_>, Vec<usize>) = airs_degrees.into_iter().unzip();
    let prover_data = ProverData::from_airs_and_degrees(&cfg, &airs, &log_degrees).unwrap();
    let circuit_prover_data =
        CircuitProverData::new(prover_data, primitive_columns, non_primitive_columns);

    let mut honest_runner = circuit.runner();
    honest_runner
        .set_public_inputs(&[KoalaBear::from_u32(42)])
        .unwrap();
    let honest_traces = honest_runner.run().unwrap();

    let prover = BatchStarkProver::new(cfg);
    let honest_proof = prover
        .prove_all_tables(&honest_traces, &circuit_prover_data)
        .unwrap();
    prover
        .verify_all_tables::<KoalaBear>(&honest_proof)
        .expect("honest fixed-key constant proof must verify");

    // Forge a circuit that requires x=43 by mutating the compiled `Op::Const` directly
    // (bypassing `CircuitBuilder`, the way a malicious prover with access to the circuit
    // representation would).
    let mut forged = circuit.clone();
    let mut changes = 0;
    for op in &mut forged.ops {
        let Op::Const { val, .. } = op else {
            continue;
        };
        if *val != KoalaBear::from_u32(42) {
            continue;
        }
        *val = KoalaBear::from_u32(43);
        changes += 1;
    }
    assert_eq!(changes, 1, "exactly one Const op should carry the value 42");

    // The two circuits must now commit to different preprocessed data — this is the fix's
    // core property: the constant's value is part of what's committed, not free.
    assert_ne!(
        circuit.generate_preprocessed_columns::<1>().unwrap(),
        forged.generate_preprocessed_columns::<1>().unwrap(),
        "circuits differing only in a constant's value must have different preprocessing"
    );

    // This is the build-profile-independent version of the check above: it holds whether or
    // not debug_assertions catches the mismatch earlier during proving. `cfg` was already
    // moved into `prover` above, so this rebuilds an equivalent (deterministic) config.
    let forged_cfg = config::koala_bear();
    let (forged_airs_degrees, forged_primitive_columns, forged_non_primitive_columns) =
        get_airs_and_degrees_with_prep::<KoalaBearConfig, _, 1>(
            &forged,
            &TablePacking::default(),
            &[],
            &[],
            ConstraintProfile::Standard,
        )
        .unwrap();
    let (forged_airs, forged_log_degrees): (Vec<_>, Vec<usize>) =
        forged_airs_degrees.into_iter().unzip();
    let forged_prover_data =
        ProverData::from_airs_and_degrees(&forged_cfg, &forged_airs, &forged_log_degrees).unwrap();
    let forged_circuit_prover_data = CircuitProverData::new(
        forged_prover_data,
        forged_primitive_columns,
        forged_non_primitive_columns,
    );
    assert_ne!(
        circuit_prover_data
            .common_data()
            .preprocessed
            .as_ref()
            .unwrap()
            .commitment,
        forged_circuit_prover_data
            .common_data()
            .preprocessed
            .as_ref()
            .unwrap()
            .commitment,
        "circuits differing only in a constant's value must commit to different preprocessed data"
    );

    let mut forged_runner = forged.runner();
    forged_runner
        .set_public_inputs(&[KoalaBear::from_u32(43)])
        .unwrap();
    let forged_traces = forged_runner.run().unwrap();

    // Prove the forged trace against the ORIGINAL (x=42) circuit's prover data — this is the
    // exploit: reusing preprocessing that no longer matches the trace's constant.
    //
    #[cfg(debug_assertions)]
    let result = match run_with_strict_debug_oracle(|| {
        let forged_proof = prover
            .prove_all_tables(&forged_traces, &circuit_prover_data)
            .map_err(AlgebraicProofCheckError::Prove)?;
        prover
            .verify_all_tables::<KoalaBear>(&forged_proof)
            .map_err(AlgebraicProofCheckError::Verify)
    }) {
        Ok(result) => result,
        Err(kind) => Err(AlgebraicProofCheckError::DebugPanic(kind)),
    };

    #[cfg(not(debug_assertions))]
    let result = {
        let forged_proof = prover
            .prove_all_tables(&forged_traces, &circuit_prover_data)
            .map_err(AlgebraicProofCheckError::Prove);
        match forged_proof {
            Ok(proof) => prover
                .verify_all_tables::<KoalaBear>(&proof)
                .map_err(AlgebraicProofCheckError::Verify),
            Err(error) => Err(error),
        }
    };

    #[cfg(debug_assertions)]
    assert!(
        matches!(
            &result,
            Err(AlgebraicProofCheckError::DebugPanic(
                DebugRejectionKind::Constraint
            ))
        ),
        "forged constant must reject specifically at its AIR constraint: {result:?}"
    );
    assert_algebraic_rejection(&result, "forged constant 42 -> 43 at Const trace row 0");
}

#[test]
fn verify_all_tables_rejects_alu_bus_only_operand_swap() {
    let mut builder = CircuitBuilder::<KoalaBear>::new();
    let a = builder.public_input();
    let b = builder.public_input();
    let expected = builder.public_input();
    let sum = builder.add(a, b);
    builder.connect(sum, expected);
    let circuit = builder.build().unwrap();

    let cfg = config::koala_bear();
    let packing = TablePacking::default();
    let (airs_degrees, primitive_columns, non_primitive_columns) =
        get_airs_and_degrees_with_prep::<KoalaBearConfig, _, 1>(
            &circuit,
            &packing,
            &[],
            &[],
            ConstraintProfile::Standard,
        )
        .unwrap();
    let alu_prep = primitive_columns[PrimitiveOpType::Alu as usize].clone();
    assert!(!alu_prep.is_empty(), "ALU preprocessing must be nonempty");
    let (airs, degrees): (Vec<_>, Vec<_>) = airs_degrees.into_iter().unzip();
    let prover_data = ProverData::from_airs_and_degrees(&cfg, &airs, &degrees).unwrap();
    let circuit_prover_data =
        CircuitProverData::new(prover_data, primitive_columns, non_primitive_columns);

    let mut runner = circuit.runner();
    let expected_values = [
        KoalaBear::from_u32(3),
        KoalaBear::from_u32(5),
        KoalaBear::from_u32(8),
    ];
    runner.set_public_inputs(&expected_values).unwrap();
    let traces = runner.run().unwrap();
    assert!(
        !traces.alu_trace.values.is_empty(),
        "ALU trace must be nonempty"
    );

    let air = crate::air::AluAir::<KoalaBear, 1>::new_with_preprocessed(
        traces.alu_trace.values.len(),
        1,
        alu_prep.clone(),
        packing.horner_packed_steps(),
    );
    let honest_matrix = air.trace_to_matrix(&traces.alu_trace, 1);
    crate::air::test_utils::assert_air_satisfies::<KoalaBear, KoalaBear, _>(&air, &honest_matrix);
    let mut locally_valid_forgery = honest_matrix;
    let width = locally_valid_forgery.width();
    let matches: Vec<_> = (0..locally_valid_forgery.height())
        .filter(|&row| {
            locally_valid_forgery.values[row * width] == expected_values[0]
                && locally_valid_forgery.values[row * width + 1] == expected_values[1]
                && locally_valid_forgery.values[row * width + 3] == expected_values[2]
        })
        .collect();
    assert_eq!(matches, vec![0], "expected one Add row at ALU row 0");
    locally_valid_forgery.values.swap(0, 1);
    crate::air::test_utils::assert_air_satisfies::<KoalaBear, KoalaBear, _>(
        &air,
        &locally_valid_forgery,
    );

    let prover = BatchStarkProver::new(cfg);
    let honest_proof = prover
        .prove_all_tables(&traces, &circuit_prover_data)
        .expect("honest ALU proof must be produced");
    prover
        .verify_all_tables::<KoalaBear>(&honest_proof)
        .expect("honest ALU proof must verify");

    #[cfg(debug_assertions)]
    let result = match run_with_strict_debug_oracle(|| {
        let proof = prover
            .prove_with_trace_matrix_transform::<KoalaBear, 1, _>(
                &traces,
                None,
                &circuit_prover_data,
                None,
                |matrices| matrices[PrimitiveOpType::Alu as usize].values.swap(0, 1),
            )
            .map_err(AlgebraicProofCheckError::Prove)?;
        prover
            .verify_all_tables::<KoalaBear>(&proof)
            .map_err(AlgebraicProofCheckError::Verify)
    }) {
        Ok(result) => result,
        Err(kind) => Err(AlgebraicProofCheckError::DebugPanic(kind)),
    };

    #[cfg(not(debug_assertions))]
    let result = match prover.prove_with_trace_matrix_transform::<KoalaBear, 1, _>(
        &traces,
        None,
        &circuit_prover_data,
        None,
        |matrices| matrices[PrimitiveOpType::Alu as usize].values.swap(0, 1),
    ) {
        Ok(proof) => prover
            .verify_all_tables::<KoalaBear>(&proof)
            .map_err(AlgebraicProofCheckError::Verify),
        Err(error) => Err(AlgebraicProofCheckError::Prove(error)),
    };

    #[cfg(debug_assertions)]
    assert!(
        matches!(
            &result,
            Err(AlgebraicProofCheckError::DebugPanic(
                DebugRejectionKind::Lookup
            ))
        ),
        "locally valid operand swap must reject specifically at lookup balance: {result:?}"
    );
    assert_eq!(
        circuit_prover_data.primitive_columns[PrimitiveOpType::Alu as usize],
        alu_prep,
        "the fixed WitnessChecks preprocessing must remain unchanged"
    );
    assert_algebraic_rejection(&result, "ALU row 0 columns a=0 and b=1 swapped");
}

#[test]
fn verify_all_tables_rejects_forged_horner_chain_head_seed() {
    let mut builder = CircuitBuilder::<KoalaBear>::new();
    let zero = builder.define_const(KoalaBear::ZERO);
    let a0 = builder.define_const(KoalaBear::from_u32(1));
    let b0 = builder.public_input();
    let c0 = builder.define_const(KoalaBear::from_u32(5));
    let a1 = builder.define_const(KoalaBear::ZERO);
    let b1 = builder.public_input();
    let c1 = builder.define_const(KoalaBear::from_u32(3));
    let a2 = builder.define_const(KoalaBear::from_u32(1));
    let b2 = builder.public_input();
    let c2 = builder.define_const(KoalaBear::from_u32(2));
    let out0 = builder.horner_acc_step(zero, b0, c0, a0);
    let out1 = builder.horner_acc_step(out0, b1, c1, a1);
    let out2 = builder.horner_acc_step(out1, b2, c2, a2);
    let expected = builder.public_input();
    builder.connect(out2, expected);
    let circuit = builder.build().unwrap();

    let cfg = config::koala_bear();
    let packing = TablePacking::default();
    let (airs_degrees, primitive_columns, non_primitive_columns) =
        get_airs_and_degrees_with_prep::<KoalaBearConfig, _, 1>(
            &circuit,
            &packing,
            &[],
            &[],
            ConstraintProfile::Standard,
        )
        .unwrap();
    let alu_prep = primitive_columns[PrimitiveOpType::Alu as usize].clone();
    assert!(
        !alu_prep.is_empty(),
        "Horner preprocessing must be nonempty"
    );
    let (airs, degrees): (Vec<_>, Vec<_>) = airs_degrees.into_iter().unzip();
    let prover_data = ProverData::from_airs_and_degrees(&cfg, &airs, &degrees).unwrap();
    let circuit_prover_data =
        CircuitProverData::new(prover_data, primitive_columns, non_primitive_columns);
    let mut runner = circuit.runner();
    runner
        .set_public_inputs(&[
            KoalaBear::from_u32(2),
            KoalaBear::from_u32(3),
            KoalaBear::from_u32(5),
            KoalaBear::from_u32(76),
        ])
        .unwrap();
    let traces = runner.run().unwrap();
    assert_eq!(
        traces.alu_trace.values.len(),
        3,
        "three Horner ops required; compiled ops={:?}",
        circuit.ops
    );

    let air = crate::air::AluAir::<KoalaBear, 1>::new_with_preprocessed(
        traces.alu_trace.values.len(),
        1,
        alu_prep,
        packing.horner_packed_steps(),
    );
    let honest_matrix = air.trace_to_matrix(&traces.alu_trace, 1);
    crate::air::test_utils::assert_air_satisfies::<KoalaBear, KoalaBear, _>(&air, &honest_matrix);
    let width = honest_matrix.width();
    assert!(width >= 4, "D1 ALU must expose lane-0 out at column 3");
    let steps = [
        (
            KoalaBear::ONE,
            KoalaBear::from_u32(2),
            KoalaBear::from_u32(5),
        ),
        (
            KoalaBear::ZERO,
            KoalaBear::from_u32(3),
            KoalaBear::from_u32(3),
        ),
        (
            KoalaBear::ONE,
            KoalaBear::from_u32(5),
            KoalaBear::from_u32(2),
        ),
    ];
    let mutate = |matrix: &mut RowMajorMatrix<KoalaBear>| {
        matrix.values[3] = KoalaBear::ONE;
        let mut acc = KoalaBear::ONE;
        for (row, &(a, b, c)) in steps.iter().enumerate() {
            acc = acc * b + c - a;
            matrix.values[(row + 1) * width + 3] = acc;
        }
    };
    let mut forged_matrix = honest_matrix;
    mutate(&mut forged_matrix);
    crate::air::test_utils::assert_air_rejects::<KoalaBear, KoalaBear, _>(&air, &forged_matrix);

    let prover = BatchStarkProver::new(cfg);
    let honest_proof = prover
        .prove_all_tables(&traces, &circuit_prover_data)
        .expect("honest Horner proof must be produced");
    prover
        .verify_all_tables::<KoalaBear>(&honest_proof)
        .expect("honest Horner proof must verify");

    #[cfg(debug_assertions)]
    let result = match run_with_strict_debug_oracle(|| {
        let proof = prover
            .prove_with_trace_matrix_transform::<KoalaBear, 1, _>(
                &traces,
                None,
                &circuit_prover_data,
                None,
                |matrices| mutate(&mut matrices[PrimitiveOpType::Alu as usize]),
            )
            .map_err(AlgebraicProofCheckError::Prove)?;
        prover
            .verify_all_tables::<KoalaBear>(&proof)
            .map_err(AlgebraicProofCheckError::Verify)
    }) {
        Ok(result) => result,
        Err(kind) => Err(AlgebraicProofCheckError::DebugPanic(kind)),
    };

    #[cfg(not(debug_assertions))]
    let result = match prover.prove_with_trace_matrix_transform::<KoalaBear, 1, _>(
        &traces,
        None,
        &circuit_prover_data,
        None,
        |matrices| mutate(&mut matrices[PrimitiveOpType::Alu as usize]),
    ) {
        Ok(proof) => prover
            .verify_all_tables::<KoalaBear>(&proof)
            .map_err(AlgebraicProofCheckError::Verify),
        Err(error) => Err(AlgebraicProofCheckError::Prove(error)),
    };
    #[cfg(debug_assertions)]
    assert!(
        matches!(
            &result,
            Err(AlgebraicProofCheckError::DebugPanic(
                DebugRejectionKind::Constraint
            ))
        ),
        "forged Horner seed must reject specifically at the chain-head constraint: {result:?}"
    );
    assert_algebraic_rejection(
        &result,
        "ALU separator row 0 out column 3 changed 0 -> 1 with rows 1..=3 recomputed",
    );
}
