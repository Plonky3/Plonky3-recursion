mod common;

use std::boxed::Box;
use std::cell::Cell;
use std::rc::Rc;
use std::sync::Arc;
use std::vec::Vec;

use p3_batch_stark::ProverData;
use p3_circuit::ops::{generate_poseidon2_trace, generate_recompose_trace};
use p3_circuit::test_utils::{FibonacciAir, generate_trace_rows};
use p3_circuit::{CircuitBuilder, CircuitRunner, NonPrimitiveOpId};
use p3_circuit_prover::batch_stark_prover::{BatchStarkProver, TableProver};
use p3_circuit_prover::common::{NpoAirBuilder, NpoPreprocessor, get_airs_and_degrees_with_prep};
use p3_circuit_prover::{BatchStarkProof, CircuitProverData, ConstraintProfile, TablePacking};
use p3_commit::{ExtensionMmcs, Pcs};
use p3_dft::Radix2DitParallel;
use p3_field::{BasedVectorSpace, Field, PrimeCharacteristicRing, PrimeField64};
use p3_fri::{FriParameters, HidingFriPcs, TwoAdicFriPcs};
use p3_koala_bear::{
    Poseidon2KoalaBear, default_koalabear_poseidon2_16, default_koalabear_poseidon2_32,
};
use p3_lookup::logup::LogUpGadget;
use p3_merkle_tree::MerkleTreeMmcs;
use p3_poseidon2_circuit_air::{KoalaBearD4Width16, KoalaBearD4Width32};
use p3_recursion::pcs::fri::{
    FriProofTargets, HidingFriProofTargets, InputProofTargets, MerkleCapTargets,
    RecExtensionValMmcs, RecExtensionValMmcsArity4, RecValMmcs, RecValMmcsArity4, Witness,
};
use p3_recursion::pcs::{
    restore_fri_query_paths, set_fri_mmcs_private_data, set_fri_mmcs_private_data_arity4,
};
use p3_recursion::{
    BatchOnly, FriRecursionBackend, FriRecursionConfig, FriVerifierParams, OpeningTranscript,
    PcsRecursionBackend, Poseidon2Config, PreparedAggregation, PreparedAggregationCross,
    PreparedInput, PreparedPcsRecursionBackend, PreparedSource, ProveNextLayerParams,
    RecursionInput, RecursiveAir, RecursivePcs, VerificationError, VerifierCircuitResult,
    merge_hiding_random_openings, observe_opened_values,
};
use p3_symmetric::{PaddingFreeSponge, TruncatedPermutation};
use p3_test_utils::koala_bear_params::{
    Challenge, ChallengeMmcs, Challenger, Dft, F, MyCompress, MyHash, MyMmcs,
};
use p3_uni_stark::{StarkConfig, StarkGenericConfig, Val, prove, verify};
use rand::SeedableRng;
use rand::rngs::StdRng;

fn fibonacci_output<Fld: PrimeCharacteristicRing + Copy>(
    start_a: u64,
    start_b: u64,
    n: usize,
) -> Fld {
    let mut a = Fld::from_u64(start_a);
    let mut b = Fld::from_u64(start_b);
    if n == 0 {
        return a;
    }
    for _ in 1..n {
        let next = a + b;
        a = b;
        b = next;
    }
    b
}

#[derive(Default)]
struct SideCounters {
    public_packs: Cell<usize>,
    private_packs: Cell<usize>,
    private_setups: Cell<usize>,
}

struct CountingVerifierResult<R> {
    inner: R,
    counters: Rc<SideCounters>,
}

impl<A, R> VerifierCircuitResult<common::KoalaBearD4RecursionConfig, A>
    for CountingVerifierResult<R>
where
    A: RecursiveAir<F, Challenge, LogUpGadget>,
    R: VerifierCircuitResult<common::KoalaBearD4RecursionConfig, A>,
{
    fn pack_public_inputs(
        &self,
        prev: &RecursionInput<'_, common::KoalaBearD4RecursionConfig, A>,
    ) -> Result<Vec<Challenge>, VerificationError>
    where
        F: PrimeField64,
        Challenge: BasedVectorSpace<F> + From<F>,
    {
        self.counters
            .public_packs
            .set(self.counters.public_packs.get() + 1);
        self.inner.pack_public_inputs(prev)
    }

    fn pack_private_inputs(
        &self,
        prev: &RecursionInput<'_, common::KoalaBearD4RecursionConfig, A>,
    ) -> Result<Vec<Challenge>, VerificationError>
    where
        F: PrimeField64,
        Challenge: BasedVectorSpace<F> + From<F>,
    {
        self.counters
            .private_packs
            .set(self.counters.private_packs.get() + 1);
        self.inner.pack_private_inputs(prev)
    }

    fn op_ids(&self) -> &[NonPrimitiveOpId] {
        self.inner.op_ids()
    }
}

#[derive(Clone)]
struct CountingBackend {
    inner: common::KoalaBearD4Backend,
    uni: Rc<SideCounters>,
    batch: Rc<SideCounters>,
    uni_output_preparations: Rc<Cell<usize>>,
    batch_output_preparations: Rc<Cell<usize>>,
}

macro_rules! impl_counting_backend {
    ($air:ty, $side:ident, $preparations:ident) => {
        impl PcsRecursionBackend<common::KoalaBearD4RecursionConfig, $air, 4> for CountingBackend {
            type VerifierResult = CountingVerifierResult<
                <common::KoalaBearD4Backend as PcsRecursionBackend<
                    common::KoalaBearD4RecursionConfig,
                    $air,
                    4,
                >>::VerifierResult,
            >;

            fn prepare_circuit(
                &self,
                config: &common::KoalaBearD4RecursionConfig,
                circuit: &mut CircuitBuilder<Challenge>,
            ) -> Result<(), VerificationError> {
                <common::KoalaBearD4Backend as PcsRecursionBackend<
                    common::KoalaBearD4RecursionConfig,
                    $air,
                    4,
                >>::prepare_circuit(&self.inner, config, circuit)
            }

            fn build_verifier_circuit(
                &self,
                prev: &RecursionInput<'_, common::KoalaBearD4RecursionConfig, $air>,
                config: &common::KoalaBearD4RecursionConfig,
                circuit: &mut CircuitBuilder<Challenge>,
            ) -> Result<Self::VerifierResult, VerificationError> {
                let inner = <common::KoalaBearD4Backend as PcsRecursionBackend<
                    common::KoalaBearD4RecursionConfig,
                    $air,
                    4,
                >>::build_verifier_circuit(&self.inner, prev, config, circuit)?;
                Ok(CountingVerifierResult {
                    inner,
                    counters: Rc::clone(&self.$side),
                })
            }

            fn set_private_data(
                &self,
                config: &common::KoalaBearD4RecursionConfig,
                runner: &mut CircuitRunner<'_, Challenge>,
                op_ids: &[NonPrimitiveOpId],
                prev: &RecursionInput<'_, common::KoalaBearD4RecursionConfig, $air>,
            ) -> Result<(), &'static str> {
                self.$side
                    .private_setups
                    .set(self.$side.private_setups.get() + 1);
                <common::KoalaBearD4Backend as PcsRecursionBackend<
                    common::KoalaBearD4RecursionConfig,
                    $air,
                    4,
                >>::set_private_data(&self.inner, config, runner, op_ids, prev)
            }

            fn non_primitive_preprocessors(&self) -> Vec<Box<dyn NpoPreprocessor<F>>> {
                self.$preparations.set(self.$preparations.get() + 1);
                <common::KoalaBearD4Backend as PcsRecursionBackend<
                    common::KoalaBearD4RecursionConfig,
                    $air,
                    4,
                >>::non_primitive_preprocessors(&self.inner)
            }

            fn non_primitive_provers(
                &self,
                ext_degree: usize,
            ) -> Vec<Box<dyn TableProver<common::KoalaBearD4RecursionConfig>>> {
                <common::KoalaBearD4Backend as PcsRecursionBackend<
                    common::KoalaBearD4RecursionConfig,
                    $air,
                    4,
                >>::non_primitive_provers(&self.inner, ext_degree)
            }

            fn non_primitive_air_builders(
                &self,
            ) -> Vec<Box<dyn NpoAirBuilder<common::KoalaBearD4RecursionConfig, 4>>> {
                <common::KoalaBearD4Backend as PcsRecursionBackend<
                    common::KoalaBearD4RecursionConfig,
                    $air,
                    4,
                >>::non_primitive_air_builders(&self.inner)
            }
        }

        impl PreparedPcsRecursionBackend<common::KoalaBearD4RecursionConfig, $air, 4>
            for CountingBackend
        {
            type InputContract = <common::KoalaBearD4Backend as PreparedPcsRecursionBackend<
                common::KoalaBearD4RecursionConfig,
                $air,
                4,
            >>::InputContract;

            fn capture_input_contract(
                &self,
                config: &common::KoalaBearD4RecursionConfig,
                source: &RecursionInput<'_, common::KoalaBearD4RecursionConfig, $air>,
            ) -> Result<Self::InputContract, VerificationError> {
                <common::KoalaBearD4Backend as PreparedPcsRecursionBackend<
                    common::KoalaBearD4RecursionConfig,
                    $air,
                    4,
                >>::capture_input_contract(&self.inner, config, source)
            }

            fn validate_prepared_input(
                &self,
                config: &common::KoalaBearD4RecursionConfig,
                contract: &Self::InputContract,
                input: &PreparedInput<'_, common::KoalaBearD4RecursionConfig>,
            ) -> Result<(), VerificationError> {
                <common::KoalaBearD4Backend as PreparedPcsRecursionBackend<
                    common::KoalaBearD4RecursionConfig,
                    $air,
                    4,
                >>::validate_prepared_input(&self.inner, config, contract, input)
            }
        }
    };
}

impl_counting_backend!(FibonacciAir, uni, uni_output_preparations);
impl_counting_backend!(BatchOnly, batch, batch_output_preparations);

mod arity4_output {
    use p3_test_utils::koala_bear_params::Challenger;

    use super::*;

    type Permutation = Poseidon2KoalaBear<32>;
    type Hash = PaddingFreeSponge<Permutation, 32, 24, 8>;
    type Compress = TruncatedPermutation<Permutation, 4, 8, 32>;
    type ValMmcs =
        MerkleTreeMmcs<<F as Field>::Packing, <F as Field>::Packing, Hash, Compress, 4, 8>;
    type ChallengeMmcs = ExtensionMmcs<F, Challenge, ValMmcs>;
    type Pcs4 = TwoAdicFriPcs<F, Radix2DitParallel<F>, ValMmcs, ChallengeMmcs>;
    type NativeConfig = StarkConfig<Pcs4, Challenge, Challenger>;
    type RecMmcs = RecValMmcsArity4<F, 8, Hash, Compress>;
    type RecExtensionMmcs = RecExtensionValMmcsArity4<F, Challenge, 8, RecMmcs>;
    type OpeningTargets = FriProofTargets<
        F,
        Challenge,
        RecExtensionMmcs,
        InputProofTargets<F, Challenge, RecMmcs>,
        Witness<F>,
    >;

    #[derive(Clone)]
    pub(super) struct Config {
        config: Arc<NativeConfig>,
        verifier_params: FriVerifierParams,
        fri_instance: Arc<(ValMmcs, FriParameters<ChallengeMmcs>)>,
    }

    impl StarkGenericConfig for Config {
        type Challenge = Challenge;
        type Challenger = Challenger;
        type Pcs = Pcs4;

        fn pcs(&self) -> &Self::Pcs {
            self.config.pcs()
        }

        fn initialise_challenger(&self) -> Self::Challenger {
            self.config.initialise_challenger()
        }
    }

    impl FriRecursionConfig for Config
    where
        Pcs4: RecursivePcs<
                Self,
                InputProofTargets<F, Challenge, RecMmcs>,
                OpeningTargets,
                MerkleCapTargets<F, 8>,
                <Pcs4 as Pcs<Challenge, Challenger>>::Domain,
            >,
    {
        type Commitment = MerkleCapTargets<F, 8>;
        type InputProof = InputProofTargets<F, Challenge, RecMmcs>;
        type OpeningProof = OpeningTargets;
        type RawOpeningProof = <Pcs4 as Pcs<Challenge, Challenger>>::Proof;
        const DIGEST_ELEMS: usize = 8;

        fn with_fri_opening_proof<'a, A, R>(
            prev: &RecursionInput<'a, Self, A>,
            f: impl FnOnce(&Self::RawOpeningProof) -> R,
        ) -> R
        where
            A: RecursiveAir<Val<Self>, Self::Challenge, LogUpGadget>,
        {
            match prev {
                RecursionInput::UniStark { proof, .. } => f(&proof.opening_proof),
                RecursionInput::BatchStark { proof, .. } => f(&proof.proof.opening_proof),
            }
        }

        fn prepare_circuit_for_verification(
            &self,
            circuit: &mut CircuitBuilder<Challenge>,
        ) -> Result<(), VerificationError> {
            circuit.enable_poseidon2_perm::<KoalaBearD4Width16, _>(
                generate_poseidon2_trace::<Challenge, KoalaBearD4Width16>,
                default_koalabear_poseidon2_16(),
            );
            circuit.enable_poseidon2_perm_width_32::<KoalaBearD4Width32, _>(
                generate_poseidon2_trace::<Challenge, KoalaBearD4Width32>,
                default_koalabear_poseidon2_32(),
            );
            circuit.enable_recompose::<F>(generate_recompose_trace::<F, Challenge>);
            Ok(())
        }

        fn pcs_verifier_params(
            &self,
        ) -> &<Pcs4 as RecursivePcs<
            Self,
            InputProofTargets<F, Challenge, RecMmcs>,
            OpeningTargets,
            MerkleCapTargets<F, 8>,
            <Pcs4 as Pcs<Challenge, Challenger>>::Domain,
        >>::VerifierParams {
            &self.verifier_params
        }

        fn set_fri_private_data(
            config: &Self,
            runner: &mut CircuitRunner<'_, Challenge>,
            op_ids: &[NonPrimitiveOpId],
            opening_proof: &Self::RawOpeningProof,
            transcript: OpeningTranscript<Self>,
        ) -> Result<(), &'static str> {
            let OpeningTranscript {
                mut challenger,
                commitments_with_opening_points,
            } = transcript;
            observe_opened_values::<Self>(&mut challenger, &commitments_with_opening_points);
            let query_paths = restore_fri_query_paths(
                &config.fri_instance.1,
                &config.fri_instance.0,
                &config.fri_instance.0,
                opening_proof,
                &mut challenger,
                &commitments_with_opening_points,
            )
            .map_err(|_| "failed to restore arity-4 FRI query paths")?;
            set_fri_mmcs_private_data_arity4::<F, Challenge, 8>(
                runner,
                op_ids,
                &query_paths,
                Poseidon2Config::KOALA_BEAR_D4_W32,
            )
        }
    }

    pub(super) fn config() -> Config {
        let permutation = default_koalabear_poseidon2_32();
        let val_mmcs = ValMmcs::new(
            Hash::new(permutation.clone()),
            Compress::new(permutation),
            0,
        );
        let fri_params = FriParameters::new_testing(ChallengeMmcs::new(val_mmcs.clone()), 0);
        let verifier_params = FriVerifierParams::with_mmcs(
            fri_params.log_blowup,
            fri_params.log_final_poly_len,
            fri_params.commit_proof_of_work_bits,
            fri_params.query_proof_of_work_bits,
            fri_params.num_queries,
            Poseidon2Config::KOALA_BEAR_D4_W32,
        );
        let pcs = Pcs4::new(
            Radix2DitParallel::default(),
            val_mmcs.clone(),
            fri_params.clone(),
        );
        Config {
            config: Arc::new(NativeConfig::new(
                pcs,
                Challenger::new(default_koalabear_poseidon2_16()),
            )),
            verifier_params,
            fri_instance: Arc::new((val_mmcs, fri_params)),
        }
    }

    pub(super) fn verify(
        config: Config,
        params: &ProveNextLayerParams,
        output: &p3_recursion::RecursionOutput<Config>,
    ) {
        let mut verifier =
            BatchStarkProver::new(config).with_table_packing(params.table_packing.clone());
        verifier.register_poseidon2_table::<4>(Poseidon2Config::KOALA_BEAR_D4_W16.for_challenger());
        verifier.register_poseidon2_table::<4>(Poseidon2Config::KOALA_BEAR_D4_W16);
        verifier.register_poseidon2_table::<4>(Poseidon2Config::KOALA_BEAR_D4_W32);
        verifier.register_recompose_table::<4>(true);
        verifier
            .verify_all_tables::<Challenge>(&output.0)
            .expect("the arity-4 output proof verifies under its output configuration");
    }
}

mod hiding_fri {
    use super::*;

    type HidingPcs = HidingFriPcs<F, Dft, MyMmcs, ChallengeMmcs, StdRng>;
    type NativeConfig = StarkConfig<HidingPcs, Challenge, Challenger>;
    type RecMmcs = RecValMmcs<F, 8, MyHash, MyCompress>;
    type RecExtensionMmcs = RecExtensionValMmcs<F, Challenge, 8, RecMmcs>;
    type OpeningTargets = HidingFriProofTargets<
        F,
        Challenge,
        RecExtensionMmcs,
        InputProofTargets<F, Challenge, RecMmcs>,
        Witness<F>,
    >;

    #[derive(Clone)]
    pub(super) struct Config {
        config: Arc<NativeConfig>,
        verifier_params: FriVerifierParams,
        val_mmcs: MyMmcs,
        fri_params: FriParameters<ChallengeMmcs>,
    }

    impl StarkGenericConfig for Config {
        type Challenge = Challenge;
        type Challenger = Challenger;
        type Pcs = HidingPcs;

        fn pcs(&self) -> &Self::Pcs {
            self.config.pcs()
        }

        fn initialise_challenger(&self) -> Self::Challenger {
            self.config.initialise_challenger()
        }
    }

    impl FriRecursionConfig for Config
    where
        HidingPcs: RecursivePcs<
                Self,
                InputProofTargets<F, Challenge, RecMmcs>,
                OpeningTargets,
                MerkleCapTargets<F, 8>,
                <HidingPcs as Pcs<Challenge, Challenger>>::Domain,
            >,
    {
        type Commitment = MerkleCapTargets<F, 8>;
        type InputProof = InputProofTargets<F, Challenge, RecMmcs>;
        type OpeningProof = OpeningTargets;
        type RawOpeningProof = <HidingPcs as Pcs<Challenge, Challenger>>::Proof;
        const DIGEST_ELEMS: usize = 8;

        fn with_fri_opening_proof<'a, A, R>(
            prev: &RecursionInput<'a, Self, A>,
            f: impl FnOnce(&Self::RawOpeningProof) -> R,
        ) -> R
        where
            A: RecursiveAir<Val<Self>, Self::Challenge, LogUpGadget>,
        {
            match prev {
                RecursionInput::UniStark { proof, .. } => f(&proof.opening_proof),
                RecursionInput::BatchStark { proof, .. } => f(&proof.proof.opening_proof),
            }
        }

        fn prepare_circuit_for_verification(
            &self,
            circuit: &mut CircuitBuilder<Challenge>,
        ) -> Result<(), VerificationError> {
            circuit.enable_poseidon2_perm::<KoalaBearD4Width16, _>(
                generate_poseidon2_trace::<Challenge, KoalaBearD4Width16>,
                default_koalabear_poseidon2_16(),
            );
            circuit.enable_recompose::<F>(generate_recompose_trace::<F, Challenge>);
            Ok(())
        }

        fn pcs_verifier_params(
            &self,
        ) -> &<HidingPcs as RecursivePcs<
            Self,
            InputProofTargets<F, Challenge, RecMmcs>,
            OpeningTargets,
            MerkleCapTargets<F, 8>,
            <HidingPcs as Pcs<Challenge, Challenger>>::Domain,
        >>::VerifierParams {
            &self.verifier_params
        }

        fn set_fri_private_data(
            config: &Self,
            runner: &mut CircuitRunner<'_, Challenge>,
            op_ids: &[NonPrimitiveOpId],
            opening_proof: &Self::RawOpeningProof,
            transcript: OpeningTranscript<Self>,
        ) -> Result<(), &'static str> {
            let OpeningTranscript {
                mut challenger,
                mut commitments_with_opening_points,
            } = transcript;
            merge_hiding_random_openings::<Self>(
                &mut commitments_with_opening_points,
                &opening_proof.0,
            )
            .map_err(|_| "failed to merge hiding FRI random openings")?;
            observe_opened_values::<Self>(&mut challenger, &commitments_with_opening_points);
            let query_paths = restore_fri_query_paths(
                &config.fri_params,
                &config.val_mmcs,
                &config.val_mmcs,
                &opening_proof.1,
                &mut challenger,
                &commitments_with_opening_points,
            )
            .map_err(|_| "failed to restore hiding FRI query paths")?;
            set_fri_mmcs_private_data::<F, Challenge, 8>(
                runner,
                op_ids,
                &query_paths,
                Poseidon2Config::KOALA_BEAR_D4_W16,
            )
        }
    }

    pub(super) fn config(seed: u64) -> Config {
        let permutation = default_koalabear_poseidon2_16();
        let val_mmcs = MyMmcs::new(
            MyHash::new(permutation.clone()),
            MyCompress::new(permutation.clone()),
            0,
        );
        let fri_params = FriParameters::new_testing(ChallengeMmcs::new(val_mmcs.clone()), 0);
        let verifier_params = FriVerifierParams::with_mmcs(
            fri_params.log_blowup,
            fri_params.log_final_poly_len,
            fri_params.commit_proof_of_work_bits,
            fri_params.query_proof_of_work_bits,
            fri_params.num_queries,
            Poseidon2Config::KOALA_BEAR_D4_W16,
        );
        let pcs = HidingPcs::new(
            Dft::default(),
            val_mmcs.clone(),
            fri_params.clone(),
            2,
            StdRng::seed_from_u64(seed),
        );
        Config {
            config: Arc::new(NativeConfig::new(pcs, Challenger::new(permutation))),
            verifier_params,
            val_mmcs,
            fri_params,
        }
    }

    pub(super) fn batch_proof(
        config: &Config,
        start_a: u64,
        start_b: u64,
    ) -> BatchStarkProof<Config> {
        let n = 100;
        let mut builder = CircuitBuilder::new();
        let expected = builder.alloc_public_input("expected_result");
        let mut a = builder.alloc_public_input("F(0)");
        let mut b = builder.alloc_public_input("F(1)");
        for _ in 2..=n {
            let next = builder.add(a, b);
            a = b;
            b = next;
        }
        builder.connect(b, expected);
        let circuit = builder.build().expect("the hiding fixture circuit builds");
        let packing = TablePacking::new(2, 4);
        let (airs_degrees, primitive_columns, non_primitive_columns) =
            get_airs_and_degrees_with_prep::<Config, _, 1>(
                &circuit,
                &packing,
                &[],
                &[],
                ConstraintProfile::Standard,
            )
            .expect("the hiding fixture tables build");
        let (airs, degrees): (Vec<_>, Vec<_>) = airs_degrees.into_iter().unzip();
        let ext_degrees: Vec<_> = degrees
            .iter()
            .map(|degree| degree + config.is_zk())
            .collect();
        let prover_data = ProverData::from_airs_and_degrees(config, &airs, &ext_degrees);
        let circuit_prover_data =
            CircuitProverData::new(prover_data, primitive_columns, non_primitive_columns);
        let mut runner = circuit.runner();
        runner
            .set_public_inputs(&[
                fibonacci_output::<F>(start_a, start_b, n),
                F::from_u64(start_a),
                F::from_u64(start_b),
            ])
            .expect("the hiding fixture public inputs fit");
        let traces = runner.run().expect("the hiding fixture runs");
        let prover = BatchStarkProver::new(config.clone()).with_table_packing(packing);
        let proof = prover
            .prove_all_tables(&traces, &circuit_prover_data)
            .expect("the hiding fixture proves");
        prover
            .verify_all_tables::<F>(&proof)
            .expect("the hiding fixture verifies");
        proof
    }

    pub(super) fn verify(
        config: Config,
        params: &ProveNextLayerParams,
        output: &p3_recursion::RecursionOutput<Config>,
    ) {
        let mut verifier =
            BatchStarkProver::new(config).with_table_packing(params.table_packing.clone());
        verifier.register_poseidon2_table::<4>(Poseidon2Config::KOALA_BEAR_D4_W16.for_challenger());
        verifier.register_poseidon2_table::<4>(Poseidon2Config::KOALA_BEAR_D4_W16);
        verifier.register_recompose_table::<4>(true);
        verifier
            .verify_all_tables::<Challenge>(&output.0)
            .expect("the hiding aggregation proof verifies");
    }
}

#[test]
fn same_config_mixed_aggregation_retains_distinct_air_and_batch_shapes() {
    let n = 1 << 10;
    let air = FibonacciAir {};
    let (config, backend) = common::koala_bear_d4_recursion_config_and_backend();
    let batch_first = common::build_koala_bear_d4_first_layer_input_with_starts(0, 1);
    let batch_second = common::build_koala_bear_d4_first_layer_input_with_starts(2, 3);
    let table_public_inputs =
        vec![vec![]; batch_first.base_proof.proof.opened_values.instances.len()];
    let params = ProveNextLayerParams::default();

    let left_first_pis = vec![F::ZERO, F::ONE, fibonacci_output::<F>(0, 1, n)];
    let left_first = prove(
        &config,
        &air,
        generate_trace_rows::<F>(0, 1, n),
        &left_first_pis,
    );
    verify(&config, &air, &left_first, &left_first_pis).expect("the first uni proof verifies");

    let left_second_pis = vec![
        F::from_u64(2),
        F::from_u64(3),
        fibonacci_output::<F>(2, 3, n),
    ];
    let left_second = prove(
        &config,
        &air,
        generate_trace_rows::<F>(2, 3, n),
        &left_second_pis,
    );
    verify(&config, &air, &left_second, &left_second_pis).expect("the second uni proof verifies");

    let prepared = PreparedAggregation::<_, FibonacciAir, BatchOnly, _, 4>::new(
        PreparedSource::UniStark {
            air: &air,
            proof: &left_first,
            public_inputs: &left_first_pis,
            preprocessed_commit: None,
        },
        PreparedSource::batch(
            &batch_first.base_proof,
            &batch_first.base_proof.stark_common,
            &table_public_inputs,
        ),
        config.clone(),
        backend,
        params.clone(),
    )
    .expect("the mixed trusted pair prepares");

    let out1 = prepared
        .prove(
            PreparedInput::UniStark {
                proof: &left_first,
                public_inputs: &left_first_pis,
                preprocessed_commit: None,
            },
            PreparedInput::BatchStark {
                proof: &batch_first.base_proof,
                common_data: &batch_first.base_proof.stark_common,
                table_public_inputs: &table_public_inputs,
            },
        )
        .expect("the first mixed pair proves");
    let out2 = prepared
        .prove(
            PreparedInput::UniStark {
                proof: &left_second,
                public_inputs: &left_second_pis,
                preprocessed_commit: None,
            },
            PreparedInput::BatchStark {
                proof: &batch_second.base_proof,
                common_data: &batch_second.base_proof.stark_common,
                table_public_inputs: &table_public_inputs,
            },
        )
        .expect("the second mixed pair proves");

    assert!(Rc::ptr_eq(&out1.1, &out2.1));
    verify_output(config.clone(), &params, &out1);
    verify_output(config, &params, &out2);
}

#[test]
fn aggregation_rejects_either_mismatch_before_packing_or_private_setup() {
    let air = FibonacciAir {};
    let n = 1 << 10;
    let short_n = 1 << 9;
    let (config, inner) = common::koala_bear_d4_recursion_config_and_backend();
    let right_reference = common::build_koala_bear_d4_first_layer_input_with_starts(0, 1);
    let right_mismatch = common::build_koala_bear_d4_first_layer_input();
    let right_public = vec![
        vec![];
        right_reference
            .base_proof
            .proof
            .opened_values
            .instances
            .len()
    ];
    let left_pis = vec![F::ZERO, F::ONE, fibonacci_output::<F>(0, 1, n)];
    let left_proof = prove(&config, &air, generate_trace_rows::<F>(0, 1, n), &left_pis);
    let short_pis = vec![F::ZERO, F::ONE, fibonacci_output::<F>(0, 1, short_n)];
    let short_proof = prove(
        &config,
        &air,
        generate_trace_rows::<F>(0, 1, short_n),
        &short_pis,
    );

    let uni = Rc::new(SideCounters::default());
    let batch = Rc::new(SideCounters::default());
    let uni_preparations = Rc::new(Cell::new(0));
    let batch_preparations = Rc::new(Cell::new(0));
    let backend = CountingBackend {
        inner,
        uni: Rc::clone(&uni),
        batch: Rc::clone(&batch),
        uni_output_preparations: Rc::clone(&uni_preparations),
        batch_output_preparations: Rc::clone(&batch_preparations),
    };
    let params = ProveNextLayerParams::default();
    let prepared = PreparedAggregation::<_, FibonacciAir, BatchOnly, _, 4>::new(
        PreparedSource::UniStark {
            air: &air,
            proof: &left_proof,
            public_inputs: &left_pis,
            preprocessed_commit: None,
        },
        PreparedSource::batch(
            &right_reference.base_proof,
            &right_reference.base_proof.stark_common,
            &right_public,
        ),
        config.clone(),
        backend.clone(),
        params.clone(),
    )
    .expect("the reference shapes prepare");

    assert_eq!(
        uni_preparations.get(),
        1,
        "same-config output dispatches through A1"
    );
    assert_eq!(batch_preparations.get(), 0);

    let compatible_left = || PreparedInput::UniStark {
        proof: &left_proof,
        public_inputs: &left_pis,
        preprocessed_commit: None,
    };
    let compatible_right = || PreparedInput::BatchStark {
        proof: &right_reference.base_proof,
        common_data: &right_reference.base_proof.stark_common,
        table_public_inputs: &right_public,
    };

    let error = match prepared.prove(
        compatible_left(),
        PreparedInput::BatchStark {
            proof: &right_mismatch.base_proof,
            common_data: &right_mismatch.base_proof.stark_common,
            table_public_inputs: &right_public,
        },
    ) {
        Ok(_) => panic!("a right-side shape mismatch must be rejected"),
        Err(error) => error,
    };
    assert!(matches!(
        error,
        VerificationError::PreparedInputMismatch { .. }
    ));
    assert_side_counters_zero(&uni);
    assert_side_counters_zero(&batch);

    let error = match prepared.prove(
        PreparedInput::UniStark {
            proof: &short_proof,
            public_inputs: &short_pis,
            preprocessed_commit: None,
        },
        compatible_right(),
    ) {
        Ok(_) => panic!("a left-side shape mismatch must be rejected"),
        Err(error) => error,
    };
    assert!(matches!(
        error,
        VerificationError::PreparedInputMismatch { .. }
    ));
    assert_side_counters_zero(&uni);
    assert_side_counters_zero(&batch);

    uni_preparations.set(0);
    batch_preparations.set(0);
    let cross = PreparedAggregationCross::<_, _, FibonacciAir, BatchOnly, _, 4>::new(
        PreparedSource::UniStark {
            air: &air,
            proof: &left_proof,
            public_inputs: &left_pis,
            preprocessed_commit: None,
        },
        PreparedSource::batch(
            &right_reference.base_proof,
            &right_reference.base_proof.stark_common,
            &right_public,
        ),
        config.clone(),
        config,
        backend,
        params,
    )
    .expect("the cross-config path prepares");
    assert_eq!(uni_preparations.get(), 0);
    assert_eq!(
        batch_preparations.get(),
        1,
        "cross-config output dispatches through BatchOnly"
    );

    let error = match cross.prove(
        compatible_left(),
        PreparedInput::BatchStark {
            proof: &right_mismatch.base_proof,
            common_data: &right_mismatch.base_proof.stark_common,
            table_public_inputs: &right_public,
        },
    ) {
        Ok(_) => panic!("a cross-config right-side mismatch must be rejected"),
        Err(error) => error,
    };
    assert!(matches!(
        error,
        VerificationError::PreparedInputMismatch { .. }
    ));
    assert_side_counters_zero(&uni);
    assert_side_counters_zero(&batch);

    let error = match cross.prove(
        PreparedInput::UniStark {
            proof: &short_proof,
            public_inputs: &short_pis,
            preprocessed_commit: None,
        },
        compatible_right(),
    ) {
        Ok(_) => panic!("a cross-config left-side mismatch must be rejected"),
        Err(error) => error,
    };
    assert!(matches!(
        error,
        VerificationError::PreparedInputMismatch { .. }
    ));
    assert_side_counters_zero(&uni);
    assert_side_counters_zero(&batch);
}

fn assert_side_counters_zero(counters: &SideCounters) {
    assert_eq!(counters.public_packs.get(), 0);
    assert_eq!(counters.private_packs.get(), 0);
    assert_eq!(counters.private_setups.get(), 0);
}

fn verify_output(
    config: common::KoalaBearD4RecursionConfig,
    params: &ProveNextLayerParams,
    output: &p3_recursion::RecursionOutput<common::KoalaBearD4RecursionConfig>,
) {
    let mut verifier =
        BatchStarkProver::new(config).with_table_packing(params.table_packing.clone());
    verifier.register_poseidon2_table::<4>(Poseidon2Config::KOALA_BEAR_D4_W16.for_challenger());
    verifier.register_poseidon2_table::<4>(Poseidon2Config::KOALA_BEAR_D4_W16);
    verifier.register_recompose_table::<4>(true);
    verifier
        .verify_all_tables::<Challenge>(&output.0)
        .expect("the aggregation proof verifies");
}

#[test]
fn same_config_batch_aggregation_reuses_preparation_for_varied_pairs() {
    let left_first = common::build_koala_bear_d4_first_layer_input_with_starts(0, 1);
    let right_first = common::build_koala_bear_d4_first_layer_input_with_starts(2, 3);
    let left_second = common::build_koala_bear_d4_first_layer_input_with_starts(4, 5);
    let right_second = common::build_koala_bear_d4_first_layer_input_with_starts(6, 7);
    let public_inputs = vec![vec![]; left_first.base_proof.proof.opened_values.instances.len()];
    let params = ProveNextLayerParams::default();
    let config = left_first.layer_config.clone();

    let prepared = PreparedAggregation::<_, BatchOnly, BatchOnly, _, 4>::new(
        PreparedSource::batch(
            &left_first.base_proof,
            &left_first.base_proof.stark_common,
            &public_inputs,
        ),
        PreparedSource::batch(
            &right_first.base_proof,
            &right_first.base_proof.stark_common,
            &public_inputs,
        ),
        config.clone(),
        left_first.backend.clone(),
        params.clone(),
    )
    .expect("the honest pair prepares");

    let first = prepared
        .prove(
            PreparedInput::BatchStark {
                proof: &left_first.base_proof,
                common_data: &left_first.base_proof.stark_common,
                table_public_inputs: &public_inputs,
            },
            PreparedInput::BatchStark {
                proof: &right_first.base_proof,
                common_data: &right_first.base_proof.stark_common,
                table_public_inputs: &public_inputs,
            },
        )
        .expect("the reference pair proves");
    drop(left_first);
    drop(right_first);
    let second = prepared
        .prove(
            PreparedInput::BatchStark {
                proof: &left_second.base_proof,
                common_data: &left_second.base_proof.stark_common,
                table_public_inputs: &public_inputs,
            },
            PreparedInput::BatchStark {
                proof: &right_second.base_proof,
                common_data: &right_second.base_proof.stark_common,
                table_public_inputs: &public_inputs,
            },
        )
        .expect("the varied pair proves");

    assert!(Rc::ptr_eq(&first.1, &second.1));
    assert!(prepared.profile().is_none());
    assert_eq!(prepared.params().table_packing, params.table_packing);
    verify_output(config.clone(), &params, &first);
    verify_output(config, &params, &second);
}

#[test]
fn cross_config_aggregation_verifies_arity2_inputs_and_emits_arity4_outputs() {
    let left_first = common::build_koala_bear_d4_first_layer_input_with_starts(0, 1);
    let right_first = common::build_koala_bear_d4_first_layer_input_with_starts(2, 3);
    let left_second = common::build_koala_bear_d4_first_layer_input_with_starts(4, 5);
    let right_second = common::build_koala_bear_d4_first_layer_input_with_starts(6, 7);
    let table_public_inputs =
        vec![vec![]; left_first.base_proof.proof.opened_values.instances.len()];
    let input_config = left_first.layer_config.clone();
    let output_config = arity4_output::config();
    let backend = FriRecursionBackend::<16, 8, _>::new(Poseidon2Config::KOALA_BEAR_D4_W16)
        .with_extra_poseidon2_table(Poseidon2Config::KOALA_BEAR_D4_W32)
        .for_extension_degree::<4>();
    let params = ProveNextLayerParams::default();

    let prepared = PreparedAggregationCross::<_, _, BatchOnly, BatchOnly, _, 4>::new(
        PreparedSource::batch(
            &left_first.base_proof,
            &left_first.base_proof.stark_common,
            &table_public_inputs,
        ),
        PreparedSource::batch(
            &right_first.base_proof,
            &right_first.base_proof.stark_common,
            &table_public_inputs,
        ),
        input_config,
        output_config.clone(),
        backend,
        params.clone(),
    )
    .expect("the arity-2 verifier circuit prepares under the arity-4 output config");

    let out1 = prepared
        .prove(
            PreparedInput::BatchStark {
                proof: &left_first.base_proof,
                common_data: &left_first.base_proof.stark_common,
                table_public_inputs: &table_public_inputs,
            },
            PreparedInput::BatchStark {
                proof: &right_first.base_proof,
                common_data: &right_first.base_proof.stark_common,
                table_public_inputs: &table_public_inputs,
            },
        )
        .expect("the first cross-config pair proves");
    drop(left_first);
    drop(right_first);
    let out2 = prepared
        .prove(
            PreparedInput::BatchStark {
                proof: &left_second.base_proof,
                common_data: &left_second.base_proof.stark_common,
                table_public_inputs: &table_public_inputs,
            },
            PreparedInput::BatchStark {
                proof: &right_second.base_proof,
                common_data: &right_second.base_proof.stark_common,
                table_public_inputs: &table_public_inputs,
            },
        )
        .expect("the second cross-config pair proves");

    assert!(Rc::ptr_eq(&out1.1, &out2.1));
    assert!(prepared.profile().is_none());
    assert_eq!(prepared.params().table_packing, params.table_packing);
    arity4_output::verify(output_config.clone(), &params, &out1);
    arity4_output::verify(output_config, &params, &out2);
}

#[test]
fn hiding_fri_aggregation_reuses_preparation_for_varied_honest_pairs() {
    let config = hiding_fri::config(7);
    let backend = FriRecursionBackend::<16, 8, _>::new(Poseidon2Config::KOALA_BEAR_D4_W16)
        .for_extension_degree::<4>();
    let params = ProveNextLayerParams::default();
    let left_first = hiding_fri::batch_proof(&config, 0, 1);
    let right_first = hiding_fri::batch_proof(&config, 2, 3);
    let left_second = hiding_fri::batch_proof(&config, 4, 5);
    let right_second = hiding_fri::batch_proof(&config, 6, 7);
    let table_public_inputs = vec![vec![]; left_first.proof.opened_values.instances.len()];

    let prepared = PreparedAggregation::<_, BatchOnly, BatchOnly, _, 4>::new(
        PreparedSource::batch(&left_first, &left_first.stark_common, &table_public_inputs),
        PreparedSource::batch(
            &right_first,
            &right_first.stark_common,
            &table_public_inputs,
        ),
        config.clone(),
        backend,
        params.clone(),
    )
    .expect("the hiding verifier pair prepares");

    let out1 = prepared
        .prove(
            PreparedInput::BatchStark {
                proof: &left_first,
                common_data: &left_first.stark_common,
                table_public_inputs: &table_public_inputs,
            },
            PreparedInput::BatchStark {
                proof: &right_first,
                common_data: &right_first.stark_common,
                table_public_inputs: &table_public_inputs,
            },
        )
        .expect("the first hiding pair proves");
    let out2 = prepared
        .prove(
            PreparedInput::BatchStark {
                proof: &left_second,
                common_data: &left_second.stark_common,
                table_public_inputs: &table_public_inputs,
            },
            PreparedInput::BatchStark {
                proof: &right_second,
                common_data: &right_second.stark_common,
                table_public_inputs: &table_public_inputs,
            },
        )
        .expect("the second hiding pair proves");

    assert!(Rc::ptr_eq(&out1.1, &out2.1));
    hiding_fri::verify(config.clone(), &params, &out1);
    hiding_fri::verify(config, &params, &out2);
}
