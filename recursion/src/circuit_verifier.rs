use alloc::vec;
use alloc::vec::Vec;

use itertools::{Itertools, zip_eq};
use p3_circuit::utils::ColumnsTargets;
use p3_circuit::{CircuitBuilder, CircuitBuilderError, CircuitError};
use p3_commit::Pcs;
use p3_field::{BasedVectorSpace, Field, PrimeCharacteristicRing};
use p3_uni_stark::StarkGenericConfig;
use thiserror::Error;

use crate::Target;
use crate::challenges::ProofChallengesTargets;
use crate::lookup::{
    AllColumnTargets, GlobalLookup, LocalLookup, NoLookup, RecursiveLookupVerification,
    RecursivePermutationAir,
};
use crate::recursive_generation::GenerationError;
use crate::recursive_traits::{
    CommitmentTargets, OpenedValuesTargets, ProofTargets, Recursive, RecursivePcs,
};

#[derive(Debug, Error)]
pub enum VerificationError {
    #[error("Invalid proof shape")]
    InvalidProofShape,

    #[error("Missing random opened values for existing random commitment")]
    RandomizationError,

    #[error("Circuit error: {0}")]
    Circuit(#[from] CircuitError),

    #[error("Circuit builder error: {0}")]
    CircuitBuilder(#[from] CircuitBuilderError),

    #[error("Generation error: {0}")]
    Generation(#[from] GenerationError),
}

// Method to get all the challenge targets.
fn get_circuit_challenges<
    SC: StarkGenericConfig,
    Comm: Recursive<SC::Challenge, Input = <SC::Pcs as Pcs<SC::Challenge, SC::Challenger>>::Commitment>,
    InputProof: Recursive<SC::Challenge>,
    OpeningProof: Recursive<SC::Challenge>,
    RecursiveLookup: RecursiveLookupVerification<SC::Challenge>,
>(
    circuit: &mut CircuitBuilder<SC::Challenge>,
    proof_targets: &ProofTargets<SC, Comm, OpeningProof>,
    local_lookups: &[LocalLookup],
    global_lookup_challenges: &[Vec<Target>],
    lookup_gadget: &RecursiveLookup,
) -> ProofChallengesTargets
where
    SC::Pcs: RecursivePcs<
            SC,
            InputProof,
            OpeningProof,
            Comm,
            <SC::Pcs as Pcs<SC::Challenge, SC::Challenger>>::Domain,
        >,
{
    // TODO: Observe degree bits and degree_bits - is_zk.
    // TODO: Observe local targets.
    // TODO: Observe public values.
    // TODO: Global challenges should be generated beforehand.
    let local_lookup_challenges =
        lookup_gadget.get_local_lookup_challenges_circuit(circuit, local_lookups);

    // First Fiat-Shamir challenge `alpha`.
    let alpha = circuit.add_public_input();
    // TODO: Observe quotient chunks.
    // TODO: Observe random commitment if any.
    // zeta and zeta_next
    let zeta = circuit.add_public_input();
    let zeta_next = circuit.add_public_input();

    let pcs_challenges = SC::Pcs::get_challenges_circuit(circuit, proof_targets);

    ProofChallengesTargets {
        alpha,
        zeta,
        zeta_next,
        pcs_challenges,
        local_lookup_challenges,
        global_lookup_challenges: global_lookup_challenges.to_vec(),
    }
}

pub struct ProofTargetsWithPVs<
    'a,
    SC: StarkGenericConfig,
    Comm: Recursive<SC::Challenge, Input = <SC::Pcs as Pcs<SC::Challenge, SC::Challenger>>::Commitment>,
    OpeningProof: Recursive<SC::Challenge>,
> {
    pub proof_targets: &'a ProofTargets<SC, Comm, OpeningProof>,
    pub public_values: &'a [Target],
}

pub fn verify_circuit_no_lookups<
    SC: StarkGenericConfig,
    Comm: Recursive<
            SC::Challenge,
            Input = <SC::Pcs as Pcs<SC::Challenge, SC::Challenger>>::Commitment,
        > + Clone,
    InputProof: Recursive<SC::Challenge>,
    OpeningProof: Recursive<SC::Challenge>,
>(
    config: &SC,
    air: &dyn RecursivePermutationAir<SC::Challenge>,
    circuit: &mut CircuitBuilder<SC::Challenge>,
    proof_targets_pvs: &ProofTargetsWithPVs<SC, Comm, OpeningProof>,
) -> Result<(), VerificationError>
where
    <SC as StarkGenericConfig>::Pcs: RecursivePcs<
            SC,
            InputProof,
            OpeningProof,
            Comm,
            <SC::Pcs as Pcs<SC::Challenge, SC::Challenger>>::Domain,
        >,
{
    let lookup_gadget = NoLookup {};
    verify_circuit(
        config,
        air,
        circuit,
        proof_targets_pvs,
        &[],
        &[],
        &[],
        &lookup_gadget,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn verify_circuit<
    SC: StarkGenericConfig,
    Comm: Recursive<
            SC::Challenge,
            Input = <SC::Pcs as Pcs<SC::Challenge, SC::Challenger>>::Commitment,
        > + Clone,
    InputProof: Recursive<SC::Challenge>,
    OpeningProof: Recursive<SC::Challenge>,
    RecursiveLookup: RecursiveLookupVerification<SC::Challenge>,
>(
    config: &SC,
    air: &dyn RecursivePermutationAir<SC::Challenge>,
    circuit: &mut CircuitBuilder<SC::Challenge>,
    proof_targets_pvs: &ProofTargetsWithPVs<SC, Comm, OpeningProof>,
    local_lookups: &[LocalLookup],
    global_lookups: &[GlobalLookup],
    global_challenges: &[Vec<Target>],
    lookup_gadget: &RecursiveLookup,
) -> Result<(), VerificationError>
where
    <SC as StarkGenericConfig>::Pcs: RecursivePcs<
            SC,
            InputProof,
            OpeningProof,
            Comm,
            <SC::Pcs as Pcs<SC::Challenge, SC::Challenger>>::Domain,
        >,
{
    let ProofTargetsWithPVs {
        proof_targets,
        public_values,
    } = proof_targets_pvs;

    let ProofTargets {
        commitments_targets:
            CommitmentTargets {
                trace_targets,
                quotient_chunks_targets,
                random_commit,
                ..
            },
        opened_values_targets:
            OpenedValuesTargets {
                trace_local_targets: opened_trace_local_targets,
                trace_next_targets: opened_trace_next_targets,
                quotient_chunks_targets: opened_quotient_chunks_targets,
                random_targets: opened_random,
                ..
            },
        opening_proof,
        degree_bits,
    } = proof_targets;

    let degree = 1 << degree_bits;
    let log_quotient_degree = air.get_log_quotient_degree(public_values.len(), config.is_zk());
    let quotient_degree = 1 << (log_quotient_degree + config.is_zk());

    let pcs = config.pcs();
    let trace_domain = pcs.natural_domain_for_degree(degree);
    let init_trace_domain = pcs.natural_domain_for_degree(degree >> (config.is_zk()));

    let quotient_domain =
        pcs.create_disjoint_domain(trace_domain, 1 << (degree_bits + log_quotient_degree));
    let quotient_chunks_domains = pcs.split_domains(&quotient_domain, quotient_degree);

    let randomized_quotient_chunks_domains = quotient_chunks_domains
        .iter()
        .map(|domain| pcs.natural_domain_for_degree(pcs.size(domain) << (config.is_zk())))
        .collect_vec();

    // Challenger is called here. But we don't have the interactions or hash tables yet.
    let challenge_targets =
        get_circuit_challenges::<SC, Comm, InputProof, OpeningProof, RecursiveLookup>(
            circuit,
            proof_targets,
            local_lookups,
            global_challenges,
            lookup_gadget,
        );

    // Verify shape.
    let air_width = air.width();
    let validate_shape = opened_trace_local_targets.len() == air_width
        && opened_trace_next_targets.len() == air_width
        && opened_quotient_chunks_targets.len() == quotient_degree
        && opened_quotient_chunks_targets
            .iter()
            .all(|opened_chunk| opened_chunk.len() == SC::Challenge::DIMENSION);
    if !validate_shape {
        return Err(VerificationError::InvalidProofShape);
    }

    let alpha = challenge_targets.alpha;
    let zeta = challenge_targets.zeta;
    let zeta_next = challenge_targets.zeta_next;

    // Need to simulate Fri here.
    let mut coms_to_verify = if let Some(r_commit) = &random_commit {
        let random_values = opened_random
            .as_ref()
            .ok_or(VerificationError::RandomizationError)?;
        vec![(
            r_commit.clone(),
            vec![(trace_domain, vec![(zeta, random_values.clone())])],
        )]
    } else {
        vec![]
    };
    coms_to_verify.extend(vec![
        (
            trace_targets.clone(),
            vec![(
                trace_domain,
                vec![
                    (zeta, opened_trace_local_targets.clone()),
                    (zeta_next, opened_trace_next_targets.clone()),
                ],
            )],
        ),
        (
            quotient_chunks_targets.clone(),
            // Check the commitment on the randomized domains.
            zip_eq(
                randomized_quotient_chunks_domains.iter(),
                opened_quotient_chunks_targets,
            )
            .map(|(domain, values)| (*domain, vec![(zeta, values.clone())]))
            .collect_vec(),
        ),
    ]);
    pcs.verify_circuit(
        circuit,
        &challenge_targets.pcs_challenges,
        &coms_to_verify,
        opening_proof,
    );

    let zero = circuit.add_const(SC::Challenge::ZERO);
    let one = circuit.add_const(SC::Challenge::ONE);
    let zps = quotient_chunks_domains
        .iter()
        .enumerate()
        .map(|(i, domain)| {
            quotient_chunks_domains
                .iter()
                .enumerate()
                .filter(|(j, _)| *j != i)
                .fold(one, |total, (_, other_domain)| {
                    let vp_zeta = vanishing_poly_at_point_circuit::<
                        SC,
                        InputProof,
                        OpeningProof,
                        Comm,
                        <SC::Pcs as Pcs<SC::Challenge, SC::Challenger>>::Domain,
                    >(config, *other_domain, zeta, circuit);

                    let first_point = circuit.add_const(pcs.first_point(domain));
                    let vp_first_point =
                        vanishing_poly_at_point_circuit::<
                            SC,
                            InputProof,
                            OpeningProof,
                            Comm,
                            <SC::Pcs as Pcs<SC::Challenge, SC::Challenger>>::Domain,
                        >(config, *other_domain, first_point, circuit);
                    let div = circuit.div(vp_zeta, vp_first_point);

                    circuit.mul(total, div)
                })
        })
        .collect_vec();

    let quotient =
        opened_quotient_chunks_targets
            .iter()
            .enumerate()
            .fold(zero, |quotient, (i, chunk)| {
                let zp = zps[i];

                let inner_result = chunk.iter().enumerate().fold(zero, |cur_s, (e_i, c)| {
                    let e_i_target =
                        circuit.add_const(SC::Challenge::ith_basis_element(e_i).unwrap());
                    let inner_mul = circuit.mul(e_i_target, *c);
                    circuit.add(cur_s, inner_mul)
                });
                let mul = circuit.mul(inner_result, zp);
                circuit.add(quotient, mul)
            });

    let zero = circuit.add_const(SC::Challenge::ZERO);
    let sels = pcs.selectors_at_point_circuit(circuit, &init_trace_domain, &zeta);
    let columns_targets = ColumnsTargets {
        challenges: &[],
        public_values,
        local_prep_values: &[],
        next_prep_values: &[],
        local_values: opened_trace_local_targets,
        next_values: opened_trace_next_targets,
    };
    let folded_constraints =
        air.eval_folded_circuit(circuit, &sels, &alpha, &columns_targets, zero);

    let all_columns_targets = AllColumnTargets {
        local_lookups,
        global_lookups,
        columns_targets: &columns_targets,
        local_lookup_challenges: &challenge_targets.local_lookup_challenges,
        global_lookup_challenges: &challenge_targets.global_lookup_challenges,
    };
    // Fold the lookup constraints with the previously computed AIR constraints.
    let folded_constraints = lookup_gadget.eval_lookup_constraints(
        air,
        circuit,
        &sels,
        &alpha,
        all_columns_targets,
        folded_constraints,
    );

    // Compute folded_constraints * sels.inv_vanishing.
    let folded_mul = circuit.mul(folded_constraints, sels.inv_vanishing);

    // Check that folded_constraints * sels.inv_vanishing == quotient
    circuit.connect(folded_mul, quotient);

    Ok(())
}

fn vanishing_poly_at_point_circuit<
    SC: StarkGenericConfig,
    InputProof: Recursive<SC::Challenge>,
    OpeningProof: Recursive<SC::Challenge>,
    Comm: Recursive<SC::Challenge>,
    Domain,
>(
    config: &SC,
    domain: Domain,
    zeta: Target,
    circuit: &mut CircuitBuilder<SC::Challenge>,
) -> Target
where
    <SC as StarkGenericConfig>::Pcs: RecursivePcs<SC, InputProof, OpeningProof, Comm, Domain>,
{
    let pcs = config.pcs();
    let inv = circuit.add_const(pcs.first_point(&domain).inverse());
    let mul = circuit.mul(zeta, inv);
    let exp = circuit.exp_power_of_2(mul, pcs.log_size(&domain));
    let one = circuit.add_const(SC::Challenge::ONE);

    circuit.sub(exp, one)
}

#[cfg(test)]
mod tests {
    use alloc::vec;
    use alloc::vec::Vec;
    use core::marker::PhantomData;

    use itertools::Itertools;
    use p3_air::{Air, AirBuilder, BaseAir};
    use p3_baby_bear::{BabyBear, Poseidon2BabyBear};
    use p3_challenger::DuplexChallenger;
    use p3_circuit::CircuitBuilder;
    use p3_circuit::utils::RowSelectorsTargets;
    use p3_commit::PolynomialSpace;
    use p3_commit::testing::TrivialPcs;
    use p3_dft::{Radix2DitParallel, TwoAdicSubgroupDft};
    use p3_field::coset::TwoAdicMultiplicativeCoset;
    use p3_field::extension::BinomialExtensionField;
    use p3_field::{ExtensionField, Field, PrimeCharacteristicRing, TwoAdicField};
    use p3_matrix::Matrix;
    use p3_matrix::dense::RowMajorMatrix;
    use p3_uni_stark::{Domain, StarkConfig, StarkGenericConfig, Val, prove};
    use rand::distr::{Distribution, StandardUniform};
    use rand::rngs::SmallRng;
    use rand::{Rng, SeedableRng};

    use crate::Target;
    use crate::circuit_verifier::{ProofTargetsWithPVs, verify_circuit_no_lookups};
    use crate::lookup::AirWithoutLookup;
    use crate::recursive_generation::{
        ComsWithOpenings, GenerationError, PcsGeneration, generate_challenges_no_lookups,
    };
    use crate::recursive_traits::{
        ComsWithOpeningsTargets, ProofTargets, Recursive, RecursiveAir, RecursiveLagrangeSelectors,
        RecursivePcs,
    };

    type DummyCom<F> = Vec<Vec<F>>;

    impl<F: Field, EF: ExtensionField<F>> Recursive<EF> for DummyCom<F> {
        type Input = Vec<Vec<F>>;

        fn new(
            _circuit: &mut CircuitBuilder<EF>,
            _lens: &mut impl Iterator<Item = usize>,
            _degree_bits: usize,
        ) -> Self {
            vec![]
        }

        fn get_values(input: &Self::Input) -> Vec<EF> {
            input.iter().flatten().map(|v| EF::from(*v)).collect()
        }

        fn num_challenges(&self) -> usize {
            0
        }

        fn lens(_input: &Self::Input) -> impl Iterator<Item = usize> {
            core::iter::empty()
        }
    }

    type EmptyTarget = ();
    impl<F: Field> Recursive<F> for EmptyTarget {
        type Input = ();

        fn new(
            _circuit: &mut p3_circuit::CircuitBuilder<F>,
            _lens: &mut impl Iterator<Item = usize>,
            _degree_bits: usize,
        ) -> Self {
        }

        fn get_values(_input: &Self::Input) -> vec::Vec<F> {
            vec![]
        }

        fn num_challenges(&self) -> usize {
            0
        }

        fn lens(_input: &Self::Input) -> impl Iterator<Item = usize> {
            core::iter::empty()
        }
    }

    impl<SC: StarkGenericConfig, Comm: Recursive<SC::Challenge>, Dft>
        RecursivePcs<SC, EmptyTarget, EmptyTarget, Comm, TwoAdicMultiplicativeCoset<Val<SC>>>
        for TrivialPcs<Val<SC>, Dft>
    where
        Domain<SC>: PolynomialSpace,
        Val<SC>: TwoAdicField,
        Dft: TwoAdicSubgroupDft<Val<SC>>,
    {
        type RecursiveProof = EmptyTarget;

        fn get_challenges_circuit(
            _circuit: &mut CircuitBuilder<<SC as StarkGenericConfig>::Challenge>,
            _proof_targets: &crate::recursive_traits::ProofTargets<SC, Comm, EmptyTarget>,
        ) -> vec::Vec<Target> {
            vec![]
        }

        fn verify_circuit(
            &self,
            _circuit: &mut CircuitBuilder<<SC as StarkGenericConfig>::Challenge>,
            _challenges: &[Target],
            _commitments_with_opening_points: &ComsWithOpeningsTargets<
                Comm,
                TwoAdicMultiplicativeCoset<Val<SC>>,
            >,
            _opening_proof: &EmptyTarget,
        ) {
        }

        fn selectors_at_point_circuit(
            &self,
            circuit: &mut CircuitBuilder<SC::Challenge>,
            domain: &TwoAdicMultiplicativeCoset<Val<SC>>,
            point: &Target,
        ) -> RecursiveLagrangeSelectors {
            // Constants that we will need.
            let shift_inv = circuit.add_const(SC::Challenge::from(domain.shift_inverse()));
            let one = circuit.add_const(SC::Challenge::from(Val::<SC>::ONE));
            let subgroup_gen_inv =
                circuit.add_const(SC::Challenge::from(domain.subgroup_generator().inverse()));

            // Unshifted and z_h
            let unshifted_point = circuit.mul(shift_inv, *point);
            let us_exp = circuit.exp_power_of_2(unshifted_point, domain.log_size());
            let z_h = circuit.sub(us_exp, one);

            // Denominators
            let us_minus_one = circuit.sub(unshifted_point, one);
            let us_minus_gen_inv = circuit.sub(unshifted_point, subgroup_gen_inv);

            // Selectors
            let is_first_row = circuit.div(z_h, us_minus_one);
            let is_last_row = circuit.div(z_h, us_minus_gen_inv);
            let is_transition = us_minus_gen_inv;
            let inv_vanishing = circuit.div(one, z_h);

            let row_selectors = RowSelectorsTargets {
                is_first_row,
                is_last_row,
                is_transition,
            };
            RecursiveLagrangeSelectors {
                row_selectors,
                inv_vanishing,
            }
        }

        fn create_disjoint_domain(
            &self,
            trace_domain: TwoAdicMultiplicativeCoset<Val<SC>>,
            degree: usize,
        ) -> TwoAdicMultiplicativeCoset<Val<SC>> {
            trace_domain.create_disjoint_domain(degree)
        }

        fn split_domains(
            &self,
            trace_domain: &TwoAdicMultiplicativeCoset<Val<SC>>,
            degree: usize,
        ) -> Vec<TwoAdicMultiplicativeCoset<Val<SC>>> {
            trace_domain.split_domains(degree)
        }

        fn size(&self, trace_domain: &TwoAdicMultiplicativeCoset<Val<SC>>) -> usize {
            trace_domain.size()
        }

        fn log_size(&self, trace_domain: &TwoAdicMultiplicativeCoset<Val<SC>>) -> usize {
            trace_domain.log_size()
        }

        fn first_point(&self, trace_domain: &TwoAdicMultiplicativeCoset<Val<SC>>) -> SC::Challenge {
            SC::Challenge::from(trace_domain.first_point())
        }
    }

    impl<SC: StarkGenericConfig> PcsGeneration<SC, EmptyTarget>
        for TrivialPcs<BabyBear, Radix2DitParallel<BabyBear>>
    {
        fn generate_challenges(
            &self,
            _config: &SC,
            _challenger: &mut <SC as StarkGenericConfig>::Challenger,
            _coms_to_verify: &ComsWithOpenings<SC>,
            _opening_proof: &EmptyTarget,
            // Depending on the `OpeningProof`, we might need additional parameters. For example, for a `FriProof`, we need the `log_max_height` to sample query indices.
            _extra_params: Option<&[usize]>,
        ) -> Result<Vec<SC::Challenge>, GenerationError> {
            Ok(vec![])
        }

        fn num_challenges(
            _opening_proof: &EmptyTarget,
            _extra_params: Option<&[usize]>,
        ) -> Result<usize, GenerationError> {
            Ok(0)
        }
    }

    const REPETITIONS: usize = 20; // This should be < 255 so it can fit into a u8.
    const TRACE_WIDTH: usize = REPETITIONS * 3;

    pub struct MulAir {
        degree: u64,
    }

    impl Default for MulAir {
        fn default() -> Self {
            Self { degree: 3 }
        }
    }

    impl MulAir {
        pub fn random_valid_trace<F: Field>(&self, rows: usize, valid: bool) -> RowMajorMatrix<F>
        where
            StandardUniform: Distribution<F>,
        {
            let mut rng = SmallRng::seed_from_u64(1);
            let mut trace_values = F::zero_vec(rows * TRACE_WIDTH);
            for (i, (a, b, c)) in trace_values.iter_mut().tuples().enumerate() {
                let row = i / REPETITIONS;
                *a = F::from_usize(i);

                *b = if row == 0 {
                    a.square() + F::ONE
                } else {
                    rng.random()
                };

                *c = a.exp_u64(self.degree - 1) * *b;

                if !valid {
                    // make it invalid
                    *c *= F::TWO;
                }
            }
            RowMajorMatrix::new(trace_values, TRACE_WIDTH)
        }
    }

    impl<F> BaseAir<F> for MulAir {
        fn width(&self) -> usize {
            TRACE_WIDTH
        }
    }

    impl<AB: AirBuilder> Air<AB> for MulAir {
        fn eval(&self, builder: &mut AB) {
            let main = builder.main();
            let main_local = main.row_slice(0).expect("Matrix is empty?");
            let main_next = main.row_slice(1).expect("Matrix only has 1 row?");

            for i in 0..REPETITIONS {
                let start = i * 3;
                let a = main_local[start].clone();
                let b = main_local[start + 1].clone();
                let c = main_local[start + 2].clone();
                builder.assert_zero(a.clone().into().exp_u64(self.degree - 1) * b.clone() - c);

                builder
                    .when_first_row()
                    .assert_eq(a.clone() * a.clone() + AB::Expr::ONE, b);

                let next_a = main_next[start].clone();
                builder
                    .when_transition()
                    .assert_eq(a + AB::Expr::from_u8(REPETITIONS as u8), next_a);
            }
        }
    }

    #[test]
    fn test_mul_verifier_circuit() -> anyhow::Result<()> {
        let log_n = 8;
        type Val = BabyBear;
        type Challenge = BinomialExtensionField<Val, 4>;

        type Perm = Poseidon2BabyBear<16>;
        let mut rng = SmallRng::seed_from_u64(1);
        let perm = Perm::new_from_rng_128(&mut rng);

        type Dft = Radix2DitParallel<Val>;
        let dft = Dft::default();

        type Challenger = DuplexChallenger<Val, Perm, 16, 8>;

        type Pcs = TrivialPcs<Val, Radix2DitParallel<Val>>;
        let pcs = TrivialPcs {
            dft,
            log_n,
            _phantom: PhantomData,
        };
        let challenger = Challenger::new(perm);

        type MyConfig = StarkConfig<Pcs, Challenge, Challenger>;
        let config = MyConfig::new(pcs, challenger);

        let air = MulAir { degree: 2 };

        let trace = air.random_valid_trace(1 << log_n, true);

        let mut proof = prove(&config, &air, trace, &vec![]);

        let log_quotient_degree =
            <MulAir as RecursiveAir<Val>>::get_log_quotient_degree(&air, 0, config.is_zk());
        let challenges = generate_challenges_no_lookups(
            &config,
            &[&proof],
            &[log_quotient_degree],
            &[&[]],
            None,
        )?;

        proof.commitments.random = None;
        proof.commitments.quotient_chunks = vec![];
        proof.commitments.trace = vec![];

        let mut all_lens = ProofTargets::<
            StarkConfig<TrivialPcs<Val, Dft>, Challenge, Challenger>,
            DummyCom<Val>,
            EmptyTarget,
        >::lens(&proof);

        // Create an air without lookups.
        let air_no_lookup = AirWithoutLookup::new(air);

        // Initialize the circuit builder.
        let mut circuit_builder = CircuitBuilder::<Challenge>::new();
        let proof_targets = ProofTargets::<
            StarkConfig<TrivialPcs<Val, Dft>, Challenge, Challenger>,
            DummyCom<Val>,
            EmptyTarget,
        >::new(&mut circuit_builder, &mut all_lens, proof.degree_bits);

        let proof_values = ProofTargets::<
            StarkConfig<TrivialPcs<Val, Dft>, Challenge, Challenger>,
            DummyCom<Val>,
            EmptyTarget,
        >::get_values(&proof);

        let pvs = proof_values
            .iter()
            .chain(&challenges)
            .copied()
            .collect::<Vec<_>>();

        let proof_targets_pvs = ProofTargetsWithPVs {
            proof_targets: &proof_targets,
            public_values: &[],
        };

        verify_circuit_no_lookups(
            &config,
            &air_no_lookup,
            &mut circuit_builder,
            &proof_targets_pvs,
        )?;

        let circuit = circuit_builder.build().unwrap();
        let mut runner = circuit.runner();
        runner.set_public_inputs(&pvs)?;

        let _traces = runner.run()?;

        Ok(())
    }
}
