use alloc::vec;
use alloc::vec::Vec;

use itertools::{Itertools, zip_eq};
use p3_circuit::utils::ColumnsTargets;
use p3_circuit::{CircuitBuilder, CircuitBuilderError, CircuitError};
use p3_commit::Pcs;
use p3_field::{BasedVectorSpace, Field, PrimeCharacteristicRing, PrimeField64};
use p3_uni_stark::StarkGenericConfig;
use thiserror::Error;

use crate::Target;
use crate::challenges::StarkChallenges;
use crate::recursive_generation::GenerationError;
use crate::recursive_pcs::MAX_QUERY_INDEX_BITS;
use crate::recursive_traits::{
    CommitmentTargets, OpenedValuesTargets, ProofTargets, Recursive, RecursiveAir, RecursivePcs,
};

type PcsVerifierParams<SC, InputProof, OpeningProof, Comm> =
    <<SC as StarkGenericConfig>::Pcs as RecursivePcs<
        SC,
        InputProof,
        OpeningProof,
        Comm,
        <<SC as StarkGenericConfig>::Pcs as Pcs<
            <SC as StarkGenericConfig>::Challenge,
            <SC as StarkGenericConfig>::Challenger,
        >>::Domain,
    >>::VerifierParams;

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
>(
    proof_targets: &ProofTargets<SC, Comm, OpeningProof>,
    circuit: &mut CircuitBuilder<SC::Challenge>,
    pcs_params: &PcsVerifierParams<SC, InputProof, OpeningProof, Comm>,
) -> Vec<Target>
where
    SC::Pcs: RecursivePcs<
            SC,
            InputProof,
            OpeningProof,
            Comm,
            <SC::Pcs as Pcs<SC::Challenge, SC::Challenger>>::Domain,
        >,
{
    // Allocate base STARK challenges (alpha, zeta, zeta_next)
    let base_challenges = StarkChallenges::allocate(circuit);

    // Get PCS-specific challenges (e.g., FRI betas and query indices)
    let pcs_challenges = SC::Pcs::get_challenges_circuit(circuit, proof_targets, pcs_params);

    // Return flat vector: [alpha, zeta, zeta_next, ...pcs_challenges]
    let mut all_challenges = base_challenges.to_vec();
    all_challenges.extend(pcs_challenges);
    all_challenges
}

/// Constructs the public input values for a STARK verification circuit.
///
/// # Parameters
/// - `public_values`: The AIR public input values
/// - `proof_values`: Values extracted from the proof targets
/// - `challenges`: All challenge values
/// - `num_queries`: Number of FRI query proofs
///
/// # Returns
/// A vector of field elements ready to be passed to `CircuitRunner::set_public_inputs`
pub fn construct_verifier_public_inputs<F, EF>(
    public_values: &[F],
    proof_values: &[EF],
    challenges: &[EF],
    num_queries: usize,
) -> Vec<EF>
where
    F: Field + PrimeField64,
    EF: Field + BasedVectorSpace<F> + From<F>,
{
    let num_challenges_before_queries = challenges.len() - num_queries;

    // Start with public values, proof values, and all challenges
    let mut inputs: Vec<EF> = public_values
        .iter()
        .map(|&pv| pv.into())
        .chain(proof_values.iter().copied())
        .chain(challenges.iter().copied())
        .collect();

    // Add bit decompositions for query indices.
    // The circuit calls decompose_to_bits on each query index,
    // which creates MAX_QUERY_INDEX_BITS additional public inputs.
    for &query_index in &challenges[num_challenges_before_queries..] {
        let coeffs = query_index.as_basis_coefficients_slice();
        let index_usize = coeffs[0].as_canonical_u64() as usize;

        for k in 0..MAX_QUERY_INDEX_BITS {
            let bit = if (index_usize >> k) & 1 == 1 {
                EF::ONE
            } else {
                EF::ZERO
            };
            inputs.push(bit);
        }
    }

    inputs
}

/// Verifies a STARK proof within a circuit.
///
/// This function adds constraints to the circuit builder that verify a STARK proof.
///
/// # Parameters
/// - `config`: STARK configuration including PCS and challenger
/// - `air`: The Algebraic Intermediate Representation defining the computation
/// - `circuit`: Circuit builder to add verification constraints to
/// - `proof_targets`: Recursive representation of the proof
/// - `public_values`: Public input targets
/// - `pcs_params`: PCS-specific verifier parameters (e.g. FRI's log blowup / final poly size)
///
/// # Returns
/// `Ok(())` if the circuit was successfully constructed, `Err` otherwise.
pub fn verify_circuit<
    A,
    SC: StarkGenericConfig,
    Comm: Recursive<
            SC::Challenge,
            Input = <SC::Pcs as Pcs<SC::Challenge, SC::Challenger>>::Commitment,
        > + Clone,
    InputProof: Recursive<SC::Challenge>,
    OpeningProof: Recursive<SC::Challenge>,
>(
    config: &SC,
    air: &A,
    circuit: &mut CircuitBuilder<SC::Challenge>,
    proof_targets: &ProofTargets<SC, Comm, OpeningProof>,
    public_values: &[Target],
    pcs_params: &PcsVerifierParams<SC, InputProof, OpeningProof, Comm>,
) -> Result<(), VerificationError>
where
    A: RecursiveAir<SC::Challenge>,
    <SC as StarkGenericConfig>::Pcs: RecursivePcs<
            SC,
            InputProof,
            OpeningProof,
            Comm,
            <SC::Pcs as Pcs<SC::Challenge, SC::Challenger>>::Domain,
        >,
{
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
    let log_quotient_degree = A::get_log_quotient_degree(air, public_values.len(), config.is_zk());
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
    let challenge_targets = get_circuit_challenges::<SC, Comm, InputProof, OpeningProof>(
        proof_targets,
        circuit,
        pcs_params,
    );

    // Verify shape.
    let air_width = A::width(air);
    let validate_shape = opened_trace_local_targets.len() == air_width
        && opened_trace_next_targets.len() == air_width
        && opened_quotient_chunks_targets.len() == quotient_degree
        && opened_quotient_chunks_targets
            .iter()
            .all(|opened_chunk| opened_chunk.len() == SC::Challenge::DIMENSION);
    if !validate_shape {
        return Err(VerificationError::InvalidProofShape);
    }

    let alpha = challenge_targets[0];
    let zeta = challenge_targets[1];
    let zeta_next = challenge_targets[2];

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
        &challenge_targets[3..],
        &coms_to_verify,
        opening_proof,
        pcs_params,
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
                    let vp_zeta =
                        vanishing_poly_at_point_circuit(config, *other_domain, zeta, circuit);

                    let first_point = circuit.add_const(pcs.first_point(domain));
                    let vp_first_point = vanishing_poly_at_point_circuit(
                        config,
                        *other_domain,
                        first_point,
                        circuit,
                    );
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

    let sels = pcs.selectors_at_point_circuit(circuit, &init_trace_domain, &zeta);
    let columns_targets = ColumnsTargets {
        challenges: &[],
        public_values,
        local_prep_values: &[],
        next_prep_values: &[],
        local_values: opened_trace_local_targets,
        next_values: opened_trace_next_targets,
    };
    let folded_constraints = air.eval_folded_circuit(circuit, &sels, &alpha, columns_targets);

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
    use alloc::string::String;
    use alloc::vec::Vec;
    use alloc::{format, vec};
    use core::marker::PhantomData;

    use itertools::Itertools;
    use p3_air::{Air, AirBuilder, BaseAir};
    use p3_baby_bear::{BabyBear, Poseidon2BabyBear};
    use p3_challenger::{CanObserve, DuplexChallenger, FieldChallenger};
    use p3_circuit::CircuitBuilder;
    use p3_circuit::utils::RowSelectorsTargets;
    use p3_commit::testing::TrivialPcs;
    use p3_commit::{Pcs, PolynomialSpace};
    use p3_dft::{Radix2DitParallel, TwoAdicSubgroupDft};
    use p3_field::coset::TwoAdicMultiplicativeCoset;
    use p3_field::extension::BinomialExtensionField;
    use p3_field::{ExtensionField, Field, PrimeCharacteristicRing, TwoAdicField};
    use p3_matrix::Matrix;
    use p3_matrix::dense::RowMajorMatrix;
    use p3_uni_stark::{Domain, StarkConfig, StarkGenericConfig, Val, prove};
    use p3_util::log2_strict_usize;
    use rand::distr::{Distribution, StandardUniform};
    use rand::rngs::SmallRng;
    use rand::{Rng, SeedableRng};

    use crate::Target;
    use crate::circuit_verifier::verify_circuit;
    use crate::recursive_traits::{
        ComsWithOpeningsTargets, ProofTargets, Recursive, RecursiveLagrangeSelectors, RecursivePcs,
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
        type VerifierParams = ();
        type RecursiveProof = EmptyTarget;

        fn get_challenges_circuit(
            _circuit: &mut CircuitBuilder<<SC as StarkGenericConfig>::Challenge>,
            _proof_targets: &crate::recursive_traits::ProofTargets<SC, Comm, EmptyTarget>,
            _params: &Self::VerifierParams,
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
            _params: &Self::VerifierParams,
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

    fn get_challenges<SC: StarkGenericConfig>(
        config: &SC,
        degree: usize,
        trace_commit: &<SC::Pcs as Pcs<SC::Challenge, SC::Challenger>>::Commitment,
        quotient_chunks: &<SC::Pcs as Pcs<SC::Challenge, SC::Challenger>>::Commitment,
        random: &Option<<SC::Pcs as Pcs<SC::Challenge, SC::Challenger>>::Commitment>,
    ) -> Vec<SC::Challenge> {
        let log_degree = log2_strict_usize(degree);
        let log_ext_degree = log_degree + config.is_zk();

        let pcs = config.pcs();
        let init_trace_domain = pcs.natural_domain_for_degree(degree >> (config.is_zk()));

        // Initialize the PCS and the Challenger.
        let mut challenger = config.initialise_challenger();

        // Observe the instance.
        // degree < 2^255 so we can safely cast log_degree to a u8.
        challenger.observe(Val::<SC>::from_u8(log_ext_degree as u8));
        challenger.observe(Val::<SC>::from_u8(log_degree as u8));
        // TODO: Might be best practice to include other instance data here; see verifier comment.

        // Observe the Merkle root of the trace commitment.
        challenger.observe(trace_commit.clone());

        // There are no public values to observe.
        let alpha: SC::Challenge = challenger.sample_algebra_element();

        challenger.observe(quotient_chunks.clone());

        // We've already checked that commitments.random is present if and only if ZK is enabled.
        // Observe the random commitment if it is present.
        if let Some(r_commit) = random.clone() {
            challenger.observe(r_commit);
        }

        // Get an out-of-domain point to open our values at.
        //
        // Soundness Error: dN/|EF| where `N` is the trace length and our constraint polynomial has degree `d`.
        let zeta = challenger.sample_algebra_element();
        let zeta_next = init_trace_domain.next_point(zeta).unwrap();

        vec![alpha, zeta, zeta_next]
    }

    #[test]
    fn test_mul_verifier_circuit() -> Result<(), String> {
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

        let challenges = get_challenges(
            &config,
            1 << log_n,
            &proof.commitments.trace,
            &proof.commitments.quotient_chunks,
            &proof.commitments.random,
        );

        proof.commitments.random = None;
        proof.commitments.quotient_chunks = vec![];
        proof.commitments.trace = vec![];

        let mut all_lens = ProofTargets::<
            StarkConfig<TrivialPcs<Val, Dft>, Challenge, Challenger>,
            DummyCom<Val>,
            EmptyTarget,
        >::lens(&proof);

        // Initialize the circuit builder.
        let mut circuit_builder = CircuitBuilder::new();
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

        verify_circuit(
            &config,
            &air,
            &mut circuit_builder,
            &proof_targets,
            &[],
            &(),
        )
        .map_err(|e| format!("{e:?}"))?;

        let circuit = circuit_builder.build().unwrap();
        let mut runner = circuit.runner();
        runner
            .set_public_inputs(&pvs)
            .map_err(|e| format!("{e:?}"))?;

        let _traces = runner.run().map_err(|e| format!("{e:?}"))?;

        Ok(())
    }
}
