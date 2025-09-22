use p3_baby_bear::{BabyBear as F, Poseidon2BabyBear as Perm, default_babybear_poseidon2_16};
use p3_challenger::{
    CanObserve, CanSampleBits, DuplexChallenger as Challenger, FieldChallenger, GrindingChallenger,
};
use p3_commit::Pcs;
use p3_dft::Radix2DitParallel as Dft;
use p3_field::coset::TwoAdicMultiplicativeCoset;
use p3_field::extension::BinomialExtensionField as ExtF;
use p3_field::{Field, PrimeCharacteristicRing, TwoAdicField};
use p3_fri::{TwoAdicFriPcs, create_test_fri_params};
use p3_matrix::dense::RowMajorMatrix;
use p3_merkle_tree::MerkleTreeMmcs;
use p3_recursion::circuit_fri_verifier::verify_query_from_index_bits;
use p3_symmetric::{PaddingFreeSponge, TruncatedPermutation};
use rand::SeedableRng;
use rand::rngs::SmallRng;

type Challenge = ExtF<F, 4>;
type MyChallenger = Challenger<F, Perm<16>, 16, 8>;
type MyHash = PaddingFreeSponge<Perm<16>, 16, 8, 8>;
type MyCompress = TruncatedPermutation<Perm<16>, 2, 8, 16>;
type ValMmcs = MerkleTreeMmcs<<F as Field>::Packing, <F as Field>::Packing, MyHash, MyCompress, 8>;
type ChallengeMmcs = p3_commit::ExtensionMmcs<F, Challenge, ValMmcs>;
#[allow(clippy::upper_case_acronyms)]
type PCS = TwoAdicFriPcs<F, Dft<F>, ValMmcs, ChallengeMmcs>;
type MatBatch = Vec<(
    TwoAdicMultiplicativeCoset<F>,
    Vec<(Challenge, Vec<Challenge>)>,
)>;

#[test]
fn test_circuit_fri_verifier() {
    // Common setup
    let perm = default_babybear_poseidon2_16();
    let hash = MyHash::new(perm.clone());
    let compress = MyCompress::new(perm.clone());
    let val_mmcs = ValMmcs::new(hash, compress);
    let challenge_mmcs = ChallengeMmcs::new(val_mmcs.clone());
    let dft = Dft::<F>::default();
    let fri_params = create_test_fri_params(challenge_mmcs, 0);
    let log_blowup = fri_params.log_blowup;
    let log_final_poly_len = fri_params.log_final_poly_len;
    let pow_bits = fri_params.proof_of_work_bits;
    let pcs = PCS::new(dft, val_mmcs, fri_params);
    let polynomial_log_sizes = [5u8, 8, 8, 10];

    // Helper to produce public inputs for a given seed
    let produce_inputs = |seed: u64| -> (Vec<Challenge>, usize, usize) {
        let mut rng = SmallRng::seed_from_u64(seed);

        // Prover path
        let mut p_challenger = MyChallenger::new(perm.clone());
        let val_sizes: Vec<F> = polynomial_log_sizes
            .iter()
            .map(|&b| F::from_u8(b))
            .collect();
        p_challenger.observe_slice(&val_sizes);
        let evals: Vec<(TwoAdicMultiplicativeCoset<F>, RowMajorMatrix<F>)> = polynomial_log_sizes
            .iter()
            .map(|&deg_bits| {
                let deg = 1usize << deg_bits;
                (
                    <PCS as Pcs<Challenge, MyChallenger>>::natural_domain_for_degree(&pcs, deg),
                    RowMajorMatrix::<F>::rand_nonzero(
                        &mut rng,
                        deg,
                        (deg_bits as usize).saturating_sub(4),
                    ),
                )
            })
            .collect();
        let (commitment, prover_data) = <PCS as Pcs<Challenge, MyChallenger>>::commit(&pcs, evals);
        p_challenger.observe(commitment);
        let zeta: Challenge = p_challenger.sample_algebra_element();
        let num_evaluations = polynomial_log_sizes.len();
        let open_data = vec![(&prover_data, vec![vec![zeta]; num_evaluations])];
        let (opened_values, fri_proof) =
            <PCS as Pcs<Challenge, MyChallenger>>::open(&pcs, open_data, &mut p_challenger);

        // Verifier transcript replay
        let mut v_challenger = MyChallenger::new(perm.clone());
        v_challenger.observe_slice(&val_sizes);
        v_challenger.observe(commitment);
        let _zeta_v: Challenge = v_challenger.sample_algebra_element();
        let domains: Vec<TwoAdicMultiplicativeCoset<F>> = polynomial_log_sizes
            .iter()
            .map(|&size| {
                <PCS as Pcs<Challenge, MyChallenger>>::natural_domain_for_degree(&pcs, 1 << size)
            })
            .collect();
        let mats: MatBatch = domains
            .into_iter()
            .zip(opened_values.into_iter().flatten().flatten())
            .map(|(domain, value_vec)| (domain, vec![(zeta, value_vec)]))
            .collect();
        let p3_fri::FriProof {
            commit_phase_commits,
            query_proofs,
            final_poly,
            pow_witness,
        } = fri_proof;
        for (_, mats) in &mats {
            for (_point, values) in mats {
                for &opening in values {
                    v_challenger.observe_algebra_element(opening);
                }
            }
        }
        let _alpha: Challenge = v_challenger.sample_algebra_element();
        let mut betas: Vec<Challenge> = Vec::with_capacity(commit_phase_commits.len());
        for c in &commit_phase_commits {
            v_challenger.observe(*c);
            betas.push(v_challenger.sample_algebra_element());
        }
        for &c in &final_poly {
            v_challenger.observe_algebra_element(c);
        }
        assert!(v_challenger.check_witness(pow_bits, pow_witness));

        let log_max_height = commit_phase_commits.len() + log_blowup + log_final_poly_len;
        let query = &query_proofs[0];
        let index: usize = v_challenger.sample_bits(log_max_height);

        // Reductions per height
        use std::collections::BTreeMap;
        let mut ro_map: BTreeMap<usize, (Challenge, Challenge)> = BTreeMap::new();
        let batch_opening = &query.input_proof[0];
        for (mat_opening, (mat_domain, mat_points_and_values)) in
            batch_opening.opened_values.iter().zip(mats.iter())
        {
            let log_height = (mat_domain.size() << log_blowup).ilog2() as usize;
            let bits_reduced = log_max_height - log_height;
            let rev_reduced_index = p3_util::reverse_bits_len(index >> bits_reduced, log_height);
            let x =
                F::GENERATOR * F::two_adic_generator(log_height).exp_u64(rev_reduced_index as u64);

            let (mut alpha_pow, mut ro) = ro_map
                .remove(&log_height)
                .unwrap_or((Challenge::ONE, Challenge::ZERO));
            for (z, ps_at_z) in mat_points_and_values.iter() {
                let quotient = (*z - Challenge::from(x)).inverse();
                for (&p_at_x, &p_at_z) in mat_opening.iter().zip(ps_at_z.iter()) {
                    ro += alpha_pow * (p_at_z - p_at_x) * quotient;
                    alpha_pow *= _alpha; // re-use alpha derived above
                }
            }
            ro_map.insert(log_height, (alpha_pow, ro));
        }
        let mut ro_desc: Vec<(usize, Challenge)> =
            ro_map.iter().map(|(k, (_apow, ro))| (*k, *ro)).collect();
        ro_desc.sort_by_key(|(h, _)| core::cmp::Reverse(*h));
        let ro_by_height: std::collections::HashMap<usize, Challenge> =
            ro_desc.iter().cloned().collect();

        // Build public inputs vector in the order expected by the circuit
        let mut pub_inputs: Vec<Challenge> = Vec::new();
        // index bits
        for k in 0..log_max_height {
            let bit_val = if (index >> k) & 1 == 1 {
                F::ONE
            } else {
                F::ZERO
            };
            pub_inputs.push(Challenge::from(bit_val));
        }
        // initial folded
        pub_inputs.push(ro_desc[0].1);
        // betas
        pub_inputs.extend(betas.iter().copied());
        // sibling values per phase
        let mut _domain_index = index;
        for (i, opening) in query.commit_phase_openings.iter().enumerate() {
            let _log_folded_height = log_max_height - i - 1;
            let e_sibling = opening.sibling_value;
            pub_inputs.push(e_sibling);
            _domain_index >>= 1;
        }
        // roll‑ins per phase (pad with ZERO when absent)
        for i in 0..commit_phase_commits.len() {
            let h = log_max_height - i - 1;
            let val = ro_by_height.get(&h).copied().unwrap_or(Challenge::ZERO);
            pub_inputs.push(val);
        }
        // final value
        pub_inputs.push(final_poly[0]);

        (pub_inputs, log_max_height, commit_phase_commits.len())
    };

    // Produce two proofs with different seeds
    let (pub_inputs1, log_max_height_1, phases_1) = produce_inputs(0);
    let (pub_inputs2, log_max_height_2, phases_2) = produce_inputs(1);
    assert_eq!(log_max_height_1, log_max_height_2);
    assert_eq!(phases_1, phases_2);

    // Build circuit once using only shape information
    let log_max_height = log_max_height_1;
    let num_phases = phases_1;
    let mut builder = p3_circuit::CircuitBuilder::<Challenge>::new();
    let index_bits_targets: Vec<p3_circuit::ExprId> = (0..log_max_height)
        .map(|_| builder.add_public_input())
        .collect();
    let initial_folded_eval_wire = builder.add_public_input();
    let betas_targets: Vec<p3_circuit::ExprId> = (0..num_phases)
        .map(|_| builder.add_public_input())
        .collect();
    let sibling_values_targets: Vec<p3_circuit::ExprId> = (0..num_phases)
        .map(|_| builder.add_public_input())
        .collect();
    let roll_ins_targets: Vec<Option<p3_circuit::ExprId>> = (0..num_phases)
        .map(|_| Some(builder.add_public_input()))
        .collect();
    let final_value_wire = builder.add_public_input();

    // Precompute per‑phase power ladders as constants
    let pows_per_phase: Vec<Vec<Challenge>> = (0..num_phases)
        .map(|i| {
            let log_folded_height = log_max_height - i - 1;
            let g = F::two_adic_generator(log_folded_height + 1);
            let mut p = Vec::with_capacity(log_folded_height);
            let mut cur = g;
            for j in 0..log_folded_height {
                if j == 0 {
                    cur = g;
                } else {
                    cur = cur.square();
                }
                p.push(Challenge::from(cur));
            }
            p
        })
        .collect();

    verify_query_from_index_bits(
        &mut builder,
        initial_folded_eval_wire,
        &index_bits_targets,
        &betas_targets,
        &sibling_values_targets,
        &roll_ins_targets,
        &pows_per_phase,
        final_value_wire,
    );

    let circuit = builder.build().unwrap();

    // Verify two different proofs by cloning the circuit
    let mut runner1 = circuit.clone().runner();
    runner1.set_public_inputs(&pub_inputs1).unwrap();
    runner1.run().unwrap();

    let mut runner2 = circuit.runner();
    runner2.set_public_inputs(&pub_inputs2).unwrap();
    runner2.run().unwrap();
}
