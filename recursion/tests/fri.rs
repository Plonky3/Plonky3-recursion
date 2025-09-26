use p3_baby_bear::{BabyBear as F, Poseidon2BabyBear as Perm, default_babybear_poseidon2_16};
use p3_challenger::{
    CanObserve, CanSampleBits, DuplexChallenger as Challenger, FieldChallenger, GrindingChallenger,
};
use p3_commit::Pcs;
use p3_dft::Radix2DitParallel as Dft;
use p3_field::coset::TwoAdicMultiplicativeCoset;
use p3_field::extension::BinomialExtensionField as ExtF;
use p3_field::{Field, PrimeCharacteristicRing};
use p3_fri::{TwoAdicFriPcs, create_test_fri_params};
use p3_matrix::dense::RowMajorMatrix;
use p3_merkle_tree::MerkleTreeMmcs;
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

// Recursive target graph pieces
use p3_recursion::recursive_pcs::{
    FriProofTargets, InputProofTargets, RecExtensionValMmcs, RecValMmcs, Witness as RecWitness,
};
use p3_recursion::recursive_traits::Recursive;

type RecVal = RecValMmcs<F, 8, MyHash, MyCompress>;
type RecExt = RecExtensionValMmcs<F, Challenge, 8, RecVal>;

/// Bring the circuit we're testing.
use p3_recursion::circuit_fri_verifier::verify_fri_circuit;

type MatBatch = Vec<(
    TwoAdicMultiplicativeCoset<F>,
    Vec<(Challenge, Vec<Challenge>)>,
)>;

#[derive(Debug)]
struct ProduceInputsResult {
    fri_values: Vec<Challenge>, // fri_values ordered to match FriProofTargets::new
    alpha: Challenge,           // alpha
    betas: Vec<Challenge>,      // betas
    index_bits_per_query: Vec<Vec<Challenge>>, // index_bits per query (LE)
    challenge_points: Vec<Challenge>, // challenge_points z (per matrix)
    point_values: Vec<Vec<Challenge>>, // f(z) per matrix
    domains_log_sizes: Vec<usize>, // domains_log_sizes
    num_phases: usize,          // num_phases
    log_max_height: usize,      // log_max_height
    fri_lens: Vec<usize>,       // fri_lens (shape)
}

#[test]
fn test_circuit_fri_verifier() {
    // Common setup
    let perm = default_babybear_poseidon2_16();
    let hash = MyHash::new(perm.clone());
    let compress = MyCompress::new(perm.clone());
    let val_mmcs = ValMmcs::new(hash, compress);
    let challenge_mmcs = ChallengeMmcs::new(val_mmcs.clone());
    let dft = Dft::<F>::default();
    // final_poly_len = 0 (constant), log_blowup = 1 in test params
    let mut fri_params = create_test_fri_params(challenge_mmcs, 0);
    // Increase query rounds to 2 to ensure circuit handles multiple queries.
    fri_params.num_queries = 2;
    let log_blowup = fri_params.log_blowup;
    let log_final_poly_len = fri_params.log_final_poly_len;
    let pow_bits = fri_params.proof_of_work_bits;
    let pcs = PCS::new(dft, val_mmcs, fri_params);

    // Keep widths >= 1 with these sizes
    let polynomial_log_sizes = [5u8, 8, 8, 10];

    // Helper to produce *all* public inputs for a given seed, AND the FriProof lens.
    // We return:
    //  - fri_values: the public inputs that FriProofTargets::new created (commitments, openings,
    //                sibling values, final_poly coeffs, pow witness, etc.)
    //  - alpha, betas, index_bits, opened_values@x, challenge_points z, f(z) values,
    //  - domains_log_sizes, phase count, and log_max_height
    //  - fri_lens: the iterator materialized as a Vec<usize>, used to size FriProofTargets.
    let produce_inputs = |seed: u64| -> ProduceInputsResult {
        let mut rng = SmallRng::seed_from_u64(seed);

        // --- Prover path ---
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

        let num_mats = polynomial_log_sizes.len();
        let open_data = vec![(&prover_data, vec![vec![zeta]; num_mats])];
        let (opened_values_nested, fri_proof) =
            <PCS as Pcs<Challenge, MyChallenger>>::open(&pcs, open_data, &mut p_challenger);

        // --- Verifier transcript replay (to derive the public inputs) ---
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

        // Flatten into the shape we need: one batch of matrices at the same zeta
        let mats: MatBatch = domains
            .iter()
            .cloned()
            .zip(opened_values_nested.into_iter().flatten().flatten())
            .map(|(domain, value_vec)| (domain, vec![(zeta, value_vec)]))
            .collect();

        let p3_fri::FriProof {
            commit_phase_commits,
            ref query_proofs,
            final_poly,
            pow_witness,
        } = fri_proof;

        // Observe all openings f(z) into the challenger
        for (_domain, round) in &mats {
            for (_z, values) in round {
                for &opening in values {
                    v_challenger.observe_algebra_element(opening);
                }
            }
        }

        // α (batch combiner)
        let alpha: Challenge = v_challenger.sample_algebra_element();

        // β_i per phase: observe commitment, then sample β
        let mut betas: Vec<Challenge> = Vec::with_capacity(commit_phase_commits.len());
        for c in &commit_phase_commits {
            v_challenger.observe(*c);
            betas.push(v_challenger.sample_algebra_element());
        }

        // Final poly coeffs (constant here)
        for &c in &final_poly {
            v_challenger.observe_algebra_element(c);
        }

        // PoW check
        assert!(v_challenger.check_witness(pow_bits, pow_witness));

        // Query indices
        let num_phases = commit_phase_commits.len();
        let log_max_height = num_phases + log_blowup + log_final_poly_len;
        let num_queries = query_proofs.len();
        let mut indices: Vec<usize> = Vec::with_capacity(num_queries);
        for _ in 0..num_queries {
            indices.push(v_challenger.sample_bits(log_max_height));
        }

        // Index bits per query (LE)
        let mut index_bits_per_query: Vec<Vec<Challenge>> = Vec::with_capacity(num_queries);
        for &index in &indices {
            let mut bits_one = Vec::with_capacity(log_max_height);
            for k in 0..log_max_height {
                bits_one.push(if (index >> k) & 1 == 1 {
                    Challenge::ONE
                } else {
                    Challenge::ZERO
                });
            }
            index_bits_per_query.push(bits_one);
        }

        // Sibling values are embedded inside `fri_proof` targets; we won’t extract here.

        // challenge points (zeta per matrix) and f(z) per matrix
        let challenge_points: Vec<Challenge> = mats.iter().map(|(_d, v)| v[0].0).collect();
        let point_values: Vec<Vec<Challenge>> = mats.iter().map(|(_d, v)| v[0].1.clone()).collect();

        // domains_log_sizes (base domains)
        let domains_log_sizes: Vec<usize> =
            polynomial_log_sizes.iter().map(|&b| b as usize).collect();

        // —— FriProofTargets lens + values ——
        // Build lens for FriProofTargets from the *real* FriProof we just produced.
        type FriTargets = FriProofTargets<
            F,
            Challenge,
            RecExt,
            InputProofTargets<F, Challenge, RecVal>,
            RecWitness<F>,
        >;

        let fri_lens_vec: Vec<usize> = FriTargets::lens(&p3_fri::FriProof {
            commit_phase_commits: commit_phase_commits.clone(),
            query_proofs: query_proofs.clone(),
            final_poly: final_poly.clone(),
            pow_witness,
        })
        .collect();

        let fri_values: Vec<Challenge> = FriTargets::get_values(&p3_fri::FriProof {
            commit_phase_commits,
            query_proofs: query_proofs.clone(),
            final_poly,
            pow_witness,
        });

        ProduceInputsResult {
            fri_values,
            alpha,
            betas,
            index_bits_per_query,
            challenge_points,
            point_values,
            domains_log_sizes,
            num_phases,
            log_max_height,
            fri_lens: fri_lens_vec,
        }
    };

    // Produce two proofs with different seeds
    let result_1 = produce_inputs(0);
    let result_2 = produce_inputs(1);

    // Shape checks (must match so we can reuse one circuit)
    assert_eq!(result_1.num_phases, result_2.num_phases);
    assert_eq!(result_1.log_max_height, result_2.log_max_height);
    assert_eq!(result_1.domains_log_sizes, result_2.domains_log_sizes);
    assert_eq!(result_1.fri_lens, result_2.fri_lens);

    let num_phases = result_1.num_phases;
    let log_max_height = result_1.log_max_height;

    // ——— Build circuit once (using first proof's shape) ———
    let mut builder = p3_circuit::CircuitBuilder::<Challenge>::new();

    // 1) Allocate FriProofTargets using lens from instance 1
    type FriTargets = FriProofTargets<
        F,
        Challenge,
        RecExt,
        InputProofTargets<F, Challenge, RecVal>,
        RecWitness<F>,
    >;
    let mut lens_iter = result_1.fri_lens.clone().into_iter();
    let fri_targets = FriTargets::new(&mut builder, &mut lens_iter, /*degree_bits*/ 0);

    // 2) Public inputs for α, βs, index bits, opened_values@x, z points, f(z)
    let alpha_t = builder.add_public_input();
    let betas_t: Vec<_> = (0..num_phases)
        .map(|_| builder.add_public_input())
        .collect();

    let index_bits_t_per_query: Vec<Vec<_>> = (0..2)
        .map(|_| {
            (0..log_max_height)
                .map(|_| builder.add_public_input())
                .collect()
        })
        .collect();

    // Shapes per matrix for point_values (opened_values come from FriProofTargets now)
    let num_mats = result_1.domains_log_sizes.len();
    let mut fz_t: Vec<Vec<_>> = Vec::with_capacity(num_mats);
    let mut zetas_t: Vec<_> = Vec::with_capacity(num_mats);
    for m in 0..num_mats {
        zetas_t.push(builder.add_public_input());
        let cols_z = result_1.point_values[m].len();
        let mut pv = Vec::with_capacity(cols_z);
        for _ in 0..cols_z {
            pv.push(builder.add_public_input());
        }
        fz_t.push(pv);
    }

    // 3) Wire the actual in-circuit verifier
    verify_fri_circuit::<F, Challenge, RecExt, RecVal, RecWitness<F>>(
        &mut builder,
        &fri_targets,
        alpha_t,
        &betas_t,
        &index_bits_t_per_query,
        &zetas_t,
        &fz_t,
        &result_1.domains_log_sizes,
        log_blowup,
    );

    let circuit = builder.build().unwrap();

    // Helper to linearize public inputs in the exact order they were allocated above:
    let pack_inputs = |fri_vals: Vec<Challenge>,
                       alpha: Challenge,
                       betas: Vec<Challenge>,
                       index_bits_q0: Vec<Challenge>,
                       index_bits_q1: Vec<Challenge>,
                       zetas: Vec<Challenge>,
                       fz: Vec<Vec<Challenge>>|
     -> Vec<Challenge> {
        let mut v = Vec::new();

        // (1) FriProofTargets public inputs
        v.extend(fri_vals);

        // (2) alpha
        v.push(alpha);

        // (3) betas
        v.extend(betas);

        // (4) index bits per query (LE)
        v.extend(index_bits_q0);
        v.extend(index_bits_q1);

        // (5) per-matrix: z, f(z) columns (opened rows come from FriProofTargets)
        for m in 0..fz.len() {
            v.push(zetas[m]);
            v.extend(fz[m].iter().copied());
        }
        v
    };

    // ---- Run instance 1 ----
    let pub_inputs1 = pack_inputs(
        result_1.fri_values,
        result_1.alpha,
        result_1.betas,
        result_1.index_bits_per_query[0].clone(),
        result_1.index_bits_per_query[1].clone(),
        result_1.challenge_points,
        result_1.point_values,
    );
    let mut runner1 = circuit.clone().runner();
    runner1.set_public_inputs(&pub_inputs1).unwrap();
    runner1.run().unwrap();

    // ---- Run instance 2 ----
    let pub_inputs2 = pack_inputs(
        result_2.fri_values,
        result_2.alpha,
        result_2.betas,
        result_2.index_bits_per_query[0].clone(),
        result_2.index_bits_per_query[1].clone(),
        result_2.challenge_points,
        result_2.point_values,
    );
    let mut runner2 = circuit.runner();
    runner2.set_public_inputs(&pub_inputs2).unwrap();
    runner2.run().unwrap();
}
