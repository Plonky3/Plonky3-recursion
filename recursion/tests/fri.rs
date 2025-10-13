use p3_baby_bear::{BabyBear as F, Poseidon2BabyBear as Perm, default_babybear_poseidon2_16};
use p3_challenger::{
    CanObserve, CanSampleBits, DuplexChallenger as Challenger, FieldChallenger, GrindingChallenger,
};
use p3_circuit::CircuitBuilder;
use p3_commit::Pcs;
use p3_dft::Radix2DitParallel as Dft;
use p3_field::coset::TwoAdicMultiplicativeCoset;
use p3_field::extension::BinomialExtensionField as ExtF;
use p3_field::{Field, PrimeCharacteristicRing};
use p3_fri::{TwoAdicFriPcs, create_test_fri_params};
use p3_matrix::dense::RowMajorMatrix;
use p3_merkle_tree::MerkleTreeMmcs;
use p3_recursion::public_inputs::{CommitmentOpening, FriVerifierInputs};
use p3_symmetric::{PaddingFreeSponge, TruncatedPermutation};
use rand::SeedableRng;
use rand::rngs::SmallRng;
use tracing_forest::ForestLayer;
use tracing_forest::util::LevelFilter;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{EnvFilter, Registry};

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

// Bring the circuit we're testing.
use p3_recursion::circuit_fri_verifier::verify_fri_circuit;

/// Alias for FriProofTargets used for lens/value extraction and allocation
type FriTargets =
    FriProofTargets<F, Challenge, RecExt, InputProofTargets<F, Challenge, RecVal>, RecWitness<F>>;

/// Type alias for commitments with opening points structure
type CommitmentsWithPoints = Vec<(
    Challenge,
    Vec<(
        TwoAdicMultiplicativeCoset<F>,
        Vec<(Challenge, Vec<Challenge>)>,
    )>,
)>;

fn init_logger() {
    let env_filter = EnvFilter::builder()
        .with_default_directive(LevelFilter::INFO.into())
        .from_env_lossy();

    Registry::default()
        .with(env_filter)
        .with(ForestLayer::default())
        .init();
}

/// Helper: build one group's evaluation matrices for a given seed and sizes.
fn make_evals(
    polynomial_log_sizes: &[u8],
    seed: u64,
) -> Vec<(TwoAdicMultiplicativeCoset<F>, RowMajorMatrix<F>)> {
    let mut rng = SmallRng::seed_from_u64(seed);
    polynomial_log_sizes
        .iter()
        .map(|&deg_bits| {
            let rows = 1usize << deg_bits;
            let domain = TwoAdicMultiplicativeCoset::new(F::GENERATOR, deg_bits as usize)
                .expect("valid two-adic size");

            // Ensure width >= 1 to avoid zero-width matrices for small degrees.
            let width = core::cmp::max(1, (deg_bits as usize).saturating_sub(4));

            (
                domain,
                RowMajorMatrix::<F>::rand_nonzero(&mut rng, rows, width),
            )
        })
        .collect()
}

/// Holds all the public inputs and challenges required for a recursive FRI verification circuit.
#[derive(Debug)]
struct ProduceInputsResult {
    /// FRI values, ordered to match the structure required by `FriProofTargets`.
    fri_values: Vec<Challenge>,
    /// The `alpha` challenge used for batching polynomial commitments.
    alpha: Challenge,
    /// The `beta` challenges, one for each FRI folding phase.
    betas: Vec<Challenge>,
    /// The query indices, represented as little-endian bits, for each query.
    index_bits_per_query: Vec<Vec<Challenge>>,
    /// Commitments with opening points structure (per batch)
    commitments_with_points: CommitmentsWithPoints,
    /// The total number of FRI folding phases (rounds).
    num_phases: usize,
    /// The log base 2 of the size of the largest domain.
    log_max_height: usize,
    /// The shape of the FRI values, indicating the number of values per proof component.
    fri_lens: Vec<usize>,
}

/// Produce all public inputs for a recursive FRI verification circuit over **multiple input batches**.
///
/// `group_sizes` is a list of groups, each group is a list of log2 degrees.
fn produce_inputs_multi(
    pcs: &PCS,
    perm: &Perm<16>,
    log_blowup: usize,
    log_final_poly_len: usize,
    pow_bits: usize,
    group_sizes: &[Vec<u8>],
    seed_base: u64,
) -> ProduceInputsResult {
    // Build per-group evals and commit
    let mut groups_evals = Vec::new();
    for (i, sizes) in group_sizes.iter().enumerate() {
        groups_evals.push(make_evals(sizes, seed_base + i as u64));
    }

    // Flatten domain sizes (base log sizes) for public inputs
    let mut domains_log_sizes = Vec::new();
    for sizes in group_sizes {
        domains_log_sizes.extend(sizes.iter().map(|&b| b as usize));
    }
    let val_sizes: Vec<F> = domains_log_sizes
        .iter()
        .map(|&b| F::from_u8(b as u8))
        .collect();

    // --- Prover path ---
    let mut p_challenger = MyChallenger::new(perm.clone());
    p_challenger.observe_slice(&val_sizes);

    // Commit each group and observe all commitments before sampling zeta
    let mut commitments_and_data = Vec::new();
    for evals in &groups_evals {
        let (commitment, prover_data) =
            <PCS as Pcs<Challenge, MyChallenger>>::commit(pcs, evals.clone());
        p_challenger.observe(commitment);
        commitments_and_data.push((commitment, prover_data));
    }

    // Single zeta for all matrices across all groups
    let zeta: Challenge = p_challenger.sample_algebra_element();

    // Build open request: one (&ProverData, points_per_matrix) per group
    let mut open_data = Vec::new();
    for (i, _evals) in groups_evals.iter().enumerate() {
        let mat_count = groups_evals[i].len();
        open_data.push((&commitments_and_data[i].1, vec![vec![zeta]; mat_count]));
    }

    // Open and produce FRI proof
    let (opened_values, fri_proof) =
        <PCS as Pcs<Challenge, MyChallenger>>::open(pcs, open_data, &mut p_challenger);

    // --- Verifier transcript replay (to derive the public inputs) ---
    let mut v_challenger = MyChallenger::new(perm.clone());
    v_challenger.observe_slice(&val_sizes);
    for (commitment, _) in &commitments_and_data {
        v_challenger.observe(*commitment);
    }
    let _zeta_v: Challenge = v_challenger.sample_algebra_element();

    // Flatten opened values in the same order we passed to `open`
    // Shape: OpenedValues -> groups -> matrices -> columns
    let point_values_flat: Vec<Vec<Challenge>> =
        opened_values.into_iter().flatten().flatten().collect();

    // Extract proof pieces
    let p3_fri::FriProof {
        commit_phase_commits,
        ref query_proofs,
        final_poly,
        pow_witness,
    } = fri_proof;

    // Observe all opened evaluation values (same order)
    for values in &point_values_flat {
        for &opening in values {
            v_challenger.observe_algebra_element(opening);
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

    // Build commitments_with_points structure
    // For each batch: (commitment_placeholder, Vec<(domain, Vec<(z, [f(z)])>)>)
    let mut commitments_with_points = Vec::new();
    let mut pv_idx = 0;
    for sizes in group_sizes.iter() {
        let mut mats_data = Vec::new();
        for &log_size in sizes {
            let domain = TwoAdicMultiplicativeCoset::new(F::GENERATOR, log_size as usize)
                .expect("valid domain");
            let points_and_values = vec![(zeta, point_values_flat[pv_idx].clone())];
            mats_data.push((domain, points_and_values));
            pv_idx += 1;
        }
        // Use a placeholder value for the commitment (not used in arithmetic verification)
        let commit_placeholder = Challenge::ZERO;
        commitments_with_points.push((commit_placeholder, mats_data));
    }

    // —— FriProofTargets lens + values ——
    let fri_lens: Vec<usize> = FriTargets::lens(&p3_fri::FriProof {
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
        commitments_with_points,
        num_phases,
        log_max_height,
        fri_lens,
    }
}

/// Linearize public inputs in the exact order allocated by the circuit builder.
fn pack_inputs(
    fri_vals: Vec<Challenge>,
    alpha: Challenge,
    betas: Vec<Challenge>,
    index_bits_all_queries: Vec<Vec<Challenge>>,
    commitments_with_points: CommitmentsWithPoints,
) -> Vec<Challenge> {
    let commitment_openings = commitments_with_points
        .into_iter()
        .map(|(commitment, mats)| {
            let mut opened_points = Vec::new();
            for (_domain, points_and_values) in mats {
                for (z, fz) in points_and_values {
                    opened_points.push((z, fz));
                }
            }
            CommitmentOpening {
                commitment,
                opened_points,
            }
        })
        .collect();

    FriVerifierInputs {
        fri_proof_values: fri_vals,
        alpha,
        betas,
        query_index_bits: index_bits_all_queries,
        commitment_openings,
    }
    .build()
}

/// Holds all the FRI parameters and group sizes to generate test inputs.
struct FriSetup {
    pcs: PCS,
    perm: Perm<16>,
    log_blowup: usize,
    log_final_poly_len: usize,
    pow_bits: usize,
    group_sizes: Vec<Vec<u8>>,
}

impl FriSetup {
    fn new(
        pcs: PCS,
        perm: Perm<16>,
        log_blowup: usize,
        log_final_poly_len: usize,
        pow_bits: usize,
        group_sizes: Vec<Vec<u8>>,
    ) -> Self {
        Self {
            pcs,
            perm,
            log_blowup,
            log_final_poly_len,
            pow_bits,
            group_sizes,
        }
    }
}

fn generate_setup(log_final_poly_len: usize, group_sizes: Vec<Vec<u8>>) -> FriSetup {
    // Common setup
    let perm = default_babybear_poseidon2_16();
    let hash = MyHash::new(perm.clone());
    let compress = MyCompress::new(perm.clone());
    let val_mmcs = ValMmcs::new(hash, compress);
    let challenge_mmcs = ChallengeMmcs::new(val_mmcs.clone());
    let dft = Dft::<F>::default();

    let fri_params = create_test_fri_params(challenge_mmcs, log_final_poly_len);
    let log_blowup = fri_params.log_blowup;
    let log_final_poly_len = fri_params.log_final_poly_len;
    let pow_bits = fri_params.proof_of_work_bits;
    let pcs = PCS::new(dft, val_mmcs, fri_params);

    FriSetup::new(
        pcs,
        perm,
        log_blowup,
        log_final_poly_len,
        pow_bits,
        group_sizes,
    )
}

fn run_fri_test(setup: FriSetup, build_only: bool) {
    let FriSetup {
        pcs,
        perm,
        log_blowup,
        log_final_poly_len,
        pow_bits,
        group_sizes,
    } = setup;

    // Produce two proofs with different inputs (same shape), to reuse one circuit
    let result_1 = produce_inputs_multi(
        &pcs,
        &perm,
        log_blowup,
        log_final_poly_len,
        pow_bits,
        &group_sizes,
        /*seed_base=*/ 0,
    );

    let result_2 = produce_inputs_multi(
        &pcs,
        &perm,
        log_blowup,
        log_final_poly_len,
        pow_bits,
        &group_sizes,
        /*seed_base=*/ 1,
    );

    // Shape checks (must match so we can reuse one circuit)
    assert_eq!(result_1.num_phases, result_2.num_phases);
    assert_eq!(result_1.log_max_height, result_2.log_max_height);
    assert_eq!(result_1.fri_lens, result_2.fri_lens);

    let num_phases = result_1.num_phases;
    let log_max_height = result_1.log_max_height;
    let expected_final_poly_len = 1 << log_final_poly_len;

    // ——— Build circuit once (using first proof's shape) ———
    let mut builder = CircuitBuilder::<Challenge>::new();

    // 1) Allocate FriProofTargets using lens from instance 1
    let mut lens_iter = result_1.fri_lens.clone().into_iter();
    let fri_targets = FriTargets::new(&mut builder, &mut lens_iter, /*degree_bits unused*/ 0);

    // Verify the final polynomial has the expected length
    assert_eq!(
        fri_targets.final_poly.len(),
        expected_final_poly_len,
        "Circuit final polynomial should have {} coefficients",
        expected_final_poly_len
    );

    // 2) Public inputs for α, βs, index bits
    let alpha_t = builder.add_public_input();
    let betas_t: Vec<_> = (0..num_phases)
        .map(|_| builder.add_public_input())
        .collect();

    let num_queries = result_1.index_bits_per_query.len();
    let index_bits_t_per_query: Vec<Vec<_>> = (0..num_queries)
        .map(|_| {
            (0..log_max_height)
                .map(|_| builder.add_public_input())
                .collect()
        })
        .collect();

    builder.push_scope("commitments_with_opening_points");

    // 3) Build commitments_with_opening_points targets structure
    // For each batch: allocate commitment target + (domain, Vec<(z_target, [fz_targets])>)
    let mut commitments_with_opening_points_targets = Vec::new();
    for (_commit_val, mats_data) in &result_1.commitments_with_points {
        // Allocate commitment target (placeholder, not used in arithmetic verification)
        let commit_t = builder.add_public_input();

        let mut mats_targets = Vec::new();
        for (domain, points_and_values) in mats_data {
            let mut pv_targets = Vec::new();
            for (_z, fz) in points_and_values {
                let z_t = builder.add_public_input();
                let fz_t: Vec<_> = (0..fz.len()).map(|_| builder.add_public_input()).collect();
                pv_targets.push((z_t, fz_t));
            }
            mats_targets.push((*domain, pv_targets));
        }
        commitments_with_opening_points_targets.push((commit_t, mats_targets));
    }
    builder.pop_scope();

    // 4) Wire the arithmetic-only FRI verifier
    let verif_res =
        verify_fri_circuit::<F, Challenge, RecExt, RecVal, RecWitness<F>, p3_recursion::Target>(
            &mut builder,
            &fri_targets,
            alpha_t,
            &betas_t,
            &index_bits_t_per_query,
            &commitments_with_opening_points_targets,
            log_blowup,
        );

    assert!(
        verif_res.is_ok(),
        "FRI verification failed: {:?}",
        verif_res
    );

    builder.dump_allocation_log();
    let circuit = builder.build().unwrap();

    if build_only {
        return;
    }

    // ---- Run instance 1 ----
    let pub_inputs1 = pack_inputs(
        result_1.fri_values,
        result_1.alpha,
        result_1.betas,
        result_1.index_bits_per_query.clone(),
        result_1.commitments_with_points,
    );
    let mut runner1 = circuit.clone().runner();
    runner1.set_public_inputs(&pub_inputs1).unwrap();
    runner1.run().unwrap();

    // ---- Run instance 2 ----
    let pub_inputs2 = pack_inputs(
        result_2.fri_values,
        result_2.alpha,
        result_2.betas,
        result_2.index_bits_per_query.clone(),
        result_2.commitments_with_points,
    );
    let mut runner2 = circuit.runner();
    runner2.set_public_inputs(&pub_inputs2).unwrap();
    runner2.run().unwrap();
}

#[test]
fn test_circuit_fri_verifier_degree_0_final_poly() {
    // Three "rounds"/batches of inputs, different shapes. Include a degree-0 (height=1)
    // matrix so the `log_height == log_blowup` reduced-opening constraint is exercised.
    //   [0, 5, 8, 8, 10], [8, 11], [4, 5, 8]
    let groups = vec![vec![0u8, 5, 8, 8, 10], vec![8u8, 11], vec![4u8, 5, 8]];

    let setup = generate_setup(0, groups);

    run_fri_test(setup, false);
}

#[test]
fn test_circuit_fri_verifier_degree_1_final_poly() {
    // Use smaller matrices to ensure we actually get a higher-degree final polynomial
    // For a final polynomial of degree 1, we need `log_max_height` small enough
    let groups = vec![vec![3u8, 4], vec![5u8]];

    let setup = generate_setup(1, groups);

    run_fri_test(setup, false);
}

#[test]
fn test_circuit_fri_verifier_degree_3_final_poly() {
    // Small matrices to get higher-degree final polynomial
    let groups = vec![vec![4u8], vec![5u8]];

    let setup = generate_setup(2, groups);

    run_fri_test(setup, false);
}

#[test]
fn test_circuit_fri_verifier_scoped_builder() {
    init_logger();

    let groups = vec![vec![0u8, 5, 8, 8, 10], vec![8u8, 11], vec![4u8, 5, 8]];
    let setup = generate_setup(0, groups);
    run_fri_test(setup, true);
}
