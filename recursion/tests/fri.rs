use p3_baby_bear::{BabyBear as F, Poseidon2BabyBear as Perm, default_babybear_poseidon2_16};
use p3_challenger::{CanObserve, CanSampleBits, DuplexChallenger as Challenger, FieldChallenger};
use p3_commit::Pcs;
use p3_dft::Radix2DitParallel as Dft;
use p3_field::coset::TwoAdicMultiplicativeCoset;
use p3_field::extension::BinomialExtensionField as ExtF;
use p3_field::{Field, PrimeCharacteristicRing, TwoAdicField};
use p3_fri::{TwoAdicFriPcs, create_test_fri_params};
use p3_matrix::dense::RowMajorMatrix;
use p3_merkle_tree::MerkleTreeMmcs;
use p3_recursion::circuit_fri_verifier::{FoldPhaseInputs, verify_fri_arithmetic_circuit};
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
fn test_circuit_fri_arithmetic_core_with_real_proof() {
    // Build real FRI commitment and opening, then feed arithmetic-only values into circuit.
    let mut rng = SmallRng::seed_from_u64(42);

    // Permutation/hash/MMCS/PCS setup
    let perm = default_babybear_poseidon2_16();
    let hash = MyHash::new(perm.clone());
    let compress = MyCompress::new(perm.clone());
    let val_mmcs = ValMmcs::new(hash, compress);
    let challenge_mmcs = ChallengeMmcs::new(val_mmcs.clone());
    let dft = Dft::<F>::default();

    // Use constant final polynomial (log_final_poly_len = 0)
    let fri_params = create_test_fri_params(challenge_mmcs, 0);
    let log_blowup = fri_params.log_blowup;
    let log_final_poly_len = fri_params.log_final_poly_len;
    let pcs = PCS::new(dft, val_mmcs, fri_params);

    // Chosen to ensure there are both multiple polynomials of the same size
    let polynomial_log_sizes = [5u8, 8, 8, 10];

    // Prover: set up challenger and sample zeta
    let mut p_challenger = MyChallenger::new(perm.clone());
    let val_sizes: Vec<F> = polynomial_log_sizes
        .iter()
        .map(|&b| F::from_u8(b))
        .collect();
    p_challenger.observe_slice(&val_sizes);

    // Build evaluation matrices for each polynomial log-size
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

    // Commit
    let (commitment, prover_data) = <PCS as Pcs<Challenge, MyChallenger>>::commit(&pcs, evals);
    p_challenger.observe(commitment);

    // Sample opening point and open
    let zeta: Challenge = p_challenger.sample_algebra_element();
    let num_evaluations = polynomial_log_sizes.len();
    let open_data = vec![(&prover_data, vec![vec![zeta]; num_evaluations])];
    let (opened_values, fri_proof) =
        <PCS as Pcs<Challenge, MyChallenger>>::open(&pcs, open_data, &mut p_challenger);

    // Verifier-like view: construct domains and zipped openings for reduction
    let mut v_challenger = MyChallenger::new(perm.clone());
    v_challenger.observe_slice(&val_sizes);
    v_challenger.observe(commitment);
    let zeta_v: Challenge = v_challenger.sample_algebra_element();
    assert_eq!(zeta, zeta_v);

    let domains: Vec<TwoAdicMultiplicativeCoset<F>> = polynomial_log_sizes
        .iter()
        .map(|&size| {
            <PCS as Pcs<Challenge, MyChallenger>>::natural_domain_for_degree(&pcs, 1 << size)
        })
        .collect();

    // Flatten to (domain, value_at_zeta) pairs for reduction use
    let mats: MatBatch = domains
        .into_iter()
        .zip(opened_values.into_iter().flatten().flatten())
        .map(|(domain, value_vec)| (domain, vec![(zeta, value_vec)]))
        .collect();

    // Extract FRI proof components (we won’t use final_poly/pow_witness here)
    let p3_fri::FriProof {
        commit_phase_commits,
        query_proofs,
        final_poly: _,
        pow_witness: _,
    } = fri_proof;

    // PCS verifier step: observe all opened evaluations before sampling alpha
    for (_, mats) in &mats {
        for (_point, values) in mats {
            for &opening in values {
                v_challenger.observe_algebra_element(opening);
            }
        }
    }

    // Sample alpha (batch combination challenge)
    let alpha: Challenge = v_challenger.sample_algebra_element();

    // Use the first query round for arithmetic-only testing.

    // Derive betas exactly like verifier: observe each commit, then sample beta
    let mut betas = Vec::with_capacity(commit_phase_commits.len());
    for c in &commit_phase_commits {
        v_challenger.observe(*c);
        betas.push(v_challenger.sample_algebra_element());
    }

    // Compute heights
    let log_max_height = commit_phase_commits.len() + log_blowup + log_final_poly_len;

    // Process first query only (arithmetic is identical per query)
    let query = &query_proofs[0];

    // Sample query index like verifier
    let index = v_challenger.sample_bits(log_max_height);

    // Build reduced openings map from the input proof (same math as verifier)
    use std::collections::BTreeMap;
    // Map: log_height -> (alpha_pow, ro)
    let mut ro_map: BTreeMap<usize, (Challenge, Challenge)> = BTreeMap::new(); // ascending by height

    // Only one batch opening in this test
    let batch_opening = &query.input_proof[0];
    for (mat_opening, (mat_domain, mat_points_and_values)) in
        batch_opening.opened_values.iter().zip(mats.iter())
    {
        let log_height = (mat_domain.size() << log_blowup).ilog2() as usize;
        // Reconstruct x = g * h^rev_reduced_index where rev_reduced_index = reverse_bits_len(index >> bits_reduced, log_height)
        let bits_reduced = log_max_height - log_height;
        let rev_reduced_index = p3_util::reverse_bits_len(index >> bits_reduced, log_height);
        let x = F::GENERATOR * F::two_adic_generator(log_height).exp_u64(rev_reduced_index as u64);

        let (mut alpha_pow, mut ro) = ro_map
            .remove(&log_height)
            .unwrap_or((Challenge::ONE, Challenge::ZERO));

        for (z, ps_at_z) in mat_points_and_values.iter() {
            let quotient = (*z - Challenge::from(x)).inverse();
            for (&p_at_x, &p_at_z) in mat_opening.iter().zip(ps_at_z.iter()) {
                ro += alpha_pow * (p_at_z - p_at_x) * quotient;
                alpha_pow *= alpha;
            }
        }

        ro_map.insert(log_height, (alpha_pow, ro));
    }

    // Convert to descending heights vector and a lookup map by height
    let mut ro_desc: Vec<(usize, Challenge)> =
        ro_map.iter().map(|(k, (_apow, ro))| (*k, *ro)).collect();
    ro_desc.sort_by_key(|(h, _)| core::cmp::Reverse(*h));
    assert!(!ro_desc.is_empty());
    let ro_by_height: std::collections::HashMap<usize, Challenge> =
        ro_desc.iter().cloned().collect();

    // Build per-phase inputs (x0, e_sibling, sibling_is_right)
    let mut phases_data: Vec<(usize, Challenge, Challenge, u64)> = Vec::new(); // (height, x0, e_sibling, is_right)
    let mut domain_index = index;
    for (phase_idx, opening) in query.commit_phase_openings.iter().enumerate() {
        let log_folded_height = log_max_height - phase_idx - 1;
        // Determine sibling position before shifting to parent
        let index_sibling = domain_index ^ 1;
        let is_right = (index_sibling % 2) as u64;

        // Update to parent index for next round
        domain_index >>= 1;

        // Compute x0 at this phase (arity=2): x0 = generator^(rev_bits) with generator at height+1
        let rev_bits = p3_util::reverse_bits_len(domain_index, log_folded_height);
        let generator = F::two_adic_generator(log_folded_height + 1);
        let subgroup_start = generator.exp_u64(rev_bits as u64);
        let x0 = subgroup_start; // x1 = -x0

        phases_data.push((
            log_folded_height,
            Challenge::from(x0),
            opening.sibling_value,
            is_right,
        ));
    }

    // Prepare circuit with constants for all arithmetic inputs (no publics)
    let mut builder = p3_circuit::CircuitBuilder::<Challenge>::new();

    // Initial folded_eval from reduced openings at max height
    let initial_folded_eval_wire = builder.add_const(ro_desc[0].1);

    // For each phase: add wires for beta, x0, e_sibling, sibling_is_right; include roll-in if ro exists at this height
    let mut phase_wires: Vec<FoldPhaseInputs> = Vec::with_capacity(phases_data.len());
    for (i, (height, x0, e_sibling, is_right)) in phases_data.iter().cloned().enumerate() {
        let beta_wire = builder.add_const(betas[i]);
        let x0_wire = builder.add_const(x0);
        let e_sibling_wire = builder.add_const(e_sibling);
        let is_right_wire = builder.add_const(Challenge::from(F::from_u64(is_right)));
        let roll_in_wire = ro_by_height
            .get(&height)
            .copied()
            .map(|v| builder.add_const(v));

        phase_wires.push(FoldPhaseInputs {
            beta: beta_wire,
            x0: x0_wire,
            e_sibling: e_sibling_wire,
            sibling_is_right: is_right_wire,
            roll_in: roll_in_wire,
        });
    }

    // Compute expected folded value off-circuit to supply as the final check value.
    let mut folded_expected = ro_desc[0].1;
    let neg_one = Challenge::from(F::NEG_ONE);
    for (i, (height, x0, e_sibling, is_right)) in phases_data.iter().cloned().enumerate() {
        let x1 = neg_one * x0;
        let is_right_ch = Challenge::from(F::from_u64(is_right));
        let one = Challenge::ONE;
        let one_minus = one - is_right_ch;
        let e0 = one_minus * e_sibling + is_right_ch * folded_expected;
        let e1 = one_minus * folded_expected + is_right_ch * e_sibling;
        let beta = betas[i];
        let intermediate = (beta - x0) * (e1 - e0) * (x1 - x0).inverse();
        folded_expected = e0 + intermediate;
        if let Some(ro) = ro_by_height.get(&height) {
            folded_expected += beta.square() * *ro;
        }
    }
    let final_value_wire = builder.add_const(folded_expected);

    // Build arithmetic-only FRI check in-circuit
    verify_fri_arithmetic_circuit(
        &mut builder,
        initial_folded_eval_wire,
        &phase_wires,
        final_value_wire,
    );

    // Execute circuit (no public inputs)
    let circuit = builder.build().unwrap();
    let runner = circuit.runner();
    runner.run().unwrap();
}
