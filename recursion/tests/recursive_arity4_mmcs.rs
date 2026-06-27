//! Integration tests: build a circuit that re-verifies an opening proof produced by the
//! **native arity-4 MMCS** through [`verify_batch_circuit_arity4`] /
//! [`verify_batch_circuit_from_extension_opened_arity4`].
//!
//! Uses `KOALA_BEAR_D4_W32` (the canonical arity-4 KoalaBear shape: D=4, width 32,
//! `capacity_ext = 2` EF limbs, `rate_ext = 6` EF limbs). One wide perm drives both the
//! leaf sponge and the 4-to-1 compression on both sides, so digests agree.
//!
//! Coverage:
//!   - single-height round-trip over indices whose level-0 `pos = b0 + 2·b1` covers all four
//!     quaternary positions `{0,1,2,3}` plus deeper indices;
//!   - a mixed-height round-trip that forces step-2 bridge levels and injection levels;
//!   - an extension-opened mixed-height round-trip through
//!     `verify_batch_circuit_from_extension_opened_arity4`;
//!   - a negative test: tampering the sibling of a step-2 bridge level makes the recovered
//!     root diverge from the native cap, surfacing a witness conflict at the root `connect`.

use p3_circuit::CircuitBuilder;
use p3_circuit::ops::{
    Poseidon2Config, generate_poseidon2_trace, generate_recompose_trace, perm_private_data,
};
use p3_commit::{BatchOpeningRef, ExtensionMmcs, Mmcs};
use p3_field::extension::BinomialExtensionField;
use p3_field::{BasedVectorSpace, PrimeCharacteristicRing};
use p3_koala_bear::{KoalaBear, Poseidon2KoalaBear, default_koalabear_poseidon2_32};
use p3_matrix::Matrix;
use p3_matrix::dense::RowMajorMatrix;
use p3_merkle_tree::MerkleTreeMmcs;
use p3_poseidon2_circuit_air::KoalaBearD4Width32;
use p3_recursion::Target;
use p3_recursion::pcs::{
    verify_batch_circuit_arity4, verify_batch_circuit_from_extension_opened_arity4,
};
use p3_symmetric::{PaddingFreeSponge, TruncatedPermutation};

type F = KoalaBear;
type CF = BinomialExtensionField<F, 4>;

// One wide perm drives both the native leaf sponge and the 4-to-1 compression; the
// in-circuit executor enables the same perm so digests agree on both sides.
type Perm32 = Poseidon2KoalaBear<32>;
type LeafHash = PaddingFreeSponge<Perm32, 32, 24, 8>;
type Compress4 = TruncatedPermutation<Perm32, 4, 8, 32>;
type Mmcs4 = MerkleTreeMmcs<F, F, LeafHash, Compress4, 4, 8>;
type ExtMmcs4 = ExtensionMmcs<F, CF, Mmcs4>;

/// Pack `D` lifted-base extension targets into one packed extension target via `Σ t_i · X^i`.
fn pack_lifted_targets(builder: &mut CircuitBuilder<CF>, lifted: &[Target]) -> Vec<Target> {
    if lifted.is_empty() {
        return Vec::new();
    }
    let d = <CF as BasedVectorSpace<F>>::DIMENSION;
    let basis: Vec<CF> = (0..d)
        .map(|i| {
            let mut coeffs = vec![F::ZERO; d];
            coeffs[i] = F::ONE;
            CF::from_basis_coefficients_slice(&coeffs).expect("valid basis")
        })
        .collect();

    lifted
        .chunks(d)
        .map(|chunk| {
            let mut acc = builder.define_const(CF::ZERO);
            for (i, &target) in chunk.iter().enumerate() {
                let basis_const = builder.define_const(basis[i]);
                acc = builder.mul_add(target, basis_const, acc);
            }
            acc
        })
        .collect()
}

/// Pack a base-field digest into `capacity_ext` packed-EF limbs (each `D` base elements becomes
/// one `EF`). Mirrors the native digest layout the W32 compression consumes.
fn pack_digest(digest: &[F]) -> Vec<CF> {
    let d = <CF as BasedVectorSpace<F>>::DIMENSION;
    digest
        .chunks(d)
        .map(|chunk| {
            let mut coeffs = vec![F::ZERO; d];
            coeffs[..chunk.len()].copy_from_slice(chunk);
            CF::from_basis_coefficients_slice(&coeffs).expect("digest packs into EF")
        })
        .collect()
}

/// Attach the sibling private data for every compression op, grouping consecutive equal op-ids
/// (3× for a step-4 level, 1× for a step-2 bridge) and padding short groups with zero limbs up to
/// `3 · capacity_ext`. `opening_proof` is consumed in order, 1 sibling per op-id occurrence.
fn set_sibling_private_data(
    runner: &mut p3_circuit::CircuitRunner<'_, CF>,
    op_ids: &[p3_circuit::NonPrimitiveOpId],
    opening_proof: &[[F; 8]],
    permutation_config: Poseidon2Config,
) {
    let capacity_ext = permutation_config.capacity_ext();
    let mut proof_idx = 0usize;
    let mut op_idx = 0usize;
    while op_idx < op_ids.len() {
        let op_id = op_ids[op_idx];
        let mut flat = Vec::new();
        let mut siblings_for_op = 0usize;
        while op_idx < op_ids.len() && op_ids[op_idx] == op_id {
            flat.extend(pack_digest(&opening_proof[proof_idx]));
            proof_idx += 1;
            op_idx += 1;
            siblings_for_op += 1;
        }
        for _ in siblings_for_op..3 {
            flat.extend(vec![CF::ZERO; capacity_ext]);
        }
        runner
            .set_private_data(op_id, perm_private_data(permutation_config, flat))
            .expect("set private data");
    }
    assert_eq!(
        proof_idx,
        opening_proof.len(),
        "every opening-proof sibling must map to an op-id occurrence"
    );
}

#[test]
fn recursive_arity4_mmcs_round_trip_single_height() {
    let perm = default_koalabear_poseidon2_32();
    let leaf_hash = LeafHash::new(perm.clone());
    let compress = Compress4::new(perm.clone());
    let mmcs = Mmcs4::new(leaf_hash, compress, 0);

    // Height 1024 = 4^5 gives five full step-4 compression levels; width 4 keeps the leaf in a
    // single absorb chunk (the arity-4 leaf seeds the merkle chain from one row).
    let height: usize = 1024;
    let width: usize = 4;
    let values: Vec<F> = (0..(height * width) as u64).map(F::from_u64).collect();
    let matrix = RowMajorMatrix::new(values, width);
    let dimensions = vec![matrix.dimensions()];
    let (commit, prover_data) = mmcs.commit(vec![matrix]);

    let log_max_height: usize = 10;
    for index in [0, 1, 2, 3, 5, height - 1] {
        let mut builder = CircuitBuilder::<CF>::new();
        let permutation_config = Poseidon2Config::KOALA_BEAR_D4_W32;
        let capacity_ext = permutation_config.capacity_ext();

        builder.enable_poseidon2_perm_width_32::<KoalaBearD4Width32, _>(
            generate_poseidon2_trace::<CF, KoalaBearD4Width32>,
            perm.clone(),
        );
        builder.enable_recompose::<F>(generate_recompose_trace::<F, CF>);

        let batch_opening = mmcs.open_batch(index, &prover_data);

        let lifted_opened: Vec<Target> = (0..width).map(|_| builder.public_input()).collect();
        let directions_expr = builder.alloc_public_inputs(log_max_height, "arity4 directions");
        let lifted_cap: Vec<Target> = (0..(capacity_ext * <CF as BasedVectorSpace<F>>::DIMENSION))
            .map(|_| builder.public_input())
            .collect();
        let cap_exprs: Vec<Vec<Target>> = vec![pack_lifted_targets(&mut builder, &lifted_cap)];

        let mmcs_op_ids = verify_batch_circuit_arity4::<F, CF>(
            &mut builder,
            permutation_config,
            &cap_exprs,
            &dimensions,
            &directions_expr,
            std::slice::from_ref(&lifted_opened),
        )
        .expect("verify_batch_circuit_arity4 should succeed");
        assert_eq!(mmcs_op_ids.len(), batch_opening.opening_proof.len());

        let circuit = builder.build().expect("circuit build");
        let mut runner = circuit.runner();

        let mut public_inputs: Vec<CF> = batch_opening
            .opened_values
            .iter()
            .flat_map(|row| row.iter().map(|&v| CF::from(v)))
            .collect();
        public_inputs.extend((0..log_max_height).map(|k| CF::from_bool((index >> k) & 1 == 1)));
        public_inputs.extend(commit.roots()[0].iter().map(|&v| CF::from(v)));
        runner
            .set_public_inputs(&public_inputs)
            .expect("set public inputs");

        set_sibling_private_data(
            &mut runner,
            &mmcs_op_ids,
            &batch_opening.opening_proof,
            permutation_config,
        );

        runner
            .run()
            .unwrap_or_else(|err| panic!("runner failed at index {index}: {err:?}"));
    }
}

#[test]
fn recursive_arity4_mmcs_round_trip_wide_leaf_multi_chunk() {
    let perm = default_koalabear_poseidon2_32();
    let leaf_hash = LeafHash::new(perm.clone());
    let compress = Compress4::new(perm.clone());
    let mmcs = Mmcs4::new(leaf_hash, compress, 0);

    // A leaf row wider than the W32 rate (rate_ext = 6 EF limbs = 24 base elements) forces a
    // multi-chunk leaf sponge: 40 base coeffs span two absorb chunks. The absorbs run in normal
    // mode and the final row seeds the Merkle chain, so the recovered root still matches native.
    let height: usize = 1024;
    let width: usize = 40;
    let values: Vec<F> = (0..(height * width) as u64).map(F::from_u64).collect();
    let matrix = RowMajorMatrix::new(values, width);
    let dimensions = vec![matrix.dimensions()];
    let (commit, prover_data) = mmcs.commit(vec![matrix]);

    let log_max_height: usize = 10;
    for index in [0, 1, 2, 3, 5, height - 1] {
        let mut builder = CircuitBuilder::<CF>::new();
        let permutation_config = Poseidon2Config::KOALA_BEAR_D4_W32;
        let capacity_ext = permutation_config.capacity_ext();

        builder.enable_poseidon2_perm_width_32::<KoalaBearD4Width32, _>(
            generate_poseidon2_trace::<CF, KoalaBearD4Width32>,
            perm.clone(),
        );
        builder.enable_recompose::<F>(generate_recompose_trace::<F, CF>);

        let batch_opening = mmcs.open_batch(index, &prover_data);

        let lifted_opened: Vec<Target> = (0..width).map(|_| builder.public_input()).collect();
        let directions_expr = builder.alloc_public_inputs(log_max_height, "arity4 directions");
        let lifted_cap: Vec<Target> = (0..(capacity_ext * <CF as BasedVectorSpace<F>>::DIMENSION))
            .map(|_| builder.public_input())
            .collect();
        let cap_exprs: Vec<Vec<Target>> = vec![pack_lifted_targets(&mut builder, &lifted_cap)];

        let mmcs_op_ids = verify_batch_circuit_arity4::<F, CF>(
            &mut builder,
            permutation_config,
            &cap_exprs,
            &dimensions,
            &directions_expr,
            std::slice::from_ref(&lifted_opened),
        )
        .expect("verify_batch_circuit_arity4 should succeed");
        assert_eq!(mmcs_op_ids.len(), batch_opening.opening_proof.len());

        let circuit = builder.build().expect("circuit build");
        let mut runner = circuit.runner();

        let mut public_inputs: Vec<CF> = batch_opening
            .opened_values
            .iter()
            .flat_map(|row| row.iter().map(|&v| CF::from(v)))
            .collect();
        public_inputs.extend((0..log_max_height).map(|k| CF::from_bool((index >> k) & 1 == 1)));
        public_inputs.extend(commit.roots()[0].iter().map(|&v| CF::from(v)));
        runner
            .set_public_inputs(&public_inputs)
            .expect("set public inputs");

        set_sibling_private_data(
            &mut runner,
            &mmcs_op_ids,
            &batch_opening.opening_proof,
            permutation_config,
        );

        runner
            .run()
            .unwrap_or_else(|err| panic!("runner failed at index {index}: {err:?}"));
    }
}

/// Mixed-height batch that forces both step-2 bridge levels (heights landing between quaternary
/// layers) and injection levels (shorter matrices entering the running tree below the leaf layer).
fn mixed_height_matrices() -> Vec<RowMajorMatrix<F>> {
    let heights = [512, 512, 512, 512, 4096, 4096, 2048, 2048, 8192, 8192];
    heights
        .iter()
        .enumerate()
        .map(|(mat_idx, &height)| {
            let values = (0..height)
                .map(|i| F::from_u64((mat_idx as u64 + 1) * 100_000 + i as u64))
                .collect();
            RowMajorMatrix::new(values, 1)
        })
        .collect()
}

#[test]
fn recursive_arity4_mmcs_round_trip_mixed_heights_with_injection() {
    let perm = default_koalabear_poseidon2_32();
    let leaf_hash = LeafHash::new(perm.clone());
    let compress = Compress4::new(perm.clone());
    let mmcs = Mmcs4::new(leaf_hash, compress, 0);

    let matrices = mixed_height_matrices();
    let dimensions: Vec<_> = matrices.iter().map(Matrix::dimensions).collect();
    let (commit, prover_data) = mmcs.commit(matrices);

    let log_max_height = 13;
    for index in [0, 1, 5, 8191] {
        let mut builder = CircuitBuilder::<CF>::new();
        let permutation_config = Poseidon2Config::KOALA_BEAR_D4_W32;
        let capacity_ext = permutation_config.capacity_ext();

        builder.enable_poseidon2_perm_width_32::<KoalaBearD4Width32, _>(
            generate_poseidon2_trace::<CF, KoalaBearD4Width32>,
            perm.clone(),
        );
        builder.enable_recompose::<F>(generate_recompose_trace::<F, CF>);

        let batch_opening = mmcs.open_batch(index, &prover_data);
        let opened: Vec<Vec<Target>> = dimensions
            .iter()
            .map(|dims| (0..dims.width).map(|_| builder.public_input()).collect())
            .collect();
        let directions_expr = builder.alloc_public_inputs(log_max_height, "arity4 directions");
        let lifted_cap: Vec<Target> = (0..(capacity_ext * <CF as BasedVectorSpace<F>>::DIMENSION))
            .map(|_| builder.public_input())
            .collect();
        let cap_exprs: Vec<Vec<Target>> = vec![pack_lifted_targets(&mut builder, &lifted_cap)];

        let mmcs_op_ids = verify_batch_circuit_arity4::<F, CF>(
            &mut builder,
            permutation_config,
            &cap_exprs,
            &dimensions,
            &directions_expr,
            &opened,
        )
        .expect("verify_batch_circuit_arity4 should succeed");
        assert_eq!(mmcs_op_ids.len(), batch_opening.opening_proof.len());

        // The schedule must include at least one step-2 bridge (an op-id occurring exactly once).
        assert!(
            has_step2_bridge(&mmcs_op_ids),
            "mixed-height schedule must exercise a step-2 bridge level"
        );

        let circuit = builder.build().expect("circuit build");
        let mut runner = circuit.runner();

        let mut public_inputs: Vec<CF> = batch_opening
            .opened_values
            .iter()
            .flat_map(|row| row.iter().map(|&v| CF::from(v)))
            .collect();
        public_inputs.extend((0..log_max_height).map(|k| CF::from_bool((index >> k) & 1 == 1)));
        public_inputs.extend(commit.roots()[0].iter().map(|&v| CF::from(v)));
        runner
            .set_public_inputs(&public_inputs)
            .expect("set public inputs");

        set_sibling_private_data(
            &mut runner,
            &mmcs_op_ids,
            &batch_opening.opening_proof,
            permutation_config,
        );

        runner
            .run()
            .unwrap_or_else(|err| panic!("runner failed at index {index}: {err:?}"));
    }
}

#[test]
fn recursive_arity4_extension_mmcs_round_trip_mixed_heights() {
    let perm = default_koalabear_poseidon2_32();
    let leaf_hash = LeafHash::new(perm.clone());
    let compress = Compress4::new(perm.clone());
    let mmcs = ExtMmcs4::new(Mmcs4::new(leaf_hash, compress, 0));

    let height0 = 1024;
    let width0 = 5;
    let values0: Vec<CF> = (0..(height0 * width0) as u64)
        .map(|i| CF::from_basis_coefficients_fn(|j| F::from_u64(i * 10 + j as u64 + 1)))
        .collect();
    let matrix0 = RowMajorMatrix::new(values0, width0);

    let height1 = 512;
    let width1 = 2;
    let values1: Vec<CF> = (0..(height1 * width1) as u64)
        .map(|i| CF::from_basis_coefficients_fn(|j| F::from_u64(50_000 + i * 10 + j as u64)))
        .collect();
    let matrix1 = RowMajorMatrix::new(values1, width1);

    let dimensions = vec![matrix0.dimensions(), matrix1.dimensions()];
    let (commit, prover_data) = mmcs.commit(vec![matrix0, matrix1]);

    let log_max_height = 10;
    for index in [0, 1, 5, height0 - 1] {
        let mut builder = CircuitBuilder::<CF>::new();
        let permutation_config = Poseidon2Config::KOALA_BEAR_D4_W32;
        let capacity_ext = permutation_config.capacity_ext();

        builder.enable_poseidon2_perm_width_32::<KoalaBearD4Width32, _>(
            generate_poseidon2_trace::<CF, KoalaBearD4Width32>,
            perm.clone(),
        );
        builder.enable_recompose::<F>(generate_recompose_trace::<F, CF>);

        let batch_opening = mmcs.open_batch(index, &prover_data);
        let opened: Vec<Vec<Target>> = [width0, width1]
            .into_iter()
            .map(|width| (0..width).map(|_| builder.public_input()).collect())
            .collect();
        let directions_expr = builder.alloc_public_inputs(log_max_height, "arity4 directions");
        let lifted_cap: Vec<Target> = (0..(capacity_ext * <CF as BasedVectorSpace<F>>::DIMENSION))
            .map(|_| builder.public_input())
            .collect();
        let cap_exprs: Vec<Vec<Target>> = vec![pack_lifted_targets(&mut builder, &lifted_cap)];

        let mmcs_op_ids = verify_batch_circuit_from_extension_opened_arity4::<F, CF>(
            &mut builder,
            permutation_config,
            &cap_exprs,
            &dimensions,
            &directions_expr,
            &opened,
        )
        .expect("verify_batch_circuit_from_extension_opened_arity4 should succeed");
        assert_eq!(mmcs_op_ids.len(), batch_opening.opening_proof.len());

        let circuit = builder.build().expect("circuit build");
        let mut runner = circuit.runner();

        let mut public_inputs: Vec<CF> = batch_opening
            .opened_values
            .iter()
            .flat_map(|row| row.iter().copied())
            .collect();
        public_inputs.extend((0..log_max_height).map(|k| CF::from_bool((index >> k) & 1 == 1)));
        public_inputs.extend(commit.roots()[0].iter().map(|&v| CF::from(v)));
        runner
            .set_public_inputs(&public_inputs)
            .expect("set public inputs");

        set_sibling_private_data(
            &mut runner,
            &mmcs_op_ids,
            &batch_opening.opening_proof,
            permutation_config,
        );

        runner
            .run()
            .unwrap_or_else(|err| panic!("runner failed at index {index}: {err:?}"));
    }
}

/// Tampering the sibling of a step-2 bridge level makes the in-circuit running hash diverge from
/// the native digest, so the recovered root no longer matches the native cap and the root
/// `connect` surfaces a witness conflict. This exercises that the step-2 schedule binds its single
/// sibling correctly end to end.
#[test]
fn recursive_arity4_mmcs_step2_bridge_tampered_sibling_fails() {
    let perm = default_koalabear_poseidon2_32();
    let leaf_hash = LeafHash::new(perm.clone());
    let compress = Compress4::new(perm.clone());
    let mmcs = Mmcs4::new(leaf_hash, compress, 0);

    let matrices = mixed_height_matrices();
    let dimensions: Vec<_> = matrices.iter().map(Matrix::dimensions).collect();
    let (commit, prover_data) = mmcs.commit(matrices);

    let log_max_height = 13;
    let index = 8191;

    let mut builder = CircuitBuilder::<CF>::new();
    let permutation_config = Poseidon2Config::KOALA_BEAR_D4_W32;
    let capacity_ext = permutation_config.capacity_ext();

    builder.enable_poseidon2_perm_width_32::<KoalaBearD4Width32, _>(
        generate_poseidon2_trace::<CF, KoalaBearD4Width32>,
        perm,
    );
    builder.enable_recompose::<F>(generate_recompose_trace::<F, CF>);

    let batch_opening = mmcs.open_batch(index, &prover_data);
    let opened: Vec<Vec<Target>> = dimensions
        .iter()
        .map(|dims| (0..dims.width).map(|_| builder.public_input()).collect())
        .collect();
    let directions_expr = builder.alloc_public_inputs(log_max_height, "arity4 directions");
    let lifted_cap: Vec<Target> = (0..(capacity_ext * <CF as BasedVectorSpace<F>>::DIMENSION))
        .map(|_| builder.public_input())
        .collect();
    let cap_exprs: Vec<Vec<Target>> = vec![pack_lifted_targets(&mut builder, &lifted_cap)];

    let mmcs_op_ids = verify_batch_circuit_arity4::<F, CF>(
        &mut builder,
        permutation_config,
        &cap_exprs,
        &dimensions,
        &directions_expr,
        &opened,
    )
    .expect("verify_batch_circuit_arity4 should succeed");
    assert_eq!(mmcs_op_ids.len(), batch_opening.opening_proof.len());

    // Locate the proof sibling belonging to the first step-2 bridge level (op-id occurring once).
    let bridge_proof_idx =
        step2_bridge_proof_idx(&mmcs_op_ids).expect("mixed-height schedule has a step-2 bridge");

    let circuit = builder.build().expect("circuit build");
    let mut runner = circuit.runner();

    let mut public_inputs: Vec<CF> = batch_opening
        .opened_values
        .iter()
        .flat_map(|row| row.iter().map(|&v| CF::from(v)))
        .collect();
    public_inputs.extend((0..log_max_height).map(|k| CF::from_bool((index >> k) & 1 == 1)));
    public_inputs.extend(commit.roots()[0].iter().map(|&v| CF::from(v)));
    runner
        .set_public_inputs(&public_inputs)
        .expect("set public inputs");

    let mut tampered_proof = batch_opening.opening_proof;
    tampered_proof[bridge_proof_idx][0] += F::ONE;

    set_sibling_private_data(
        &mut runner,
        &mmcs_op_ids,
        &tampered_proof,
        permutation_config,
    );

    let result = runner.run();
    assert!(
        matches!(
            result,
            Err(p3_circuit::CircuitError::WitnessConflict { .. })
        ),
        "tampered step-2 bridge sibling must fail the in-circuit root check with a witness \
         conflict, got: {result:?}"
    );
}

/// Native-parity round trip for a single power-of-two-height matrix at a given `cap_height`.
///
/// Asserts (a) the native opening verifies via `verify_batch`, (b) the integer pos/cap split
/// matches native arithmetic (`cap_index = index >> path_bit_total`, `path_bit_total =
/// log2(height) - log2(num_roots)`), and (c) the in-circuit recovered root equals the native cap
/// entry the prover checks (the runner connects the recovered root to the quaternary-selected cap).
fn assert_single_matrix_cap_parity(height: usize, cap_height: usize, indices: &[usize]) {
    let perm = default_koalabear_poseidon2_32();
    let leaf_hash = LeafHash::new(perm.clone());
    let compress = Compress4::new(perm.clone());
    let mmcs = Mmcs4::new(leaf_hash, compress, cap_height);

    // width == D packs into a single-chunk leaf, so the leaf row seeds the Merkle chain.
    let width = 4;
    let values: Vec<F> = (0..(height * width) as u64).map(F::from_u64).collect();
    let matrix = RowMajorMatrix::new(values, width);
    let dimensions = vec![matrix.dimensions()];
    let (commit, prover_data) = mmcs.commit(vec![matrix]);

    let num_roots = commit.roots().len();
    assert!(
        num_roots.is_power_of_two(),
        "cap is a power-of-two binary mux"
    );
    let log_max_height = (height as u64).ilog2() as usize;
    let cap_log2 = (num_roots as u64).ilog2() as usize;
    let path_bit_total = log_max_height - cap_log2;

    for &index in indices {
        let batch_opening = mmcs.open_batch(index, &prover_data);

        // (a) Ground truth: the native verifier accepts this opening.
        mmcs.verify_batch(
            &commit,
            &dimensions,
            index,
            BatchOpeningRef::new(&batch_opening.opened_values, &batch_opening.opening_proof),
        )
        .unwrap_or_else(|e| {
            panic!("native verify_batch failed (cap={cap_height}, idx={index}): {e:?}")
        });

        // (b) Native integer cap split: the verifier checks `commit[index >> path_bit_total]`.
        let cap_index = index >> path_bit_total;
        assert!(
            cap_index < num_roots,
            "cap_index {cap_index} out of range {num_roots} (cap={cap_height}, idx={index})"
        );

        let mut builder = CircuitBuilder::<CF>::new();
        let permutation_config = Poseidon2Config::KOALA_BEAR_D4_W32;
        builder.enable_poseidon2_perm_width_32::<KoalaBearD4Width32, _>(
            generate_poseidon2_trace::<CF, KoalaBearD4Width32>,
            perm.clone(),
        );
        builder.enable_recompose::<F>(generate_recompose_trace::<F, CF>);

        let lifted_opened: Vec<Target> = (0..width).map(|_| builder.public_input()).collect();
        let directions_expr = builder.alloc_public_inputs(log_max_height, "arity4 directions");
        // Feed the full cap as constants; the in-circuit quaternary selector recovers the entry
        // addressed by the high index bits and the root `connect` ties the recovered hash to it.
        let cap_exprs: Vec<Vec<Target>> = commit
            .roots()
            .iter()
            .map(|root| {
                pack_digest(root)
                    .iter()
                    .map(|&v| builder.alloc_const(v, "cap"))
                    .collect()
            })
            .collect();

        let mmcs_op_ids = verify_batch_circuit_arity4::<F, CF>(
            &mut builder,
            permutation_config,
            &cap_exprs,
            &dimensions,
            &directions_expr,
            std::slice::from_ref(&lifted_opened),
        )
        .expect("verify_batch_circuit_arity4 should succeed");
        assert_eq!(mmcs_op_ids.len(), batch_opening.opening_proof.len());

        let circuit = builder.build().expect("circuit build");
        let mut runner = circuit.runner();

        let mut public_inputs: Vec<CF> = batch_opening
            .opened_values
            .iter()
            .flat_map(|row| row.iter().map(|&v| CF::from(v)))
            .collect();
        public_inputs.extend((0..log_max_height).map(|k| CF::from_bool((index >> k) & 1 == 1)));
        runner
            .set_public_inputs(&public_inputs)
            .expect("set public inputs");

        set_sibling_private_data(
            &mut runner,
            &mmcs_op_ids,
            &batch_opening.opening_proof,
            permutation_config,
        );

        // (c) A successful run means the recovered root equals `commit.roots()[cap_index]`.
        runner.run().unwrap_or_else(|err| {
            panic!(
                "cap-parity run failed (cap={cap_height}, idx={index}, cap_index={cap_index}): {err:?}"
            )
        });
    }
}

/// Native parity across `cap_height ∈ {0,1,2,3}` for an **even** `log2(height)` (height 1024 =
/// 4^5): an all-step-4 schedule whose cap entries are powers of four (1, 4, 16, 64).
#[test]
fn recursive_arity4_mmcs_native_parity_cap_heights_even_log2() {
    for cap_height in 0..=3 {
        assert_single_matrix_cap_parity(1024, cap_height, &[0, 1, 2, 3, 5, 27, 1023]);
    }
}

/// Native parity across `cap_height ∈ {0,1,2,3}` for an **odd** `log2(height)` (height 512): the
/// full schedule ends in a step-2 bridge, so the cap entry counts are 1, 2, 8, 32 and the cap
/// absorbs the bridge at `cap_height ≥ 1`.
#[test]
fn recursive_arity4_mmcs_native_parity_cap_heights_odd_log2() {
    for cap_height in 0..=3 {
        assert_single_matrix_cap_parity(512, cap_height, &[0, 1, 2, 3, 5, 27, 511]);
    }
}

/// SOUNDNESS NEGATIVE: a direction bit that disagrees with the sampled index lands the running
/// hash in the wrong chunk, so the recovered root diverges from the native cap and the root
/// `connect` surfaces a witness conflict. The native opening is untouched; only the public
/// direction bits are flipped away from the real index.
#[test]
fn recursive_arity4_mmcs_flipped_direction_bit_fails() {
    let perm = default_koalabear_poseidon2_32();
    let leaf_hash = LeafHash::new(perm.clone());
    let compress = Compress4::new(perm.clone());
    let mmcs = Mmcs4::new(leaf_hash, compress, 0);

    let height = 1024;
    let width = 4;
    let values: Vec<F> = (0..(height * width) as u64).map(F::from_u64).collect();
    let matrix = RowMajorMatrix::new(values, width);
    let dimensions = vec![matrix.dimensions()];
    let (commit, prover_data) = mmcs.commit(vec![matrix]);

    let log_max_height = 10;
    let index = 5usize;

    let mut builder = CircuitBuilder::<CF>::new();
    let permutation_config = Poseidon2Config::KOALA_BEAR_D4_W32;
    builder.enable_poseidon2_perm_width_32::<KoalaBearD4Width32, _>(
        generate_poseidon2_trace::<CF, KoalaBearD4Width32>,
        perm,
    );
    builder.enable_recompose::<F>(generate_recompose_trace::<F, CF>);

    let batch_opening = mmcs.open_batch(index, &prover_data);
    let lifted_opened: Vec<Target> = (0..width).map(|_| builder.public_input()).collect();
    let directions_expr = builder.alloc_public_inputs(log_max_height, "arity4 directions");
    let lifted_cap: Vec<Target> = (0..(permutation_config.capacity_ext()
        * <CF as BasedVectorSpace<F>>::DIMENSION))
        .map(|_| builder.public_input())
        .collect();
    let cap_exprs: Vec<Vec<Target>> = vec![pack_lifted_targets(&mut builder, &lifted_cap)];

    let mmcs_op_ids = verify_batch_circuit_arity4::<F, CF>(
        &mut builder,
        permutation_config,
        &cap_exprs,
        &dimensions,
        &directions_expr,
        std::slice::from_ref(&lifted_opened),
    )
    .expect("verify_batch_circuit_arity4 should succeed");

    let circuit = builder.build().expect("circuit build");
    let mut runner = circuit.runner();

    let mut public_inputs: Vec<CF> = batch_opening
        .opened_values
        .iter()
        .flat_map(|row| row.iter().map(|&v| CF::from(v)))
        .collect();
    // Flip the level-0 direction bit away from the sampled index.
    let flipped = index ^ 1;
    public_inputs.extend((0..log_max_height).map(|k| CF::from_bool((flipped >> k) & 1 == 1)));
    public_inputs.extend(commit.roots()[0].iter().map(|&v| CF::from(v)));
    runner
        .set_public_inputs(&public_inputs)
        .expect("set public inputs");

    set_sibling_private_data(
        &mut runner,
        &mmcs_op_ids,
        &batch_opening.opening_proof,
        permutation_config,
    );

    let result = runner.run();
    assert!(
        matches!(
            result,
            Err(p3_circuit::CircuitError::WitnessConflict { .. })
        ),
        "a direction bit disagreeing with the sampled index must fail the root check, got: {result:?}"
    );
}

/// SOUNDNESS NEGATIVE: tampering an injected matrix's opened value changes its in-circuit
/// injection digest (the W32 leaf hash feeding chunk 1 of the injection compression row), so the
/// recovered root no longer matches the native cap and the root `connect` conflicts. This binds the
/// injection preimage to the opened values end to end.
#[test]
fn recursive_arity4_mmcs_tampered_injected_value_fails() {
    let perm = default_koalabear_poseidon2_32();
    let leaf_hash = LeafHash::new(perm.clone());
    let compress = Compress4::new(perm.clone());
    let mmcs = Mmcs4::new(leaf_hash, compress, 0);

    let matrices = mixed_height_matrices();
    let dimensions: Vec<_> = matrices.iter().map(Matrix::dimensions).collect();
    let (commit, prover_data) = mmcs.commit(matrices);

    let log_max_height = 13;
    let index = 8191usize;

    let mut builder = CircuitBuilder::<CF>::new();
    let permutation_config = Poseidon2Config::KOALA_BEAR_D4_W32;
    let capacity_ext = permutation_config.capacity_ext();
    builder.enable_poseidon2_perm_width_32::<KoalaBearD4Width32, _>(
        generate_poseidon2_trace::<CF, KoalaBearD4Width32>,
        perm,
    );
    builder.enable_recompose::<F>(generate_recompose_trace::<F, CF>);

    let batch_opening = mmcs.open_batch(index, &prover_data);
    let opened: Vec<Vec<Target>> = dimensions
        .iter()
        .map(|dims| (0..dims.width).map(|_| builder.public_input()).collect())
        .collect();
    let directions_expr = builder.alloc_public_inputs(log_max_height, "arity4 directions");
    let lifted_cap: Vec<Target> = (0..(capacity_ext * <CF as BasedVectorSpace<F>>::DIMENSION))
        .map(|_| builder.public_input())
        .collect();
    let cap_exprs: Vec<Vec<Target>> = vec![pack_lifted_targets(&mut builder, &lifted_cap)];

    let mmcs_op_ids = verify_batch_circuit_arity4::<F, CF>(
        &mut builder,
        permutation_config,
        &cap_exprs,
        &dimensions,
        &directions_expr,
        &opened,
    )
    .expect("verify_batch_circuit_arity4 should succeed");
    // The schedule must actually inject a shorter matrix for this test to be meaningful.
    assert!(
        has_step2_bridge(&mmcs_op_ids),
        "mixed-height schedule must exercise a bridge/injection level"
    );

    let circuit = builder.build().expect("circuit build");
    let mut runner = circuit.runner();

    let mut public_inputs: Vec<CF> = batch_opening
        .opened_values
        .iter()
        .flat_map(|row| row.iter().map(|&v| CF::from(v)))
        .collect();
    // Tamper the opened value of matrix 0 (height 512, an injected matrix below the leaf layer).
    public_inputs[0] += CF::ONE;
    public_inputs.extend((0..log_max_height).map(|k| CF::from_bool((index >> k) & 1 == 1)));
    public_inputs.extend(commit.roots()[0].iter().map(|&v| CF::from(v)));
    runner
        .set_public_inputs(&public_inputs)
        .expect("set public inputs");

    set_sibling_private_data(
        &mut runner,
        &mmcs_op_ids,
        &batch_opening.opening_proof,
        permutation_config,
    );

    let result = runner.run();
    assert!(
        matches!(
            result,
            Err(p3_circuit::CircuitError::WitnessConflict { .. })
        ),
        "a tampered injected opened value must fail the root check, got: {result:?}"
    );
}

/// True if any op-id occurs exactly once (a step-2 bridge level; step-4 levels occur 3×).
fn has_step2_bridge(op_ids: &[p3_circuit::NonPrimitiveOpId]) -> bool {
    step2_bridge_proof_idx(op_ids).is_some()
}

/// Proof-sibling index of the first step-2 bridge level (the single sibling of an op-id that
/// occurs exactly once). Op-id occurrences map 1:1 to opening-proof siblings, in order.
fn step2_bridge_proof_idx(op_ids: &[p3_circuit::NonPrimitiveOpId]) -> Option<usize> {
    let mut idx = 0usize;
    while idx < op_ids.len() {
        let op_id = op_ids[idx];
        let start = idx;
        while idx < op_ids.len() && op_ids[idx] == op_id {
            idx += 1;
        }
        if idx - start == 1 {
            return Some(start);
        }
    }
    None
}
