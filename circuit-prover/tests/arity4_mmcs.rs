//! Circuit-level round-trip for the arity-4 (4-to-1) MMCS op layer.
//!
//! Builds a native arity-4 Merkle tree (`TruncatedPermutation<Perm32, 4, 8, 32>`
//! compression + `MerkleTreeMmcs<.., 4, 8>`) over a single matrix whose height is a
//! power of four, opens a query index, and drives the opening through
//! [`CircuitBuilder::add_mmcs_verify_arity4`]. The in-circuit running hash is the
//! native leaf digest entering level 0; at each level the queried child lands in
//! chunk `pos = b0 + 2·b1` (`pos = index % 4`) and the three native siblings fill
//! the remaining chunks in ascending order. The recovered root is connected to the
//! native commitment cap and the full proof is generated and verified through the
//! W32 Poseidon2 STARK table.
//!
//! The positive test sweeps query indices whose level-0 `pos` covers all four
//! quaternary positions `{0, 1, 2, 3}` plus deeper indices that exercise nonzero
//! `pos` at higher levels — the regression for the index-0-only sibling placement
//! bug, where only `pos = 0` was wired self-consistently.

use p3_batch_stark::ProverData;
use p3_circuit::CircuitBuilder;
use p3_circuit::ops::{
    Poseidon2Config, generate_poseidon2_trace, generate_recompose_trace, perm_private_data,
};
use p3_circuit_prover::batch_stark_prover::{poseidon2_air_builders, recompose_air_builders};
use p3_circuit_prover::common::{NpoPreprocessor, get_airs_and_degrees_with_prep};
use p3_circuit_prover::config::KoalaBearConfig;
use p3_circuit_prover::{
    BatchStarkProver, CircuitProverData, ConstraintProfile, Poseidon2Preprocessor,
    RecomposePreprocessor, TablePacking, config,
};
use p3_commit::Mmcs;
use p3_field::extension::BinomialExtensionField;
use p3_field::{BasedVectorSpace, PrimeCharacteristicRing};
use p3_koala_bear::{KoalaBear, Poseidon2KoalaBear, default_koalabear_poseidon2_32};
use p3_matrix::dense::RowMajorMatrix;
use p3_merkle_tree::MerkleTreeMmcs;
use p3_poseidon2_circuit_air::KoalaBearD4Width32;
use p3_symmetric::{PaddingFreeSponge, TruncatedPermutation};

type F = KoalaBear;
type EF = BinomialExtensionField<F, 4>;

// One wide perm drives both the native leaf sponge and the 4-to-1 compression; the
// in-circuit executor enables the same perm so digests agree on both sides.
type Perm32 = Poseidon2KoalaBear<32>;
type LeafHash = PaddingFreeSponge<Perm32, 32, 24, 8>;
type Compress4 = TruncatedPermutation<Perm32, 4, 8, 32>;
type Mmcs4 = MerkleTreeMmcs<F, F, LeafHash, Compress4, 4, 8>;

// Height 64 = 4³ ⇒ three full quaternary compression levels (64 → 16 → 4 → 1).
const TREE_HEIGHT: usize = 64;
const MATRIX_WIDTH: usize = 4;
// Single-matrix power-of-four path: every level is a full step-4 compression.
const SIBS_PER_LEVEL: usize = 3;

/// Pack a base-field digest into `capacity_ext` packed-EF limbs (each `D` base
/// elements become one `EF`). Mirrors the native digest layout the W32
/// compression consumes.
fn pack_digest(digest: &[F]) -> Vec<EF> {
    let d = <EF as BasedVectorSpace<F>>::DIMENSION;
    digest
        .chunks(d)
        .map(|chunk| {
            let mut coeffs = vec![F::ZERO; d];
            coeffs[..chunk.len()].copy_from_slice(chunk);
            EF::from_basis_coefficients_slice(&coeffs).expect("digest packs into EF")
        })
        .collect()
}

/// Build the circuit, native witness, and run the prover for an arity-4 opening at
/// `index`. The `tamper` closure may mutate the siblings (as packed-EF limbs)
/// before they are wired into the circuit.
///
/// Returns the runner result: `Ok` means the in-circuit root matched the native
/// cap (the prover then proves and verifies the W32 table, which must succeed),
/// `Err` means the `connect` against the root surfaced a witness conflict. The
/// circuit build is infallible here, so build/prover-setup failures panic rather
/// than masquerade as a tamper detection.
fn run_arity4_round_trip(
    index: usize,
    tamper: impl FnOnce(&mut Vec<Vec<EF>>),
) -> Result<(), p3_circuit::CircuitError> {
    let perm = default_koalabear_poseidon2_32();
    let leaf_hash = LeafHash::new(perm.clone());
    let compress = Compress4::new(perm.clone());
    // cap_height = 0 ⇒ the commitment cap is the single root.
    let mmcs = Mmcs4::new(leaf_hash, compress, 0);

    let values: Vec<F> = (0..(TREE_HEIGHT * MATRIX_WIDTH) as u64)
        .map(F::from_u64)
        .collect();
    let matrix = RowMajorMatrix::new(values, MATRIX_WIDTH);

    let (commit, prover_data) = mmcs.commit(vec![matrix]);

    let opening = mmcs.open_batch(index, &prover_data);
    let opened_row = &opening.opened_values[0];

    assert_eq!(
        opening.opening_proof.len() % SIBS_PER_LEVEL,
        0,
        "single-matrix power-of-four path has 3 siblings per level"
    );
    let num_levels = opening.opening_proof.len() / SIBS_PER_LEVEL;

    let mut siblings_per_level: Vec<Vec<EF>> = opening
        .opening_proof
        .iter()
        .map(|sib| pack_digest(sib))
        .collect();
    tamper(&mut siblings_per_level);

    let mut builder = CircuitBuilder::<EF>::new();
    builder.enable_poseidon2_perm_width_32::<KoalaBearD4Width32, _>(
        generate_poseidon2_trace::<EF, KoalaBearD4Width32>,
        perm,
    );
    builder.enable_recompose::<F>(generate_recompose_trace::<F, EF>);

    let permutation_config = Poseidon2Config::KOALA_BEAR_D4_W32;

    // The opened row (width 4 = D) packs into a single EF leaf-data slot, so the
    // in-circuit D4 W32 leaf-hash row places the four base values at the same
    // state lanes the native `PaddingFreeSponge` does and reproduces its digest.
    let leaf_packed = EF::from_basis_coefficients_slice(opened_row)
        .expect("width-4 opened row packs into one EF");
    let leaf_exprs = vec![builder.alloc_const(leaf_packed, "leaf")];

    // Per-level position bits: `pos = index % 4` at level `i`, then `index /= 4`.
    // `directions[i] = [b0, b1]` with `pos = b0 + 2·b1` selects the chunk the
    // running hash lands in, matching the native `pos_in_group` placement.
    let zero = builder.alloc_const(EF::ZERO, "dir_bit_0");
    let one = builder.alloc_const(EF::ONE, "dir_bit_1");
    let directions: Vec<[_; 2]> = (0..num_levels)
        .map(|level| {
            let pos = (index >> (2 * level)) & 0b11;
            let b0 = if pos & 1 == 1 { one } else { zero };
            let b1 = if (pos >> 1) & 1 == 1 { one } else { zero };
            [b0, b1]
        })
        .collect();

    let root = &commit.roots()[0];
    let root_packed = pack_digest(root);
    let root_exprs: Vec<_> = root_packed
        .iter()
        .map(|&v| builder.alloc_const(v, "root"))
        .collect();

    let op_ids = builder
        .add_mmcs_verify_arity4(permutation_config, &leaf_exprs, &directions, &root_exprs)
        .expect("arity-4 MMCS verify wiring");

    let circuit = builder.build().expect("circuit build");
    let mut runner = circuit.runner();
    runner.set_public_inputs(&[]).expect("set public inputs");

    // The leaf-hash row (`op_ids[0]`) has no siblings; each compression row gets
    // its three native siblings as flat `(N-1)·capacity_ext` EF private data, in
    // ascending chunk order (the native opening-proof sibling order).
    for (level, &op_id) in op_ids.iter().skip(1).enumerate() {
        let sibling: Vec<EF> = siblings_per_level
            [level * SIBS_PER_LEVEL..(level + 1) * SIBS_PER_LEVEL]
            .iter()
            .flatten()
            .copied()
            .collect();
        runner
            .set_private_data(op_id, perm_private_data(permutation_config, sibling))
            .expect("attach arity-4 sibling private data");
    }

    // The run carries the load-bearing assertion: a tampered sibling makes the
    // recovered root diverge from the native cap, so the root `connect` surfaces a
    // witness conflict here. Return it to the caller unmodified.
    let traces = runner.run()?;

    // Prove and verify the W32 Poseidon2 table end to end. On an untampered path
    // this must succeed; a failure here is a real prover regression, not a tamper.
    let table_packing = TablePacking::new(4, 4);
    let stark_config = config::koala_bear();
    let npo_prep: Vec<Box<dyn NpoPreprocessor<F>>> = vec![
        Box::new(Poseidon2Preprocessor),
        Box::new(RecomposePreprocessor::default()),
    ];
    let mut air_builders = poseidon2_air_builders::<_, 4>();
    air_builders.extend(recompose_air_builders(1, false));
    let (airs_degrees, primitive_columns, non_primitive_columns) =
        get_airs_and_degrees_with_prep::<KoalaBearConfig, _, 4>(
            &circuit,
            &table_packing,
            &npo_prep,
            &air_builders,
            ConstraintProfile::Standard,
        )
        .expect("derive airs and preprocessed columns");
    let (airs, degrees): (Vec<_>, Vec<usize>) = airs_degrees.into_iter().unzip();

    let prover_data_stark = ProverData::from_airs_and_degrees(&stark_config, &airs, &degrees);
    let circuit_prover_data =
        CircuitProverData::new(prover_data_stark, primitive_columns, non_primitive_columns);

    let mut prover = BatchStarkProver::new(stark_config).with_table_packing(table_packing);
    prover.register_poseidon2_table::<4>(permutation_config);
    prover.register_recompose_table::<4>(false);

    let proof = prover
        .prove_all_tables(&traces, &circuit_prover_data)
        .expect("prove all tables");
    prover
        .verify_all_tables::<EF>(&proof)
        .expect("verify all tables");

    Ok(())
}

/// The in-circuit arity-4 root must equal the native commitment cap, and the
/// whole circuit must prove and verify under the W32 Poseidon2 table — for every
/// quaternary position. Indices 0..=3 cover level-0 `pos` ∈ {0, 1, 2, 3}; indices
/// 27 (`pos` 3, 2, 1) and 63 (`pos` 3, 3, 3) exercise nonzero `pos` at higher
/// levels.
#[test]
fn arity4_mmcs_circuit_round_trip_all_positions() {
    for index in [0usize, 1, 2, 3, 27, 63] {
        run_arity4_round_trip(index, |_siblings| {}).unwrap_or_else(|err| {
            panic!("arity-4 MMCS round trip should succeed at index {index}: {err:?}")
        });
    }
}

/// Tampering with a sibling digest makes the in-circuit root diverge from the
/// native cap, so the `connect` against the root must surface a witness conflict.
/// Checked at a nonzero-position index so the tamper is caught off chunk 0.
#[test]
fn arity4_mmcs_circuit_tampered_sibling_fails() {
    let result = run_arity4_round_trip(27, |siblings| {
        siblings[0][0] += EF::ONE;
    });
    assert!(
        matches!(
            result,
            Err(p3_circuit::CircuitError::WitnessConflict { .. })
        ),
        "tampered arity-4 sibling must fail the in-circuit root check with a \
         witness conflict, got: {result:?}"
    );
}
