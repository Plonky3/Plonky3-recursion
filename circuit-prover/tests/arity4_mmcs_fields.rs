//! Circuit-level arity-4 (4-to-1) MMCS round-trip for the non-KoalaBear fields.
//!
//! Mirrors `arity4_mmcs.rs` (KoalaBear `D4_W32`) for the BabyBear `D4_W32` and
//! Goldilocks `D2_W16` arity-4 compression shapes. A native arity-4 Merkle tree is
//! built over a single power-of-four-height matrix, a query is opened, and the
//! opening is driven through [`CircuitBuilder::add_mmcs_verify_arity4`]. The
//! recovered root is connected to the native cap and the whole circuit is proved
//! and verified through the wide Poseidon2 STARK table.
//!
//! The positive test sweeps query indices covering every quaternary position; the
//! negative test tampers a sibling and asserts the in-circuit root check fails with
//! a witness conflict.

use p3_batch_stark::ProverData;
use p3_circuit::CircuitBuilder;
use p3_circuit::ops::{
    Poseidon2Config, generate_poseidon2_trace, generate_recompose_trace, perm_private_data,
};
use p3_circuit_prover::batch_stark_prover::{poseidon2_air_builders, recompose_air_builders};
use p3_circuit_prover::common::{NpoPreprocessor, get_airs_and_degrees_with_prep};
use p3_circuit_prover::{
    BatchStarkProver, CircuitProverData, ConstraintProfile, Poseidon2Preprocessor,
    RecomposePreprocessor, TablePacking, config,
};
use p3_commit::Mmcs;
use p3_field::extension::BinomialExtensionField;
use p3_field::{BasedVectorSpace, PrimeCharacteristicRing};
use p3_matrix::dense::RowMajorMatrix;
use p3_merkle_tree::MerkleTreeMmcs;
use p3_symmetric::{PaddingFreeSponge, TruncatedPermutation};

/// Emit an arity-4 MMCS round-trip suite (positive sweep + tampered-sibling
/// negative) for one field's wide compression shape.
macro_rules! arity4_field_suite {
    (
        $modname:ident,
        $field:ty,
        $d:expr,
        $perm:ty,
        $default_perm:expr,
        $air_cfg:ty,
        $p2cfg:expr,
        $stark_cfg_ty:ty,
        $stark_cfg_fn:expr,
        $enable_fn:ident,
        $width:expr,
        $rate:expr,
        $digest:expr
    ) => {
        mod $modname {
            use super::*;

            type F = $field;
            const D: usize = $d;
            type EF = BinomialExtensionField<F, D>;
            type Perm = $perm;
            type LeafHash = PaddingFreeSponge<Perm, $width, $rate, $digest>;
            type Compress4 = TruncatedPermutation<Perm, 4, $digest, $width>;
            type Mmcs4 = MerkleTreeMmcs<F, F, LeafHash, Compress4, 4, $digest>;

            // Height 64 = 4³ ⇒ three full quaternary compression levels (64 → 16 → 4 → 1).
            const TREE_HEIGHT: usize = 64;
            // Matrix width D ⇒ each opened row packs into exactly one EF leaf slot.
            const MATRIX_WIDTH: usize = D;
            const SIBS_PER_LEVEL: usize = 3;

            /// Pack a base-field digest into `capacity_ext` packed-EF limbs (each `D`
            /// base elements become one `EF`).
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

            /// Build the circuit, native witness, and run the prover for an arity-4
            /// opening at `index`; `tamper` may mutate the packed-EF siblings first.
            fn run_arity4_round_trip(
                index: usize,
                tamper: impl FnOnce(&mut Vec<Vec<EF>>),
            ) -> Result<(), p3_circuit::CircuitError> {
                let perm = $default_perm;
                let leaf_hash = LeafHash::new(perm.clone());
                let compress = Compress4::new(perm.clone());
                let mmcs = Mmcs4::new(leaf_hash.clone(), compress, 0);

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
                builder.$enable_fn::<$air_cfg, _>(generate_poseidon2_trace::<EF, $air_cfg>, perm);
                builder.enable_recompose::<F>(generate_recompose_trace::<F, EF>);

                let permutation_config = $p2cfg;

                let leaf_packed = EF::from_basis_coefficients_slice(opened_row)
                    .expect("width-D opened row packs into one EF");
                let leaf_exprs = vec![builder.alloc_const(leaf_packed, "leaf")];

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
                    .add_mmcs_verify_arity4(
                        permutation_config,
                        &leaf_exprs,
                        &directions,
                        &root_exprs,
                    )
                    .expect("arity-4 MMCS verify wiring");

                let circuit = builder.build().expect("circuit build");
                let mut runner = circuit.runner();
                runner.set_public_inputs(&[]).expect("set public inputs");

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

                let traces = runner.run()?;

                let table_packing = TablePacking::new(4, 4);
                let stark_config = $stark_cfg_fn;
                let npo_prep: Vec<Box<dyn NpoPreprocessor<F>>> = vec![
                    Box::new(Poseidon2Preprocessor),
                    Box::new(RecomposePreprocessor::default()),
                ];
                let mut air_builders = poseidon2_air_builders::<_, D>();
                air_builders.extend(recompose_air_builders(1, false));
                let (airs_degrees, primitive_columns, non_primitive_columns) =
                    get_airs_and_degrees_with_prep::<$stark_cfg_ty, _, D>(
                        &circuit,
                        &table_packing,
                        &npo_prep,
                        &air_builders,
                        ConstraintProfile::Standard,
                    )
                    .expect("derive airs and preprocessed columns");
                let (airs, degrees): (Vec<_>, Vec<usize>) = airs_degrees.into_iter().unzip();

                let prover_data_stark =
                    ProverData::from_airs_and_degrees(&stark_config, &airs, &degrees);
                let circuit_prover_data = CircuitProverData::new(
                    prover_data_stark,
                    primitive_columns,
                    non_primitive_columns,
                );

                let mut prover =
                    BatchStarkProver::new(stark_config).with_table_packing(table_packing);
                prover.register_poseidon2_table::<D>(permutation_config);
                prover.register_recompose_table::<D>(false);

                let proof = prover
                    .prove_all_tables(&traces, &circuit_prover_data)
                    .expect("prove all tables");
                prover
                    .verify_all_tables::<EF>(&proof)
                    .expect("verify all tables");

                Ok(())
            }

            /// The in-circuit arity-4 root must equal the native commitment cap, and
            /// the whole circuit must prove and verify under the wide Poseidon2 table —
            /// for every quaternary position.
            #[test]
            fn arity4_mmcs_circuit_round_trip_all_positions() {
                for index in [0usize, 1, 2, 3, 27, 63] {
                    run_arity4_round_trip(index, |_siblings| {}).unwrap_or_else(|err| {
                        panic!("arity-4 MMCS round trip should succeed at index {index}: {err:?}")
                    });
                }
            }

            /// Tampering with a sibling digest makes the in-circuit root diverge from
            /// the native cap, so the `connect` against the root must surface a witness
            /// conflict.
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
        }
    };
}

arity4_field_suite!(
    baby_bear,
    p3_baby_bear::BabyBear,
    4,
    p3_baby_bear::Poseidon2BabyBear<32>,
    p3_baby_bear::default_babybear_poseidon2_32(),
    p3_poseidon2_circuit_air::BabyBearD4Width32,
    Poseidon2Config::BABY_BEAR_D4_W32,
    p3_circuit_prover::config::BabyBearConfig,
    config::baby_bear(),
    enable_poseidon2_perm_width_32,
    32,
    24,
    8
);

arity4_field_suite!(
    goldilocks,
    p3_goldilocks::Goldilocks,
    2,
    p3_goldilocks::Poseidon2Goldilocks<16>,
    {
        use rand::SeedableRng;
        let mut rng = rand::rngs::SmallRng::seed_from_u64(1);
        p3_goldilocks::Poseidon2Goldilocks::<16>::new_from_rng_128(&mut rng)
    },
    p3_poseidon2_circuit_air::GoldilocksD2Width16,
    Poseidon2Config::GOLDILOCKS_D2_W16,
    p3_circuit_prover::config::GoldilocksConfig,
    config::goldilocks(),
    enable_poseidon2_perm,
    16,
    12,
    4
);
