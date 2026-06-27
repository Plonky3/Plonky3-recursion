//! Bus-balance regression for the arity-4 (4-to-1) MMCS recursive verifier.
//!
//! Builds an arity-4 `verify_batch_circuit_arity4` circuit whose schedule contains a step-2 bridge
//! and/or an injection level, runs it to witness the traces, then proves AND verifies the W32
//! Poseidon2 + recompose tables end to end. A balanced `WitnessChecks` bus is the load-bearing
//! assertion: if the per-row producer/consumer multiplicities for the bridge/injection pad slots,
//! the injected leaf-hash digest, or the direction-bit binding were off, `verify_all_tables` would
//! reject with `Lookup(TerminalSumNonZero)`.

use p3_batch_stark::ProverData;
use p3_circuit::ops::{
    Poseidon2Config, generate_poseidon2_trace, generate_recompose_trace, perm_private_data,
};
use p3_circuit::{CircuitBuilder, CircuitRunner, NonPrimitiveOpId};
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
use p3_matrix::Matrix;
use p3_matrix::dense::RowMajorMatrix;
use p3_merkle_tree::MerkleTreeMmcs;
use p3_poseidon2_circuit_air::KoalaBearD4Width32;
use p3_recursion::Target;
use p3_recursion::pcs::verify_batch_circuit_arity4;
use p3_symmetric::{PaddingFreeSponge, TruncatedPermutation};

type F = KoalaBear;
type CF = BinomialExtensionField<F, 4>;

type Perm32 = Poseidon2KoalaBear<32>;
type LeafHash = PaddingFreeSponge<Perm32, 32, 24, 8>;
type Compress4 = TruncatedPermutation<Perm32, 4, 8, 32>;
type Mmcs4 = MerkleTreeMmcs<F, F, LeafHash, Compress4, 4, 8>;

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

/// Attach per-op sibling private data, grouping consecutive equal op-ids (3× for step-4, 1× for a
/// step-2 bridge) and padding short groups with zero limbs up to `3 · capacity_ext`.
fn set_sibling_private_data(
    runner: &mut CircuitRunner<'_, CF>,
    op_ids: &[NonPrimitiveOpId],
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
    assert_eq!(proof_idx, opening_proof.len());
}

/// Build an arity-4 verify-batch circuit over `matrices`, witness it at `index`, then prove and
/// verify the resulting tables. Returns `Ok(())` only when the full bus balances.
fn prove_verify_arity4(matrices: Vec<RowMajorMatrix<F>>, log_max_height: usize, index: usize) {
    let perm = default_koalabear_poseidon2_32();
    let leaf_hash = LeafHash::new(perm.clone());
    let compress = Compress4::new(perm.clone());
    let mmcs = Mmcs4::new(leaf_hash, compress, 0);

    let dimensions: Vec<_> = matrices.iter().map(Matrix::dimensions).collect();
    let (commit, prover_data) = mmcs.commit(matrices);
    let batch_opening = mmcs.open_batch(index, &prover_data);

    let mut builder = CircuitBuilder::<CF>::new();
    let permutation_config = Poseidon2Config::KOALA_BEAR_D4_W32;
    let capacity_ext = permutation_config.capacity_ext();
    builder.enable_poseidon2_perm_width_32::<KoalaBearD4Width32, _>(
        generate_poseidon2_trace::<CF, KoalaBearD4Width32>,
        perm,
    );
    builder.enable_recompose::<F>(generate_recompose_trace::<F, CF>);

    let opened: Vec<Vec<Target>> = dimensions
        .iter()
        .map(|dims| (0..dims.width).map(|_| builder.public_input()).collect())
        .collect();
    let directions_expr = builder.alloc_public_inputs(log_max_height, "arity4 directions");
    let lifted_cap: Vec<Target> = (0..(capacity_ext * <CF as BasedVectorSpace<F>>::DIMENSION))
        .map(|_| builder.public_input())
        .collect();
    let d = <CF as BasedVectorSpace<F>>::DIMENSION;
    let cap_packed: Vec<Target> = lifted_cap
        .chunks(d)
        .map(|chunk| {
            let mut acc = builder.define_const(CF::ZERO);
            for (i, &t) in chunk.iter().enumerate() {
                let mut basis = vec![F::ZERO; d];
                basis[i] = F::ONE;
                let b = builder.define_const(CF::from_basis_coefficients_slice(&basis).unwrap());
                acc = builder.mul_add(t, b, acc);
            }
            acc
        })
        .collect();
    let cap_exprs: Vec<Vec<Target>> = vec![cap_packed];

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

    let traces = runner
        .run()
        .expect("runner should witness the arity-4 circuit");

    // Prove and verify the W32 Poseidon2 + recompose tables. A balanced WitnessChecks bus is the
    // assertion: an imbalance from the bridge/injection pad slots or the bit binding surfaces here
    // as `Lookup(TerminalSumNonZero)`.
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
        .verify_all_tables::<CF>(&proof)
        .expect("verify all tables (bus must balance: no TerminalSumNonZero)");
}

/// Bridge fixture: a single height-512 matrix yields the schedule `[4,4,4,4,2]`, whose final
/// step-2 bridge pins chunks 2,3 to the CTL-loaded zero const. Prove+verify must balance.
#[test]
fn arity4_bus_balance_bridge_only() {
    let height = 512usize;
    let width = 4usize;
    let values: Vec<F> = (0..(height * width) as u64).map(F::from_u64).collect();
    let matrix = RowMajorMatrix::new(values, width);
    for index in [0usize, 1, 5, 511] {
        prove_verify_arity4(vec![matrix.clone()], 9, index);
    }
}

/// Injection fixture: heights `{1024, 256}` inject the 256-row matrix at level 0 (chunk 1 carries
/// its W32 leaf-hash digest, chunks 2,3 are pinned zeros) with no bridge. Prove+verify must balance.
#[test]
fn arity4_bus_balance_injection_only() {
    let tall: Vec<F> = (0..(1024u64 * 4)).map(F::from_u64).collect();
    let m_tall = RowMajorMatrix::new(tall, 4);
    let short: Vec<F> = (0..256u64).map(|i| F::from_u64(1_000_000 + i)).collect();
    let m_short = RowMajorMatrix::new(short, 1);
    for index in [0usize, 1, 5, 1023] {
        prove_verify_arity4(vec![m_tall.clone(), m_short.clone()], 10, index);
    }
}
