//! WHIR base-opening packing checks against independently committed native MMCS leaves.
//!

use alloc::boxed::Box;

use p3_baby_bear::{BabyBear, Poseidon1BabyBear, default_babybear_poseidon1_16};
use p3_circuit::ops::poseidon1_perm::{
    BabyBearD4Width16 as P1BabyBearD4Width16, GoldilocksD2Width8 as P1GoldilocksD2Width8,
};
use p3_circuit::ops::{
    GoldilocksD2Width8 as P2GoldilocksD2Width8, NpoTypeId, Op, Poseidon1Config, Poseidon2Config,
    generate_poseidon1_trace, generate_poseidon2_trace, generate_recompose_trace,
};
use p3_circuit::tables::Traces;
use p3_circuit::{Circuit, WitnessId};
use p3_circuit_prover::batch_stark_prover::{
    poseidon1_air_builders_for_configs, poseidon2_air_builders_for_configs, recompose_air_builders,
};
use p3_circuit_prover::common::NpoPreprocessor;
use p3_circuit_prover::config::{BabyBearConfig, GoldilocksConfig};
use p3_circuit_prover::{
    BatchStarkProver, ConstraintProfile, Poseidon1Preprocessor, Poseidon2Preprocessor,
    RecomposePreprocessor, TablePacking, config,
};
use p3_commit::{BatchOpeningRef, Mmcs};
use p3_field::extension::{BinomialExtensionField, QuinticTrinomialExtensionField};
use p3_field::{BasedVectorSpace, PrimeCharacteristicRing};
use p3_goldilocks::poseidon1::{Poseidon1Goldilocks, default_goldilocks_poseidon1_8};
use p3_goldilocks::{Goldilocks, Poseidon2Goldilocks};
use p3_koala_bear::{KoalaBear, Poseidon2KoalaBear, default_koalabear_poseidon2_16};
use p3_matrix::Matrix;
use p3_matrix::dense::RowMajorMatrix;
use p3_merkle_tree::MerkleTreeMmcs;
use p3_poseidon2_circuit_air::{
    KoalaBearD1Width16 as P2KoalaBearD1Width16, KoalaBearD4Width16 as P2KoalaBearD4Width16,
};
use p3_symmetric::{PaddingFreeSponge, Permutation, TruncatedPermutation};

use super::*;
use crate::builtin_config::fixed_goldilocks_poseidon2_8;

type NpoRow<'a> = (&'a [Vec<WitnessId>], &'a [Vec<WitnessId>]);

/// Read the final, canonical witness graph. In particular, never infer packing from debug text.
fn npo_rows<'a, EF: Field>(circuit: &'a Circuit<EF>, op_type: &NpoTypeId) -> Vec<NpoRow<'a>> {
    circuit
        .ops
        .iter()
        .filter_map(|op| match op {
            Op::NonPrimitiveOpWithExecutor {
                inputs,
                outputs,
                executor,
                ..
            } if executor.op_type() == op_type => Some((inputs.as_slice(), outputs.as_slice())),
            _ => None,
        })
        .collect()
}

fn assert_bound_leaf_wiring<EF: Field>(
    circuit: &Circuit<EF>,
    config: PermConfig,
    degree: usize,
    rate: usize,
    width: usize,
    root_limbs: usize,
) {
    let rows = npo_rows(circuit, &NpoTypeId::recompose_with_coeff_lookups());
    let perms = npo_rows(circuit, &config.npo_type_id());
    let full_limbs = rate / degree;
    let expected_rows = full_limbs + if width == rate { 0 } else { 2 };
    assert_eq!(
        rows.len(),
        expected_rows,
        "each pack and carry needs a bound row"
    );
    assert_eq!(perms.len(), if width == rate { 1 } else { 2 });

    for (inputs, outputs) in &rows {
        assert_eq!(inputs.len(), 1, "one coefficient group per bound row");
        assert_eq!(inputs[0].len(), degree, "all D coefficients are consumed");
        assert_eq!(outputs.len(), 1);
        assert_eq!(outputs[0].len(), 1);
    }

    let (first_inputs, first_outputs) = perms[0];
    for limb in 0..full_limbs {
        assert_eq!(
            first_inputs[limb][0], rows[limb].1[0][0],
            "first absorb must use the bound pack output"
        );
        for coefficient in 0..degree {
            assert_eq!(
                rows[limb].0[0][coefficient],
                circuit.public_rows[root_limbs + limb * degree + coefficient],
                "each full pack uses the correct public leaf coefficients"
            );
        }
    }

    if width > rate {
        let (carry_inputs, carry_outputs) = rows[full_limbs];
        let (partial_inputs, partial_outputs) = rows[full_limbs + 1];
        let (second_inputs, _) = perms[1];
        assert_eq!(
            carry_outputs[0][0], first_outputs[0][0],
            "the carry decomposition reconstructs the preceding permutation output"
        );
        assert_eq!(
            partial_inputs[0][0],
            circuit.public_rows[root_limbs + rate],
            "the partial repack consumes the new public leaf coefficient"
        );
        assert_eq!(
            &partial_inputs[0][1..],
            &carry_inputs[0][1..],
            "the remaining coefficients come from the prior output's carry decomposition"
        );
        assert_eq!(
            second_inputs[0][0], partial_outputs[0][0],
            "the second absorb consumes the bound partial repack output"
        );
    }

    // A direct bound-row output must feed each packed permutation limb. An ALU substitute
    // cannot have the same canonical output witness in this operation slice.
    for (_, outputs) in rows {
        let packed = outputs[0][0];
        assert!(
            !circuit
                .ops
                .iter()
                .any(|op| { matches!(op, Op::Alu { out, .. } if *out == packed) })
        );
    }
}

macro_rules! family {
    (
        $name:ident, $field:ty, $extension:ty, $permutation:ty,
        $width:expr, $rate:expr, $digest:expr, $degree:expr,
        $permutation_config:expr, $make_permutation:expr, $enable:expr,
        $stark_config:ty, $make_stark_config:expr, $air_builders:expr,
        $preprocessor:expr, $register:ident, $public_bound:expr
    ) => {
        mod $name {
            use super::*;

            type F = $field;
            type EF = $extension;
            type Perm = $permutation;
            type LeafHash = PaddingFreeSponge<Perm, $width, $rate, $digest>;
            type Compress = TruncatedPermutation<Perm, 2, $digest, $width>;
            type NativeMmcs = MerkleTreeMmcs<F, F, LeafHash, Compress, 2, $digest>;
            const D: usize = $degree;
            const RATE: usize = $rate;

            fn cfg() -> PermConfig {
                PermConfig::from($permutation_config)
            }

            struct Fixture {
                circuit: Circuit<EF>,
                traces: Traces<EF>,
                public_inputs: Vec<EF>,
                root_limbs: usize,
                width: usize,
            }

            fn fixture_with_route(width: usize, whir_route: bool) -> Fixture {
                assert!(width == RATE || width == RATE + 1);
                let perm: Perm = $make_permutation;
                let mmcs = NativeMmcs::new(LeafHash::new(perm.clone()), Compress::new(perm), 0);
                let leaf: Vec<F> = (0..width).map(|i| F::from_u64(100 + i as u64)).collect();
                let matrix = RowMajorMatrix::new(leaf.clone(), width);
                let dimensions = [matrix.dimensions()];
                let (commitment, prover_data) = mmcs.commit(vec![matrix]);
                let opening = mmcs.open_batch(0, &prover_data);
                mmcs.verify_batch(
                    &commitment,
                    &dimensions,
                    0,
                    BatchOpeningRef::new(&opening.opened_values, &opening.opening_proof),
                )
                .expect("native opening verifies against the independently computed root");
                assert_eq!(opening.opened_values[0], leaf);

                let mut builder = CircuitBuilder::<EF>::new();
                ($enable)(&mut builder);
                builder.enable_recompose::<F>(generate_recompose_trace::<F, EF>);

                let cap: Vec<Vec<Target>> = commitment
                    .roots()
                    .iter()
                    .map(|root| root.chunks(D).map(|_| builder.public_input()).collect())
                    .collect();
                let leaf_targets = vec![(0..width).map(|_| builder.public_input()).collect()];
                if whir_route {
                    verify_whir_base_batch_circuit::<F, EF>(
                        &mut builder,
                        cfg(),
                        &cap,
                        &dimensions,
                        &[],
                        &leaf_targets,
                    )
                } else {
                    verify_batch_circuit::<F, EF>(
                        &mut builder,
                        cfg(),
                        &cap,
                        &dimensions,
                        &[],
                        &leaf_targets,
                        None,
                    )
                }
                .expect("base MMCS opening circuit builds");
                let circuit = builder.build().expect("base MMCS opening circuit compiles");

                let mut public_inputs: Vec<EF> = commitment
                    .roots()
                    .iter()
                    .flat_map(|root| {
                        root.chunks(D).map(|chunk| {
                            EF::from_basis_coefficients_slice(chunk)
                                .expect("native root packs into the extension field")
                        })
                    })
                    .collect();
                let root_limbs = public_inputs.len();
                public_inputs.extend(leaf.iter().copied().map(EF::from));
                let mut runner = circuit.runner();
                runner.set_public_inputs(&public_inputs).unwrap();
                let traces = runner
                    .run()
                    .expect("honest native MMCS root matches the circuit");

                Fixture {
                    circuit,
                    traces,
                    public_inputs,
                    root_limbs,
                    width,
                }
            }

            fn fixture(width: usize) -> Fixture {
                fixture_with_route(width, true)
            }

            fn prove_and_verify(fixture: &Fixture) {
                let preprocessors: Vec<Box<dyn NpoPreprocessor<F>>> = vec![
                    Box::new($preprocessor),
                    Box::new(RecomposePreprocessor::new(true)),
                ];
                let mut air_builders = $air_builders;
                air_builders.extend(recompose_air_builders::<$stark_config, D>(1, true));
                let mut prover = BatchStarkProver::new($make_stark_config)
                    .with_table_packing(TablePacking::new(1, 1));
                prover.$register::<D>($permutation_config);
                prover.register_recompose_table::<D>(true);
                let prepared = prover
                    .prepare_circuit::<EF, D>(
                        &fixture.circuit,
                        &preprocessors,
                        &air_builders,
                        ConstraintProfile::Standard,
                    )
                    .expect("canonical P1/P2 and split recompose tables prepare");
                let verifier = prepared.verifier();
                let proof = prepared
                    .prove(&fixture.traces)
                    .expect("honest MMCS circuit proves");
                verifier
                    .verify(&proof, &[])
                    .expect("honest MMCS proof verifies");
            }

            fn reject_wrong_public_values(fixture: &Fixture) {
                let mut changed_leaf = fixture.public_inputs.clone();
                changed_leaf[fixture.root_limbs] += EF::ONE;
                let mut runner = fixture.circuit.runner();
                runner.set_public_inputs(&changed_leaf).unwrap();
                assert!(
                    runner.run().is_err(),
                    "wrong public leaf must fail authentication"
                );

                let mut changed_root = fixture.public_inputs.clone();
                changed_root[0] += EF::ONE;
                let mut runner = fixture.circuit.runner();
                runner.set_public_inputs(&changed_root).unwrap();
                assert!(
                    runner.run().is_err(),
                    "wrong public root must fail authentication"
                );
            }

            #[test]
            fn bound_full_and_partial_leaves_with_honest_proofs() {
                for width in [RATE, RATE + 1] {
                    let fixture = fixture(width);
                    assert_eq!(fixture.width, width);
                    assert_bound_leaf_wiring(
                        &fixture.circuit,
                        cfg(),
                        D,
                        RATE,
                        width,
                        fixture.root_limbs,
                    );
                    prove_and_verify(&fixture);
                    reject_wrong_public_values(&fixture);
                }
            }

            #[test]
            fn public_route_preserves_its_packing_policy() {
                let fixture = fixture_with_route(RATE + 1, false);
                let bound_rows =
                    npo_rows(&fixture.circuit, &NpoTypeId::recompose_with_coeff_lookups());
                if $public_bound {
                    assert_bound_leaf_wiring(
                        &fixture.circuit,
                        cfg(),
                        D,
                        RATE,
                        RATE + 1,
                        fixture.root_limbs,
                    );
                } else {
                    assert!(
                        bound_rows.is_empty(),
                        "public/default route keeps legacy ALU packing"
                    );
                }
            }
        }
    };
}

family!(
    gold_p2,
    Goldilocks,
    BinomialExtensionField<Goldilocks, 2>,
    Poseidon2Goldilocks<8>,
    8, 4, 4, 2,
    Poseidon2Config::GOLDILOCKS_D2_W8,
    fixed_goldilocks_poseidon2_8(),
    |builder: &mut CircuitBuilder<BinomialExtensionField<Goldilocks, 2>>| {
        builder.enable_poseidon2_perm_width_8::<P2GoldilocksD2Width8, _>(
            generate_poseidon2_trace::<BinomialExtensionField<Goldilocks, 2>, P2GoldilocksD2Width8>,
            fixed_goldilocks_poseidon2_8(),
        );
    },
    GoldilocksConfig,
    config::goldilocks(),
    poseidon2_air_builders_for_configs::<GoldilocksConfig, 2>(vec![Poseidon2Config::GOLDILOCKS_D2_W8]),
    Poseidon2Preprocessor,
    register_poseidon2_table,
    false
);

family!(
    baby_p1,
    BabyBear,
    BinomialExtensionField<BabyBear, 4>,
    Poseidon1BabyBear<16>,
    16, 8, 8, 4,
    Poseidon1Config::BABY_BEAR_D4_W16,
    default_babybear_poseidon1_16(),
    |builder: &mut CircuitBuilder<BinomialExtensionField<BabyBear, 4>>| {
        builder.enable_poseidon1_perm::<P1BabyBearD4Width16, _>(
            generate_poseidon1_trace::<BinomialExtensionField<BabyBear, 4>, P1BabyBearD4Width16>,
            default_babybear_poseidon1_16(),
        );
    },
    BabyBearConfig,
    config::baby_bear(),
    poseidon1_air_builders_for_configs::<BabyBearConfig, 4>(vec![Poseidon1Config::BABY_BEAR_D4_W16]),
    Poseidon1Preprocessor,
    register_poseidon1_table,
    false
);

family!(
    gold_p1,
    Goldilocks,
    BinomialExtensionField<Goldilocks, 2>,
    Poseidon1Goldilocks<8>,
    8, 4, 4, 2,
    Poseidon1Config::GOLDILOCKS_D2_W8,
    default_goldilocks_poseidon1_8(),
    |builder: &mut CircuitBuilder<BinomialExtensionField<Goldilocks, 2>>| {
        builder.enable_poseidon1_perm_width_8::<P1GoldilocksD2Width8, _>(
            generate_poseidon1_trace::<BinomialExtensionField<Goldilocks, 2>, P1GoldilocksD2Width8>,
            default_goldilocks_poseidon1_8(),
        );
    },
    GoldilocksConfig,
    config::goldilocks(),
    poseidon1_air_builders_for_configs::<GoldilocksConfig, 2>(vec![Poseidon1Config::GOLDILOCKS_D2_W8]),
    Poseidon1Preprocessor,
    register_poseidon1_table,
    false
);

family!(
    koala_p2,
    KoalaBear,
    BinomialExtensionField<KoalaBear, 4>,
    Poseidon2KoalaBear<16>,
    16, 8, 8, 4,
    Poseidon2Config::KOALA_BEAR_D4_W16,
    default_koalabear_poseidon2_16(),
    |builder: &mut CircuitBuilder<BinomialExtensionField<KoalaBear, 4>>| {
        builder.enable_poseidon2_perm::<P2KoalaBearD4Width16, _>(
            generate_poseidon2_trace::<BinomialExtensionField<KoalaBear, 4>, P2KoalaBearD4Width16>,
            default_koalabear_poseidon2_16(),
        );
    },
    p3_circuit_prover::config::KoalaBearConfig,
    config::koala_bear(),
    poseidon2_air_builders_for_configs::<p3_circuit_prover::config::KoalaBearConfig, 4>(vec![Poseidon2Config::KOALA_BEAR_D4_W16]),
    Poseidon2Preprocessor,
    register_poseidon2_table,
    true
);

type KoalaQuintic = QuinticTrinomialExtensionField<KoalaBear>;

#[derive(Clone)]
struct LiftKoalaPermutation(Poseidon2KoalaBear<16>);

impl Permutation<[KoalaQuintic; 16]> for LiftKoalaPermutation {
    fn permute(&self, input: [KoalaQuintic; 16]) -> [KoalaQuintic; 16] {
        let base: [KoalaBear; 16] =
            core::array::from_fn(|i| input[i].as_basis_coefficients_slice()[0]);
        self.0.permute(base).map(KoalaQuintic::from)
    }
}

fn koala_d1_leaf_and_root() -> (Vec<KoalaBear>, Vec<KoalaBear>, [Dimensions; 1]) {
    type Hash = PaddingFreeSponge<Poseidon2KoalaBear<16>, 16, 8, 8>;
    type Compress = TruncatedPermutation<Poseidon2KoalaBear<16>, 2, 8, 16>;
    type NativeMmcs = MerkleTreeMmcs<KoalaBear, KoalaBear, Hash, Compress, 2, 8>;
    let perm = default_koalabear_poseidon2_16();
    let mmcs = NativeMmcs::new(Hash::new(perm.clone()), Compress::new(perm), 0);
    let leaf: Vec<KoalaBear> = (0..8).map(|i| KoalaBear::from_u64(i + 37)).collect();
    let matrix = RowMajorMatrix::new(leaf.clone(), 8);
    let dims = [matrix.dimensions()];
    let (commitment, prover_data) = mmcs.commit(vec![matrix]);
    let opening = mmcs.open_batch(0, &prover_data);
    mmcs.verify_batch(
        &commitment,
        &dims,
        0,
        BatchOpeningRef::new(&opening.opened_values, &opening.opening_proof),
    )
    .expect("native D1 opening verifies");
    (leaf, commitment.roots()[0].to_vec(), dims)
}

#[test]
fn whir_d1_over_d5_keeps_direct_lift_without_recompose() {
    let (leaf, root, dims) = koala_d1_leaf_and_root();
    let mut builder = CircuitBuilder::<KoalaQuintic>::new();
    builder.enable_poseidon2_perm_base::<P2KoalaBearD1Width16, _>(
        generate_poseidon2_trace::<KoalaQuintic, P2KoalaBearD1Width16>,
        LiftKoalaPermutation(default_koalabear_poseidon2_16()),
    );
    let root_targets = vec![(0..8).map(|_| builder.public_input()).collect()];
    let leaf_targets = vec![(0..8).map(|_| builder.public_input()).collect()];
    verify_whir_base_batch_circuit::<KoalaBear, KoalaQuintic>(
        &mut builder,
        Poseidon2Config::KOALA_BEAR_D1_W16,
        &root_targets,
        &dims,
        &[],
        &leaf_targets,
    )
    .expect("D1-over-D5 wrapper retains the direct-lift shape without recompose enabled");
    let circuit = builder.build().unwrap();
    assert!(npo_rows(&circuit, &NpoTypeId::recompose_with_coeff_lookups()).is_empty());
    assert!(npo_rows(&circuit, &NpoTypeId::recompose()).is_empty());
    let perms = npo_rows(
        &circuit,
        &NpoTypeId::poseidon2_perm(Poseidon2Config::KOALA_BEAR_D1_W16),
    );
    assert_eq!(perms.len(), 1);
    for i in 0..8 {
        assert_eq!(perms[0].0[i][0], circuit.public_rows[8 + i]);
    }
    let public: Vec<KoalaQuintic> = root
        .into_iter()
        .chain(leaf)
        .map(KoalaQuintic::from)
        .collect();
    let mut runner = circuit.runner();
    runner.set_public_inputs(&public).unwrap();
    runner
        .run()
        .expect("honest D1-over-D5 native root verifies");
}

#[test]
fn whir_ef1_fallback_needs_no_recompose_table() {
    let (leaf, root, dims) = koala_d1_leaf_and_root();
    let mut builder = CircuitBuilder::<KoalaBear>::new();
    builder.enable_poseidon2_perm_base::<P2KoalaBearD1Width16, _>(
        generate_poseidon2_trace::<KoalaBear, P2KoalaBearD1Width16>,
        default_koalabear_poseidon2_16(),
    );
    let root_targets = vec![(0..8).map(|_| builder.public_input()).collect()];
    let leaf_targets = vec![(0..8).map(|_| builder.public_input()).collect()];
    verify_whir_base_batch_circuit::<KoalaBear, KoalaBear>(
        &mut builder,
        Poseidon2Config::KOALA_BEAR_D1_W16,
        &root_targets,
        &dims,
        &[],
        &leaf_targets,
    )
    .expect("EF1 wrapper must not newly require enable_recompose");
    let circuit = builder.build().unwrap();
    assert!(npo_rows(&circuit, &NpoTypeId::recompose_with_coeff_lookups()).is_empty());
    let mut runner = circuit.runner();
    let public: Vec<KoalaBear> = root.into_iter().chain(leaf).collect();
    runner.set_public_inputs(&public).unwrap();
    runner.run().expect("honest EF1 native root verifies");
}
