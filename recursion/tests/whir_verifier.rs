//! Field/config matrix for the WHIR recursive verifier.
//!
//! Exercises `verify_whir_circuit` under configurations beyond the unit-test
//! baseline (BabyBear D4, 1 round):
//!   - BabyBear D4, 2 rounds — tests the generic multi-round loop and
//!     the Extension-leaf query path that only appears in rounds ≥ 1.
//!   - KoalaBear D4, 1 round — verifies the generic field typing.

use std::collections::VecDeque;

use p3_baby_bear::{BabyBear, Poseidon2BabyBear};
use p3_challenger::{
    CanObserve, CanSample, CanSampleUniformBits, DuplexChallenger, FieldChallenger,
};
use p3_circuit::{CircuitBuilder, CircuitBuilderError};
use p3_commit::MultilinearPcs;
use p3_dft::Radix2DFTSmallBatch;
use p3_field::extension::BinomialExtensionField;
use p3_field::{Field, PrimeCharacteristicRing};
use p3_koala_bear::{KoalaBear, Poseidon2KoalaBear};
use p3_merkle_tree::MerkleTreeMmcs;
use p3_multilinear_util::poly::Poly;
use p3_recursion::Target;
use p3_recursion::pcs::whir::{
    ConstraintWeightData, WhirProofTargets, WhirVerifierParams, verify_whir_circuit,
};
use p3_recursion::traits::RecursiveChallenger;
use p3_sumcheck::layout::{Layout, PrefixProver, Table, Verifier};
use p3_sumcheck::{OpeningProtocol, TableShape, TableSpec};
use p3_symmetric::{PaddingFreeSponge, TruncatedPermutation};
use p3_util::log2_strict_usize;
use p3_whir::fiat_shamir::domain_separator::DomainSeparator;
use p3_whir::parameters::{FoldingFactor, ProtocolParameters, SecurityAssumption, WhirConfig};
use p3_whir::pcs::prover::WhirProver;
use rand::SeedableRng;
use rand::rngs::SmallRng;

/// Replay the WHIR Fiat–Shamir transcript over a native `DuplexChallenger` and
/// collect the extension / base samples the `MockChallenger` must return.
///
/// Generic over any number of WHIR rounds; works for both BabyBear and KoalaBear.
macro_rules! whir_arithmetic_test {
    (
        $modname:ident,
        $BF:ty,
        $make_perm:expr,
        $Perm:ty,
        $EF:ty,
        $poseidon_cfg:expr,
        $num_vars:expr,
        $folding:expr,
        $round_log_inv_rates:expr
    ) => {
        mod $modname {
            use super::*;

            type BF = $BF;
            type EF = $EF;
            type Perm = $Perm;
            type MyHash = PaddingFreeSponge<Perm, 16, 8, 8>;
            type MyCompress = TruncatedPermutation<Perm, 2, 8, 16>;
            type PackedBF = <BF as Field>::Packing;
            type MyMmcs = MerkleTreeMmcs<PackedBF, PackedBF, MyHash, MyCompress, 2, 8>;
            type MyDft = Radix2DFTSmallBatch<BF>;
            type MyChallenger = DuplexChallenger<BF, Perm, 16, 8>;
            type TestPcs = WhirProver<EF, BF, MyDft, MyMmcs, MyChallenger, PrefixProver<BF, EF>>;

            fn make_perm() -> Perm {
                ($make_perm)()
            }
            fn make_challenger() -> MyChallenger {
                MyChallenger::new(make_perm())
            }

            struct MockChallenger {
                ext_samples: VecDeque<EF>,
                base_samples: VecDeque<BF>,
            }

            impl RecursiveChallenger<BF, EF> for MockChallenger {
                fn observe(&mut self, _: &mut CircuitBuilder<EF>, _: Target) {}
                fn observe_ext(&mut self, _: &mut CircuitBuilder<EF>, _: Target) {}

                fn sample(&mut self, circuit: &mut CircuitBuilder<EF>) -> Target {
                    let v = self.base_samples.pop_front().expect("base exhausted");
                    circuit.define_const(EF::from(v))
                }

                fn sample_ext(&mut self, circuit: &mut CircuitBuilder<EF>) -> Target {
                    let v = self.ext_samples.pop_front().expect("ext exhausted");
                    circuit.define_const(v)
                }

                fn sample_bits(
                    &mut self,
                    circuit: &mut CircuitBuilder<EF>,
                    k: usize,
                ) -> Result<Vec<Target>, CircuitBuilderError> {
                    let raw = self.base_samples.pop_front().expect("base exhausted");
                    let raw_target = circuit.define_const(EF::from(raw));
                    let bits = circuit.decompose_to_bits::<BF>(raw_target, BF::bits())?;
                    Ok(bits[..k].to_vec())
                }

                fn check_pow_witness(
                    &mut self,
                    _: &mut CircuitBuilder<EF>,
                    _: usize,
                    _: Target,
                ) -> Result<(), CircuitBuilderError> {
                    Ok(())
                }

                fn clear(&mut self, _: &mut CircuitBuilder<EF>) {}
            }

            fn sample_stir_indices(
                vc: &mut MyChallenger,
                domain_size: usize,
                folding_factor: usize,
                num_queries: usize,
            ) -> Vec<usize> {
                let folded = domain_size >> folding_factor;
                let k = log2_strict_usize(folded);
                let target = num_queries.min(folded);
                let mut indices: Vec<usize> = Vec::new();
                while indices.len() < target {
                    let q = vc
                        .sample_uniform_bits::<true>(k)
                        .expect("sample_uniform_bits");
                    if !indices.contains(&q) {
                        indices.push(q);
                    }
                }
                indices.sort_unstable();
                indices
            }

            #[test]
            fn arithmetic_only_passes() {
                const NUM_VARIABLES: usize = $num_vars;
                const FOLDING: usize = $folding;

                let perm = make_perm();
                let hash = MyHash::new(perm.clone());
                let compress = MyCompress::new(perm);
                let mmcs = MyMmcs::new(hash, compress, 0);
                let dft = MyDft::default();

                let spec = TableSpec::new(TableShape::new(NUM_VARIABLES, 1), vec![vec![0]]);
                let protocol = OpeningProtocol::new(vec![spec]).pad_to_min_num_variables(FOLDING);
                let poly = Poly::<BF>::rand(&mut SmallRng::seed_from_u64(42), NUM_VARIABLES);
                let witness =
                    PrefixProver::<BF, EF>::new_witness(vec![Table::new(vec![poly])], FOLDING);

                let whir_params = ProtocolParameters {
                    security_level: 32,
                    pow_bits: 0,
                    round_log_inv_rates: $round_log_inv_rates,
                    folding_factor: FoldingFactor::Constant(FOLDING),
                    soundness_type: SecurityAssumption::CapacityBound,
                    starting_log_inv_rate: 1,
                };
                let config =
                    WhirConfig::<EF, BF, MyChallenger>::new(NUM_VARIABLES, whir_params).unwrap();
                let pcs = TestPcs::new(config.clone(), dft, mmcs);

                let (commitment, proof) = {
                    let mut ch = make_challenger();
                    let mut ds = DomainSeparator::new(vec![]);
                    pcs.add_domain_separator::<8>(&mut ds);
                    ds.observe_domain_separator(&mut ch);
                    let (commitment, prover_data) =
                        <TestPcs as MultilinearPcs<EF, MyChallenger>>::commit(
                            &pcs, witness, &mut ch,
                        );
                    let proof = <TestPcs as MultilinearPcs<EF, MyChallenger>>::open(
                        &pcs,
                        prover_data,
                        protocol.clone(),
                        &mut ch,
                    );
                    (commitment, proof)
                };

                let (initial_constraint, initial_claimed_eval, mut vc) = {
                    let mut ch = make_challenger();
                    let mut ds = DomainSeparator::new(vec![]);
                    pcs.add_domain_separator::<8>(&mut ds);
                    ds.observe_domain_separator(&mut ch);
                    ch.observe(commitment.clone());
                    let mut lv = Verifier::<BF, EF>::new(
                        &protocol.table_shapes(),
                        PrefixProver::<BF, EF>::strategy(),
                    );
                    for &eval in &proof.whir.initial_ood_answers {
                        lv.add_virtual_eval(eval, &mut ch);
                    }
                    for ((table_idx, polys), evals) in protocol.iter_openings().zip(&proof.evals) {
                        lv.add_claim(table_idx, polys, evals, &mut ch);
                    }
                    let alpha: EF = ch.sample_algebra_element();
                    let constraint = lv.constraint(alpha);
                    let mut claimed_eval = EF::ZERO;
                    constraint.combine_evals(&mut claimed_eval);
                    (constraint, claimed_eval, ch)
                };

                // Replay Fiat–Shamir transcript across all rounds.
                let mut ext_samples: Vec<EF> = Vec::new();
                let mut base_samples: Vec<BF> = Vec::new();

                for &[c0, cinf] in proof.whir.initial_sumcheck.polynomial_evaluations() {
                    vc.observe_algebra_element(c0);
                    vc.observe_algebra_element(cinf);
                    ext_samples.push(vc.sample_algebra_element());
                }
                for (rproof, rp) in proof.whir.rounds.iter().zip(&config.round_parameters) {
                    vc.observe(
                        rproof
                            .commitment
                            .as_ref()
                            .expect("round commitment")
                            .clone(),
                    );
                    for &answer in &rproof.ood_answers {
                        ext_samples.push(vc.sample_algebra_element());
                        vc.observe_algebra_element(answer);
                    }
                    let checkpoint: BF = CanSample::sample(&mut vc);
                    base_samples.push(checkpoint);
                    let indices = sample_stir_indices(
                        &mut vc,
                        rp.domain_size,
                        rp.folding_factor,
                        rp.num_queries,
                    );
                    for &idx in &indices {
                        base_samples.push(BF::from_u64(idx as u64));
                    }
                    ext_samples.push(vc.sample_algebra_element());
                    for &[c0, cinf] in rproof.sumcheck.polynomial_evaluations() {
                        vc.observe_algebra_element(c0);
                        vc.observe_algebra_element(cinf);
                        ext_samples.push(vc.sample_algebra_element());
                    }
                }
                {
                    let fp = proof.whir.final_poly.as_ref().expect("final_poly");
                    vc.observe_algebra_slice(fp.as_slice());
                    let fin_rc = config.final_round_config();
                    let final_indices = sample_stir_indices(
                        &mut vc,
                        fin_rc.domain_size,
                        config.final_sumcheck_rounds,
                        config.final_queries,
                    );
                    for &idx in &final_indices {
                        base_samples.push(BF::from_u64(idx as u64));
                    }
                    if let Some(ref fsc) = proof.whir.final_sumcheck {
                        for &[c0, cinf] in fsc.polynomial_evaluations() {
                            vc.observe_algebra_element(c0);
                            vc.observe_algebra_element(cinf);
                            ext_samples.push(vc.sample_algebra_element());
                        }
                    }
                }

                let vp =
                    WhirVerifierParams::<BF>::unsafe_arithmetic_only_for_tests::<EF, MyChallenger>(
                        &config,
                        PrefixProver::<BF, EF>::variable_order(),
                        $poseidon_cfg,
                    );

                let mut circuit = CircuitBuilder::<EF>::new();
                let proof_targets = WhirProofTargets::alloc::<BF, EF>(&mut circuit, &vp, 1, 1);
                let initial_cap: Vec<Vec<Target>> = vec![vec![circuit.define_const(EF::ZERO)]];
                let gamma_target = circuit.define_const(initial_constraint.challenge);
                let eq_points: Vec<Vec<Target>> = initial_constraint
                    .eq_statement
                    .points
                    .iter()
                    .map(|pt| {
                        pt.as_slice()
                            .iter()
                            .map(|&e| circuit.define_const(e))
                            .collect()
                    })
                    .collect();
                let circuit_constraint = ConstraintWeightData {
                    num_variables: initial_constraint.eq_statement.num_variables(),
                    eq_points,
                    sel_scalars: vec![],
                    gamma: gamma_target,
                };
                let initial_claimed_eval_target = circuit.define_const(initial_claimed_eval);

                let mut mock = MockChallenger {
                    ext_samples: ext_samples.into_iter().collect(),
                    base_samples: base_samples.into_iter().collect(),
                };
                verify_whir_circuit::<BF, EF, MockChallenger>(
                    &mut circuit,
                    &mut mock,
                    &vp,
                    &proof_targets,
                    &initial_cap,
                    circuit_constraint,
                    initial_claimed_eval_target,
                )
                .expect("verify_whir_circuit failed");

                assert!(
                    mock.ext_samples.is_empty(),
                    "unused ext_samples: {}",
                    mock.ext_samples.len()
                );
                assert!(
                    mock.base_samples.is_empty(),
                    "unused base_samples: {}",
                    mock.base_samples.len()
                );

                let circuit = circuit.build().expect("circuit build failed");

                // Assemble public inputs: loop generically over all rounds.
                let mut public_inputs: Vec<EF> = Vec::new();
                for &v in &proof.whir.initial_ood_answers {
                    public_inputs.push(v);
                }
                for &[c0, cinf] in proof.whir.initial_sumcheck.polynomial_evaluations() {
                    public_inputs.push(c0);
                    public_inputs.push(cinf);
                }
                for r in &proof.whir.rounds {
                    public_inputs.push(EF::ZERO); // dummy cap placeholder
                    for &v in &r.ood_answers {
                        public_inputs.push(v);
                    }
                    public_inputs.push(EF::from(r.pow_witness));
                    for &[c0, cinf] in r.sumcheck.polynomial_evaluations() {
                        public_inputs.push(c0);
                        public_inputs.push(cinf);
                    }
                }
                for &v in proof.whir.final_poly.as_ref().unwrap().as_slice() {
                    public_inputs.push(v);
                }
                public_inputs.push(EF::from(proof.whir.final_pow_witness));
                if let Some(ref fsc) = proof.whir.final_sumcheck {
                    for &[c0, cinf] in fsc.polynomial_evaluations() {
                        public_inputs.push(c0);
                        public_inputs.push(cinf);
                    }
                }

                // Private inputs: query leaf values across all rounds.
                let mut private_inputs: Vec<EF> = Vec::new();
                for r in &proof.whir.rounds {
                    for q in &r.queries {
                        match q {
                            p3_whir::pcs::proof::QueryOpening::Base { values, .. } => {
                                for &v in values {
                                    private_inputs.push(EF::from(v));
                                }
                            }
                            p3_whir::pcs::proof::QueryOpening::Extension { values, .. } => {
                                for &v in values {
                                    private_inputs.push(v);
                                }
                            }
                        }
                    }
                }
                for q in &proof.whir.final_queries {
                    match q {
                        p3_whir::pcs::proof::QueryOpening::Base { values, .. } => {
                            for &v in values {
                                private_inputs.push(EF::from(v));
                            }
                        }
                        p3_whir::pcs::proof::QueryOpening::Extension { values, .. } => {
                            for &v in values {
                                private_inputs.push(v);
                            }
                        }
                    }
                }

                let mut runner = circuit.runner();
                runner
                    .set_public_inputs(&public_inputs)
                    .expect("set_public_inputs");
                runner
                    .set_private_inputs(&private_inputs)
                    .expect("set_private_inputs");
                runner.run().expect("circuit run failed");
            }
        }
    };
}

use p3_baby_bear::default_babybear_poseidon2_16;
use p3_koala_bear::default_koalabear_poseidon2_16;

whir_arithmetic_test!(
    babybear_d4_2rounds,
    BabyBear,
    default_babybear_poseidon2_16,
    Poseidon2BabyBear<16>,
    BinomialExtensionField<BabyBear, 4>,
    p3_circuit::ops::Poseidon2Config::BABY_BEAR_D4_W16,
    16,
    4,
    vec![4usize, 4]
);

whir_arithmetic_test!(
    koalabear_d4_1round,
    KoalaBear,
    default_koalabear_poseidon2_16,
    Poseidon2KoalaBear<16>,
    BinomialExtensionField<KoalaBear, 4>,
    p3_circuit::ops::Poseidon2Config::KOALA_BEAR_D4_W16,
    12,
    4,
    vec![4usize]
);
