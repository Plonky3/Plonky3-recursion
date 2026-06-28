//! In-circuit WHIR verifier — mirrors `WhirVerifier::verify`.
//!
//! [`verify_whir_circuit`] replays the WHIR Fiat–Shamir transcript and
//! enforces every arithmetic check gate-for-gate against the native verifier
//! in `p3-whir`. The caller is responsible for wiring the returned
//! [`NonPrimitiveOpId`]s to their private Merkle-path data.
//!
//! # Split of concerns
//!
//! This function mirrors `WhirVerifier::verify` (not the full PCS adapter).
//! The adapter's work — observing the initial commitment, sampling initial OOD
//! points, processing opening claims, and sampling the batching challenge α —
//! belongs in items G/H/I and is passed in by the caller as `initial_constraint`
//! and `initial_claimed_eval`.

use alloc::vec;
use alloc::vec::Vec;

use p3_circuit::{CircuitBuilder, CircuitBuilderError, NonPrimitiveOpId};
use p3_field::{ExtensionField, PrimeField64, TwoAdicField};
use p3_matrix::Dimensions;
use p3_sumcheck::strategy::VariableOrder;

use super::params::WhirVerifierParams;
use crate::Target;
use crate::pcs::mmcs::{verify_batch_circuit, verify_batch_circuit_from_extension_opened};
use crate::pcs::whir::gadgets::{
    ConstraintWeightData, eval_constraints_poly_circuit, eval_multilinear, eval_powers_combination,
    expand_from_univariate, horner_eval, pow_const_base,
};
use crate::pcs::whir::sumcheck::verify_sumcheck_rounds;
use crate::pcs::whir::targets::{QueryOpeningTargets, WhirProofTargets};
use crate::traits::RecursiveChallenger;

/// Verify a WHIR proof in-circuit.
///
/// Mirrors `WhirVerifier::verify` from `p3-whir`: replays the transcript, checks
/// all PoW witnesses, verifies STIR query MMCS paths, folds leaves, runs all
/// sumchecks, and enforces the final `claimed_eval == W(r) * f(r)` identity.
///
/// # Parameters
///
/// - `params` — Verifier parameters derived from `WhirConfig` (see [`WhirVerifierParams`]).
/// - `proof` — Circuit-target mirror of the WHIR proof (see [`WhirProofTargets`]).
/// - `initial_commitment_cap` — Merkle cap of the initial commitment; used as
///   `prev_commitment` for round-0 STIR query MMCS verification.  Comes from
///   the PCS adapter (items G/H).
/// - `initial_constraint` — Constraint data for the initial polynomial
///   (OOD eq points, opening select scalars, batching gamma).  Built by the
///   caller from the initial OOD sampling and opening claims (items H/I).
/// - `initial_claimed_eval` — The initial claimed sumcheck sum formed by the
///   adapter from the opening claim evaluations and OOD answers.
///
/// # Returns
///
/// A list of [`NonPrimitiveOpId`]s, one per MMCS path verification, in the
/// order they were verified (initial-round queries first, then per-round, then
/// final-round queries).  The caller must supply private path data for each ID.
///
/// When `params.permutation_config` is `None` (arithmetic-only, unsound test mode),
/// no MMCS verification is performed and an empty list is returned.
pub fn verify_whir_circuit<BF, EF, Ch>(
    circuit: &mut CircuitBuilder<EF>,
    challenger: &mut Ch,
    params: &WhirVerifierParams<BF>,
    proof: &WhirProofTargets,
    initial_commitment_cap: &[Vec<Target>],
    initial_constraint: ConstraintWeightData,
    initial_claimed_eval: Target,
) -> Result<Vec<NonPrimitiveOpId>, CircuitBuilderError>
where
    BF: PrimeField64 + TwoAdicField,
    EF: ExtensionField<BF> + TwoAdicField,
    Ch: RecursiveChallenger<BF, EF>,
{
    let is_suffix = params.variable_order == VariableOrder::Suffix;

    let mut all_np_ops: Vec<NonPrimitiveOpId> = Vec::new();
    let mut all_constraints: Vec<ConstraintWeightData> = vec![initial_constraint];
    let mut all_r: Vec<Target> = Vec::new();
    let mut claimed_eval = initial_claimed_eval;

    // ── Initial sumcheck ──────────────────────────────────────────────────────
    let (new_claim, initial_r) = verify_sumcheck_rounds::<BF, EF, Ch>(
        circuit,
        challenger,
        claimed_eval,
        &proof.initial_sumcheck.round_polys,
        &proof.initial_sumcheck.pow_witnesses,
        params.starting_folding_pow_bits,
    )?;
    claimed_eval = new_claim;
    let mut last_r = initial_r.clone();
    all_r.extend_from_slice(&initial_r);

    // ── Intermediate round loop ───────────────────────────────────────────────
    let mut prev_cap: Vec<Vec<Target>> = initial_commitment_cap.to_vec();

    for (round_idx, rp) in params.round_params.iter().enumerate() {
        let round_proof = &proof.rounds[round_idx];

        // 1. Observe round commitment cap (public inputs, already in transcript order).
        for cap_entry in &round_proof.commitment_cap {
            challenger.observe_slice(circuit, cap_entry);
        }

        // 2. OOD: sample univariate point, expand, observe answer — one per OOD sample.
        let mut ood_eq_points: Vec<Vec<Target>> = Vec::with_capacity(rp.ood_samples);
        for i in 0..rp.ood_samples {
            let ood_univ = challenger.sample_ext(circuit);
            let ood_pt = expand_from_univariate(circuit, ood_univ, rp.num_variables);
            challenger.observe_ext(circuit, round_proof.ood_answers[i]);
            ood_eq_points.push(ood_pt);
        }

        // 3. PoW check (after OOD, before STIR index sampling).
        if rp.pow_bits > 0 {
            challenger.check_pow_witness(circuit, rp.pow_bits, round_proof.pow_witness)?;
        }

        // 4. Transcript checkpoint: native calls `challenger.sample()` for intermediate
        //    rounds only (not the final round) to advance the sponge state.
        let _ = challenger.sample(circuit);

        // 5. STIR query sampling and leaf folding.
        //
        //    query_randomness = last_r (Prefix) or last_r reversed (Suffix).
        //    fold_j = eval_multilinear(leaf_j, query_randomness).
        let folded_domain_size = rp.domain_size >> rp.folding_factor;
        let domain_size_bits = p3_util::log2_strict_usize(folded_domain_size);
        let dims = vec![Dimensions {
            height: folded_domain_size,
            width: 1usize << rp.folding_factor,
        }];

        let query_r: Vec<Target> = if is_suffix {
            last_r.iter().copied().rev().collect()
        } else {
            last_r.clone()
        };

        let mut fold_vals: Vec<Target> = Vec::with_capacity(rp.num_queries);
        let mut sel_scalars: Vec<Target> = Vec::with_capacity(rp.num_queries);

        for q_idx in 0..rp.num_queries {
            // Sample domain_size_bits bits as little-endian index.
            let index_bits = challenger.sample_bits(circuit, domain_size_bits)?;

            // domain_point = folded_domain_gen^index (big-endian powers → LE bits).
            let domain_pt = pow_const_base(circuit, rp.folded_domain_gen.into(), &index_bits);
            sel_scalars.push(domain_pt);

            let query_opening = &round_proof.queries[q_idx];
            let leaf_vals = query_opening.leaf_values();
            fold_vals.push(eval_multilinear(circuit, leaf_vals, &query_r));

            // 6. MMCS path verification (skipped when permutation_config is None).
            if let Some(ref perm) = params.permutation_config {
                let np_ops = match query_opening {
                    QueryOpeningTargets::Base { leaf_values } => verify_batch_circuit::<BF, EF>(
                        circuit,
                        *perm,
                        &prev_cap,
                        &dims,
                        &index_bits,
                        core::slice::from_ref(leaf_values),
                        None,
                    )?,
                    QueryOpeningTargets::Extension { leaf_values } => {
                        verify_batch_circuit_from_extension_opened::<BF, EF>(
                            circuit,
                            *perm,
                            &prev_cap,
                            &dims,
                            &index_bits,
                            core::slice::from_ref(leaf_values),
                            None,
                        )?
                    }
                };
                all_np_ops.extend(np_ops);
            }
        }

        // 7. Sample gamma, update claimed_eval, record round constraint.
        //
        //    Native: `constraint.combine_evals(&mut claimed_eval)` adds
        //    Σ_i γ^i·ood_ans[i] + Σ_j γ^{n_ood+j}·fold[j].
        let gamma = challenger.sample_ext(circuit);
        let mut combined: Vec<Target> = round_proof.ood_answers.clone();
        combined.extend_from_slice(&fold_vals);
        let contrib = eval_powers_combination(circuit, &combined, gamma);
        claimed_eval = circuit.add(claimed_eval, contrib);

        all_constraints.push(ConstraintWeightData {
            num_variables: rp.num_variables,
            eq_points: ood_eq_points,
            sel_scalars,
            gamma,
        });

        // 8. Round sumcheck → next `last_r`.
        let (new_claim, round_r) = verify_sumcheck_rounds::<BF, EF, Ch>(
            circuit,
            challenger,
            claimed_eval,
            &round_proof.sumcheck.round_polys,
            &round_proof.sumcheck.pow_witnesses,
            rp.folding_pow_bits,
        )?;
        claimed_eval = new_claim;
        last_r = round_r.clone();
        all_r.extend_from_slice(&round_r);

        prev_cap = round_proof.commitment_cap.clone();
    }

    // ── Final phase ───────────────────────────────────────────────────────────

    // Observe the final polynomial sent in the clear.
    challenger.observe_ext_slice(circuit, &proof.final_poly);

    // Final PoW check — no transcript checkpoint after this (native omits it).
    if params.final_pow_bits > 0 {
        challenger.check_pow_witness(circuit, params.final_pow_bits, proof.final_pow_witness)?;
    }

    // Final STIR queries: domain = final_round_config.domain_size >> final_sumcheck_rounds.
    let final_folded_size = params.final_domain_size >> params.final_sumcheck_rounds;
    let final_domain_bits = p3_util::log2_strict_usize(final_folded_size);
    let final_dims = vec![Dimensions {
        height: final_folded_size,
        width: 1usize << params.final_sumcheck_rounds,
    }];

    let final_query_r: Vec<Target> = if is_suffix {
        last_r.iter().copied().rev().collect()
    } else {
        last_r.clone()
    };

    for q_idx in 0..params.final_queries {
        let index_bits = challenger.sample_bits(circuit, final_domain_bits)?;

        let domain_scalar =
            pow_const_base(circuit, params.final_folded_domain_gen.into(), &index_bits);

        let query_opening = &proof.final_queries[q_idx];
        let leaf_vals = query_opening.leaf_values();
        let fold = eval_multilinear(circuit, leaf_vals, &final_query_r);

        // Mirrors `SelectStatement::verify(final_poly)`: the hypercube evaluations
        // of the final polynomial are treated as univariate coefficients and
        // evaluated at `domain_scalar` via Horner's method.
        let expected = horner_eval(circuit, &proof.final_poly, domain_scalar);
        circuit.connect(fold, expected);

        // MMCS path verification for the final commitment.
        if let Some(ref perm) = params.permutation_config {
            let np_ops = match query_opening {
                QueryOpeningTargets::Base { leaf_values } => verify_batch_circuit::<BF, EF>(
                    circuit,
                    *perm,
                    &prev_cap,
                    &final_dims,
                    &index_bits,
                    core::slice::from_ref(leaf_values),
                    None,
                )?,
                QueryOpeningTargets::Extension { leaf_values } => {
                    verify_batch_circuit_from_extension_opened::<BF, EF>(
                        circuit,
                        *perm,
                        &prev_cap,
                        &final_dims,
                        &index_bits,
                        core::slice::from_ref(leaf_values),
                        None,
                    )?
                }
            };
            all_np_ops.extend(np_ops);
        }
    }

    // Optional final sumcheck.
    if params.final_sumcheck_rounds > 0
        && let Some(ref final_sc) = proof.final_sumcheck
    {
        let (new_claim, final_r) = verify_sumcheck_rounds::<BF, EF, Ch>(
            circuit,
            challenger,
            claimed_eval,
            &final_sc.round_polys,
            &final_sc.pow_witnesses,
            params.final_folding_pow_bits,
        )?;
        claimed_eval = new_claim;
        last_r = final_r.clone();
        all_r.extend_from_slice(&final_r);
    }

    // ── Final consistency check ───────────────────────────────────────────────
    //
    // Native: `claimed_eval == eval_constraints_poly(all_constraints, all_r) * final_value`
    //
    // `eval_constraints_poly` sums per-constraint weight polynomials evaluated
    // at the appropriate local slice of `all_r` (last k elements, per variable_order).
    //
    // `final_value = eval_multilinear(final_poly, last_r)`  [Prefix]
    //             or `eval_multilinear(final_poly, last_r.reversed())`  [Suffix].

    let eval_weights = eval_constraints_poly_circuit(circuit, &all_r, &all_constraints, is_suffix);

    let final_r_local: Vec<Target> = if is_suffix {
        last_r.iter().copied().rev().collect()
    } else {
        last_r
    };
    let final_value = eval_multilinear(circuit, &proof.final_poly, &final_r_local);

    let expected = circuit.mul(eval_weights, final_value);
    circuit.connect(claimed_eval, expected);

    Ok(all_np_ops)
}

#[cfg(test)]
mod tests {
    extern crate std;
    use alloc::collections::VecDeque;
    use alloc::vec;
    use alloc::vec::Vec;

    use p3_baby_bear::{BabyBear, Poseidon2BabyBear};
    use p3_challenger::{
        CanObserve, CanSample, CanSampleUniformBits, DuplexChallenger, FieldChallenger,
    };
    use p3_circuit::ops::{generate_poseidon2_trace, generate_recompose_trace};
    use p3_circuit::{CircuitBuilder, CircuitBuilderError};
    use p3_commit::MultilinearPcs;
    use p3_dft::Radix2DFTSmallBatch;
    use p3_field::extension::BinomialExtensionField;
    use p3_field::{Field, PrimeCharacteristicRing};
    use p3_merkle_tree::MerkleTreeMmcs;
    use p3_multilinear_util::poly::Poly;
    use p3_poseidon2_circuit_air::BabyBearD4Width16;
    use p3_sumcheck::layout::{Layout, PrefixProver, Table, Verifier};
    use p3_sumcheck::{OpeningProtocol, TableShape, TableSpec};
    use p3_symmetric::{PaddingFreeSponge, TruncatedPermutation};
    use p3_util::log2_strict_usize;
    use p3_whir::fiat_shamir::domain_separator::DomainSeparator;
    use p3_whir::parameters::{FoldingFactor, ProtocolParameters, SecurityAssumption, WhirConfig};
    use p3_whir::pcs::prover::WhirProver;
    use rand::SeedableRng;
    use rand::rngs::SmallRng;

    use crate::Target;
    use crate::pcs::mmcs::{convert_merkle_proof_to_siblings, set_whir_mmcs_private_data};
    use crate::pcs::whir::gadgets::ConstraintWeightData;
    use crate::pcs::whir::params::WhirVerifierParams;
    use crate::pcs::whir::targets::WhirProofTargets;
    use crate::pcs::whir::verifier::verify_whir_circuit;
    use crate::traits::RecursiveChallenger;

    type BF = BabyBear;
    type EF = BinomialExtensionField<BF, 4>;
    type Perm = Poseidon2BabyBear<16>;
    type MyHash = PaddingFreeSponge<Perm, 16, 8, 8>;
    type MyCompress = TruncatedPermutation<Perm, 2, 8, 16>;
    type MyChallenger = DuplexChallenger<BF, Perm, 16, 8>;
    type PackedBF = <BF as Field>::Packing;
    type MyMmcs = MerkleTreeMmcs<PackedBF, PackedBF, MyHash, MyCompress, 2, 8>;
    type MyDft = Radix2DFTSmallBatch<BF>;
    type TestPcs = WhirProver<EF, BF, MyDft, MyMmcs, MyChallenger, PrefixProver<BF, EF>>;

    fn make_perm() -> Perm {
        let mut rng = SmallRng::seed_from_u64(1);
        Perm::new_from_rng_128(&mut rng)
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
            let v = self
                .base_samples
                .pop_front()
                .expect("base_samples exhausted");
            circuit.define_const(EF::from(v))
        }

        fn sample_ext(&mut self, circuit: &mut CircuitBuilder<EF>) -> Target {
            let v = self.ext_samples.pop_front().expect("ext_samples exhausted");
            circuit.define_const(v)
        }

        fn sample_bits(
            &mut self,
            circuit: &mut CircuitBuilder<EF>,
            k: usize,
        ) -> Result<Vec<Target>, CircuitBuilderError> {
            let raw = self
                .base_samples
                .pop_front()
                .expect("base_samples exhausted");
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

    /// Mirror of `get_challenge_stir_queries` from p3-whir (pub(crate) there).
    fn sample_stir_indices(
        vc: &mut MyChallenger,
        domain_size: usize,
        folding_factor: usize,
        num_queries: usize,
    ) -> Vec<usize> {
        let folded_domain_size = domain_size >> folding_factor;
        let k = log2_strict_usize(folded_domain_size);
        let target = num_queries.min(folded_domain_size);
        let mut indices: Vec<usize> = Vec::new();
        while indices.len() < target {
            let q = vc
                .sample_uniform_bits::<true>(k)
                .expect("RESAMPLE=true never errors");
            if !indices.contains(&q) {
                indices.push(q);
            }
        }
        indices.sort_unstable();
        indices
    }

    /// Builds the WHIR arithmetic-only circuit and assembles its witness.
    ///
    /// Returns `(built_circuit, public_inputs, private_inputs)` ready for
    /// `runner.set_public_inputs` / `runner.set_private_inputs` / `runner.run()`.
    fn build_whir_arithmetic_circuit() -> (p3_circuit::Circuit<EF>, Vec<EF>, Vec<EF>) {
        const NUM_VARIABLES: usize = 12;
        const FOLDING: usize = 4;

        let perm = make_perm();
        let hash = MyHash::new(perm.clone());
        let compress = MyCompress::new(perm);
        let mmcs = MyMmcs::new(hash, compress, 0);
        let dft = MyDft::default();

        let spec = TableSpec::new(TableShape::new(NUM_VARIABLES, 1), vec![vec![0]]);
        let protocol = OpeningProtocol::new(vec![spec]).pad_to_min_num_variables(FOLDING);
        let poly = Poly::<BF>::rand(&mut SmallRng::seed_from_u64(42), NUM_VARIABLES);
        let table = Table::new(vec![poly]);
        let witness = PrefixProver::<BF, EF>::new_witness(vec![table], FOLDING);

        let whir_params = ProtocolParameters {
            security_level: 32,
            pow_bits: 0,
            round_log_inv_rates: vec![4],
            folding_factor: FoldingFactor::Constant(FOLDING),
            soundness_type: SecurityAssumption::CapacityBound,
            starting_log_inv_rate: 1,
        };
        let config = WhirConfig::<EF, BF, MyChallenger>::new(NUM_VARIABLES, whir_params).unwrap();
        let pcs = TestPcs::new(config.clone(), dft, mmcs);

        let (commitment, proof) = {
            let mut ch = make_challenger();
            let mut ds = DomainSeparator::new(vec![]);
            pcs.add_domain_separator::<8>(&mut ds);
            ds.observe_domain_separator(&mut ch);
            let (commitment, prover_data) =
                <TestPcs as MultilinearPcs<EF, MyChallenger>>::commit(&pcs, witness, &mut ch);
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
            ch.observe(commitment);
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

        let mut ext_samples: Vec<EF> = Vec::new();
        let mut base_samples: Vec<BF> = Vec::new();
        let rp0 = &config.round_parameters[0];

        for &[c0, cinf] in proof.whir.initial_sumcheck.polynomial_evaluations() {
            vc.observe_algebra_element(c0);
            vc.observe_algebra_element(cinf);
            ext_samples.push(vc.sample_algebra_element());
        }
        {
            let rproof = &proof.whir.rounds[0];
            let cap = rproof.commitment.as_ref().expect("round commitment");
            vc.observe(cap.clone());
            for &answer in &rproof.ood_answers {
                ext_samples.push(vc.sample_algebra_element());
                vc.observe_algebra_element(answer);
            }
            let checkpoint: BF = CanSample::sample(&mut vc);
            base_samples.push(checkpoint);
            let round0_indices = sample_stir_indices(
                &mut vc,
                rp0.domain_size,
                rp0.folding_factor,
                rp0.num_queries,
            );
            for &idx in &round0_indices {
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
            let final_poly = proof.whir.final_poly.as_ref().expect("final_poly");
            vc.observe_algebra_slice(final_poly.as_slice());
            let final_indices = sample_stir_indices(
                &mut vc,
                config.final_round_config().domain_size,
                config.final_sumcheck_rounds,
                config.final_queries,
            );
            for &idx in &final_indices {
                base_samples.push(BF::from_u64(idx as u64));
            }
            if let Some(ref final_sc) = proof.whir.final_sumcheck {
                for &[c0, cinf] in final_sc.polynomial_evaluations() {
                    vc.observe_algebra_element(c0);
                    vc.observe_algebra_element(cinf);
                    ext_samples.push(vc.sample_algebra_element());
                }
            }
        }

        let vp = WhirVerifierParams::<BF>::unsafe_arithmetic_only_for_tests::<EF, MyChallenger>(
            &config,
            PrefixProver::<BF, EF>::variable_order(),
            p3_circuit::ops::Poseidon2Config::BABY_BEAR_D4_W16,
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

        let mut public_inputs: Vec<EF> = Vec::new();
        for &v in &proof.whir.initial_ood_answers {
            public_inputs.push(v);
        }
        for &[c0, cinf] in proof.whir.initial_sumcheck.polynomial_evaluations() {
            public_inputs.push(c0);
            public_inputs.push(cinf);
        }
        public_inputs.push(EF::ZERO); // round-0 cap placeholder
        for &v in &proof.whir.rounds[0].ood_answers {
            public_inputs.push(v);
        }
        public_inputs.push(EF::from(proof.whir.rounds[0].pow_witness));
        for &[c0, cinf] in proof.whir.rounds[0].sumcheck.polynomial_evaluations() {
            public_inputs.push(c0);
            public_inputs.push(cinf);
        }
        let final_poly = proof.whir.final_poly.as_ref().unwrap();
        for &v in final_poly.as_slice() {
            public_inputs.push(v);
        }
        public_inputs.push(EF::from(proof.whir.final_pow_witness));
        if let Some(ref fsc) = proof.whir.final_sumcheck {
            for &[c0, cinf] in fsc.polynomial_evaluations() {
                public_inputs.push(c0);
                public_inputs.push(cinf);
            }
        }

        let mut private_inputs: Vec<EF> = Vec::new();
        for q in &proof.whir.rounds[0].queries {
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

        (circuit, public_inputs, private_inputs)
    }

    #[test]
    fn test_verify_whir_circuit_arithmetic_only() {
        let (circuit, public_inputs, private_inputs) = build_whir_arithmetic_circuit();
        let mut runner = circuit.runner();
        runner
            .set_public_inputs(&public_inputs)
            .expect("set_public_inputs");
        runner
            .set_private_inputs(&private_inputs)
            .expect("set_private_inputs");
        runner.run().expect("circuit run failed");
    }

    #[test]
    fn test_verify_whir_circuit_tamper_rejects() {
        let (circuit, mut public_inputs, private_inputs) = build_whir_arithmetic_circuit();
        // Corrupt the first entry of the initial sumcheck round polynomial (public input index 1).
        // This value feeds directly into sumcheck_round_claim_update, so any corruption
        // propagates through the claimed-eval accumulator and breaks the final identity check.
        public_inputs[1] += EF::ONE;
        let mut runner = circuit.runner();
        runner
            .set_public_inputs(&public_inputs)
            .expect("set_public_inputs");
        runner
            .set_private_inputs(&private_inputs)
            .expect("set_private_inputs");
        assert!(
            runner.run().is_err(),
            "tampered proof must be rejected by the circuit"
        );
    }

    /// Converts a single `[BF; 8]` Merkle digest to 2 EF elements.
    ///
    /// `MerkleTreeMmcs<_, _, _, _, 2, 8>` digests have 8 BF values; with extension
    /// degree D=4, they pack into 2 EF elements. Reuses `convert_merkle_proof_to_siblings`.
    fn digest_to_ef(digest: &[BF; 8]) -> Vec<EF> {
        convert_merkle_proof_to_siblings::<BF, EF, 8>(core::slice::from_ref(digest))
            .into_iter()
            .next()
            .expect("single digest produces one sibling entry")
    }

    /// End-to-end test with real Merkle-tree MMCS verification enabled.
    ///
    /// Uses [`WhirVerifierParams::from_config`] so `permutation_config = Some(...)` and
    /// all Merkle path hashes are verified in-circuit. Leaf values are private inputs;
    /// sibling digests are set via [`set_whir_mmcs_private_data`].
    #[test]
    fn test_verify_whir_circuit_with_mmcs() {
        const NUM_VARIABLES: usize = 12;
        const FOLDING: usize = 4;
        const DIGEST_ELEMS: usize = 8;
        // D=4 base elements per EF element → 8/4 = 2 EF per Merkle digest.
        const CAP_ENTRY_LEN: usize = DIGEST_ELEMS / 4;

        let perm = make_perm();
        let hash = MyHash::new(perm.clone());
        let compress = MyCompress::new(perm);
        let mmcs = MyMmcs::new(hash, compress, 0);
        let dft = MyDft::default();

        let spec = TableSpec::new(TableShape::new(NUM_VARIABLES, 1), vec![vec![0]]);
        let protocol = OpeningProtocol::new(vec![spec]).pad_to_min_num_variables(FOLDING);
        let poly = Poly::<BF>::rand(&mut SmallRng::seed_from_u64(42), NUM_VARIABLES);
        let table = Table::new(vec![poly]);
        let witness = PrefixProver::<BF, EF>::new_witness(vec![table], FOLDING);

        let whir_params = ProtocolParameters {
            security_level: 32,
            pow_bits: 0,
            round_log_inv_rates: vec![4],
            folding_factor: FoldingFactor::Constant(FOLDING),
            soundness_type: SecurityAssumption::CapacityBound,
            starting_log_inv_rate: 1,
        };
        let config = WhirConfig::<EF, BF, MyChallenger>::new(NUM_VARIABLES, whir_params).unwrap();
        let pcs = TestPcs::new(config.clone(), dft, mmcs);

        let (commitment, proof) = {
            let mut ch = make_challenger();
            let mut ds = DomainSeparator::new(vec![]);
            pcs.add_domain_separator::<8>(&mut ds);
            ds.observe_domain_separator(&mut ch);
            let (commitment, prover_data) =
                <TestPcs as MultilinearPcs<EF, MyChallenger>>::commit(&pcs, witness, &mut ch);
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

        // Record transcript (same logic as arithmetic test).
        let mut ext_samples: Vec<EF> = Vec::new();
        let mut base_samples: Vec<BF> = Vec::new();
        let rp0 = &config.round_parameters[0];
        for &[c0, cinf] in proof.whir.initial_sumcheck.polynomial_evaluations() {
            vc.observe_algebra_element(c0);
            vc.observe_algebra_element(cinf);
            ext_samples.push(vc.sample_algebra_element());
        }
        {
            let rproof = &proof.whir.rounds[0];
            vc.observe(rproof.commitment.as_ref().unwrap().clone());
            for &answer in &rproof.ood_answers {
                ext_samples.push(vc.sample_algebra_element());
                vc.observe_algebra_element(answer);
            }
            let checkpoint: BF = CanSample::sample(&mut vc);
            base_samples.push(checkpoint);
            let round0_indices = sample_stir_indices(
                &mut vc,
                rp0.domain_size,
                rp0.folding_factor,
                rp0.num_queries,
            );
            for &idx in &round0_indices {
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
            let final_poly = proof.whir.final_poly.as_ref().unwrap();
            vc.observe_algebra_slice(final_poly.as_slice());
            let final_indices = sample_stir_indices(
                &mut vc,
                config.final_round_config().domain_size,
                config.final_sumcheck_rounds,
                config.final_queries,
            );
            for &idx in &final_indices {
                base_samples.push(BF::from_u64(idx as u64));
            }
            if let Some(ref final_sc) = proof.whir.final_sumcheck {
                for &[c0, cinf] in final_sc.polynomial_evaluations() {
                    vc.observe_algebra_element(c0);
                    vc.observe_algebra_element(cinf);
                    ext_samples.push(vc.sample_algebra_element());
                }
            }
        }

        // Build circuit with real MMCS verification enabled.
        let vp = WhirVerifierParams::<BF>::from_config::<EF, MyChallenger>(
            &config,
            PrefixProver::<BF, EF>::variable_order(),
            p3_circuit::ops::Poseidon2Config::BABY_BEAR_D4_W16,
        );

        let mut circuit = CircuitBuilder::<EF>::new();
        circuit.enable_poseidon2_perm::<BabyBearD4Width16, _>(
            generate_poseidon2_trace::<EF, BabyBearD4Width16>,
            make_perm(),
        );
        circuit.enable_recompose::<BF>(generate_recompose_trace::<BF, EF>);
        let proof_targets = WhirProofTargets::alloc::<BF, EF>(&mut circuit, &vp, 1, CAP_ENTRY_LEN);

        // Initial commitment cap: 1 cap entry → 2 EF targets.
        let initial_cap: Vec<Vec<Target>> = commitment
            .roots()
            .iter()
            .map(|digest| {
                digest_to_ef(digest)
                    .into_iter()
                    .map(|e| circuit.define_const(e))
                    .collect()
            })
            .collect();

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
        let op_ids = verify_whir_circuit::<BF, EF, MockChallenger>(
            &mut circuit,
            &mut mock,
            &vp,
            &proof_targets,
            &initial_cap,
            circuit_constraint,
            initial_claimed_eval_target,
        )
        .expect("verify_whir_circuit failed");

        assert!(mock.ext_samples.is_empty(), "unused ext_samples");
        assert!(mock.base_samples.is_empty(), "unused base_samples");

        let circuit = circuit.build().expect("circuit build failed");

        // Assemble public inputs.
        let mut public_inputs: Vec<EF> = Vec::new();
        for &v in &proof.whir.initial_ood_answers {
            public_inputs.push(v);
        }
        for &[c0, cinf] in proof.whir.initial_sumcheck.polynomial_evaluations() {
            public_inputs.push(c0);
            public_inputs.push(cinf);
        }
        // Round-0 cap: CAP_ENTRY_LEN=2 EF elements per cap entry.
        let round0_cap = proof.whir.rounds[0].commitment.as_ref().unwrap();
        for digest in round0_cap.roots() {
            for e in digest_to_ef(digest) {
                public_inputs.push(e);
            }
        }
        for &v in &proof.whir.rounds[0].ood_answers {
            public_inputs.push(v);
        }
        public_inputs.push(EF::from(proof.whir.rounds[0].pow_witness));
        for &[c0, cinf] in proof.whir.rounds[0].sumcheck.polynomial_evaluations() {
            public_inputs.push(c0);
            public_inputs.push(cinf);
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

        // Assemble private inputs (query leaf values).
        let mut private_inputs: Vec<EF> = Vec::new();
        for q in &proof.whir.rounds[0].queries {
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
        set_whir_mmcs_private_data::<BF, EF, MyMmcs, DIGEST_ELEMS>(
            &mut runner,
            &op_ids,
            &proof.whir,
            p3_circuit::ops::Poseidon2Config::BABY_BEAR_D4_W16,
        )
        .expect("set_whir_mmcs_private_data failed");
        runner.run().expect("circuit run with MMCS failed");
    }

    /// Tamper variant: corrupt the first query leaf value. The in-circuit Poseidon2
    /// hash of the fake leaf diverges from the real sibling path, so the circuit rejects.
    #[test]
    fn test_verify_whir_circuit_with_mmcs_tamper_rejects() {
        const NUM_VARIABLES: usize = 12;
        const FOLDING: usize = 4;
        const DIGEST_ELEMS: usize = 8;
        const CAP_ENTRY_LEN: usize = DIGEST_ELEMS / 4;

        let perm = make_perm();
        let hash = MyHash::new(perm.clone());
        let compress = MyCompress::new(perm);
        let mmcs = MyMmcs::new(hash, compress, 0);
        let dft = MyDft::default();

        let spec = TableSpec::new(TableShape::new(NUM_VARIABLES, 1), vec![vec![0]]);
        let protocol = OpeningProtocol::new(vec![spec]).pad_to_min_num_variables(FOLDING);
        let poly = Poly::<BF>::rand(&mut SmallRng::seed_from_u64(42), NUM_VARIABLES);
        let table = Table::new(vec![poly]);
        let witness = PrefixProver::<BF, EF>::new_witness(vec![table], FOLDING);

        let whir_params = ProtocolParameters {
            security_level: 32,
            pow_bits: 0,
            round_log_inv_rates: vec![4],
            folding_factor: FoldingFactor::Constant(FOLDING),
            soundness_type: SecurityAssumption::CapacityBound,
            starting_log_inv_rate: 1,
        };
        let config = WhirConfig::<EF, BF, MyChallenger>::new(NUM_VARIABLES, whir_params).unwrap();
        let pcs = TestPcs::new(config.clone(), dft, mmcs);

        let (commitment, proof) = {
            let mut ch = make_challenger();
            let mut ds = DomainSeparator::new(vec![]);
            pcs.add_domain_separator::<8>(&mut ds);
            ds.observe_domain_separator(&mut ch);
            let (commitment, prover_data) =
                <TestPcs as MultilinearPcs<EF, MyChallenger>>::commit(&pcs, witness, &mut ch);
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

        let mut ext_samples: Vec<EF> = Vec::new();
        let mut base_samples: Vec<BF> = Vec::new();
        let rp0 = &config.round_parameters[0];
        for &[c0, cinf] in proof.whir.initial_sumcheck.polynomial_evaluations() {
            vc.observe_algebra_element(c0);
            vc.observe_algebra_element(cinf);
            ext_samples.push(vc.sample_algebra_element());
        }
        {
            let rproof = &proof.whir.rounds[0];
            vc.observe(rproof.commitment.as_ref().unwrap().clone());
            for &answer in &rproof.ood_answers {
                ext_samples.push(vc.sample_algebra_element());
                vc.observe_algebra_element(answer);
            }
            let checkpoint: BF = CanSample::sample(&mut vc);
            base_samples.push(checkpoint);
            let round0_indices = sample_stir_indices(
                &mut vc,
                rp0.domain_size,
                rp0.folding_factor,
                rp0.num_queries,
            );
            for &idx in &round0_indices {
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
            let final_poly = proof.whir.final_poly.as_ref().unwrap();
            vc.observe_algebra_slice(final_poly.as_slice());
            let final_indices = sample_stir_indices(
                &mut vc,
                config.final_round_config().domain_size,
                config.final_sumcheck_rounds,
                config.final_queries,
            );
            for &idx in &final_indices {
                base_samples.push(BF::from_u64(idx as u64));
            }
            if let Some(ref final_sc) = proof.whir.final_sumcheck {
                for &[c0, cinf] in final_sc.polynomial_evaluations() {
                    vc.observe_algebra_element(c0);
                    vc.observe_algebra_element(cinf);
                    ext_samples.push(vc.sample_algebra_element());
                }
            }
        }

        let vp = WhirVerifierParams::<BF>::from_config::<EF, MyChallenger>(
            &config,
            PrefixProver::<BF, EF>::variable_order(),
            p3_circuit::ops::Poseidon2Config::BABY_BEAR_D4_W16,
        );

        let mut circuit = CircuitBuilder::<EF>::new();
        circuit.enable_poseidon2_perm::<BabyBearD4Width16, _>(
            generate_poseidon2_trace::<EF, BabyBearD4Width16>,
            make_perm(),
        );
        circuit.enable_recompose::<BF>(generate_recompose_trace::<BF, EF>);
        let proof_targets = WhirProofTargets::alloc::<BF, EF>(&mut circuit, &vp, 1, CAP_ENTRY_LEN);

        let initial_cap: Vec<Vec<Target>> = commitment
            .roots()
            .iter()
            .map(|digest| {
                digest_to_ef(digest)
                    .into_iter()
                    .map(|e| circuit.define_const(e))
                    .collect()
            })
            .collect();

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
        let op_ids = verify_whir_circuit::<BF, EF, MockChallenger>(
            &mut circuit,
            &mut mock,
            &vp,
            &proof_targets,
            &initial_cap,
            circuit_constraint,
            initial_claimed_eval_target,
        )
        .expect("verify_whir_circuit failed");

        let circuit = circuit.build().expect("circuit build failed");

        let mut public_inputs: Vec<EF> = Vec::new();
        for &v in &proof.whir.initial_ood_answers {
            public_inputs.push(v);
        }
        for &[c0, cinf] in proof.whir.initial_sumcheck.polynomial_evaluations() {
            public_inputs.push(c0);
            public_inputs.push(cinf);
        }
        let round0_cap = proof.whir.rounds[0].commitment.as_ref().unwrap();
        for digest in round0_cap.roots() {
            for e in digest_to_ef(digest) {
                public_inputs.push(e);
            }
        }
        for &v in &proof.whir.rounds[0].ood_answers {
            public_inputs.push(v);
        }
        public_inputs.push(EF::from(proof.whir.rounds[0].pow_witness));
        for &[c0, cinf] in proof.whir.rounds[0].sumcheck.polynomial_evaluations() {
            public_inputs.push(c0);
            public_inputs.push(cinf);
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

        let mut private_inputs: Vec<EF> = Vec::new();
        for q in &proof.whir.rounds[0].queries {
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

        // Corrupt the first leaf value — the Merkle hash will disagree with the path.
        private_inputs[0] += EF::ONE;

        let mut runner = circuit.runner();
        runner
            .set_public_inputs(&public_inputs)
            .expect("set_public_inputs");
        runner
            .set_private_inputs(&private_inputs)
            .expect("set_private_inputs");
        set_whir_mmcs_private_data::<BF, EF, MyMmcs, DIGEST_ELEMS>(
            &mut runner,
            &op_ids,
            &proof.whir,
            p3_circuit::ops::Poseidon2Config::BABY_BEAR_D4_W16,
        )
        .expect("set_whir_mmcs_private_data failed");
        assert!(
            runner.run().is_err(),
            "tampered leaf must be rejected by the circuit"
        );
    }
}
