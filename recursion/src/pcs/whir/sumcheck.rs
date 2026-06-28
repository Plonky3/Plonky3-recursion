//! In-circuit sumcheck round arithmetic mirroring `p3-sumcheck`.
//!
//! The native verifier stores each degree-2 round polynomial compactly as
//! `[h(0), h(inf)]` and reconstructs the next claim with
//! `extrapolate_01inf(h(0), claimed_sum - h(0), h(inf), r)`, where
//! `extrapolate_01inf(e0, e1, e_inf, r) = e0·(1-r) + e1·r + e_inf·r·(r-1)`
//! (`p3_sumcheck::extrapolate_01inf`). `h(1)` is never sent; it is derived from
//! the running claim as `claimed_sum - h(0)`.
//!
//! [`sumcheck_round_claim_update`] reproduces that field formula for one round;
//! [`fold_sumcheck_claim`] chains it across every round of a `SumcheckData`,
//! given the challenges the caller sampled from the transcript.

use alloc::vec::Vec;

use p3_circuit::{CircuitBuilder, CircuitBuilderError};
use p3_field::{ExtensionField, Field, PrimeField64};

use crate::Target;
use crate::traits::RecursiveChallenger;

/// Updates the running sumcheck claim for one round.
///
/// Given the running `claimed_sum`, the sent round-polynomial values
/// `c0 = h(0)` and `c_inf = h(inf)`, and the round challenge `r`, returns
/// `h(r)` with `h(1)` derived as `claimed_sum - c0`. Equal to
/// `extrapolate_01inf(c0, claimed_sum - c0, c_inf, r)`.
pub fn sumcheck_round_claim_update<F: Field>(
    builder: &mut CircuitBuilder<F>,
    claimed_sum: Target,
    c0: Target,
    c_inf: Target,
    r: Target,
) -> Target {
    let one = builder.define_const(F::ONE);

    // Interpolation weights on {0, 1, inf}: L_0 = 1 - r, L_1 = r, L_inf = r·(r - 1).
    let w0 = builder.sub(one, r);
    let r_minus_one = builder.sub(r, one);
    let w_inf = builder.mul(r, r_minus_one);

    // h(1) = claimed_sum - h(0).
    let e1 = builder.sub(claimed_sum, c0);

    // h(r) = c0·w0 + h(1)·r + c_inf·w_inf.
    let t0 = builder.mul(c0, w0);
    let t1 = builder.mul_add(e1, r, t0);
    builder.mul_add(c_inf, w_inf, t1)
}

/// Folds an initial claim through every round of a sumcheck transcript.
///
/// `round_polys[i] = [h_i(0), h_i(inf)]` and `challenges[i]` is the round-`i`
/// verifier challenge the caller sampled from the transcript. Returns the claim
/// remaining after all rounds.
///
/// # Panics
/// Panics if `round_polys.len() != challenges.len()`: a mismatch would silently
/// drop rounds, which is a soundness-relevant construction error rather than a
/// recoverable condition.
pub fn fold_sumcheck_claim<F: Field>(
    builder: &mut CircuitBuilder<F>,
    initial_claim: Target,
    round_polys: &[[Target; 2]],
    challenges: &[Target],
) -> Target {
    assert_eq!(
        round_polys.len(),
        challenges.len(),
        "fold_sumcheck_claim: round/challenge count mismatch"
    );

    let mut claim = initial_claim;
    for (&[c0, c_inf], &r) in round_polys.iter().zip(challenges) {
        claim = sumcheck_round_claim_update(builder, claim, c0, c_inf, r);
    }
    claim
}

/// Verifies the standard sumcheck rounds against the Fiat–Shamir transcript,
/// returning the reduced claim and the folding randomness.
///
/// Mirrors native `SumcheckData::verify_rounds`: for each round it observes the
/// sent `[h(0), h(inf)]` into the `challenger`, checks the round's PoW witness
/// (when `pow_bits > 0`), samples the round challenge `r`, and updates the claim
/// to `h(r)` via [`sumcheck_round_claim_update`]. The observe-then-sample order
/// is load-bearing: it must match the native transcript exactly.
///
/// # Panics
/// Panics if `pow_bits > 0` and `pow_witnesses.len() != round_polys.len()`,
/// mirroring the native length guard (a mismatch would desynchronize the
/// transcript or index out of bounds).
pub fn verify_sumcheck_rounds<BF, EF, Ch>(
    circuit: &mut CircuitBuilder<EF>,
    challenger: &mut Ch,
    claimed_sum: Target,
    round_polys: &[[Target; 2]],
    pow_witnesses: &[Target],
    pow_bits: usize,
) -> Result<(Target, Vec<Target>), CircuitBuilderError>
where
    BF: PrimeField64,
    EF: ExtensionField<BF>,
    Ch: RecursiveChallenger<BF, EF>,
{
    if pow_bits > 0 {
        assert_eq!(
            pow_witnesses.len(),
            round_polys.len(),
            "verify_sumcheck_rounds: pow witness count must equal round count"
        );
    }

    let mut claim = claimed_sum;
    let mut randomness = Vec::with_capacity(round_polys.len());
    for (i, &[c0, c_inf]) in round_polys.iter().enumerate() {
        // Observe (h(0), h(inf)); h(1) is derived from the running claim, never sent.
        challenger.observe_ext_slice(circuit, &[c0, c_inf]);
        if pow_bits > 0 {
            challenger.check_pow_witness(circuit, pow_bits, pow_witnesses[i])?;
        }
        let r = challenger.sample_ext(circuit);
        claim = sumcheck_round_claim_update(circuit, claim, c0, c_inf, r);
        randomness.push(r);
    }
    Ok((claim, randomness))
}

#[cfg(test)]
mod tests {
    use alloc::vec::Vec;

    use p3_baby_bear::BabyBear;
    use p3_circuit::{CircuitBuilder, CircuitBuilderError};
    use p3_field::PrimeCharacteristicRing;
    use p3_sumcheck::lagrange::extrapolate_01inf;
    use proptest::prelude::*;

    use super::{fold_sumcheck_claim, sumcheck_round_claim_update, verify_sumcheck_rounds};
    use crate::Target;
    use crate::pcs::whir::test_util::eval_gadget;
    use crate::traits::RecursiveChallenger;

    type F = BabyBear;

    fn f(x: u32) -> F {
        F::from_u32(x)
    }

    /// Deterministic test-double challenger.
    ///
    /// Native transcript fidelity of the real Poseidon2 sponge is covered by
    /// `tests/challenger_transcript.rs`; this double instead returns a fixed
    /// challenge sequence and records the observe/sample call order, isolating
    /// the routine's own round ordering and claim-folding logic.
    struct MockChallenger {
        challenges: Vec<F>,
        next: usize,
        events: Vec<&'static str>,
    }

    impl MockChallenger {
        fn next_challenge(&mut self, circuit: &mut CircuitBuilder<F>) -> Target {
            self.events.push("sample");
            let v = self.challenges[self.next];
            self.next += 1;
            circuit.define_const(v)
        }
    }

    impl RecursiveChallenger<BabyBear, BabyBear> for MockChallenger {
        fn observe(&mut self, _circuit: &mut CircuitBuilder<F>, _value: Target) {
            self.events.push("observe");
        }

        fn sample(&mut self, circuit: &mut CircuitBuilder<F>) -> Target {
            self.next_challenge(circuit)
        }

        fn observe_ext(&mut self, _circuit: &mut CircuitBuilder<F>, _value: Target) {
            self.events.push("observe");
        }

        fn sample_ext(&mut self, circuit: &mut CircuitBuilder<F>) -> Target {
            self.next_challenge(circuit)
        }

        fn sample_bits(
            &mut self,
            _circuit: &mut CircuitBuilder<F>,
            _num_bits: usize,
        ) -> Result<Vec<Target>, CircuitBuilderError> {
            Ok(Vec::new())
        }

        fn check_pow_witness(
            &mut self,
            _circuit: &mut CircuitBuilder<F>,
            _witness_bits: usize,
            _witness: Target,
        ) -> Result<(), CircuitBuilderError> {
            Ok(())
        }

        fn clear(&mut self, _circuit: &mut CircuitBuilder<F>) {}
    }

    #[test]
    fn verify_rounds_orders_observe_sample_and_folds_claim() {
        let polys_v = [[f(3), f(5)], [f(7), f(2)], [f(1), f(9)]];
        let chals = [f(11), f(13), f(17)];
        let initial = f(100);

        // Native reference: fold round by round with the same challenges.
        let mut native = initial;
        for ([c0, c_inf], &r) in polys_v.iter().zip(&chals) {
            native = extrapolate_01inf(*c0, native - *c0, *c_inf, r);
        }

        let mut builder = CircuitBuilder::<F>::new();
        let claim_t = builder.public_input();
        let poly_ts: Vec<[Target; 2]> = (0..polys_v.len())
            .map(|_| [builder.public_input(), builder.public_input()])
            .collect();

        let mut challenger = MockChallenger {
            challenges: chals.to_vec(),
            next: 0,
            events: Vec::new(),
        };
        let (out_claim, randomness) = verify_sumcheck_rounds::<BabyBear, F, _>(
            &mut builder,
            &mut challenger,
            claim_t,
            &poly_ts,
            &[],
            0,
        )
        .unwrap();
        builder.tag(out_claim, "claim").unwrap();

        // Every round observes (h(0), h(inf)) before sampling its challenge.
        let expected_events: Vec<&str> = polys_v
            .iter()
            .flat_map(|_| ["observe", "observe", "sample"])
            .collect();
        assert_eq!(challenger.events, expected_events);
        assert_eq!(randomness.len(), polys_v.len());

        let circuit = builder.build().unwrap();
        let mut runner = circuit.runner();
        let mut inputs = Vec::with_capacity(1 + 2 * polys_v.len());
        inputs.push(initial);
        for [c0, c_inf] in &polys_v {
            inputs.push(*c0);
            inputs.push(*c_inf);
        }
        runner.set_public_inputs(&inputs).unwrap();
        let traces = runner.run().unwrap();

        assert_eq!(*traces.probe("claim").unwrap(), native);
    }

    #[test]
    fn round_update_recovers_endpoints() {
        // At r = 0 the update returns h(0); at r = 1 it returns h(1) = claim - h(0).
        let claim = f(50);
        let c0 = f(7);
        let c_inf = f(11);

        let at_zero = eval_gadget(&[claim, c0, c_inf, F::ZERO], |b, ins| {
            sumcheck_round_claim_update(b, ins[0], ins[1], ins[2], ins[3])
        });
        assert_eq!(at_zero, c0);

        let at_one = eval_gadget(&[claim, c0, c_inf, F::ONE], |b, ins| {
            sumcheck_round_claim_update(b, ins[0], ins[1], ins[2], ins[3])
        });
        assert_eq!(at_one, claim - c0);
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(48))]

        /// One round matches `p3_sumcheck::extrapolate_01inf` exactly.
        #[test]
        fn prop_round_update_matches_native(
            c0 in 0u32..1_000_000,
            c_inf in 0u32..1_000_000,
            claim in 0u32..1_000_000,
            r in 0u32..1_000_000,
        ) {
            let (c0, c_inf, claim, r) = (f(c0), f(c_inf), f(claim), f(r));
            let native = extrapolate_01inf(c0, claim - c0, c_inf, r);
            let got = eval_gadget(&[claim, c0, c_inf, r], |b, ins| {
                sumcheck_round_claim_update(b, ins[0], ins[1], ins[2], ins[3])
            });
            prop_assert_eq!(got, native);
        }

        /// Folding all rounds matches the native per-round reduction.
        #[test]
        fn prop_fold_matches_native(
            (polys, chals, init) in (1usize..6).prop_flat_map(|n| (
                proptest::collection::vec(0u32..1_000_000, 2 * n),
                proptest::collection::vec(0u32..1_000_000, n),
                0u32..1_000_000,
            ))
        ) {
            let n = chals.len();

            // Native reference: chain extrapolate_01inf round by round.
            let mut native = f(init);
            for i in 0..n {
                let c0 = f(polys[2 * i]);
                let c_inf = f(polys[2 * i + 1]);
                let r = f(chals[i]);
                native = extrapolate_01inf(c0, native - c0, c_inf, r);
            }

            // Circuit inputs: [init, c0_0, c_inf_0, …, r_0, r_1, …].
            let mut inputs = Vec::with_capacity(1 + 3 * n);
            inputs.push(f(init));
            inputs.extend(polys.iter().map(|&x| f(x)));
            inputs.extend(chals.iter().map(|&x| f(x)));

            let got = eval_gadget(&inputs, |b, ins| {
                let init_t = ins[0];
                let round_polys: Vec<[Target; 2]> =
                    ins[1..1 + 2 * n].chunks_exact(2).map(|c| [c[0], c[1]]).collect();
                let challenges = &ins[1 + 2 * n..];
                fold_sumcheck_claim(b, init_t, &round_polys, challenges)
            });
            prop_assert_eq!(got, native);
        }
    }
}
