//! In-circuit building blocks for the WHIR polynomial-commitment verifier.
//!
//! This module provides the field-arithmetic primitives the WHIR verifier
//! evaluates, each a faithful gate-for-gate mirror of its native counterpart in
//! `p3-multilinear-util` and `p3-sumcheck`. Proof-target types, the Fiat–Shamir
//! replay, and the full verifier are layered on top of these primitives in
//! later phases; see `docs/rfcs/0009-rfc-whir-recursive-verifier.md`.

pub mod gadgets;
pub mod params;
pub mod sumcheck;
pub mod targets;
pub mod verifier;

pub use gadgets::{
    ConstraintWeightData, eq_eval, eval_constraint_weight, eval_constraints_poly_circuit,
    eval_multilinear, eval_powers_combination, expand_from_univariate, horner_eval, pow_const_base,
    select_eval,
};
pub use params::{WhirRoundParams, WhirVerifierParams};
pub use sumcheck::{fold_sumcheck_claim, sumcheck_round_claim_update, verify_sumcheck_rounds};
pub use targets::{
    QueryOpeningTargets, SumcheckDataTargets, WhirPcsProofTargets, WhirProofTargets,
    WhirRoundProofTargets,
};
pub use verifier::verify_whir_circuit;

#[cfg(test)]
pub(crate) mod test_util {
    use alloc::format;
    use alloc::vec::Vec;

    use p3_baby_bear::BabyBear;
    use p3_circuit::CircuitBuilder;

    use crate::Target;

    /// Build a single-output gadget over `BabyBear`, drive it with runtime
    /// public inputs (so nothing is const-folded away and the real ALU witness
    /// path is exercised), and return the witnessed output value.
    pub(crate) fn eval_gadget<G>(inputs: &[BabyBear], build: G) -> BabyBear
    where
        G: FnOnce(&mut CircuitBuilder<BabyBear>, &[Target]) -> Target,
    {
        let mut builder = CircuitBuilder::<BabyBear>::new();
        let in_targets: Vec<Target> = (0..inputs.len()).map(|_| builder.public_input()).collect();
        let out = build(&mut builder, &in_targets);
        builder.tag(out, "out").unwrap();

        let circuit = builder.build().unwrap();
        let mut runner = circuit.runner();
        runner.set_public_inputs(inputs).unwrap();
        let traces = runner.run().unwrap();
        *traces.probe("out").unwrap()
    }

    /// Like [`eval_gadget`] but for a gadget producing several outputs; returns
    /// them in order.
    pub(crate) fn eval_gadget_multi<G>(inputs: &[BabyBear], build: G) -> Vec<BabyBear>
    where
        G: FnOnce(&mut CircuitBuilder<BabyBear>, &[Target]) -> Vec<Target>,
    {
        let mut builder = CircuitBuilder::<BabyBear>::new();
        let in_targets: Vec<Target> = (0..inputs.len()).map(|_| builder.public_input()).collect();
        let outs = build(&mut builder, &in_targets);
        let n = outs.len();
        for (i, out) in outs.iter().enumerate() {
            builder.tag(*out, format!("out{i}")).unwrap();
        }

        let circuit = builder.build().unwrap();
        let mut runner = circuit.runner();
        runner.set_public_inputs(inputs).unwrap();
        let traces = runner.run().unwrap();
        (0..n)
            .map(|i| *traces.probe(&format!("out{i}")).unwrap())
            .collect()
    }
}
