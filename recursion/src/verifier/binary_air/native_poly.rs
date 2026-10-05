//! Native Poly64 AIR expressions with full three-coefficient challenges.

use core::hash::Hash;

use p3_binary_field::{Poly64, Poly192};
use p3_circuit::ops::NativePoly192Target;
use p3_circuit::{CircuitBuilder, ExprId};
use p3_field::Field;

use super::{
    BinaryAirEvaluation, BinaryPolyAirConstraintPlan, BinaryRelationPolicy, VerificationError,
};
use crate::verifier::binary_field_policy::NativePoly64Relation;

impl BinaryPolyAirConstraintPlan {
    /// Arithmetic fold only; the surrounding relation authenticates all openings.
    /// Public values are native Poly64 cells, while openings and points retain
    /// all three Poly192 coefficients.
    pub fn evaluate_native(
        &self,
        b: &mut CircuitBuilder<Poly64>,
        point: &[NativePoly192Target],
        current: &[NativePoly192Target],
        next: &[NativePoly192Target],
        public: &[ExprId],
        alpha: &NativePoly192Target,
    ) -> Result<NativePoly192Target, VerificationError> {
        self.evaluate_native_with_auxiliary(b, point, current, next, &[], &[], public, alpha)
    }

    pub fn evaluate_native_with_auxiliary(
        &self,
        b: &mut CircuitBuilder<Poly64>,
        point: &[NativePoly192Target],
        current: &[NativePoly192Target],
        next: &[NativePoly192Target],
        preprocessed_current: &[NativePoly192Target],
        preprocessed_next: &[NativePoly192Target],
        public: &[ExprId],
        alpha: &NativePoly192Target,
    ) -> Result<NativePoly192Target, VerificationError> {
        self.evaluate_using::<NativePoly64Relation, Poly64>(
            b,
            point,
            current,
            next,
            preprocessed_current,
            preprocessed_next,
            public,
            alpha,
        )
        .map(|evaluation| evaluation.folded)
    }

    pub(in crate::verifier) fn evaluate_using<P, CF>(
        &self,
        b: &mut CircuitBuilder<CF>,
        point: &[P::ChallengeTarget],
        current: &[P::ChallengeTarget],
        next: &[P::ChallengeTarget],
        preprocessed_current: &[P::ChallengeTarget],
        preprocessed_next: &[P::ChallengeTarget],
        public: &[P::BaseTarget],
        alpha: &P::ChallengeTarget,
    ) -> Result<BinaryAirEvaluation<P::ChallengeTarget>, VerificationError>
    where
        CF: Field + Eq + Hash,
        P: BinaryRelationPolicy<CF, Base = Poly64, Challenge = Poly192>,
    {
        self.program.evaluate::<P, CF>(
            b,
            point,
            current,
            next,
            preprocessed_current,
            preprocessed_next,
            public,
            alpha,
        )
    }
}
