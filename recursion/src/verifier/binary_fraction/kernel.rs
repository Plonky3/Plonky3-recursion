//! Closed binary Fraction-GKR layer arithmetic and continuation handling.
use super::super::binary_field_policy::BinaryProtocolPolicy;
use crate::{BinaryQueryContinuation, BinaryTower128Challenger, verifier::VerificationError};
use alloc::vec;
use alloc::vec::Vec;
use core::hash::Hash;
use p3_circuit::CircuitBuilder;
use p3_field::{ExtensionField, Field, PrimeField64};

pub(crate) struct FractionLayerView<'a, T> {
    pub messages: &'a [[T; 3]],
    pub claims: &'a [T; 4],
}
pub(crate) struct FractionDraw<T> {
    pub value: T,
    pub following: Option<T>,
    pub continuation: BinaryQueryContinuation,
}
pub(crate) struct FractionKernelOutput<T> {
    pub point: Vec<T>,
    pub numerator: T,
    pub denominator: T,
    pub continuation: BinaryQueryContinuation,
}

/// The adapter checks nonempty geometry and the root before this kernel runs.
pub(crate) fn verify_layers<P, BF, EF>(
    b: &mut CircuitBuilder<EF>,
    mut ch: BinaryTower128Challenger,
    root_denominator: &P::ChallengeTarget,
    layers: &[FractionLayerView<'_, P::ChallengeTarget>],
    mut interpolate: impl FnMut(
        &mut CircuitBuilder<EF>,
        &P::ChallengeTarget,
        &[P::ChallengeTarget],
        &P::ChallengeTarget,
    ) -> Result<P::ChallengeTarget, VerificationError>,
    mut draw: impl FnMut(
        &mut CircuitBuilder<EF>,
        BinaryTower128Challenger,
        bool,
    ) -> Result<FractionDraw<P::ChallengeTarget>, VerificationError>,
) -> Result<FractionKernelOutput<P::ChallengeTarget>, VerificationError>
where
    P: BinaryProtocolPolicy,
    BF: PrimeField64,
    EF: ExtensionField<BF> + Eq + Hash,
{
    P::observe::<BF, EF>(b, &mut ch, core::slice::from_ref(root_denominator))?;
    let mut lambda = P::sample::<BF, EF>(b, &mut ch)?;
    let mut state = MessageState::Live(ch);
    let mut numerator = P::constant(b, 0)?;
    let mut denominator = root_denominator.clone();
    let mut point = Vec::new();
    for (index, layer) in layers.iter().enumerate() {
        let weighted = P::mul(b, &lambda, &denominator);
        let mut claim = P::add(b, &numerator, &weighted);
        let mut round_point = Vec::with_capacity(index + 1);
        for polynomial in layer.messages {
            let ch = state.observe::<P, BF, EF>(b, polynomial)?;
            let output = draw(b, ch, false)?;
            claim = interpolate(b, &claim, polynomial, &output.value)?;
            round_point.push(output.value);
            state = MessageState::Waiting(output.continuation);
        }
        let [n0, d0, n1, d1] = layer.claims;
        let left = P::mul(b, d1, n0);
        let right = P::mul(b, d0, n1);
        let product = P::mul(b, d0, d1);
        let weighted = P::mul(b, &lambda, &product);
        let sum = P::add(b, &left, &right);
        let gate = P::add(b, &sum, &weighted);
        let equality = P::eq_eval(b, &point, &round_point)?;
        let expected = P::mul(b, &equality, &gate);
        P::assert_equal(b, &claim, &expected);
        let ch = state.observe::<P, BF, EF>(b, layer.claims)?;
        let final_layer = index + 1 == layers.len();
        let output = draw(b, ch, !final_layer)?;
        if !final_layer {
            lambda = output.following.expect("trusted nonfinal batching tail");
        }
        numerator = pair::<P, EF>(b, n0, n1, &output.value);
        denominator = pair::<P, EF>(b, d0, d1, &output.value);
        point = vec![output.value];
        point.extend(round_point);
        if final_layer {
            // Fraction points already use MSB-first order, unlike Product-GKR.
            return Ok(FractionKernelOutput {
                point,
                numerator,
                denominator,
                continuation: output.continuation,
            });
        }
        state = MessageState::Waiting(output.continuation);
    }
    unreachable!("trusted positive fraction height")
}

enum MessageState {
    Live(BinaryTower128Challenger),
    Waiting(BinaryQueryContinuation),
}
impl MessageState {
    fn observe<P, BF, EF>(
        self,
        b: &mut CircuitBuilder<EF>,
        values: &[P::ChallengeTarget],
    ) -> Result<BinaryTower128Challenger, VerificationError>
    where
        P: BinaryProtocolPolicy,
        BF: PrimeField64,
        EF: ExtensionField<BF> + Eq + Hash,
    {
        match self {
            Self::Live(mut ch) => {
                P::observe::<BF, EF>(b, &mut ch, values)?;
                Ok(ch)
            }
            Self::Waiting(token) => P::observe_after_queries::<BF, EF>(b, token, values),
        }
    }
}
fn pair<P: BinaryProtocolPolicy, EF: Field + Eq + Hash>(
    b: &mut CircuitBuilder<EF>,
    a: &P::ChallengeTarget,
    c: &P::ChallengeTarget,
    r: &P::ChallengeTarget,
) -> P::ChallengeTarget {
    let difference = P::add(b, a, c);
    let weighted = P::mul(b, &difference, r);
    P::add(b, a, &weighted)
}
