//! Field-neutral layer arithmetic; the closed adapters own all encodings.

use alloc::vec;
use alloc::vec::Vec;
use core::hash::Hash;

use p3_bus::ProductGkrRootShape;
use p3_circuit::CircuitBuilder;
use p3_circuit::ops::binary_host::BinaryCircuitHost;
use p3_field::Field;

use super::super::binary_field_policy::BinaryProtocolPolicy;
use crate::BinaryTower128Challenger;
use crate::verifier::VerificationError;

pub(crate) struct ProductLayerView<'a, T> {
    pub messages: &'a [Vec<T>],
    pub children: &'a [Vec<T>],
}

pub(crate) struct ProductKernelOutput<T> {
    pub roots: Vec<T>,
    pub point: Vec<T>,
    pub values: Vec<T>,
    pub challenger: BinaryTower128Challenger,
}

/// All shapes are checked by the adapter before this kernel adds constraints.
pub(crate) fn verify_layers<P, H, EF>(
    b: &mut CircuitBuilder<EF>,
    mut ch: BinaryTower128Challenger,
    transmitted_roots: &[P::ChallengeTarget],
    root_shape: ProductGkrRootShape,
    schedule: &[(usize, usize)],
    layers: &[ProductLayerView<'_, P::ChallengeTarget>],
    mut interpolate: impl FnMut(
        &mut CircuitBuilder<EF>,
        &P::ChallengeTarget,
        &[P::ChallengeTarget],
        &P::ChallengeTarget,
    ) -> Result<P::ChallengeTarget, VerificationError>,
) -> Result<ProductKernelOutput<P::ChallengeTarget>, VerificationError>
where
    P: BinaryProtocolPolicy<EF>,
    H: BinaryCircuitHost<EF>,
    EF: Field + Eq + Hash,
{
    P::observe::<H>(b, &mut ch, transmitted_roots)?;
    let roots = if root_shape == ProductGkrRootShape::FirstTwoShared {
        let mut roots = vec![transmitted_roots[0].clone(), transmitted_roots[0].clone()];
        roots.extend_from_slice(&transmitted_roots[1..]);
        roots
    } else {
        transmitted_roots.to_vec()
    };
    let mut values = roots.clone();
    let mut point = Vec::new();
    for (&(arity, _), layer) in schedule.iter().zip(layers) {
        let batching = P::sample::<H>(b, &mut ch)?;
        let mut claim = combine::<P, EF>(b, &values, &batching)?;
        let mut round_point = Vec::new();
        for polynomial in layer.messages {
            P::observe::<H>(b, &mut ch, polynomial)?;
            let challenge = P::sample::<H>(b, &mut ch)?;
            claim = interpolate(b, &claim, polynomial, &challenge)?;
            round_point.push(challenge);
            b.check_construction_limits()?;
        }
        let products: Vec<_> = layer
            .children
            .iter()
            .map(|children| {
                let mut product = children[0].clone();
                for child in &children[1..] {
                    product = P::mul(b, &product, child);
                    b.check_construction_limits()?;
                }
                b.check_construction_limits()?;
                Ok(product)
            })
            .collect::<Result<_, VerificationError>>()?;
        let mut expected = combine::<P, EF>(b, &products, &batching)?;
        if arity == 4 {
            let equality = P::eq_eval(b, &point, &round_point)?;
            expected = P::mul(b, &equality, &expected);
        }
        P::assert_equal(b, &claim, &expected);
        let children: Vec<_> = layer.children.iter().flatten().cloned().collect();
        P::observe::<H>(b, &mut ch, &children)?;
        let branches = (0..arity.trailing_zeros())
            .map(|_| P::sample::<H>(b, &mut ch))
            .collect::<Result<Vec<_>, _>>()?;
        values = layer
            .children
            .iter()
            .map(|children| {
                let low = pair::<P, EF>(b, &children[0], &children[1], &branches[0]);
                let value = if arity == 2 {
                    low
                } else {
                    let high = pair::<P, EF>(b, &children[2], &children[3], &branches[0]);
                    pair::<P, EF>(b, &low, &high, &branches[1])
                };
                b.check_construction_limits()?;
                Ok(value)
            })
            .collect::<Result<_, VerificationError>>()?;
        point = branches;
        point.extend(round_point);
    }
    point.reverse();
    Ok(ProductKernelOutput {
        roots,
        point,
        values,
        challenger: ch,
    })
}

fn pair<P: BinaryProtocolPolicy<EF>, EF: Field + Eq + Hash>(
    b: &mut CircuitBuilder<EF>,
    left: &P::ChallengeTarget,
    right: &P::ChallengeTarget,
    r: &P::ChallengeTarget,
) -> P::ChallengeTarget {
    let difference = P::add(b, left, right);
    let weighted = P::mul(b, &difference, r);
    P::add(b, left, &weighted)
}

fn combine<P: BinaryProtocolPolicy<EF>, EF: Field + Eq + Hash>(
    b: &mut CircuitBuilder<EF>,
    values: &[P::ChallengeTarget],
    batching: &P::ChallengeTarget,
) -> Result<P::ChallengeTarget, VerificationError> {
    let mut result = P::constant(b, 0)?;
    for value in values.iter().rev() {
        result = P::mul(b, &result, batching);
        result = P::add(b, &result, value);
        b.check_construction_limits()?;
    }
    Ok(result)
}
