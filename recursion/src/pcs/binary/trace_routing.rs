//! Shared native column routing for raw and WHIR Boolean commitments.

use alloc::vec;
use alloc::vec::Vec;
use core::hash::Hash;

use p3_binary_pcs::{ChallengeField, Coordinates, FoldAlphabet};
use p3_circuit::ops::BinaryTower128Target;
use p3_circuit::ops::binary_encoding::PrimeBinaryEncoding;
use p3_circuit::{CircuitBuilder, ExprId};
use p3_field::{ExtensionField, Field, PrimeField64};
use p3_multilinear_util::point::Point;
use p3_sumcheck::OpeningBatch;
use serde::Serialize;
use serde::de::DeserializeOwned;

use super::trace_native::route;
use super::trace_plan::{Route, TracePlan};
use super::verifier::{
    assert_equal, constrain_width, observe_seed, observe_values, seed_bytes_with_host,
};
use super::{BinaryRingClaimTargets, RecursiveBinaryChallengeField};
use crate::transcript::SeedTap;
use crate::verifier::VerificationError;
use crate::{BinaryQueryContinuation, BinaryTower128Challenger};

#[derive(Clone, Debug)]
pub(super) struct TraceRouting<E> {
    pub plan: TracePlan,
    column_seed: Vec<E>,
}

pub(super) enum TraceEntry {
    Ready(BinaryTower128Challenger),
    AfterQueries(BinaryQueryContinuation),
}

impl<E> TraceRouting<E>
where
    E: RecursiveBinaryChallengeField
        + ChallengeField<E>
        + FoldAlphabet<E>
        + Coordinates
        + Serialize
        + DeserializeOwned,
{
    pub fn new(plan: TracePlan) -> Result<Self, VerificationError> {
        let num_variables = plan.num_variables;
        let column_seed = if matches!(plan.route, Route::Batched { .. }) {
            let points = plan
                .point_arities
                .iter()
                .map(|&n| Point::new(vec![E::ZERO; n]))
                .collect::<Vec<_>>();
            let mut tap = SeedTap::new();
            let captured = route(
                num_variables,
                &plan.protocol,
                &points,
                &vec![E::ZERO; plan.value_count],
                &mut tap,
            )?;
            if captured.openings.len() != plan.specs.len() {
                return Err(invalid("binary trace route disagrees with native planning"));
            }
            tap.binary_seed()
        } else {
            vec![]
        };
        Ok(Self { plan, column_seed })
    }

    /// Binds every allocated ring claim to the native trace route. The owning
    /// wrapper preflights the complete child proof before calling this method.
    pub fn bind<BF, EF>(
        &self,
        circuit: &mut CircuitBuilder<EF>,
        entry: TraceEntry,
        points: &[Vec<BinaryTower128Target>],
        values: &[BinaryTower128Target],
        claims: &[BinaryRingClaimTargets<E>],
    ) -> Result<TraceEntry, VerificationError>
    where
        BF: PrimeField64,
        EF: ExtensionField<BF> + Eq + Hash,
    {
        self.check_points(points.iter().map(Vec::len), values.len())?;
        if claims.len() != self.plan.specs.len()
            || claims.iter().zip(&self.plan.specs).any(|(claim, spec)| {
                claim.point.len() != self.plan.num_variables
                    || claim.current.is_some() != spec.current
                    || claim.next.is_some() != spec.next_rows.is_some()
            })
        {
            return Err(invalid("binary trace ring claim shape mismatch"));
        }
        for value in points.iter().flatten().chain(values) {
            constrain_width(circuit, value, E::RAW_BITS);
        }
        let entry = match &self.plan.route {
            Route::Batched {
                width,
                columns,
                next,
            } => {
                let mut challenger = match entry {
                    TraceEntry::Ready(mut ch) => {
                        observe_seed::<E, BF, EF>(circuit, &mut ch, &self.column_seed)?;
                        ch
                    }
                    TraceEntry::AfterQueries(token) => {
                        let bytes = seed_bytes_with_host::<E, PrimeBinaryEncoding<BF>, EF>(
                            circuit,
                            &self.column_seed,
                        )?;
                        token.resume_with_observation::<BF, EF>(circuit, &bytes)?
                    }
                };
                let run = width * (1 + usize::from(*next));
                for ((point, values), claim) in
                    points.iter().zip(values.chunks_exact(run)).zip(claims)
                {
                    let (current, successor) = values.split_at(*width);
                    observe_values::<BF, EF>(circuit, &mut challenger, point, E::RAW_BITS)?;
                    observe_values::<BF, EF>(circuit, &mut challenger, current, E::RAW_BITS)?;
                    if *next {
                        observe_values::<BF, EF>(circuit, &mut challenger, successor, E::RAW_BITS)?;
                    }
                    let column_point = (0..*columns)
                        .map(|_| sample_challenge::<E, BF, EF>(circuit, &mut challenger))
                        .collect::<Result<Vec<_>, _>>()?;
                    let mut lifted = column_point.clone();
                    lifted.extend_from_slice(point);
                    bind_point(circuit, &claim.point, &lifted)?;
                    let current_value = combine_columns(circuit, current, &column_point)?;
                    assert_equal(
                        circuit,
                        claim.current.as_ref().expect("checked current request"),
                        &current_value,
                    );
                    if *next {
                        let next_value = combine_columns(circuit, successor, &column_point)?;
                        assert_equal(
                            circuit,
                            claim.next.as_ref().expect("checked next request"),
                            &next_value,
                        );
                    }
                }
                TraceEntry::Ready(challenger)
            }
            Route::Columns(routes) => {
                for (route, claim) in routes.iter().zip(claims) {
                    let mut lifted = route
                        .selector
                        .iter()
                        .map(|&bit| circuit.binary128_constant(u128::from(bit)))
                        .collect::<Result<Vec<_>, _>>()?;
                    lifted.extend_from_slice(&points[route.opening]);
                    bind_point(circuit, &claim.point, &lifted)?;
                    if let Some(at) = route.current_at {
                        assert_equal(
                            circuit,
                            claim.current.as_ref().expect("checked current request"),
                            &values[at],
                        );
                    }
                    if let Some(at) = route.next_at {
                        assert_equal(
                            circuit,
                            claim.next.as_ref().expect("checked next request"),
                            &values[at],
                        );
                    }
                }
                entry
            }
        };
        Ok(entry)
    }

    pub fn evals(
        &self,
        values: &[BinaryTower128Target],
    ) -> Vec<OpeningBatch<BinaryTower128Target>> {
        let mut cursor = 0;
        self.plan
            .protocol
            .iter_openings()
            .map(|(_, batch)| {
                let current = values[cursor..cursor + batch.current().len()].to_vec();
                cursor += batch.current().len();
                let next = values[cursor..cursor + batch.next().len()].to_vec();
                cursor += batch.next().len();
                OpeningBatch::new(current, next)
            })
            .collect()
    }

    pub fn check_points(
        &self,
        arities: impl Iterator<Item = usize>,
        values: usize,
    ) -> Result<(), VerificationError> {
        if values != self.plan.value_count || !arities.eq(self.plan.point_arities.iter().copied()) {
            return Err(invalid("binary trace row point or value count mismatch"));
        }
        Ok(())
    }
}

fn sample_challenge<E, BF, EF>(
    circuit: &mut CircuitBuilder<EF>,
    challenger: &mut BinaryTower128Challenger,
) -> Result<BinaryTower128Target, VerificationError>
where
    E: RecursiveBinaryChallengeField,
    BF: PrimeField64,
    EF: ExtensionField<BF> + Eq + Hash,
{
    let bytes = challenger.sample_bytes::<BF, EF>(circuit, E::RAW_BITS / 8)?;
    let mut bits = [ExprId::ZERO; 128];
    for (i, byte) in bytes.into_iter().enumerate() {
        let byte_bits = circuit.decompose_to_bits::<BF>(byte, 8)?;
        bits[8 * i..8 * i + 8].copy_from_slice(&byte_bits);
    }
    Ok(circuit.binary128_from_bits(bits)?)
}

fn combine_columns<EF: Field + Eq + Hash>(
    circuit: &mut CircuitBuilder<EF>,
    values: &[BinaryTower128Target],
    point: &[BinaryTower128Target],
) -> Result<BinaryTower128Target, VerificationError> {
    let zero = circuit.binary128_constant(0)?;
    let mut layer = values.to_vec();
    layer.resize(1usize << point.len(), zero);
    for coordinate in point.iter().rev() {
        layer = layer
            .chunks_exact(2)
            .map(|pair| {
                let difference = circuit.binary128_add(&pair[0], &pair[1]);
                let product = circuit.binary128_mul(coordinate, &difference);
                circuit.binary128_add(&pair[0], &product)
            })
            .collect();
    }
    Ok(layer[0].clone())
}

fn bind_point<EF: Field + Eq + Hash>(
    circuit: &mut CircuitBuilder<EF>,
    actual: &[BinaryTower128Target],
    expected: &[BinaryTower128Target],
) -> Result<(), VerificationError> {
    if actual.len() != expected.len() {
        return Err(invalid("binary trace lifted point arity mismatch"));
    }
    for (actual, expected) in actual.iter().zip(expected) {
        assert_equal(circuit, actual, expected);
    }
    Ok(())
}

fn invalid(message: &'static str) -> VerificationError {
    VerificationError::InvalidProofShape(message.into())
}
