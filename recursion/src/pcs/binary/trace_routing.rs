//! Shared native column routing for raw and WHIR Boolean commitments.

use alloc::vec;
use alloc::vec::Vec;
use core::hash::Hash;
use core::marker::PhantomData;

use p3_binary_field::{BinaryField128, BitCoordinates, Poly64, Poly192, TowerLevel};
use p3_binary_pcs::{ChallengeField, Coordinates, FoldAlphabet};
use p3_challenger::fs::TranscriptField;
use p3_circuit::ops::binary_encoding::{NativeBinaryEncoding, PrimeBinaryEncoding};
use p3_circuit::ops::binary_host::BinaryCircuitHost;
use p3_circuit::ops::{BinaryTower128Target, NativePoly192Target, NativeTower128Target};
use p3_circuit::{CircuitBuilder, ExprId};
use p3_field::{ExtensionField, Field, PrimeField64};
use p3_multilinear_util::point::Point;
use p3_sumcheck::layout::plan_stacked_layout;
use p3_sumcheck::{OpeningBatch, OpeningProtocol, TableSpec};
use serde::Serialize;
use serde::de::DeserializeOwned;

use super::trace_native::route;
use super::trace_plan::{Route, TableRun, TracePlan};
use super::verifier::{
    assert_equal, constrain_width, observe_seed, observe_seed_with_host, observe_values,
    seed_bytes_with_host,
};
use super::{
    BinaryRingClaimTargets, NativeBitRingReading, NativePolyBitRingReading,
    RecursiveBinaryChallengeField,
};
use crate::transcript::SeedTap;
use crate::verifier::VerificationError;
use crate::verifier::binary_field_policy::{
    BinaryProtocolPolicy, NativePoly64Relation, NativeTower128Relation, poly_observe_seed_with_host,
};
use crate::{BinaryQueryContinuation, BinaryTower128Challenger};

/// Routing of a trace whose bits are packed into values of `F` and read at points of `E`.
#[derive(Clone, Debug)]
pub(super) struct TraceRouting<F, E = F> {
    pub plan: TracePlan,
    /// One column-batching seed per batched table run.
    column_seeds: Vec<Vec<F>>,
    challenge: PhantomData<E>,
}

/// One opening's ring claim on the native column-batched route: the lifted point
/// `column point || row point`, and the current and successor values combined at the column
/// point.
struct NativeColumnReading<T> {
    point: Vec<T>,
    current: T,
    next: Option<T>,
}

/// Every opening's ring claim on the native column-batched route, with the challenger after
/// the column batch.
type NativeColumnRoute<T> = (Vec<NativeColumnReading<T>>, BinaryTower128Challenger);

/// Observes a column-batching seed in a native carrier.
type ObserveSeed<F, CF> = fn(
    &mut CircuitBuilder<CF>,
    &mut BinaryTower128Challenger,
    &[F],
) -> Result<(), VerificationError>;

pub(super) enum TraceEntry {
    Ready(BinaryTower128Challenger),
    AfterQueries(BinaryQueryContinuation),
}

impl<F, E> TraceRouting<F, E>
where
    F: TranscriptField + TowerLevel + Serialize + DeserializeOwned,
    E: BitCoordinates + ExtensionField<F>,
{
    pub fn new(plan: TracePlan) -> Result<Self, VerificationError> {
        let column_seeds = match &plan.route {
            Route::Batched(runs) => {
                let captured =
                    Self::route_zeros(plan.num_variables, &plan.protocol, &mut SeedTap::new())?;
                if captured.openings.len() != plan.specs.len() {
                    return Err(invalid("binary trace route disagrees with native planning"));
                }
                // Each run opens its own transcript, whose seed only its table's batches fix.
                runs.iter()
                    .map(|run| {
                        let shape = plan.protocol.table_shapes()[run.table];
                        let schedule = plan
                            .protocol
                            .iter_openings()
                            .filter(|&(table, _)| table == run.table)
                            .map(|(_, batch)| batch.clone())
                            .collect();
                        let protocol = OpeningProtocol::new(vec![TableSpec::new(shape, schedule)]);
                        let (arity, _) = plan_stacked_layout(&[shape]);
                        let mut tap = SeedTap::new();
                        Self::route_zeros(arity, &protocol, &mut tap)?;
                        Ok(tap.binary_seed())
                    })
                    .collect::<Result<Vec<_>, VerificationError>>()?
            }
            Route::Columns(_) => vec![],
        };
        Ok(Self {
            plan,
            column_seeds,
            challenge: PhantomData,
        })
    }

    /// Replays the native route over zero points and values through `tap`.
    fn route_zeros(
        num_variables: usize,
        protocol: &OpeningProtocol,
        tap: &mut SeedTap<F>,
    ) -> Result<super::trace_native::TraceReadings<E>, VerificationError> {
        let shapes = protocol.table_shapes();
        let points = protocol
            .iter_openings()
            .map(|(table, _)| Point::new(vec![E::ZERO; shapes[table].num_variables()]))
            .collect::<Vec<_>>();
        let values =
            protocol
                .checked_num_claims()
                .ok_or(VerificationError::ResourceArithmeticOverflow {
                    component: "binary trace values",
                })?;
        route::<F, E, _>(
            num_variables,
            protocol,
            &points,
            &vec![E::ZERO; values],
            tap,
        )
    }
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
            Route::Batched(runs) => {
                let mut entry = entry;
                let mut points = points.iter();
                let mut values = values;
                let mut claims = claims.iter();
                for (run, seed) in runs.iter().zip(&self.column_seeds) {
                    let mut challenger = match entry {
                        TraceEntry::Ready(mut ch) => {
                            observe_seed::<E, BF, EF>(circuit, &mut ch, seed)?;
                            ch
                        }
                        TraceEntry::AfterQueries(token) => {
                            let bytes = seed_bytes_with_host::<E, PrimeBinaryEncoding<BF>, EF>(
                                circuit, seed,
                            )?;
                            token.resume_with_observation::<BF, EF>(circuit, &bytes)?
                        }
                    };
                    let per_batch = run.width * (1 + usize::from(run.next));
                    let (run_values, rest) = values.split_at(per_batch * run.batches);
                    values = rest;
                    for (point, values) in points
                        .by_ref()
                        .take(run.batches)
                        .zip(run_values.chunks_exact(per_batch))
                    {
                        let (current, successor) = values.split_at(run.width);
                        observe_values::<BF, EF>(circuit, &mut challenger, point, E::RAW_BITS)?;
                        observe_values::<BF, EF>(circuit, &mut challenger, current, E::RAW_BITS)?;
                        if run.next {
                            observe_values::<BF, EF>(
                                circuit,
                                &mut challenger,
                                successor,
                                E::RAW_BITS,
                            )?;
                        }
                        let column_point = (0..run.columns)
                            .map(|_| sample_challenge::<E, BF, EF>(circuit, &mut challenger))
                            .collect::<Result<Vec<_>, _>>()?;
                        // Block `b` reads its columns at the first `j_b` column coordinates.
                        for block in &run.blocks {
                            let claim = claims.next().expect("checked ring claim count");
                            let columns =
                                block.first..(block.first + (1 << block.variables)).min(run.width);
                            let block_point = &column_point[..block.variables];
                            let mut lifted = block
                                .selector
                                .iter()
                                .map(|&bit| circuit.binary128_constant(u128::from(bit)))
                                .collect::<Result<Vec<_>, _>>()?;
                            lifted.extend_from_slice(block_point);
                            lifted.extend_from_slice(point);
                            bind_point(circuit, &claim.point, &lifted)?;
                            let current_value =
                                combine_columns(circuit, &current[columns.clone()], block_point)?;
                            assert_equal(
                                circuit,
                                claim.current.as_ref().expect("checked current request"),
                                &current_value,
                            );
                            if run.next {
                                let next_value =
                                    combine_columns(circuit, &successor[columns], block_point)?;
                                assert_equal(
                                    circuit,
                                    claim.next.as_ref().expect("checked next request"),
                                    &next_value,
                                );
                            }
                        }
                    }
                    entry = TraceEntry::Ready(challenger);
                }
                entry
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
}

impl<F, E> TraceRouting<F, E> {
    pub fn evals<T: Clone>(&self, values: &[T]) -> Vec<OpeningBatch<T>> {
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

    /// The run the native carrier replays, with its column-batching seed: the batched route of
    /// one table alone, whose column slots form one block read at `column point || row point`.
    pub(super) fn native_run(&self) -> Result<(&TableRun, &[F]), VerificationError> {
        let unsupported = || {
            invalid(
                "native binary trace routing supports only the column-batched route of one table",
            )
        };
        let Route::Batched(runs) = &self.plan.route else {
            return Err(unsupported());
        };
        let ([run], [seed]) = (runs.as_slice(), self.column_seeds.as_slice()) else {
            return Err(unsupported());
        };
        match run.blocks.as_slice() {
            [block]
                if block.selector.is_empty()
                    && block.first == 0
                    && block.variables == run.columns =>
            {
                Ok((run, seed))
            }
            _ => Err(unsupported()),
        }
    }

    /// Replays the column batch of the batched route in a native carrier and returns each
    /// opening's ring claim: the lifted point `column point || row point`, with the current
    /// and successor values combined at the column point. The column point is drawn after the
    /// row point and every opened value are absorbed.
    fn bind_native_using<P, CF>(
        &self,
        b: &mut CircuitBuilder<CF>,
        mut ch: BinaryTower128Challenger,
        points: &[Vec<P::ChallengeTarget>],
        values: &[P::ChallengeTarget],
        observe_seed: ObserveSeed<F, CF>,
    ) -> Result<NativeColumnRoute<P::ChallengeTarget>, VerificationError>
    where
        CF: Field + Eq + Hash,
        NativeBinaryEncoding: BinaryCircuitHost<CF>,
        P: BinaryProtocolPolicy<CF>,
    {
        type H = NativeBinaryEncoding;
        self.check_points(points.iter().map(Vec::len), values.len())?;
        let (run, seed) = self.native_run()?;
        observe_seed(b, &mut ch, seed)?;
        let per_batch = run.width * (1 + usize::from(run.next));
        let mut readings = Vec::with_capacity(points.len());
        for (point, values) in points.iter().zip(values.chunks_exact(per_batch)) {
            let (current, successor) = values.split_at(run.width);
            P::observe::<H>(b, &mut ch, point)?;
            P::observe::<H>(b, &mut ch, current)?;
            if run.next {
                P::observe::<H>(b, &mut ch, successor)?;
            }
            let column_point = (0..run.columns)
                .map(|_| P::sample::<H>(b, &mut ch))
                .collect::<Result<Vec<_>, _>>()?;
            let current = combine_native::<P, CF>(b, current, &column_point)?;
            let successor = run
                .next
                .then(|| combine_native::<P, CF>(b, successor, &column_point))
                .transpose()?;
            let mut lifted = column_point;
            lifted.extend_from_slice(point);
            readings.push(NativeColumnReading {
                point: lifted,
                current,
                next: successor,
            });
            b.check_construction_limits()?;
        }
        Ok((readings, ch))
    }
}

impl TraceRouting<BinaryField128> {
    /// The native column batch in the Tower128 carrier.
    pub fn bind_native(
        &self,
        b: &mut CircuitBuilder<BinaryField128>,
        ch: BinaryTower128Challenger,
        points: &[Vec<NativeTower128Target>],
        values: &[NativeTower128Target],
    ) -> Result<(Vec<NativeBitRingReading>, BinaryTower128Challenger), VerificationError> {
        let (readings, ch) = self
            .bind_native_using::<NativeTower128Relation<BinaryField128>, BinaryField128>(
                b,
                ch,
                points,
                values,
                observe_seed_with_host::<BinaryField128, NativeBinaryEncoding, BinaryField128>,
            )?;
        let readings = readings
            .into_iter()
            .map(|reading| NativeBitRingReading {
                point: reading.point,
                current: Some(reading.current),
                next: reading.next,
            })
            .collect();
        Ok((readings, ch))
    }
}

impl TraceRouting<Poly64, Poly192> {
    /// The native column batch in the Poly64 carrier, with Poly192 points, values and column
    /// coordinates.
    pub fn bind_native(
        &self,
        b: &mut CircuitBuilder<Poly64>,
        ch: BinaryTower128Challenger,
        points: &[Vec<NativePoly192Target>],
        values: &[NativePoly192Target],
    ) -> Result<(Vec<NativePolyBitRingReading>, BinaryTower128Challenger), VerificationError> {
        let (readings, ch) = self.bind_native_using::<NativePoly64Relation, Poly64>(
            b,
            ch,
            points,
            values,
            poly_observe_seed_with_host::<NativeBinaryEncoding, Poly64>,
        )?;
        let readings = readings
            .into_iter()
            .map(|reading| NativePolyBitRingReading {
                point: reading.point,
                current: Some(reading.current),
                next: reading.next,
            })
            .collect();
        Ok((readings, ch))
    }
}

/// `sum_j eq(point, j) * values[j]`, missing values reading as zero, with the point's first
/// coordinate as the most significant index bit.
fn combine_native<P, CF>(
    b: &mut CircuitBuilder<CF>,
    values: &[P::ChallengeTarget],
    point: &[P::ChallengeTarget],
) -> Result<P::ChallengeTarget, VerificationError>
where
    CF: Field + Eq + Hash,
    P: BinaryProtocolPolicy<CF>,
{
    let zero = P::constant(b, 0)?;
    let mut layer = values.to_vec();
    layer.resize(1usize << point.len(), zero);
    for coordinate in point.iter().rev() {
        layer = layer
            .as_chunks::<2>()
            .0
            .iter()
            .map(|[low, high]| {
                let slope = P::add(b, low, high);
                P::mul_add(b, coordinate, &slope, low)
            })
            .collect();
    }
    Ok(layer.swap_remove(0))
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
            .as_chunks::<2>()
            .0
            .iter()
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
