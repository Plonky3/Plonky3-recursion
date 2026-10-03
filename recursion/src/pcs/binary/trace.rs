//! Released Boolean trace column routing followed by a checked bit opening.

use alloc::vec;
use alloc::vec::Vec;
use core::hash::Hash;

use p3_binary_pcs::{
    BinaryPcsConfig, BooleanTraceProof, ChallengeField, Coordinates, FoldAlphabet,
};
use p3_challenger::{CanObserve, CanSampleUniformBits, FieldChallenger, GrindingChallenger};
use p3_circuit::ops::{BinaryTower128Target, ByteHash};
use p3_circuit::{CircuitBuilder, ExprId};
use p3_field::{ExtensionField, Field, PackedValue, PrimeField64};
use p3_merkle_tree::{MerkleCap, MerkleTreeMmcs};
use p3_multilinear_util::point::Point;
use p3_sumcheck::{OpeningBatch, OpeningProtocol};
use p3_symmetric::{CryptographicHasher, PseudoCompressionFunction};
use serde::Serialize;
use serde::de::DeserializeOwned;

use super::trace_native::route;
use super::trace_plan::{Route, TracePlan};
use super::verifier::{assert_equal, constrain_width, observe_seed, observe_values, seed_bytes};
use super::{
    BinaryBooleanInputShape, BinaryBooleanPcsVerifier, BinaryBooleanProofTargets,
    NativeBinaryBooleanInput, RecursiveBinaryChallengeField,
};
use crate::transcript::SeedTap;
use crate::verifier::{VerificationError, VerifierLimits};
use crate::{BinaryQueryContinuation, BinaryTower128Challenger};

#[derive(Clone, Debug)]
pub struct BinaryBooleanTraceVerifier<E> {
    plan: TracePlan,
    child: BinaryBooleanPcsVerifier<E>,
    column_seed: Vec<E>,
}

#[derive(Clone, Debug)]
pub struct BinaryBooleanTraceProofTargets<E> {
    /// Batch order, current values then next values in each batch.
    pub values: Vec<BinaryTower128Target>,
    pub opening: BinaryBooleanProofTargets<E>,
}

/// Includes the complete trusted schedule, including unopened tables, so equal
/// counts never allow inputs to move between different column placements.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BinaryBooleanTraceInputShape<E> {
    protocol: OpeningProtocol,
    value_count: usize,
    opening: BinaryBooleanInputShape<E>,
}

impl<E: RecursiveBinaryChallengeField> BinaryBooleanTraceInputShape<E> {
    pub fn allocate_targets<BF, EF>(
        &self,
        circuit: &mut CircuitBuilder<EF>,
    ) -> Result<BinaryBooleanTraceProofTargets<E>, VerificationError>
    where
        BF: PrimeField64,
        EF: ExtensionField<BF> + Eq + Hash,
    {
        let values = (0..self.value_count)
            .map(|_| {
                let limbs = circuit.alloc_private_input_array::<8>("binary trace value");
                Ok(circuit.binary128_from_limbs::<BF>(limbs)?)
            })
            .collect::<Result<_, VerificationError>>()?;
        Ok(BinaryBooleanTraceProofTargets {
            values,
            opening: self.opening.allocate_targets::<BF, EF>(circuit)?,
        })
    }
}

#[derive(Clone, Debug)]
pub struct NativeBinaryBooleanTraceInput<E> {
    shape: BinaryBooleanTraceInputShape<E>,
    values: Vec<u128>,
    opening: NativeBinaryBooleanInput<E>,
}

impl<E: RecursiveBinaryChallengeField> NativeBinaryBooleanTraceInput<E> {
    pub fn shape(&self) -> &BinaryBooleanTraceInputShape<E> {
        &self.shape
    }
    pub fn private_values<EF: Field>(
        &self,
        expected: &BinaryBooleanTraceInputShape<E>,
    ) -> Result<Vec<EF>, VerificationError> {
        if &self.shape != expected {
            return Err(invalid(
                "binary trace input belongs to a different verifier",
            ));
        }
        let mut values = self
            .values
            .iter()
            .flat_map(|&v| (0..8).map(move |i| EF::from_u16((v >> (16 * i)) as u16)))
            .collect::<Vec<_>>();
        values.extend(self.opening.private_values::<EF>(&expected.opening)?);
        Ok(values)
    }
}

enum Entry {
    Ready(BinaryTower128Challenger),
    AfterQueries(BinaryQueryContinuation),
}

impl<E> BinaryBooleanTraceVerifier<E>
where
    E: RecursiveBinaryChallengeField
        + ExtensionField<E>
        + ChallengeField<E>
        + FoldAlphabet<E>
        + Coordinates
        + Serialize
        + DeserializeOwned,
{
    pub fn new(
        config: BinaryPcsConfig,
        protocol: OpeningProtocol,
        hash: ByteHash,
        cap_height: usize,
        max_query_draws: usize,
    ) -> Result<Self, VerificationError> {
        Self::with_limits(
            config,
            protocol,
            hash,
            cap_height,
            max_query_draws,
            &VerifierLimits::default(),
        )
    }

    pub fn with_limits(
        config: BinaryPcsConfig,
        protocol: OpeningProtocol,
        hash: ByteHash,
        cap_height: usize,
        max_query_draws: usize,
        limits: &VerifierLimits,
    ) -> Result<Self, VerificationError> {
        let num_variables = config
            .num_variables()
            .checked_add(E::RAW_BITS.ilog2() as usize)
            .ok_or(VerificationError::ResourceArithmeticOverflow {
                component: "binary trace bit arity",
            })?;
        let plan = TracePlan::new(protocol, num_variables, limits)?;
        let child = BinaryBooleanPcsVerifier::with_limits(
            config,
            plan.specs.clone(),
            hash,
            cap_height,
            max_query_draws,
            limits,
        )?;
        let mut usage = plan.usage;
        usage.merge(limits, child.usage)?;
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
        Ok(Self {
            plan,
            child,
            column_seed,
        })
    }

    pub fn input_shape(&self) -> BinaryBooleanTraceInputShape<E> {
        BinaryBooleanTraceInputShape {
            protocol: self.plan.protocol.clone(),
            value_count: self.plan.value_count,
            opening: self.child.input_shape(),
        }
    }

    pub fn observe_commitment<BF, EF>(
        &self,
        circuit: &mut CircuitBuilder<EF>,
        challenger: &mut BinaryTower128Challenger,
        cap: &[Vec<ExprId>],
    ) -> Result<(), VerificationError>
    where
        BF: PrimeField64,
        EF: ExtensionField<BF> + Eq + Hash,
    {
        self.child
            .observe_commitment::<BF, EF>(circuit, challenger, cap)
    }

    /// The caller supplies prescribed row points and binds the commitment. Every
    /// flat value and row coordinate is constrained to the native field width,
    /// then every allocated child claim is bound to its derived route.
    pub fn verify_at<BF, EF>(
        &self,
        circuit: &mut CircuitBuilder<EF>,
        challenger: BinaryTower128Challenger,
        cap: &[Vec<ExprId>],
        points: &[Vec<BinaryTower128Target>],
        proof: &BinaryBooleanTraceProofTargets<E>,
    ) -> Result<Vec<OpeningBatch<BinaryTower128Target>>, VerificationError>
    where
        BF: PrimeField64,
        EF: ExtensionField<BF> + Eq + Hash,
    {
        self.verify_at_with_continuation::<BF, EF>(circuit, challenger, cap, points, proof)
            .map(|(evals, _)| evals)
    }

    pub fn verify_at_with_continuation<BF, EF>(
        &self,
        circuit: &mut CircuitBuilder<EF>,
        challenger: BinaryTower128Challenger,
        cap: &[Vec<ExprId>],
        points: &[Vec<BinaryTower128Target>],
        proof: &BinaryBooleanTraceProofTargets<E>,
    ) -> Result<
        (
            Vec<OpeningBatch<BinaryTower128Target>>,
            BinaryQueryContinuation,
        ),
        VerificationError,
    >
    where
        BF: PrimeField64,
        EF: ExtensionField<BF> + Eq + Hash,
    {
        self.verify_impl::<BF, EF>(circuit, Entry::Ready(challenger), cap, points, proof)
    }

    pub fn verify_at_after_queries<BF, EF>(
        &self,
        circuit: &mut CircuitBuilder<EF>,
        continuation: BinaryQueryContinuation,
        cap: &[Vec<ExprId>],
        points: &[Vec<BinaryTower128Target>],
        proof: &BinaryBooleanTraceProofTargets<E>,
    ) -> Result<
        (
            Vec<OpeningBatch<BinaryTower128Target>>,
            BinaryQueryContinuation,
        ),
        VerificationError,
    >
    where
        BF: PrimeField64,
        EF: ExtensionField<BF> + Eq + Hash,
    {
        self.verify_impl::<BF, EF>(
            circuit,
            Entry::AfterQueries(continuation),
            cap,
            points,
            proof,
        )
    }

    fn verify_impl<BF, EF>(
        &self,
        circuit: &mut CircuitBuilder<EF>,
        entry: Entry,
        cap: &[Vec<ExprId>],
        points: &[Vec<BinaryTower128Target>],
        proof: &BinaryBooleanTraceProofTargets<E>,
    ) -> Result<
        (
            Vec<OpeningBatch<BinaryTower128Target>>,
            BinaryQueryContinuation,
        ),
        VerificationError,
    >
    where
        BF: PrimeField64,
        EF: ExtensionField<BF> + Eq + Hash,
    {
        self.check_points(points.iter().map(Vec::len), proof.values.len())?;
        self.child.check_targets(cap, &proof.opening)?;
        for value in points.iter().flatten().chain(&proof.values) {
            constrain_width(circuit, value, E::RAW_BITS);
        }
        let entry = match &self.plan.route {
            Route::Batched {
                width,
                columns,
                next,
            } => {
                let mut challenger = match entry {
                    Entry::Ready(mut ch) => {
                        observe_seed::<E, BF, EF>(circuit, &mut ch, &self.column_seed)?;
                        ch
                    }
                    Entry::AfterQueries(token) => {
                        let bytes = seed_bytes(circuit, &self.column_seed);
                        token.resume_with_observation::<BF, EF>(circuit, &bytes)?
                    }
                };
                let run = width * (1 + usize::from(*next));
                for ((point, values), claim) in points
                    .iter()
                    .zip(proof.values.chunks_exact(run))
                    .zip(&proof.opening.reduction.claims)
                {
                    let (current, successor) = values.split_at(*width);
                    observe_values::<BF, EF>(circuit, &mut challenger, point, E::RAW_BITS)?;
                    observe_values::<BF, EF>(circuit, &mut challenger, current, E::RAW_BITS)?;
                    if *next {
                        observe_values::<BF, EF>(circuit, &mut challenger, successor, E::RAW_BITS)?;
                    }
                    let column_point = (0..*columns)
                        .map(|_| {
                            self.child
                                .sample_challenge::<BF, EF>(circuit, &mut challenger)
                        })
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
                Entry::Ready(challenger)
            }
            Route::Columns(claims) => {
                for (route, claim) in claims.iter().zip(&proof.opening.reduction.claims) {
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
                            &proof.values[at],
                        );
                    }
                    if let Some(at) = route.next_at {
                        assert_equal(
                            circuit,
                            claim.next.as_ref().expect("checked next request"),
                            &proof.values[at],
                        );
                    }
                }
                entry
            }
        };
        let continuation = match entry {
            Entry::Ready(ch) => self.child.verify_readings_with_continuation::<BF, EF>(
                circuit,
                ch,
                cap,
                &proof.opening,
            )?,
            Entry::AfterQueries(token) => self.child.verify_readings_after_queries::<BF, EF>(
                circuit,
                token,
                cap,
                &proof.opening,
            )?,
        };
        let mut cursor = 0;
        let evals = self
            .plan
            .protocol
            .iter_openings()
            .map(|(_, batch)| {
                let current = proof.values[cursor..cursor + batch.current().len()].to_vec();
                cursor += batch.current().len();
                let next = proof.values[cursor..cursor + batch.next().len()].to_vec();
                cursor += batch.next().len();
                OpeningBatch::new(current, next)
            })
            .collect();
        Ok((evals, continuation))
    }

    fn check_points(
        &self,
        arities: impl Iterator<Item = usize>,
        values: usize,
    ) -> Result<(), VerificationError> {
        if values != self.plan.value_count || !arities.eq(self.plan.point_arities.iter().copied()) {
            return Err(invalid("binary trace row point or value count mismatch"));
        }
        Ok(())
    }

    /// Native routing is witness extraction. It never replaces the child ring,
    /// PCS or Merkle checks. Proof-independent structure is checked before the
    /// column transcript, and query sampling remains explicitly bounded.
    pub fn import_native<H0, C0, H1, C1, Ch>(
        &self,
        base_mmcs: &MerkleTreeMmcs<E, u8, H0, C0, 2, 32>,
        round_mmcs: &MerkleTreeMmcs<E, u8, H1, C1, 2, 32>,
        commitment: &MerkleCap<E, [u8; 32]>,
        points: &[Point<E>],
        proof: &BooleanTraceProof<
            E,
            MerkleTreeMmcs<E, u8, H0, C0, 2, 32>,
            MerkleTreeMmcs<E, u8, H1, C1, 2, 32>,
        >,
        mut challenger: Ch,
    ) -> Result<NativeBinaryBooleanTraceInput<E>, VerificationError>
    where
        E: PackedValue<Value = E>,
        H0: CryptographicHasher<E, [u8; 32]> + Sync,
        H1: CryptographicHasher<E, [u8; 32]> + Sync,
        C0: PseudoCompressionFunction<[u8; 32], 2> + Sync,
        C1: PseudoCompressionFunction<[u8; 32], 2> + Sync,
        Ch: FieldChallenger<E>
            + CanSampleUniformBits<E>
            + GrindingChallenger<Witness = E>
            + CanObserve<MerkleCap<E, [u8; 32]>>,
    {
        self.check_points(points.iter().map(Point::num_variables), proof.values.len())?;
        self.child
            .check_native_structure(base_mmcs, round_mmcs, commitment, &proof.opening)?;
        let captured = route(
            self.plan.num_variables,
            &self.plan.protocol,
            points,
            &proof.values,
            &mut challenger,
        )?;
        let lifted = captured
            .openings
            .iter()
            .map(|o| o.point.clone())
            .collect::<Vec<_>>();
        let readings = captured
            .readings
            .iter()
            .map(|r| (r.current, r.next))
            .collect::<Vec<_>>();
        let opening = self.child.import_native(
            base_mmcs,
            round_mmcs,
            commitment,
            &lifted,
            &readings,
            &proof.opening,
            challenger,
        )?;
        Ok(NativeBinaryBooleanTraceInput {
            shape: self.input_shape(),
            values: proof
                .values
                .iter()
                .copied()
                .map(E::raw_coordinates)
                .collect(),
            opening,
        })
    }
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
