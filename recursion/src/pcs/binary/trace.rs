//! Released Boolean trace column routing followed by a checked bit opening.

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
use super::trace_plan::TracePlan;
use super::trace_routing::{TraceEntry as Entry, TraceRouting};
use super::{
    BinaryBooleanInputShape, BinaryBooleanPcsVerifier, BinaryBooleanProofTargets,
    NativeBinaryBooleanInput, RecursiveBinaryChallengeField,
};
use crate::verifier::{VerificationError, VerifierLimits};
use crate::{BinaryQueryContinuation, BinaryTower128Challenger};

#[derive(Clone, Debug)]
pub struct BinaryBooleanTraceVerifier<E> {
    routing: TraceRouting<E>,
    child: BinaryBooleanPcsVerifier<E>,
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
        Ok(Self {
            routing: TraceRouting::new(plan)?,
            child,
        })
    }

    pub fn input_shape(&self) -> BinaryBooleanTraceInputShape<E> {
        BinaryBooleanTraceInputShape {
            protocol: self.routing.plan.protocol.clone(),
            value_count: self.routing.plan.value_count,
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
        self.routing
            .check_points(points.iter().map(Vec::len), proof.values.len())?;
        self.child.check_targets(cap, &proof.opening)?;
        let entry = self.routing.bind::<BF, EF>(
            circuit,
            entry,
            points,
            &proof.values,
            &proof.opening.reduction.claims,
        )?;
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
        Ok((self.routing.evals(&proof.values), continuation))
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
        self.routing
            .check_points(points.iter().map(Point::num_variables), proof.values.len())?;
        self.child
            .check_native_structure(base_mmcs, round_mmcs, commitment, &proof.opening)?;
        let captured = route(
            self.routing.plan.num_variables,
            &self.routing.plan.protocol,
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

fn invalid(message: &'static str) -> VerificationError {
    VerificationError::InvalidProofShape(message.into())
}
