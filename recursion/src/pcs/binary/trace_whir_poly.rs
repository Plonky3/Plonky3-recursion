//! Native Boolean trace column routing over Poly64 values followed by a full Poly64→Poly192
//! WHIR opening, in the native Poly64 carrier.

use alloc::vec::Vec;

use p3_binary_field::{Poly64, Poly192};
use p3_binary_pcs::BooleanTraceCommitmentProof;
use p3_binary_pcs::whir::BooleanWhirProof;
use p3_challenger::{CanObserve, CanSampleUniformBits, FieldChallenger, GrindingChallenger};
use p3_circuit::ops::{ByteHash, NativePoly192Target};
use p3_circuit::{CircuitBuilder, ExprId};
use p3_merkle_tree::MerkleCap;
use p3_multilinear_util::point::Point;
use p3_sumcheck::{OpeningBatch, OpeningProtocol};
use p3_whir::WhirConfig;

use super::boolean_whir_poly::ABSORBED;
use super::trace_native::route;
use super::trace_plan::TracePlan;
use super::trace_routing::TraceRouting;
use super::whir_plan::invalid;
use super::{
    BinaryPolyBooleanWhirInputShape, BinaryPolyBooleanWhirVerifier, ByteDigestMmcs, MerkleArity,
    NativeBinaryPolyBooleanWhirInput, NativePolyBooleanWhirProofTargets,
};
use crate::BinaryTower128Challenger;
use crate::verifier::{InputResourceUsage, VerificationError, VerifierLimits};

/// Sixteen-bit input limbs of one Poly192 value or point coordinate.
const VALUE_LIMBS: usize = 12;

/// A Boolean trace opening over Poly64 values with Poly192 challenges.
type PolyBooleanWhirTraceProof<M> =
    BooleanTraceCommitmentProof<Poly192, BooleanWhirProof<Poly64, Poly192, M>>;

/// Native verifier of a packed Boolean trace over Poly64 values: the column batch of one
/// table, the bit ring switch with every round, and the packed WHIR opening.
#[derive(Clone, Debug)]
pub struct BinaryPolyBooleanWhirTraceVerifier {
    routing: TraceRouting<Poly64, Poly192>,
    child: BinaryPolyBooleanWhirVerifier,
    usage: InputResourceUsage,
}

#[derive(Clone, Debug)]
pub struct NativePolyBooleanWhirTraceProofTargets {
    /// Protocol batch order, current values then next values in each batch.
    pub values: Vec<NativePoly192Target>,
    pub opening: NativePolyBooleanWhirProofTargets,
}

/// Pins the complete trace schedule, including unopened table placement, and the child WHIR
/// configuration independently of the concrete proof.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BinaryPolyBooleanWhirTraceInputShape {
    protocol: OpeningProtocol,
    value_count: usize,
    opening: BinaryPolyBooleanWhirInputShape,
}

impl BinaryPolyBooleanWhirTraceInputShape {
    pub(crate) fn native_decode_shape(
        &self,
    ) -> crate::artifact::binary_native::codec::BooleanTraceDecode<
        crate::artifact::binary_native::codec::WhirDecode,
    > {
        let (ring, packed) = self.opening.native_decode_shape();
        crate::artifact::binary_native::codec::BooleanTraceDecode {
            value_count: self.value_count,
            ring,
            packed,
        }
    }

    pub(crate) fn write_identity(
        &self,
        w: &mut crate::artifact::wire::Writer,
    ) -> Result<(), crate::artifact::ArtifactError> {
        let shapes = self.protocol.table_shapes();
        w.write_vec("binary WHIR trace tables", &shapes, |w, shape| {
            w.write_count("binary WHIR trace table height", shape.num_variables())?;
            w.write_count("binary WHIR trace table width", shape.width())
        })?;
        w.write_count("binary WHIR trace openings", self.protocol.num_openings())?;
        for (table, batch) in self.protocol.iter_openings() {
            w.write_count("binary WHIR trace opening table", table)?;
            for columns in [batch.current(), batch.next()] {
                w.write_vec(
                    "binary WHIR trace opening columns",
                    columns,
                    |w, &column| w.write_count("binary WHIR trace opening column", column),
                )?;
            }
        }
        self.opening.write_identity(w)
    }

    /// Three Poly64 inputs per opened value, then the packed opening's native inputs.
    pub fn allocate_native_targets(
        &self,
        b: &mut CircuitBuilder<Poly64>,
    ) -> Result<NativePolyBooleanWhirTraceProofTargets, VerificationError> {
        let values = (0..self.value_count)
            .map(|_| {
                let coefficients =
                    b.alloc_private_input_array::<3>("native Poly64 Boolean WHIR trace value");
                b.check_construction_limits()?;
                Ok(b.native_poly192_from_coefficients(coefficients))
            })
            .collect::<Result<_, VerificationError>>()?;
        Ok(NativePolyBooleanWhirTraceProofTargets {
            values,
            opening: self.opening.allocate_native_targets(b)?,
        })
    }
}

#[derive(Clone, Debug)]
pub struct NativeBinaryPolyBooleanWhirTraceInput {
    shape: BinaryPolyBooleanWhirTraceInputShape,
    values: Vec<Poly192>,
    opening: NativeBinaryPolyBooleanWhirInput,
}

impl NativeBinaryPolyBooleanWhirTraceInput {
    pub const fn shape(&self) -> &BinaryPolyBooleanWhirTraceInputShape {
        &self.shape
    }

    /// The native verifier's inputs, in allocation order.
    pub fn private_native_values(
        &self,
        expected: &BinaryPolyBooleanWhirTraceInputShape,
    ) -> Result<Vec<Poly64>, VerificationError> {
        if &self.shape != expected {
            return Err(invalid(
                "Poly64 Boolean WHIR trace input belongs to another verifier",
            ));
        }
        let mut values: Vec<_> = self
            .values
            .iter()
            .flat_map(|value| value.coefficients())
            .collect();
        values.extend(self.opening.private_native_values(&expected.opening)?);
        Ok(values)
    }
}

impl BinaryPolyBooleanWhirTraceVerifier {
    /// [`Self::with_limits`] for pairwise trees under the default limits.
    pub fn new<C>(
        config: &WhirConfig<Poly192, Poly64, C>,
        protocol: OpeningProtocol,
        hash: ByteHash,
        cap_height: usize,
    ) -> Result<Self, VerificationError>
    where
        C: FieldChallenger<Poly64> + GrindingChallenger<Witness = Poly64>,
    {
        Self::with_limits(
            config,
            protocol,
            hash,
            MerkleArity::Two,
            cap_height,
            &VerifierLimits::default(),
        )
    }

    /// Plans the routed bit openings over a tree whose nodes compress `arity` digests and
    /// whose cap replaces its top `cap_height` levels.
    pub fn with_limits<C>(
        config: &WhirConfig<Poly192, Poly64, C>,
        protocol: OpeningProtocol,
        hash: ByteHash,
        arity: MerkleArity,
        cap_height: usize,
        limits: &VerifierLimits,
    ) -> Result<Self, VerificationError>
    where
        C: FieldChallenger<Poly64> + GrindingChallenger<Witness = Poly64>,
    {
        let n = config.num_variables().checked_add(ABSORBED).ok_or(
            VerificationError::ResourceArithmeticOverflow {
                component: "Poly64 Boolean WHIR trace bit arity",
            },
        )?;
        let plan = TracePlan::with_value_limbs(protocol, n, VALUE_LIMBS, limits)?;
        let child = BinaryPolyBooleanWhirVerifier::with_limits(
            config,
            plan.specs.clone(),
            hash,
            arity,
            cap_height,
            limits,
        )?;
        let mut usage = plan.usage;
        usage.merge(limits, child.input_resource_usage())?;
        Ok(Self {
            routing: TraceRouting::new(plan)?,
            child,
            usage,
        })
    }

    pub const fn input_resource_usage(&self) -> InputResourceUsage {
        self.usage
    }

    /// The variables of the packed table's bit stack: the packed configuration's, and the six
    /// one Poly64 element absorbs.
    pub(crate) const fn bit_variables(&self) -> usize {
        self.routing.plan.num_variables
    }

    pub fn input_shape(&self) -> BinaryPolyBooleanWhirTraceInputShape {
        BinaryPolyBooleanWhirTraceInputShape {
            protocol: self.routing.plan.protocol.clone(),
            value_count: self.routing.plan.value_count,
            opening: self.child.input_shape(),
        }
    }

    /// The native carrier verifies the column-batched route of one table only, over a hash
    /// with a native circuit.
    pub(crate) fn check_native_circuit_support(&self) -> Result<(), VerificationError> {
        self.routing.native_run()?;
        self.child.check_native_circuit_support()
    }

    pub fn observe_commitment_native(
        &self,
        b: &mut CircuitBuilder<Poly64>,
        ch: &mut BinaryTower128Challenger,
        cap: &[Vec<ExprId>],
    ) -> Result<(), VerificationError> {
        self.child.observe_commitment_native(b, ch, cap)
    }

    /// Native target shapes at `points`: the opened values against the routing plan, then the
    /// packed opening's targets.
    pub(crate) fn check_native_targets(
        &self,
        b: &CircuitBuilder<Poly64>,
        cap: &[Vec<ExprId>],
        points: &[Vec<NativePoly192Target>],
        proof: &NativePolyBooleanWhirTraceProofTargets,
    ) -> Result<(), VerificationError> {
        self.routing
            .check_points(points.iter().map(Vec::len), proof.values.len())?;
        self.child.check_native_targets(b, cap, &proof.opening)
    }

    /// Binds the opened values to one column-batched ring claim per opening, runs every
    /// ring-switch round, authenticates the packed opening, and returns the opened values in
    /// protocol order with the exact challenger after the packed WHIR opening.
    pub fn verify_at_native(
        &self,
        b: &mut CircuitBuilder<Poly64>,
        ch: BinaryTower128Challenger,
        cap: &[Vec<ExprId>],
        points: &[Vec<NativePoly192Target>],
        proof: &NativePolyBooleanWhirTraceProofTargets,
    ) -> Result<
        (
            Vec<OpeningBatch<NativePoly192Target>>,
            BinaryTower128Challenger,
        ),
        VerificationError,
    > {
        self.check_native_circuit_support()?;
        self.check_native_targets(b, cap, points, proof)?;
        let (readings, ch) = self.routing.bind_native(b, ch, points, &proof.values)?;
        let ch = self
            .child
            .verify_readings_native(b, ch, cap, &readings, &proof.opening)?;
        Ok((self.routing.evals(&proof.values), ch))
    }

    pub(crate) fn check_native_structure_with_usage<C, M>(
        &self,
        config: &WhirConfig<Poly192, Poly64, C>,
        mmcs: &M,
        commitment: &MerkleCap<Poly64, [u8; 32]>,
        points: &[Point<Poly192>],
        proof: &PolyBooleanWhirTraceProof<M>,
        usage: &mut InputResourceUsage,
    ) -> Result<(), VerificationError>
    where
        C: FieldChallenger<Poly64> + GrindingChallenger<Witness = Poly64>,
        M: ByteDigestMmcs<Poly64>,
    {
        self.routing
            .check_points(points.iter().map(Point::num_variables), proof.values.len())?;
        self.child.check_native_structure_with_usage(
            config,
            mmcs,
            commitment,
            &proof.opening,
            usage,
        )
    }

    /// Checks both child proof shapes before replaying the native column route. Restored
    /// paths and captured readings supply witnesses, not authority. The caller's challenger
    /// moves to the exact native continuation on success and is unchanged on every error.
    pub fn import_native<C, Ch, M>(
        &self,
        config: &WhirConfig<Poly192, Poly64, C>,
        mmcs: &M,
        commitment: &MerkleCap<Poly64, [u8; 32]>,
        points: &[Point<Poly192>],
        proof: &PolyBooleanWhirTraceProof<M>,
        target_challenger: &mut Ch,
    ) -> Result<NativeBinaryPolyBooleanWhirTraceInput, VerificationError>
    where
        C: FieldChallenger<Poly64> + GrindingChallenger<Witness = Poly64>,
        M: ByteDigestMmcs<Poly64>,
        Ch: Clone
            + FieldChallenger<Poly64>
            + CanSampleUniformBits<Poly64>
            + GrindingChallenger<Witness = Poly64>
            + CanObserve<MerkleCap<Poly64, [u8; 32]>>,
    {
        self.check_native_structure_with_usage(
            config,
            mmcs,
            commitment,
            points,
            proof,
            &mut InputResourceUsage::default(),
        )?;
        let mut ch = target_challenger.clone();
        let plan = &self.routing.plan;
        let captured = route::<Poly64, Poly192, _>(
            plan.num_variables,
            &plan.protocol,
            points,
            &proof.values,
            &mut ch,
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
            config,
            mmcs,
            commitment,
            &lifted,
            &readings,
            &proof.opening,
            &mut ch,
        )?;
        *target_challenger = ch;
        Ok(NativeBinaryPolyBooleanWhirTraceInput {
            shape: self.input_shape(),
            values: proof.values.clone(),
            opening,
        })
    }
}
