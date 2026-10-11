//! Poly64 bit ring-switch readings closed against the released additive Poly64→Poly192 WHIR
//! PCS, in the native Poly64 carrier.

use alloc::vec;
use alloc::vec::Vec;

use p3_binary_field::{Poly64, Poly192};
use p3_binary_pcs::whir::BooleanWhirProof;
use p3_challenger::{CanObserve, CanSampleUniformBits, FieldChallenger, GrindingChallenger};
use p3_circuit::ops::binary_encoding::NativeBinaryEncoding;
use p3_circuit::ops::{ByteHash, NativePoly192Target};
use p3_circuit::{CircuitBuilder, ExprId};
use p3_field::PrimeCharacteristicRing;
use p3_merkle_tree::MerkleCap;
use p3_multilinear_util::point::Point;
use p3_sumcheck::ring_switch::bits::BitRingSwitch;
use p3_sumcheck::strategy::VariableOrder;
use p3_sumcheck::{OpeningBatch, OpeningProtocol, TableShape, TableSpec};
use p3_whir::WhirConfig;

use super::whir_plan::invalid;
use super::{
    BinaryPolyBitRingVerifier, BinaryPolyRingInputShape, BinaryPolyWhirInputShape,
    BinaryPolyWhirProofTargets, BinaryPolyWhirVerifier, BinaryRingClaimSpec, ByteDigestMmcs,
    MerkleArity, NativeBinaryPolyRingInput, NativeBinaryPolyWhirInput,
    NativePolyBitRingProofTargets, NativePolyBitRingReading,
};
use crate::BinaryTower128Challenger;
use crate::verifier::binary_field_policy::{BinaryProtocolPolicy, NativePoly64Relation};
use crate::verifier::{InputResourceUsage, VerificationError, VerifierLimits};

/// Bit variables one packed Poly64 element absorbs.
pub(super) const ABSORBED: usize = BitRingSwitch::<Poly64, Poly192>::ABSORBED;

/// Trusted schedule for the released Poly64 Boolean-WHIR family: the ring switch reduces all
/// readings to one claim on the packing, which one Poly64→Poly192 WHIR opening of one column,
/// bound suffix first, discharges.
#[derive(Clone, Debug)]
pub struct BinaryPolyBooleanWhirVerifier {
    reduction: BinaryPolyBitRingVerifier,
    opening: BinaryPolyWhirVerifier,
    usage: InputResourceUsage,
}

#[derive(Clone, Debug)]
pub struct NativePolyBooleanWhirProofTargets {
    pub reduction: NativePolyBitRingProofTargets,
    pub opening: BinaryPolyWhirProofTargets<NativePoly192Target, ExprId>,
}

/// Pure geometry of the ring switch and the packed opening.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BinaryPolyBooleanWhirInputShape {
    reduction: BinaryPolyRingInputShape,
    opening: BinaryPolyWhirInputShape,
}

impl BinaryPolyBooleanWhirInputShape {
    pub(crate) fn native_decode_shape(
        &self,
    ) -> (
        crate::artifact::binary_native::codec::RingDecode,
        crate::artifact::binary_native::codec::WhirDecode,
    ) {
        (
            self.reduction.native_decode_shape(),
            self.opening.native_decode_shape(),
        )
    }

    pub(crate) fn write_identity(
        &self,
        w: &mut crate::artifact::wire::Writer,
    ) -> Result<(), crate::artifact::ArtifactError> {
        self.reduction.write_identity(w)?;
        self.opening.write_identity(w)
    }

    /// Native Poly64 inputs: the ring-switch elements and messages, then the packed opening.
    pub fn allocate_native_targets(
        &self,
        b: &mut CircuitBuilder<Poly64>,
    ) -> Result<NativePolyBooleanWhirProofTargets, VerificationError> {
        Ok(NativePolyBooleanWhirProofTargets {
            reduction: self.reduction.allocate_native_targets(b)?,
            opening: self.opening.allocate_native_targets(b)?,
        })
    }
}

/// Bounded witness extraction; authentication remains a circuit constraint.
#[derive(Clone, Debug)]
pub struct NativeBinaryPolyBooleanWhirInput {
    shape: BinaryPolyBooleanWhirInputShape,
    reduction: NativeBinaryPolyRingInput,
    opening: NativeBinaryPolyWhirInput,
}

impl NativeBinaryPolyBooleanWhirInput {
    pub const fn shape(&self) -> &BinaryPolyBooleanWhirInputShape {
        &self.shape
    }

    /// The native verifier's inputs, in allocation order.
    pub fn private_native_values(
        &self,
        expected: &BinaryPolyBooleanWhirInputShape,
    ) -> Result<Vec<Poly64>, VerificationError> {
        if &self.shape != expected {
            return Err(invalid(
                "Poly64 Boolean WHIR input belongs to a different verifier",
            ));
        }
        let mut values = self.reduction.private_native_values(&expected.reduction)?;
        values.extend(self.opening.private_native_values(&expected.opening)?);
        Ok(values)
    }
}

impl BinaryPolyBooleanWhirVerifier {
    /// [`Self::with_limits`] for pairwise trees under the default limits.
    pub fn new<Ch>(
        config: &WhirConfig<Poly192, Poly64, Ch>,
        specs: Vec<BinaryRingClaimSpec>,
        hash: ByteHash,
        cap_height: usize,
    ) -> Result<Self, VerificationError>
    where
        Ch: FieldChallenger<Poly64> + GrindingChallenger<Witness = Poly64>,
    {
        Self::with_limits(
            config,
            specs,
            hash,
            MerkleArity::Two,
            cap_height,
            &VerifierLimits::default(),
        )
    }

    /// Checks the aggregate ring-switch and WHIR budget before allocation. The packed
    /// opening's tree compresses `arity` digests per node and its cap replaces the top
    /// `cap_height` levels.
    pub fn with_limits<Ch>(
        config: &WhirConfig<Poly192, Poly64, Ch>,
        specs: Vec<BinaryRingClaimSpec>,
        hash: ByteHash,
        arity: MerkleArity,
        cap_height: usize,
        limits: &VerifierLimits,
    ) -> Result<Self, VerificationError>
    where
        Ch: FieldChallenger<Poly64> + GrindingChallenger<Witness = Poly64>,
    {
        let num_variables = config.num_variables().checked_add(ABSORBED).ok_or(
            VerificationError::ResourceArithmeticOverflow {
                component: "Poly64 Boolean WHIR bit arity",
            },
        )?;
        let reduction = BinaryPolyBitRingVerifier::with_limits(num_variables, specs, limits)?;
        let protocol = OpeningProtocol::new(vec![TableSpec::new(
            TableShape::new(config.num_variables(), 1),
            vec![OpeningBatch::new(vec![0], vec![])],
        )]);
        let opening = BinaryPolyWhirVerifier::with_limits(
            config,
            protocol,
            VariableOrder::Suffix,
            hash,
            arity,
            cap_height,
            limits,
        )?;
        let mut usage = reduction.input_resource_usage();
        usage.merge(limits, opening.input_resource_usage())?;
        Ok(Self {
            reduction,
            opening,
            usage,
        })
    }

    pub const fn input_resource_usage(&self) -> InputResourceUsage {
        self.usage
    }

    pub fn input_shape(&self) -> BinaryPolyBooleanWhirInputShape {
        BinaryPolyBooleanWhirInputShape {
            reduction: self.reduction.input_shape(),
            opening: self.opening.input_shape(),
        }
    }

    /// The packed opening's hash must have a native circuit.
    pub(super) fn check_native_circuit_support(&self) -> Result<(), VerificationError> {
        self.opening.check_host::<NativeBinaryEncoding, Poly64>()
    }

    pub(super) fn check_native_targets(
        &self,
        b: &CircuitBuilder<Poly64>,
        cap: &[Vec<ExprId>],
        proof: &NativePolyBooleanWhirProofTargets,
    ) -> Result<(), VerificationError> {
        self.reduction.check_native_proof(&proof.reduction)?;
        let placeholder = vec![
            b.native_poly192_from_coefficients([ExprId::ZERO; 3]);
            self.opening.plan.variables
        ];
        self.opening
            .check_targets(cap, &[placeholder], &proof.opening)
    }

    pub fn observe_commitment_native(
        &self,
        b: &mut CircuitBuilder<Poly64>,
        ch: &mut BinaryTower128Challenger,
        cap: &[Vec<ExprId>],
    ) -> Result<(), VerificationError> {
        self.opening
            .observe_commitment_with_host::<NativeBinaryEncoding, Poly64>(b, ch, cap)
    }

    /// Verifies the readings in the native carrier, running every ring-switch round, then
    /// opens the packing at the surviving point, whose value must be the surviving value.
    /// Returns the exact challenger after the packed WHIR opening, including its closing fold.
    pub fn verify_readings_native(
        &self,
        b: &mut CircuitBuilder<Poly64>,
        ch: BinaryTower128Challenger,
        cap: &[Vec<ExprId>],
        readings: &[NativePolyBitRingReading],
        proof: &NativePolyBooleanWhirProofTargets,
    ) -> Result<BinaryTower128Challenger, VerificationError> {
        self.check_native_circuit_support()?;
        self.check_native_targets(b, cap, proof)?;
        let output = self
            .reduction
            .verify_native(b, ch, readings, &proof.reduction)?;
        NativePoly64Relation::assert_equal(b, &output.value, &proof.opening.evals[0].current()[0]);
        self.opening
            .verify_at_native(b, output.challenger, cap, &[output.point], &proof.opening)
            .map(|(_, ch)| ch)
    }

    pub(super) fn check_native_structure<C, M>(
        &self,
        config: &WhirConfig<Poly192, Poly64, C>,
        mmcs: &M,
        commitment: &MerkleCap<Poly64, [u8; 32]>,
        proof: &BooleanWhirProof<Poly64, Poly192, M>,
    ) -> Result<(), VerificationError>
    where
        C: FieldChallenger<Poly64> + GrindingChallenger<Witness = Poly64>,
        M: ByteDigestMmcs<Poly64>,
    {
        self.check_native_structure_with_usage(
            config,
            mmcs,
            commitment,
            proof,
            &mut InputResourceUsage::default(),
        )
    }

    /// Checks the ring-switch proof and the packed opening against this verifier's shapes, and
    /// the surviving value against the packed opening's evaluation.
    pub(super) fn check_native_structure_with_usage<C, M>(
        &self,
        config: &WhirConfig<Poly192, Poly64, C>,
        mmcs: &M,
        commitment: &MerkleCap<Poly64, [u8; 32]>,
        proof: &BooleanWhirProof<Poly64, Poly192, M>,
        usage: &mut InputResourceUsage,
    ) -> Result<(), VerificationError>
    where
        C: FieldChallenger<Poly64> + GrindingChallenger<Witness = Poly64>,
        M: ByteDigestMmcs<Poly64>,
    {
        self.reduction.check_native_structure(&proof.reduction)?;
        let placeholder = Point::new(vec![Poly192::ZERO; self.opening.plan.variables]);
        self.opening.check_native_with_usage(
            config,
            mmcs,
            commitment,
            &[placeholder],
            &proof.opening,
            usage,
        )?;
        if proof.opening.evals[0].current()[0] != proof.reduction.final_eval {
            return Err(invalid(
                "Poly64 Boolean WHIR surviving value differs from the packed opening",
            ));
        }
        Ok(())
    }

    /// Preflights both proof components before replay, replays the ring switch on the
    /// readings, and imports the WHIR opening at the surviving point. The caller's challenger
    /// moves to the exact native continuation on success and is unchanged on every error.
    #[expect(
        clippy::too_many_arguments,
        reason = "The verifier keeps protocol inputs explicit."
    )]
    pub fn import_native<C, Ch, M>(
        &self,
        config: &WhirConfig<Poly192, Poly64, C>,
        mmcs: &M,
        commitment: &MerkleCap<Poly64, [u8; 32]>,
        points: &[Point<Poly192>],
        readings: &[(Option<Poly192>, Option<Poly192>)],
        proof: &BooleanWhirProof<Poly64, Poly192, M>,
        target_challenger: &mut Ch,
    ) -> Result<NativeBinaryPolyBooleanWhirInput, VerificationError>
    where
        C: FieldChallenger<Poly64> + GrindingChallenger<Witness = Poly64>,
        M: ByteDigestMmcs<Poly64>,
        Ch: Clone
            + FieldChallenger<Poly64>
            + CanSampleUniformBits<Poly64>
            + GrindingChallenger<Witness = Poly64>
            + CanObserve<MerkleCap<Poly64, [u8; 32]>>,
    {
        self.check_native_structure(config, mmcs, commitment, proof)?;
        let (reduction, point, mut ch) = self.reduction.import_native(
            points,
            readings,
            &proof.reduction,
            target_challenger.clone(),
        )?;
        let opening = self.opening.import_native(
            config,
            mmcs,
            commitment,
            &[point],
            &proof.opening,
            &mut ch,
        )?;
        *target_challenger = ch;
        Ok(NativeBinaryPolyBooleanWhirInput {
            shape: self.input_shape(),
            reduction,
            opening,
        })
    }
}
