//! Bit ring-switch readings closed against the released additive WHIR PCS.

use alloc::vec;
use alloc::vec::Vec;
use core::hash::Hash;

use p3_binary_field::BinaryField128;
use p3_binary_pcs::whir::BooleanWhirProof;
use p3_challenger::{CanObserve, CanSampleUniformBits, FieldChallenger, GrindingChallenger};
use p3_circuit::ops::ByteHash;
use p3_circuit::{CircuitBuilder, ExprId};
use p3_field::{ExtensionField, Field, PrimeCharacteristicRing, PrimeField64};
use p3_merkle_tree::{MerkleCap, MerkleTreeMmcs};
use p3_multilinear_util::point::Point;
use p3_sumcheck::strategy::VariableOrder;
use p3_sumcheck::{OpeningBatch, OpeningProtocol, TableShape, TableSpec};
use p3_symmetric::{CryptographicHasher, PseudoCompressionFunction};
use p3_whir::WhirConfig;

use super::verifier::assert_equal;
use super::whir_plan::invalid;
use super::{
    BinaryBitRingVerifier, BinaryRingClaimSpec, BinaryRingInputShape, BinaryRingOutput,
    BinaryRingProofTargets, BinaryWhirInputShape, BinaryWhirProofTargets, BinaryWhirVerifier,
    NativeBinaryRingInput, NativeBinaryWhirInput,
};
use crate::verifier::{InputResourceUsage, VerificationError, VerifierLimits};
use crate::{BinaryQueryContinuation, BinaryTower128Challenger};

/// Trusted schedule for the released Tower128 Boolean-WHIR family. The native
/// adapter fixes suffix binding and reduces all readings to one packed opening.
#[derive(Clone, Debug)]
pub struct BinaryBooleanWhirVerifier {
    reduction: BinaryBitRingVerifier<BinaryField128>,
    opening: BinaryWhirVerifier<BinaryField128>,
    pub(super) usage: InputResourceUsage,
}

#[derive(Clone, Debug)]
pub struct BinaryBooleanWhirProofTargets {
    pub reduction: BinaryRingProofTargets<BinaryField128>,
    pub opening: BinaryWhirProofTargets,
}

/// Pure geometry independent of the proof's common Boolean point prefix.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BinaryBooleanWhirInputShape {
    reduction: BinaryRingInputShape<BinaryField128>,
    opening: BinaryWhirInputShape<BinaryField128>,
}

impl BinaryBooleanWhirInputShape {
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

    pub fn allocate_targets<BF, EF>(
        &self,
        b: &mut CircuitBuilder<EF>,
    ) -> Result<BinaryBooleanWhirProofTargets, VerificationError>
    where
        BF: PrimeField64,
        EF: ExtensionField<BF> + Eq + Hash,
    {
        Ok(BinaryBooleanWhirProofTargets {
            reduction: self.reduction.allocate_targets::<BF, EF>(b)?,
            opening: self.opening.allocate_targets::<BF, EF>(b)?,
        })
    }
}

/// Bounded witness extraction; authentication remains a circuit constraint.
#[derive(Clone, Debug)]
pub struct NativeBinaryBooleanWhirInput {
    shape: BinaryBooleanWhirInputShape,
    reduction: NativeBinaryRingInput<BinaryField128>,
    opening: NativeBinaryWhirInput<BinaryField128>,
}

impl NativeBinaryBooleanWhirInput {
    pub const fn shape(&self) -> &BinaryBooleanWhirInputShape {
        &self.shape
    }

    pub fn private_values<EF: Field>(
        &self,
        expected: &BinaryBooleanWhirInputShape,
    ) -> Result<Vec<EF>, VerificationError> {
        if &self.shape != expected {
            return Err(invalid(
                "binary Boolean WHIR input belongs to a different verifier",
            ));
        }
        let mut values = self.reduction.private_values::<EF>(&expected.reduction)?;
        values.extend(self.opening.private_values::<EF>(&expected.opening)?);
        Ok(values)
    }
}

impl BinaryBooleanWhirVerifier {
    pub fn new<Ch>(
        config: &WhirConfig<BinaryField128, BinaryField128, Ch>,
        specs: Vec<BinaryRingClaimSpec>,
        hash: ByteHash,
        cap_height: usize,
    ) -> Result<Self, VerificationError>
    where
        Ch: FieldChallenger<BinaryField128> + GrindingChallenger<Witness = BinaryField128>,
    {
        Self::with_limits(config, specs, hash, cap_height, &VerifierLimits::default())
    }

    /// Checks the aggregate ring-switch and WHIR budget before allocation.
    pub fn with_limits<Ch>(
        config: &WhirConfig<BinaryField128, BinaryField128, Ch>,
        specs: Vec<BinaryRingClaimSpec>,
        hash: ByteHash,
        cap_height: usize,
        limits: &VerifierLimits,
    ) -> Result<Self, VerificationError>
    where
        Ch: FieldChallenger<BinaryField128> + GrindingChallenger<Witness = BinaryField128>,
    {
        let num_variables = config.num_variables().checked_add(7).ok_or(
            VerificationError::ResourceArithmeticOverflow {
                component: "binary Boolean WHIR bit arity",
            },
        )?;
        let reduction = BinaryBitRingVerifier::with_limits(num_variables, specs, limits)?;
        let protocol = OpeningProtocol::new(vec![TableSpec::new(
            TableShape::new(config.num_variables(), 1),
            vec![OpeningBatch::new(vec![0], vec![])],
        )]);
        let opening = BinaryWhirVerifier::with_limits(
            config,
            protocol,
            VariableOrder::Suffix,
            hash,
            cap_height,
            limits,
        )?;
        let mut usage = reduction.usage;
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

    pub fn input_shape(&self) -> BinaryBooleanWhirInputShape {
        BinaryBooleanWhirInputShape {
            reduction: self.reduction.input_shape(),
            opening: self.opening.input_shape(),
        }
    }

    pub fn observe_commitment<BF, EF>(
        &self,
        b: &mut CircuitBuilder<EF>,
        ch: &mut BinaryTower128Challenger,
        cap: &[Vec<ExprId>],
    ) -> Result<(), VerificationError>
    where
        BF: PrimeField64,
        EF: ExtensionField<BF> + Eq + Hash,
    {
        self.opening.observe_commitment::<BF, EF>(b, ch, cap)
    }

    /// Verifies all requested bit readings and returns the exact ordinary
    /// challenger after the packed WHIR opening, including its closing fold.
    pub fn verify_readings<BF, EF>(
        &self,
        b: &mut CircuitBuilder<EF>,
        ch: BinaryTower128Challenger,
        cap: &[Vec<ExprId>],
        proof: &BinaryBooleanWhirProofTargets,
    ) -> Result<BinaryTower128Challenger, VerificationError>
    where
        BF: PrimeField64,
        EF: ExtensionField<BF> + Eq + Hash,
    {
        self.check_targets(cap, proof)?;
        let output = self.reduction.verify::<BF, EF>(b, ch, &proof.reduction)?;
        self.verify_reduced::<BF, EF>(b, cap, proof, output)
    }

    /// Resumes a preceding bounded raw-PCS query sampler through the native
    /// ring-switch separator exactly once.
    pub fn verify_readings_after_queries<BF, EF>(
        &self,
        b: &mut CircuitBuilder<EF>,
        continuation: BinaryQueryContinuation,
        cap: &[Vec<ExprId>],
        proof: &BinaryBooleanWhirProofTargets,
    ) -> Result<BinaryTower128Challenger, VerificationError>
    where
        BF: PrimeField64,
        EF: ExtensionField<BF> + Eq + Hash,
    {
        self.check_targets(cap, proof)?;
        let output =
            self.reduction
                .verify_after_queries::<BF, EF>(b, continuation, &proof.reduction)?;
        self.verify_reduced::<BF, EF>(b, cap, proof, output)
    }

    pub(super) fn check_targets(
        &self,
        cap: &[Vec<ExprId>],
        proof: &BinaryBooleanWhirProofTargets,
    ) -> Result<(), VerificationError> {
        self.reduction.check_targets(&proof.reduction)?;
        let placeholder = proof.reduction.claims[0].point[..self.opening.plan.variables].to_vec();
        self.opening
            .check_targets(cap, &[placeholder], &proof.opening)
    }

    fn verify_reduced<BF, EF>(
        &self,
        b: &mut CircuitBuilder<EF>,
        cap: &[Vec<ExprId>],
        proof: &BinaryBooleanWhirProofTargets,
        output: BinaryRingOutput,
    ) -> Result<BinaryTower128Challenger, VerificationError>
    where
        BF: PrimeField64,
        EF: ExtensionField<BF> + Eq + Hash,
    {
        assert_equal(b, &output.value, &proof.opening.evals[0].current()[0]);
        self.opening
            .verify_at::<BF, EF>(b, output.challenger, cap, &[output.point], &proof.opening)
            .map(|(_, ch)| ch)
    }

    pub(super) fn check_native_structure<C, H, Co>(
        &self,
        config: &WhirConfig<BinaryField128, BinaryField128, C>,
        mmcs: &MerkleTreeMmcs<BinaryField128, u8, H, Co, 2, 32>,
        commitment: &MerkleCap<BinaryField128, [u8; 32]>,
        proof: &BooleanWhirProof<BinaryField128, MerkleTreeMmcs<BinaryField128, u8, H, Co, 2, 32>>,
    ) -> Result<(), VerificationError>
    where
        C: FieldChallenger<BinaryField128> + GrindingChallenger<Witness = BinaryField128>,
        H: CryptographicHasher<BinaryField128, [u8; 32]> + Sync,
        Co: PseudoCompressionFunction<[u8; 32], 2> + Sync,
    {
        self.check_native_structure_with_usage(
            config,
            mmcs,
            commitment,
            proof,
            &mut InputResourceUsage::default(),
        )
    }

    pub(super) fn check_native_structure_with_usage<C, H, Co>(
        &self,
        config: &WhirConfig<BinaryField128, BinaryField128, C>,
        mmcs: &MerkleTreeMmcs<BinaryField128, u8, H, Co, 2, 32>,
        commitment: &MerkleCap<BinaryField128, [u8; 32]>,
        proof: &BooleanWhirProof<BinaryField128, MerkleTreeMmcs<BinaryField128, u8, H, Co, 2, 32>>,
        usage: &mut InputResourceUsage,
    ) -> Result<(), VerificationError>
    where
        C: FieldChallenger<BinaryField128> + GrindingChallenger<Witness = BinaryField128>,
        H: CryptographicHasher<BinaryField128, [u8; 32]> + Sync,
        Co: PseudoCompressionFunction<[u8; 32], 2> + Sync,
    {
        self.reduction.check_native_structure(&proof.reduction)?;
        let placeholder = Point::new(vec![BinaryField128::ZERO; self.opening.plan.variables]);
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
                "binary Boolean WHIR surviving value differs from the packed opening",
            ));
        }
        Ok(())
    }

    /// Preflights both proof components before replay, verifies the native
    /// readings, and imports the WHIR opening at the surviving point. Passing
    /// a mutable challenger preserves its exact native continuation.
    #[expect(
        clippy::too_many_arguments,
        reason = "The verifier keeps protocol inputs explicit."
    )]
    pub fn import_native<C, Ch, H, Co>(
        &self,
        config: &WhirConfig<BinaryField128, BinaryField128, C>,
        mmcs: &MerkleTreeMmcs<BinaryField128, u8, H, Co, 2, 32>,
        commitment: &MerkleCap<BinaryField128, [u8; 32]>,
        points: &[Point<BinaryField128>],
        readings: &[(Option<BinaryField128>, Option<BinaryField128>)],
        proof: &BooleanWhirProof<BinaryField128, MerkleTreeMmcs<BinaryField128, u8, H, Co, 2, 32>>,
        target_challenger: &mut Ch,
    ) -> Result<NativeBinaryBooleanWhirInput, VerificationError>
    where
        C: FieldChallenger<BinaryField128> + GrindingChallenger<Witness = BinaryField128>,
        H: CryptographicHasher<BinaryField128, [u8; 32]> + Sync,
        Co: PseudoCompressionFunction<[u8; 32], 2> + Sync,
        Ch: Clone
            + FieldChallenger<BinaryField128>
            + CanSampleUniformBits<BinaryField128>
            + GrindingChallenger<Witness = BinaryField128>
            + CanObserve<MerkleCap<BinaryField128, [u8; 32]>>,
    {
        self.check_native_structure(config, mmcs, commitment, proof)?;
        let mut ch = target_challenger.clone();
        let (reduction, point, _) =
            self.reduction
                .import_native(points, readings, &proof.reduction, &mut ch)?;
        let opening = self.opening.import_native(
            config,
            mmcs,
            commitment,
            &[point],
            &proof.opening,
            &mut ch,
        )?;
        *target_challenger = ch;
        Ok(NativeBinaryBooleanWhirInput {
            shape: self.input_shape(),
            reduction,
            opening,
        })
    }
}
