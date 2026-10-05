//! Boolean bit readings closed against complete grouped-codeword commitments.

use alloc::vec;
use alloc::vec::Vec;
use core::hash::Hash;

use p3_binary_pcs::BinaryPcsConfig;
use p3_challenger::{CanObserve, CanSampleUniformBits, FieldChallenger, GrindingChallenger};
use p3_circuit::ops::ByteHash;
use p3_circuit::{CircuitBuilder, ExprId};
use p3_field::{ExtensionField, Field, PackedValue, PrimeField64};
use p3_merkle_tree::{MerkleCap, MerkleTreeMmcs};
use p3_multilinear_util::point::Point;
use p3_sumcheck::{OpeningBatch, OpeningProtocol, TableShape, TableSpec};
use p3_symmetric::{CryptographicHasher, PseudoCompressionFunction};

use super::verifier::assert_equal;
use super::{
    BinaryBitRingVerifier, BinaryCodewordGrouping, BinaryGroupedPcsInputShape,
    BinaryGroupedPcsProofTargets, BinaryGroupedPcsVerifier, BinaryRingClaimSpec,
    BinaryRingInputShape, BinaryRingOutput, BinaryRingProofTargets, NativeBinaryGroupedPcsInput,
    NativeBinaryRingInput, RecursiveBinaryChallengeField,
};
use crate::verifier::{InputResourceUsage, VerificationError, VerifierLimits};
use crate::{BinaryQueryContinuation, BinaryTower128Challenger};

/// Verifier-owned schedule for a released Boolean PCS opening. The ring switch
/// binds each incoming point and reduces all requested readings to one packed
/// opening. The caller binds the commitment and readings to its statement.
#[derive(Clone, Debug)]
pub struct BinaryGroupedBooleanPcsVerifier<E> {
    reduction: BinaryBitRingVerifier<E>,
    opening: BinaryGroupedPcsVerifier<E, E>,
    pub(super) usage: InputResourceUsage,
}

#[derive(Clone, Debug)]
pub struct BinaryGroupedBooleanProofTargets<E> {
    pub reduction: BinaryRingProofTargets<E>,
    pub opening: BinaryGroupedPcsProofTargets,
}

/// Pure input geometry, reusable across proofs and common Boolean prefixes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BinaryGroupedBooleanInputShape<E> {
    reduction: BinaryRingInputShape<E>,
    opening: BinaryGroupedPcsInputShape,
}

impl<E: RecursiveBinaryChallengeField> BinaryGroupedBooleanInputShape<E> {
    pub(crate) fn native_decode_shape(
        &self,
    ) -> (
        crate::artifact::binary_native::codec::RingDecode,
        crate::artifact::binary_native::codec::PcsDecode<
            crate::artifact::binary_native::codec::GroupedOracleDecode,
        >,
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
        self.reduction.write_identity(w)
    }

    pub fn allocate_targets<BF, EF>(
        &self,
        circuit: &mut CircuitBuilder<EF>,
    ) -> Result<BinaryGroupedBooleanProofTargets<E>, VerificationError>
    where
        BF: PrimeField64,
        EF: ExtensionField<BF> + Eq + Hash,
    {
        Ok(BinaryGroupedBooleanProofTargets {
            reduction: self.reduction.allocate_targets::<BF, EF>(circuit)?,
            opening: self.opening.allocate_targets::<BF, EF>(circuit)?,
        })
    }
}

/// Bounded witness material; the recursive relation authenticates the opening.
#[derive(Clone, Debug)]
pub struct NativeBinaryGroupedBooleanInput<E> {
    shape: BinaryGroupedBooleanInputShape<E>,
    reduction: NativeBinaryRingInput<E>,
    opening: NativeBinaryGroupedPcsInput,
}

impl<E: RecursiveBinaryChallengeField> NativeBinaryGroupedBooleanInput<E> {
    pub const fn shape(&self) -> &BinaryGroupedBooleanInputShape<E> {
        &self.shape
    }

    pub fn private_values<EF: Field>(
        &self,
        expected: &BinaryGroupedBooleanInputShape<E>,
    ) -> Result<Vec<EF>, VerificationError> {
        if &self.shape != expected {
            return Err(invalid(
                "binary Boolean input belongs to a different verifier",
            ));
        }
        let mut values = self.reduction.private_values::<EF>(&expected.reduction)?;
        values.extend(self.opening.private_values::<EF>(&expected.opening)?);
        Ok(values)
    }
}

impl<E: RecursiveBinaryChallengeField + ExtensionField<E>> BinaryGroupedBooleanPcsVerifier<E> {
    pub fn new(
        config: BinaryPcsConfig,
        specs: Vec<BinaryRingClaimSpec>,
        hash: ByteHash,
        cap_height: usize,
        max_query_draws: usize,
        base_grouping: BinaryCodewordGrouping,
        round_grouping: BinaryCodewordGrouping,
    ) -> Result<Self, VerificationError> {
        Self::with_limits(
            config,
            specs,
            hash,
            cap_height,
            max_query_draws,
            base_grouping,
            round_grouping,
            &VerifierLimits::default(),
        )
    }

    /// Checks the combined operational budget before constructing any inputs.
    #[expect(
        clippy::too_many_arguments,
        reason = "The verifier keeps protocol inputs explicit."
    )]
    pub fn with_limits(
        config: BinaryPcsConfig,
        specs: Vec<BinaryRingClaimSpec>,
        hash: ByteHash,
        cap_height: usize,
        max_query_draws: usize,
        base_grouping: BinaryCodewordGrouping,
        round_grouping: BinaryCodewordGrouping,
        limits: &VerifierLimits,
    ) -> Result<Self, VerificationError> {
        let num_variables = config
            .num_variables()
            .checked_add(E::RAW_BITS.ilog2() as usize)
            .ok_or(VerificationError::ResourceArithmeticOverflow {
                component: "binary Boolean variables",
            })?;
        let reduction = BinaryBitRingVerifier::with_limits(num_variables, specs, limits)?;
        let protocol = OpeningProtocol::new(vec![TableSpec::new(
            TableShape::new(config.num_variables(), 1),
            vec![OpeningBatch::new(vec![0], vec![])],
        )]);
        let opening = BinaryGroupedPcsVerifier::with_limits(
            config,
            protocol,
            hash,
            cap_height,
            max_query_draws,
            base_grouping,
            round_grouping,
            limits,
        )?;
        let mut usage = reduction.usage;
        usage.merge(limits, opening.inner.usage)?;
        Ok(Self {
            reduction,
            opening,
            usage,
        })
    }

    pub fn input_shape(&self) -> BinaryGroupedBooleanInputShape<E> {
        BinaryGroupedBooleanInputShape {
            reduction: self.reduction.input_shape(),
            opening: self.opening.input_shape(),
        }
    }

    /// Binds the packed commitment at its native transcript position.
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
        self.opening
            .observe_commitment::<BF, EF>(circuit, challenger, cap)
    }

    /// Constrains the complete bit-reading relation, including equality of the
    /// reduced value and the authenticated opening at the derived point, and
    /// drops the terminal query continuation.
    pub fn verify_readings<BF, EF>(
        &self,
        circuit: &mut CircuitBuilder<EF>,
        challenger: BinaryTower128Challenger,
        cap: &[Vec<ExprId>],
        proof: &BinaryGroupedBooleanProofTargets<E>,
    ) -> Result<(), VerificationError>
    where
        BF: PrimeField64,
        EF: ExtensionField<BF> + Eq + Hash,
    {
        self.verify_readings_with_continuation::<BF, EF>(circuit, challenger, cap, proof)
            .map(|_| ())
    }

    /// Verifies all bit readings and returns the exact packed PCS query
    /// completion for a following nonempty protocol observation.
    pub fn verify_readings_with_continuation<BF, EF>(
        &self,
        circuit: &mut CircuitBuilder<EF>,
        challenger: BinaryTower128Challenger,
        cap: &[Vec<ExprId>],
        proof: &BinaryGroupedBooleanProofTargets<E>,
    ) -> Result<BinaryQueryContinuation, VerificationError>
    where
        BF: PrimeField64,
        EF: ExtensionField<BF> + Eq + Hash,
    {
        self.check_targets(cap, proof)?;
        let output = self
            .reduction
            .verify::<BF, EF>(circuit, challenger, &proof.reduction)?;
        self.verify_reduced::<BF, EF>(circuit, cap, proof, output)
    }

    /// Resumes a following Boolean opening through its ring-switch seed. The
    /// commitment must already be bound at the surrounding native protocol site.
    pub fn verify_readings_after_queries<BF, EF>(
        &self,
        circuit: &mut CircuitBuilder<EF>,
        continuation: BinaryQueryContinuation,
        cap: &[Vec<ExprId>],
        proof: &BinaryGroupedBooleanProofTargets<E>,
    ) -> Result<BinaryQueryContinuation, VerificationError>
    where
        BF: PrimeField64,
        EF: ExtensionField<BF> + Eq + Hash,
    {
        self.check_targets(cap, proof)?;
        let output = self.reduction.verify_after_queries::<BF, EF>(
            circuit,
            continuation,
            &proof.reduction,
        )?;
        self.verify_reduced::<BF, EF>(circuit, cap, proof, output)
    }

    pub(super) fn check_targets(
        &self,
        cap: &[Vec<ExprId>],
        proof: &BinaryGroupedBooleanProofTargets<E>,
    ) -> Result<(), VerificationError> {
        self.reduction.check_targets(&proof.reduction)?;
        // The preflight only needs the point shape. The transcript derives its
        // actual value before the packed opening relation is installed.
        let placeholder =
            proof.reduction.claims[0].point[..self.opening.inner.config.num_variables()].to_vec();
        self.opening
            .check_targets(cap, &[placeholder], &proof.opening)
    }

    fn verify_reduced<BF, EF>(
        &self,
        circuit: &mut CircuitBuilder<EF>,
        cap: &[Vec<ExprId>],
        proof: &BinaryGroupedBooleanProofTargets<E>,
        output: BinaryRingOutput,
    ) -> Result<BinaryQueryContinuation, VerificationError>
    where
        BF: PrimeField64,
        EF: ExtensionField<BF> + Eq + Hash,
    {
        assert_equal(
            circuit,
            &output.value,
            &proof.opening.opening.evals[0].current()[0],
        );
        self.opening.verify_at_with_continuation::<BF, EF>(
            circuit,
            output.challenger,
            cap,
            &[output.point],
            &proof.opening,
        )
    }

    pub(super) fn check_native_structure<H0, C0, H1, C1>(
        &self,
        base_mmcs: &MerkleTreeMmcs<E, u8, H0, C0, 2, 32>,
        round_mmcs: &MerkleTreeMmcs<E, u8, H1, C1, 2, 32>,
        commitment: &MerkleCap<E, [u8; 32]>,
        proof: &super::GroupedByteMerkleBooleanProof<E, H0, C0, H1, C1>,
    ) -> Result<(), VerificationError>
    where
        E: PackedValue<Value = E>,
        H0: CryptographicHasher<E, [u8; 32]> + Sync,
        H1: CryptographicHasher<E, [u8; 32]> + Sync,
        C0: PseudoCompressionFunction<[u8; 32], 2> + Sync,
        C1: PseudoCompressionFunction<[u8; 32], 2> + Sync,
    {
        self.reduction.check_native_structure(&proof.reduction)?;
        let placeholder = Point::new(vec![E::ZERO; self.opening.inner.config.num_variables()]);
        self.opening.check_native(
            base_mmcs,
            round_mmcs,
            commitment,
            &[placeholder],
            &proof.opening,
        )?;
        if proof.opening.evals[0].current()[0] != proof.reduction.final_eval {
            return Err(invalid(
                "binary Boolean surviving value does not match the packed opening",
            ));
        }
        Ok(())
    }

    /// Checks both native proof shapes before replay, verifies the ring readings,
    /// and imports the remaining opening with a finite query draw budget. Every
    /// failure leaves the caller's challenger unchanged. Path
    /// restoration supplies witnesses; it does not replace circuit verification.
    #[expect(
        clippy::too_many_arguments,
        reason = "The verifier keeps protocol inputs explicit."
    )]
    pub fn import_native<H0, C0, H1, C1, Ch>(
        &self,
        base_mmcs: &MerkleTreeMmcs<E, u8, H0, C0, 2, 32>,
        round_mmcs: &MerkleTreeMmcs<E, u8, H1, C1, 2, 32>,
        commitment: &MerkleCap<E, [u8; 32]>,
        points: &[Point<E>],
        readings: &[(Option<E>, Option<E>)],
        proof: &super::GroupedByteMerkleBooleanProof<E, H0, C0, H1, C1>,
        challenger: &mut Ch,
    ) -> Result<NativeBinaryGroupedBooleanInput<E>, VerificationError>
    where
        E: PackedValue<Value = E>,
        H0: CryptographicHasher<E, [u8; 32]> + Sync,
        H1: CryptographicHasher<E, [u8; 32]> + Sync,
        C0: PseudoCompressionFunction<[u8; 32], 2> + Sync,
        C1: PseudoCompressionFunction<[u8; 32], 2> + Sync,
        Ch: Clone
            + FieldChallenger<E>
            + CanSampleUniformBits<E>
            + GrindingChallenger<Witness = E>
            + CanObserve<MerkleCap<E, [u8; 32]>>,
    {
        self.import_native_with_usage(
            base_mmcs,
            round_mmcs,
            commitment,
            points,
            readings,
            proof,
            challenger,
            &core::cell::RefCell::new(InputResourceUsage::default()),
        )
    }

    #[expect(
        clippy::too_many_arguments,
        reason = "The verifier keeps protocol inputs explicit."
    )]
    pub(crate) fn import_native_with_usage<H0, C0, H1, C1, Ch>(
        &self,
        base_mmcs: &MerkleTreeMmcs<E, u8, H0, C0, 2, 32>,
        round_mmcs: &MerkleTreeMmcs<E, u8, H1, C1, 2, 32>,
        commitment: &MerkleCap<E, [u8; 32]>,
        points: &[Point<E>],
        readings: &[(Option<E>, Option<E>)],
        proof: &super::GroupedByteMerkleBooleanProof<E, H0, C0, H1, C1>,
        challenger: &mut Ch,
        usage: &core::cell::RefCell<InputResourceUsage>,
    ) -> Result<NativeBinaryGroupedBooleanInput<E>, VerificationError>
    where
        E: PackedValue<Value = E>,
        H0: CryptographicHasher<E, [u8; 32]> + Sync,
        H1: CryptographicHasher<E, [u8; 32]> + Sync,
        C0: PseudoCompressionFunction<[u8; 32], 2> + Sync,
        C1: PseudoCompressionFunction<[u8; 32], 2> + Sync,
        Ch: Clone
            + FieldChallenger<E>
            + CanSampleUniformBits<E>
            + GrindingChallenger<Witness = E>
            + CanObserve<MerkleCap<E, [u8; 32]>>,
    {
        self.check_native_structure(base_mmcs, round_mmcs, commitment, proof)?;
        let mut staged = challenger.clone();
        let (reduction, point, _) =
            self.reduction
                .import_native(points, readings, &proof.reduction, &mut staged)?;
        let opening = self.opening.import_native_with_usage(
            base_mmcs,
            round_mmcs,
            commitment,
            &[point],
            &proof.opening,
            &mut staged,
            usage,
        )?;
        *challenger = staged;
        Ok(NativeBinaryGroupedBooleanInput {
            shape: self.input_shape(),
            reduction,
            opening,
        })
    }
}

fn invalid(message: &'static str) -> VerificationError {
    VerificationError::InvalidProofShape(message.into())
}
