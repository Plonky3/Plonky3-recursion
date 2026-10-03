//! Boolean bit readings closed against the committed packed multilinear.

use alloc::vec;
use alloc::vec::Vec;
use core::hash::Hash;

use p3_binary_pcs::{BinaryPcsConfig, BooleanProof};
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
    BinaryBitRingVerifier, BinaryPcs128ProofTargets, BinaryPcsInputShape, BinaryPcsVerifier,
    BinaryRingClaimSpec, BinaryRingInputShape, BinaryRingProofTargets, NativeBinaryPcsInput,
    NativeBinaryRingInput, RecursiveBinaryChallengeField,
};
use crate::BinaryTower128Challenger;
use crate::verifier::{VerificationError, VerifierLimits};

/// Verifier-owned schedule for a released Boolean PCS opening. The ring switch
/// binds each incoming point and reduces all requested readings to one packed
/// opening. The caller binds the commitment and readings to its statement.
#[derive(Clone, Debug)]
pub struct BinaryBooleanPcsVerifier<E> {
    reduction: BinaryBitRingVerifier<E>,
    opening: BinaryPcsVerifier<E, E>,
}

#[derive(Clone, Debug)]
pub struct BinaryBooleanProofTargets<E> {
    pub reduction: BinaryRingProofTargets<E>,
    pub opening: BinaryPcs128ProofTargets,
}

/// Pure input geometry, reusable across proofs and common Boolean prefixes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BinaryBooleanInputShape<E> {
    reduction: BinaryRingInputShape<E>,
    opening: BinaryPcsInputShape,
}

impl<E: RecursiveBinaryChallengeField> BinaryBooleanInputShape<E> {
    pub fn allocate_targets<BF, EF>(
        &self,
        circuit: &mut CircuitBuilder<EF>,
    ) -> Result<BinaryBooleanProofTargets<E>, VerificationError>
    where
        BF: PrimeField64,
        EF: ExtensionField<BF> + Eq + Hash,
    {
        Ok(BinaryBooleanProofTargets {
            reduction: self.reduction.allocate_targets::<BF, EF>(circuit)?,
            opening: self.opening.allocate_targets::<BF, EF>(circuit)?,
        })
    }
}

/// Bounded witness material; the recursive relation authenticates the opening.
#[derive(Clone, Debug)]
pub struct NativeBinaryBooleanInput<E> {
    shape: BinaryBooleanInputShape<E>,
    reduction: NativeBinaryRingInput<E>,
    opening: NativeBinaryPcsInput,
}

impl<E: RecursiveBinaryChallengeField> NativeBinaryBooleanInput<E> {
    pub fn shape(&self) -> &BinaryBooleanInputShape<E> {
        &self.shape
    }

    pub fn private_values<EF: Field>(
        &self,
        expected: &BinaryBooleanInputShape<E>,
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

impl<E: RecursiveBinaryChallengeField + ExtensionField<E>> BinaryBooleanPcsVerifier<E> {
    pub fn new(
        config: BinaryPcsConfig,
        specs: Vec<BinaryRingClaimSpec>,
        hash: ByteHash,
        cap_height: usize,
        max_query_draws: usize,
    ) -> Result<Self, VerificationError> {
        Self::with_limits(
            config,
            specs,
            hash,
            cap_height,
            max_query_draws,
            &VerifierLimits::default(),
        )
    }

    /// Checks the combined operational budget before constructing any inputs.
    pub fn with_limits(
        config: BinaryPcsConfig,
        specs: Vec<BinaryRingClaimSpec>,
        hash: ByteHash,
        cap_height: usize,
        max_query_draws: usize,
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
        let opening = BinaryPcsVerifier::with_limits(
            config,
            protocol,
            hash,
            cap_height,
            max_query_draws,
            limits,
        )?;
        let mut usage = reduction.usage;
        usage.merge(limits, opening.usage)?;
        Ok(Self { reduction, opening })
    }

    pub fn input_shape(&self) -> BinaryBooleanInputShape<E> {
        BinaryBooleanInputShape {
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
    /// reduced value and the authenticated opening at the derived point. Query
    /// rejection sampling consumes the transcript as a terminal operation.
    pub fn verify_readings<BF, EF>(
        &self,
        circuit: &mut CircuitBuilder<EF>,
        challenger: BinaryTower128Challenger,
        cap: &[Vec<ExprId>],
        proof: &BinaryBooleanProofTargets<E>,
    ) -> Result<(), VerificationError>
    where
        BF: PrimeField64,
        EF: ExtensionField<BF> + Eq + Hash,
    {
        self.reduction.check_targets(&proof.reduction)?;
        // Only the point shape matters to this preflight. Its actual value is
        // subsequently derived by the constrained ring-switch transcript.
        let placeholder =
            proof.reduction.claims[0].point[..self.opening.config.num_variables()].to_vec();
        self.opening
            .check_targets(cap, &[placeholder], &proof.opening)?;
        let output = self
            .reduction
            .verify::<BF, EF>(circuit, challenger, &proof.reduction)?;
        assert_equal(circuit, &output.value, &proof.opening.evals[0].current()[0]);
        self.opening.verify_at::<BF, EF>(
            circuit,
            output.challenger,
            cap,
            &[output.point],
            &proof.opening,
        )
    }

    /// Checks both native proof shapes before replay, verifies the ring readings,
    /// and imports the remaining opening with a finite query draw budget. Path
    /// restoration supplies witnesses; it does not replace circuit verification.
    pub fn import_native<H0, C0, H1, C1, Ch>(
        &self,
        base_mmcs: &MerkleTreeMmcs<E, u8, H0, C0, 2, 32>,
        round_mmcs: &MerkleTreeMmcs<E, u8, H1, C1, 2, 32>,
        commitment: &MerkleCap<E, [u8; 32]>,
        points: &[Point<E>],
        readings: &[(Option<E>, Option<E>)],
        proof: &BooleanProof<
            E,
            MerkleTreeMmcs<E, u8, H0, C0, 2, 32>,
            MerkleTreeMmcs<E, u8, H1, C1, 2, 32>,
        >,
        mut challenger: Ch,
    ) -> Result<NativeBinaryBooleanInput<E>, VerificationError>
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
        let placeholder = Point::new(vec![E::ZERO; self.opening.config.num_variables()]);
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
        let (reduction, point, _) =
            self.reduction
                .import_native(points, readings, &proof.reduction, &mut challenger)?;
        let opening = self.opening.import_native(
            base_mmcs,
            round_mmcs,
            commitment,
            &[point],
            &proof.opening,
            challenger,
        )?;
        Ok(NativeBinaryBooleanInput {
            shape: self.input_shape(),
            reduction,
            opening,
        })
    }
}

fn invalid(message: &'static str) -> VerificationError {
    VerificationError::InvalidProofShape(message.into())
}
