//! Complete released Poly64→Poly192 additive WHIR relation.

use alloc::vec::Vec;
use core::hash::Hash;

use p3_binary_field::{Poly64, Poly192};
use p3_challenger::{FieldChallenger, GrindingChallenger};
use p3_circuit::ops::binary_encoding::{NativeBinaryEncoding, PrimeBinaryEncoding};
use p3_circuit::ops::binary_host::BinaryCircuitHost;
use p3_circuit::ops::{BinaryPoly192Target, ByteHash, NativePoly192Target};
use p3_circuit::{CircuitBuilder, ExprId};
use p3_field::{ExtensionField, Field, PrimeField64};
use p3_sumcheck::strategy::VariableOrder;
use p3_sumcheck::{OpeningBatch, OpeningProtocol};
use p3_whir::WhirConfig;

use super::BinaryPolyWhirProofTargets;
use super::verifier::observe_cap_with_host;
use super::whir_plan::WhirPlan;
use crate::BinaryTower128Challenger;
use crate::verifier::binary_field_policy::{
    BinaryWhirPolicy, NativePoly64Relation, Poly64Relation, poly_observe_seed_with_host,
};
use crate::verifier::{InputResourceUsage, VerificationError, VerifierLimits};

/// Verifier-owned native domain, schedule, separators and finite input bounds.
/// Supports the released Poly64→Poly192 polynomial-basis additive family
/// with ordinary binary-arity byte Merkle trees. The caller binds
/// the commitment and prescribed opening points to its statement.
#[derive(Clone, Debug)]
pub struct BinaryPolyWhirVerifier {
    pub(super) plan: WhirPlan<Poly64, Poly192>,
}

impl BinaryPolyWhirVerifier {
    pub(crate) fn check_host<H, CF>(&self) -> Result<(), VerificationError>
    where
        CF: Field + Eq + Hash,
        H: BinaryCircuitHost<CF>,
    {
        H::check_hash(self.plan.hash)?;
        Ok(())
    }

    /// Conservative checked input counters retained by the trusted plan.
    pub fn input_resource_usage(&self) -> InputResourceUsage {
        self.plan.usage
    }
    pub fn new<Ch>(
        config: &WhirConfig<Poly192, Poly64, Ch>,
        protocol: OpeningProtocol,
        order: VariableOrder,
        hash: ByteHash,
        cap_height: usize,
    ) -> Result<Self, VerificationError>
    where
        Ch: FieldChallenger<Poly64> + GrindingChallenger<Witness = Poly64>,
    {
        Self::with_limits(
            config,
            protocol,
            order,
            hash,
            cap_height,
            &VerifierLimits::default(),
        )
    }

    pub fn with_limits<Ch>(
        config: &WhirConfig<Poly192, Poly64, Ch>,
        protocol: OpeningProtocol,
        order: VariableOrder,
        hash: ByteHash,
        cap_height: usize,
        limits: &VerifierLimits,
    ) -> Result<Self, VerificationError>
    where
        Ch: FieldChallenger<Poly64> + GrindingChallenger<Witness = Poly64>,
    {
        Ok(Self {
            plan: WhirPlan::new(config, protocol, order, hash, cap_height, limits)?,
        })
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
        self.observe_commitment_with_host::<PrimeBinaryEncoding<BF>, EF>(b, ch, cap)
    }
    pub fn observe_commitment_with_host<H, CF>(
        &self,
        b: &mut CircuitBuilder<CF>,
        ch: &mut BinaryTower128Challenger,
        cap: &[Vec<ExprId>],
    ) -> Result<(), VerificationError>
    where
        CF: Field + Eq + Hash,
        H: BinaryCircuitHost<CF>,
    {
        self.check_cap(cap)?;
        H::check_hash(self.plan.hash)?;
        poly_observe_seed_with_host::<H, CF>(b, ch, &self.plan.commitment_seed)?;
        observe_cap_with_host::<H, CF>(b, ch, cap)
    }

    /// Replays the complete native PCS adapter and WHIR engine. Every query
    /// authenticates its full row, every sumcheck uses its phase separator,
    /// and the terminal constraint binds all opening, OOD and selector claims.
    /// The fixed stratified query schedule returns an exact ordinary challenger.
    pub fn verify_at<BF, EF>(
        &self,
        b: &mut CircuitBuilder<EF>,
        ch: BinaryTower128Challenger,
        cap: &[Vec<ExprId>],
        points: &[Vec<BinaryPoly192Target>],
        proof: &BinaryPolyWhirProofTargets,
    ) -> Result<
        (
            Vec<OpeningBatch<BinaryPoly192Target>>,
            BinaryTower128Challenger,
        ),
        VerificationError,
    >
    where
        BF: PrimeField64,
        EF: ExtensionField<BF> + Eq + Hash,
    {
        self.verify_at_using::<Poly64Relation, PrimeBinaryEncoding<BF>, EF>(
            b, ch, cap, points, proof,
        )
    }
    pub(crate) fn verify_at_using<P, H, CF>(
        &self,
        b: &mut CircuitBuilder<CF>,
        ch: BinaryTower128Challenger,
        cap: &[Vec<ExprId>],
        points: &[Vec<P::ChallengeTarget>],
        proof: &BinaryPolyWhirProofTargets<P::ChallengeTarget, P::BaseTarget>,
    ) -> Result<
        (
            Vec<OpeningBatch<P::ChallengeTarget>>,
            BinaryTower128Challenger,
        ),
        VerificationError,
    >
    where
        CF: Field + Eq + Hash,
        H: BinaryCircuitHost<CF>,
        P: BinaryWhirPolicy<CF, Base = Poly64, Challenge = Poly192>,
    {
        super::whir_kernel::verify_using::<P, H, CF>(&self.plan, b, ch, cap, points, proof)
    }
    fn check_cap(&self, cap: &[Vec<ExprId>]) -> Result<(), VerificationError> {
        super::whir_kernel::check_cap(self.plan.cap_height, cap)
    }
    pub(crate) fn check_targets<T, B>(
        &self,
        cap: &[Vec<ExprId>],
        points: &[Vec<T>],
        proof: &BinaryPolyWhirProofTargets<T, B>,
    ) -> Result<(), VerificationError> {
        super::whir_kernel::check_targets(&self.plan, cap, points, proof)
    }
    /// Complete additive WHIR relation using native Poly64 coefficient cells.
    pub fn verify_at_native(
        &self,
        b: &mut CircuitBuilder<Poly64>,
        ch: BinaryTower128Challenger,
        cap: &[Vec<ExprId>],
        points: &[Vec<NativePoly192Target>],
        proof: &BinaryPolyWhirProofTargets<NativePoly192Target, ExprId>,
    ) -> Result<
        (
            Vec<OpeningBatch<NativePoly192Target>>,
            BinaryTower128Challenger,
        ),
        VerificationError,
    > {
        self.verify_at_using::<NativePoly64Relation, NativeBinaryEncoding, Poly64>(
            b, ch, cap, points, proof,
        )
    }
}
