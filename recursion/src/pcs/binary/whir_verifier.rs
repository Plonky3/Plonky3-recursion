//! Full released non-hiding additive WHIR relation for tower alphabets.

use alloc::vec::Vec;
use core::hash::Hash;

use p3_binary_field::BinaryField128;
use p3_challenger::{FieldChallenger, GrindingChallenger};
use p3_circuit::ops::binary_encoding::{NativeBinaryEncoding, PrimeBinaryEncoding};
use p3_circuit::ops::binary_host::BinaryCircuitHost;
use p3_circuit::ops::{BinaryTower128Target, ByteHash, NativeTower128Target};
use p3_circuit::{CircuitBuilder, ExprId};
use p3_field::{ExtensionField, Field, PrimeField64};
use p3_sumcheck::strategy::VariableOrder;
use p3_sumcheck::{OpeningBatch, OpeningProtocol};
use p3_whir::WhirConfig;

use super::verifier::{observe_cap_with_host, observe_seed_with_host};
use super::whir_plan::WhirPlan;
use super::{BinaryWhirProofTargets, RecursiveBinaryWhirTowerField};
use crate::BinaryTower128Challenger;
use crate::verifier::binary_field_policy::{
    BinaryTowerPolicy, BinaryWhirPolicy, NativeTower128Relation, TowerRelation,
};
use crate::verifier::{InputResourceUsage, VerificationError, VerifierLimits};

/// Verifier-owned native domain, schedule, separators and finite input bounds.
/// Supports the released Tower32→Tower128 and Tower128→Tower128 additive
/// families with ordinary binary-arity byte Merkle trees. The caller binds
/// the commitment and prescribed opening points to its statement.
#[derive(Clone, Debug)]
pub struct BinaryWhirVerifier<F = BinaryField128> {
    pub(super) plan: WhirPlan<F>,
}

impl<F> BinaryWhirVerifier<F>
where
    F: RecursiveBinaryWhirTowerField,
    BinaryField128: ExtensionField<F>,
{
    /// Conservative checked input counters retained by the trusted plan.
    pub fn input_resource_usage(&self) -> InputResourceUsage {
        self.plan.usage
    }
    pub(crate) fn check_host<H, CF>(&self) -> Result<(), VerificationError>
    where
        CF: Field + Eq + Hash,
        H: BinaryCircuitHost<CF>,
    {
        H::check_hash(self.plan.hash)?;
        Ok(())
    }
    pub fn new<Ch>(
        config: &WhirConfig<BinaryField128, F, Ch>,
        protocol: OpeningProtocol,
        order: VariableOrder,
        hash: ByteHash,
        cap_height: usize,
    ) -> Result<Self, VerificationError>
    where
        Ch: FieldChallenger<F> + GrindingChallenger<Witness = F>,
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
        config: &WhirConfig<BinaryField128, F, Ch>,
        protocol: OpeningProtocol,
        order: VariableOrder,
        hash: ByteHash,
        cap_height: usize,
        limits: &VerifierLimits,
    ) -> Result<Self, VerificationError>
    where
        Ch: FieldChallenger<F> + GrindingChallenger<Witness = F>,
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
        observe_seed_with_host::<F, H, CF>(b, ch, &self.plan.commitment_seed)?;
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
        points: &[Vec<BinaryTower128Target>],
        proof: &BinaryWhirProofTargets,
    ) -> Result<
        (
            Vec<OpeningBatch<BinaryTower128Target>>,
            BinaryTower128Challenger,
        ),
        VerificationError,
    >
    where
        BF: PrimeField64,
        EF: ExtensionField<BF> + Eq + Hash,
    {
        self.verify_at_using::<TowerRelation<F, BinaryField128>, PrimeBinaryEncoding<BF>, EF>(
            b, ch, cap, points, proof,
        )
    }
    pub(crate) fn verify_at_using<P, H, CF>(
        &self,
        b: &mut CircuitBuilder<CF>,
        ch: BinaryTower128Challenger,
        cap: &[Vec<ExprId>],
        points: &[Vec<P::ChallengeTarget>],
        proof: &BinaryWhirProofTargets<P::ChallengeTarget, P::BaseTarget>,
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
        P: BinaryTowerPolicy<CF, Base = F, Challenge = BinaryField128> + BinaryWhirPolicy<CF>,
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
        proof: &BinaryWhirProofTargets<T, B>,
    ) -> Result<(), VerificationError> {
        super::whir_kernel::check_targets(&self.plan, cap, points, proof)
    }
}

impl<F: RecursiveBinaryWhirTowerField> BinaryWhirVerifier<F>
where
    BinaryField128: ExtensionField<F>,
{
    /// Complete authenticated additive WHIR relation over native scalar cells.
    pub fn verify_at_native(
        &self,
        b: &mut CircuitBuilder<BinaryField128>,
        ch: BinaryTower128Challenger,
        cap: &[Vec<ExprId>],
        points: &[Vec<NativeTower128Target>],
        proof: &BinaryWhirProofTargets<NativeTower128Target>,
    ) -> Result<
        (
            Vec<OpeningBatch<NativeTower128Target>>,
            BinaryTower128Challenger,
        ),
        VerificationError,
    > {
        self.verify_at_using::<NativeTower128Relation<F>, NativeBinaryEncoding, BinaryField128>(
            b, ch, cap, points, proof,
        )
    }
}
