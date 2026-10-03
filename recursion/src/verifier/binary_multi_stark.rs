//! Complete native binary MultiStark verification with supported AIR reductions.

pub(crate) mod relation;
use relation::{BinaryMultiStarkRelation, BinaryMultiStarkRelationShape};

use alloc::vec;
use alloc::vec::Vec;
use core::hash::Hash;

use p3_air::Air;
use p3_binary_field::BinaryField128;
use p3_binary_pcs::{BinaryPcsConfig, BinaryPcsProof};
use p3_bus::{BusPlan, BusPlanInput, BusSymbolicBuilder};
use p3_challenger::{CanObserve, CanSampleUniformBits, FieldChallenger, GrindingChallenger};
use p3_circuit::ops::{BinaryTower128Target, ByteHash, bytes_to_limbs};
use p3_circuit::{CircuitBuilder, ExprId};
use p3_commit::MultilinearPcs;
use p3_field::{ExtensionField, Field, PackedValue, PrimeField64};
use p3_lookup::InteractionSymbolicBuilder;
use p3_merkle_tree::{MerkleCap, MerkleTreeMmcs};
use p3_multi_stark::MultiStarkProof;
use p3_multi_stark::config::MultiStarkConfig;
use p3_multi_stark::rounds::AirDegrees;
use p3_multi_stark::transcript::{MultiStarkInstanceShape, MultiStarkShape};
use p3_multi_stark::zerocheck::transcript::ZerocheckShape;
use p3_multilinear_util::point::Point;
use p3_sumcheck::OpeningProtocol;
use p3_sumcheck::layout;
use p3_symmetric::{CryptographicHasher, PseudoCompressionFunction};

use super::binary_air::constrain_width;
use super::binary_bus::{BinaryBusInputShape, BinaryBusVerifier};
use super::binary_indexed::{
    BinaryIndexedLookupProofTargets, BinaryIndexedVerifier, BinaryOpeningSchedule,
    IndexedInputShape, NativeIndexedInput, schedule,
};
use super::{
    BinaryAirConstraintPlan, BinaryProductGkrProofTargets, InputResourceUsage,
    NativeBinaryProductGkrInput, VerificationError, VerifierLimits,
};
use crate::pcs::binary::{
    BinaryGenericSumcheckInputShape, BinaryGenericSumcheckProofTargets,
    BinaryGenericSumcheckVerifier, BinaryNonzeroChallengePlan, BinaryPcs128ProofTargets,
    BinaryPcsInputShape, BinaryPcsVerifier, NativeBinaryGenericSumcheckInput, NativeBinaryPcsInput,
    RecursiveBinaryChallengeField, RecursiveBinaryTowerField, assert_equal, binary128_eq_eval,
    observe_cap, observe_seed, observe_values,
};
use crate::transcript::domain_separator_seed;
use crate::{BinaryQueryContinuation, BinaryTower128Challenger};

/// Proof-independent input shape including the trusted AIR program.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BinaryMultiStarkInputShape<F = BinaryField128, E = BinaryField128> {
    relation: alloc::sync::Arc<BinaryMultiStarkRelationShape<F, E>>,
    opening: BinaryPcsInputShape,
    preprocessed: Option<PreprocessedInputShape>,
    cap_height: usize,
}

/// Trusted preprocessing authority, supplied independently of every proof.
/// The commitment must belong to the ordered nonempty preprocessing tables
/// at the fixed AIR heights. Its PCS geometry may differ from the main trace.
#[derive(Clone, Debug)]
pub struct BinaryMultiStarkPreprocessing<F = BinaryField128> {
    pub config: BinaryPcsConfig,
    pub hash: ByteHash,
    pub cap_height: usize,
    pub max_query_draws: usize,
    pub commitment: MerkleCap<F, [u8; 32]>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct PreprocessedInputShape {
    opening: BinaryPcsInputShape,
    commitment: Vec<[u8; 32]>,
}

impl PreprocessedInputShape {
    fn constant_cap<EF: Field + Eq + Hash>(&self, b: &mut CircuitBuilder<EF>) -> Vec<Vec<ExprId>> {
        self.commitment
            .iter()
            .map(|root| {
                bytes_to_limbs(root)
                    .into_iter()
                    .map(|limb| b.define_const(EF::from_u16(limb)))
                    .collect()
            })
            .collect()
    }
}

#[derive(Clone, Debug)]
pub struct BinaryMultiStarkProofTargets {
    pub commitment: Vec<Vec<ExprId>>,
    pub bus: Option<BinaryProductGkrProofTargets>,
    pub sumcheck: BinaryGenericSumcheckProofTargets,
    pub indexed: Option<BinaryIndexedLookupProofTargets>,
    pub opening: BinaryPcs128ProofTargets,
    pub preprocessed_opening: Option<BinaryPcs128ProofTargets>,
}

impl<F: RecursiveBinaryTowerField, E: RecursiveBinaryChallengeField>
    BinaryMultiStarkInputShape<F, E>
{
    pub(crate) fn native_decode_shape(&self) -> crate::artifact::binary_native::codec::MultiDecode
    where
        E: ExtensionField<F>,
    {
        crate::artifact::binary_native::codec::MultiDecode {
            public_counts: self.public_value_counts().collect(),
            cap_roots: 1usize << self.cap_height,
            bus: self
                .relation
                .bus
                .as_ref()
                .map(|b| b.product.native_decode_shape()),
            sumcheck: self.relation.sumcheck.native_decode_shape(),
            indexed: self
                .relation
                .indexed
                .as_ref()
                .map(|i| i.native_decode_shape()),
            opening: self.opening.native_decode_shape(),
            preprocessed: self
                .preprocessed
                .as_ref()
                .map(|p| p.opening.native_decode_shape()),
        }
    }

    pub(crate) fn write_identity(
        &self,
        w: &mut crate::artifact::wire::Writer,
    ) -> Result<(), crate::artifact::ArtifactError>
    where
        E: ExtensionField<F>,
    {
        w.write_vec("binary native AIRs", &self.relation.airs, |w, air| {
            air.write_identity(w)
        })?;
        for seed in [&self.relation.outer_seed, &self.relation.zerocheck_seed] {
            w.write_vec("binary native transcript seed", seed, |w, value| {
                w.write_bytes(&value.raw_coordinates().to_le_bytes()[..F::RAW_BITS / 8])
            })?;
        }
        if let Some(pp) = &self.preprocessed {
            w.write_vec(
                "binary native preprocessing cap",
                &pp.commitment,
                |w, root| w.write_bytes(root),
            )?;
        }
        Ok(())
    }

    /// Trusted public-value counts in the original AIR instance order.
    pub fn public_value_counts(&self) -> impl ExactSizeIterator<Item = usize> + '_
    where
        E: ExtensionField<F>,
    {
        self.relation
            .airs
            .iter()
            .map(BinaryAirConstraintPlan::public_value_count)
    }

    /// Allocates cap, bus, sumcheck, indexed reduction and PCS witnesses in order.
    /// Public values are allocated and bound separately by the caller.
    pub fn allocate_targets<BF, EF>(
        &self,
        b: &mut CircuitBuilder<EF>,
    ) -> Result<BinaryMultiStarkProofTargets, VerificationError>
    where
        BF: PrimeField64,
        EF: ExtensionField<BF> + Eq + Hash,
    {
        let commitment = (0..1usize << self.cap_height)
            .map(|_| {
                b.alloc_private_input_array::<16>("binary MultiStark commitment")
                    .to_vec()
            })
            .collect();
        let bus = self
            .relation
            .bus
            .as_ref()
            .map(|bus| bus.product.allocate_targets::<BF, EF>(b))
            .transpose()?;
        let sumcheck = self.relation.sumcheck.allocate_targets::<BF, EF>(b)?;
        let indexed = self
            .relation
            .indexed
            .as_ref()
            .map(|shape| shape.allocate_targets::<BF, EF>(b))
            .transpose()?;
        let opening = self.opening.allocate_targets::<BF, EF>(b)?;
        let preprocessed_opening = self
            .preprocessed
            .as_ref()
            .map(|preprocessed| preprocessed.opening.allocate_targets::<BF, EF>(b))
            .transpose()?;
        Ok(BinaryMultiStarkProofTargets {
            commitment,
            bus,
            sumcheck,
            indexed,
            opening,
            preprocessed_opening,
        })
    }
}

/// Bounded witness material. It conveys no independent verification authority.
#[derive(Clone, Debug)]
pub struct NativeBinaryMultiStarkInput<F = BinaryField128, E = BinaryField128> {
    shape: BinaryMultiStarkInputShape<F, E>,
    commitment: Vec<[u8; 32]>,
    bus: Option<NativeBinaryProductGkrInput<F, E>>,
    sumcheck: NativeBinaryGenericSumcheckInput<F, E>,
    indexed: Option<NativeIndexedInput<F, E>>,
    opening: NativeBinaryPcsInput,
    preprocessed_opening: Option<NativeBinaryPcsInput>,
}

impl<F: RecursiveBinaryTowerField, E: RecursiveBinaryChallengeField>
    NativeBinaryMultiStarkInput<F, E>
{
    pub fn shape(&self) -> &BinaryMultiStarkInputShape<F, E> {
        &self.shape
    }

    pub fn private_values<EF: Field>(
        &self,
        expected: &BinaryMultiStarkInputShape<F, E>,
    ) -> Result<Vec<EF>, VerificationError> {
        if &self.shape != expected {
            return Err(invalid(
                "binary MultiStark input belongs to another verifier",
            ));
        }
        let mut values: Vec<EF> = self
            .commitment
            .iter()
            .flat_map(|root| bytes_to_limbs(root).into_iter().map(EF::from_u16))
            .collect();
        match (&expected.relation.bus, &self.bus) {
            (Some(shape), Some(input)) => {
                values.extend(input.private_values::<EF>(&shape.product)?)
            }
            (None, None) => {}
            _ => return Err(invalid("binary MultiStark bus input shape mismatch")),
        }
        values.extend(
            self.sumcheck
                .private_values::<EF>(&expected.relation.sumcheck)?,
        );
        match (&expected.relation.indexed, &self.indexed) {
            (Some(shape), Some(input)) => values.extend(input.private_values::<EF>(shape)?),
            (None, None) => {}
            _ => return Err(invalid("binary MultiStark indexed input shape mismatch")),
        }
        values.extend(self.opening.private_values::<EF>(&expected.opening)?);
        match (&expected.preprocessed, &self.preprocessed_opening) {
            (Some(shape), Some(input)) => {
                values.extend(input.private_values::<EF>(&shape.opening)?)
            }
            (None, None) => {}
            _ => {
                return Err(invalid(
                    "binary MultiStark preprocessing input shape mismatch",
                ));
            }
        }
        Ok(values)
    }
}

/// Trusted binary MultiStark verifier with ordinary byte MMCS.
/// Binds caller-owned public values through the complete AIR, sumcheck, and
/// authenticated PCS relation. Periodic constants and preprocessing authority
/// are fixed by construction. Native binary buses are reduced through the
/// authenticated AIR sumcheck. Indexed reads are reduced by LogUpStar and
/// authenticated at their own PCS points. Classical lookups remain unsupported.
#[derive(Clone, Debug)]
pub struct BinaryMultiStarkVerifier<F = BinaryField128, E = BinaryField128> {
    input: BinaryMultiStarkInputShape<F, E>,
    relation: BinaryMultiStarkRelation<F, E>,
    opening: BinaryPcsVerifier<F, E>,
    preprocessed: Option<BinaryPcsVerifier<F, E>>,
    usage: InputResourceUsage,
}

impl<F, E> BinaryMultiStarkVerifier<F, E>
where
    F: RecursiveBinaryTowerField,
    E: RecursiveBinaryChallengeField + ExtensionField<F>,
{
    /// Installs the exact cap captured from the factory's matched native setup.
    /// Geometry was validated before setup, with a placeholder cap of this size.
    pub(crate) fn bind_native_preprocessing_cap(
        &mut self,
        cap: Vec<[u8; 32]>,
    ) -> Result<(), VerificationError> {
        let Some(pp) = &mut self.input.preprocessed else {
            return Err(invalid(
                "binary native setup produced an unexpected preprocessing cap",
            ));
        };
        if cap.len() != pp.commitment.len() {
            return Err(invalid(
                "binary native setup preprocessing cap shape mismatch",
            ));
        }
        pp.commitment = cap;
        Ok(())
    }

    pub fn new<A>(
        airs: &[&A],
        heights: &[usize],
        config: BinaryPcsConfig,
        hash: ByteHash,
        cap_height: usize,
        pow_bits: usize,
        max_tau_draws: usize,
        max_query_draws: usize,
    ) -> Result<Self, VerificationError>
    where
        A: Air<InteractionSymbolicBuilder<F, E>> + Air<BusSymbolicBuilder<F, E>>,
    {
        Self::with_limits(
            airs,
            heights,
            config,
            hash,
            cap_height,
            pow_bits,
            max_tau_draws,
            max_query_draws,
            &VerifierLimits::default(),
        )
    }

    pub fn with_limits<A>(
        airs: &[&A],
        heights: &[usize],
        config: BinaryPcsConfig,
        hash: ByteHash,
        cap_height: usize,
        pow_bits: usize,
        max_tau_draws: usize,
        max_query_draws: usize,
        limits: &VerifierLimits,
    ) -> Result<Self, VerificationError>
    where
        A: Air<InteractionSymbolicBuilder<F, E>> + Air<BusSymbolicBuilder<F, E>>,
    {
        Self::build(
            airs,
            heights,
            config,
            hash,
            cap_height,
            pow_bits,
            max_tau_draws,
            max_query_draws,
            None,
            limits,
        )
    }

    /// Builds a verifier retaining an independent trusted preprocessing cap.
    /// No proof can provide or replace this authority.
    pub fn with_preprocessing<A>(
        airs: &[&A],
        heights: &[usize],
        config: BinaryPcsConfig,
        hash: ByteHash,
        cap_height: usize,
        pow_bits: usize,
        max_tau_draws: usize,
        max_query_draws: usize,
        preprocessing: BinaryMultiStarkPreprocessing<F>,
        limits: &VerifierLimits,
    ) -> Result<Self, VerificationError>
    where
        A: Air<InteractionSymbolicBuilder<F, E>> + Air<BusSymbolicBuilder<F, E>>,
    {
        Self::build(
            airs,
            heights,
            config,
            hash,
            cap_height,
            pow_bits,
            max_tau_draws,
            max_query_draws,
            Some(preprocessing),
            limits,
        )
    }

    fn build<A>(
        airs: &[&A],
        heights: &[usize],
        config: BinaryPcsConfig,
        hash: ByteHash,
        cap_height: usize,
        pow_bits: usize,
        max_tau_draws: usize,
        max_query_draws: usize,
        preprocessing: Option<BinaryMultiStarkPreprocessing<F>>,
        limits: &VerifierLimits,
    ) -> Result<Self, VerificationError>
    where
        A: Air<InteractionSymbolicBuilder<F, E>> + Air<BusSymbolicBuilder<F, E>>,
    {
        let (relation, main_protocol, preprocessed_protocol) = BinaryMultiStarkRelation::build(
            airs,
            heights,
            pow_bits,
            max_tau_draws,
            preprocessing.is_some(),
            limits,
        )?;
        let mut usage = relation.usage;
        let opening = BinaryPcsVerifier::<F, E>::with_limits(
            config,
            main_protocol,
            hash,
            cap_height,
            max_query_draws,
            limits,
        )?;
        let mut opening_usage = opening.input_resource_usage();
        opening_usage.instances = 0;
        usage.merge(limits, opening_usage)?;
        let (preprocessed, preprocessed_input) = if let Some(preprocessing) = preprocessing {
            let verifier = BinaryPcsVerifier::<F, E>::with_limits(
                preprocessing.config,
                preprocessed_protocol.expect("checked preprocessing protocol"),
                preprocessing.hash,
                preprocessing.cap_height,
                preprocessing.max_query_draws,
                limits,
            )?;
            if preprocessing.commitment.num_roots() != 1usize << preprocessing.cap_height {
                return Err(invalid(
                    "binary MultiStark trusted preprocessing cap shape mismatch",
                ));
            }
            let mut preprocessed_usage = verifier.input_resource_usage();
            preprocessed_usage.instances = 0;
            usage.merge(limits, preprocessed_usage)?;
            usage.add_metadata_entries(limits, preprocessing.commitment.num_roots())?;
            let input = PreprocessedInputShape {
                opening: verifier.input_shape(),
                commitment: preprocessing.commitment.roots().to_vec(),
            };
            (Some(verifier), Some(input))
        } else {
            (None, None)
        };
        let input = BinaryMultiStarkInputShape {
            relation: relation.input.clone(),
            opening: opening.input_shape(),
            preprocessed: preprocessed_input,
            cap_height,
        };
        Ok(Self {
            input,
            relation,
            opening,
            preprocessed,
            usage,
        })
    }

    pub fn input_shape(&self) -> BinaryMultiStarkInputShape<F, E> {
        self.input.clone()
    }
    pub fn input_resource_usage(&self) -> InputResourceUsage {
        self.usage
    }

    /// Checks all AIR obligations and authenticates their committed openings.
    /// Public targets are the caller's actual statement, in instance order.
    /// The returned token resumes only through a nonempty next observation.
    pub fn verify<BF, EF>(
        &self,
        b: &mut CircuitBuilder<EF>,
        mut ch: BinaryTower128Challenger,
        public: &[Vec<BinaryTower128Target>],
        proof: &BinaryMultiStarkProofTargets,
    ) -> Result<BinaryQueryContinuation, VerificationError>
    where
        BF: PrimeField64,
        EF: ExtensionField<BF> + Eq + Hash,
    {
        self.check_public(public)?;
        match (&self.relation.bus, &proof.bus) {
            (Some(verifier), Some(proof)) => verifier.check_targets(proof)?,
            (None, None) => {}
            _ => return Err(invalid("binary MultiStark bus proof shape mismatch")),
        }
        self.relation.sumcheck.check_targets(&proof.sumcheck)?;
        match (&self.relation.indexed, &proof.indexed) {
            (Some(verifier), Some(proof)) => verifier.check_proof_targets(proof)?,
            (None, None) => {}
            _ => return Err(invalid("binary MultiStark indexed proof shape mismatch")),
        }
        let zero = b.binary128_constant(0)?;
        let heights: Vec<_> = self
            .input
            .relation
            .airs
            .iter()
            .map(|air| air.log_height())
            .collect();
        let points = self
            .input
            .relation
            .main_schedule
            .zero_points(&heights, zero.clone());
        self.opening
            .check_targets(&proof.commitment, &points, &proof.opening)?;
        let preprocessed_cap = match (
            &self.preprocessed,
            &self.input.preprocessed,
            &proof.preprocessed_opening,
        ) {
            (Some(verifier), Some(shape), Some(proof)) => {
                let cap = shape.constant_cap(b);
                let points = self
                    .relation
                    .input
                    .preprocessed_schedule
                    .as_ref()
                    .unwrap()
                    .zero_points(&heights, zero.clone());
                verifier.check_targets(&cap, &points, proof)?;
                Some(cap)
            }
            (None, None, None) => None,
            _ => {
                return Err(invalid(
                    "binary MultiStark preprocessed opening shape mismatch",
                ));
            }
        };
        observe_seed::<F, BF, EF>(b, &mut ch, &self.input.relation.outer_seed)?;
        if let Some(cap) = &preprocessed_cap {
            // Native MultiStark absorbs this trusted VK cap directly, without
            // the seed used by the throwaway setup commitment transcript.
            observe_cap::<BF, EF>(b, &mut ch, cap)?;
        }
        self.opening
            .observe_commitment::<BF, EF>(b, &mut ch, &proof.commitment)?;
        for values in public {
            for value in values {
                constrain_width(b, value, F::RAW_BITS);
            }
            observe_values::<BF, EF>(b, &mut ch, values, F::RAW_BITS)?;
        }
        let bus_claims = if let (Some(verifier), Some(proof)) = (&self.relation.bus, &proof.bus) {
            let (claims, next) = verifier.verify::<BF, EF>(b, ch, proof)?;
            ch = next;
            Some(claims)
        } else {
            None
        };
        observe_seed::<F, BF, EF>(b, &mut ch, &self.input.relation.zerocheck_seed)?;
        let alpha = self.opening.sample_challenge::<BF, EF>(b, &mut ch)?;
        let beta = self.opening.sample_challenge::<BF, EF>(b, &mut ch)?;
        let lambda = if bus_claims.is_some() {
            Some(self.opening.sample_challenge::<BF, EF>(b, &mut ch)?)
        } else {
            None
        };
        let initial = if let (Some(claims), Some(lambda)) = (&bus_claims, &lambda) {
            let one = b.binary128_constant(1)?;
            let push = b.binary128_add(&claims.values[0], &one);
            let pull = b.binary128_add(&claims.values[1], &one);
            let pull = b.binary128_mul(lambda, &pull);
            let batched = b.binary128_add(&push, &pull);
            b.binary128_mul(lambda, &batched)
        } else {
            zero.clone()
        };
        let output = self.relation.tau.sample::<BF, EF>(b, ch)?;
        let reduction = self
            .relation
            .sumcheck
            .verify_reduction_after_queries::<BF, EF>(
                b,
                output.continuation,
                &initial,
                &proof.sumcheck,
            )?;
        let tau = output.values;
        let indexed =
            if let (Some(verifier), Some(proof)) = (&self.relation.indexed, &proof.indexed) {
                Some(verifier.verify::<BF, EF>(
                    b,
                    reduction.challenger.clone(),
                    &reduction.point,
                    proof,
                )?)
            } else {
                None
            };
        let indexed_points = indexed.as_ref().map(|output| {
            (
                output.position_point.as_slice(),
                output.table_point.as_slice(),
            )
        });
        let points =
            self.input
                .relation
                .main_schedule
                .points(&heights, &reduction.point, indexed_points);
        let challenger = indexed
            .as_ref()
            .map(|output| output.challenger.clone())
            .unwrap_or(reduction.challenger);
        let mut continuation = self.opening.verify_at_with_continuation::<BF, EF>(
            b,
            challenger,
            &proof.commitment,
            &points,
            &proof.opening,
        )?;
        if let (Some(verifier), Some(_shape), Some(cap), Some(proof)) = (
            &self.preprocessed,
            &self.input.preprocessed,
            &preprocessed_cap,
            &proof.preprocessed_opening,
        ) {
            let points = self
                .relation
                .input
                .preprocessed_schedule
                .as_ref()
                .unwrap()
                .points(&heights, &reduction.point, indexed_points);
            continuation =
                verifier.verify_at_after_queries::<BF, EF>(b, continuation, cap, &points, proof)?;
        }
        if let (Some(verifier), Some(indexed_proof), Some(output)) =
            (&self.relation.indexed, &proof.indexed, &indexed)
        {
            let preprocessing = self
                .input
                .preprocessed
                .as_ref()
                .zip(proof.preprocessed_opening.as_ref())
                .map(|(_shape, opening)| {
                    (
                        self.relation.input.preprocessed_schedule.as_ref().unwrap(),
                        opening.evals.as_slice(),
                    )
                });
            verifier.authenticate(
                b,
                indexed_proof,
                output,
                &self.input.relation.main_schedule,
                &proof.opening.evals,
                preprocessing,
            );
        }
        let mut folded = zero;
        let mut weight = b.binary128_constant(1)?;
        let mut air_evaluations = Vec::with_capacity(self.input.relation.airs.len());
        for (i, air) in self.input.relation.airs.iter().enumerate() {
            let values = &proof.opening.evals[self.input.relation.main_schedule.air_batch(i)];
            let (preprocessed_current, preprocessed_next) = if air.preprocessed_width() != 0 {
                let slot = self
                    .relation
                    .input
                    .preprocessed_schedule
                    .as_ref()
                    .unwrap()
                    .air_batch(i);
                let values = &proof.preprocessed_opening.as_ref().unwrap().evals[slot];
                (values.current(), values.next())
            } else {
                (&[][..], &[][..])
            };
            let evaluation = air.evaluate_with_bus(
                b,
                &reduction.point[reduction.point.len() - air.log_height()..],
                values.current(),
                values.next(),
                preprocessed_current,
                preprocessed_next,
                &public[i],
                &alpha,
            )?;
            let term = b.binary128_mul(&weight, &evaluation.folded);
            folded = b.binary128_add(&folded, &term);
            weight = b.binary128_mul(&weight, &beta);
            air_evaluations.push(evaluation);
        }
        let equality = binary128_eq_eval(b, &tau, &reduction.point)?;
        let mut terminal = b.binary128_mul(&equality, &folded);
        if let (Some(verifier), Some(claims), Some(lambda)) =
            (&self.relation.bus, &bus_claims, &lambda)
        {
            let bus = verifier.terminal(b, claims, &air_evaluations, &reduction.point, lambda)?;
            let weighted = b.binary128_mul(lambda, &bus);
            terminal = b.binary128_add(&terminal, &weighted);
        }
        assert_equal(b, &reduction.claim, &terminal);
        Ok(continuation)
    }

    fn check_public<T>(&self, public: &[Vec<T>]) -> Result<(), VerificationError> {
        if public.len() != self.input.relation.airs.len()
            || public
                .iter()
                .zip(&self.input.relation.airs)
                .any(|(values, air)| values.len() != air.public_value_count())
        {
            return Err(invalid("binary MultiStark public value shape mismatch"));
        }
        Ok(())
    }

    /// Imports ordinary-byte-tree native proofs with finite transcript replay.
    /// Every visible shape is checked before sampling. Failure leaves the
    /// caller's challenger unchanged; success retains exact native completion.
    pub fn import_native<C, H0, C0, H1, C1, Ch>(
        &self,
        base_mmcs: &MerkleTreeMmcs<F, u8, H0, C0, 2, 32>,
        round_mmcs: &MerkleTreeMmcs<E, u8, H1, C1, 2, 32>,
        public: &[Vec<F>],
        proof: &MultiStarkProof<C>,
        ch: &mut Ch,
    ) -> Result<NativeBinaryMultiStarkInput<F, E>, VerificationError>
    where
        C: MultiStarkConfig<Val = F, Challenge = E>,
        C::Pcs: MultilinearPcs<
                E,
                C::Challenger,
                Commitment = MerkleCap<F, [u8; 32]>,
                Proof = BinaryPcsProof<
                    F,
                    E,
                    MerkleTreeMmcs<F, u8, H0, C0, 2, 32>,
                    MerkleTreeMmcs<E, u8, H1, C1, 2, 32>,
                >,
            >,
        F: PackedValue<Value = F>,
        E: PackedValue<Value = E>,
        H0: CryptographicHasher<F, [u8; 32]> + Sync,
        H1: CryptographicHasher<E, [u8; 32]> + Sync,
        C0: PseudoCompressionFunction<[u8; 32], 2> + Sync,
        C1: PseudoCompressionFunction<[u8; 32], 2> + Sync,
        Ch: FieldChallenger<F>
            + CanSampleUniformBits<F>
            + GrindingChallenger<Witness = F>
            + CanObserve<MerkleCap<F, [u8; 32]>>
            + CanObserve<MerkleCap<E, [u8; 32]>>
            + Clone,
    {
        let preprocessing = self.preprocessed.as_ref().map(|_| (base_mmcs, round_mmcs));
        self.import_native_with_preprocessing(
            base_mmcs,
            round_mmcs,
            preprocessing,
            public,
            proof,
            ch,
        )
    }

    /// Imports a proof whose preprocessing uses independently configured MMCS
    /// instances, including a cap height distinct from the main trace.
    pub fn import_native_with_preprocessing<C, H0, C0, H1, C1, Ch>(
        &self,
        base_mmcs: &MerkleTreeMmcs<F, u8, H0, C0, 2, 32>,
        round_mmcs: &MerkleTreeMmcs<E, u8, H1, C1, 2, 32>,
        preprocessed_mmcs: Option<(
            &MerkleTreeMmcs<F, u8, H0, C0, 2, 32>,
            &MerkleTreeMmcs<E, u8, H1, C1, 2, 32>,
        )>,
        public: &[Vec<F>],
        proof: &MultiStarkProof<C>,
        ch: &mut Ch,
    ) -> Result<NativeBinaryMultiStarkInput<F, E>, VerificationError>
    where
        C: MultiStarkConfig<Val = F, Challenge = E>,
        C::Pcs: MultilinearPcs<
                E,
                C::Challenger,
                Commitment = MerkleCap<F, [u8; 32]>,
                Proof = BinaryPcsProof<
                    F,
                    E,
                    MerkleTreeMmcs<F, u8, H0, C0, 2, 32>,
                    MerkleTreeMmcs<E, u8, H1, C1, 2, 32>,
                >,
            >,
        F: PackedValue<Value = F>,
        E: PackedValue<Value = E>,
        H0: CryptographicHasher<F, [u8; 32]> + Sync,
        H1: CryptographicHasher<E, [u8; 32]> + Sync,
        C0: PseudoCompressionFunction<[u8; 32], 2> + Sync,
        C1: PseudoCompressionFunction<[u8; 32], 2> + Sync,
        Ch: FieldChallenger<F>
            + CanSampleUniformBits<F>
            + GrindingChallenger<Witness = F>
            + CanObserve<MerkleCap<F, [u8; 32]>>
            + CanObserve<MerkleCap<E, [u8; 32]>>
            + Clone,
    {
        self.check_public(public)?;
        if proof.lookup.is_some()
            || (self.relation.bus.is_none() && proof.sumcheck.claimed_sum != E::ZERO)
        {
            return Err(invalid(
                "binary MultiStark proof has unsupported parts or a nonzero initial sum",
            ));
        }
        match (&self.relation.bus, &proof.bus) {
            (Some(verifier), Some(proof)) => verifier.check_native(proof)?,
            (None, None) => {}
            _ => return Err(invalid("binary MultiStark native bus proof shape mismatch")),
        }
        self.relation.sumcheck.check_native(&proof.sumcheck)?;
        let heights: Vec<_> = self
            .input
            .relation
            .airs
            .iter()
            .map(|air| air.log_height())
            .collect();
        let height = *heights.iter().max().unwrap();
        match (&self.relation.indexed, &proof.indexed) {
            (Some(verifier), Some(proof)) => {
                verifier.check_native(&Point::new(vec![E::ZERO; height]), proof)?
            }
            (None, None) => {}
            _ => {
                return Err(invalid(
                    "binary MultiStark native indexed proof shape mismatch",
                ));
            }
        }
        let points: Vec<_> = self
            .input
            .relation
            .main_schedule
            .zero_points(&heights, E::ZERO)
            .into_iter()
            .map(Point::new)
            .collect();
        self.opening.check_native(
            base_mmcs,
            round_mmcs,
            &proof.commitment,
            &points,
            &proof.opening,
        )?;
        let preprocessing = match (
            &self.preprocessed,
            &self.input.preprocessed,
            preprocessed_mmcs,
            &proof.preprocessed_opening,
        ) {
            (Some(verifier), Some(shape), Some((base, round)), Some(proof)) => {
                let cap = MerkleCap::<F, _>::new(shape.commitment.clone());
                let points: Vec<_> = self
                    .relation
                    .input
                    .preprocessed_schedule
                    .as_ref()
                    .unwrap()
                    .zero_points(&heights, E::ZERO)
                    .into_iter()
                    .map(Point::new)
                    .collect();
                verifier.check_native(base, round, &cap, &points, proof)?;
                Some((verifier, shape, base, round, proof, cap))
            }
            (None, None, None, None) => None,
            _ => {
                return Err(invalid(
                    "binary MultiStark native preprocessed opening shape mismatch",
                ));
            }
        };
        let mut staged = ch.clone();
        staged.observe_slice(&self.input.relation.outer_seed);
        if let Some((_, _, _, _, _, cap)) = &preprocessing {
            staged.observe(cap.clone());
        }
        layout::observe_commitment::<F, _, _>(&mut staged, proof.commitment.clone());
        for values in public {
            staged.observe_slice(values);
        }
        let bus_reduction = if let (Some(verifier), Some(proof)) = (&self.relation.bus, &proof.bus)
        {
            Some(verifier.import_native(proof, &mut staged)?)
        } else {
            None
        };
        staged.observe_slice(&self.input.relation.zerocheck_seed);
        let _alpha = staged.sample_algebra_element::<E>();
        let _beta = staged.sample_algebra_element::<E>();
        if let Some((_, values)) = &bus_reduction {
            let lambda = staged.sample_algebra_element::<E>();
            let expected = lambda * ((values[0] + E::ONE) + lambda * (values[1] + E::ONE));
            if proof.sumcheck.claimed_sum != expected {
                return Err(invalid("binary MultiStark bus initial sum mismatch"));
            }
        }
        let _ = self.relation.tau.sample_native::<F, _>(&mut staged)?;
        let (sumcheck, point, _) = self
            .relation
            .sumcheck
            .import_native_with_reduction(&proof.sumcheck, &mut staged)?;
        let indexed =
            if let (Some(verifier), Some(proof)) = (&self.relation.indexed, &proof.indexed) {
                Some(verifier.import_native(&point, proof, &mut staged)?)
            } else {
                None
            };
        let indexed_points = indexed.as_ref().map(|(_, output)| {
            (
                output.position_point.as_slice(),
                output.table_point.as_slice(),
            )
        });
        let points: Vec<_> = self
            .input
            .relation
            .main_schedule
            .points(&heights, point.as_slice(), indexed_points)
            .into_iter()
            .map(Point::new)
            .collect();
        let opening = self.opening.import_native(
            base_mmcs,
            round_mmcs,
            &proof.commitment,
            &points,
            &proof.opening,
            &mut staged,
        )?;
        let preprocessed_opening = preprocessing
            .map(|(verifier, _shape, base, round, proof, cap)| {
                let points: Vec<_> = self
                    .relation
                    .input
                    .preprocessed_schedule
                    .as_ref()
                    .unwrap()
                    .points(&heights, point.as_slice(), indexed_points)
                    .into_iter()
                    .map(Point::new)
                    .collect();
                verifier.import_native(base, round, &cap, &points, proof, &mut staged)
            })
            .transpose()?;
        *ch = staged;
        Ok(NativeBinaryMultiStarkInput {
            shape: self.input.clone(),
            commitment: proof.commitment.roots().to_vec(),
            bus: bus_reduction.map(|(input, _)| input),
            sumcheck,
            indexed: indexed.map(|(input, _)| input),
            opening,
            preprocessed_opening,
        })
    }
}

fn invalid(message: &'static str) -> VerificationError {
    VerificationError::InvalidProofShape(message.into())
}
