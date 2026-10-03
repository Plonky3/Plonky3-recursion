//! Complete native binary MultiStark verification with supported AIR reductions.

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
use p3_sumcheck::layout;
use p3_sumcheck::{OpeningBatch, OpeningProtocol, TableShape, TableSpec};
use p3_symmetric::{CryptographicHasher, PseudoCompressionFunction};

use super::binary_air::constrain_width;
use super::binary_bus::{BinaryBusInputShape, BinaryBusVerifier};
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
    airs: Vec<BinaryAirConstraintPlan<F, E>>,
    outer_seed: Vec<F>,
    zerocheck_seed: Vec<F>,
    sumcheck: BinaryGenericSumcheckInputShape<F, E>,
    opening: BinaryPcsInputShape,
    preprocessed: Option<PreprocessedInputShape>,
    bus: Option<BinaryBusInputShape<F, E>>,
    cap_height: usize,
    max_tau_draws: usize,
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
    air_indices: Vec<usize>,
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
    pub opening: BinaryPcs128ProofTargets,
    pub preprocessed_opening: Option<BinaryPcs128ProofTargets>,
}

impl<F: RecursiveBinaryTowerField, E: RecursiveBinaryChallengeField>
    BinaryMultiStarkInputShape<F, E>
{
    /// Allocates cap, optional bus, generic sumcheck and PCS witnesses in order.
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
            .bus
            .as_ref()
            .map(|bus| bus.product.allocate_targets::<BF, EF>(b))
            .transpose()?;
        let sumcheck = self.sumcheck.allocate_targets::<BF, EF>(b)?;
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
        match (&expected.bus, &self.bus) {
            (Some(shape), Some(input)) => {
                values.extend(input.private_values::<EF>(&shape.product)?)
            }
            (None, None) => {}
            _ => return Err(invalid("binary MultiStark bus input shape mismatch")),
        }
        values.extend(self.sumcheck.private_values::<EF>(&expected.sumcheck)?);
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
/// authenticated AIR sumcheck; indexed and classical lookups require other plans.
#[derive(Clone, Debug)]
pub struct BinaryMultiStarkVerifier<F = BinaryField128, E = BinaryField128> {
    input: BinaryMultiStarkInputShape<F, E>,
    sumcheck: BinaryGenericSumcheckVerifier<F, E>,
    tau: BinaryNonzeroChallengePlan<E>,
    opening: BinaryPcsVerifier<F, E>,
    preprocessed: Option<BinaryPcsVerifier<F, E>>,
    bus: Option<BinaryBusVerifier<F, E>>,
    usage: InputResourceUsage,
}

impl<F, E> BinaryMultiStarkVerifier<F, E>
where
    F: RecursiveBinaryTowerField,
    E: RecursiveBinaryChallengeField + ExtensionField<F>,
{
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
        if airs.is_empty() || airs.len() != heights.len() || heights.contains(&0) {
            return Err(invalid("binary MultiStark trusted instance shape mismatch"));
        }
        // TableShape stores its height as usize and shifts by this exponent.
        // A caller may widen resource limits, but cannot widen the platform.
        if let Some(&height) = heights
            .iter()
            .find(|&&height| height >= usize::BITS as usize)
        {
            return Err(VerificationError::ResourceLimitExceeded {
                component: "binary MultiStark trace log height",
                actual: height,
                limit: usize::BITS as usize - 1,
            });
        }
        let mut usage = InputResourceUsage::default();
        // Check the axis before compiling any trusted callback or cloning lists.
        usage.add_instances(limits, airs.len())?;
        let mut plans = Vec::with_capacity(airs.len());
        let mut bus_declarations = Vec::with_capacity(airs.len());
        for (&air, &height) in airs.iter().zip(heights) {
            let (plan, declarations) =
                BinaryAirConstraintPlan::<F, E>::with_bus_limits(air, height, limits)?;
            if plan.preprocessed_width() != 0 && preprocessing.is_none() {
                return Err(invalid(
                    "binary MultiStark preprocessing requires a trusted commitment plan",
                ));
            }
            usage.merge(limits, plan.input_resource_usage())?;
            let public_limbs = plan.public_value_count().checked_mul(8).ok_or(
                VerificationError::ResourceArithmeticOverflow {
                    component: "binary MultiStark public limbs",
                },
            )?;
            usage.add_scalar_elements(limits, public_limbs)?;
            plans.push(plan);
            bus_declarations.push(declarations);
        }
        let bus_inputs: Vec<_> = bus_declarations
            .iter()
            .zip(heights)
            .map(|(interactions, &log_height)| BusPlanInput {
                log_height,
                interactions,
            })
            .collect();
        let bus = BusPlan::build(&bus_inputs)
            .map_err(|_| invalid("binary MultiStark bus geometry is invalid"))?
            .map(|plan| BinaryBusVerifier::<F, E>::with_limits(plan, &plans, limits))
            .transpose()?;
        if let Some(bus) = &bus {
            let mut bus_usage = bus.input_resource_usage();
            bus_usage.instances = 0;
            usage.merge(limits, bus_usage)?;
        }
        let height = *heights.iter().max().unwrap();
        let degree = plans
            .iter()
            .map(BinaryAirConstraintPlan::constraint_degree)
            .max()
            .unwrap();
        let degree =
            degree
                .checked_add(1)
                .ok_or(VerificationError::ResourceArithmeticOverflow {
                    component: "binary MultiStark sumcheck degree",
                })?;
        let degree = degree.max(bus.as_ref().map(|bus| bus.degree()).unwrap_or(0));
        let sumcheck =
            BinaryGenericSumcheckVerifier::<F, E>::with_limits(height, degree, pow_bits, limits)?;
        usage.merge(limits, sumcheck.input_resource_usage())?;
        let tau = BinaryNonzeroChallengePlan::<E>::with_limits(height, max_tau_draws, limits)?;
        usage.merge(limits, tau.input_resource_usage())?;
        let tables = plans
            .iter()
            .map(|air| {
                TableSpec::new(
                    TableShape::new(air.log_height(), air.main_width()),
                    vec![OpeningBatch::new(
                        (0..air.main_width()).collect(),
                        air.next_columns().to_vec(),
                    )],
                )
            })
            .collect();
        let opening = BinaryPcsVerifier::<F, E>::with_limits(
            config,
            OpeningProtocol::new(tables),
            hash,
            cap_height,
            max_query_draws,
            limits,
        )?;
        // PCS usage already accounts for the outer cap and instance axis.
        let mut opening_usage = opening.input_resource_usage();
        opening_usage.instances = 0;
        usage.merge(limits, opening_usage)?;
        let preprocessed_indices: Vec<_> = plans
            .iter()
            .enumerate()
            .filter_map(|(index, air)| (air.preprocessed_width() != 0).then_some(index))
            .collect();
        usage.add_metadata_entries(limits, preprocessed_indices.len())?;
        if preprocessed_indices.is_empty() && preprocessing.is_some() {
            return Err(invalid(
                "binary MultiStark has an unused preprocessing authority",
            ));
        }
        let (preprocessed, preprocessed_input) = if let Some(preprocessing) = preprocessing {
            let tables = preprocessed_indices
                .iter()
                .map(|&index| {
                    let air = &plans[index];
                    TableSpec::new(
                        TableShape::new(air.log_height(), air.preprocessed_width()),
                        vec![OpeningBatch::new(
                            (0..air.preprocessed_width()).collect(),
                            air.preprocessed_next_columns().to_vec(),
                        )],
                    )
                })
                .collect();
            let verifier = BinaryPcsVerifier::<F, E>::with_limits(
                preprocessing.config,
                OpeningProtocol::new(tables),
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
                air_indices: preprocessed_indices,
            };
            (Some(verifier), Some(input))
        } else {
            (None, None)
        };
        let outer = MultiStarkShape {
            instances: plans
                .iter()
                .map(|air| MultiStarkInstanceShape {
                    num_variables: air.log_height(),
                    main_width: air.main_width(),
                    preprocessed_width: air.preprocessed_width(),
                    num_public_values: air.public_value_count(),
                    main_next_row_columns: air.next_columns().to_vec(),
                    preprocessed_next_row_columns: air.preprocessed_next_columns().to_vec(),
                })
                .collect(),
            pow_bits,
            has_indexed: false,
            has_bus: bus.is_some(),
        };
        let degrees: Vec<_> = plans
            .iter()
            .map(|air| AirDegrees {
                constraints: air.constraint_degree(),
                interactions: 0,
            })
            .collect();
        let mut zerocheck = ZerocheckShape::new(&degrees, height, 0, pow_bits);
        if let Some(bus) = &bus {
            zerocheck = zerocheck.with_bus(bus.degree());
        }
        let input = BinaryMultiStarkInputShape {
            airs: plans,
            outer_seed: domain_separator_seed(&outer.domain_separator::<F>()),
            zerocheck_seed: domain_separator_seed(&zerocheck.domain_separator::<F, E>()),
            sumcheck: sumcheck.input_shape(),
            opening: opening.input_shape(),
            preprocessed: preprocessed_input,
            bus: bus.as_ref().map(|bus| bus.input_shape()),
            cap_height,
            max_tau_draws,
        };
        Ok(Self {
            input,
            sumcheck,
            tau,
            opening,
            preprocessed,
            bus,
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
        match (&self.bus, &proof.bus) {
            (Some(verifier), Some(proof)) => verifier.check_targets(proof)?,
            (None, None) => {}
            _ => return Err(invalid("binary MultiStark bus proof shape mismatch")),
        }
        self.sumcheck.check_targets(&proof.sumcheck)?;
        let zero = b.binary128_constant(0)?;
        let points: Vec<_> = self
            .input
            .airs
            .iter()
            .map(|air| vec![zero.clone(); air.log_height()])
            .collect();
        self.opening
            .check_targets(&proof.commitment, &points, &proof.opening)?;
        let preprocessed_cap = match (
            &self.preprocessed,
            &self.input.preprocessed,
            &proof.preprocessed_opening,
        ) {
            (Some(verifier), Some(shape), Some(proof)) => {
                let cap = shape.constant_cap(b);
                let points: Vec<_> = shape
                    .air_indices
                    .iter()
                    .map(|&index| points[index].clone())
                    .collect();
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
        observe_seed::<F, BF, EF>(b, &mut ch, &self.input.outer_seed)?;
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
        let bus_claims = if let (Some(verifier), Some(proof)) = (&self.bus, &proof.bus) {
            let (claims, next) = verifier.verify::<BF, EF>(b, ch, proof)?;
            ch = next;
            Some(claims)
        } else {
            None
        };
        observe_seed::<F, BF, EF>(b, &mut ch, &self.input.zerocheck_seed)?;
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
        let output = self.tau.sample::<BF, EF>(b, ch)?;
        let reduction = self.sumcheck.verify_reduction_after_queries::<BF, EF>(
            b,
            output.continuation,
            &initial,
            &proof.sumcheck,
        )?;
        let tau = output.values;
        let points: Vec<_> = self
            .input
            .airs
            .iter()
            .map(|air| reduction.point[reduction.point.len() - air.log_height()..].to_vec())
            .collect();
        let mut continuation = self.opening.verify_at_with_continuation::<BF, EF>(
            b,
            reduction.challenger,
            &proof.commitment,
            &points,
            &proof.opening,
        )?;
        if let (Some(verifier), Some(shape), Some(cap), Some(proof)) = (
            &self.preprocessed,
            &self.input.preprocessed,
            &preprocessed_cap,
            &proof.preprocessed_opening,
        ) {
            let points: Vec<_> = shape
                .air_indices
                .iter()
                .map(|&index| points[index].clone())
                .collect();
            continuation =
                verifier.verify_at_after_queries::<BF, EF>(b, continuation, cap, &points, proof)?;
        }
        let mut folded = zero;
        let mut weight = b.binary128_constant(1)?;
        let mut preprocessed_slot = 0;
        let mut air_evaluations = Vec::with_capacity(self.input.airs.len());
        for (i, air) in self.input.airs.iter().enumerate() {
            let values = &proof.opening.evals[i];
            let (preprocessed_current, preprocessed_next) = if air.preprocessed_width() != 0 {
                let values = &proof.preprocessed_opening.as_ref().unwrap().evals[preprocessed_slot];
                preprocessed_slot += 1;
                (values.current(), values.next())
            } else {
                (&[][..], &[][..])
            };
            let evaluation = air.evaluate_with_bus(
                b,
                &points[i],
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
        if let (Some(verifier), Some(claims), Some(lambda)) = (&self.bus, &bus_claims, &lambda) {
            let bus = verifier.terminal(b, claims, &air_evaluations, &reduction.point, lambda)?;
            let weighted = b.binary128_mul(lambda, &bus);
            terminal = b.binary128_add(&terminal, &weighted);
        }
        assert_equal(b, &reduction.claim, &terminal);
        Ok(continuation)
    }

    fn check_public<T>(&self, public: &[Vec<T>]) -> Result<(), VerificationError> {
        if public.len() != self.input.airs.len()
            || public
                .iter()
                .zip(&self.input.airs)
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
            || proof.indexed.is_some()
            || (self.bus.is_none() && proof.sumcheck.claimed_sum != E::ZERO)
        {
            return Err(invalid(
                "binary MultiStark proof has unsupported parts or a nonzero initial sum",
            ));
        }
        match (&self.bus, &proof.bus) {
            (Some(verifier), Some(proof)) => verifier.check_native(proof)?,
            (None, None) => {}
            _ => return Err(invalid("binary MultiStark native bus proof shape mismatch")),
        }
        self.sumcheck.check_native(&proof.sumcheck)?;
        let points: Vec<_> = self
            .input
            .airs
            .iter()
            .map(|air| Point::new(vec![E::ZERO; air.log_height()]))
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
                let points: Vec<_> = shape
                    .air_indices
                    .iter()
                    .map(|&index| points[index].clone())
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
        staged.observe_slice(&self.input.outer_seed);
        if let Some((_, _, _, _, _, cap)) = &preprocessing {
            staged.observe(cap.clone());
        }
        layout::observe_commitment::<F, _, _>(&mut staged, proof.commitment.clone());
        for values in public {
            staged.observe_slice(values);
        }
        let bus_reduction = if let (Some(verifier), Some(proof)) = (&self.bus, &proof.bus) {
            Some(verifier.import_native(proof, &mut staged)?)
        } else {
            None
        };
        staged.observe_slice(&self.input.zerocheck_seed);
        let _alpha = staged.sample_algebra_element::<E>();
        let _beta = staged.sample_algebra_element::<E>();
        if let Some((_, values)) = &bus_reduction {
            let lambda = staged.sample_algebra_element::<E>();
            let expected = lambda * ((values[0] + E::ONE) + lambda * (values[1] + E::ONE));
            if proof.sumcheck.claimed_sum != expected {
                return Err(invalid("binary MultiStark bus initial sum mismatch"));
            }
        }
        let _ = self.tau.sample_native::<F, _>(&mut staged)?;
        let (sumcheck, point, _) = self
            .sumcheck
            .import_native_with_reduction(&proof.sumcheck, &mut staged)?;
        let points: Vec<_> = self
            .input
            .airs
            .iter()
            .map(|air| {
                Point::new(point.as_slice()[point.num_variables() - air.log_height()..].to_vec())
            })
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
            .map(|(verifier, shape, base, round, proof, cap)| {
                let points: Vec<_> = shape
                    .air_indices
                    .iter()
                    .map(|&index| points[index].clone())
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
            opening,
            preprocessed_opening,
        })
    }
}

fn invalid(message: &'static str) -> VerificationError {
    VerificationError::InvalidProofShape(message.into())
}
