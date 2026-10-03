//! Native binary MultiStark verification through grouped Boolean trace openings.

use alloc::vec::Vec;
use core::cell::RefCell;
use core::hash::Hash;
use p3_air::Air;
use p3_binary_field::BinaryField128;
use p3_binary_pcs::{BinaryPcsConfig, BooleanTraceProof, GroupedCodewordMmcs};
use p3_bus::BusSymbolicBuilder;
use p3_challenger::{CanObserve, CanSampleUniformBits, FieldChallenger, GrindingChallenger};
use p3_circuit::ops::{BinaryTower128Target, ByteHash, bytes_to_limbs};
use p3_circuit::{CircuitBuilder, ExprId};
use p3_commit::MultilinearPcs;
use p3_field::{ExtensionField, Field, PackedValue, PrimeField64};
use p3_lookup::InteractionSymbolicBuilder;
use p3_merkle_tree::{MerkleCap, MerkleTreeMmcs};
use p3_multi_stark::MultiStarkProof;
use p3_multi_stark::config::MultiStarkConfig;
use p3_multilinear_util::point::Point;
use p3_sumcheck::layout;
use p3_symmetric::{CryptographicHasher, PseudoCompressionFunction};

use super::binary_indexed::{BinaryIndexedLookupProofTargets, NativeIndexedInput};
use super::binary_multi_stark::relation::{
    BinaryMultiStarkRelation, BinaryMultiStarkRelationShape, BinaryRelationProof,
};
use super::{
    BinaryAirConstraintPlan, BinaryProductGkrProofTargets, InputResourceUsage,
    NativeBinaryProductGkrInput, VerificationError, VerifierLimits,
};
use crate::pcs::binary::{
    BinaryCodewordGrouping, BinaryGenericSumcheckProofTargets, BinaryGroupedBooleanTraceInputShape,
    BinaryGroupedBooleanTraceProofTargets, BinaryGroupedBooleanTraceVerifier,
    NativeBinaryGenericSumcheckInput, NativeBinaryGroupedBooleanTraceInput,
    RecursiveBinaryChallengeField,
};
use crate::{BinaryQueryContinuation, BinaryTower128Challenger};

/// Proof-independent input shape including the trusted AIR program.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BinaryGroupedBooleanTraceMultiStarkInputShape<E = BinaryField128> {
    relation: alloc::sync::Arc<BinaryMultiStarkRelationShape<E, E>>,
    opening: BinaryGroupedBooleanTraceInputShape<E>,
    preprocessed: Option<PreprocessedInputShape<E>>,
    cap_height: usize,
}

/// Trusted preprocessing authority, supplied independently of every proof.
/// The commitment must belong to the ordered nonempty preprocessing tables
/// at the fixed AIR heights. Its PCS geometry may differ from the main trace.
#[derive(Clone, Debug)]
pub struct BinaryGroupedBooleanTraceMultiStarkPreprocessing<E = BinaryField128> {
    pub config: BinaryPcsConfig,
    pub hash: ByteHash,
    pub cap_height: usize,
    pub max_query_draws: usize,
    pub base_grouping: BinaryCodewordGrouping,
    pub round_grouping: BinaryCodewordGrouping,
    pub commitment: MerkleCap<E, [u8; 32]>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct PreprocessedInputShape<E> {
    opening: BinaryGroupedBooleanTraceInputShape<E>,
    commitment: Vec<[u8; 32]>,
}

impl<E> PreprocessedInputShape<E> {
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
pub struct BinaryGroupedBooleanTraceMultiStarkProofTargets<E = BinaryField128> {
    pub commitment: Vec<Vec<ExprId>>,
    pub bus: Option<BinaryProductGkrProofTargets>,
    pub sumcheck: BinaryGenericSumcheckProofTargets,
    pub indexed: Option<BinaryIndexedLookupProofTargets>,
    pub opening: BinaryGroupedBooleanTraceProofTargets<E>,
    pub preprocessed_opening: Option<BinaryGroupedBooleanTraceProofTargets<E>>,
}

impl<E: RecursiveBinaryChallengeField + ExtensionField<E>>
    BinaryGroupedBooleanTraceMultiStarkInputShape<E>
{
    /// Trusted public-value counts in the original AIR instance order.
    pub fn public_value_counts(&self) -> impl ExactSizeIterator<Item = usize> + '_
    where
        E: ExtensionField<E>,
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
    ) -> Result<BinaryGroupedBooleanTraceMultiStarkProofTargets<E>, VerificationError>
    where
        BF: PrimeField64,
        EF: ExtensionField<BF> + Eq + Hash,
    {
        let commitment = (0..1usize << self.cap_height)
            .map(|_| {
                b.alloc_private_input_array::<16>(
                    "binary grouped Boolean trace MultiStark commitment",
                )
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
        Ok(BinaryGroupedBooleanTraceMultiStarkProofTargets {
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
pub struct NativeBinaryGroupedBooleanTraceMultiStarkInput<E = BinaryField128> {
    shape: BinaryGroupedBooleanTraceMultiStarkInputShape<E>,
    commitment: Vec<[u8; 32]>,
    bus: Option<NativeBinaryProductGkrInput<E, E>>,
    sumcheck: NativeBinaryGenericSumcheckInput<E, E>,
    indexed: Option<NativeIndexedInput<E, E>>,
    opening: NativeBinaryGroupedBooleanTraceInput<E>,
    preprocessed_opening: Option<NativeBinaryGroupedBooleanTraceInput<E>>,
}

impl<E: RecursiveBinaryChallengeField + ExtensionField<E>>
    NativeBinaryGroupedBooleanTraceMultiStarkInput<E>
{
    pub fn shape(&self) -> &BinaryGroupedBooleanTraceMultiStarkInputShape<E> {
        &self.shape
    }

    pub fn private_values<EF: Field>(
        &self,
        expected: &BinaryGroupedBooleanTraceMultiStarkInputShape<E>,
    ) -> Result<Vec<EF>, VerificationError> {
        if &self.shape != expected {
            return Err(invalid(
                "binary grouped Boolean trace MultiStark input belongs to another verifier",
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
            _ => {
                return Err(invalid(
                    "binary grouped Boolean trace MultiStark bus input shape mismatch",
                ));
            }
        }
        values.extend(
            self.sumcheck
                .private_values::<EF>(&expected.relation.sumcheck)?,
        );
        match (&expected.relation.indexed, &self.indexed) {
            (Some(shape), Some(input)) => values.extend(input.private_values::<EF>(shape)?),
            (None, None) => {}
            _ => {
                return Err(invalid(
                    "binary grouped Boolean trace MultiStark indexed input shape mismatch",
                ));
            }
        }
        values.extend(self.opening.private_values::<EF>(&expected.opening)?);
        match (&expected.preprocessed, &self.preprocessed_opening) {
            (Some(shape), Some(input)) => {
                values.extend(input.private_values::<EF>(&shape.opening)?)
            }
            (None, None) => {}
            _ => {
                return Err(invalid(
                    "binary grouped Boolean trace MultiStark preprocessing input shape mismatch",
                ));
            }
        }
        Ok(values)
    }
}

/// Trusted binary grouped Boolean trace MultiStark verifier with grouped codeword MMCS.
/// Binds caller-owned public values through the complete AIR, sumcheck, and
/// authenticated PCS relation. Periodic constants and preprocessing authority
/// are fixed by construction. Native binary buses are reduced through the
/// authenticated AIR sumcheck. Indexed reads are reduced by LogUpStar and
/// authenticated at their own PCS points. Classical lookups remain unsupported.
#[derive(Clone, Debug)]
pub struct BinaryGroupedBooleanTraceMultiStarkVerifier<E = BinaryField128> {
    input: BinaryGroupedBooleanTraceMultiStarkInputShape<E>,
    relation: BinaryMultiStarkRelation<E, E>,
    opening: BinaryGroupedBooleanTraceVerifier<E>,
    preprocessed: Option<BinaryGroupedBooleanTraceVerifier<E>>,
    usage: InputResourceUsage,
}

impl<E> BinaryGroupedBooleanTraceMultiStarkVerifier<E>
where
    E: RecursiveBinaryChallengeField
        + ExtensionField<E>
        + p3_binary_pcs::ChallengeField<E>
        + p3_binary_pcs::FoldAlphabet<E>
        + p3_binary_pcs::Coordinates
        + serde::Serialize
        + serde::de::DeserializeOwned,
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
        base_grouping: BinaryCodewordGrouping,
        round_grouping: BinaryCodewordGrouping,
    ) -> Result<Self, VerificationError>
    where
        A: Air<InteractionSymbolicBuilder<E, E>> + Air<BusSymbolicBuilder<E, E>>,
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
            base_grouping,
            round_grouping,
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
        base_grouping: BinaryCodewordGrouping,
        round_grouping: BinaryCodewordGrouping,
        limits: &VerifierLimits,
    ) -> Result<Self, VerificationError>
    where
        A: Air<InteractionSymbolicBuilder<E, E>> + Air<BusSymbolicBuilder<E, E>>,
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
            base_grouping,
            round_grouping,
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
        base_grouping: BinaryCodewordGrouping,
        round_grouping: BinaryCodewordGrouping,
        preprocessing: BinaryGroupedBooleanTraceMultiStarkPreprocessing<E>,
        limits: &VerifierLimits,
    ) -> Result<Self, VerificationError>
    where
        A: Air<InteractionSymbolicBuilder<E, E>> + Air<BusSymbolicBuilder<E, E>>,
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
            base_grouping,
            round_grouping,
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
        base_grouping: BinaryCodewordGrouping,
        round_grouping: BinaryCodewordGrouping,
        preprocessing: Option<BinaryGroupedBooleanTraceMultiStarkPreprocessing<E>>,
        limits: &VerifierLimits,
    ) -> Result<Self, VerificationError>
    where
        A: Air<InteractionSymbolicBuilder<E, E>> + Air<BusSymbolicBuilder<E, E>>,
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
        let main_table_count = main_protocol.table_shapes().len();
        let opening = BinaryGroupedBooleanTraceVerifier::<E>::with_limits(
            config,
            main_protocol,
            hash,
            cap_height,
            max_query_draws,
            base_grouping,
            round_grouping,
            limits,
        )?;
        let mut opening_usage = opening.input_resource_usage();
        // The relation already counts the logical AIR tables. Ring claims and
        // the internal packed PCS instance remain additional verifier work.
        opening_usage.instances = opening_usage
            .instances
            .checked_sub(main_table_count)
            .ok_or(VerificationError::ResourceArithmeticOverflow {
                component: "binary Boolean trace instance accounting",
            })?;
        usage.merge(limits, opening_usage)?;
        let (preprocessed, preprocessed_input) = if let Some(preprocessing) = preprocessing {
            let protocol = preprocessed_protocol.expect("checked preprocessing protocol");
            let table_count = protocol.table_shapes().len();
            let verifier = BinaryGroupedBooleanTraceVerifier::<E>::with_limits(
                preprocessing.config,
                protocol,
                preprocessing.hash,
                preprocessing.cap_height,
                preprocessing.max_query_draws,
                preprocessing.base_grouping,
                preprocessing.round_grouping,
                limits,
            )?;
            if preprocessing.commitment.num_roots() != 1usize << preprocessing.cap_height {
                return Err(invalid(
                    "binary grouped Boolean trace MultiStark trusted preprocessing cap shape mismatch",
                ));
            }
            let mut preprocessed_usage = verifier.input_resource_usage();
            preprocessed_usage.instances = preprocessed_usage
                .instances
                .checked_sub(table_count)
                .ok_or(VerificationError::ResourceArithmeticOverflow {
                    component: "binary Boolean trace instance accounting",
                })?;
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
        let input = BinaryGroupedBooleanTraceMultiStarkInputShape {
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

    pub fn input_shape(&self) -> BinaryGroupedBooleanTraceMultiStarkInputShape<E> {
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
        proof: &BinaryGroupedBooleanTraceMultiStarkProofTargets<E>,
    ) -> Result<BinaryQueryContinuation, VerificationError>
    where
        BF: PrimeField64,
        EF: ExtensionField<BF> + Eq + Hash,
    {
        let common = BinaryRelationProof {
            bus: proof.bus.as_ref(),
            sumcheck: &proof.sumcheck,
            indexed: proof.indexed.as_ref(),
        };
        self.relation.check_targets(public, &common)?;
        let zero = b.binary128_constant(0)?;
        let points = self.relation.zero_points(false, zero.clone());
        self.opening
            .check_targets(&proof.commitment, &points, &proof.opening)?;
        let preprocessed_cap = match (
            &self.preprocessed,
            &self.input.preprocessed,
            &proof.preprocessed_opening,
        ) {
            (Some(verifier), Some(shape), Some(proof)) => {
                let cap = shape.constant_cap(b);
                let points = self.relation.zero_points(true, zero.clone());
                verifier.check_targets(&cap, &points, proof)?;
                Some(cap)
            }
            (None, None, None) => None,
            _ => {
                return Err(invalid(
                    "binary grouped Boolean trace MultiStark preprocessed opening shape mismatch",
                ));
            }
        };
        self.relation
            .observe_prefix::<BF, EF>(b, &mut ch, preprocessed_cap.as_deref())?;
        self.opening
            .observe_commitment::<BF, EF>(b, &mut ch, &proof.commitment)?;
        let reduction = self.relation.reduce::<BF, EF>(b, ch, public, &common)?;
        let (main_evals, mut continuation) = self.opening.verify_at_with_continuation::<BF, EF>(
            b,
            reduction.challenger.clone(),
            &proof.commitment,
            &reduction.main_points,
            &proof.opening,
        )?;
        let mut preprocessed_evals = None;
        if let (Some(verifier), Some(cap), Some(proof)) = (
            &self.preprocessed,
            &preprocessed_cap,
            &proof.preprocessed_opening,
        ) {
            let (evals, next) = verifier.verify_at_after_queries::<BF, EF>(
                b,
                continuation,
                cap,
                reduction
                    .preprocessed_points
                    .as_ref()
                    .expect("checked preprocessing points"),
                proof,
            )?;
            preprocessed_evals = Some(evals);
            continuation = next;
        }
        self.relation.finish(
            b,
            public,
            &common,
            &reduction,
            &main_evals,
            preprocessed_evals.as_deref(),
        )?;
        Ok(continuation)
    }

    /// Imports grouped-byte-tree native proofs with finite transcript replay.
    /// Every visible shape is checked before sampling. Failure leaves the
    /// caller's challenger unchanged; success retains exact native completion.
    pub fn import_native<C, H0, C0, H1, C1, Ch>(
        &self,
        base_mmcs: &MerkleTreeMmcs<E, u8, H0, C0, 2, 32>,
        round_mmcs: &MerkleTreeMmcs<E, u8, H1, C1, 2, 32>,
        public: &[Vec<E>],
        proof: &MultiStarkProof<C>,
        ch: &mut Ch,
    ) -> Result<NativeBinaryGroupedBooleanTraceMultiStarkInput<E>, VerificationError>
    where
        C: MultiStarkConfig<Val = E, Challenge = E>,
        C::Pcs: MultilinearPcs<
                E,
                C::Challenger,
                Commitment = MerkleCap<E, [u8; 32]>,
                Proof = BooleanTraceProof<
                    E,
                    GroupedCodewordMmcs<MerkleTreeMmcs<E, u8, H0, C0, 2, 32>>,
                    GroupedCodewordMmcs<MerkleTreeMmcs<E, u8, H1, C1, 2, 32>>,
                >,
            >,
        E: PackedValue<Value = E>,
        H0: CryptographicHasher<E, [u8; 32]> + Sync,
        H1: CryptographicHasher<E, [u8; 32]> + Sync,
        C0: PseudoCompressionFunction<[u8; 32], 2> + Sync,
        C1: PseudoCompressionFunction<[u8; 32], 2> + Sync,
        Ch: FieldChallenger<E>
            + CanSampleUniformBits<E>
            + GrindingChallenger<Witness = E>
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
        base_mmcs: &MerkleTreeMmcs<E, u8, H0, C0, 2, 32>,
        round_mmcs: &MerkleTreeMmcs<E, u8, H1, C1, 2, 32>,
        preprocessed_mmcs: Option<(
            &MerkleTreeMmcs<E, u8, H0, C0, 2, 32>,
            &MerkleTreeMmcs<E, u8, H1, C1, 2, 32>,
        )>,
        public: &[Vec<E>],
        proof: &MultiStarkProof<C>,
        ch: &mut Ch,
    ) -> Result<NativeBinaryGroupedBooleanTraceMultiStarkInput<E>, VerificationError>
    where
        C: MultiStarkConfig<Val = E, Challenge = E>,
        C::Pcs: MultilinearPcs<
                E,
                C::Challenger,
                Commitment = MerkleCap<E, [u8; 32]>,
                Proof = BooleanTraceProof<
                    E,
                    GroupedCodewordMmcs<MerkleTreeMmcs<E, u8, H0, C0, 2, 32>>,
                    GroupedCodewordMmcs<MerkleTreeMmcs<E, u8, H1, C1, 2, 32>>,
                >,
            >,
        E: PackedValue<Value = E>,
        H0: CryptographicHasher<E, [u8; 32]> + Sync,
        H1: CryptographicHasher<E, [u8; 32]> + Sync,
        C0: PseudoCompressionFunction<[u8; 32], 2> + Sync,
        C1: PseudoCompressionFunction<[u8; 32], 2> + Sync,
        Ch: FieldChallenger<E>
            + CanSampleUniformBits<E>
            + GrindingChallenger<Witness = E>
            + CanObserve<MerkleCap<E, [u8; 32]>>
            + Clone,
    {
        self.relation.check_native(public, proof)?;
        let points: Vec<_> = self
            .relation
            .zero_points(false, E::ZERO)
            .into_iter()
            .map(Point::new)
            .collect();
        self.opening.check_native_structure(
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
                let cap = MerkleCap::<E, _>::new(shape.commitment.clone());
                let points: Vec<_> = self
                    .relation
                    .zero_points(true, E::ZERO)
                    .into_iter()
                    .map(Point::new)
                    .collect();
                verifier.check_native_structure(base, round, &cap, &points, proof)?;
                Some((verifier, shape, base, round, proof, cap))
            }
            (None, None, None, None) => None,
            _ => {
                return Err(invalid(
                    "binary grouped Boolean trace MultiStark native preprocessed opening shape mismatch",
                ));
            }
        };
        let mut staged = ch.clone();
        self.relation.observe_native_prefix(
            &mut staged,
            preprocessing.as_ref().map(|(_, _, _, _, _, cap)| cap),
        );
        layout::observe_commitment::<E, _, _>(&mut staged, proof.commitment.clone());
        let reduction = self.relation.reduce_native(public, proof, &mut staged)?;
        let frontier_usage = RefCell::new(InputResourceUsage::default());
        let opening = self.opening.import_native_with_usage(
            base_mmcs,
            round_mmcs,
            &proof.commitment,
            &reduction.main_points,
            &proof.opening,
            &mut staged,
            &frontier_usage,
        )?;
        let preprocessed_opening = preprocessing
            .map(|(verifier, _shape, base, round, proof, cap)| {
                let points = reduction
                    .preprocessed_points
                    .as_ref()
                    .expect("checked preprocessing points");
                verifier.import_native_with_usage(
                    base,
                    round,
                    &cap,
                    points,
                    proof,
                    &mut staged,
                    &frontier_usage,
                )
            })
            .transpose()?;
        *ch = staged;
        Ok(NativeBinaryGroupedBooleanTraceMultiStarkInput {
            shape: self.input.clone(),
            commitment: proof.commitment.roots().to_vec(),
            bus: reduction.bus,
            sumcheck: reduction.sumcheck,
            indexed: reduction.indexed,
            opening,
            preprocessed_opening,
        })
    }
}

fn invalid(message: &'static str) -> VerificationError {
    VerificationError::InvalidProofShape(message.into())
}
