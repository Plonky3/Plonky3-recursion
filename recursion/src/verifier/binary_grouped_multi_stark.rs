//! Native binary MultiStark verification with complete grouped-codeword authentication.

use alloc::vec::Vec;
use core::cell::RefCell;
use core::hash::Hash;

use p3_air::Air;
use p3_binary_field::BinaryField128;
use p3_binary_pcs::{BinaryPcsConfig, BinaryPcsProof, GroupedCodewordMmcs};
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
    BinaryCodewordGrouping, BinaryGenericSumcheckProofTargets, BinaryGroupedPcsInputShape,
    BinaryGroupedPcsProofTargets, BinaryGroupedPcsVerifier, NativeBinaryGenericSumcheckInput,
    NativeBinaryGroupedPcsInput, RecursiveBinaryChallengeField, RecursiveBinaryTowerField,
};
use crate::{BinaryQueryContinuation, BinaryTower128Challenger};

/// Proof-independent input shape including the trusted AIR program.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BinaryGroupedMultiStarkInputShape<F = BinaryField128, E = BinaryField128> {
    relation: alloc::sync::Arc<BinaryMultiStarkRelationShape<F, E>>,
    opening: BinaryGroupedPcsInputShape,
    preprocessed: Option<PreprocessedInputShape>,
    cap_height: usize,
}

/// Trusted preprocessing authority, supplied independently of every proof.
/// The commitment must belong to the ordered nonempty preprocessing tables
/// at the fixed AIR heights. Its PCS geometry may differ from the main trace.
#[derive(Clone, Debug)]
pub struct BinaryGroupedMultiStarkPreprocessing<F = BinaryField128> {
    pub config: BinaryPcsConfig,
    pub hash: ByteHash,
    pub cap_height: usize,
    pub max_query_draws: usize,
    pub base_grouping: BinaryCodewordGrouping,
    pub round_grouping: BinaryCodewordGrouping,
    pub commitment: MerkleCap<F, [u8; 32]>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct PreprocessedInputShape {
    opening: BinaryGroupedPcsInputShape,
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
pub struct BinaryGroupedMultiStarkProofTargets {
    pub commitment: Vec<Vec<ExprId>>,
    pub bus: Option<BinaryProductGkrProofTargets>,
    pub sumcheck: BinaryGenericSumcheckProofTargets,
    pub indexed: Option<BinaryIndexedLookupProofTargets>,
    pub opening: BinaryGroupedPcsProofTargets,
    pub preprocessed_opening: Option<BinaryGroupedPcsProofTargets>,
}

impl<F: RecursiveBinaryTowerField, E: RecursiveBinaryChallengeField>
    BinaryGroupedMultiStarkInputShape<F, E>
{
    pub(crate) fn native_decode_shape(
        &self,
    ) -> crate::artifact::binary_native::codec::MultiDecode<
        crate::artifact::binary_native::codec::PcsDecode<
            crate::artifact::binary_native::codec::GroupedOracleDecode,
        >,
    >
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
        self.relation.write_identity(w)?;
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
    ) -> Result<BinaryGroupedMultiStarkProofTargets, VerificationError>
    where
        BF: PrimeField64,
        EF: ExtensionField<BF> + Eq + Hash,
    {
        let commitment = (0..1usize << self.cap_height)
            .map(|_| {
                b.alloc_private_input_array::<16>("binary grouped MultiStark commitment")
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
        Ok(BinaryGroupedMultiStarkProofTargets {
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
pub struct NativeBinaryGroupedMultiStarkInput<F = BinaryField128, E = BinaryField128> {
    shape: BinaryGroupedMultiStarkInputShape<F, E>,
    commitment: Vec<[u8; 32]>,
    bus: Option<NativeBinaryProductGkrInput<F, E>>,
    sumcheck: NativeBinaryGenericSumcheckInput<F, E>,
    indexed: Option<NativeIndexedInput<F, E>>,
    opening: NativeBinaryGroupedPcsInput,
    preprocessed_opening: Option<NativeBinaryGroupedPcsInput>,
}

impl<F: RecursiveBinaryTowerField, E: RecursiveBinaryChallengeField>
    NativeBinaryGroupedMultiStarkInput<F, E>
{
    pub const fn shape(&self) -> &BinaryGroupedMultiStarkInputShape<F, E> {
        &self.shape
    }

    pub fn private_values<EF: Field>(
        &self,
        expected: &BinaryGroupedMultiStarkInputShape<F, E>,
    ) -> Result<Vec<EF>, VerificationError> {
        if &self.shape != expected {
            return Err(invalid(
                "binary grouped MultiStark input belongs to another verifier",
            ));
        }
        let mut values: Vec<EF> = self
            .commitment
            .iter()
            .flat_map(|root| bytes_to_limbs(root).into_iter().map(EF::from_u16))
            .collect();
        match (&expected.relation.bus, &self.bus) {
            (Some(shape), Some(input)) => {
                values.extend(input.private_values::<EF>(&shape.product)?);
            }
            (None, None) => {}
            _ => {
                return Err(invalid(
                    "binary grouped MultiStark bus input shape mismatch",
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
                    "binary grouped MultiStark indexed input shape mismatch",
                ));
            }
        }
        values.extend(self.opening.private_values::<EF>(&expected.opening)?);
        match (&expected.preprocessed, &self.preprocessed_opening) {
            (Some(shape), Some(input)) => {
                values.extend(input.private_values::<EF>(&shape.opening)?);
            }
            (None, None) => {}
            _ => {
                return Err(invalid(
                    "binary grouped MultiStark preprocessing input shape mismatch",
                ));
            }
        }
        Ok(values)
    }
}

/// Trusted binary grouped MultiStark verifier with grouped codeword MMCS.
/// Binds caller-owned public values through the complete AIR, sumcheck, and
/// authenticated PCS relation. Periodic constants and preprocessing authority
/// are fixed by construction. Native binary buses are reduced through the
/// authenticated AIR sumcheck. Indexed reads are reduced by LogUpStar and
/// authenticated at their own PCS points. Classical lookups remain unsupported.
#[derive(Clone, Debug)]
pub struct BinaryGroupedMultiStarkVerifier<F = BinaryField128, E = BinaryField128> {
    input: BinaryGroupedMultiStarkInputShape<F, E>,
    relation: BinaryMultiStarkRelation<F, E>,
    opening: BinaryGroupedPcsVerifier<F, E>,
    preprocessed: Option<BinaryGroupedPcsVerifier<F, E>>,
    usage: InputResourceUsage,
}

impl<F, E> BinaryGroupedMultiStarkVerifier<F, E>
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
        base_grouping: BinaryCodewordGrouping,
        round_grouping: BinaryCodewordGrouping,
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
        preprocessing: BinaryGroupedMultiStarkPreprocessing<F>,
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
        preprocessing: Option<BinaryGroupedMultiStarkPreprocessing<F>>,
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
        let opening = BinaryGroupedPcsVerifier::<F, E>::with_limits(
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
        opening_usage.instances = 0;
        usage.merge(limits, opening_usage)?;
        let (preprocessed, preprocessed_input) = if let Some(preprocessing) = preprocessing {
            let verifier = BinaryGroupedPcsVerifier::<F, E>::with_limits(
                preprocessing.config,
                preprocessed_protocol.expect("checked preprocessing protocol"),
                preprocessing.hash,
                preprocessing.cap_height,
                preprocessing.max_query_draws,
                preprocessing.base_grouping,
                preprocessing.round_grouping,
                limits,
            )?;
            if preprocessing.commitment.num_roots() != 1usize << preprocessing.cap_height {
                return Err(invalid(
                    "binary grouped MultiStark trusted preprocessing cap shape mismatch",
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
        let input = BinaryGroupedMultiStarkInputShape {
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

    pub fn input_shape(&self) -> BinaryGroupedMultiStarkInputShape<F, E> {
        self.input.clone()
    }
    pub const fn input_resource_usage(&self) -> InputResourceUsage {
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
        proof: &BinaryGroupedMultiStarkProofTargets,
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
                let points = self.relation.zero_points(true, zero);
                verifier.check_targets(&cap, &points, proof)?;
                Some(cap)
            }
            (None, None, None) => None,
            _ => {
                return Err(invalid(
                    "binary grouped MultiStark preprocessed opening shape mismatch",
                ));
            }
        };
        self.relation
            .observe_prefix::<BF, EF>(b, &mut ch, preprocessed_cap.as_deref())?;
        self.opening
            .observe_commitment::<BF, EF>(b, &mut ch, &proof.commitment)?;
        let reduction = self.relation.reduce::<BF, EF>(b, ch, public, &common)?;
        let mut continuation = self.opening.verify_at_with_continuation::<BF, EF>(
            b,
            reduction.challenger.clone(),
            &proof.commitment,
            &reduction.main_points,
            &proof.opening,
        )?;
        if let (Some(verifier), Some(cap), Some(proof)) = (
            &self.preprocessed,
            &preprocessed_cap,
            &proof.preprocessed_opening,
        ) {
            continuation = verifier.verify_at_after_queries::<BF, EF>(
                b,
                continuation,
                cap,
                reduction
                    .preprocessed_points
                    .as_ref()
                    .expect("checked preprocessing points"),
                proof,
            )?;
        }
        self.relation.finish(
            b,
            public,
            &common,
            &reduction,
            &proof.opening.opening.evals,
            proof
                .preprocessed_opening
                .as_ref()
                .map(|p| p.opening.evals.as_slice()),
        )?;
        Ok(continuation)
    }

    /// Imports grouped-byte-tree native proofs with finite transcript replay.
    /// Every visible shape is checked before sampling. Failure leaves the
    /// caller's challenger unchanged; success retains exact native completion.
    pub fn import_native<C, H0, C0, H1, C1, Ch>(
        &self,
        base_mmcs: &MerkleTreeMmcs<F, u8, H0, C0, 2, 32>,
        round_mmcs: &MerkleTreeMmcs<E, u8, H1, C1, 2, 32>,
        public: &[Vec<F>],
        proof: &MultiStarkProof<C>,
        ch: &mut Ch,
    ) -> Result<NativeBinaryGroupedMultiStarkInput<F, E>, VerificationError>
    where
        C: MultiStarkConfig<Val = F, Challenge = E>,
        C::Pcs: MultilinearPcs<
                E,
                C::Challenger,
                Commitment = MerkleCap<F, [u8; 32]>,
                Proof = BinaryPcsProof<
                    F,
                    E,
                    GroupedCodewordMmcs<MerkleTreeMmcs<F, u8, H0, C0, 2, 32>>,
                    GroupedCodewordMmcs<MerkleTreeMmcs<E, u8, H1, C1, 2, 32>>,
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
    ) -> Result<NativeBinaryGroupedMultiStarkInput<F, E>, VerificationError>
    where
        C: MultiStarkConfig<Val = F, Challenge = E>,
        C::Pcs: MultilinearPcs<
                E,
                C::Challenger,
                Commitment = MerkleCap<F, [u8; 32]>,
                Proof = BinaryPcsProof<
                    F,
                    E,
                    GroupedCodewordMmcs<MerkleTreeMmcs<F, u8, H0, C0, 2, 32>>,
                    GroupedCodewordMmcs<MerkleTreeMmcs<E, u8, H1, C1, 2, 32>>,
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
        self.relation.check_native(public, proof)?;
        let points: Vec<_> = self
            .relation
            .zero_points(false, E::ZERO)
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
                    .zero_points(true, E::ZERO)
                    .into_iter()
                    .map(Point::new)
                    .collect();
                verifier.check_native(base, round, &cap, &points, proof)?;
                Some((verifier, shape, base, round, proof, cap))
            }
            (None, None, None, None) => None,
            _ => {
                return Err(invalid(
                    "binary grouped MultiStark native preprocessed opening shape mismatch",
                ));
            }
        };
        let mut staged = ch.clone();
        self.relation.observe_native_prefix(
            &mut staged,
            preprocessing.as_ref().map(|(_, _, _, _, _, cap)| cap),
        );
        layout::observe_commitment::<F, _, _>(&mut staged, proof.commitment.clone());
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
        Ok(NativeBinaryGroupedMultiStarkInput {
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
