//! Complete released tower WHIR MultiStark relations in prime-field circuits.
use super::binary_indexed::{BinaryIndexedLookupProofTargets, NativeIndexedInput};
use super::binary_multi_stark::relation::{
    BinaryMultiStarkRelation, BinaryMultiStarkRelationShape, BinaryRelationProof,
};
use super::{
    BinaryAirConstraintPlan, BinaryProductGkrProofTargets, InputResourceUsage,
    NativeBinaryProductGkrInput, VerificationError, VerifierLimits,
};
use crate::BinaryTower128Challenger;
use crate::pcs::binary::{
    BinaryGenericSumcheckProofTargets, BinaryWhirInputShape, BinaryWhirProofTargets,
    BinaryWhirVerifier, NativeBinaryGenericSumcheckInput, NativeBinaryWhirInput,
    RecursiveBinaryWhirTowerField,
};
use alloc::vec::Vec;
use core::hash::Hash;
use p3_air::Air;
use p3_binary_field::BinaryField128;
use p3_bus::BusSymbolicBuilder;
use p3_challenger::{CanObserve, CanSampleUniformBits, FieldChallenger, GrindingChallenger};
use p3_circuit::ops::{BinaryTower128Target, ByteHash, bytes_to_limbs};
use p3_circuit::{CircuitBuilder, ExprId};
use p3_commit::MultilinearPcs;
use p3_field::{ExtensionField, Field, PackedValue, PrimeCharacteristicRing, PrimeField64};
use p3_lookup::InteractionSymbolicBuilder;
use p3_merkle_tree::{MerkleCap, MerkleTreeMmcs};
use p3_multi_stark::MultiStarkProof;
use p3_multi_stark::config::MultiStarkConfig;
use p3_multilinear_util::point::Point;
use p3_sumcheck::layout;
use p3_sumcheck::strategy::VariableOrder;
use p3_symmetric::{CryptographicHasher, PseudoCompressionFunction};
use p3_whir::WhirConfig;
use p3_whir::pcs::proof::PcsProof as WhirPcsProof;
/// Proof-independent input shape including the trusted AIR program.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BinaryWhirMultiStarkInputShape<F = BinaryField128> {
    relation: alloc::sync::Arc<BinaryMultiStarkRelationShape<F, BinaryField128>>,
    opening: BinaryWhirInputShape<F>,
    preprocessed: Option<WhirPreprocessedInputShape<F>>,
    cap_height: usize,
}

/// Trusted preprocessing authority, supplied independently of every proof.
/// The commitment must belong to the ordered nonempty preprocessing tables
/// at the fixed AIR heights. Its PCS geometry may differ from the main trace.
#[derive(Clone, Debug)]
pub struct BinaryWhirMultiStarkPreprocessing<F: Field, PC>
where
    BinaryField128: ExtensionField<F>,
{
    pub config: WhirConfig<BinaryField128, F, PC>,
    pub order: VariableOrder,
    pub hash: ByteHash,
    pub cap_height: usize,
    pub commitment: MerkleCap<F, [u8; 32]>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct WhirPreprocessedInputShape<F> {
    opening: BinaryWhirInputShape<F>,
    commitment: Vec<[u8; 32]>,
}

impl<F> WhirPreprocessedInputShape<F> {
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
pub struct BinaryWhirMultiStarkProofTargets {
    pub commitment: Vec<Vec<ExprId>>,
    pub bus: Option<BinaryProductGkrProofTargets>,
    pub sumcheck: BinaryGenericSumcheckProofTargets,
    pub indexed: Option<BinaryIndexedLookupProofTargets>,
    pub opening: BinaryWhirProofTargets,
    pub preprocessed_opening: Option<BinaryWhirProofTargets>,
}

impl<F: RecursiveBinaryWhirTowerField> BinaryWhirMultiStarkInputShape<F> {
    pub(crate) fn native_decode_shape(
        &self,
    ) -> crate::artifact::binary_native::codec::MultiDecode<
        crate::artifact::binary_native::codec::WhirDecode,
    >
    where
        BinaryField128: ExtensionField<F>,
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
        BinaryField128: ExtensionField<F>,
    {
        self.relation.write_identity(w)?;
        self.opening.write_identity(w)?;
        w.write_u8(u8::from(self.preprocessed.is_some()))?;
        if let Some(pp) = &self.preprocessed {
            pp.opening.write_identity(w)?;
            w.write_vec(
                "binary native WHIR preprocessing cap",
                &pp.commitment,
                |w, root| w.write_bytes(root),
            )?;
        }
        Ok(())
    }

    /// Trusted public-value counts in the original AIR instance order.
    pub fn public_value_counts(&self) -> impl ExactSizeIterator<Item = usize> + '_
    where
        BinaryField128: ExtensionField<F>,
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
    ) -> Result<BinaryWhirMultiStarkProofTargets, VerificationError>
    where
        BF: PrimeField64,
        EF: ExtensionField<BF> + Eq + Hash,
    {
        let commitment = (0..1usize << self.cap_height)
            .map(|_| {
                b.alloc_private_input_array::<16>("binary WHIR MultiStark commitment")
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
        Ok(BinaryWhirMultiStarkProofTargets {
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
pub struct NativeBinaryWhirMultiStarkInput<F = BinaryField128> {
    shape: BinaryWhirMultiStarkInputShape<F>,
    commitment: Vec<[u8; 32]>,
    bus: Option<NativeBinaryProductGkrInput<F, BinaryField128>>,
    sumcheck: NativeBinaryGenericSumcheckInput<F, BinaryField128>,
    indexed: Option<NativeIndexedInput<F, BinaryField128>>,
    opening: NativeBinaryWhirInput<F>,
    preprocessed_opening: Option<NativeBinaryWhirInput<F>>,
}

impl<F: RecursiveBinaryWhirTowerField> NativeBinaryWhirMultiStarkInput<F> {
    pub fn shape(&self) -> &BinaryWhirMultiStarkInputShape<F> {
        &self.shape
    }

    pub fn private_values<EF: Field>(
        &self,
        expected: &BinaryWhirMultiStarkInputShape<F>,
    ) -> Result<Vec<EF>, VerificationError> {
        if &self.shape != expected {
            return Err(invalid(
                "binary WHIR MultiStark input belongs to another verifier",
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
            _ => return Err(invalid("binary WHIR MultiStark bus input shape mismatch")),
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
                    "binary WHIR MultiStark indexed input shape mismatch",
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
                    "binary WHIR MultiStark preprocessing input shape mismatch",
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
pub struct BinaryWhirMultiStarkVerifier<F = BinaryField128> {
    input: BinaryWhirMultiStarkInputShape<F>,
    relation: BinaryMultiStarkRelation<F, BinaryField128>,
    opening: BinaryWhirVerifier<F>,
    preprocessed: Option<BinaryWhirVerifier<F>>,
    usage: InputResourceUsage,
}

impl<F> BinaryWhirMultiStarkVerifier<F>
where
    F: RecursiveBinaryWhirTowerField,
    BinaryField128: ExtensionField<F>,
{
    /// Installs the exact cap captured from the factory's matched native setup.
    /// Geometry was validated before setup, with a placeholder cap of this size.
    pub(crate) fn bind_native_preprocessing_cap(
        &mut self,
        cap: Vec<[u8; 32]>,
    ) -> Result<(), VerificationError> {
        let Some(pp) = &mut self.input.preprocessed else {
            return Err(invalid(
                "binary native WHIR setup produced an unexpected preprocessing cap",
            ));
        };
        if cap.len() != pp.commitment.len() {
            return Err(invalid(
                "binary native WHIR setup preprocessing cap shape mismatch",
            ));
        }
        pp.commitment = cap;
        Ok(())
    }

    pub fn new<A, PC>(
        airs: &[&A],
        heights: &[usize],
        config: &WhirConfig<BinaryField128, F, PC>,
        order: VariableOrder,
        hash: ByteHash,
        cap_height: usize,
        pow_bits: usize,
        max_tau_draws: usize,
    ) -> Result<Self, VerificationError>
    where
        A: Air<InteractionSymbolicBuilder<F, BinaryField128>>
            + Air<BusSymbolicBuilder<F, BinaryField128>>,
        PC: FieldChallenger<F> + GrindingChallenger<Witness = F>,
    {
        Self::with_limits(
            airs,
            heights,
            config,
            order,
            hash,
            cap_height,
            pow_bits,
            max_tau_draws,
            &VerifierLimits::default(),
        )
    }

    pub fn with_limits<A, PC>(
        airs: &[&A],
        heights: &[usize],
        config: &WhirConfig<BinaryField128, F, PC>,
        order: VariableOrder,
        hash: ByteHash,
        cap_height: usize,
        pow_bits: usize,
        max_tau_draws: usize,
        limits: &VerifierLimits,
    ) -> Result<Self, VerificationError>
    where
        A: Air<InteractionSymbolicBuilder<F, BinaryField128>>
            + Air<BusSymbolicBuilder<F, BinaryField128>>,
        PC: FieldChallenger<F> + GrindingChallenger<Witness = F>,
    {
        Self::build(
            airs,
            heights,
            config,
            order,
            hash,
            cap_height,
            pow_bits,
            max_tau_draws,
            None,
            limits,
        )
    }

    /// Builds a verifier retaining an independent trusted preprocessing cap.
    /// No proof can provide or replace this authority.
    pub fn with_preprocessing<A, PC>(
        airs: &[&A],
        heights: &[usize],
        config: &WhirConfig<BinaryField128, F, PC>,
        order: VariableOrder,
        hash: ByteHash,
        cap_height: usize,
        pow_bits: usize,
        max_tau_draws: usize,
        preprocessing: BinaryWhirMultiStarkPreprocessing<F, PC>,
        limits: &VerifierLimits,
    ) -> Result<Self, VerificationError>
    where
        A: Air<InteractionSymbolicBuilder<F, BinaryField128>>
            + Air<BusSymbolicBuilder<F, BinaryField128>>,
        PC: FieldChallenger<F> + GrindingChallenger<Witness = F>,
    {
        Self::build(
            airs,
            heights,
            config,
            order,
            hash,
            cap_height,
            pow_bits,
            max_tau_draws,
            Some(preprocessing),
            limits,
        )
    }

    fn build<A, PC>(
        airs: &[&A],
        heights: &[usize],
        config: &WhirConfig<BinaryField128, F, PC>,
        order: VariableOrder,
        hash: ByteHash,
        cap_height: usize,
        pow_bits: usize,
        max_tau_draws: usize,
        preprocessing: Option<BinaryWhirMultiStarkPreprocessing<F, PC>>,
        limits: &VerifierLimits,
    ) -> Result<Self, VerificationError>
    where
        A: Air<InteractionSymbolicBuilder<F, BinaryField128>>
            + Air<BusSymbolicBuilder<F, BinaryField128>>,
        PC: FieldChallenger<F> + GrindingChallenger<Witness = F>,
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
        let opening = BinaryWhirVerifier::<F>::with_limits(
            config,
            main_protocol,
            order,
            hash,
            cap_height,
            limits,
        )?;
        let mut opening_usage = opening.input_resource_usage();
        opening_usage.instances = 0;
        usage.merge(limits, opening_usage)?;
        let (preprocessed, preprocessed_input) = if let Some(preprocessing) = preprocessing {
            let verifier = BinaryWhirVerifier::<F>::with_limits(
                &preprocessing.config,
                preprocessed_protocol.expect("checked preprocessing protocol"),
                preprocessing.order,
                preprocessing.hash,
                preprocessing.cap_height,
                limits,
            )?;
            if preprocessing.commitment.num_roots() != 1usize << preprocessing.cap_height {
                return Err(invalid(
                    "binary WHIR MultiStark trusted preprocessing cap shape mismatch",
                ));
            }
            let mut preprocessed_usage = verifier.input_resource_usage();
            preprocessed_usage.instances = 0;
            usage.merge(limits, preprocessed_usage)?;
            usage.add_metadata_entries(limits, preprocessing.commitment.num_roots())?;
            let input = WhirPreprocessedInputShape {
                opening: verifier.input_shape(),
                commitment: preprocessing.commitment.roots().to_vec(),
            };
            (Some(verifier), Some(input))
        } else {
            (None, None)
        };
        let input = BinaryWhirMultiStarkInputShape {
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

    pub fn input_shape(&self) -> BinaryWhirMultiStarkInputShape<F> {
        self.input.clone()
    }
    pub fn input_resource_usage(&self) -> InputResourceUsage {
        self.usage
    }

    pub(crate) fn retain_native_parameter_metadata(
        &mut self,
        entries: usize,
        limits: &VerifierLimits,
    ) -> Result<(), VerificationError> {
        self.usage.add_metadata_entries(limits, entries)
    }

    /// Checks all AIR obligations and authenticates their committed openings.
    /// Public targets are the caller's actual statement, in instance order.
    /// Returns the exact ordinary challenger after the fixed stratified query schedule.
    pub fn verify<BF, EF>(
        &self,
        b: &mut CircuitBuilder<EF>,
        mut ch: BinaryTower128Challenger,
        public: &[Vec<BinaryTower128Target>],
        proof: &BinaryWhirMultiStarkProofTargets,
    ) -> Result<BinaryTower128Challenger, VerificationError>
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
                    "binary WHIR MultiStark preprocessed opening shape mismatch",
                ));
            }
        };
        self.relation
            .observe_prefix::<BF, EF>(b, &mut ch, preprocessed_cap.as_deref())?;
        self.opening
            .observe_commitment::<BF, EF>(b, &mut ch, &proof.commitment)?;
        let reduction = self.relation.reduce::<BF, EF>(b, ch, public, &common)?;
        let (main_evals, mut continuation) = self.opening.verify_at::<BF, EF>(
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
            let (evals, next) = verifier.verify_at::<BF, EF>(
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

    /// Checks the complete visible proof before bounded replay. Failure leaves
    /// the caller's native transcript unchanged.
    pub fn import_native<C, H, Co, Ch>(
        &self,
        config: &WhirConfig<BinaryField128, F, C::Challenger>,
        mmcs: &MerkleTreeMmcs<F, u8, H, Co, 2, 32>,
        public: &[Vec<F>],
        proof: &MultiStarkProof<C>,
        ch: &mut Ch,
    ) -> Result<NativeBinaryWhirMultiStarkInput<F>, VerificationError>
    where
        C: MultiStarkConfig<Val = F, Challenge = BinaryField128>,
        C::Challenger: FieldChallenger<F> + GrindingChallenger<Witness = F>,
        C::Pcs: MultilinearPcs<
                BinaryField128,
                C::Challenger,
                Commitment = MerkleCap<F, [u8; 32]>,
                Proof = WhirPcsProof<F, BinaryField128, MerkleTreeMmcs<F, u8, H, Co, 2, 32>>,
            >,
        F: PackedValue<Value = F>,
        H: CryptographicHasher<F, [u8; 32]> + Sync,
        Co: PseudoCompressionFunction<[u8; 32], 2> + Sync,
        Ch: FieldChallenger<F>
            + CanSampleUniformBits<F>
            + GrindingChallenger<Witness = F>
            + CanObserve<MerkleCap<F, [u8; 32]>>
            + Clone,
    {
        let preprocessing = self.preprocessed.as_ref().map(|_| (config, mmcs));
        self.import_native_with_preprocessing(config, mmcs, preprocessing, public, proof, ch)
    }

    /// Main and preprocessing may use independent WHIR schedules and byte trees.
    /// Both share one frontier budget before any transcript replay starts.
    pub fn import_native_with_preprocessing<C, H, Co, Ch>(
        &self,
        config: &WhirConfig<BinaryField128, F, C::Challenger>,
        mmcs: &MerkleTreeMmcs<F, u8, H, Co, 2, 32>,
        preprocessed: Option<(
            &WhirConfig<BinaryField128, F, C::Challenger>,
            &MerkleTreeMmcs<F, u8, H, Co, 2, 32>,
        )>,
        public: &[Vec<F>],
        proof: &MultiStarkProof<C>,
        ch: &mut Ch,
    ) -> Result<NativeBinaryWhirMultiStarkInput<F>, VerificationError>
    where
        C: MultiStarkConfig<Val = F, Challenge = BinaryField128>,
        C::Challenger: FieldChallenger<F> + GrindingChallenger<Witness = F>,
        C::Pcs: MultilinearPcs<
                BinaryField128,
                C::Challenger,
                Commitment = MerkleCap<F, [u8; 32]>,
                Proof = WhirPcsProof<F, BinaryField128, MerkleTreeMmcs<F, u8, H, Co, 2, 32>>,
            >,
        F: PackedValue<Value = F>,
        H: CryptographicHasher<F, [u8; 32]> + Sync,
        Co: PseudoCompressionFunction<[u8; 32], 2> + Sync,
        Ch: FieldChallenger<F>
            + CanSampleUniformBits<F>
            + GrindingChallenger<Witness = F>
            + CanObserve<MerkleCap<F, [u8; 32]>>
            + Clone,
    {
        self.relation.check_native(public, proof)?;
        let points: Vec<_> = self
            .relation
            .zero_points(false, BinaryField128::ZERO)
            .into_iter()
            .map(Point::new)
            .collect();
        let mut usage = InputResourceUsage::default();
        self.opening.check_native_with_usage(
            config,
            mmcs,
            &proof.commitment,
            &points,
            &proof.opening,
            &mut usage,
        )?;
        let preprocessing = match (
            &self.preprocessed,
            &self.input.preprocessed,
            preprocessed,
            &proof.preprocessed_opening,
        ) {
            (Some(verifier), Some(shape), Some((config, mmcs)), Some(proof)) => {
                let cap = MerkleCap::<F, _>::new(shape.commitment.clone());
                let points: Vec<_> = self
                    .relation
                    .zero_points(true, BinaryField128::ZERO)
                    .into_iter()
                    .map(Point::new)
                    .collect();
                verifier.check_native_with_usage(config, mmcs, &cap, &points, proof, &mut usage)?;
                Some((verifier, config, mmcs, proof, cap))
            }
            (None, None, None, None) => None,
            _ => {
                return Err(invalid(
                    "binary WHIR MultiStark native preprocessing shape mismatch",
                ));
            }
        };
        let mut staged = ch.clone();
        self.relation.observe_native_prefix(
            &mut staged,
            preprocessing.as_ref().map(|(_, _, _, _, cap)| cap),
        );
        layout::observe_commitment::<F, _, _>(&mut staged, proof.commitment.clone());
        let reduction = self.relation.reduce_native(public, proof, &mut staged)?;
        let opening = self.opening.import_native(
            config,
            mmcs,
            &proof.commitment,
            &reduction.main_points,
            &proof.opening,
            &mut staged,
        )?;
        let preprocessed_opening = preprocessing
            .map(|(verifier, config, mmcs, proof, cap)| {
                verifier.import_native(
                    config,
                    mmcs,
                    &cap,
                    reduction
                        .preprocessed_points
                        .as_ref()
                        .expect("checked preprocessing points"),
                    proof,
                    &mut staged,
                )
            })
            .transpose()?;
        *ch = staged;
        Ok(NativeBinaryWhirMultiStarkInput {
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
