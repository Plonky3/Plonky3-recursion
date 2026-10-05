//! Complete released Poly64/Poly192 WHIR MultiStark relations.
mod relation;
use alloc::vec::Vec;
use core::hash::Hash;

use p3_air::Air;
use p3_binary_field::{Poly64, Poly192};
use p3_bus::BusSymbolicBuilder;
use p3_challenger::{CanObserve, CanSampleUniformBits, FieldChallenger, GrindingChallenger};
use p3_circuit::ops::binary_encoding::{
    BinaryCircuitEncoding, NativeBinaryEncoding, PrimeBinaryEncoding,
};
use p3_circuit::ops::binary_host::BinaryCircuitHost;
use p3_circuit::ops::{
    BinaryPoly64Target, BinaryPoly192Target, ByteHash, NativePoly192Target, bytes_to_limbs,
};
use p3_circuit::{CircuitBuilder, ExprId};
use p3_commit::MultilinearPcs;
use p3_field::{ExtensionField, Field, PrimeCharacteristicRing, PrimeField64};
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
use relation::{PolyMultiStarkRelation, PolyMultiStarkRelationShape};

use super::binary_field_policy::NativePoly64Relation;
use super::binary_poly_indexed::NativePolyIndexedInput;
use super::{BinaryPolyAirConstraintPlan, InputResourceUsage, VerificationError, VerifierLimits};
use crate::BinaryTower128Challenger;
use crate::pcs::binary::{
    BinaryPolyGenericSumcheckProofTargets, BinaryPolyWhirInputShape, BinaryPolyWhirProofTargets,
    BinaryPolyWhirVerifier, NativeBinaryPolyGenericSumcheckInput, NativeBinaryPolyWhirInput,
};
/// Proof-independent input shape including the trusted AIR program.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BinaryPolyWhirMultiStarkInputShape {
    relation: alloc::sync::Arc<PolyMultiStarkRelationShape>,
    opening: BinaryPolyWhirInputShape,
    preprocessed: Option<WhirPreprocessedInputShape>,
    cap_height: usize,
}

/// Trusted preprocessing authority, supplied independently of every proof.
/// The commitment must belong to the ordered nonempty preprocessing tables
/// at the fixed AIR heights. Its PCS geometry may differ from the main trace.
#[derive(Clone, Debug)]
pub struct BinaryPolyWhirMultiStarkPreprocessing<PC> {
    pub config: WhirConfig<Poly192, Poly64, PC>,
    pub order: VariableOrder,
    pub hash: ByteHash,
    pub cap_height: usize,
    pub commitment: MerkleCap<Poly64, [u8; 32]>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct WhirPreprocessedInputShape {
    opening: BinaryPolyWhirInputShape,
    commitment: Vec<[u8; 32]>,
}

impl WhirPreprocessedInputShape {
    fn constant_cap<H, CF>(
        &self,
        b: &mut CircuitBuilder<CF>,
    ) -> Result<Vec<Vec<ExprId>>, VerificationError>
    where
        CF: Field + Eq + Hash,
        H: BinaryCircuitHost<CF>,
    {
        self.commitment
            .iter()
            .map(|root| {
                let digest = bytes_to_limbs(root)
                    .into_iter()
                    .map(|limb| Ok(b.define_const(H::encode_u16(limb)?)))
                    .collect::<Result<Vec<_>, VerificationError>>()?;
                b.check_construction_limits()?;
                Ok(digest)
            })
            .collect()
    }
}

#[derive(Clone, Debug)]
pub struct BinaryPolyWhirMultiStarkProofTargets<T = BinaryPoly192Target, B = BinaryPoly64Target> {
    pub commitment: Vec<Vec<ExprId>>,
    pub sumcheck: BinaryPolyGenericSumcheckProofTargets<T, B>,
    pub bus: Option<super::BinaryPolyProductGkrProofTargets<T>>,
    pub indexed: Option<super::BinaryPolyIndexedLookupProofTargets>,
    pub opening: BinaryPolyWhirProofTargets<T, B>,
    pub preprocessed_opening: Option<BinaryPolyWhirProofTargets<T, B>>,
}

impl BinaryPolyWhirMultiStarkInputShape {
    pub(crate) fn native_decode_shape(
        &self,
    ) -> crate::artifact::binary_native::codec::MultiDecode<
        crate::artifact::binary_native::codec::WhirDecode,
    > {
        crate::artifact::binary_native::codec::MultiDecode {
            public_counts: self.public_value_counts().collect(),
            cap_roots: 1usize << self.cap_height,
            bus: self
                .relation
                .bus
                .as_ref()
                .map(|bus| bus.product.native_decode_shape()),
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
    ) -> Result<(), crate::artifact::ArtifactError> {
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
    pub fn public_value_counts(&self) -> impl ExactSizeIterator<Item = usize> + '_ {
        self.relation
            .airs
            .iter()
            .map(BinaryPolyAirConstraintPlan::public_value_count)
    }

    /// Allocates cap, sumcheck and authenticated PCS witnesses in order.
    /// Public values are allocated and bound separately by the caller.
    pub fn allocate_targets<BF, EF>(
        &self,
        b: &mut CircuitBuilder<EF>,
    ) -> Result<BinaryPolyWhirMultiStarkProofTargets, VerificationError>
    where
        BF: PrimeField64,
        EF: ExtensionField<BF> + Eq + Hash,
    {
        let commitment = (0..1usize << self.cap_height)
            .map(|_| {
                b.alloc_private_input_array::<16>("polynomial WHIR MultiStark commitment")
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
            .map(|i| i.allocate_targets::<BF, EF>(b))
            .transpose()?;
        let opening = self.opening.allocate_targets::<BF, EF>(b)?;
        let preprocessed_opening = self
            .preprocessed
            .as_ref()
            .map(|preprocessed| preprocessed.opening.allocate_targets::<BF, EF>(b))
            .transpose()?;
        Ok(BinaryPolyWhirMultiStarkProofTargets {
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
pub struct NativeBinaryPolyWhirMultiStarkInput {
    shape: BinaryPolyWhirMultiStarkInputShape,
    commitment: Vec<[u8; 32]>,
    sumcheck: NativeBinaryPolyGenericSumcheckInput,
    bus: Option<super::NativeBinaryPolyProductGkrInput>,
    indexed: Option<NativePolyIndexedInput>,
    opening: NativeBinaryPolyWhirInput,
    preprocessed_opening: Option<NativeBinaryPolyWhirInput>,
}

impl NativeBinaryPolyWhirMultiStarkInput {
    pub fn shape(&self) -> &BinaryPolyWhirMultiStarkInputShape {
        &self.shape
    }

    pub fn private_values<EF: Field>(
        &self,
        expected: &BinaryPolyWhirMultiStarkInputShape,
    ) -> Result<Vec<EF>, VerificationError> {
        if &self.shape != expected {
            return Err(invalid(
                "polynomial WHIR MultiStark input belongs to another verifier",
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
            _ => return Err(invalid("binary Poly MultiStark bus input shape mismatch")),
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
                    "binary Poly MultiStark indexed input shape mismatch",
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
                    "polynomial WHIR MultiStark preprocessing input shape mismatch",
                ));
            }
        }
        Ok(values)
    }
}

/// Complete polynomial AIR, optional bus and indexed reductions, and additive WHIR relation.
/// The caller supplies the statement and independent preprocessing authority.
#[derive(Clone, Debug)]
pub struct BinaryPolyWhirMultiStarkVerifier {
    input: BinaryPolyWhirMultiStarkInputShape,
    relation: PolyMultiStarkRelation,
    opening: BinaryPolyWhirVerifier,
    preprocessed: Option<BinaryPolyWhirVerifier>,
    usage: InputResourceUsage,
}

impl BinaryPolyWhirMultiStarkVerifier {
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

    pub(crate) fn retain_native_parameter_metadata(
        &mut self,
        entries: usize,
        limits: &VerifierLimits,
    ) -> Result<(), VerificationError> {
        self.usage.add_metadata_entries(limits, entries)
    }

    pub fn new<A, PC>(
        airs: &[&A],
        heights: &[usize],
        config: &WhirConfig<Poly192, Poly64, PC>,
        order: VariableOrder,
        hash: ByteHash,
        cap_height: usize,
        pow_bits: usize,
        max_tau_draws: usize,
    ) -> Result<Self, VerificationError>
    where
        A: Air<InteractionSymbolicBuilder<Poly64, Poly192>>
            + Air<BusSymbolicBuilder<Poly64, Poly192>>,
        PC: FieldChallenger<Poly64> + GrindingChallenger<Witness = Poly64>,
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
        config: &WhirConfig<Poly192, Poly64, PC>,
        order: VariableOrder,
        hash: ByteHash,
        cap_height: usize,
        pow_bits: usize,
        max_tau_draws: usize,
        limits: &VerifierLimits,
    ) -> Result<Self, VerificationError>
    where
        A: Air<InteractionSymbolicBuilder<Poly64, Poly192>>
            + Air<BusSymbolicBuilder<Poly64, Poly192>>,
        PC: FieldChallenger<Poly64> + GrindingChallenger<Witness = Poly64>,
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
        config: &WhirConfig<Poly192, Poly64, PC>,
        order: VariableOrder,
        hash: ByteHash,
        cap_height: usize,
        pow_bits: usize,
        max_tau_draws: usize,
        preprocessing: BinaryPolyWhirMultiStarkPreprocessing<PC>,
        limits: &VerifierLimits,
    ) -> Result<Self, VerificationError>
    where
        A: Air<InteractionSymbolicBuilder<Poly64, Poly192>>
            + Air<BusSymbolicBuilder<Poly64, Poly192>>,
        PC: FieldChallenger<Poly64> + GrindingChallenger<Witness = Poly64>,
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
        config: &WhirConfig<Poly192, Poly64, PC>,
        order: VariableOrder,
        hash: ByteHash,
        cap_height: usize,
        pow_bits: usize,
        max_tau_draws: usize,
        preprocessing: Option<BinaryPolyWhirMultiStarkPreprocessing<PC>>,
        limits: &VerifierLimits,
    ) -> Result<Self, VerificationError>
    where
        A: Air<InteractionSymbolicBuilder<Poly64, Poly192>>
            + Air<BusSymbolicBuilder<Poly64, Poly192>>,
        PC: FieldChallenger<Poly64> + GrindingChallenger<Witness = Poly64>,
    {
        if heights
            .iter()
            .any(|&height| height < config.round_folding_factor(0))
        {
            return Err(invalid(
                "polynomial WHIR trace height is below the native first fold",
            ));
        }
        if preprocessing.as_ref().is_some_and(|pp| {
            pp.config.round_folding_factor(0) != config.round_folding_factor(0) || pp.order != order
        }) {
            return Err(invalid(
                "polynomial WHIR preprocessing must share the native witness layout and first fold",
            ));
        }
        let (relation, main_protocol, preprocessed_protocol) = PolyMultiStarkRelation::build(
            airs,
            heights,
            pow_bits,
            max_tau_draws,
            preprocessing.is_some(),
            limits,
        )?;
        let mut usage = relation.usage;
        let opening = BinaryPolyWhirVerifier::with_limits(
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
            let verifier = BinaryPolyWhirVerifier::with_limits(
                &preprocessing.config,
                preprocessed_protocol.expect("checked preprocessing protocol"),
                preprocessing.order,
                preprocessing.hash,
                preprocessing.cap_height,
                limits,
            )?;
            if preprocessing.commitment.num_roots() != 1usize << preprocessing.cap_height {
                return Err(invalid(
                    "polynomial WHIR MultiStark trusted preprocessing cap shape mismatch",
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
        let input = BinaryPolyWhirMultiStarkInputShape {
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

    pub fn input_shape(&self) -> BinaryPolyWhirMultiStarkInputShape {
        self.input.clone()
    }
    pub fn input_resource_usage(&self) -> InputResourceUsage {
        self.usage
    }

    /// Checks all AIR obligations and authenticates their committed openings.
    /// Public targets are the caller's actual statement, in instance order.
    /// Returns the exact ordinary challenger after the fixed stratified query schedule.
    pub fn verify<BF, EF>(
        &self,
        b: &mut CircuitBuilder<EF>,
        mut ch: BinaryTower128Challenger,
        public: &[Vec<BinaryPoly64Target>],
        proof: &BinaryPolyWhirMultiStarkProofTargets,
    ) -> Result<BinaryTower128Challenger, VerificationError>
    where
        BF: PrimeField64,
        EF: ExtensionField<BF> + Eq + Hash,
    {
        self.relation.check_targets(public, proof)?;
        let zero = b.binary_poly192_constant([0; 3])?;
        let points = self.relation.zero_points(false, zero.clone());
        self.opening
            .check_targets(&proof.commitment, &points, &proof.opening)?;
        let preprocessed_cap = match (
            &self.preprocessed,
            &self.input.preprocessed,
            &proof.preprocessed_opening,
        ) {
            (Some(verifier), Some(shape), Some(proof)) => {
                let cap = shape.constant_cap::<PrimeBinaryEncoding<BF>, EF>(b)?;
                let points = self.relation.zero_points(true, zero.clone());
                verifier.check_targets(&cap, &points, proof)?;
                Some(cap)
            }
            (None, None, None) => None,
            _ => {
                return Err(invalid(
                    "polynomial WHIR MultiStark preprocessed opening shape mismatch",
                ));
            }
        };
        self.relation
            .observe_prefix::<BF, EF>(b, &mut ch, preprocessed_cap.as_deref())?;
        self.opening
            .observe_commitment::<BF, EF>(b, &mut ch, &proof.commitment)?;
        let reduction = self.relation.reduce::<BF, EF>(b, ch, public, proof)?;
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
            proof,
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
        config: &WhirConfig<Poly192, Poly64, C::Challenger>,
        mmcs: &MerkleTreeMmcs<Poly64, u8, H, Co, 2, 32>,
        public: &[Vec<Poly64>],
        proof: &MultiStarkProof<C>,
        ch: &mut Ch,
    ) -> Result<NativeBinaryPolyWhirMultiStarkInput, VerificationError>
    where
        C: MultiStarkConfig<Val = Poly64, Challenge = Poly192>,
        C::Challenger: FieldChallenger<Poly64> + GrindingChallenger<Witness = Poly64>,
        C::Pcs: MultilinearPcs<
                Poly192,
                C::Challenger,
                Commitment = MerkleCap<Poly64, [u8; 32]>,
                Proof = WhirPcsProof<Poly64, Poly192, MerkleTreeMmcs<Poly64, u8, H, Co, 2, 32>>,
            >,
        H: CryptographicHasher<Poly64, [u8; 32]> + Sync,
        Co: PseudoCompressionFunction<[u8; 32], 2> + Sync,
        Ch: FieldChallenger<Poly64>
            + CanSampleUniformBits<Poly64>
            + GrindingChallenger<Witness = Poly64>
            + CanObserve<MerkleCap<Poly64, [u8; 32]>>
            + Clone,
    {
        let preprocessing = self.preprocessed.as_ref().map(|_| (config, mmcs));
        self.import_native_with_preprocessing(config, mmcs, preprocessing, public, proof, ch)
    }

    /// Main and preprocessing may use independent WHIR schedules and byte trees.
    /// Both share one frontier budget before any transcript replay starts.
    pub fn import_native_with_preprocessing<C, H, Co, Ch>(
        &self,
        config: &WhirConfig<Poly192, Poly64, C::Challenger>,
        mmcs: &MerkleTreeMmcs<Poly64, u8, H, Co, 2, 32>,
        preprocessed: Option<(
            &WhirConfig<Poly192, Poly64, C::Challenger>,
            &MerkleTreeMmcs<Poly64, u8, H, Co, 2, 32>,
        )>,
        public: &[Vec<Poly64>],
        proof: &MultiStarkProof<C>,
        ch: &mut Ch,
    ) -> Result<NativeBinaryPolyWhirMultiStarkInput, VerificationError>
    where
        C: MultiStarkConfig<Val = Poly64, Challenge = Poly192>,
        C::Challenger: FieldChallenger<Poly64> + GrindingChallenger<Witness = Poly64>,
        C::Pcs: MultilinearPcs<
                Poly192,
                C::Challenger,
                Commitment = MerkleCap<Poly64, [u8; 32]>,
                Proof = WhirPcsProof<Poly64, Poly192, MerkleTreeMmcs<Poly64, u8, H, Co, 2, 32>>,
            >,
        H: CryptographicHasher<Poly64, [u8; 32]> + Sync,
        Co: PseudoCompressionFunction<[u8; 32], 2> + Sync,
        Ch: FieldChallenger<Poly64>
            + CanSampleUniformBits<Poly64>
            + GrindingChallenger<Witness = Poly64>
            + CanObserve<MerkleCap<Poly64, [u8; 32]>>
            + Clone,
    {
        self.relation.check_native(public, proof)?;
        let points: Vec<_> = self
            .relation
            .zero_points(false, Poly192::ZERO)
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
                let cap = MerkleCap::<Poly64, _>::new(shape.commitment.clone());
                let points: Vec<_> = self
                    .relation
                    .zero_points(true, Poly192::ZERO)
                    .into_iter()
                    .map(Point::new)
                    .collect();
                verifier.check_native_with_usage(config, mmcs, &cap, &points, proof, &mut usage)?;
                Some((verifier, config, mmcs, proof, cap))
            }
            (None, None, None, None) => None,
            _ => {
                return Err(invalid(
                    "polynomial WHIR MultiStark native preprocessing shape mismatch",
                ));
            }
        };
        let mut staged = ch.clone();
        self.relation.observe_native_prefix(
            &mut staged,
            preprocessing.as_ref().map(|(_, _, _, _, cap)| cap),
        );
        layout::observe_commitment::<Poly64, _, _>(&mut staged, proof.commitment.clone());
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
        Ok(NativeBinaryPolyWhirMultiStarkInput {
            shape: self.input.clone(),
            commitment: proof.commitment.roots().to_vec(),
            sumcheck: reduction.sumcheck,
            bus: reduction.bus,
            indexed: reduction.indexed,
            opening,
            preprocessed_opening,
        })
    }
}
fn invalid(message: &'static str) -> VerificationError {
    VerificationError::InvalidProofShape(message.into())
}

impl BinaryPolyWhirMultiStarkInputShape {
    /// Scalar input traversal for the bus/AIR native backend. Indexed plans
    /// require a different native reduction and are rejected before allocation.
    pub fn allocate_native_targets(
        &self,
        b: &mut CircuitBuilder<Poly64>,
    ) -> Result<BinaryPolyWhirMultiStarkProofTargets<NativePoly192Target, ExprId>, VerificationError>
    {
        if self.relation.indexed.is_some() {
            return Err(invalid(
                "native polynomial WHIR verifier does not support indexed relations",
            ));
        }
        let commitment = (0..1usize << self.cap_height)
            .map(|_| {
                let digest = b
                    .alloc_private_input_array::<16>("native WHIR MultiStark commitment")
                    .to_vec();
                b.check_construction_limits()?;
                Ok(digest)
            })
            .collect::<Result<_, VerificationError>>()?;
        let bus = self
            .relation
            .bus
            .as_ref()
            .map(|bus| bus.product.allocate_native_targets(b))
            .transpose()?;
        let sumcheck = self.relation.sumcheck.allocate_native_targets(b)?;
        let opening = self.opening.allocate_native_targets(b)?;
        let preprocessed_opening = self
            .preprocessed
            .as_ref()
            .map(|pp| pp.opening.allocate_native_targets(b))
            .transpose()?;
        Ok(BinaryPolyWhirMultiStarkProofTargets {
            commitment,
            bus,
            sumcheck,
            indexed: None,
            opening,
            preprocessed_opening,
        })
    }
}
impl NativeBinaryPolyWhirMultiStarkInput {
    pub fn private_native_values(
        &self,
        expected: &BinaryPolyWhirMultiStarkInputShape,
    ) -> Result<Vec<Poly64>, VerificationError> {
        if &self.shape != expected {
            return Err(invalid(
                "polynomial WHIR MultiStark input belongs to another verifier",
            ));
        }
        if expected.relation.indexed.is_some() || self.indexed.is_some() {
            return Err(invalid(
                "native polynomial WHIR verifier does not support indexed relations",
            ));
        }
        let mut values: Vec<_> = self
            .commitment
            .iter()
            .flat_map(|root| {
                bytes_to_limbs(root)
                    .into_iter()
                    .map(|word| NativeBinaryEncoding::encode_u16(word))
            })
            .collect::<Result<_, _>>()?;
        match (&expected.relation.bus, &self.bus) {
            (Some(shape), Some(input)) => {
                values.extend(input.private_native_values(&shape.product)?)
            }
            (None, None) => {}
            _ => {
                return Err(invalid(
                    "polynomial WHIR MultiStark bus input shape mismatch",
                ));
            }
        }
        values.extend(
            self.sumcheck
                .private_native_values(&expected.relation.sumcheck)?,
        );
        values.extend(self.opening.private_native_values(&expected.opening)?);
        match (&expected.preprocessed, &self.preprocessed_opening) {
            (Some(shape), Some(input)) => {
                values.extend(input.private_native_values(&shape.opening)?)
            }
            (None, None) => {}
            _ => {
                return Err(invalid(
                    "polynomial WHIR MultiStark preprocessing input shape mismatch",
                ));
            }
        }
        Ok(values)
    }
}
impl BinaryPolyWhirMultiStarkVerifier {
    pub(crate) fn check_native_circuit_support(&self) -> Result<(), VerificationError> {
        if self.relation.indexed.is_some() {
            return Err(invalid(
                "native polynomial WHIR verifier does not support indexed relations",
            ));
        }
        self.opening.check_host::<NativeBinaryEncoding, Poly64>()?;
        if let Some(pp) = &self.preprocessed {
            pp.check_host::<NativeBinaryEncoding, Poly64>()?;
        }
        Ok(())
    }

    /// Complete native Poly64/Poly192 relation, including product buses and trusted
    /// preprocessing. Caller-supplied public scalars bind the expected statement.
    pub fn verify_native(
        &self,
        b: &mut CircuitBuilder<Poly64>,
        mut ch: BinaryTower128Challenger,
        public: &[Vec<ExprId>],
        proof: &BinaryPolyWhirMultiStarkProofTargets<NativePoly192Target, ExprId>,
    ) -> Result<BinaryTower128Challenger, VerificationError> {
        self.check_native_circuit_support()?;
        if proof.indexed.is_some() {
            return Err(invalid(
                "native polynomial WHIR verifier does not support indexed relations",
            ));
        }
        self.relation.check_targets(public, proof)?;
        let zero = b.native_poly192_constant([0; 3]);
        let points = self.relation.zero_points(false, zero.clone());
        self.opening
            .check_targets(&proof.commitment, &points, &proof.opening)?;
        let preprocessed_cap = match (
            &self.preprocessed,
            &self.input.preprocessed,
            &proof.preprocessed_opening,
        ) {
            (Some(verifier), Some(shape), Some(proof)) => {
                let cap = shape.constant_cap::<NativeBinaryEncoding, Poly64>(b)?;
                let points = self.relation.zero_points(true, zero.clone());
                verifier.check_targets(&cap, &points, proof)?;
                Some(cap)
            }
            (None, None, None) => None,
            _ => {
                return Err(invalid(
                    "polynomial WHIR MultiStark preprocessed opening shape mismatch",
                ));
            }
        };
        self.relation
            .observe_prefix_with_host::<NativeBinaryEncoding, Poly64>(
                b,
                &mut ch,
                preprocessed_cap.as_deref(),
            )?;
        self.opening
            .observe_commitment_with_host::<NativeBinaryEncoding, Poly64>(
                b,
                &mut ch,
                &proof.commitment,
            )?;
        let mut reduction = self
            .relation
            .reduce_common::<NativePoly64Relation, NativeBinaryEncoding, Poly64>(
                b, ch, public, proof,
            )?;
        let heights: Vec<_> = self
            .relation
            .input
            .airs
            .iter()
            .map(|air| air.log_height())
            .collect();
        reduction.main_points =
            self.relation
                .input
                .main_schedule
                .points(&heights, &reduction.point, None);
        reduction.preprocessed_points = self
            .relation
            .input
            .preprocessed_schedule
            .as_ref()
            .map(|schedule| schedule.points(&heights, &reduction.point, None));
        let (main_evals, mut continuation) = self.opening.verify_at_native(
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
            let (evals, next) = verifier.verify_at_native(
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
        self.relation
            .finish_common::<NativePoly64Relation, Poly64>(
                b,
                public,
                &reduction,
                &main_evals,
                preprocessed_evals.as_deref(),
            )?;
        Ok(continuation)
    }
}
