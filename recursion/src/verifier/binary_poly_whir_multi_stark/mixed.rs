//! Complete Poly64/Poly192 MultiStark relations over a dense WHIR commitment and one packed-bit
//! table commitment, in the native Poly64 carrier.
//!
//! ```text
//!     tables        one configured table is committed as bits, sixty-four per Poly64 element,
//!                   every other table densely
//!     commitment    one cap: the dense roots, then the packed roots, arity^c of each
//!     transcript    relation prefix, dense binding, packed binding, relation reduction,
//!                   dense opening, packed opening, preprocessing opening, relation closing
//!     evaluations   both openings merged back into protocol order before the AIRs close
//! ```
//!
//! The split of the main opening and its transcript order are the Tower128 mixed verifier's.
//! The bit-committed table's AIR assumes a Boolean trace, and no other AIR does: its cells are
//! bits because the packed commitment can represent nothing else, and every value the relation
//! reads from that table arrives through the column batch, the bit ring switch and the packed
//! WHIR opening. The table index, its bit variables and the trees' arity are fixed at
//! construction and bound into the identity, so a proof cannot move the table to the dense
//! side.
//!
//! The packed opening closes its ring switch only in the native Poly64 carrier, so the relation
//! has no prime-field circuit and no indexed lookups.

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::hash::Hash;

use p3_air::Air;
use p3_binary_field::{Poly64, Poly192};
use p3_bus::BusSymbolicBuilder;
use p3_challenger::{CanObserve, CanSampleUniformBits, FieldChallenger, GrindingChallenger};
use p3_circuit::ops::{BinaryPoly64Target, ByteHash, NativePoly192Target};
use p3_circuit::{CircuitBuilder, ExprId};
use p3_field::{ExtensionField, PrimeCharacteristicRing, PrimeField64};
use p3_lookup::InteractionSymbolicBuilder;
use p3_merkle_tree::MerkleCap;
use p3_multi_stark::MultiStarkProof;
use p3_multilinear_util::point::Point;
use p3_sumcheck::layout::{self, Layout, SuffixProver};
use p3_whir::WhirConfig;

use super::super::binary_mixed_whir_multi_stark::{MixedSplit, split_protocol};
use super::super::{
    BinaryPolyProductGkrProofTargets, InputResourceUsage, NativeBinaryPolyProductGkrInput,
    VerificationError, VerifierLimits,
};
use super::WhirPreprocessedInputShape;
use super::relation::{PolyMultiStarkRelation, PolyMultiStarkRelationShape};
use crate::BinaryTower128Challenger;
use crate::artifact::binary_native::{BinaryNativePolyMixedWhirConfig, NativeWhirMmcs};
use crate::pcs::binary::{
    BinaryPolyBooleanWhirTraceInputShape, BinaryPolyBooleanWhirTraceVerifier,
    BinaryPolyGenericSumcheckProofTargets, BinaryPolyWhirInputShape, BinaryPolyWhirProofTargets,
    BinaryPolyWhirVerifier, MerkleArity, NativeBinaryPolyBooleanWhirTraceInput,
    NativeBinaryPolyGenericSumcheckInput, NativeBinaryPolyWhirInput,
    NativePolyBooleanWhirTraceProofTargets,
};

mod native;

/// A WHIR configuration over Poly64 cells with Poly192 challenges.
type Whir<C> = WhirConfig<Poly192, Poly64, C>;
/// A WHIR configuration and the byte Merkle tree it commits with.
type WhirParameters<'a, C> = (&'a Whir<C>, &'a NativeWhirMmcs<Poly64>);

/// Proof-independent input shape including the trusted AIR program.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BinaryPolyMixedWhirMultiStarkInputShape {
    relation: Arc<PolyMultiStarkRelationShape>,
    packed_table: usize,
    /// The variables of the packed table's bit stack.
    bit_variables: usize,
    /// The node arity of both parts' trees.
    arity: MerkleArity,
    dense: BinaryPolyWhirInputShape,
    packed: BinaryPolyBooleanWhirTraceInputShape,
    preprocessed: Option<WhirPreprocessedInputShape>,
    /// The roots of each part's cap.
    cap_roots: usize,
}

/// Trusted preprocessing authority, supplied independently of every proof.
/// The commitment is dense, bound suffix first, and must belong to the ordered nonempty
/// preprocessing tables at the fixed AIR heights. Its PCS geometry may differ from the main
/// trace.
#[derive(Clone, Debug)]
pub struct BinaryPolyMixedWhirMultiStarkPreprocessing<PC> {
    pub config: Whir<PC>,
    pub hash: ByteHash,
    pub arity: MerkleArity,
    pub cap_height: usize,
    pub commitment: MerkleCap<Poly64, [u8; 32]>,
}

/// Native Poly64 proof targets: three coefficient cells per Poly192 value, one cell per Poly64
/// value.
#[derive(Clone, Debug)]
pub struct BinaryPolyMixedWhirMultiStarkProofTargets {
    /// The dense roots, then the packed roots.
    pub commitment: Vec<Vec<ExprId>>,
    pub bus: Option<BinaryPolyProductGkrProofTargets<NativePoly192Target>>,
    pub sumcheck: BinaryPolyGenericSumcheckProofTargets<NativePoly192Target, ExprId>,
    pub dense: BinaryPolyWhirProofTargets<NativePoly192Target, ExprId>,
    pub packed: NativePolyBooleanWhirTraceProofTargets,
    pub preprocessed_opening: Option<BinaryPolyWhirProofTargets<NativePoly192Target, ExprId>>,
}

impl BinaryPolyMixedWhirMultiStarkInputShape {
    /// The proof geometry: one main cap per part, the dense and the packed opening of the main
    /// commitment, and the dense preprocessing opening.
    pub(crate) fn native_decode_shape(
        &self,
    ) -> crate::artifact::binary_native::codec::MultiDecode<
        crate::artifact::binary_native::codec::MixedWhirDecode,
    > {
        use crate::artifact::binary_native::codec::{MixedWhirDecode, MultiDecode};
        MultiDecode {
            public_counts: self.public_value_counts().collect(),
            cap_roots: 2 * self.cap_roots,
            bus: self
                .relation
                .bus
                .as_ref()
                .map(|bus| bus.product.native_decode_shape()),
            sumcheck: self.relation.sumcheck.native_decode_shape(),
            indexed: None,
            opening: MixedWhirDecode {
                dense: self.dense.native_decode_shape(),
                packed: Some(self.packed.native_decode_shape()),
            },
            preprocessed: self.preprocessed.as_ref().map(|pp| MixedWhirDecode {
                dense: pp.opening.native_decode_shape(),
                packed: None,
            }),
        }
    }

    /// The relation identity, the bit-committed table, its bit variables, the trees' arity,
    /// both opening shapes and the trusted preprocessing shape and cap.
    pub(crate) fn write_identity(
        &self,
        w: &mut crate::artifact::wire::Writer,
    ) -> Result<(), crate::artifact::ArtifactError> {
        self.relation.write_identity(w)?;
        w.write_count("binary native mixed WHIR packed table", self.packed_table)?;
        w.write_count("binary native mixed WHIR bit variables", self.bit_variables)?;
        w.write_count("binary native mixed WHIR tree arity", self.arity.digests())?;
        self.dense.write_identity(w)?;
        self.packed.write_identity(w)?;
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
            .map(super::BinaryPolyAirConstraintPlan::public_value_count)
    }
}

/// Bounded witness material. It conveys no independent verification authority.
#[derive(Clone, Debug)]
pub struct NativeBinaryPolyMixedWhirMultiStarkInput {
    shape: BinaryPolyMixedWhirMultiStarkInputShape,
    commitment: Vec<[u8; 32]>,
    bus: Option<NativeBinaryPolyProductGkrInput>,
    sumcheck: NativeBinaryPolyGenericSumcheckInput,
    dense: NativeBinaryPolyWhirInput,
    packed: NativeBinaryPolyBooleanWhirTraceInput,
    preprocessed_opening: Option<NativeBinaryPolyWhirInput>,
}

impl NativeBinaryPolyMixedWhirMultiStarkInput {
    pub const fn shape(&self) -> &BinaryPolyMixedWhirMultiStarkInputShape {
        &self.shape
    }
}

/// Trusted Poly64/Poly192 MultiStark verifier over a dense WHIR commitment and a packed-bit
/// commitment of one table, both on one byte Merkle tree configuration.
///
/// Binds caller-owned public values through the complete AIR, sumcheck, and authenticated PCS
/// relation. The dense part opens every other table as the dense Poly64 WHIR verifier does; the
/// packed part opens the bit-committed table through column batching, the Poly64 bit ring
/// switch and a packed WHIR opening. Periodic constants and preprocessing authority are fixed
/// by construction. Native binary buses are reduced through the authenticated AIR sumcheck.
#[derive(Clone, Debug)]
pub struct BinaryPolyMixedWhirMultiStarkVerifier {
    input: BinaryPolyMixedWhirMultiStarkInputShape,
    relation: PolyMultiStarkRelation,
    split: MixedSplit,
    dense: BinaryPolyWhirVerifier,
    packed: BinaryPolyBooleanWhirTraceVerifier,
    preprocessed: Option<BinaryPolyWhirVerifier>,
    usage: InputResourceUsage,
}

impl BinaryPolyMixedWhirMultiStarkVerifier {
    /// Installs the exact cap captured from the factory's matched native setup.
    /// Geometry was validated before setup, with a placeholder cap of this size.
    pub(crate) fn bind_native_preprocessing_cap(
        &mut self,
        cap: Vec<[u8; 32]>,
    ) -> Result<(), VerificationError> {
        let Some(pp) = &mut self.input.preprocessed else {
            return Err(invalid(
                "binary native mixed WHIR setup produced an unexpected preprocessing cap",
            ));
        };
        if cap.len() != pp.commitment.len() {
            return Err(invalid(
                "binary native mixed WHIR setup preprocessing cap shape mismatch",
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

    /// `packed_table` names the one AIR whose main trace is committed as bits. That AIR, and
    /// only that AIR, must assume a Boolean trace, and its main trace must be opened as one
    /// batch: every column at the current row, and every column or none one row ahead.
    /// `packed` is the packed WHIR configuration over the bit stack of that table, six
    /// variables shorter. Both parts share `hash`, and their trees share `arity` and
    /// `cap_height`.
    #[expect(
        clippy::too_many_arguments,
        reason = "The verifier keeps protocol inputs explicit."
    )]
    pub fn with_limits<A, PC>(
        airs: &[&A],
        heights: &[usize],
        packed_table: usize,
        dense: &Whir<PC>,
        packed: &Whir<PC>,
        hash: ByteHash,
        arity: MerkleArity,
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
            packed_table,
            (dense, packed),
            (hash, arity, cap_height),
            pow_bits,
            max_tau_draws,
            None,
            limits,
        )
    }

    /// Builds a verifier retaining an independent trusted preprocessing cap.
    /// No proof can provide or replace this authority.
    #[expect(
        clippy::too_many_arguments,
        reason = "The verifier keeps protocol inputs explicit."
    )]
    pub fn with_preprocessing<A, PC>(
        airs: &[&A],
        heights: &[usize],
        packed_table: usize,
        dense: &Whir<PC>,
        packed: &Whir<PC>,
        hash: ByteHash,
        arity: MerkleArity,
        cap_height: usize,
        pow_bits: usize,
        max_tau_draws: usize,
        preprocessing: BinaryPolyMixedWhirMultiStarkPreprocessing<PC>,
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
            packed_table,
            (dense, packed),
            (hash, arity, cap_height),
            pow_bits,
            max_tau_draws,
            Some(preprocessing),
            limits,
        )
    }

    #[expect(
        clippy::too_many_arguments,
        reason = "The verifier keeps protocol inputs explicit."
    )]
    fn build<A, PC>(
        airs: &[&A],
        heights: &[usize],
        packed_table: usize,
        (dense_config, packed_config): (&Whir<PC>, &Whir<PC>),
        (hash, arity, cap_height): (ByteHash, MerkleArity, usize),
        pow_bits: usize,
        max_tau_draws: usize,
        preprocessing: Option<BinaryPolyMixedWhirMultiStarkPreprocessing<PC>>,
        limits: &VerifierLimits,
    ) -> Result<Self, VerificationError>
    where
        A: Air<InteractionSymbolicBuilder<Poly64, Poly192>>
            + Air<BusSymbolicBuilder<Poly64, Poly192>>,
        PC: FieldChallenger<Poly64> + GrindingChallenger<Witness = Poly64>,
    {
        if packed_table >= airs.len() {
            return Err(invalid(
                "polynomial mixed WHIR MultiStark packed table index exceeds the AIRs",
            ));
        }
        // The relation admits a Boolean assumption only on the bit-committed table. The
        // converse is checked here: the bit-committed table's AIR is the Boolean-assuming one.
        if airs
            .iter()
            .enumerate()
            .any(|(i, air)| air.assumes_boolean_trace() != (i == packed_table))
        {
            return Err(invalid(
                "polynomial mixed WHIR MultiStark bit-committed table is not exactly the Boolean-assuming AIR",
            ));
        }
        let first = dense_config.round_folding_factor(0);
        if heights.iter().any(|&height| height < first) {
            return Err(invalid(
                "polynomial WHIR trace height is below the native first fold",
            ));
        }
        if preprocessing
            .as_ref()
            .is_some_and(|pp| pp.config.round_folding_factor(0) != first)
        {
            return Err(invalid(
                "polynomial WHIR preprocessing must share the native witness layout and first fold",
            ));
        }
        let bits_committed: Vec<bool> = (0..airs.len()).map(|i| i == packed_table).collect();
        let (relation, main_protocol, preprocessed_protocol) =
            PolyMultiStarkRelation::build_with_bit_tables(
                airs,
                heights,
                &bits_committed,
                pow_bits,
                max_tau_draws,
                preprocessing.is_some(),
                limits,
            )?;
        if relation.indexed.is_some() {
            return Err(indexed_unsupported());
        }
        // One main table per AIR, in AIR order, so the AIR index names the protocol table.
        if main_protocol.table_shapes().len() != airs.len() {
            return Err(invalid(
                "polynomial mixed WHIR MultiStark main tables do not match the AIRs",
            ));
        }
        let (dense_protocol, packed_protocol) = split_protocol(&main_protocol, packed_table)?;
        let mut usage = relation.usage;
        let order = SuffixProver::<Poly64, Poly192>::variable_order();
        let dense = BinaryPolyWhirVerifier::with_limits(
            dense_config,
            dense_protocol,
            order,
            hash,
            arity,
            cap_height,
            limits,
        )?;
        let mut dense_usage = dense.input_resource_usage();
        dense_usage.instances = 0;
        usage.merge(limits, dense_usage)?;
        let packed = BinaryPolyBooleanWhirTraceVerifier::with_limits(
            packed_config,
            packed_protocol,
            hash,
            arity,
            cap_height,
            limits,
        )?;
        // The relation already charges the bit-committed table itself.
        let mut packed_usage = packed.input_resource_usage();
        packed_usage.instances = packed_usage.instances.checked_sub(1).ok_or(
            VerificationError::ResourceArithmeticOverflow {
                component: "polynomial mixed WHIR packed instance accounting",
            },
        )?;
        usage.merge(limits, packed_usage)?;
        let (preprocessed, preprocessed_input) = if let Some(preprocessing) = preprocessing {
            let verifier = BinaryPolyWhirVerifier::with_limits(
                &preprocessing.config,
                preprocessed_protocol.expect("checked preprocessing protocol"),
                order,
                preprocessing.hash,
                preprocessing.arity,
                preprocessing.cap_height,
                limits,
            )?;
            if preprocessing.commitment.num_roots() != verifier.cap_roots() {
                return Err(invalid(
                    "polynomial mixed WHIR MultiStark trusted preprocessing cap shape mismatch",
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
        let input = BinaryPolyMixedWhirMultiStarkInputShape {
            relation: relation.input.clone(),
            packed_table,
            bit_variables: packed.bit_variables(),
            arity,
            dense: dense.input_shape(),
            packed: packed.input_shape(),
            preprocessed: preprocessed_input,
            cap_roots: dense.cap_roots(),
        };
        Ok(Self {
            input,
            relation,
            split: MixedSplit::new(&main_protocol, packed_table, dense.cap_roots()),
            dense,
            packed,
            preprocessed,
            usage,
        })
    }

    pub fn input_shape(&self) -> BinaryPolyMixedWhirMultiStarkInputShape {
        self.input.clone()
    }

    pub const fn input_resource_usage(&self) -> InputResourceUsage {
        self.usage
    }

    /// Refused: the packed opening's ring switch closes only in the native Poly64 carrier, so
    /// this relation has no prime-field circuit. [`Self::verify_native`] verifies it.
    pub fn verify<BF, EF>(
        &self,
        _b: &mut CircuitBuilder<EF>,
        _ch: BinaryTower128Challenger,
        _public: &[Vec<BinaryPoly64Target>],
    ) -> Result<BinaryTower128Challenger, VerificationError>
    where
        BF: PrimeField64,
        EF: ExtensionField<BF> + Eq + Hash,
    {
        Err(invalid(
            "polynomial mixed WHIR MultiStark relation has no prime-field circuit; verify it in the native Poly64 carrier",
        ))
    }

    /// Checks the complete visible proof before bounded replay. Failure leaves the caller's
    /// native transcript unchanged. Merkle paths are restored as witnesses and authenticated
    /// only by the verifier circuit, so a successful import is no verification of the proof.
    ///
    /// `dense` and `packed` are the two parts' WHIR configurations on the shared tree `mmcs`.
    /// `preprocessed` is the dense preprocessing commitment's configuration and tree, present
    /// exactly when the verifier retains a preprocessing authority.
    #[expect(
        clippy::too_many_arguments,
        reason = "The verifier keeps protocol inputs explicit."
    )]
    pub(crate) fn import_native<C, Ch>(
        &self,
        dense: &Whir<C>,
        packed: &Whir<C>,
        mmcs: &NativeWhirMmcs<Poly64>,
        preprocessed: Option<WhirParameters<'_, C>>,
        public: &[Vec<Poly64>],
        proof: &MultiStarkProof<BinaryNativePolyMixedWhirConfig>,
        ch: &mut Ch,
    ) -> Result<NativeBinaryPolyMixedWhirMultiStarkInput, VerificationError>
    where
        C: FieldChallenger<Poly64> + GrindingChallenger<Witness = Poly64>,
        Ch: FieldChallenger<Poly64>
            + CanSampleUniformBits<Poly64>
            + GrindingChallenger<Witness = Poly64>
            + CanObserve<MerkleCap<Poly64, [u8; 32]>>
            + Clone,
    {
        self.relation.check_native(public, proof)?;
        let (dense_cap, packed_cap) = self.split.split_cap(proof.commitment.roots())?;
        let (dense_cap, packed_cap) = (
            MerkleCap::<Poly64, _>::new(dense_cap.to_vec()),
            MerkleCap::<Poly64, _>::new(packed_cap.to_vec()),
        );
        let packed_proof = proof.opening.packed.as_ref().ok_or_else(|| {
            invalid("polynomial mixed WHIR MultiStark native proof has no packed opening")
        })?;
        let points: Vec<_> = self
            .relation
            .zero_points(false, Poly192::ZERO)
            .into_iter()
            .map(Point::new)
            .collect();
        let (dense_points, packed_points) = self.split.split(&points)?;
        let mut usage = InputResourceUsage::default();
        self.dense.check_native_with_usage(
            dense,
            mmcs,
            &dense_cap,
            &dense_points,
            &proof.opening.dense,
            &mut usage,
        )?;
        self.packed.check_native_structure_with_usage(
            packed,
            mmcs,
            &packed_cap,
            &packed_points,
            packed_proof,
            &mut usage,
        )?;
        let preprocessing = match (
            &self.preprocessed,
            &self.input.preprocessed,
            preprocessed,
            &proof.preprocessed_opening,
        ) {
            (Some(verifier), Some(shape), Some((config, mmcs)), Some(opening))
                if opening.packed.is_none() =>
            {
                let cap = MerkleCap::<Poly64, _>::new(shape.commitment.clone());
                let points: Vec<_> = self
                    .relation
                    .zero_points(true, Poly192::ZERO)
                    .into_iter()
                    .map(Point::new)
                    .collect();
                verifier.check_native_with_usage(
                    config,
                    mmcs,
                    &cap,
                    &points,
                    &opening.dense,
                    &mut usage,
                )?;
                Some((verifier, config, mmcs, &opening.dense, cap))
            }
            (None, None, None, None) => None,
            _ => {
                return Err(invalid(
                    "polynomial mixed WHIR MultiStark native preprocessing shape mismatch",
                ));
            }
        };
        let mut staged = ch.clone();
        self.relation.observe_native_prefix(
            &mut staged,
            preprocessing.as_ref().map(|(_, _, _, _, cap)| cap),
        );
        layout::observe_commitment::<Poly64, _, _>(&mut staged, dense_cap.clone());
        layout::observe_commitment::<Poly64, _, _>(&mut staged, packed_cap.clone());
        let reduction = self.relation.reduce_native(public, proof, &mut staged)?;
        let (dense_points, packed_points) = self.split.split(&reduction.main_points)?;
        let dense_opening = self.dense.import_native(
            dense,
            mmcs,
            &dense_cap,
            &dense_points,
            &proof.opening.dense,
            &mut staged,
        )?;
        let packed_opening = self.packed.import_native(
            packed,
            mmcs,
            &packed_cap,
            &packed_points,
            packed_proof,
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
        Ok(NativeBinaryPolyMixedWhirMultiStarkInput {
            shape: self.input.clone(),
            commitment: proof.commitment.roots().to_vec(),
            bus: reduction.bus,
            sumcheck: reduction.sumcheck,
            dense: dense_opening,
            packed: packed_opening,
            preprocessed_opening,
        })
    }
}

fn indexed_unsupported() -> VerificationError {
    invalid("native polynomial mixed WHIR verifier does not support indexed relations")
}

fn invalid(message: &'static str) -> VerificationError {
    VerificationError::InvalidProofShape(message.into())
}

#[cfg(test)]
mod tests;
