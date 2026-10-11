//! Complete Tower128 MultiStark relations over a dense WHIR commitment and one packed-bit
//! table commitment, in prime-field circuits.
//!
//! ```text
//!     tables        one configured table is committed as bits, every other table densely
//!     commitment    one cap: the dense roots, then the packed roots, 2^c of each
//!     transcript    relation prefix, dense binding, packed binding, relation reduction,
//!                   dense opening, packed opening, preprocessing opening, relation closing
//!     evaluations   both openings merged back into protocol order before the AIRs close
//! ```
//!
//! The bit-committed table's AIR assumes a Boolean trace, and no other AIR does. Its cells are
//! bits because the packed commitment can represent nothing else, and every value the relation
//! reads from that table arrives through the column batch, the bit ring switch and the packed
//! WHIR opening. The table index is fixed at construction and bound into the identity, so a
//! proof cannot move the table to the dense side.
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::hash::Hash;

use p3_air::Air;
use p3_binary_field::BinaryField128;
use p3_bus::BusSymbolicBuilder;
use p3_challenger::{CanObserve, CanSampleUniformBits, FieldChallenger, GrindingChallenger};
use p3_circuit::ops::binary_encoding::PrimeBinaryEncoding;
use p3_circuit::ops::binary_host::BinaryCircuitHost;
use p3_circuit::ops::{BinaryTower128Target, ByteHash, bytes_to_limbs};
use p3_circuit::{CircuitBuilder, ExprId};
use p3_field::{ExtensionField, Field, PrimeCharacteristicRing, PrimeField64};
use p3_lookup::InteractionSymbolicBuilder;
use p3_merkle_tree::MerkleCap;
use p3_multi_stark::MultiStarkProof;
use p3_multilinear_util::point::Point;
use p3_sumcheck::layout::{self, Layout, SuffixProver};
use p3_sumcheck::{OpeningBatch, OpeningProtocol, TableSpec};
use p3_whir::WhirConfig;

use super::binary_indexed::{BinaryIndexedLookupProofTargets, NativeIndexedInput};
use super::binary_multi_stark::relation::{
    BinaryMultiStarkRelation, BinaryMultiStarkRelationShape, BinaryRelationProof,
};
use super::{
    BinaryAirConstraintPlan, BinaryProductGkrProofTargets, InputResourceUsage,
    NativeBinaryProductGkrInput, VerificationError, VerifierLimits,
};
use crate::BinaryTower128Challenger;
use crate::artifact::binary_native::{BinaryNativeMixedWhirConfig, NativeMmcs};
use crate::pcs::binary::{
    BinaryBooleanWhirTraceInputShape, BinaryBooleanWhirTraceProofTargets,
    BinaryBooleanWhirTraceVerifier, BinaryGenericSumcheckProofTargets, BinaryWhirInputShape,
    BinaryWhirProofTargets, BinaryWhirVerifier, NativeBinaryBooleanWhirTraceInput,
    NativeBinaryGenericSumcheckInput, NativeBinaryWhirInput,
};

type F = BinaryField128;
/// A WHIR configuration and the byte Merkle tree it commits with.
type WhirParameters<'a, C> = (&'a WhirConfig<BinaryField128, F, C>, &'a NativeMmcs<F>);

/// Proof-independent input shape including the trusted AIR program.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BinaryMixedWhirMultiStarkInputShape {
    relation: Arc<BinaryMultiStarkRelationShape<F, F>>,
    packed_table: usize,
    dense: BinaryWhirInputShape<F>,
    packed: BinaryBooleanWhirTraceInputShape,
    preprocessed: Option<MixedPreprocessedInputShape>,
    cap_height: usize,
}

/// Trusted preprocessing authority, supplied independently of every proof.
/// The commitment is dense and must belong to the ordered nonempty preprocessing tables at
/// the fixed AIR heights. Its PCS geometry may differ from the main trace.
#[derive(Clone, Debug)]
pub struct BinaryMixedWhirMultiStarkPreprocessing<PC> {
    pub config: WhirConfig<BinaryField128, F, PC>,
    pub hash: ByteHash,
    pub cap_height: usize,
    pub commitment: MerkleCap<F, [u8; 32]>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct MixedPreprocessedInputShape {
    opening: BinaryWhirInputShape<F>,
    commitment: Vec<[u8; 32]>,
}

impl MixedPreprocessedInputShape {
    fn constant_cap<H, CF>(
        &self,
        b: &mut CircuitBuilder<CF>,
    ) -> Result<Vec<Vec<ExprId>>, VerificationError>
    where
        CF: Field + Eq + Hash,
        H: BinaryCircuitHost<CF>,
    {
        H::check_carrier()?;
        self.commitment
            .iter()
            .map(|root| {
                let digest = bytes_to_limbs(root)
                    .into_iter()
                    .map(|word| Ok(b.define_const(H::encode_u16(word)?)))
                    .collect::<Result<Vec<_>, VerificationError>>()?;
                b.check_construction_limits()?;
                Ok(digest)
            })
            .collect()
    }
}

#[derive(Clone, Debug)]
pub struct BinaryMixedWhirMultiStarkProofTargets {
    /// The dense roots, then the packed roots.
    pub commitment: Vec<Vec<ExprId>>,
    pub bus: Option<BinaryProductGkrProofTargets>,
    pub sumcheck: BinaryGenericSumcheckProofTargets,
    pub indexed: Option<BinaryIndexedLookupProofTargets>,
    pub dense: BinaryWhirProofTargets,
    pub packed: BinaryBooleanWhirTraceProofTargets,
    pub preprocessed_opening: Option<BinaryWhirProofTargets>,
}

impl BinaryMixedWhirMultiStarkInputShape {
    /// The relation identity, the bit-committed table, both opening shapes and the trusted
    /// preprocessing shape and cap.
    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "only the unit tests write the mixed verifier identity"
        )
    )]
    pub(crate) fn write_identity(
        &self,
        w: &mut crate::artifact::wire::Writer,
    ) -> Result<(), crate::artifact::ArtifactError> {
        self.relation.write_identity(w)?;
        w.write_count("binary native mixed WHIR packed table", self.packed_table)?;
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
            .map(BinaryAirConstraintPlan::public_value_count)
    }

    /// Allocates cap, bus, sumcheck, indexed reduction and both PCS witnesses in order.
    /// Public values are allocated and bound separately by the caller.
    pub fn allocate_targets<BF, EF>(
        &self,
        b: &mut CircuitBuilder<EF>,
    ) -> Result<BinaryMixedWhirMultiStarkProofTargets, VerificationError>
    where
        BF: PrimeField64,
        EF: ExtensionField<BF> + Eq + Hash,
    {
        let commitment = (0..2usize << self.cap_height)
            .map(|_| {
                b.alloc_private_input_array::<16>("binary mixed WHIR MultiStark commitment")
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
        let dense = self.dense.allocate_targets::<BF, EF>(b)?;
        let packed = self.packed.allocate_targets::<BF, EF>(b)?;
        let preprocessed_opening = self
            .preprocessed
            .as_ref()
            .map(|preprocessed| preprocessed.opening.allocate_targets::<BF, EF>(b))
            .transpose()?;
        Ok(BinaryMixedWhirMultiStarkProofTargets {
            commitment,
            bus,
            sumcheck,
            indexed,
            dense,
            packed,
            preprocessed_opening,
        })
    }
}

/// Bounded witness material. It conveys no independent verification authority.
#[derive(Clone, Debug)]
pub struct NativeBinaryMixedWhirMultiStarkInput {
    shape: BinaryMixedWhirMultiStarkInputShape,
    commitment: Vec<[u8; 32]>,
    bus: Option<NativeBinaryProductGkrInput<F, F>>,
    sumcheck: NativeBinaryGenericSumcheckInput<F, F>,
    indexed: Option<NativeIndexedInput<F, F>>,
    dense: NativeBinaryWhirInput<F>,
    packed: NativeBinaryBooleanWhirTraceInput,
    preprocessed_opening: Option<NativeBinaryWhirInput<F>>,
}

impl NativeBinaryMixedWhirMultiStarkInput {
    pub const fn shape(&self) -> &BinaryMixedWhirMultiStarkInputShape {
        &self.shape
    }

    pub fn private_values<EF: Field>(
        &self,
        expected: &BinaryMixedWhirMultiStarkInputShape,
    ) -> Result<Vec<EF>, VerificationError> {
        if &self.shape != expected {
            return Err(invalid(
                "binary mixed WHIR MultiStark input belongs to another verifier",
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
                    "binary mixed WHIR MultiStark bus input shape mismatch",
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
                    "binary mixed WHIR MultiStark indexed input shape mismatch",
                ));
            }
        }
        values.extend(self.dense.private_values::<EF>(&expected.dense)?);
        values.extend(self.packed.private_values::<EF>(&expected.packed)?);
        match (&expected.preprocessed, &self.preprocessed_opening) {
            (Some(shape), Some(input)) => {
                values.extend(input.private_values::<EF>(&shape.opening)?);
            }
            (None, None) => {}
            _ => {
                return Err(invalid(
                    "binary mixed WHIR MultiStark preprocessing input shape mismatch",
                ));
            }
        }
        Ok(values)
    }
}

/// Trusted binary MultiStark verifier over a dense WHIR commitment and a packed-bit commitment
/// of one table, both on one byte Merkle tree configuration.
///
/// Binds caller-owned public values through the complete AIR, sumcheck, and authenticated PCS
/// relation. The dense part opens every other table as the dense WHIR verifier does; the
/// packed part opens the bit-committed table through column batching, the bit ring switch and
/// a packed WHIR opening. Periodic constants and preprocessing authority are fixed by
/// construction. Native binary buses are reduced through the authenticated AIR sumcheck.
#[derive(Clone, Debug)]
pub struct BinaryMixedWhirMultiStarkVerifier {
    input: BinaryMixedWhirMultiStarkInputShape,
    relation: BinaryMultiStarkRelation<F, F>,
    /// Whether each main opening batch, in protocol order, belongs to the packed table.
    packed_batches: Vec<bool>,
    dense: BinaryWhirVerifier<F>,
    packed: BinaryBooleanWhirTraceVerifier,
    preprocessed: Option<BinaryWhirVerifier<F>>,
    usage: InputResourceUsage,
}

impl BinaryMixedWhirMultiStarkVerifier {
    /// `packed_table` names the one AIR whose main trace is committed as bits. That AIR, and
    /// only that AIR, must assume a Boolean trace, and its main trace must be opened as one
    /// batch: every column at the current row, and every column or none one row ahead.
    /// `packed` is the packed WHIR configuration over the bit stack of that table, seven
    /// variables shorter. Both parts share `hash` and `cap_height`.
    #[expect(
        clippy::too_many_arguments,
        reason = "The verifier keeps protocol inputs explicit."
    )]
    pub fn with_limits<A, PC>(
        airs: &[&A],
        heights: &[usize],
        packed_table: usize,
        dense: &WhirConfig<BinaryField128, F, PC>,
        packed: &WhirConfig<BinaryField128, F, PC>,
        hash: ByteHash,
        cap_height: usize,
        pow_bits: usize,
        max_tau_draws: usize,
        limits: &VerifierLimits,
    ) -> Result<Self, VerificationError>
    where
        A: Air<InteractionSymbolicBuilder<F, F>> + Air<BusSymbolicBuilder<F, F>>,
        PC: FieldChallenger<F> + GrindingChallenger<Witness = F>,
    {
        Self::build(
            airs,
            heights,
            packed_table,
            (dense, packed),
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
    #[expect(
        clippy::too_many_arguments,
        reason = "The verifier keeps protocol inputs explicit."
    )]
    pub fn with_preprocessing<A, PC>(
        airs: &[&A],
        heights: &[usize],
        packed_table: usize,
        dense: &WhirConfig<BinaryField128, F, PC>,
        packed: &WhirConfig<BinaryField128, F, PC>,
        hash: ByteHash,
        cap_height: usize,
        pow_bits: usize,
        max_tau_draws: usize,
        preprocessing: BinaryMixedWhirMultiStarkPreprocessing<PC>,
        limits: &VerifierLimits,
    ) -> Result<Self, VerificationError>
    where
        A: Air<InteractionSymbolicBuilder<F, F>> + Air<BusSymbolicBuilder<F, F>>,
        PC: FieldChallenger<F> + GrindingChallenger<Witness = F>,
    {
        Self::build(
            airs,
            heights,
            packed_table,
            (dense, packed),
            hash,
            cap_height,
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
        (dense_config, packed_config): (
            &WhirConfig<BinaryField128, F, PC>,
            &WhirConfig<BinaryField128, F, PC>,
        ),
        hash: ByteHash,
        cap_height: usize,
        pow_bits: usize,
        max_tau_draws: usize,
        preprocessing: Option<BinaryMixedWhirMultiStarkPreprocessing<PC>>,
        limits: &VerifierLimits,
    ) -> Result<Self, VerificationError>
    where
        A: Air<InteractionSymbolicBuilder<F, F>> + Air<BusSymbolicBuilder<F, F>>,
        PC: FieldChallenger<F> + GrindingChallenger<Witness = F>,
    {
        if packed_table >= airs.len() {
            return Err(invalid(
                "binary mixed WHIR MultiStark packed table index exceeds the AIRs",
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
                "binary mixed WHIR MultiStark bit-committed table is not exactly the Boolean-assuming AIR",
            ));
        }
        let bits_committed: Vec<bool> = (0..airs.len()).map(|i| i == packed_table).collect();
        let (relation, main_protocol, preprocessed_protocol) =
            BinaryMultiStarkRelation::build_with_bit_tables(
                airs,
                heights,
                &bits_committed,
                pow_bits,
                max_tau_draws,
                preprocessing.is_some(),
                limits,
            )?;
        // One main table per AIR, in AIR order, so the AIR index names the protocol table.
        if main_protocol.table_shapes().len() != airs.len() {
            return Err(invalid(
                "binary mixed WHIR MultiStark main tables do not match the AIRs",
            ));
        }
        let (dense_protocol, packed_protocol) = split_protocol(&main_protocol, packed_table)?;
        let packed_batches = main_protocol
            .iter_openings()
            .map(|(table, _)| table == packed_table)
            .collect();
        let mut usage = relation.usage;
        let order = SuffixProver::<F, F>::variable_order();
        let dense = BinaryWhirVerifier::<F>::with_limits(
            dense_config,
            dense_protocol,
            order,
            hash,
            cap_height,
            limits,
        )?;
        let mut dense_usage = dense.input_resource_usage();
        dense_usage.instances = 0;
        usage.merge(limits, dense_usage)?;
        let packed = BinaryBooleanWhirTraceVerifier::with_limits(
            packed_config,
            packed_protocol,
            hash,
            cap_height,
            limits,
        )?;
        // The relation already charges the bit-committed table itself.
        let mut packed_usage = packed.input_resource_usage();
        packed_usage.instances = packed_usage.instances.checked_sub(1).ok_or(
            VerificationError::ResourceArithmeticOverflow {
                component: "binary mixed WHIR packed instance accounting",
            },
        )?;
        usage.merge(limits, packed_usage)?;
        let (preprocessed, preprocessed_input) = if let Some(preprocessing) = preprocessing {
            let verifier = BinaryWhirVerifier::<F>::with_limits(
                &preprocessing.config,
                preprocessed_protocol.expect("checked preprocessing protocol"),
                order,
                preprocessing.hash,
                preprocessing.cap_height,
                limits,
            )?;
            if preprocessing.commitment.num_roots() != 1usize << preprocessing.cap_height {
                return Err(invalid(
                    "binary mixed WHIR MultiStark trusted preprocessing cap shape mismatch",
                ));
            }
            let mut preprocessed_usage = verifier.input_resource_usage();
            preprocessed_usage.instances = 0;
            usage.merge(limits, preprocessed_usage)?;
            usage.add_metadata_entries(limits, preprocessing.commitment.num_roots())?;
            let input = MixedPreprocessedInputShape {
                opening: verifier.input_shape(),
                commitment: preprocessing.commitment.roots().to_vec(),
            };
            (Some(verifier), Some(input))
        } else {
            (None, None)
        };
        let input = BinaryMixedWhirMultiStarkInputShape {
            relation: relation.input.clone(),
            packed_table,
            dense: dense.input_shape(),
            packed: packed.input_shape(),
            preprocessed: preprocessed_input,
            cap_height,
        };
        Ok(Self {
            input,
            relation,
            packed_batches,
            dense,
            packed,
            preprocessed,
            usage,
        })
    }

    pub fn input_shape(&self) -> BinaryMixedWhirMultiStarkInputShape {
        self.input.clone()
    }
    pub const fn input_resource_usage(&self) -> InputResourceUsage {
        self.usage
    }

    /// Splits per-batch items of the main protocol into the dense and the packed opening's,
    /// each in protocol order.
    fn split<T: Clone>(&self, items: &[T]) -> Result<(Vec<T>, Vec<T>), VerificationError> {
        if items.len() != self.packed_batches.len() {
            return Err(invalid(
                "binary mixed WHIR MultiStark opening count mismatch",
            ));
        }
        let (mut dense, mut packed) = (Vec::new(), Vec::new());
        for (item, &is_packed) in items.iter().zip(&self.packed_batches) {
            if is_packed {
                packed.push(item.clone());
            } else {
                dense.push(item.clone());
            }
        }
        Ok((dense, packed))
    }

    /// Puts both openings' per-batch items back into protocol order.
    fn merge<T>(&self, dense: Vec<T>, packed: Vec<T>) -> Result<Vec<T>, VerificationError> {
        let (mut dense, mut packed) = (dense.into_iter(), packed.into_iter());
        let merged = self
            .packed_batches
            .iter()
            .map(|&is_packed| {
                if is_packed {
                    packed.next()
                } else {
                    dense.next()
                }
            })
            .collect::<Option<Vec<_>>>()
            .ok_or_else(|| {
                invalid("binary mixed WHIR MultiStark opening returned too few batches")
            })?;
        if dense.next().is_some() || packed.next().is_some() {
            return Err(invalid(
                "binary mixed WHIR MultiStark opening returned too many batches",
            ));
        }
        Ok(merged)
    }

    /// The dense half and the packed half of a cap, `2^c` roots each.
    fn split_cap<'a, T>(&self, cap: &'a [T]) -> Result<(&'a [T], &'a [T]), VerificationError> {
        let roots = 1usize << self.input.cap_height;
        if cap.len() != 2 * roots {
            return Err(invalid(
                "binary mixed WHIR MultiStark cap does not hold one cap per part",
            ));
        }
        Ok(cap.split_at(roots))
    }

    /// Checks all AIR obligations and authenticates their committed openings.
    /// Public targets are the caller's actual statement, in instance order.
    /// Returns the exact ordinary challenger after the fixed stratified query schedule.
    pub fn verify<BF, EF>(
        &self,
        b: &mut CircuitBuilder<EF>,
        mut ch: BinaryTower128Challenger,
        public: &[Vec<BinaryTower128Target>],
        proof: &BinaryMixedWhirMultiStarkProofTargets,
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
        let (dense_cap, packed_cap) = self.split_cap(&proof.commitment)?;
        let zero = b.binary128_constant(0)?;
        let (dense_points, packed_points) =
            self.split(&self.relation.zero_points(false, zero.clone()))?;
        self.dense
            .check_targets(dense_cap, &dense_points, &proof.dense)?;
        self.packed
            .check_targets(packed_cap, &packed_points, &proof.packed)?;
        let preprocessed_cap = match (
            &self.preprocessed,
            &self.input.preprocessed,
            &proof.preprocessed_opening,
        ) {
            (Some(verifier), Some(shape), Some(proof)) => {
                let cap = shape.constant_cap::<PrimeBinaryEncoding<BF>, EF>(b)?;
                let points = self.relation.zero_points(true, zero);
                verifier.check_targets(&cap, &points, proof)?;
                Some(cap)
            }
            (None, None, None) => None,
            _ => {
                return Err(invalid(
                    "binary mixed WHIR MultiStark preprocessed opening shape mismatch",
                ));
            }
        };
        self.relation
            .observe_prefix::<BF, EF>(b, &mut ch, preprocessed_cap.as_deref())?;
        self.dense
            .observe_commitment::<BF, EF>(b, &mut ch, dense_cap)?;
        self.packed
            .observe_commitment::<BF, EF>(b, &mut ch, packed_cap)?;
        let reduction = self.relation.reduce::<BF, EF>(b, ch, public, &common)?;
        let (dense_points, packed_points) = self.split(&reduction.main_points)?;
        let (dense_evals, ch) = self.dense.verify_at::<BF, EF>(
            b,
            reduction.challenger.clone(),
            dense_cap,
            &dense_points,
            &proof.dense,
        )?;
        let (packed_evals, mut continuation) =
            self.packed
                .verify_at::<BF, EF>(b, ch, packed_cap, &packed_points, &proof.packed)?;
        let main_evals = self.merge(dense_evals, packed_evals)?;
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
    #[cfg_attr(
        not(test),
        expect(dead_code, reason = "only the unit tests import mixed proofs")
    )]
    pub(crate) fn import_native<C, Ch>(
        &self,
        dense: &WhirConfig<BinaryField128, F, C>,
        packed: &WhirConfig<BinaryField128, F, C>,
        mmcs: &NativeMmcs<F>,
        preprocessed: Option<WhirParameters<'_, C>>,
        public: &[Vec<F>],
        proof: &MultiStarkProof<BinaryNativeMixedWhirConfig>,
        ch: &mut Ch,
    ) -> Result<NativeBinaryMixedWhirMultiStarkInput, VerificationError>
    where
        C: FieldChallenger<F> + GrindingChallenger<Witness = F>,
        Ch: FieldChallenger<F>
            + CanSampleUniformBits<F>
            + GrindingChallenger<Witness = F>
            + CanObserve<MerkleCap<F, [u8; 32]>>
            + Clone,
    {
        self.relation.check_native(public, proof)?;
        let (dense_cap, packed_cap) = self.split_cap(proof.commitment.roots())?;
        let (dense_cap, packed_cap) = (
            MerkleCap::<F, _>::new(dense_cap.to_vec()),
            MerkleCap::<F, _>::new(packed_cap.to_vec()),
        );
        let packed_proof = proof.opening.packed.as_ref().ok_or_else(|| {
            invalid("binary mixed WHIR MultiStark native proof has no packed opening")
        })?;
        let points: Vec<_> = self
            .relation
            .zero_points(false, F::ZERO)
            .into_iter()
            .map(Point::new)
            .collect();
        let (dense_points, packed_points) = self.split(&points)?;
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
                let cap = MerkleCap::<F, _>::new(shape.commitment.clone());
                let points: Vec<_> = self
                    .relation
                    .zero_points(true, F::ZERO)
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
                    "binary mixed WHIR MultiStark native preprocessing shape mismatch",
                ));
            }
        };
        let mut staged = ch.clone();
        self.relation.observe_native_prefix(
            &mut staged,
            preprocessing.as_ref().map(|(_, _, _, _, cap)| cap),
        );
        layout::observe_commitment::<F, _, _>(&mut staged, dense_cap.clone());
        layout::observe_commitment::<F, _, _>(&mut staged, packed_cap.clone());
        let reduction = self.relation.reduce_native(public, proof, &mut staged)?;
        let (dense_points, packed_points) = self.split(&reduction.main_points)?;
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
        Ok(NativeBinaryMixedWhirMultiStarkInput {
            shape: self.input.clone(),
            commitment: proof.commitment.roots().to_vec(),
            bus: reduction.bus,
            sumcheck: reduction.sumcheck,
            indexed: reduction.indexed,
            dense: dense_opening,
            packed: packed_opening,
            preprocessed_opening,
        })
    }
}

/// Splits a main protocol into the dense tables, in order, and the bit-committed table alone.
///
/// The bit-committed table must be opened in exactly one batch, every column at the current
/// row and every column or none one row ahead, which is the batch the column batching of the
/// packed opening reads.
fn split_protocol(
    protocol: &OpeningProtocol,
    packed_table: usize,
) -> Result<(OpeningProtocol, OpeningProtocol), VerificationError> {
    let shapes = protocol.table_shapes();
    if packed_table >= shapes.len() {
        return Err(invalid(
            "binary mixed WHIR MultiStark packed table is not a committed table",
        ));
    }
    let mut schedules = alloc::vec![Vec::new(); shapes.len()];
    for (table, batch) in protocol.iter_openings() {
        schedules[table].push(batch.clone());
    }
    let width = shapes[packed_table].width();
    let all: Vec<usize> = (0..width).collect();
    let complete = |batch: &OpeningBatch<usize>| {
        batch.current() == all.as_slice()
            && (batch.next().is_empty() || batch.next() == all.as_slice())
    };
    if !matches!(schedules[packed_table].as_slice(), [batch] if complete(batch)) {
        return Err(invalid(
            "binary mixed WHIR MultiStark packed table is not opened as one complete batch",
        ));
    }
    let (mut dense, mut packed) = (Vec::new(), Vec::new());
    for (table, (shape, schedule)) in shapes.into_iter().zip(schedules).enumerate() {
        let spec = TableSpec::new(shape, schedule);
        if table == packed_table {
            packed.push(spec);
        } else {
            dense.push(spec);
        }
    }
    if dense.is_empty() {
        return Err(invalid(
            "binary mixed WHIR MultiStark dense commitment holds no table",
        ));
    }
    Ok((OpeningProtocol::new(dense), OpeningProtocol::new(packed)))
}

fn invalid(message: &'static str) -> VerificationError {
    VerificationError::InvalidProofShape(message.into())
}

#[cfg(test)]
mod tests;
