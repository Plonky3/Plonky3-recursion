//! Closed composite of a dense WHIR commitment and one packed-bit table commitment, over
//! Tower128 values and challenges or Poly64 values and Poly192 challenges.
//!
//! ```text
//!     witness      tables in instance order; one configured table goes to the bit commitment,
//!                  every other table to the dense stacked commitment, order kept
//!     commitment   one cap: the dense roots, then the packed roots, arity^c of each
//!     transcript   dense binding, then packed binding, inside one main-commitment bracket
//!     opening      dense tables at their points, then the packed table at its point
//! ```
//!
//! Each part runs its own library transcript in sequence. Nothing is sampled between the two
//! bindings, since WHIR draws its out-of-domain samples when it opens. The split position is
//! a function of the configured tree arity and cap height alone, and the packed table index is
//! fixed by the configuration, so the prover cannot move a root or a table across the boundary.

use alloc::vec;

use p3_binary_field::{BinaryField128, BitCoordinates, Poly64, Poly192, TowerLevel};
use p3_binary_pcs::whir::{
    BinaryWhirDomain, BooleanWhirData, BooleanWhirError, BooleanWhirPcs, BooleanWhirProof,
};
use p3_binary_pcs::{
    BooleanTraceCommitment, BooleanTraceCommitmentData, BooleanTraceCommitmentError,
    BooleanTraceCommitmentProof, Coordinates,
};
use p3_challenger::fs::TranscriptField;
use p3_commit::MultilinearPcs;
use p3_field::Field;
use p3_multilinear_util::point::Point;
use p3_sumcheck::layout::plan_stacked_layout;
use p3_sumcheck::ring_switch::bits::BitRingSwitch;
use p3_sumcheck::{
    OpeningEvals, OpeningProtocol, PrescribedOpeningSecurity, PrescribedPointPcs, TableSpec,
};
use p3_whir::{
    PcsProof, VerifierError, WhirConfig, WhirConfigError, WhirDomain, WhirProver, WhirProverData,
};
use serde::{Deserialize, Serialize};

use super::*;
use crate::pcs::binary::MerkleArity;

type Cap<F> = MerkleCap<F, [u8; 32]>;
type DensePcs<F, E> = WhirProver<
    E,
    F,
    BinaryWhirDomain<F>,
    NativeWhirMmcs<F>,
    BinaryNativeChallenger<F>,
    SuffixProver<F, E>,
>;
type DenseProof<F, E> = PcsProof<F, E, NativeWhirMmcs<F>>;
type PackedPcs<F, E> = BooleanTraceCommitment<
    E,
    BooleanWhirPcs<F, E, BinaryWhirDomain<F>, NativeWhirMmcs<F>, BinaryNativeChallenger<F>>,
>;
type PackedError = BooleanTraceCommitmentError<BooleanWhirError>;
type PackedData<F, E> = BooleanTraceCommitmentData<F, BooleanWhirData<F, E, NativeWhirMmcs<F>>>;
type PackedProof<F, E> = BooleanTraceCommitmentProof<E, BooleanWhirProof<F, E, NativeWhirMmcs<F>>>;
/// One part's share of an opening: its tables' batches, and their points in order.
type Part<E> = (OpeningProtocol, Vec<Point<E>>);

/// The mixed commitment over Tower128 values and challenges.
pub type MixedWhirPcs = NativeMixedWhirPcs<BinaryField128, BinaryField128>;
/// The opening proof of a [`MixedWhirPcs`].
pub type MixedWhirProof = NativeMixedWhirProof<BinaryField128, BinaryField128>;
/// Mixed commitment parameters over Tower128 values and challenges.
pub type BinaryNativeMixedWhirPcsParameters =
    NativeMixedWhirPcsParameters<BinaryNativeWhirPcsParameters<BinaryField128>>;
/// Mixed commitment parameters over Poly64 values and Poly192 challenges.
pub type BinaryNativePolyMixedWhirPcsParameters =
    NativeMixedWhirPcsParameters<BinaryNativePolyWhirPcsParameters>;
/// Mixed configuration over Tower128 values and challenges.
pub type BinaryNativeMixedWhirConfig = NativeMixedWhirConfig<BinaryField128, BinaryField128>;
/// Mixed configuration over Poly64 values and Poly192 challenges.
pub type BinaryNativePolyMixedWhirConfig = NativeMixedWhirConfig<Poly64, Poly192>;

/// Why the composite commitment refused a witness, an opening or a proof.
#[derive(Debug, thiserror::Error)]
pub enum MixedWhirError<D> {
    /// The dense commitment refused.
    #[error("dense commitment refused: {0:?}")]
    Dense(D),
    /// The packed-bit commitment refused.
    #[error("packed-bit commitment refused: {0}")]
    Packed(PackedError),
    /// A table, point, cap or proof part does not match the configured split.
    #[error("mixed commitment shape mismatch: {0}")]
    Shape(&'static str),
}

/// Parameters of one part of a mixed commitment: a released WHIR configuration over `Val`
/// cells with `Challenge` challenges, and the Merkle trees it commits on.
pub trait MixedWhirPartParameters {
    /// The committed cells, and the elements the packed part packs bits into.
    type Val: TowerLevel;
    /// The field every challenge is drawn from.
    type Challenge: BitCoordinates + ExtensionField<Self::Val>;
    /// The part's released WHIR configuration.
    fn whir(&self) -> &WhirConfig<Self::Challenge, Self::Val, BinaryNativeChallenger<Self::Val>>;
    /// The hash, tree arity and cap height of the part's Merkle trees.
    fn trees(&self) -> (ByteHash, MerkleArity, usize);
}

impl MixedWhirPartParameters for BinaryNativeWhirPcsParameters<BinaryField128> {
    type Val = BinaryField128;
    type Challenge = BinaryField128;
    fn whir(
        &self,
    ) -> &WhirConfig<BinaryField128, BinaryField128, BinaryNativeChallenger<BinaryField128>> {
        &self.config
    }
    fn trees(&self) -> (ByteHash, MerkleArity, usize) {
        (self.hash, self.arity, self.cap_height)
    }
}

impl MixedWhirPartParameters for BinaryNativePolyWhirPcsParameters {
    type Val = Poly64;
    type Challenge = Poly192;
    fn whir(&self) -> &WhirConfig<Poly192, Poly64, BinaryNativeChallenger<Poly64>> {
        &self.config
    }
    fn trees(&self) -> (ByteHash, MerkleArity, usize) {
        (self.hash, self.arity, self.cap_height)
    }
}

/// Dense stacked WHIR over every table but one, and a bit commitment over that one table, of
/// `F` cells with `E` challenges.
///
/// Both parts' Merkle trees have one hash, one arity and one cap height, which
/// [`Self::from_parameters`] enforces, so each part contributes `cap_roots` roots to the
/// shared commitment.
pub struct NativeMixedWhirPcs<F: Field, E: ExtensionField<F>> {
    dense: DensePcs<F, E>,
    packed: Option<(PackedPcs<F, E>, usize)>,
    cap_roots: usize,
}

/// Prover data of both parts, and where each instance's table is retained.
#[derive(Clone)]
pub struct MixedWhirData<F: Field, E: ExtensionField<F>> {
    dense: WhirProverData<F, E, NativeWhirMmcs<F>, SuffixProver<F, E>>,
    packed: Option<PackedData<F, E>>,
    slots: Vec<Slot>,
}

/// The part and position holding one instance's committed table.
#[derive(Clone, Copy, Debug)]
enum Slot {
    Dense(usize),
    Packed(usize),
}

/// The dense opening, then the packed opening when a table is bit-committed.
#[derive(Clone, Serialize, Deserialize)]
#[serde(bound(
    serialize = "DenseProof<F, E>: Serialize, PackedProof<F, E>: Serialize",
    deserialize = "DenseProof<F, E>: Deserialize<'de>, PackedProof<F, E>: Deserialize<'de>"
))]
pub struct NativeMixedWhirProof<F: Field, E: ExtensionField<F>> {
    pub dense: DenseProof<F, E>,
    pub packed: Option<PackedProof<F, E>>,
}

/// Trusted parameters of the mixed commitment: dense WHIR over every table but the packed one,
/// and, when there is a packed table, a packed-bit WHIR commitment of it. Each part's
/// parameters are a `P`.
///
/// Both parts use one hash, one tree arity and one cap height, which
/// [`Self::with_packed_table`] enforces.
/// The preprocessing commitment holds no packed table.
#[derive(Clone)]
pub struct NativeMixedWhirPcsParameters<P> {
    pub(in crate::artifact::binary_native) dense: P,
    pub(in crate::artifact::binary_native) packed: Option<PackedTableParameters<P>>,
}

/// The packed-bit part: the table it commits, the variable count of that table's bit stack,
/// and WHIR parameters over [`NativeMixedWhirPcsParameters::ABSORBED_VARIABLES`] variables
/// fewer, the ones each field element absorbs.
#[derive(Clone)]
pub(in crate::artifact::binary_native) struct PackedTableParameters<P> {
    pub(in crate::artifact::binary_native) whir: P,
    pub(in crate::artifact::binary_native) table: usize,
    pub(in crate::artifact::binary_native) bit_variables: usize,
}

impl<P: MixedWhirPartParameters> NativeMixedWhirPcsParameters<P> {
    /// Row variables one packed field element absorbs: seven for a Tower128 element, six for a
    /// Poly64 one.
    pub const ABSORBED_VARIABLES: usize = BitRingSwitch::<P::Val, P::Challenge>::ABSORBED;

    /// A dense commitment of every table: the preprocessing commitment's parameters. Setup
    /// refuses them for the main commitment, which bit-commits one table through
    /// [`Self::with_packed_table`].
    pub const fn dense(dense: P) -> Self {
        Self {
            dense,
            packed: None,
        }
    }

    /// A dense commitment of every table but `table`, and `packed`, a commitment of the
    /// `bit_variables`-variable bit stack of `table`. Packed parameters naming another hash,
    /// tree arity or cap height than the dense ones are refused.
    pub fn with_packed_table(
        dense: P,
        packed: P,
        table: usize,
        bit_variables: usize,
    ) -> Result<Self, VerificationError> {
        if packed.trees() != dense.trees() {
            return Err(super::super::invalid(
                "binary native mixed WHIR parts differ in hash, tree arity or cap height",
            ));
        }
        Ok(Self {
            dense,
            packed: Some(PackedTableParameters {
                whir: packed,
                table,
                bit_variables,
            }),
        })
    }
}

impl<F, E> NativeMixedWhirPcs<F, E>
where
    F: TranscriptField + TowerLevel + Coordinates + Ord,
    E: BitCoordinates + ExtensionField<F>,
    BinaryWhirDomain<F>: WhirDomain<F, E>,
    BinaryNativeChallenger<F>:
        FieldChallenger<F> + GrindingChallenger<Witness = F> + CanSampleUniformBits<F>,
{
    /// Build both parts from checked parameters, on Merkle trees of the dense part's hash, arity
    /// and cap height.
    ///
    /// `packed` holds the bit commitment's parameters, the table it commits and the table's
    /// bit arity. Parameters naming another hash, tree arity or cap height are refused.
    pub(crate) fn from_parameters<P>(
        dense: &P,
        packed: Option<(&P, usize, usize)>,
    ) -> Result<Self, VerificationError>
    where
        P: MixedWhirPartParameters<Val = F, Challenge = E>,
    {
        let (hash, arity, cap_height) = dense.trees();
        let whir = |parameters: &P| -> DensePcs<F, E> {
            WhirProver::new(
                parameters.whir().clone(),
                BinaryWhirDomain::<F>::default(),
                NativeWhirMmcs::new(hash, arity, cap_height),
            )
        };
        let packed = packed
            .map(|(parameters, table, bit_variables)| {
                if parameters.trees() != (hash, arity, cap_height) {
                    return Err(super::super::invalid(
                        "binary native mixed WHIR parts differ in hash, tree arity or cap height",
                    ));
                }
                let bits = BooleanWhirPcs::new(whir(parameters), bit_variables).map_err(|_| {
                    super::super::invalid("binary native mixed WHIR bit configuration rejected")
                })?;
                Ok((BooleanTraceCommitment::from_commitment(bits), table))
            })
            .transpose()?;
        Self::new(whir(dense), packed, arity, cap_height)
    }

    /// Pair a dense commitment with an optional bit commitment of table `packed.1`.
    ///
    /// Both parts' Merkle trees compress `arity` digests per node and have caps of
    /// `cap_height` levels.
    fn new(
        dense: DensePcs<F, E>,
        packed: Option<(PackedPcs<F, E>, usize)>,
        arity: MerkleArity,
        cap_height: usize,
    ) -> Result<Self, VerificationError> {
        let cap_roots = arity
            .cap_roots(cap_height)
            .filter(|roots| roots.checked_mul(2).is_some())
            .ok_or_else(|| {
                super::super::invalid("binary native mixed WHIR cap height is invalid")
            })?;
        Ok(Self {
            dense,
            packed,
            cap_roots,
        })
    }

    fn packed_table(&self) -> Option<usize> {
        self.packed.as_ref().map(|(_, table)| *table)
    }

    /// Roots the shared cap holds: one cap per part.
    fn expected_roots(&self) -> usize {
        self.cap_roots << usize::from(self.packed.is_some())
    }

    /// Split a protocol by table into the dense tables, in order, and the packed table alone.
    fn split(&self, protocol: &OpeningProtocol) -> Result<[OpeningProtocol; 2], &'static str> {
        let shapes = protocol.table_shapes();
        let packed = self.packed_table();
        if packed.is_some_and(|table| table >= shapes.len()) {
            return Err("the packed table index exceeds the opened tables");
        }
        let mut schedules = vec![Vec::new(); shapes.len()];
        for (table, batch) in protocol.iter_openings() {
            schedules[table].push(batch.clone());
        }
        let mut sides = [Vec::new(), Vec::new()];
        for (table, (shape, schedule)) in shapes.into_iter().zip(schedules).enumerate() {
            sides[usize::from(packed == Some(table))].push(TableSpec::new(shape, schedule));
        }
        if sides[0].is_empty() {
            return Err("the dense commitment holds no table");
        }
        let [dense, packed] = sides;
        Ok([OpeningProtocol::new(dense), OpeningProtocol::new(packed)])
    }

    /// Split one entry per batch, such as its opening point, the way [`Self::split`] splits
    /// the batches.
    fn split_entries<T: Clone>(&self, protocol: &OpeningProtocol, entries: &[T]) -> [Vec<T>; 2] {
        let packed = self.packed_table();
        let mut sides = [Vec::new(), Vec::new()];
        for ((table, _), entry) in protocol.iter_openings().zip(entries) {
            sides[usize::from(packed == Some(table))].push(entry.clone());
        }
        sides
    }

    /// Check what both parts need before either one touches the transcript.
    fn split_opening(
        &self,
        protocol: &OpeningProtocol,
        points: &[Point<E>],
    ) -> Result<[Part<E>; 2], &'static str> {
        if points.len() != protocol.num_openings() {
            return Err("one opening point per batch is required");
        }
        let [dense, packed] = self.split(protocol)?;
        if (packed.num_openings() > 0) != self.packed.is_some() {
            return Err("the packed table is opened exactly when one is configured");
        }
        let [dense_points, packed_points] = self.split_entries(protocol, points);
        if dense.check_points(&dense_points).is_err()
            || packed.check_points(&packed_points).is_err()
        {
            return Err("an opening point does not name its table's rows");
        }
        Ok([(dense, dense_points), (packed, packed_points)])
    }

    /// Put both parts' evaluations back into protocol order.
    fn merge(
        &self,
        protocol: &OpeningProtocol,
        dense: Vec<OpeningEvals<E>>,
        packed: Vec<OpeningEvals<E>>,
    ) -> Result<Vec<OpeningEvals<E>>, &'static str> {
        let table = self.packed_table();
        let (mut dense, mut packed) = (dense.into_iter(), packed.into_iter());
        let merged = protocol
            .iter_openings()
            .map(|(index, _)| {
                if table == Some(index) {
                    packed.next()
                } else {
                    dense.next()
                }
            })
            .collect::<Option<Vec<_>>>()
            .ok_or("an opening part returned too few evaluations")?;
        if dense.next().is_some() || packed.next().is_some() {
            return Err("an opening part returned too many evaluations");
        }
        Ok(merged)
    }

    /// Refuse a masked table the bit commitment would refuse, before the transcript moves.
    ///
    /// Packed storage holds bits by construction; dense storage is scanned cell by cell.
    fn check_packed_table(
        pcs: &PackedPcs<F, E>,
        index: usize,
        table: &Table<F>,
    ) -> Result<(), PackedError> {
        let actual = plan_stacked_layout(&[table.shape()]).0;
        if actual != pcs.num_variables() {
            return Err(BooleanTraceCommitmentError::StackedArity {
                expected: pcs.num_variables(),
                actual,
            });
        }
        if table.packed_bits().is_some() {
            return Ok(());
        }
        let is_bit = |value: &F| *value == F::ZERO || *value == F::ONE;
        table
            .columns()
            .position(|column| !column.values().all(|value| is_bit(&value)))
            .map_or(Ok(()), |column| {
                Err(BooleanTraceCommitmentError::NonBooleanCell {
                    table: index,
                    column,
                })
            })
    }
}

/// Whether a protocol opens one table in one batch: every column at the current row, and
/// every column or none one row ahead.
fn is_complete_single_batch(protocol: &OpeningProtocol) -> bool {
    let shapes = protocol.table_shapes();
    let mut openings = protocol.iter_openings();
    let (Some((0, batch)), None, [shape]) = (openings.next(), openings.next(), shapes.as_slice())
    else {
        return false;
    };
    let all = (0..shape.width()).collect::<Vec<_>>();
    batch.current() == all.as_slice() && (batch.next().is_empty() || batch.next() == all.as_slice())
}

impl<F, E> MultilinearPcs<E, BinaryNativeChallenger<F>> for NativeMixedWhirPcs<F, E>
where
    F: TranscriptField + TowerLevel + Coordinates + Ord,
    E: BitCoordinates + ExtensionField<F>,
    BinaryWhirDomain<F>: WhirDomain<F, E>,
    BinaryNativeChallenger<F>: FieldChallenger<F>
        + GrindingChallenger<Witness = F>
        + CanSampleUniformBits<F>
        + CanObserve<Cap<F>>,
    PackedPcs<F, E>: PrescribedPointPcs<
            E,
            BinaryNativeChallenger<F>,
            Val = F,
            Commitment = Cap<F>,
            ProverData = PackedData<F, E>,
            Proof = PackedProof<F, E>,
            Error = PackedError,
            ProverError = PackedError,
            Witness = Vec<Table<F>>,
            OpeningProtocol = OpeningProtocol,
        >,
{
    type Val = F;
    type Commitment = Cap<F>;
    type ProverData = MixedWhirData<F, E>;
    type Proof = NativeMixedWhirProof<F, E>;
    type Error = MixedWhirError<VerifierError>;
    type ProverError = MixedWhirError<WhirConfigError>;
    type Witness = Vec<Table<F>>;
    type OpeningProtocol = OpeningProtocol;

    fn num_vars(&self) -> usize {
        MultilinearPcs::<E, BinaryNativeChallenger<F>>::num_vars(&self.dense)
    }

    fn commit(
        &self,
        witness: Vec<Table<F>>,
        challenger: &mut BinaryNativeChallenger<F>,
    ) -> Result<(Cap<F>, MixedWhirData<F, E>), Self::ProverError> {
        // Refusals of the witness precede the first binding, so they leave the transcript alone.
        let packed_table = self.packed_table();
        if let Some((pcs, index)) = &self.packed {
            let table = witness.get(*index).ok_or(MixedWhirError::Shape(
                "the packed table index exceeds the witness",
            ))?;
            Self::check_packed_table(pcs, *index, table).map_err(MixedWhirError::Packed)?;
        }
        let (mut dense_tables, mut packed_tables, mut slots) = (Vec::new(), Vec::new(), Vec::new());
        for (index, table) in witness.into_iter().enumerate() {
            if packed_table == Some(index) {
                slots.push(Slot::Packed(packed_tables.len()));
                packed_tables.push(table);
            } else {
                slots.push(Slot::Dense(dense_tables.len()));
                dense_tables.push(table);
            }
        }
        if dense_tables.is_empty() {
            return Err(MixedWhirError::Shape("the dense commitment holds no table"));
        }
        let dense_witness =
            SuffixProver::<F, E>::new_witness(dense_tables, self.dense.round_folding_factor(0));
        if dense_witness.num_variables() != self.dense.num_variables() {
            return Err(MixedWhirError::Shape(
                "the dense tables do not stack to the dense commitment's arity",
            ));
        }

        let (dense_cap, dense) = self
            .dense
            .commit(dense_witness, challenger)
            .map_err(MixedWhirError::Dense)?;
        // Both trees have the constructor's cap height. A cap of another size is a
        // configuration error, refused after its part's binding.
        if dense_cap.num_roots() != self.cap_roots {
            return Err(MixedWhirError::Shape(
                "the dense cap does not have the configured height",
            ));
        }
        let Some((pcs, _)) = &self.packed else {
            let data = MixedWhirData {
                dense,
                packed: None,
                slots,
            };
            return Ok((dense_cap, data));
        };
        let (packed_cap, packed) = pcs
            .commit(packed_tables, challenger)
            .map_err(MixedWhirError::Packed)?;
        if packed_cap.num_roots() != self.cap_roots {
            return Err(MixedWhirError::Shape(
                "the packed cap does not have the configured height",
            ));
        }
        let cap = MerkleCap::new([dense_cap.roots(), packed_cap.roots()].concat());
        let data = MixedWhirData {
            dense,
            packed: Some(packed),
            slots,
        };
        Ok((cap, data))
    }

    fn observe_commitment(&self, commitment: &Cap<F>, challenger: &mut BinaryNativeChallenger<F>) {
        match &self.packed {
            Some((pcs, _)) if commitment.num_roots() == self.expected_roots() => {
                let (dense, packed) = commitment.roots().split_at(self.cap_roots);
                self.dense
                    .observe_commitment(&MerkleCap::new(dense.to_vec()), challenger);
                pcs.observe_commitment(&MerkleCap::new(packed.to_vec()), challenger);
            }
            // A dense-only cap is bound whole. So is a mixed cap of any other length, which
            // `verify_at` then rejects.
            _ => self.dense.observe_commitment(commitment, challenger),
        }
    }

    fn open(
        &self,
        _prover_data: MixedWhirData<F, E>,
        _protocol: OpeningProtocol,
        _challenger: &mut BinaryNativeChallenger<F>,
    ) -> Result<NativeMixedWhirProof<F, E>, Self::ProverError> {
        Err(MixedWhirError::Shape(
            "the mixed commitment opens only at prescribed points",
        ))
    }

    fn verify(
        &self,
        _commitment: &Cap<F>,
        _proof: &NativeMixedWhirProof<F, E>,
        _challenger: &mut BinaryNativeChallenger<F>,
        _protocol: OpeningProtocol,
    ) -> Result<(), Self::Error> {
        Err(MixedWhirError::Shape(
            "the mixed commitment opens only at prescribed points",
        ))
    }
}

impl<F, E> PrescribedPointPcs<E, BinaryNativeChallenger<F>> for NativeMixedWhirPcs<F, E>
where
    F: TranscriptField + TowerLevel + Coordinates + Ord,
    E: BitCoordinates + ExtensionField<F>,
    BinaryWhirDomain<F>: WhirDomain<F, E>,
    BinaryNativeChallenger<F>: FieldChallenger<F>
        + GrindingChallenger<Witness = F>
        + CanSampleUniformBits<F>
        + CanObserve<Cap<F>>,
    PackedPcs<F, E>: PrescribedPointPcs<
            E,
            BinaryNativeChallenger<F>,
            Val = F,
            Commitment = Cap<F>,
            ProverData = PackedData<F, E>,
            Proof = PackedProof<F, E>,
            Error = PackedError,
            ProverError = PackedError,
            Witness = Vec<Table<F>>,
            OpeningProtocol = OpeningProtocol,
        >,
{
    /// The union of both parts' terms, over the product of their candidate sets.
    ///
    /// Every outer draw precedes both openings, so a prover holding a candidate list per
    /// part tries every pair. Each part's own reductions are charged over its own list.
    fn prescribed_security(&self, protocol: &OpeningProtocol) -> Option<PrescribedOpeningSecurity> {
        let [dense_protocol, packed_protocol] = self.split(protocol).ok()?;
        let dense = self.dense.prescribed_security(&dense_protocol)?;
        let Some((pcs, _)) = &self.packed else {
            return Some(dense);
        };
        if !is_complete_single_batch(&packed_protocol) {
            return None;
        }
        let packed = pcs.prescribed_security(&packed_protocol)?;
        if dense.candidates().is_none() || packed.candidates().is_none() {
            return None;
        }
        Some(PrescribedOpeningSecurity {
            log2_max_candidates: dense.log2_max_candidates + packed.log2_max_candidates,
            terms: [dense.terms, packed.terms].concat(),
        })
    }

    /// The packed table is committed one bit per cell, every other table one field element
    /// per cell.
    fn bit_region(&self, table: usize, width: usize) -> usize {
        if self.packed_table() == Some(table) {
            width
        } else {
            0
        }
    }

    fn open_at(
        &self,
        prover_data: MixedWhirData<F, E>,
        protocol: &OpeningProtocol,
        points: &[Point<E>],
        challenger: &mut BinaryNativeChallenger<F>,
    ) -> Result<NativeMixedWhirProof<F, E>, Self::ProverError> {
        let known = vec![None; protocol.num_openings()];
        self.open_at_known(prover_data, protocol, points, &known, challenger)
    }

    /// The packed part binds the supplied values of the packed table's batches in place of
    /// evaluating its columns. The dense part has no such path and evaluates its own batches.
    fn open_at_known(
        &self,
        prover_data: MixedWhirData<F, E>,
        protocol: &OpeningProtocol,
        points: &[Point<E>],
        known: &[Option<OpeningEvals<E>>],
        challenger: &mut BinaryNativeChallenger<F>,
    ) -> Result<NativeMixedWhirProof<F, E>, Self::ProverError> {
        let [
            (dense_protocol, dense_points),
            (packed_protocol, packed_points),
        ] = self
            .split_opening(protocol, points)
            .map_err(MixedWhirError::Shape)?;
        // The dense opening moves the transcript first, so the packed part's supplied values
        // are checked here.
        if known.len() != protocol.num_openings()
            || protocol
                .iter_openings()
                .zip(known)
                .any(|((_, batch), known)| {
                    known
                        .as_ref()
                        .is_some_and(|known| !batch.has_same_shape(known))
                })
        {
            return Err(MixedWhirError::Shape(
                "the supplied values do not match the opening batches",
            ));
        }
        let [dense_known, packed_known] = self.split_entries(protocol, known);
        let MixedWhirData { dense, packed, .. } = prover_data;
        let packed = match (&self.packed, packed) {
            (Some((pcs, _)), Some(data)) => Some((pcs, data)),
            (None, None) => None,
            _ => {
                return Err(MixedWhirError::Shape(
                    "the prover data does not match the configured parts",
                ));
            }
        };
        let dense = self
            .dense
            .open_at_known(
                dense,
                &dense_protocol,
                &dense_points,
                &dense_known,
                challenger,
            )
            .map_err(MixedWhirError::Dense)?;
        let packed = packed
            .map(|(pcs, data)| {
                pcs.open_at_known(
                    data,
                    &packed_protocol,
                    &packed_points,
                    &packed_known,
                    challenger,
                )
            })
            .transpose()
            .map_err(MixedWhirError::Packed)?;
        Ok(NativeMixedWhirProof { dense, packed })
    }

    fn verify_at(
        &self,
        commitment: &Cap<F>,
        proof: &NativeMixedWhirProof<F, E>,
        protocol: &OpeningProtocol,
        points: &[Point<E>],
        challenger: &mut BinaryNativeChallenger<F>,
    ) -> Result<Vec<OpeningEvals<E>>, Self::Error> {
        if commitment.num_roots() != self.expected_roots() {
            return Err(MixedWhirError::Shape(
                "the cap does not hold one cap per configured part",
            ));
        }
        if proof.packed.is_some() != self.packed.is_some() {
            return Err(MixedWhirError::Shape(
                "the proof parts do not match the configured parts",
            ));
        }
        let [
            (dense_protocol, dense_points),
            (packed_protocol, packed_points),
        ] = self
            .split_opening(protocol, points)
            .map_err(MixedWhirError::Shape)?;
        let (dense_cap, packed_cap) = commitment.roots().split_at(self.cap_roots);
        let dense = self
            .dense
            .verify_at(
                &MerkleCap::new(dense_cap.to_vec()),
                &proof.dense,
                &dense_protocol,
                &dense_points,
                challenger,
            )
            .map_err(MixedWhirError::Dense)?;
        let packed = match (&self.packed, &proof.packed) {
            (Some((pcs, _)), Some(opening)) => pcs
                .verify_at(
                    &MerkleCap::new(packed_cap.to_vec()),
                    opening,
                    &packed_protocol,
                    &packed_points,
                    challenger,
                )
                .map_err(MixedWhirError::Packed)?,
            _ => Vec::new(),
        };
        self.merge(protocol, dense, packed)
            .map_err(MixedWhirError::Shape)
    }
}

/// Complete native mixed dense and packed-bit WHIR configuration over `F` cells with `E`
/// challenges, constructed by its owner.
///
/// The preprocessing commitment is dense only.
pub struct NativeMixedWhirConfig<F: Field, E: ExtensionField<F>> {
    pub(crate) main: NativeMixedWhirPcs<F, E>,
    pub(crate) preprocessed: Option<NativeMixedWhirPcs<F, E>>,
}

impl<F: Field, E: ExtensionField<F>> NativeMixedWhirConfig<F, E> {
    pub(crate) fn new(
        main: NativeMixedWhirPcs<F, E>,
        preprocessed: Option<NativeMixedWhirPcs<F, E>>,
    ) -> Result<Self, VerificationError> {
        if preprocessed.as_ref().is_some_and(|pp| pp.packed.is_some()) {
            return Err(super::super::invalid(
                "binary native mixed WHIR preprocessing commits no packed table",
            ));
        }
        Ok(Self { main, preprocessed })
    }
}

impl<F, E> MultiStarkConfig for NativeMixedWhirConfig<F, E>
where
    F: TranscriptField + TowerLevel + Coordinates + Ord,
    E: BitCoordinates + ExtensionField<F>,
    BinaryWhirDomain<F>: WhirDomain<F, E>,
    BinaryNativeChallenger<F>: FieldChallenger<F>
        + GrindingChallenger<Witness = F>
        + CanSampleUniformBits<F>
        + CanObserve<Cap<F>>,
    PackedPcs<F, E>: PrescribedPointPcs<
            E,
            BinaryNativeChallenger<F>,
            Val = F,
            Commitment = Cap<F>,
            ProverData = PackedData<F, E>,
            Proof = PackedProof<F, E>,
            Error = PackedError,
            ProverError = PackedError,
            Witness = Vec<Table<F>>,
            OpeningProtocol = OpeningProtocol,
        >,
{
    type Val = F;
    type Challenge = E;
    type Challenger = BinaryNativeChallenger<F>;
    type Pcs = NativeMixedWhirPcs<F, E>;
    fn pcs(&self) -> &Self::Pcs {
        &self.main
    }
    fn preprocessed_pcs(&self) -> &Self::Pcs {
        self.preprocessed
            .as_ref()
            .expect("validated native mixed WHIR preprocessing")
    }
    fn collision_resistance_bits(&self) -> Option<usize> {
        Some(128)
    }
    fn min_num_variables(&self) -> usize {
        self.main.dense.round_folding_factor(0)
    }
    fn build_witness(&self, tables: Vec<Table<F>>) -> Vec<Table<F>> {
        tables
    }
    fn committed_table<'a>(&self, data: &'a MixedWhirData<F, E>, index: usize) -> &'a Table<F> {
        match data.slots[index] {
            Slot::Dense(slot) => data.dense.table(slot),
            Slot::Packed(slot) => data
                .packed
                .as_ref()
                .expect("a packed slot is recorded only beside packed prover data")
                .table(slot),
        }
    }
}

#[cfg(test)]
mod poly_tests;
#[cfg(test)]
mod tests;
