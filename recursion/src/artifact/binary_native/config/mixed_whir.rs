//! Closed Tower128 composite of a dense WHIR commitment and one packed-bit table commitment.
//!
//! ```text
//!     witness      tables in instance order; one configured table goes to the bit commitment,
//!                  every other table to the dense stacked commitment, order kept
//!     commitment   one cap: the dense roots, then the packed roots, 2^c of each
//!     transcript   dense binding, then packed binding, inside one main-commitment bracket
//!     opening      dense tables at their points, then the packed table at its point
//! ```
//!
//! Each part runs its own library transcript in sequence. Nothing is sampled between the two
//! bindings, since WHIR draws its out-of-domain samples when it opens. The split position is
//! a function of the configured cap height alone, and the packed table index is fixed by the
//! configuration, so the prover cannot move a root or a table across the boundary.

use alloc::vec;

use p3_binary_field::BinaryField128;
use p3_binary_pcs::whir::{
    BinaryWhirDomain, BooleanWhirData, BooleanWhirError, BooleanWhirPcs, BooleanWhirProof,
};
use p3_binary_pcs::{
    BooleanTraceCommitment, BooleanTraceCommitmentData, BooleanTraceCommitmentError,
    BooleanTraceCommitmentProof,
};
use p3_commit::MultilinearPcs;
use p3_field::PrimeCharacteristicRing;
use p3_multilinear_util::point::Point;
use p3_sumcheck::layout::plan_stacked_layout;
use p3_sumcheck::{
    OpeningEvals, OpeningProtocol, PrescribedOpeningSecurity, PrescribedPointPcs, TableSpec,
};
use p3_whir::{PcsProof, VerifierError, WhirConfigError, WhirProver, WhirProverData};
use serde::{Deserialize, Serialize};

use super::*;

type E = BinaryField128;
type Cap = MerkleCap<E, [u8; 32]>;
type Challenger = BinaryNativeChallenger<E>;
type DensePcs = NativeWhirPcs<E, SuffixProver<E, E>>;
type PackedError = BooleanTraceCommitmentError<BooleanWhirError>;
type PackedData = BooleanTraceCommitmentData<E, BooleanWhirData<E, E, NativeMmcs<E>>>;
type PackedProof = BooleanTraceCommitmentProof<E, BooleanWhirProof<E, E, NativeMmcs<E>>>;
/// One part's share of an opening: its tables' batches, and their points in order.
type Part = (OpeningProtocol, Vec<Point<E>>);

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

/// Dense stacked WHIR over every table but one, and a bit commitment over that one table.
///
/// Both parts' Merkle trees have one hash and one cap height, which
/// [`Self::from_parameters`] enforces, so each part contributes `cap_roots` roots to the
/// shared commitment.
pub struct MixedWhirPcs {
    dense: DensePcs,
    packed: Option<(NativeBooleanWhirTracePcs, usize)>,
    cap_roots: usize,
}

/// Prover data of both parts, and where each instance's table is retained.
#[derive(Clone)]
pub struct MixedWhirData {
    dense: WhirProverData<E, E, NativeMmcs<E>, SuffixProver<E, E>>,
    packed: Option<PackedData>,
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
pub struct MixedWhirProof {
    pub dense: PcsProof<E, E, NativeMmcs<E>>,
    pub packed: Option<PackedProof>,
}

/// Trusted parameters of the mixed commitment: dense WHIR over every table but the packed one,
/// and, when there is a packed table, a packed-bit WHIR commitment of it.
///
/// Both parts use one hash and one cap height, which [`Self::with_packed_table`] enforces.
/// The preprocessing commitment holds no packed table.
#[derive(Clone)]
pub struct BinaryNativeMixedWhirPcsParameters {
    pub(in crate::artifact::binary_native) dense: BinaryNativeWhirPcsParameters<E>,
    pub(in crate::artifact::binary_native) packed: Option<PackedTableParameters>,
}

/// The packed-bit part: the table it commits, the variable count of that table's bit stack,
/// and WHIR parameters over seven variables fewer, the ones each field element absorbs.
#[derive(Clone)]
pub(in crate::artifact::binary_native) struct PackedTableParameters {
    pub(in crate::artifact::binary_native) whir: BinaryNativeWhirPcsParameters<E>,
    pub(in crate::artifact::binary_native) table: usize,
    pub(in crate::artifact::binary_native) bit_variables: usize,
}

impl BinaryNativeMixedWhirPcsParameters {
    /// A dense commitment of every table: the preprocessing commitment's parameters. Setup
    /// refuses them for the main commitment, which bit-commits one table through
    /// [`Self::with_packed_table`].
    pub const fn dense(dense: BinaryNativeWhirPcsParameters<E>) -> Self {
        Self {
            dense,
            packed: None,
        }
    }

    /// A dense commitment of every table but `table`, and `packed`, a commitment of the
    /// `bit_variables`-variable bit stack of `table`. Packed parameters naming another hash or
    /// cap height than the dense ones are refused.
    pub fn with_packed_table(
        dense: BinaryNativeWhirPcsParameters<E>,
        packed: BinaryNativeWhirPcsParameters<E>,
        table: usize,
        bit_variables: usize,
    ) -> Result<Self, VerificationError> {
        if (packed.hash, packed.cap_height) != (dense.hash, dense.cap_height) {
            return Err(super::super::invalid(
                "binary native mixed WHIR parts differ in hash or cap height",
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

impl MixedWhirPcs {
    /// Build both parts from checked parameters, on Merkle trees of the dense part's hash and
    /// cap height.
    ///
    /// `packed` holds the bit commitment's parameters, the table it commits and the table's
    /// bit arity. Parameters naming another hash or cap height are refused.
    pub(crate) fn from_parameters(
        dense: &BinaryNativeWhirPcsParameters<E>,
        packed: Option<(&BinaryNativeWhirPcsParameters<E>, usize, usize)>,
    ) -> Result<Self, VerificationError> {
        let (hash, cap_height) = (dense.hash, dense.cap_height);
        let whir = |parameters: &BinaryNativeWhirPcsParameters<E>| -> DensePcs {
            WhirProver::new(
                parameters.config.clone(),
                BinaryWhirDomain::<E>::default(),
                tree(hash, cap_height),
            )
        };
        let packed = packed
            .map(|(parameters, table, bit_variables)| {
                if (parameters.hash, parameters.cap_height) != (hash, cap_height) {
                    return Err(super::super::invalid(
                        "binary native mixed WHIR parts differ in hash or cap height",
                    ));
                }
                let bits = BooleanWhirPcs::new(whir(parameters), bit_variables).map_err(|_| {
                    super::super::invalid("binary native mixed WHIR bit configuration rejected")
                })?;
                Ok((BooleanTraceCommitment::from_commitment(bits), table))
            })
            .transpose()?;
        Self::new(whir(dense), packed, cap_height)
    }

    /// Pair a dense commitment with an optional bit commitment of table `packed.1`.
    ///
    /// `cap_height` is the cap height of both parts' Merkle trees.
    fn new(
        dense: DensePcs,
        packed: Option<(NativeBooleanWhirTracePcs, usize)>,
        cap_height: usize,
    ) -> Result<Self, VerificationError> {
        if cap_height >= usize::BITS as usize - 1 {
            return Err(super::super::invalid(
                "binary native mixed WHIR cap height is invalid",
            ));
        }
        Ok(Self {
            dense,
            packed,
            cap_roots: 1 << cap_height,
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

    /// Split the opening points the way [`Self::split`] splits their batches.
    fn split_points(&self, protocol: &OpeningProtocol, points: &[Point<E>]) -> [Vec<Point<E>>; 2] {
        let packed = self.packed_table();
        let mut sides = [Vec::new(), Vec::new()];
        for ((table, _), point) in protocol.iter_openings().zip(points) {
            sides[usize::from(packed == Some(table))].push(point.clone());
        }
        sides
    }

    /// Check what both parts need before either one touches the transcript.
    fn split_opening(
        &self,
        protocol: &OpeningProtocol,
        points: &[Point<E>],
    ) -> Result<[Part; 2], &'static str> {
        if points.len() != protocol.num_openings() {
            return Err("one opening point per batch is required");
        }
        let [dense, packed] = self.split(protocol)?;
        if (packed.num_openings() > 0) != self.packed.is_some() {
            return Err("the packed table is opened exactly when one is configured");
        }
        let [dense_points, packed_points] = self.split_points(protocol, points);
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
        pcs: &NativeBooleanWhirTracePcs,
        index: usize,
        table: &Table<E>,
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
        let is_bit = |value: &E| *value == E::ZERO || *value == E::ONE;
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

impl MultilinearPcs<E, Challenger> for MixedWhirPcs {
    type Val = E;
    type Commitment = Cap;
    type ProverData = MixedWhirData;
    type Proof = MixedWhirProof;
    type Error = MixedWhirError<VerifierError>;
    type ProverError = MixedWhirError<WhirConfigError>;
    type Witness = Vec<Table<E>>;
    type OpeningProtocol = OpeningProtocol;

    fn num_vars(&self) -> usize {
        MultilinearPcs::<E, Challenger>::num_vars(&self.dense)
    }

    fn commit(
        &self,
        witness: Vec<Table<E>>,
        challenger: &mut Challenger,
    ) -> Result<(Cap, MixedWhirData), Self::ProverError> {
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
            SuffixProver::<E, E>::new_witness(dense_tables, self.dense.round_folding_factor(0));
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

    fn observe_commitment(&self, commitment: &Cap, challenger: &mut Challenger) {
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
        _prover_data: MixedWhirData,
        _protocol: OpeningProtocol,
        _challenger: &mut Challenger,
    ) -> Result<MixedWhirProof, Self::ProverError> {
        Err(MixedWhirError::Shape(
            "the mixed commitment opens only at prescribed points",
        ))
    }

    fn verify(
        &self,
        _commitment: &Cap,
        _proof: &MixedWhirProof,
        _challenger: &mut Challenger,
        _protocol: OpeningProtocol,
    ) -> Result<(), Self::Error> {
        Err(MixedWhirError::Shape(
            "the mixed commitment opens only at prescribed points",
        ))
    }
}

impl PrescribedPointPcs<E, Challenger> for MixedWhirPcs {
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
        prover_data: MixedWhirData,
        protocol: &OpeningProtocol,
        points: &[Point<E>],
        challenger: &mut Challenger,
    ) -> Result<MixedWhirProof, Self::ProverError> {
        let [
            (dense_protocol, dense_points),
            (packed_protocol, packed_points),
        ] = self
            .split_opening(protocol, points)
            .map_err(MixedWhirError::Shape)?;
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
            .open_at(dense, &dense_protocol, &dense_points, challenger)
            .map_err(MixedWhirError::Dense)?;
        let packed = packed
            .map(|(pcs, data)| pcs.open_at(data, &packed_protocol, &packed_points, challenger))
            .transpose()
            .map_err(MixedWhirError::Packed)?;
        Ok(MixedWhirProof { dense, packed })
    }

    fn verify_at(
        &self,
        commitment: &Cap,
        proof: &MixedWhirProof,
        protocol: &OpeningProtocol,
        points: &[Point<E>],
        challenger: &mut Challenger,
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

/// Complete native mixed dense and packed-bit WHIR configuration, constructed by its owner.
///
/// The preprocessing commitment is dense only.
pub struct BinaryNativeMixedWhirConfig {
    pub(crate) main: MixedWhirPcs,
    pub(crate) preprocessed: Option<MixedWhirPcs>,
}

impl BinaryNativeMixedWhirConfig {
    pub(crate) fn new(
        main: MixedWhirPcs,
        preprocessed: Option<MixedWhirPcs>,
    ) -> Result<Self, VerificationError> {
        if preprocessed.as_ref().is_some_and(|pp| pp.packed.is_some()) {
            return Err(super::super::invalid(
                "binary native mixed WHIR preprocessing commits no packed table",
            ));
        }
        Ok(Self { main, preprocessed })
    }
}

impl MultiStarkConfig for BinaryNativeMixedWhirConfig {
    type Val = E;
    type Challenge = E;
    type Challenger = Challenger;
    type Pcs = MixedWhirPcs;
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
    fn build_witness(&self, tables: Vec<Table<E>>) -> Vec<Table<E>> {
        tables
    }
    fn committed_table<'a>(&self, data: &'a MixedWhirData, index: usize) -> &'a Table<E> {
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
mod tests;
