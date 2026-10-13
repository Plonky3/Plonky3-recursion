//! Compact native binary circuits with a product-bus wiring argument.
//!
//! A frozen fanout table repeats each canonical witness once per declared read.
//! Adjacent copies with the same fixed ID must agree. Gate, public, Keccak
//! boundary and BLAKE3 rows exchange exactly those occurrences through native
//! product buses;
//! no integer multiplicities or indexed pushforward vectors are used. Supply
//! every AIR and its preprocessing to one native multi-STARK authority. Local
//! AIR checks alone do not establish bus balance. These proofs are not hiding.
//! The caller must assign distinct trusted namespaces to separate circuits
//! composed under the same authority. Bus names are part of its verifier identity.

use alloc::sync::Arc;
use alloc::vec::Vec;
use alloc::{format, vec};

use hashbrown::HashMap;
use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_blake3_air::NUM_BLAKE3_BINARY_COLS;
use p3_bus::{
    BusActivation, BusBoundary, BusDirection, BusInteractionBuilder, BusName, BusNameError,
};
use p3_circuit::Circuit;
use p3_circuit::ops::binary_native::BinaryCoordinateField;
use p3_circuit::ops::{KECCAK_STATE_LIMBS, KECCAK256_DIGEST_LIMBS, NpoTypeId};
use p3_circuit::tables::WitnessTrace;
use p3_circuit::types::WitnessId;
use p3_field::{Field, PrimeCharacteristicRing};
use p3_keccak_air::{KECCAK_BINARY_ROWS_PER_PERM, NUM_KECCAK_BINARY_COLS};
use p3_matrix::dense::RowMajorMatrix;
use thiserror::Error;

use crate::direct::{DirectCircuitError, DirectCircuitLimits};
use crate::indexed::{IndexedCircuitError, cells, gate, padded_height, variables};
use crate::native_binary::{
    KeccakCall, NativeBinaryCircuitError, eval_keccak_bits, keccak_bit_trace, keccak_calls,
    keccak_limb_expression, keccak_packed_words,
};
use crate::native_blake3::{
    Blake3Call, Blake3Layout, ElementSlots, blake3_calls, blake3_layout, blake3_packed_words,
    blake3_preprocessed, blake3_trace, eval_blake3,
};
use crate::primitive_plan::{PrimitiveConstraint, PrimitivePlan};

const MAX_NAMESPACE_BYTES: usize = BusName::MAX_LEN - ".witness".len();
/// Gate selectors: the six of the frozen primitive codec, then the two fused gates. No
/// addition row reaches the table, so the codec's addition selector is [`SELECT`].
const GATE_SELECTORS: usize = 8;
/// `out = a * (c - addend) + addend`: `c` when `a` is one, `addend` when it is zero.
const SELECT: usize = 1;
/// The frozen codec's `out = a * c + addend`.
const MUL_ADD: usize = 4;
/// `out = a * k + addend`, with the constant `k` in preprocessing.
const MUL_ADD_CONSTANT: usize = 6;
/// [`MUL_ADD_CONSTANT`] with `a` constrained to be Boolean.
const BOOLEAN_MUL_ADD_CONSTANT: usize = 7;
/// Gate preprocessed columns: five slot labels, the constant, one-hot selectors.
const GATE_PP: usize = 6 + GATE_SELECTORS;
const HASH_WIDTH: usize = NUM_KECCAK_BINARY_COLS;
/// Bridge main columns: a boundary's 100 state limbs, then its first 16 limbs byte-swapped.
const BRIDGE_WIDTH: usize = KECCAK_STATE_LIMBS + KECCAK256_DIGEST_LIMBS;
/// Bridge preprocessed columns: a witness label per main column, the boundary tag, the
/// boundary activation and the swapped-digest activation.
const BRIDGE_PP: usize = BRIDGE_WIDTH + 3;
const BRIDGE_TAG: usize = BRIDGE_WIDTH;
const BRIDGE_ACTIVE: usize = BRIDGE_WIDTH + 1;
const BRIDGE_SWAPPED_ACTIVE: usize = BRIDGE_WIDTH + 2;

#[derive(Debug, Error)]
pub enum NativeBusCircuitError {
    #[error("native circuit bus namespace must contain 1..=56 bytes, got {length}")]
    InvalidNamespace { length: usize },
    #[error(transparent)]
    Namespace(#[from] BusNameError),
    #[error(transparent)]
    Primitive(#[from] DirectCircuitError),
    #[error(transparent)]
    Layout(#[from] IndexedCircuitError),
    #[error(transparent)]
    Hash(#[from] NativeBinaryCircuitError),
    #[error("raw bus label {label} does not fit the carrier's {bits} coordinates")]
    LabelCapacity { label: usize, bits: usize },
    #[error("expected {expected} circuit public values, got {actual}")]
    PublicLength { expected: usize, actual: usize },
    #[error(
        "a native bus circuit commits one hash table, so it cannot mix Keccak-f and BLAKE3 calls"
    )]
    MixedHashTables,
    #[error(
        "native BLAKE3 operation {operation} requires one input group of 56 limbs and an output group of 16 or 32"
    )]
    Blake3Layout { operation: usize },
    #[error("native BLAKE3 requires 16 coordinates, got {bits}")]
    Blake3CoordinateWidth { bits: usize },
    #[error("native BLAKE3 witness {witness} is outside the 16-coordinate limb span")]
    InvalidBlake3Limb { witness: usize },
}

/// How the hash table, Keccak or BLAKE3, is committed.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum KeccakCommitment {
    /// One field element per cell, with the booleanity constraints in the AIR.
    #[default]
    Dense,
    /// One bit per cell, packed 64 rows to a word. The AIR assumes a Boolean trace, which is
    /// sound only under a commitment that stores bits.
    Bits,
}

/// One table's main trace.
#[derive(Clone, Debug)]
pub enum NativeBusTrace<F> {
    Dense(RowMajorMatrix<F>),
    /// Row blocks of one word per column each, `ceil(2^log_height / 64)` blocks in all.
    PackedBits {
        words: RowMajorMatrix<u64>,
        log_height: usize,
    },
}

/// Sorted witness reads, one fanout row each, in a table of `height` rows.
#[derive(Debug)]
struct Fanout {
    ids: Vec<usize>,
    height: usize,
}

/// One gate: its slot IDs, selector and constant.
#[derive(Clone, Copy, Debug)]
struct GateRow<F> {
    ids: [usize; 5],
    selector: usize,
    constant: F,
}

/// Primitive gates, one row each, in a table of `height` rows.
#[derive(Debug)]
struct Gates<F> {
    rows: Vec<GateRow<F>>,
    height: usize,
}

/// The fanout and gate tables keep their rows and expand preprocessing only
/// when a setup asks for it; the dense matrices are the largest part of it.
#[derive(Clone, Debug)]
enum Table<F> {
    Witness(Arc<Fanout>),
    Gates(Arc<Gates<F>>),
    Public(Vec<F>),
    Keccak {
        pp: Arc<RowMajorMatrix<F>>,
        weights: [F; 16],
        bits: bool,
    },
    Bridge(Arc<RowMajorMatrix<F>>),
    Blake3 {
        pp: Arc<RowMajorMatrix<F>>,
        weights: [F; 16],
        bits: bool,
        layout: Blake3Layout,
    },
}

#[derive(Clone, Debug)]
pub struct NativeBusCircuitAir<F> {
    table: Table<F>,
    witness_bus: Arc<str>,
    hash_bus: Arc<str>,
}

#[derive(Clone, Debug)]
pub struct NativeBusCircuit<F> {
    width: usize,
    public: Vec<usize>,
    calls: Vec<KeccakCall>,
    blake3_calls: Vec<Blake3Call>,
    fanout: Arc<Fanout>,
    gates: Arc<Gates<F>>,
    airs: Vec<NativeBusCircuitAir<F>>,
    log_heights: Vec<usize>,
    main_variables: usize,
    preprocessed_variables: usize,
    keccak: KeccakCommitment,
    limits: DirectCircuitLimits,
    /// The bound of [`Self::traces`], which builds every table dense.
    dense_cells: usize,
}

impl<F: BinaryCoordinateField> NativeBusCircuit<F> {
    /// `namespace` must be unique among separate circuits in a combined authority.
    pub fn new(circuit: &Circuit<F>, namespace: &str) -> Result<Self, NativeBusCircuitError> {
        Self::with_limits(circuit, namespace, DirectCircuitLimits::default())
    }

    pub fn with_limits(
        circuit: &Circuit<F>,
        namespace: &str,
        limits: DirectCircuitLimits,
    ) -> Result<Self, NativeBusCircuitError> {
        Self::with_min_log_height_and_limits(circuit, namespace, 1, limits)
    }

    /// Floors every present table at `2^max(1, min_log_height)` rows. Trusted
    /// padding preserves the live bus occurrences while allowing larger initial
    /// PCS folds. The final padded geometry is charged before allocation.
    pub fn with_min_log_height_and_limits(
        circuit: &Circuit<F>,
        namespace: &str,
        min_log_height: usize,
        limits: DirectCircuitLimits,
    ) -> Result<Self, NativeBusCircuitError> {
        Self::with_options(
            circuit,
            namespace,
            min_log_height,
            limits,
            KeccakCommitment::Dense,
        )
    }

    /// As [`Self::with_min_log_height_and_limits`], committing the hash table as `keccak`.
    /// In [`KeccakCommitment::Bits`] mode the hash table is left out of
    /// [`Self::main_variables`] and its trace is requested through [`Self::trace_tables`];
    /// `limits` charge its packed words, at `F::COORDINATE_BITS` bits a cell. The circuit's
    /// native hash calls must be all Keccak-f or all BLAKE3 compressions.
    pub fn with_options(
        circuit: &Circuit<F>,
        namespace: &str,
        min_log_height: usize,
        limits: DirectCircuitLimits,
        keccak: KeccakCommitment,
    ) -> Result<Self, NativeBusCircuitError> {
        let bits = keccak == KeccakCommitment::Bits;
        let shift = u32::try_from(min_log_height.max(1))
            .map_err(|_| IndexedCircuitError::AllocationOverflow)?;
        let minimum_height = 1usize
            .checked_shl(shift)
            .ok_or(IndexedCircuitError::AllocationOverflow)?;
        if namespace.is_empty() || namespace.len() > MAX_NAMESPACE_BYTES {
            return Err(NativeBusCircuitError::InvalidNamespace {
                length: namespace.len(),
            });
        }
        BusName::try_new(namespace)?;
        let witness_bus: Arc<str> = format!("{namespace}.witness").into();
        let hash_bus: Arc<str> = format!("{namespace}.keccak").into();
        BusName::try_new(&witness_bus)?;
        BusName::try_new(&hash_bus)?;
        let air = |table| NativeBusCircuitAir {
            table,
            witness_bus: witness_bus.clone(),
            hash_bus: hash_bus.clone(),
        };
        let plan = PrimitivePlan::with_supported_npos(
            circuit,
            limits,
            &[
                NpoTypeId::native_keccak_f1600(),
                NpoTypeId::native_blake3_compress(),
            ],
        )?;
        let calls = keccak_calls(circuit, true)?;
        let mut blake3_calls = blake3_calls(circuit)?;
        if !calls.is_empty() && !blake3_calls.is_empty() {
            return Err(NativeBusCircuitError::MixedHashTables);
        }
        // The witness reads of the public, Keccak boundary and BLAKE3 rows.
        let mut external: Vec<usize> = plan.public.iter().map(|&w| w + 1).collect();
        for call in &calls {
            let swapped = call.swapped.iter().flatten();
            external.extend(
                call.input
                    .iter()
                    .chain(&call.output)
                    .chain(swapped)
                    .map(|&w| w + 1),
            );
        }
        let constants = constant_values(&plan.constraints);
        let mut layout = blake3_layout(&mut blake3_calls, |w| constants.get(&w).copied().flatten());
        let blake3_reads = external.len();
        for call in &blake3_calls {
            external.extend(call.labels(layout).into_iter().flatten().map(|w| w + 1));
        }
        let mut gate_rows = fuse_selects(
            gate_rows(&plan.constraints, &constants, plan.width),
            &external,
            plan.width,
        );
        if let Some(slots) = ElementSlots::of::<F>()
            && !blake3_calls.is_empty()
        {
            gate_rows =
                bind_blake3_elements(gate_rows, &external, &mut blake3_calls, slots, plan.width);
            if blake3_calls.iter().any(|call| !call.bound.is_empty()) {
                layout.elements = Some(slots);
                external.truncate(blake3_reads);
                for call in &blake3_calls {
                    external.extend(call.labels(layout).into_iter().flatten().map(|w| w + 1));
                }
            }
        }
        let gate_occurrences = gate_rows.iter().try_fold(0, |total, row| {
            add(
                total,
                (0..5)
                    .filter(|&slot| gate_slot_used(row.selector, slot))
                    .count(),
            )
        })?;
        let n = add(gate_occurrences, external.len())?;
        let witness_height = padded_height(n.max(minimum_height))?;
        let gate_height = if gate_rows.is_empty() {
            0
        } else {
            padded_height(gate_rows.len().max(minimum_height))?
        };
        let hash_height = if !calls.is_empty() {
            padded_height(cells(calls.len(), KECCAK_BINARY_ROWS_PER_PERM)?.max(minimum_height))?
        } else if !blake3_calls.is_empty() {
            padded_height(blake3_calls.len().max(minimum_height))?
        } else {
            0
        };
        let bridge_height = if calls.is_empty() {
            0
        } else {
            padded_height(cells(calls.len(), 2)?.max(minimum_height))?
        };
        if !calls.is_empty() && F::COORDINATE_BITS < 16 {
            return Err(NativeBinaryCircuitError::CoordinateWidth {
                bits: F::COORDINATE_BITS,
            }
            .into());
        }
        if !blake3_calls.is_empty() && F::COORDINATE_BITS < 16 {
            return Err(NativeBusCircuitError::Blake3CoordinateWidth {
                bits: F::COORDINATE_BITS,
            });
        }
        // IDs and boundary tags, rather than fanout row numbers, are bus labels.
        label::<F>(plan.width.max(cells(calls.len(), 2)?))?;
        let (hash_width, hash_pp) = if blake3_calls.is_empty() {
            (HASH_WIDTH, 3)
        } else {
            (NUM_BLAKE3_BINARY_COLS, layout.width())
        };
        let hash_cells = cells(hash_height, hash_width)?;
        let main_cells = add(
            add(witness_height, cells(gate_height, 5)?)?,
            add(
                cells(plan.public.len(), minimum_height)?,
                add(
                    if bits { 0 } else { hash_cells },
                    cells(bridge_height, BRIDGE_WIDTH)?,
                )?,
            )?,
        )?;
        let pp_cells = add(
            add(cells(witness_height, 3)?, cells(gate_height, GATE_PP)?)?,
            add(
                cells(hash_height, hash_pp)?,
                cells(bridge_height, BRIDGE_PP)?,
            )?,
        )?;
        // The bus uses the bit matrix, dense or packed, directly. Only an
        // enlarged minimum height needs an old allocation alongside the final one.
        let natural_hash_height = if calls.is_empty() {
            0
        } else {
            padded_height(cells(calls.len(), KECCAK_BINARY_ROWS_PER_PERM)?)?
        };
        let temporary_height = if hash_height > natural_hash_height {
            natural_hash_height
        } else {
            0
        };
        let hash_temporary = cells(temporary_height, NUM_KECCAK_BINARY_COLS)?;
        let field_cells = add(main_cells, pp_cells)?;
        // `traces` builds the dense hash table in either mode.
        let dense_cells = add(
            add(field_cells, if bits { hash_cells } else { 0 })?,
            hash_temporary,
        )?;
        let bounded = if bits {
            add(
                field_cells,
                add(
                    packed_cells::<F>(hash_height, hash_width)?,
                    packed_cells::<F>(temporary_height, HASH_WIDTH)?,
                )?,
            )?
        } else {
            dense_cells
        };
        limits.check(
            "native bus traces, preprocessing and temporary cells",
            bounded,
            limits.max_trace_cells,
        )?;
        let main_variables = variables(main_cells)?;
        let preprocessed_variables = variables(pp_cells)?;

        let mut occurrences = Vec::with_capacity(n);
        for row in &gate_rows {
            occurrences.extend(
                row.ids
                    .iter()
                    .enumerate()
                    .filter_map(|(slot, &id)| gate_slot_used(row.selector, slot).then_some(id)),
            );
        }
        occurrences.extend(external);
        let fanout = Arc::new(Fanout::new(occurrences, witness_height));
        let gates = Arc::new(Gates {
            rows: gate_rows,
            height: gate_height,
        });
        let mut airs = vec![air(Table::Witness(fanout.clone()))];
        let mut log_heights = vec![witness_height.ilog2() as usize];
        if gate_height != 0 {
            airs.push(air(Table::Gates(gates.clone())));
            log_heights.push(gate_height.ilog2() as usize);
        }
        if !plan.public.is_empty() {
            let ids = plan
                .public
                .iter()
                .map(|&w| label::<F>(w + 1))
                .collect::<Result<_, _>>()?;
            airs.push(air(Table::Public(ids)));
            log_heights.push(minimum_height.ilog2() as usize);
        }
        if !calls.is_empty() {
            let mut pp = vec![F::ZERO; cells(hash_height, 3)?];
            for c in 0..calls.len() {
                pp[3 * c * KECCAK_BINARY_ROWS_PER_PERM] = F::ONE;
                for boundary in 0..2 {
                    let row = c * KECCAK_BINARY_ROWS_PER_PERM
                        + boundary * (KECCAK_BINARY_ROWS_PER_PERM - 1);
                    pp[3 * row + 1] = label::<F>(2 * c + boundary + 1)?;
                    pp[3 * row + 2] = F::ONE;
                }
            }
            let weights = core::array::from_fn(|i| {
                F::from_raw_coordinates(1 << i).expect("validated limb width")
            });
            airs.push(air(Table::Keccak {
                pp: Arc::new(RowMajorMatrix::new(pp, 3)),
                weights,
                bits,
            }));
            log_heights.push(hash_height.ilog2() as usize);
            let mut pp = vec![F::ZERO; cells(bridge_height, BRIDGE_PP)?];
            for (c, call) in calls.iter().enumerate() {
                for (boundary, ids) in [&call.input, &call.output].into_iter().enumerate() {
                    let row =
                        &mut pp[(2 * c + boundary) * BRIDGE_PP..(2 * c + boundary + 1) * BRIDGE_PP];
                    for i in 0..KECCAK_STATE_LIMBS {
                        row[i] = label::<F>(ids[i] + 1)?;
                    }
                    row[BRIDGE_TAG] = label::<F>(2 * c + boundary + 1)?;
                    row[BRIDGE_ACTIVE] = F::ONE;
                    if let (1, Some(swapped)) = (boundary, &call.swapped) {
                        for (m, &id) in swapped.iter().enumerate() {
                            row[KECCAK_STATE_LIMBS + m] = label::<F>(id + 1)?;
                        }
                        row[BRIDGE_SWAPPED_ACTIVE] = F::ONE;
                    }
                }
            }
            airs.push(air(Table::Bridge(Arc::new(RowMajorMatrix::new(
                pp, BRIDGE_PP,
            )))));
            log_heights.push(bridge_height.ilog2() as usize);
        }
        if !blake3_calls.is_empty() {
            let weights = core::array::from_fn(|i| {
                F::from_raw_coordinates(1 << i).expect("validated limb width")
            });
            airs.push(air(Table::Blake3 {
                pp: Arc::new(blake3_preprocessed(
                    &blake3_calls,
                    layout,
                    hash_height,
                    label::<F>,
                )?),
                weights,
                bits,
                layout,
            }));
            log_heights.push(hash_height.ilog2() as usize);
        }
        Ok(Self {
            width: plan.width,
            public: plan.public,
            calls,
            blake3_calls,
            fanout,
            gates,
            airs,
            log_heights,
            main_variables,
            preprocessed_variables,
            keccak,
            limits,
            dense_cells,
        })
    }

    pub fn airs(&self) -> &[NativeBusCircuitAir<F>] {
        &self.airs
    }
    pub fn log_heights(&self) -> &[usize] {
        &self.log_heights
    }
    pub const fn main_variables(&self) -> usize {
        self.main_variables
    }
    pub const fn preprocessed_variables(&self) -> Option<usize> {
        Some(self.preprocessed_variables)
    }

    /// Position of the bit-committed Keccak table in [`Self::airs`], when there is one.
    pub fn keccak_table_index(&self) -> Option<usize> {
        self.airs
            .iter()
            .position(|air| matches!(air.table, Table::Keccak { bits: true, .. }))
    }

    /// Position of the bit-committed hash table in [`Self::airs`], when there is one: the only
    /// AIR that assumes a Boolean trace.
    pub fn packed_table_index(&self) -> Option<usize> {
        self.airs
            .iter()
            .position(|air| BaseAir::<F>::assumes_boolean_trace(air))
    }

    /// Variables of the bit-committed table's bit stack: its column and row coordinates.
    pub fn packed_bit_variables(&self) -> Option<usize> {
        let table = self.packed_table_index()?;
        Some(column_variables(BaseAir::<F>::width(&self.airs[table])) + self.log_heights[table])
    }

    pub fn public_values(&self, public: &[F]) -> Result<Vec<Vec<F>>, NativeBusCircuitError> {
        if public.len() != self.public.len() {
            return Err(NativeBusCircuitError::PublicLength {
                expected: self.public.len(),
                actual: public.len(),
            });
        }
        Ok(self
            .airs
            .iter()
            .map(|air| {
                if matches!(air.table, Table::Public(_)) {
                    public.to_vec()
                } else {
                    Vec::new()
                }
            })
            .collect())
    }

    /// Dense main traces of every table, including the hash table in either mode. The
    /// construction limits bound the dense geometry, which [`KeccakCommitment::Bits`] mode
    /// charges here rather than at construction.
    pub fn traces(
        &self,
        witness: &WitnessTrace<F>,
    ) -> Result<Vec<RowMajorMatrix<F>>, NativeBusCircuitError> {
        self.limits.check(
            "native bus dense traces, preprocessing and temporary cells",
            self.dense_cells,
            self.limits.max_trace_cells,
        )?;
        Ok(self
            .trace_tables_with(witness, false)?
            .into_iter()
            .map(|trace| match trace {
                NativeBusTrace::Dense(matrix) => matrix,
                NativeBusTrace::PackedBits { .. } => unreachable!("dense traces are requested"),
            })
            .collect())
    }

    /// Main traces of every table, with the hash table as packed bits in
    /// [`KeccakCommitment::Bits`] mode.
    pub fn trace_tables(
        &self,
        witness: &WitnessTrace<F>,
    ) -> Result<Vec<NativeBusTrace<F>>, NativeBusCircuitError> {
        self.trace_tables_with(witness, self.keccak == KeccakCommitment::Bits)
    }

    fn trace_tables_with(
        &self,
        witness: &WitnessTrace<F>,
        packed: bool,
    ) -> Result<Vec<NativeBusTrace<F>>, NativeBusCircuitError> {
        if witness.num_rows() != self.width {
            return Err(DirectCircuitError::WitnessLength {
                expected: self.width,
                actual: witness.num_rows(),
            }
            .into());
        }
        let read = |id: usize| {
            if id == 0 {
                F::ZERO
            } else {
                *witness
                    .get_value(WitnessId((id - 1) as u32))
                    .expect("validated witness length and IDs")
            }
        };
        let mut traces = Vec::with_capacity(self.airs.len());
        for (air, &log) in self.airs.iter().zip(&self.log_heights) {
            let height = 1usize << log;
            if packed && matches!(air.table, Table::Keccak { bits: true, .. }) {
                traces.push(NativeBusTrace::PackedBits {
                    words: keccak_packed_words(&self.calls, witness, height)?,
                    log_height: log,
                });
                continue;
            }
            if packed && matches!(air.table, Table::Blake3 { bits: true, .. }) {
                traces.push(NativeBusTrace::PackedBits {
                    words: blake3_packed_words(&self.blake3_calls, witness, height)?,
                    log_height: log,
                });
                continue;
            }
            let trace = match &air.table {
                Table::Witness(_) => {
                    let mut values: Vec<_> = self.fanout.ids.iter().map(|&id| read(id)).collect();
                    values.resize(height, F::ZERO);
                    RowMajorMatrix::new(values, 1)
                }
                Table::Gates(_) => {
                    let mut values = vec![F::ZERO; cells(height, 5)?];
                    for (row, gate) in values
                        .as_chunks_mut::<5>()
                        .0
                        .iter_mut()
                        .zip(&self.gates.rows)
                    {
                        for (cell, &id) in row.iter_mut().zip(&gate.ids) {
                            *cell = read(id);
                        }
                    }
                    RowMajorMatrix::new(values, 5)
                }
                Table::Public(_) => {
                    let values: Vec<_> = (0..height)
                        .flat_map(|_| self.public.iter().map(|&w| read(w + 1)))
                        .collect();
                    RowMajorMatrix::new(values, self.public.len())
                }
                Table::Keccak { .. } => keccak_bit_trace(&self.calls, witness, height)?,
                Table::Bridge(_) => {
                    let mut values = vec![F::ZERO; cells(height, BRIDGE_WIDTH)?];
                    let rows = values.as_chunks_mut::<BRIDGE_WIDTH>().0;
                    for (row, output) in rows.iter_mut().enumerate() {
                        if let Some(call) = self.calls.get(row / 2) {
                            let ids = if row % 2 == 0 {
                                &call.input
                            } else {
                                &call.output
                            };
                            for i in 0..KECCAK_STATE_LIMBS {
                                output[i] = read(ids[i] + 1);
                            }
                            // Generating the Keccak table, before this one, checked every
                            // boundary limb's width.
                            for m in 0..KECCAK256_DIGEST_LIMBS {
                                output[KECCAK_STATE_LIMBS + m] = swap_bytes(output[m]);
                            }
                        }
                    }
                    RowMajorMatrix::new(values, BRIDGE_WIDTH)
                }
                Table::Blake3 { .. } => blake3_trace(&self.blake3_calls, witness, height)?,
            };
            traces.push(NativeBusTrace::Dense(trace));
        }
        Ok(traces)
    }
}

impl Fanout {
    fn new(mut ids: Vec<usize>, height: usize) -> Self {
        ids.sort_unstable();
        Self { ids, height }
    }

    /// Whether a gate reads ID 0, the zero sentinel of an absent addend. Sorted, those reads
    /// are the first rows, each but the last marked the same as the next, so checking the
    /// first row's value checks them all.
    fn reads_zero(&self) -> bool {
        self.ids.first() == Some(&0)
    }

    /// Columns: label, active, same ID as the next row.
    fn preprocessed<F: BinaryCoordinateField>(&self) -> RowMajorMatrix<F> {
        let mut pp = vec![F::ZERO; 3 * self.height];
        for ((i, row), &id) in pp
            .as_chunks_mut::<3>()
            .0
            .iter_mut()
            .enumerate()
            .zip(&self.ids)
        {
            row[0] = checked_label(id);
            row[1] = F::ONE;
            row[2] = F::from_bool(self.ids.get(i + 1) == Some(&id));
        }
        RowMajorMatrix::new(pp, 3)
    }
}

impl<F: BinaryCoordinateField> Gates<F> {
    /// Columns: five slot labels, constant, one-hot selector.
    fn preprocessed(&self) -> RowMajorMatrix<F> {
        let mut pp = vec![F::ZERO; GATE_PP * self.height];
        for (row, gate) in pp.as_chunks_mut::<GATE_PP>().0.iter_mut().zip(&self.rows) {
            for (cell, &id) in row.iter_mut().zip(&gate.ids) {
                *cell = checked_label(id);
            }
            row[5] = gate.constant;
            row[6 + gate.selector] = F::ONE;
        }
        RowMajorMatrix::new(pp, GATE_PP)
    }
}

/// Construction checks the widest label against the carrier, so every ID fits.
fn checked_label<F: BinaryCoordinateField>(id: usize) -> F {
    label(id).expect("construction checks the widest label")
}

fn add(a: usize, b: usize) -> Result<usize, IndexedCircuitError> {
    a.checked_add(b)
        .ok_or(IndexedCircuitError::AllocationOverflow)
}
/// Cells of `F::COORDINATE_BITS` bits holding the packed words of a table of `height` rows and
/// `width` columns, one word per column and started block of 64 rows.
fn packed_cells<F: BinaryCoordinateField>(
    height: usize,
    width: usize,
) -> Result<usize, IndexedCircuitError> {
    const BITS: usize = u64::BITS as usize;
    let words = cells(height.div_ceil(BITS), width)?;
    Ok(cells(words, BITS)?.div_ceil(F::COORDINATE_BITS))
}
/// Coordinates indexing the columns of a packed table of `width` columns.
const fn column_variables(width: usize) -> usize {
    width.next_power_of_two().ilog2() as usize
}
/// A sixteen-coordinate limb with coordinates `0..8` and `8..16` exchanged.
fn swap_bytes<F: BinaryCoordinateField>(limb: F) -> F {
    let raw = u16::try_from(limb.to_raw_coordinates()).expect("checked limb width");
    F::from_raw_coordinates(raw.swap_bytes().into()).expect("validated limb width")
}
fn label<F: BinaryCoordinateField>(label: usize) -> Result<F, NativeBusCircuitError> {
    F::from_raw_coordinates(label as u128).ok_or(NativeBusCircuitError::LabelCapacity {
        label,
        bits: F::COORDINATE_BITS,
    })
}

/// The value each witness that a constant constraint fixes is fixed to: `None` for one fixed
/// to two different values, which keeps its reads.
fn constant_values<F: Field>(constraints: &[PrimitiveConstraint<F>]) -> HashMap<usize, Option<F>> {
    let mut constants = HashMap::<usize, Option<F>>::new();
    for constraint in constraints {
        if let PrimitiveConstraint::Constant { out, value } = *constraint {
            let fixed = constants.entry(out).or_insert(Some(value));
            if *fixed != Some(value) {
                *fixed = None;
            }
        }
    }
    constants
}

/// One row per primitive constraint in the frozen codec, except that a multiply-add with a
/// constant operand becomes a [`MUL_ADD_CONSTANT`] row reading the constant from
/// preprocessing, and an addition `a + b` one with constant one and addend `b`. A Boolean
/// check moves into the first multiply-add or product with a constant whose other operand it
/// checks, which becomes a [`BOOLEAN_MUL_ADD_CONSTANT`] row. The fanout table equates every
/// occurrence of a witness ID, so one check covers all of them. `constants` holds the
/// [`constant_values`] of `constraints`.
fn gate_rows<F: Field>(
    constraints: &[PrimitiveConstraint<F>],
    constants: &HashMap<usize, Option<F>>,
    width: usize,
) -> Vec<GateRow<F>> {
    let mut checked = vec![false; width];
    for constraint in constraints {
        // Only a check whose output is its input leaves no other witness to constrain.
        if let PrimitiveConstraint::Boolean { value, out } = *constraint
            && value == out
        {
            checked[value] = true;
        }
    }
    // The multiplicand, constant multiplier, addend and output of a product with a constant.
    let product = |constraint: &PrimitiveConstraint<F>| {
        let (a, b, addend, out) = match *constraint {
            PrimitiveConstraint::MulAdd { a, b, c, out } => (a, b, c, out),
            PrimitiveConstraint::Mul { a, b, out } => (a, b, None, out),
            _ => return None,
        };
        let constant = |id: usize| constants.get(&id).copied().flatten();
        match (constant(b), constant(a)) {
            (Some(k), _) => Some((a, k, addend, out)),
            (None, Some(k)) => Some((b, k, addend, out)),
            (None, None) => None,
        }
    };
    // The first product multiplying a checked witness takes over its check.
    let mut fold = vec![false; constraints.len()];
    let mut folded = vec![false; width];
    for (i, constraint) in constraints.iter().enumerate() {
        if let Some((multiplicand, ..)) = product(constraint)
            && checked[multiplicand]
            && !folded[multiplicand]
        {
            fold[i] = true;
            folded[multiplicand] = true;
        }
    }
    constraints
        .iter()
        .zip(fold)
        .filter(|(constraint, _)| {
            !matches!(**constraint, PrimitiveConstraint::Boolean { value, out }
                if value == out && folded[value])
        })
        .map(|(constraint, fold)| match product(constraint) {
            Some((multiplicand, constant, addend, out))
                if fold || matches!(constraint, PrimitiveConstraint::MulAdd { .. }) =>
            {
                GateRow {
                    ids: [multiplicand + 1, 0, addend.map_or(0, |c| c + 1), 0, out + 1],
                    selector: if fold {
                        BOOLEAN_MUL_ADD_CONSTANT
                    } else {
                        MUL_ADD_CONSTANT
                    },
                    constant,
                }
            }
            _ => match *constraint {
                PrimitiveConstraint::Add { a, b, out } => GateRow {
                    ids: [a + 1, 0, b + 1, 0, out + 1],
                    selector: MUL_ADD_CONSTANT,
                    constant: F::ONE,
                },
                _ => {
                    let (ids, selector, constant) = gate(constraint);
                    GateRow {
                        ids,
                        selector,
                        constant,
                    }
                }
            },
        })
        .collect()
}

/// Fuses selects into [`SELECT`] rows. In characteristic two, an addition row (a
/// [`MUL_ADD_CONSTANT`] row with constant one) over three distinct witnesses makes each of them
/// the difference `t - e` of the other two. Take one of them, `d`, whose every other read is one
/// factor of a [`MUL_ADD`] row `s * d + e`, with `e` one of the other two and `t` the remaining
/// one: each such row becomes `SELECT(s, t, e)` and the addition row is dropped, since nothing
/// reads `d` any more. A row is rewritten once, so a selector `s` that is itself such a
/// difference keeps its addition. `external` holds the reads outside the gate table, so that
/// `d`'s count covers its every fanout occurrence.
fn fuse_selects<F: BinaryCoordinateField>(
    rows: Vec<GateRow<F>>,
    external: &[usize],
    width: usize,
) -> Vec<GateRow<F>> {
    let mut reads = vec![0usize; width + 1];
    for row in &rows {
        for slot in (0..5).filter(|&slot| gate_slot_used(row.selector, slot)) {
            reads[row.ids[slot]] += 1;
        }
    }
    for &id in external {
        reads[id] += 1;
    }
    // The multiply-adds reading each ID as exactly one of their two factors.
    let mut factor_of = HashMap::<usize, Vec<usize>>::new();
    for (i, row) in rows.iter().enumerate() {
        let [a, c, ..] = row.ids;
        if row.selector == MUL_ADD && a != c {
            factor_of.entry(a).or_default().push(i);
            factor_of.entry(c).or_default().push(i);
        }
    }
    let mut selects: Vec<Option<[usize; 5]>> = vec![None; rows.len()];
    let mut fused = vec![false; rows.len()];
    for (i, row) in rows.iter().enumerate() {
        let [a, _, addend, _, out] = row.ids;
        let trio = [a, addend, out];
        if row.selector != MUL_ADD_CONSTANT
            || row.constant != F::ONE
            || trio.contains(&0)
            || a == addend
            || a == out
            || addend == out
        {
            continue;
        }
        for k in 0..3 {
            let d = trio[k];
            let others = [trio[(k + 1) % 3], trio[(k + 2) % 3]];
            let Some(readers) = factor_of.get(&d) else {
                continue;
            };
            if reads[d] != readers.len() + 1
                || readers
                    .iter()
                    .any(|&r| selects[r].is_some() || !others.contains(&rows[r].ids[2]))
            {
                continue;
            }
            for &r in readers {
                let [x, y, e, _, product] = rows[r].ids;
                let s = if x == d { y } else { x };
                let t = if others[0] == e { others[1] } else { others[0] };
                selects[r] = Some([s, t, e, 0, product]);
            }
            fused[i] = true;
            break;
        }
    }
    rows.into_iter()
        .zip(selects)
        .zip(fused)
        .filter(|&(_, fused)| !fused)
        .map(|((row, select), _)| {
            select.map_or(row, |ids| GateRow {
                ids,
                selector: SELECT,
                constant: F::ZERO,
            })
        })
        .collect()
}

/// Binds whole elements to BLAKE3 rows. A call's slot (see [`ElementSlots`]) with words
/// `w_0, ..., w_(n-1)` binds `s_(n-1)` when [`MUL_ADD_CONSTANT`] rows compute
/// `s_j = w_j * shift_j + s_(j-1)` for `j = 1..n` from `s_0 = w_0`, each multiplier exactly the
/// slot's `shift_j`, and every word and every partial sum `s_1, ..., s_(n-2)` has exactly two
/// reads: a word its row and its push, a partial sum its row and the next. The row then pushes
/// `s_(n-1)` as `sum_j shift_j * w_j` over its limbs' bits, the chain's own relation, so the
/// chain rows are dropped and nothing reads the words or partial sums any more. Only the full run
/// of an aligned slot binds, so a shorter split keeps the rows that also bound its value's high
/// coordinates. `external` holds the reads outside the gate table, every call's pushed limbs
/// among them, as for [`fuse_selects`], so the counts cover every fanout occurrence. A call that
/// binds a slot records its elements.
fn bind_blake3_elements<F: BinaryCoordinateField>(
    rows: Vec<GateRow<F>>,
    external: &[usize],
    calls: &mut [Blake3Call],
    slots: ElementSlots,
    width: usize,
) -> Vec<GateRow<F>> {
    let mut reads = vec![0usize; width + 1];
    for row in &rows {
        for slot in (0..5).filter(|&slot| gate_slot_used(row.selector, slot)) {
            reads[row.ids[slot]] += 1;
        }
    }
    for &id in external {
        reads[id] += 1;
    }
    // A witness that is the multiplicand of two such rows has more than two reads.
    let mut product_of = HashMap::<usize, usize>::new();
    for (i, row) in rows.iter().enumerate() {
        if row.selector == MUL_ADD_CONSTANT {
            product_of.insert(row.ids[0], i);
        }
    }
    let shifts = slots.shifts::<F>();
    // The chain rows over `words`, low first, and the sum they end at.
    let chain = |words: &[usize], kept: &[bool]| -> Option<(Vec<usize>, usize)> {
        if words.iter().any(|&word| reads[word] != 2) {
            return None;
        }
        let mut rows_of_chain = Vec::with_capacity(words.len() - 1);
        let mut sum = words[0];
        for (j, (&word, &shift)) in words.iter().zip(&shifts).enumerate().skip(1) {
            let &r = product_of.get(&word)?;
            let row = &rows[r];
            if !kept[r] || row.ids[2] != sum || row.constant != shift || (j > 1 && reads[sum] != 2)
            {
                return None;
            }
            rows_of_chain.push(r);
            sum = row.ids[4];
        }
        Some((rows_of_chain, sum))
    };
    let mut kept = vec![true; rows.len()];
    for call in calls {
        let mut bound = vec![None; slots.count()];
        for (slot, element) in bound.iter_mut().enumerate() {
            let Some(words) = slots
                .limbs(slot)
                .map(|limb| call.limb(limb).map(|w| w + 1))
                .collect::<Option<Vec<_>>>()
            else {
                continue;
            };
            if let Some((rows_of_chain, sum)) = chain(&words, &kept) {
                for r in rows_of_chain {
                    kept[r] = false;
                }
                *element = Some(sum - 1);
            }
        }
        if bound.iter().any(Option::is_some) {
            call.bound = bound;
        }
    }
    rows.into_iter()
        .zip(kept)
        .filter_map(|(row, kept)| kept.then_some(row))
        .collect()
}

// Selectors below six other than SELECT come from the shared frozen primitive gate
// codec. MulAdd and the fused gates retain the optional addend slot: an absent
// addend reads the zero sentinel, ID 0, which the fanout checks to be zero. Every
// other inactive slot can be omitted from the product bus.
fn gate_slot_used(selector: usize, slot: usize) -> bool {
    match selector {
        0 => slot == 4,
        SELECT => matches!(slot, 0 | 1 | 2 | 4),
        2 => matches!(slot, 0 | 1 | 4),
        3 => matches!(slot, 0 | 4),
        MUL_ADD => slot != 3,
        5 => true,
        MUL_ADD_CONSTANT | BOOLEAN_MUL_ADD_CONSTANT => matches!(slot, 0 | 2 | 4),
        _ => unreachable!("native bus gate selector"),
    }
}

impl<F: BinaryCoordinateField> BaseAir<F> for NativeBusCircuitAir<F> {
    fn width(&self) -> usize {
        match &self.table {
            Table::Witness(_) => 1,
            Table::Gates(_) => 5,
            Table::Public(ids) => ids.len(),
            Table::Keccak { .. } => HASH_WIDTH,
            Table::Bridge(_) => BRIDGE_WIDTH,
            Table::Blake3 { .. } => NUM_BLAKE3_BINARY_COLS,
        }
    }
    fn assumes_boolean_trace(&self) -> bool {
        matches!(
            self.table,
            Table::Keccak { bits: true, .. } | Table::Blake3 { bits: true, .. }
        )
    }
    fn num_public_values(&self) -> usize {
        match &self.table {
            Table::Public(ids) => ids.len(),
            _ => 0,
        }
    }
    fn preprocessed_width(&self) -> usize {
        match self.table {
            Table::Witness(_) => 3,
            Table::Gates(_) => GATE_PP,
            Table::Public(_) => 0,
            Table::Keccak { .. } => 3,
            Table::Bridge(_) => BRIDGE_PP,
            Table::Blake3 { layout, .. } => layout.width(),
        }
    }
    fn preprocessed_trace(&self) -> Option<RowMajorMatrix<F>> {
        match &self.table {
            Table::Witness(fanout) => Some(fanout.preprocessed()),
            Table::Gates(gates) => Some(gates.preprocessed()),
            Table::Bridge(pp) | Table::Keccak { pp, .. } | Table::Blake3 { pp, .. } => {
                Some(pp.as_ref().clone())
            }
            Table::Public(_) => None,
        }
    }
    fn main_next_row_columns(&self) -> Vec<usize> {
        match self.table {
            Table::Witness(_) => vec![0],
            Table::Keccak { .. } => (0..NUM_KECCAK_BINARY_COLS).collect(),
            _ => Vec::new(),
        }
    }
    fn preprocessed_next_row_columns(&self) -> Vec<usize> {
        Vec::new()
    }
}

impl<AB: AirBuilder + BusInteractionBuilder> Air<AB> for NativeBusCircuitAir<AB::F>
where
    AB::F: BinaryCoordinateField,
{
    fn eval(&self, b: &mut AB) {
        if let Table::Keccak { bits, .. } = &self.table {
            eval_keccak_bits(b, *bits);
        }
        let main = b.main();
        let row = main.current_slice();
        if let Table::Public(ids) = &self.table {
            for (i, &id) in ids.iter().enumerate() {
                b.assert_eq(row[i], b.public_values()[i]);
                b.push_bus_interaction(
                    BusName::new(self.witness_bus.as_ref()),
                    BusDirection::Push,
                    [AB::Expr::from(id), row[i].into()],
                    BusActivation::Boundary(BusBoundary::First),
                );
            }
            return;
        }
        let preprocessed = b.preprocessed().clone();
        let pp = preprocessed.current_slice();
        match &self.table {
            Table::Witness(fanout) => {
                b.when(pp[2]).assert_eq(row[0], main.next_slice()[0]);
                if fanout.reads_zero() {
                    b.when_first_row().assert_zero(row[0]);
                }
                b.push_bus_interaction(
                    BusName::new(self.witness_bus.as_ref()),
                    BusDirection::Pull,
                    [pp[0].into(), row[0].into()],
                    BusActivation::Boolean(pp[1].into()),
                );
            }
            Table::Gates(_) => {
                for i in 0..5 {
                    let active: AB::Expr = pp[6..GATE_PP]
                        .iter()
                        .enumerate()
                        .filter(|&(selector, _)| gate_slot_used(selector, i))
                        .map(|(_, &value)| value.into())
                        .sum();
                    b.when(AB::Expr::ONE - active.clone()).assert_zero(row[i]);
                    b.push_bus_interaction(
                        BusName::new(self.witness_bus.as_ref()),
                        BusDirection::Push,
                        [pp[i].into(), row[i].into()],
                        BusActivation::Boolean(active.clone()),
                    );
                }
                let [a, c, addend, accumulator, out] = core::array::from_fn::<_, 5, _>(|i| row[i]);
                b.when(pp[6]).assert_eq(out, pp[5]);
                b.when(pp[6 + SELECT])
                    .assert_eq(out, a * (c - addend) + addend);
                b.when(pp[8]).assert_eq(out, a * c);
                b.when(pp[9]).assert_bool(a);
                b.when(pp[9]).assert_eq(out, a);
                b.when(pp[10]).assert_eq(out, a * c + addend);
                b.when(pp[11]).assert_eq(out, accumulator * c + addend - a);
                let constant_product = a * pp[5] + addend;
                b.when(pp[6 + MUL_ADD_CONSTANT])
                    .assert_eq(out, constant_product.clone());
                b.when(pp[6 + BOOLEAN_MUL_ADD_CONSTANT]).assert_bool(a);
                b.when(pp[6 + BOOLEAN_MUL_ADD_CONSTANT])
                    .assert_eq(out, constant_product);
            }
            Table::Public(_) => unreachable!("public tables have no preprocessing window"),
            Table::Keccak { weights, .. } => {
                // Exchanging the weights of a limb's two bytes swaps them.
                let swapped: [AB::F; 16] = core::array::from_fn(|bit| weights[bit ^ 8]);
                let fields = core::iter::once(pp[1].into())
                    .chain(
                        (0..KECCAK_STATE_LIMBS)
                            .map(|limb| keccak_limb_expression::<AB>(row, weights, limb)),
                    )
                    .chain(
                        (0..KECCAK256_DIGEST_LIMBS)
                            .map(|limb| keccak_limb_expression::<AB>(row, &swapped, limb)),
                    );
                b.push_bus_interaction(
                    BusName::new(self.hash_bus.as_ref()),
                    BusDirection::Push,
                    fields,
                    BusActivation::Boolean(pp[2].into()),
                );
            }
            Table::Bridge(_) => {
                for i in 0..BRIDGE_WIDTH {
                    let active = if i < KECCAK_STATE_LIMBS {
                        pp[BRIDGE_ACTIVE]
                    } else {
                        pp[BRIDGE_SWAPPED_ACTIVE]
                    };
                    b.push_bus_interaction(
                        BusName::new(self.witness_bus.as_ref()),
                        BusDirection::Push,
                        [pp[i].into(), row[i].into()],
                        BusActivation::Boolean(active.into()),
                    );
                }
                let fields =
                    core::iter::once(pp[BRIDGE_TAG].into()).chain(row.iter().map(|&x| x.into()));
                b.push_bus_interaction(
                    BusName::new(self.hash_bus.as_ref()),
                    BusDirection::Pull,
                    fields,
                    BusActivation::Boolean(pp[BRIDGE_ACTIVE].into()),
                );
            }
            Table::Blake3 {
                weights,
                bits,
                layout,
                ..
            } => eval_blake3(
                b,
                row,
                pp,
                weights,
                *layout,
                *bits,
                BusName::new(self.witness_bus.as_ref()),
            ),
        }
    }
}
