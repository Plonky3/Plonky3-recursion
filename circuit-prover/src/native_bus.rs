//! Compact native binary circuits with a product-bus wiring argument.
//!
//! A frozen fanout table repeats each canonical witness once per declared read.
//! Adjacent copies with the same fixed ID must agree. Gate, public and Keccak
//! boundaries exchange exactly those occurrences through native product buses;
//! no integer multiplicities or indexed pushforward vectors are used. Supply
//! every AIR and its preprocessing to one native multi-STARK authority. Local
//! AIR checks alone do not establish bus balance. These proofs are not hiding.
//! The caller must assign distinct trusted namespaces to separate circuits
//! composed under the same authority. Bus names are part of its verifier identity.

use alloc::sync::Arc;
use alloc::vec::Vec;
use alloc::{format, vec};

use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_bus::{
    BusActivation, BusBoundary, BusDirection, BusInteractionBuilder, BusName, BusNameError,
};
use p3_circuit::Circuit;
use p3_circuit::ops::NpoTypeId;
use p3_circuit::ops::binary_native::BinaryCoordinateField;
use p3_circuit::tables::WitnessTrace;
use p3_circuit::types::WitnessId;
use p3_field::PrimeCharacteristicRing;
use p3_keccak_air::{KECCAK_BINARY_ROWS_PER_PERM, NUM_KECCAK_BINARY_COLS};
use p3_matrix::dense::RowMajorMatrix;
use thiserror::Error;

use crate::direct::{DirectCircuitError, DirectCircuitLimits};
use crate::indexed::{IndexedCircuitError, cells, gate, padded_height, variables};
use crate::native_binary::{
    KeccakCall, NativeBinaryCircuitError, eval_keccak_bits, keccak_bit_trace, keccak_calls,
    keccak_limb_expression,
};
use crate::primitive_plan::PrimitivePlan;

const MAX_NAMESPACE_BYTES: usize = BusName::MAX_LEN - ".witness".len();
const GATE_PP: usize = 12;
const HASH_WIDTH: usize = NUM_KECCAK_BINARY_COLS;

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
}

/// Sorted witness reads, one fanout row each, in a table of `height` rows.
#[derive(Debug)]
struct Fanout {
    ids: Vec<usize>,
    height: usize,
}

/// One primitive gate: its slot IDs, frozen selector and constant.
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
    },
    Bridge(Arc<RowMajorMatrix<F>>),
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
    fanout: Arc<Fanout>,
    gates: Arc<Gates<F>>,
    airs: Vec<NativeBusCircuitAir<F>>,
    log_heights: Vec<usize>,
    main_variables: usize,
    preprocessed_variables: usize,
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
            &[NpoTypeId::native_keccak_f1600()],
        )?;
        let calls = keccak_calls(circuit)?;
        let gate_occurrences = plan.constraints.iter().try_fold(0, |total, constraint| {
            let (_, selector, _) = gate(constraint);
            add(
                total,
                (0..5)
                    .filter(|&slot| gate_slot_used(selector, slot))
                    .count(),
            )
        })?;
        let n = add(
            add(gate_occurrences, plan.public.len())?,
            cells(calls.len(), 200)?,
        )?;
        let witness_height = padded_height(n.max(minimum_height))?;
        let gate_height = if plan.constraints.is_empty() {
            0
        } else {
            padded_height(plan.constraints.len().max(minimum_height))?
        };
        let hash_height = if calls.is_empty() {
            0
        } else {
            padded_height(cells(calls.len(), KECCAK_BINARY_ROWS_PER_PERM)?.max(minimum_height))?
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
        // IDs and boundary tags, rather than fanout row numbers, are bus labels.
        label::<F>(plan.width.max(cells(calls.len(), 2)?))?;
        let main_cells = add(
            add(witness_height, cells(gate_height, 5)?)?,
            add(
                cells(plan.public.len(), minimum_height)?,
                add(cells(hash_height, HASH_WIDTH)?, cells(bridge_height, 100)?)?,
            )?,
        )?;
        let pp_cells = add(
            add(cells(witness_height, 4)?, cells(gate_height, GATE_PP)?)?,
            add(cells(hash_height, 3)?, cells(bridge_height, 102)?)?,
        )?;
        // The bus uses the bit matrix directly. Only an enlarged minimum
        // height needs an old allocation alongside the final one.
        let natural_hash_height = if calls.is_empty() {
            0
        } else {
            padded_height(cells(calls.len(), KECCAK_BINARY_ROWS_PER_PERM)?)?
        };
        let hash_temporary = if hash_height > natural_hash_height {
            cells(natural_hash_height, NUM_KECCAK_BINARY_COLS)?
        } else {
            0
        };
        let bounded = add(add(main_cells, pp_cells)?, hash_temporary)?;
        limits.check(
            "native bus traces, preprocessing and temporary cells",
            bounded,
            limits.max_trace_cells,
        )?;
        let main_variables = variables(main_cells)?;
        let preprocessed_variables = variables(pp_cells)?;

        let gate_rows: Vec<_> = plan
            .constraints
            .iter()
            .map(|constraint| {
                let (ids, selector, constant) = gate(constraint);
                GateRow {
                    ids,
                    selector,
                    constant,
                }
            })
            .collect();
        let mut occurrences = Vec::with_capacity(n);
        for row in &gate_rows {
            occurrences.extend(
                row.ids
                    .iter()
                    .enumerate()
                    .filter_map(|(slot, &id)| gate_slot_used(row.selector, slot).then_some(id)),
            );
        }
        occurrences.extend(plan.public.iter().map(|&w| w + 1));
        for call in &calls {
            occurrences.extend(call.input.iter().chain(&call.output).map(|&w| w + 1));
        }
        occurrences.sort_unstable();
        let fanout = Arc::new(Fanout {
            ids: occurrences,
            height: witness_height,
        });
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
            }));
            log_heights.push(hash_height.ilog2() as usize);
            let mut pp = vec![F::ZERO; cells(bridge_height, 102)?];
            for (c, call) in calls.iter().enumerate() {
                for (boundary, ids) in [&call.input, &call.output].into_iter().enumerate() {
                    let row = &mut pp[(2 * c + boundary) * 102..(2 * c + boundary + 1) * 102];
                    for i in 0..100 {
                        row[i] = label::<F>(ids[i] + 1)?;
                    }
                    row[100] = label::<F>(2 * c + boundary + 1)?;
                    row[101] = F::ONE;
                }
            }
            airs.push(air(Table::Bridge(Arc::new(RowMajorMatrix::new(pp, 102)))));
            log_heights.push(bridge_height.ilog2() as usize);
        }
        Ok(Self {
            width: plan.width,
            public: plan.public,
            calls,
            fanout,
            gates,
            airs,
            log_heights,
            main_variables,
            preprocessed_variables,
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

    pub fn traces(
        &self,
        witness: &WitnessTrace<F>,
    ) -> Result<Vec<RowMajorMatrix<F>>, NativeBusCircuitError> {
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
                    let mut values = vec![F::ZERO; cells(height, 100)?];
                    for (row, output) in values.as_chunks_mut::<100>().0.iter_mut().enumerate() {
                        if let Some(call) = self.calls.get(row / 2) {
                            let ids = if row % 2 == 0 {
                                &call.input
                            } else {
                                &call.output
                            };
                            for i in 0..100 {
                                output[i] = read(ids[i] + 1);
                            }
                        }
                    }
                    RowMajorMatrix::new(values, 100)
                }
            };
            traces.push(trace);
        }
        Ok(traces)
    }
}

impl Fanout {
    /// Columns: label, active, same ID as the next row, zero sentinel.
    fn preprocessed<F: BinaryCoordinateField>(&self) -> RowMajorMatrix<F> {
        let mut pp = vec![F::ZERO; 4 * self.height];
        for ((i, row), &id) in pp
            .as_chunks_mut::<4>()
            .0
            .iter_mut()
            .enumerate()
            .zip(&self.ids)
        {
            row[0] = checked_label(id);
            row[1] = F::ONE;
            row[2] = F::from_bool(self.ids.get(i + 1) == Some(&id));
            row[3] = F::from_bool(id == 0);
        }
        RowMajorMatrix::new(pp, 4)
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
fn label<F: BinaryCoordinateField>(label: usize) -> Result<F, NativeBusCircuitError> {
    F::from_raw_coordinates(label as u128).ok_or(NativeBusCircuitError::LabelCapacity {
        label,
        bits: F::COORDINATE_BITS,
    })
}

// Slot order and selectors come from the shared frozen primitive gate codec.
// MulAdd retains its optional addend slot: an absent addend uses the checked
// zero sentinel. Every other inactive slot can be omitted from the product bus.
fn gate_slot_used(selector: usize, slot: usize) -> bool {
    match selector {
        0 => slot == 4,
        1 | 2 => matches!(slot, 0 | 1 | 4),
        3 => matches!(slot, 0 | 4),
        4 => slot != 3,
        5 => true,
        _ => unreachable!("frozen primitive gate selector"),
    }
}

impl<F: BinaryCoordinateField> BaseAir<F> for NativeBusCircuitAir<F> {
    fn width(&self) -> usize {
        match &self.table {
            Table::Witness(_) => 1,
            Table::Gates(_) => 5,
            Table::Public(ids) => ids.len(),
            Table::Keccak { .. } => HASH_WIDTH,
            Table::Bridge(_) => 100,
        }
    }
    fn num_public_values(&self) -> usize {
        match &self.table {
            Table::Public(ids) => ids.len(),
            _ => 0,
        }
    }
    fn preprocessed_width(&self) -> usize {
        match self.table {
            Table::Witness(_) => 4,
            Table::Gates(_) => GATE_PP,
            Table::Public(_) => 0,
            Table::Keccak { .. } => 3,
            Table::Bridge(_) => 102,
        }
    }
    fn preprocessed_trace(&self) -> Option<RowMajorMatrix<F>> {
        match &self.table {
            Table::Witness(fanout) => Some(fanout.preprocessed()),
            Table::Gates(gates) => Some(gates.preprocessed()),
            Table::Bridge(pp) | Table::Keccak { pp, .. } => Some(pp.as_ref().clone()),
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
        if let Table::Keccak { .. } = &self.table {
            eval_keccak_bits(b);
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
            Table::Witness(_) => {
                b.when(pp[2]).assert_eq(row[0], main.next_slice()[0]);
                b.when(pp[3]).assert_zero(row[0]);
                b.push_bus_interaction(
                    BusName::new(self.witness_bus.as_ref()),
                    BusDirection::Pull,
                    [pp[0].into(), row[0].into()],
                    BusActivation::Boolean(pp[1].into()),
                );
            }
            Table::Gates(_) => {
                for i in 0..5 {
                    let active: AB::Expr = pp[6..12]
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
                b.when(pp[7]).assert_eq(out, a + c);
                b.when(pp[8]).assert_eq(out, a * c);
                b.when(pp[9]).assert_bool(a);
                b.when(pp[9]).assert_eq(out, a);
                b.when(pp[10]).assert_eq(out, a * c + addend);
                b.when(pp[11]).assert_eq(out, accumulator * c + addend - a);
            }
            Table::Public(_) => unreachable!("public tables have no preprocessing window"),
            Table::Keccak { weights, .. } => {
                let fields = core::iter::once(pp[1].into())
                    .chain((0..100).map(|limb| keccak_limb_expression::<AB>(row, weights, limb)));
                b.push_bus_interaction(
                    BusName::new(self.hash_bus.as_ref()),
                    BusDirection::Push,
                    fields,
                    BusActivation::Boolean(pp[2].into()),
                );
            }
            Table::Bridge(_) => {
                for i in 0..100 {
                    b.push_bus_interaction(
                        BusName::new(self.witness_bus.as_ref()),
                        BusDirection::Push,
                        [pp[i].into(), row[i].into()],
                        BusActivation::Boolean(pp[101].into()),
                    );
                }
                let fields = core::iter::once(pp[100].into()).chain(row.iter().map(|&x| x.into()));
                b.push_bus_interaction(
                    BusName::new(self.hash_bus.as_ref()),
                    BusDirection::Pull,
                    fields,
                    BusActivation::Boolean(pp[101].into()),
                );
            }
        }
    }
}
