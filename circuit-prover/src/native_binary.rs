//! Native binary circuit tables, including fixed indexed Keccak calls.
//!
//! Keccak's bit AIR exposes checked raw 16-coordinate state limbs. A separate
//! bridge reads each frozen call's input/output from both the hash table and
//! the canonical circuit witness table. Preprocessing fixes the full schedule
//! and all read positions. The native authority must retain the complete AIR
//! list and preprocessing commitments. These proofs do not hide witnesses.

use alloc::{vec, vec::Vec};

use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_circuit::ops::binary_native::BinaryCoordinateField;
use p3_circuit::ops::keccak_perm::{KECCAK_STATE_LIMBS, keccak_limbs_to_state};
use p3_circuit::{
    Circuit,
    ops::{NpoTypeId, Op},
    tables::WitnessTrace,
    types::WitnessId,
};
use p3_field::Field;
use p3_keccak_air::{
    KECCAK_BINARY_ROWS_PER_PERM, KeccakBinaryAir, NUM_KECCAK_BINARY_COLS,
    generate_binary_trace_rows,
};
use p3_lookup::{IndexedLookupBuilder, TraceWindow};
use p3_matrix::dense::RowMajorMatrix;
use p3_uni_stark::SubAirBuilder;
use thiserror::Error;

use crate::direct::DirectCircuitLimits;
use crate::indexed::{
    IndexedCircuit, IndexedCircuitAir, IndexedCircuitError, cells, padded_height, position,
    variables,
};

const HASH_TABLE: &str = "native-keccak-limbs";
const HASH_WIDTH: usize = NUM_KECCAK_BINARY_COLS + KECCAK_STATE_LIMBS;
const HASH_POSITION: usize = KECCAK_STATE_LIMBS;
const PAYLOAD: usize = HASH_POSITION + 1;
const BRIDGE_WIDTH: usize = PAYLOAD + KECCAK_STATE_LIMBS;

#[derive(Debug, Error)]
pub enum NativeBinaryCircuitError {
    #[error(transparent)]
    Indexed(#[from] IndexedCircuitError),
    #[error("native Keccak requires 16 coordinates, got {bits}")]
    CoordinateWidth { bits: usize },
    #[error("native Keccak operation {operation} requires one input and output group of 100 limbs")]
    KeccakLayout { operation: usize },
    #[error("native Keccak witness {witness} is outside the 16-coordinate limb span")]
    InvalidLimb { witness: usize },
}

#[derive(Clone, Debug)]
enum NativeTable<F> {
    Primitive(IndexedCircuitAir<F>),
    Keccak {
        round_zero: RowMajorMatrix<F>,
        weights: [F; 16],
    },
    Bridge {
        positions: RowMajorMatrix<F>,
    },
}

/// One frozen AIR in the native binary circuit's ordered table list.
#[derive(Clone, Debug)]
pub struct NativeBinaryCircuitAir<F> {
    kind: NativeTable<F>,
}

#[derive(Clone, Debug)]
pub(crate) struct KeccakCall {
    pub(crate) input: [usize; KECCAK_STATE_LIMBS],
    pub(crate) output: [usize; KECCAK_STATE_LIMBS],
}

/// Compact native primitives and supported binary hash tables.
///
/// Only native Keccak NPOs are accepted; other custom operations fail closed.
#[derive(Clone, Debug)]
pub struct NativeBinaryCircuit<F> {
    primitive: IndexedCircuit<F>,
    calls: Vec<KeccakCall>,
    airs: Vec<NativeBinaryCircuitAir<F>>,
    log_heights: Vec<usize>,
    main_variables: usize,
    preprocessed_variables: Option<usize>,
}

impl<F: BinaryCoordinateField> NativeBinaryCircuit<F> {
    pub fn new(circuit: &Circuit<F>) -> Result<Self, NativeBinaryCircuitError> {
        Self::with_limits(circuit, DirectCircuitLimits::default())
    }

    pub fn with_limits(
        circuit: &Circuit<F>,
        limits: DirectCircuitLimits,
    ) -> Result<Self, NativeBinaryCircuitError> {
        let primitive = IndexedCircuit::with_supported_npos(
            circuit,
            limits,
            &[NpoTypeId::native_keccak_f1600()],
        )?;
        let calls = keccak_calls(circuit)?;
        let mut airs: Vec<_> = primitive
            .airs()
            .iter()
            .cloned()
            .map(|air| NativeBinaryCircuitAir {
                kind: NativeTable::Primitive(air),
            })
            .collect();
        let mut log_heights = primitive.log_heights().to_vec();
        let mut main_cells = 0usize;
        let mut pp_cells = 0usize;
        for (air, &log) in primitive.airs().iter().zip(&log_heights) {
            main_cells = add(main_cells, cells(1 << log, air.width())?)?;
            pp_cells = add(pp_cells, cells(1 << log, air.preprocessed_width())?)?;
        }
        if !calls.is_empty() {
            if F::COORDINATE_BITS < 16 {
                return Err(NativeBinaryCircuitError::CoordinateWidth {
                    bits: F::COORDINATE_BITS,
                });
            }
            let real_hash_rows = cells(calls.len(), KECCAK_BINARY_ROWS_PER_PERM)?;
            let hash_height = padded_height(real_hash_rows)?;
            let hash_log = hash_height.ilog2() as usize;
            if hash_log >= F::bits() {
                return Err(IndexedCircuitError::PositionCapacity {
                    log_height: hash_log,
                    field_bits: F::bits(),
                }
                .into());
            }
            let bridge_height = padded_height(cells(calls.len(), 2)?)?;
            main_cells = add(
                main_cells,
                add(
                    cells(hash_height, HASH_WIDTH)?,
                    cells(bridge_height, BRIDGE_WIDTH)?,
                )?,
            )?;
            pp_cells = add(pp_cells, add(hash_height, cells(bridge_height, PAYLOAD)?)?)?;
            // Account for the temporary upstream bit matrix retained while its
            // appended raw-limb columns are generated. No extra NTT capacity.
            let temporary = cells(hash_height, NUM_KECCAK_BINARY_COLS)?;
            let bounded = add(add(main_cells, pp_cells)?, temporary)?;
            limits
                .check(
                    "native binary trace, preprocessing and temporary cells",
                    bounded,
                    limits.max_trace_cells,
                )
                .map_err(IndexedCircuitError::from)?;

            let mut round_zero = vec![F::ZERO; hash_height];
            for i in 0..calls.len() {
                round_zero[i * KECCAK_BINARY_ROWS_PER_PERM] = F::ONE;
            }
            let weights = core::array::from_fn(|i| {
                F::from_raw_coordinates(1 << i).expect("validated limb width")
            });
            airs.push(NativeBinaryCircuitAir {
                kind: NativeTable::Keccak {
                    round_zero: RowMajorMatrix::new(round_zero, 1),
                    weights,
                },
            });
            log_heights.push(hash_log);
            let mut positions = vec![F::ZERO; cells(bridge_height, PAYLOAD)?];
            for row in positions.chunks_exact_mut(PAYLOAD) {
                row[HASH_POSITION] = position::<F>(real_hash_rows);
            }
            for (i, call) in calls.iter().enumerate() {
                for (boundary, witnesses) in [&call.input, &call.output].into_iter().enumerate() {
                    let row = &mut positions
                        [(2 * i + boundary) * PAYLOAD..(2 * i + boundary + 1) * PAYLOAD];
                    for (slot, &w) in witnesses.iter().enumerate() {
                        row[slot] = position::<F>(w + 1);
                    }
                    row[HASH_POSITION] = position::<F>(
                        i * KECCAK_BINARY_ROWS_PER_PERM
                            + boundary * (KECCAK_BINARY_ROWS_PER_PERM - 1),
                    );
                }
            }
            airs.push(NativeBinaryCircuitAir {
                kind: NativeTable::Bridge {
                    positions: RowMajorMatrix::new(positions, PAYLOAD),
                },
            });
            log_heights.push(bridge_height.ilog2() as usize);
        }
        Ok(Self {
            primitive,
            calls,
            airs,
            log_heights,
            main_variables: variables(main_cells)?,
            preprocessed_variables: if pp_cells == 0 {
                None
            } else {
                Some(variables(pp_cells)?)
            },
        })
    }

    pub fn airs(&self) -> &[NativeBinaryCircuitAir<F>] {
        &self.airs
    }
    pub fn log_heights(&self) -> &[usize] {
        &self.log_heights
    }
    pub const fn main_variables(&self) -> usize {
        self.main_variables
    }
    pub const fn preprocessed_variables(&self) -> Option<usize> {
        self.preprocessed_variables
    }

    pub fn public_values(&self, public: &[F]) -> Result<Vec<Vec<F>>, NativeBinaryCircuitError> {
        let mut values = self.primitive.public_values(public)?;
        values.resize_with(self.airs.len(), Vec::new);
        Ok(values)
    }

    /// Regenerates hash rows from frozen input IDs, and reads boundary payloads
    /// from the supplied canonical assignment. A native proof enforces equality.
    pub fn traces(
        &self,
        witness: &WitnessTrace<F>,
    ) -> Result<Vec<RowMajorMatrix<F>>, NativeBinaryCircuitError> {
        let mut traces = self.primitive.traces(witness)?;
        if self.calls.is_empty() {
            return Ok(traces);
        }
        let read = |w: usize| {
            *witness
                .get_value(WitnessId(w as u32))
                .expect("validated witness length and call IDs")
        };
        traces.push(keccak_trace(&self.calls, witness)?);
        let NativeTable::Bridge { positions } = &self.airs[traces.len()].kind else {
            unreachable!()
        };
        let height = positions.values.len() / PAYLOAD;
        let mut values = vec![F::ZERO; cells(height, BRIDGE_WIDTH)?];
        for (row, prep) in positions.values.chunks_exact(PAYLOAD).enumerate() {
            let output = &mut values[row * BRIDGE_WIDTH..(row + 1) * BRIDGE_WIDTH];
            output[..PAYLOAD].copy_from_slice(prep);
            if let Some(call) = self.calls.get(row / 2) {
                let ids = if row % 2 == 0 {
                    &call.input
                } else {
                    &call.output
                };
                for i in 0..KECCAK_STATE_LIMBS {
                    output[PAYLOAD + i] = read(ids[i]);
                }
            }
        }
        traces.push(RowMajorMatrix::new(values, BRIDGE_WIDTH));
        Ok(traces)
    }
}

fn add(a: usize, b: usize) -> Result<usize, IndexedCircuitError> {
    a.checked_add(b)
        .ok_or(IndexedCircuitError::AllocationOverflow)
}

impl<F: Field> BaseAir<F> for NativeBinaryCircuitAir<F> {
    fn width(&self) -> usize {
        match &self.kind {
            NativeTable::Primitive(air) => air.width(),
            NativeTable::Keccak { .. } => HASH_WIDTH,
            NativeTable::Bridge { .. } => BRIDGE_WIDTH,
        }
    }
    fn num_public_values(&self) -> usize {
        match &self.kind {
            NativeTable::Primitive(air) => air.num_public_values(),
            _ => 0,
        }
    }
    fn preprocessed_width(&self) -> usize {
        match &self.kind {
            NativeTable::Primitive(air) => air.preprocessed_width(),
            NativeTable::Keccak { .. } => 1,
            NativeTable::Bridge { .. } => PAYLOAD,
        }
    }
    fn preprocessed_trace(&self) -> Option<RowMajorMatrix<F>> {
        match &self.kind {
            NativeTable::Primitive(air) => air.preprocessed_trace(),
            NativeTable::Keccak { round_zero, .. } => Some(round_zero.clone()),
            NativeTable::Bridge { positions } => Some(positions.clone()),
        }
    }
    fn main_next_row_columns(&self) -> Vec<usize> {
        match &self.kind {
            NativeTable::Primitive(air) => air.main_next_row_columns(),
            NativeTable::Keccak { .. } => (0..NUM_KECCAK_BINARY_COLS).collect(),
            NativeTable::Bridge { .. } => Vec::new(),
        }
    }
    fn preprocessed_next_row_columns(&self) -> Vec<usize> {
        Vec::new()
    }
}

impl<AB: AirBuilder + IndexedLookupBuilder> Air<AB> for NativeBinaryCircuitAir<AB::F>
where
    AB::F: Field,
{
    fn eval(&self, builder: &mut AB) {
        match &self.kind {
            NativeTable::Primitive(air) => air.eval(builder),
            NativeTable::Keccak { weights, .. } => {
                eval_keccak(builder, weights);
                builder.push_indexed_table(
                    HASH_TABLE,
                    TraceWindow::Main,
                    NUM_KECCAK_BINARY_COLS..HASH_WIDTH,
                );
            }
            NativeTable::Bridge { .. } => {
                let main = builder.main();
                let row = main.current_slice();
                let prep = builder.preprocessed().clone();
                let pp = prep.current_slice();
                for i in 0..PAYLOAD {
                    builder.assert_eq(row[i], pp[i]);
                }
                for i in 0..KECCAK_STATE_LIMBS {
                    builder.push_indexed_read("circuit-witness", i, [PAYLOAD + i]);
                }
                builder.push_indexed_read(HASH_TABLE, HASH_POSITION, PAYLOAD..BRIDGE_WIDTH);
            }
        }
    }
}

/// Called only after the primitive plan has validated operation identities and IDs.
pub(crate) fn keccak_calls<F: Field>(
    circuit: &Circuit<F>,
) -> Result<Vec<KeccakCall>, NativeBinaryCircuitError> {
    let mut calls = Vec::new();
    for (operation, op) in circuit.ops.iter().enumerate() {
        if let Op::NonPrimitiveOpWithExecutor {
            inputs, outputs, ..
        } = op
        {
            // The primitive plan has already rejected unrecognized identities
            // and validated all witness IDs. Validate the supported shape too.
            if inputs.len() != 1
                || outputs.len() != 1
                || inputs[0].len() != KECCAK_STATE_LIMBS
                || outputs[0].len() != KECCAK_STATE_LIMBS
            {
                return Err(NativeBinaryCircuitError::KeccakLayout { operation });
            }
            calls.push(KeccakCall {
                input: core::array::from_fn(|i| inputs[0][i].0 as usize),
                output: core::array::from_fn(|i| outputs[0][i].0 as usize),
            });
        }
    }
    Ok(calls)
}

/// Callers validate the witness length and bound the expanded and temporary matrices first.
pub(crate) fn keccak_trace<F: BinaryCoordinateField>(
    calls: &[KeccakCall],
    witness: &WitnessTrace<F>,
) -> Result<RowMajorMatrix<F>, NativeBinaryCircuitError> {
    let read = |w: usize| {
        *witness
            .get_value(WitnessId(w as u32))
            .expect("validated witness length and call IDs")
    };
    let mut inputs = Vec::with_capacity(calls.len());
    for call in calls {
        let mut limbs = [0u16; KECCAK_STATE_LIMBS];
        for (i, &w) in call.input.iter().enumerate() {
            limbs[i] = u16::try_from(read(w).to_raw_coordinates())
                .map_err(|_| NativeBinaryCircuitError::InvalidLimb { witness: w })?;
        }
        for &w in &call.output {
            u16::try_from(read(w).to_raw_coordinates())
                .map_err(|_| NativeBinaryCircuitError::InvalidLimb { witness: w })?;
        }
        inputs.push(keccak_limbs_to_state(&limbs));
    }
    let hash = generate_binary_trace_rows::<F>(inputs, 0);
    let weights = core::array::from_fn::<_, 16, _>(|i| {
        F::from_raw_coordinates(1 << i).expect("validated limb width")
    });
    let height = hash.values.len() / NUM_KECCAK_BINARY_COLS;
    let mut values = hash.values;
    let final_len = cells(height, HASH_WIDTH)?;
    values.reserve_exact(final_len - values.len());
    values.resize(final_len, F::ZERO);
    // Expand backwards so destinations cannot overwrite an unprocessed row.
    // This reuses the hash allocation instead of retaining two full matrices.
    for index in (0..height).rev() {
        let source = index * NUM_KECCAK_BINARY_COLS;
        let destination = index * HASH_WIDTH;
        values.copy_within(source..source + NUM_KECCAK_BINARY_COLS, destination);
        for limb in 0..KECCAK_STATE_LIMBS {
            let packed = (0..16)
                .map(|bit| {
                    values[destination + KECCAK_BINARY_ROWS_PER_PERM + 16 * limb + bit]
                        * weights[bit]
                })
                .sum();
            values[destination + NUM_KECCAK_BINARY_COLS + limb] = packed;
        }
    }
    Ok(RowMajorMatrix::new(values, HASH_WIDTH))
}

pub(crate) fn eval_keccak<AB: AirBuilder>(builder: &mut AB, weights: &[AB::F; 16])
where
    AB::F: Field,
{
    let mut sub =
        SubAirBuilder::<AB, KeccakBinaryAir, AB::Var>::new(builder, 0..NUM_KECCAK_BINARY_COLS);
    KeccakBinaryAir::default().eval(&mut sub);
    let main = builder.main();
    let row = main.current_slice();
    builder.assert_eq(row[0], builder.preprocessed().current_slice()[0]);
    for limb in 0..KECCAK_STATE_LIMBS {
        let value: AB::Expr = (0..16)
            .map(|bit| row[KECCAK_BINARY_ROWS_PER_PERM + 16 * limb + bit] * weights[bit])
            .sum();
        builder.assert_eq(row[NUM_KECCAK_BINARY_COLS + limb], value);
    }
}
