//! Compact primitive circuit AIRs with fixed, indexed witness wiring.
//!
//! One committed table stores the canonical witness assignment. Every gate
//! operand and output reads that table at a position pinned by preprocessing.
//! This requires a backend that enforces indexed lookups, such as native binary
//! multi-STARK; row-local constraint checks alone do not prove the wiring.
//! These traces are binding, not hiding.

use alloc::{vec, vec::Vec};

use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_circuit::{Circuit, tables::WitnessTrace, types::WitnessId};
use p3_field::Field;
use p3_lookup::{IndexedLookupBuilder, TraceWindow};
use p3_matrix::dense::RowMajorMatrix;
use thiserror::Error;

use crate::direct::{DirectCircuitError, DirectCircuitLimits};
use crate::primitive_plan::{PrimitiveConstraint, PrimitivePlan};

const TABLE: &str = "circuit-witness";
const SLOTS: usize = 5; // a, b, c, accumulator, output
const GATE_WIDTH: usize = 2 * SLOTS;
const CONSTANT: usize = SLOTS;
const SELECTORS: usize = CONSTANT + 1;
const PREPROCESSED_WIDTH: usize = SELECTORS + 6;

#[derive(Debug, Error)]
pub enum IndexedCircuitError {
    #[error(transparent)]
    Primitive(#[from] DirectCircuitError),
    #[error("indexed circuit allocation exceeds representable dimensions")]
    AllocationOverflow,
    #[error(
        "indexed witness height 2^{log_height} requires log height below field width {field_bits}"
    )]
    PositionCapacity {
        log_height: usize,
        field_bits: usize,
    },
    #[error("expected {expected} circuit public values, got {actual}")]
    PublicLength { expected: usize, actual: usize },
}

#[derive(Clone, Debug)]
enum TableKind<F> {
    Witness,
    Gates { preprocessed: RowMajorMatrix<F> },
    Public { positions: Vec<F> },
}

/// One frozen table in an [`IndexedCircuit`].
///
/// The private representation pins selectors, positions, constants and public
/// input order. Supply the complete ordered AIR list to the native authority.
#[derive(Clone, Debug)]
pub struct IndexedCircuitAir<F> {
    kind: TableKind<F>,
}

/// An owned primitive circuit relation and its compact table layout.
#[derive(Clone, Debug)]
pub struct IndexedCircuit<F> {
    plan: PrimitivePlan<F>,
    airs: Vec<IndexedCircuitAir<F>>,
    log_heights: Vec<usize>,
    gate_positions: Vec<[usize; SLOTS]>,
    main_variables: usize,
    preprocessed_variables: Option<usize>,
}

impl<F: Field> IndexedCircuit<F> {
    pub fn new(circuit: &Circuit<F>) -> Result<Self, IndexedCircuitError> {
        Self::with_limits(circuit, DirectCircuitLimits::default())
    }

    /// Bounds the combined main and preprocessing allocation before preparing
    /// matrices. Hint outputs are witnesses; table-backed operations fail closed.
    pub fn with_limits(
        circuit: &Circuit<F>,
        limits: DirectCircuitLimits,
    ) -> Result<Self, IndexedCircuitError> {
        let plan = PrimitivePlan::new(circuit, limits)?;
        let witness_height = padded_height(
            plan.width
                .checked_add(1)
                .ok_or(IndexedCircuitError::AllocationOverflow)?,
        )?;
        let witness_log = witness_height.ilog2() as usize;
        // The native Logup* provider requires this strict bound, even for a
        // two-row Gf2 table. Never substitute integer ring embeddings here.
        if witness_log >= F::bits() {
            return Err(IndexedCircuitError::PositionCapacity {
                log_height: witness_log,
                field_bits: F::bits(),
            });
        }
        let gate_height = if plan.constraints.is_empty() {
            0
        } else {
            padded_height(plan.constraints.len())?
        };
        let public_width = plan
            .public
            .len()
            .checked_mul(2)
            .ok_or(IndexedCircuitError::AllocationOverflow)?;
        let main_cells = witness_height
            .checked_add(cells(gate_height, GATE_WIDTH)?)
            .and_then(|n| n.checked_add(public_width.checked_mul(2)?))
            .ok_or(IndexedCircuitError::AllocationOverflow)?;
        let pp_cells = cells(gate_height, PREPROCESSED_WIDTH)?;
        let total_cells = main_cells
            .checked_add(pp_cells)
            .ok_or(IndexedCircuitError::AllocationOverflow)?;
        limits.check(
            "indexed trace and preprocessing cells",
            total_cells,
            limits.max_trace_cells,
        )?;
        let main_variables = variables(main_cells)?;
        let preprocessed_variables = if pp_cells == 0 {
            None
        } else {
            Some(variables(pp_cells)?)
        };

        let mut airs = vec![IndexedCircuitAir {
            kind: TableKind::Witness,
        }];
        let mut log_heights = vec![witness_log];
        let mut gate_positions = Vec::with_capacity(plan.constraints.len());
        if gate_height != 0 {
            let mut preprocessed = vec![F::ZERO; pp_cells];
            for (row, constraint) in plan.constraints.iter().enumerate() {
                let (positions, selector, constant) = gate(constraint);
                let prep =
                    &mut preprocessed[row * PREPROCESSED_WIDTH..(row + 1) * PREPROCESSED_WIDTH];
                for i in 0..SLOTS {
                    prep[i] = position::<F>(positions[i]);
                }
                prep[CONSTANT] = constant;
                prep[SELECTORS + selector] = F::ONE;
                gate_positions.push(positions);
            }
            airs.push(IndexedCircuitAir {
                kind: TableKind::Gates {
                    preprocessed: RowMajorMatrix::new(preprocessed, PREPROCESSED_WIDTH),
                },
            });
            log_heights.push(gate_height.ilog2() as usize);
        }
        if !plan.public.is_empty() {
            airs.push(IndexedCircuitAir {
                kind: TableKind::Public {
                    positions: plan.public.iter().map(|&w| position::<F>(w + 1)).collect(),
                },
            });
            log_heights.push(1);
        }
        Ok(Self {
            plan,
            airs,
            log_heights,
            gate_positions,
            main_variables,
            preprocessed_variables,
        })
    }

    pub fn airs(&self) -> &[IndexedCircuitAir<F>] {
        &self.airs
    }
    pub fn log_heights(&self) -> &[usize] {
        &self.log_heights
    }

    /// Exact variable count of the stacked main commitment, including all tables.
    pub const fn main_variables(&self) -> usize {
        self.main_variables
    }
    /// Exact variable count of the separate stacked preprocessing commitment.
    pub const fn preprocessed_variables(&self) -> Option<usize> {
        self.preprocessed_variables
    }

    /// Public values in authority AIR order, preserving caller order and aliases.
    pub fn public_values(&self, public: &[F]) -> Result<Vec<Vec<F>>, IndexedCircuitError> {
        if public.len() != self.plan.public.len() {
            return Err(IndexedCircuitError::PublicLength {
                expected: self.plan.public.len(),
                actual: public.len(),
            });
        }
        Ok(self
            .airs
            .iter()
            .map(|air| match air.kind {
                TableKind::Public { .. } => public.to_vec(),
                _ => Vec::new(),
            })
            .collect())
    }

    /// Produces canonical provider, gate and public-reader traces from one assignment.
    /// The native proof, rather than this generator, enforces all indexed reads.
    pub fn traces(
        &self,
        witness: &WitnessTrace<F>,
    ) -> Result<Vec<RowMajorMatrix<F>>, IndexedCircuitError> {
        if witness.num_rows() != self.plan.width {
            return Err(DirectCircuitError::WitnessLength {
                expected: self.plan.width,
                actual: witness.num_rows(),
            }
            .into());
        }
        let mut provider = vec![F::ZERO; 1 << self.log_heights[0]];
        for i in 0..self.plan.width {
            provider[i + 1] = *witness
                .get_value(WitnessId(i as u32))
                .expect("validated witness length");
        }
        let mut traces = Vec::with_capacity(self.airs.len());
        for (air, &log_height) in self.airs.iter().zip(&self.log_heights) {
            let trace = match &air.kind {
                TableKind::Witness => RowMajorMatrix::new(provider.clone(), 1),
                TableKind::Gates { preprocessed } => {
                    let mut values = vec![F::ZERO; (1 << log_height) * GATE_WIDTH];
                    for (row, positions) in self.gate_positions.iter().enumerate() {
                        let output = &mut values[row * GATE_WIDTH..(row + 1) * GATE_WIDTH];
                        for i in 0..SLOTS {
                            output[i] = preprocessed.values[row * PREPROCESSED_WIDTH + i];
                            output[SLOTS + i] = provider[positions[i]];
                        }
                    }
                    RowMajorMatrix::new(values, GATE_WIDTH)
                }
                TableKind::Public { positions } => {
                    let mut row = positions.clone();
                    row.extend(self.plan.public.iter().map(|&w| provider[w + 1]));
                    let mut values = row.clone();
                    values.extend(row);
                    RowMajorMatrix::new(values, 2 * positions.len())
                }
            };
            traces.push(trace);
        }
        Ok(traces)
    }
}

fn padded_height(rows: usize) -> Result<usize, IndexedCircuitError> {
    rows.max(2)
        .checked_next_power_of_two()
        .ok_or(IndexedCircuitError::AllocationOverflow)
}
fn cells(height: usize, width: usize) -> Result<usize, IndexedCircuitError> {
    height
        .checked_mul(width)
        .ok_or(IndexedCircuitError::AllocationOverflow)
}
fn variables(cells: usize) -> Result<usize, IndexedCircuitError> {
    Ok(cells
        .checked_next_power_of_two()
        .ok_or(IndexedCircuitError::AllocationOverflow)?
        .ilog2() as usize)
}

// Match p3-multi-stark's position::embed for prime and binary fields alike.
fn position<F: Field>(index: usize) -> F {
    (0..usize::BITS)
        .filter(|&i| index >> i & 1 != 0)
        .map(|i| F::interpolation_node(1 << i))
        .sum()
}

fn gate<F: Field>(constraint: &PrimitiveConstraint<F>) -> ([usize; SLOTS], usize, F) {
    let (slots, selector, constant) = match *constraint {
        PrimitiveConstraint::Constant { out, value } => {
            ([None, None, None, None, Some(out)], 0, value)
        }
        PrimitiveConstraint::Add { a, b, out } => {
            ([Some(a), Some(b), None, None, Some(out)], 1, F::ZERO)
        }
        PrimitiveConstraint::Mul { a, b, out } => {
            ([Some(a), Some(b), None, None, Some(out)], 2, F::ZERO)
        }
        PrimitiveConstraint::Boolean { value, out } => {
            ([Some(value), None, None, None, Some(out)], 3, F::ZERO)
        }
        PrimitiveConstraint::MulAdd { a, b, c, out } => {
            ([Some(a), Some(b), c, None, Some(out)], 4, F::ZERO)
        }
        PrimitiveConstraint::Horner {
            a,
            b,
            c,
            accumulator,
            out,
        } => (
            [Some(a), Some(b), Some(c), Some(accumulator), Some(out)],
            5,
            F::ZERO,
        ),
    };
    (
        slots.map(|slot| slot.map_or(0, |w| w + 1)),
        selector,
        constant,
    )
}

impl<F: Field> BaseAir<F> for IndexedCircuitAir<F> {
    fn width(&self) -> usize {
        match &self.kind {
            TableKind::Witness => 1,
            TableKind::Gates { .. } => GATE_WIDTH,
            TableKind::Public { positions } => 2 * positions.len(),
        }
    }
    fn num_public_values(&self) -> usize {
        match &self.kind {
            TableKind::Public { positions } => positions.len(),
            _ => 0,
        }
    }
    fn preprocessed_width(&self) -> usize {
        match &self.kind {
            TableKind::Gates { .. } => PREPROCESSED_WIDTH,
            _ => 0,
        }
    }
    fn preprocessed_trace(&self) -> Option<RowMajorMatrix<F>> {
        match &self.kind {
            TableKind::Gates { preprocessed } => Some(preprocessed.clone()),
            _ => None,
        }
    }
    fn main_next_row_columns(&self) -> Vec<usize> {
        Vec::new()
    }
    fn preprocessed_next_row_columns(&self) -> Vec<usize> {
        Vec::new()
    }
}

impl<AB: AirBuilder + IndexedLookupBuilder> Air<AB> for IndexedCircuitAir<AB::F>
where
    AB::F: Field,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let row = main.current_slice();
        match &self.kind {
            TableKind::Witness => {
                builder.when_first_row().assert_zero(row[0]);
                builder.push_indexed_table(TABLE, TraceWindow::Main, [0]);
            }
            TableKind::Gates { .. } => {
                let preprocessed = builder.preprocessed().clone();
                let pp = preprocessed.current_slice();
                for i in 0..SLOTS {
                    builder.assert_eq(row[i], pp[i]);
                    builder.push_indexed_read(TABLE, i, [SLOTS + i]);
                }
                let [a, b, c, accumulator, out] =
                    core::array::from_fn::<_, SLOTS, _>(|i| row[SLOTS + i]);
                builder.when(pp[SELECTORS]).assert_eq(out, pp[CONSTANT]);
                builder.when(pp[SELECTORS + 1]).assert_eq(out, a + b);
                builder.when(pp[SELECTORS + 2]).assert_eq(out, a * b);
                builder.when(pp[SELECTORS + 3]).assert_bool(a);
                builder.when(pp[SELECTORS + 3]).assert_eq(out, a);
                builder.when(pp[SELECTORS + 4]).assert_eq(out, a * b + c);
                builder
                    .when(pp[SELECTORS + 5])
                    .assert_eq(out, accumulator * b + c - a);
            }
            TableKind::Public { positions } => {
                for (i, &position) in positions.iter().enumerate() {
                    builder.assert_eq(row[i], position);
                    builder.assert_eq(row[positions.len() + i], builder.public_values()[i]);
                    builder.push_indexed_read(TABLE, i, [positions.len() + i]);
                }
            }
        }
    }
}
