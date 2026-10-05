//! Direct primitive circuit AIR, including circuits over binary fields.
//!
//! Each witness occupies one column. Every row enforces the whole frozen
//! circuit relation, with public values bound in caller order. This avoids
//! field-encoded wire IDs, signed lookup counts, and creator-role tags.
//! It is a correctness baseline: width and opening size grow with the circuit.
//! The repeated-assignment trace constructor does not hide the witness.

use alloc::vec::Vec;

use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_circuit::Circuit;
use p3_circuit::tables::WitnessTrace;
use p3_circuit::types::WitnessId;
use p3_field::{Field, PrimeCharacteristicRing};
use p3_matrix::dense::RowMajorMatrix;
use thiserror::Error;

use crate::primitive_plan::{PrimitiveConstraint, PrimitivePlan};

/// Allocation limits for preparation and repeated-assignment trace generation.
#[derive(Clone, Copy, Debug)]
pub struct DirectCircuitLimits {
    pub max_witnesses: usize,
    pub max_operations: usize,
    pub max_trace_cells: usize,
}

impl Default for DirectCircuitLimits {
    fn default() -> Self {
        Self {
            max_witnesses: 1 << 20,
            max_operations: 1 << 20,
            max_trace_cells: 1 << 24,
        }
    }
}

impl DirectCircuitLimits {
    pub(crate) const fn check(
        self,
        component: &'static str,
        actual: usize,
        limit: usize,
    ) -> Result<(), DirectCircuitError> {
        if actual > limit {
            Err(DirectCircuitError::ResourceLimit {
                component,
                actual,
                limit,
            })
        } else {
            Ok(())
        }
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum DirectCircuitError {
    #[error("circuit has no nonempty primitive relation")]
    EmptyRelation,
    #[error("witness {index} is outside circuit width {width}")]
    WitnessOutOfBounds { index: usize, width: usize },
    #[error("circuit input mapping is inconsistent")]
    PublicMapping,
    #[error("ALU operation {operation} has inconsistent operands")]
    MalformedAlu { operation: usize },
    #[error("table-backed operation {operation} has no direct primitive AIR translation")]
    UnsupportedOperation { operation: usize },
    #[error("witness length {actual} differs from circuit width {expected}")]
    WitnessLength { expected: usize, actual: usize },
    #[error("trace height must be a nonzero representable logarithmic height")]
    InvalidHeight,
    #[error("{component} requires {actual} entries, exceeding limit {limit}")]
    ResourceLimit {
        component: &'static str,
        actual: usize,
        limit: usize,
    },
}

/// An owned, validated relation with no next-row reads or lookup arguments.
#[derive(Clone, Debug)]
pub struct DirectCircuitAir<F> {
    plan: PrimitivePlan<F>,
    limits: DirectCircuitLimits,
}

impl<F: Field> DirectCircuitAir<F> {
    pub fn new(circuit: &Circuit<F>) -> Result<Self, DirectCircuitError> {
        Self::with_limits(circuit, DirectCircuitLimits::default())
    }

    pub fn with_limits(
        circuit: &Circuit<F>,
        limits: DirectCircuitLimits,
    ) -> Result<Self, DirectCircuitError> {
        Ok(Self {
            plan: PrimitivePlan::new(circuit, limits)?,
            limits,
        })
    }

    /// Repeat one witness assignment over 2^log_height rows.
    ///
    /// Each row proves the same relation. Native PCS parameters must cover both
    /// the selected height and this AIR's width. Unsupported table operations
    /// are rejected during preparation; hint outputs remain ordinary witnesses.
    pub fn trace(
        &self,
        witness: &WitnessTrace<F>,
        log_height: usize,
    ) -> Result<RowMajorMatrix<F>, DirectCircuitError> {
        if witness.num_rows() != self.plan.width {
            return Err(DirectCircuitError::WitnessLength {
                expected: self.plan.width,
                actual: witness.num_rows(),
            });
        }
        if log_height == 0 || log_height >= usize::BITS as usize {
            return Err(DirectCircuitError::InvalidHeight);
        }
        let height = 1usize << log_height;
        let cells = height
            .checked_mul(self.plan.width)
            .ok_or(DirectCircuitError::InvalidHeight)?;
        self.limits
            .check("trace cells", cells, self.limits.max_trace_cells)?;
        let mut values = Vec::with_capacity(cells);
        let row = (0..self.plan.width)
            .map(|i| {
                *witness
                    .get_value(WitnessId(i as u32))
                    .expect("validated witness length")
            })
            .collect::<Vec<_>>();
        for _ in 0..height {
            values.extend_from_slice(&row);
        }
        Ok(RowMajorMatrix::new(values, self.plan.width))
    }
}

impl<F: Field> BaseAir<F> for DirectCircuitAir<F> {
    fn width(&self) -> usize {
        self.plan.width
    }
    fn num_public_values(&self) -> usize {
        self.plan.public.len()
    }
    fn main_next_row_columns(&self) -> Vec<usize> {
        Vec::new()
    }
}

impl<AB: AirBuilder> Air<AB> for DirectCircuitAir<AB::F>
where
    AB::F: Field,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let row = main.current_slice();
        for (position, &column) in self.plan.public.iter().enumerate() {
            builder.assert_eq(row[column], builder.public_values()[position]);
        }
        for constraint in &self.plan.constraints {
            match *constraint {
                PrimitiveConstraint::Constant { out, value } => builder.assert_eq(row[out], value),
                PrimitiveConstraint::Add { a, b, out } => {
                    builder.assert_eq(row[out], row[a] + row[b]);
                }
                PrimitiveConstraint::Mul { a, b, out } => {
                    builder.assert_eq(row[out], row[a] * row[b]);
                }
                PrimitiveConstraint::Boolean { value, out } => {
                    builder.assert_bool(row[value]);
                    builder.assert_eq(row[out], row[value]);
                }
                PrimitiveConstraint::MulAdd { a, b, c, out } => {
                    let addend = c.map_or(AB::Expr::ZERO, |column| row[column].into());
                    builder.assert_eq(row[out], row[a] * row[b] + addend);
                }
                PrimitiveConstraint::Horner {
                    a,
                    b,
                    c,
                    accumulator,
                    out,
                } => {
                    builder.assert_eq(row[out], row[accumulator] * row[b] + row[c] - row[a]);
                }
            }
        }
    }
}
