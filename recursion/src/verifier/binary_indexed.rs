//! Trusted indexed placements and the committed batches that close LogUpStar.

use alloc::collections::BTreeMap;
use alloc::vec;
use alloc::vec::Vec;
use core::hash::Hash;

use p3_binary_field::BinaryField128;
use p3_challenger::{FieldChallenger, GrindingChallenger};
use p3_circuit::CircuitBuilder;
use p3_circuit::ops::BinaryTower128Target;
use p3_field::{ExtensionField, Field, PrimeField64};
use p3_lookup::indexed::TraceWindow;
use p3_multi_stark::indexed::{IndexedTablePlan, ReaderPlacement, TablePlacement};
use p3_multi_stark::logup_star::transcript::LogupStarTableShape;
use p3_multi_stark::logup_star::{LogupStarOutput, Reader, TableLookup};
use p3_multi_stark::proof::IndexedLookupProof;
use p3_multilinear_util::point::Point;
use p3_sumcheck::{OpeningBatch, TableShape, TableSpec};

use super::{
    BinaryAirConstraintPlan, BinaryLogupStarInputShape, BinaryLogupStarOutput,
    BinaryLogupStarProofTargets, BinaryLogupStarReaderTargets, BinaryLogupStarVerifier,
    InputResourceUsage, NativeBinaryLogupStarInput, VerificationError, VerifierLimits,
};
use crate::BinaryTower128Challenger;
use crate::pcs::binary::{RecursiveBinaryChallengeField, RecursiveBinaryTowerField, assert_equal};

#[derive(Clone, Debug)]
pub struct BinaryIndexedLookupProofTargets {
    pub reader_claims: Vec<Vec<BinaryTower128Target>>,
    pub reduction: BinaryLogupStarProofTargets,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct IndexedInputShape<F = BinaryField128, E = BinaryField128> {
    tables: Vec<IndexedTablePlan>,
    reduction: BinaryLogupStarInputShape<F, E>,
}

impl<F: RecursiveBinaryTowerField, E: RecursiveBinaryChallengeField> IndexedInputShape<F, E> {
    pub(crate) fn native_decode_shape(
        &self,
    ) -> crate::artifact::binary_native::codec::IndexedDecode {
        crate::artifact::binary_native::codec::IndexedDecode {
            reader_widths: self
                .tables
                .iter()
                .flat_map(|t| t.readers.iter().map(|r| r.payload.len()))
                .collect(),
            reduction: self.reduction.native_decode_shape(),
        }
    }

    pub(super) fn allocate_targets<BF, EF>(
        &self,
        b: &mut CircuitBuilder<EF>,
    ) -> Result<BinaryIndexedLookupProofTargets, VerificationError>
    where
        BF: PrimeField64,
        EF: ExtensionField<BF> + Eq + Hash,
    {
        let mut reader_claims = Vec::new();
        for table in &self.tables {
            for reader in &table.readers {
                let mut claims = Vec::with_capacity(reader.payload.len());
                for _ in &reader.payload {
                    let limbs = b.alloc_private_input_array::<8>("binary indexed reader claim");
                    claims.push(b.binary128_from_limbs::<BF>(limbs)?);
                }
                reader_claims.push(claims);
            }
        }
        Ok(BinaryIndexedLookupProofTargets {
            reader_claims,
            reduction: self.reduction.allocate_targets::<BF, EF>(b)?,
        })
    }
}

#[derive(Clone, Debug)]
pub(super) struct NativeIndexedInput<F = BinaryField128, E = BinaryField128> {
    claims: Vec<Vec<E>>,
    reduction: NativeBinaryLogupStarInput<F, E>,
}

impl<F: RecursiveBinaryTowerField, E: RecursiveBinaryChallengeField> NativeIndexedInput<F, E> {
    pub(super) fn private_values<EF: Field>(
        &self,
        expected: &IndexedInputShape<F, E>,
    ) -> Result<Vec<EF>, VerificationError> {
        let mut values: Vec<_> = self
            .claims
            .iter()
            .flatten()
            .flat_map(|value| {
                let raw = value.raw_coordinates();
                (0..8).map(move |i| EF::from_u16((raw >> (16 * i)) as u16))
            })
            .collect();
        values.extend(self.reduction.private_values::<EF>(&expected.reduction)?);
        Ok(values)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum Role {
    Air(usize),
    Position {
        table: usize,
        reader: usize,
        air: usize,
    },
    Columns {
        table: usize,
        air: usize,
    },
}

/// Flattened in committed-table order, then in each table's native batch order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct BinaryOpeningSchedule {
    roles: Vec<Role>,
    air_batches: Vec<Option<usize>>,
}

impl BinaryOpeningSchedule {
    pub(super) fn with_indexed<'a>(
        geometry: impl ExactSizeIterator<Item = (usize, usize, &'a [usize])>,
        indexed_tables: &[IndexedTablePlan],
        preprocessed: bool,
    ) -> (Vec<TableSpec>, Self) {
        let geometry: Vec<_> = geometry.collect();
        let mut pending: Vec<_> = geometry
            .iter()
            .enumerate()
            .map(|(air, plan)| {
                let (_, width, next) = *plan;
                if width == 0 {
                    Vec::new()
                } else {
                    vec![(
                        OpeningBatch::new((0..width).collect(), next.to_vec()),
                        Role::Air(air),
                    )]
                }
            })
            .collect();
        for (table, plan) in indexed_tables.iter().enumerate() {
            if !preprocessed {
                for (reader, placement) in plan.readers.iter().enumerate() {
                    pending[placement.air].push((
                        OpeningBatch::new(vec![placement.position], Vec::new()),
                        Role::Position {
                            table,
                            reader,
                            air: placement.air,
                        },
                    ));
                }
            }
            if (plan.table.window == TraceWindow::Preprocessed) == preprocessed {
                pending[plan.table.air].push((
                    OpeningBatch::new(plan.table.columns.clone(), Vec::new()),
                    Role::Columns {
                        table,
                        air: plan.table.air,
                    },
                ));
            }
        }
        let mut roles = Vec::new();
        let mut air_batches = vec![None; geometry.len()];
        let mut tables = Vec::new();
        for (air, batches) in pending.into_iter().enumerate() {
            if batches.is_empty() {
                continue;
            }
            air_batches[air] = Some(roles.len());
            let (height, width, _) = geometry[air];
            let batches = batches
                .into_iter()
                .map(|(batch, role)| {
                    roles.push(role);
                    batch
                })
                .collect();
            tables.push(TableSpec::new(TableShape::new(height, width), batches));
        }
        (tables, BinaryOpeningSchedule { roles, air_batches })
    }

    pub(super) const fn len(&self) -> usize {
        self.roles.len()
    }
    pub(super) fn air_batch(&self, air: usize) -> usize {
        self.air_batches[air].expect("committed AIR has its ordinary batch")
    }
    pub(super) fn points<T: Clone>(
        &self,
        heights: &[usize],
        air_point: &[T],
        indexed: Option<(&[T], &[T])>,
    ) -> Vec<Vec<T>> {
        self.roles
            .iter()
            .map(|role| {
                let (air, point) = match role {
                    Role::Air(air) => (*air, air_point),
                    Role::Position { air, .. } => {
                        (*air, indexed.expect("indexed position point").0)
                    }
                    Role::Columns { air, .. } => (*air, indexed.expect("indexed provider point").1),
                };
                point[point.len() - heights[air]..].to_vec()
            })
            .collect()
    }
    pub(super) fn zero_points<T: Clone>(&self, heights: &[usize], zero: T) -> Vec<Vec<T>> {
        self.roles
            .iter()
            .map(|role| {
                let air = match role {
                    Role::Air(air) | Role::Position { air, .. } | Role::Columns { air, .. } => *air,
                };
                vec![zero.clone(); heights[air]]
            })
            .collect()
    }
    pub(super) fn position(&self, table: usize, reader: usize) -> usize {
        self.roles.iter().position(|role| matches!(role, Role::Position { table: t, reader: r, .. } if *t == table && *r == reader)).expect("scheduled indexed position")
    }
    pub(super) fn columns(&self, table: usize) -> usize {
        self.roles
            .iter()
            .position(|role| matches!(role, Role::Columns { table: t, .. } if *t == table))
            .expect("scheduled indexed columns")
    }
}

#[derive(Clone, Debug)]
pub(super) struct BinaryIndexedVerifier<F = BinaryField128, E = BinaryField128> {
    input: IndexedInputShape<F, E>,
    reduction: BinaryLogupStarVerifier<F, E>,
    usage: InputResourceUsage,
}

impl<F, E> BinaryIndexedVerifier<F, E>
where
    F: RecursiveBinaryTowerField,
    E: RecursiveBinaryChallengeField + ExtensionField<F>,
{
    pub(super) fn build(
        airs: &[BinaryAirConstraintPlan<F, E>],
        max_nonzero_draws: usize,
        limits: &VerifierLimits,
    ) -> Result<Option<Self>, VerificationError> {
        let mut tables = BTreeMap::new();
        for (air, plan) in airs.iter().enumerate() {
            for declaration in plan.indexed_tables() {
                if plan.log_height() >= F::RAW_BITS {
                    return Err(invalid(
                        "binary indexed provider height exceeds the field embedding",
                    ));
                }
                let table = IndexedTablePlan {
                    name: declaration.name.clone(),
                    table: TablePlacement {
                        air,
                        window: declaration.window,
                        columns: declaration.columns.clone(),
                        num_variables: plan.log_height(),
                    },
                    readers: Vec::new(),
                };
                if tables.insert(declaration.name.clone(), table).is_some() {
                    return Err(invalid("binary indexed table has multiple providers"));
                }
            }
        }
        for (air, plan) in airs.iter().enumerate() {
            for declaration in plan.indexed_reads() {
                let table = tables
                    .get_mut(&declaration.table)
                    .ok_or_else(|| invalid("binary indexed reader has no provider"))?;
                if declaration.payload.len() != table.table.columns.len() {
                    return Err(invalid("binary indexed payload width mismatch"));
                }
                table.readers.push(ReaderPlacement {
                    air,
                    position: declaration.position,
                    payload: declaration.payload.clone(),
                    num_variables: plan.log_height(),
                });
            }
        }
        if tables.is_empty() {
            return Ok(None);
        }
        if tables.values().any(|table| table.readers.is_empty()) {
            return Err(invalid("binary indexed table has no readers"));
        }
        let tables: Vec<_> = tables.into_values().collect();
        let shapes: Vec<_> = tables
            .iter()
            .map(|table| LogupStarTableShape {
                num_variables: table.table.num_variables,
                width: table.table.columns.len(),
                readers: table
                    .readers
                    .iter()
                    .map(|reader| reader.num_variables)
                    .collect(),
            })
            .collect();
        let reduction = BinaryLogupStarVerifier::<F, E>::with_embedded_indexed_limits(
            &shapes,
            max_nonzero_draws,
            limits,
        )?;
        let mut usage = reduction.input_resource_usage();
        let fields = tables
            .iter()
            .try_fold(0usize, |total, table| {
                table
                    .table
                    .columns
                    .len()
                    .checked_mul(table.readers.len())
                    .and_then(|count| total.checked_add(count))
            })
            .ok_or(VerificationError::ResourceArithmeticOverflow {
                component: "binary indexed reader claims",
            })?;
        usage.add_scalar_elements(
            limits,
            fields
                .checked_mul(8)
                .ok_or(VerificationError::ResourceArithmeticOverflow {
                    component: "binary indexed reader claim limbs",
                })?,
        )?;
        let input = IndexedInputShape {
            tables,
            reduction: reduction.input_shape(),
        };
        Ok(Some(Self {
            input,
            reduction,
            usage,
        }))
    }

    pub(super) fn input_shape(&self) -> IndexedInputShape<F, E> {
        self.input.clone()
    }
    pub(super) const fn usage(&self) -> InputResourceUsage {
        self.usage
    }

    fn check_claims<T>(&self, claims: &[Vec<T>]) -> Result<(), VerificationError> {
        let expected = self.input.tables.iter().flat_map(|table| &table.readers);
        if claims.len() != expected.clone().count()
            || expected
                .zip(claims)
                .any(|(reader, claims)| reader.payload.len() != claims.len())
        {
            return Err(invalid("binary indexed reader claims shape mismatch"));
        }
        Ok(())
    }

    fn target_readers(
        &self,
        point: &[BinaryTower128Target],
        claims: &[Vec<BinaryTower128Target>],
    ) -> Vec<Vec<BinaryLogupStarReaderTargets>> {
        let mut flat = 0;
        self.input
            .tables
            .iter()
            .map(|table| {
                table
                    .readers
                    .iter()
                    .map(|reader| {
                        let result = BinaryLogupStarReaderTargets {
                            point: point[point.len() - reader.num_variables..].to_vec(),
                            claims: claims[flat].clone(),
                        };
                        flat += 1;
                        result
                    })
                    .collect()
            })
            .collect()
    }

    pub(super) fn check_targets(
        &self,
        point: &[BinaryTower128Target],
        proof: &BinaryIndexedLookupProofTargets,
    ) -> Result<(), VerificationError> {
        self.check_claims(&proof.reader_claims)?;
        self.reduction.check_targets(
            &self.target_readers(point, &proof.reader_claims),
            &proof.reduction,
        )
    }

    pub(super) fn check_proof_targets(
        &self,
        proof: &BinaryIndexedLookupProofTargets,
    ) -> Result<(), VerificationError> {
        self.check_claims(&proof.reader_claims)?;
        let height = self
            .input
            .tables
            .iter()
            .flat_map(|table| &table.readers)
            .map(|reader| reader.num_variables)
            .max()
            .unwrap();
        // Geometry alone is inspected before the caller mutates its builder.
        self.check_targets(&vec![proof.reader_claims[0][0].clone(); height], proof)
    }

    pub(super) fn verify<BF, EF>(
        &self,
        b: &mut CircuitBuilder<EF>,
        ch: BinaryTower128Challenger,
        point: &[BinaryTower128Target],
        proof: &BinaryIndexedLookupProofTargets,
    ) -> Result<BinaryLogupStarOutput, VerificationError>
    where
        BF: PrimeField64,
        EF: ExtensionField<BF> + Eq + Hash,
    {
        self.check_targets(point, proof)?;
        self.reduction.verify_reduction::<BF, EF>(
            b,
            ch,
            &self.target_readers(point, &proof.reader_claims),
            &proof.reduction,
        )
    }

    pub(super) fn check_native(
        &self,
        point: &Point<E>,
        proof: &IndexedLookupProof<F, E>,
    ) -> Result<(), VerificationError> {
        self.check_claims(&proof.reader_claims)?;
        let points = self.native_points(point);
        let readers: Vec<_> = points
            .iter()
            .zip(&proof.reader_claims)
            .map(|(point, claims)| Reader { point, claims })
            .collect();
        self.reduction
            .check_native(&self.lookups(&readers), &proof.reduction)
    }

    fn native_points(&self, point: &Point<E>) -> Vec<Point<E>> {
        self.input
            .tables
            .iter()
            .flat_map(|table| &table.readers)
            .map(|reader| {
                Point::new(
                    point.as_slice()[point.num_variables() - reader.num_variables..].to_vec(),
                )
            })
            .collect()
    }

    fn lookups<'a>(&self, readers: &'a [Reader<'a, E>]) -> Vec<TableLookup<'a, E>> {
        let mut first = 0;
        self.input
            .tables
            .iter()
            .map(|table| {
                let end = first + table.readers.len();
                let result = TableLookup {
                    num_variables: table.table.num_variables,
                    readers: &readers[first..end],
                };
                first = end;
                result
            })
            .collect()
    }

    pub(super) fn import_native<Ch>(
        &self,
        point: &Point<E>,
        proof: &IndexedLookupProof<F, E>,
        ch: &mut Ch,
    ) -> Result<(NativeIndexedInput<F, E>, LogupStarOutput<E>), VerificationError>
    where
        Ch: FieldChallenger<F> + GrindingChallenger<Witness = F> + Clone,
    {
        self.check_native(point, proof)?;
        let points = self.native_points(point);
        let readers: Vec<_> = points
            .iter()
            .zip(&proof.reader_claims)
            .map(|(point, claims)| Reader { point, claims })
            .collect();
        let (reduction, output) = self.reduction.import_native_with_reduction(
            &self.lookups(&readers),
            &proof.reduction,
            ch,
        )?;
        Ok((
            NativeIndexedInput {
                claims: proof.reader_claims.clone(),
                reduction,
            },
            output,
        ))
    }

    pub(super) fn authenticate<EF: Field + Eq + Hash>(
        &self,
        b: &mut CircuitBuilder<EF>,
        proof: &BinaryIndexedLookupProofTargets,
        output: &BinaryLogupStarOutput,
        main: &BinaryOpeningSchedule,
        main_evals: &[OpeningBatch<BinaryTower128Target>],
        preprocessing: Option<(
            &BinaryOpeningSchedule,
            &[OpeningBatch<BinaryTower128Target>],
        )>,
    ) {
        let mut flat = 0;
        for (table, plan) in self.input.tables.iter().enumerate() {
            for (reader, placement) in plan.readers.iter().enumerate() {
                let current = main_evals[main.air_batch(placement.air)].current();
                for (claim, &column) in proof.reader_claims[flat].iter().zip(&placement.payload) {
                    assert_equal(b, claim, &current[column]);
                }
                assert_equal(
                    b,
                    &output.tables[table].position_claims[reader],
                    &main_evals[main.position(table, reader)].current()[0],
                );
                flat += 1;
            }
            let opened = match plan.table.window {
                TraceWindow::Main => main_evals[main.columns(table)].current(),
                TraceWindow::Preprocessed => {
                    let (schedule, evals) = preprocessing.expect("trusted indexed preprocessing");
                    evals[schedule.columns(table)].current()
                }
            };
            for (claim, opened) in output.tables[table].column_claims.iter().zip(opened) {
                assert_equal(b, claim, opened);
            }
        }
    }
}

pub(super) fn schedule<F, E>(
    airs: &[BinaryAirConstraintPlan<F, E>],
    indexed: Option<&BinaryIndexedVerifier<F, E>>,
    preprocessed: bool,
) -> (Vec<TableSpec>, BinaryOpeningSchedule)
where
    F: RecursiveBinaryTowerField,
    E: RecursiveBinaryChallengeField + ExtensionField<F>,
{
    BinaryOpeningSchedule::with_indexed(
        airs.iter().map(|air| {
            (
                air.log_height(),
                if preprocessed {
                    air.preprocessed_width()
                } else {
                    air.main_width()
                },
                if preprocessed {
                    air.preprocessed_next_columns()
                } else {
                    air.next_columns()
                },
            )
        }),
        indexed.map(|i| i.input.tables.as_slice()).unwrap_or(&[]),
        preprocessed,
    )
}

fn invalid(message: &'static str) -> VerificationError {
    VerificationError::InvalidProofShape(message.into())
}
