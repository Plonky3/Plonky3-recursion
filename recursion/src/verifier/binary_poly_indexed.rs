//! Trusted indexed placements and the committed batches that close LogUpStar.

use alloc::collections::BTreeMap;
use alloc::vec;
use alloc::vec::Vec;
use core::hash::Hash;

use p3_binary_field::{Poly64, Poly192};
use p3_challenger::{FieldChallenger, GrindingChallenger};
use p3_circuit::CircuitBuilder;
use p3_circuit::ops::BinaryPoly192Target;
use p3_field::{ExtensionField, Field, PrimeField64};
use p3_lookup::indexed::TraceWindow;
use p3_multi_stark::indexed::{IndexedTablePlan, ReaderPlacement, TablePlacement};
use p3_multi_stark::logup_star::transcript::LogupStarTableShape;
use p3_multi_stark::logup_star::{LogupStarOutput, Reader, TableLookup};
use p3_multi_stark::proof::IndexedLookupProof;
use p3_multilinear_util::point::Point;
use p3_sumcheck::OpeningBatch;

use super::binary_indexed::BinaryOpeningSchedule;
use super::{
    BinaryPolyAirConstraintPlan, BinaryPolyLogupStarInputShape, BinaryPolyLogupStarOutput,
    BinaryPolyLogupStarProofTargets, BinaryPolyLogupStarReaderTargets, BinaryPolyLogupStarVerifier,
    InputResourceUsage, NativeBinaryPolyLogupStarInput, VerificationError, VerifierLimits,
};
use crate::BinaryTower128Challenger;
use crate::pcs::binary::poly_assert_equal;

#[derive(Clone, Debug)]
pub struct BinaryPolyIndexedLookupProofTargets {
    pub reader_claims: Vec<Vec<BinaryPoly192Target>>,
    pub reduction: BinaryPolyLogupStarProofTargets,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct PolyIndexedInputShape {
    tables: Vec<IndexedTablePlan>,
    reduction: BinaryPolyLogupStarInputShape,
}

impl PolyIndexedInputShape {
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
    ) -> Result<BinaryPolyIndexedLookupProofTargets, VerificationError>
    where
        BF: PrimeField64,
        EF: ExtensionField<BF> + Eq + Hash,
    {
        let mut reader_claims = Vec::new();
        for table in &self.tables {
            for reader in &table.readers {
                let mut claims = Vec::with_capacity(reader.payload.len());
                for _ in &reader.payload {
                    let limbs = b.alloc_private_input_array::<12>("binary indexed reader claim");
                    claims.push(b.binary_poly192_from_limbs::<BF>(limbs)?);
                }
                reader_claims.push(claims);
            }
        }
        Ok(BinaryPolyIndexedLookupProofTargets {
            reader_claims,
            reduction: self.reduction.allocate_targets::<BF, EF>(b)?,
        })
    }
}

#[derive(Clone, Debug)]
pub(super) struct NativePolyIndexedInput {
    claims: Vec<Vec<Poly192>>,
    reduction: NativeBinaryPolyLogupStarInput,
}

impl NativePolyIndexedInput {
    pub(super) fn private_values<EF: Field>(
        &self,
        expected: &PolyIndexedInputShape,
    ) -> Result<Vec<EF>, VerificationError> {
        let mut values: Vec<_> = self
            .claims
            .iter()
            .flatten()
            .flat_map(|value| {
                value.coefficients().into_iter().flat_map(|c| {
                    (0..4).map(move |i| EF::from_u16((c.to_bits() >> (16 * i)) as u16))
                })
            })
            .collect();
        values.extend(self.reduction.private_values::<EF>(&expected.reduction)?);
        Ok(values)
    }
}

#[derive(Clone, Debug)]
pub(super) struct BinaryPolyIndexedVerifier {
    input: PolyIndexedInputShape,
    reduction: BinaryPolyLogupStarVerifier,
    usage: InputResourceUsage,
}

impl BinaryPolyIndexedVerifier {
    pub(super) fn build(
        airs: &[BinaryPolyAirConstraintPlan],
        max_nonzero_draws: usize,
        limits: &VerifierLimits,
    ) -> Result<Option<Self>, VerificationError> {
        let mut tables = BTreeMap::new();
        for (air, plan) in airs.iter().enumerate() {
            for declaration in plan.indexed_tables() {
                if plan.log_height() >= 64 {
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
        let reduction = BinaryPolyLogupStarVerifier::with_embedded_indexed_limits(
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
                .checked_mul(12)
                .ok_or(VerificationError::ResourceArithmeticOverflow {
                    component: "binary indexed reader claim limbs",
                })?,
        )?;
        let input = PolyIndexedInputShape {
            tables,
            reduction: reduction.input_shape(),
        };
        Ok(Some(Self {
            input,
            reduction,
            usage,
        }))
    }

    pub(super) fn tables(&self) -> &[IndexedTablePlan] {
        &self.input.tables
    }

    pub(super) fn input_shape(&self) -> PolyIndexedInputShape {
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
        point: &[BinaryPoly192Target],
        claims: &[Vec<BinaryPoly192Target>],
    ) -> Vec<Vec<BinaryPolyLogupStarReaderTargets>> {
        let mut flat = 0;
        self.input
            .tables
            .iter()
            .map(|table| {
                table
                    .readers
                    .iter()
                    .map(|reader| {
                        let result = BinaryPolyLogupStarReaderTargets {
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
        point: &[BinaryPoly192Target],
        proof: &BinaryPolyIndexedLookupProofTargets,
    ) -> Result<(), VerificationError> {
        self.check_claims(&proof.reader_claims)?;
        self.reduction.check_targets(
            &self.target_readers(point, &proof.reader_claims),
            &proof.reduction,
        )
    }

    pub(super) fn check_proof_targets(
        &self,
        proof: &BinaryPolyIndexedLookupProofTargets,
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
        point: &[BinaryPoly192Target],
        proof: &BinaryPolyIndexedLookupProofTargets,
    ) -> Result<BinaryPolyLogupStarOutput, VerificationError>
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
        point: &Point<Poly192>,
        proof: &IndexedLookupProof<Poly64, Poly192>,
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

    fn native_points(&self, point: &Point<Poly192>) -> Vec<Point<Poly192>> {
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

    fn lookups<'a>(&self, readers: &'a [Reader<'a, Poly192>]) -> Vec<TableLookup<'a, Poly192>> {
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
        point: &Point<Poly192>,
        proof: &IndexedLookupProof<Poly64, Poly192>,
        ch: &mut Ch,
    ) -> Result<(NativePolyIndexedInput, LogupStarOutput<Poly192>), VerificationError>
    where
        Ch: FieldChallenger<Poly64> + GrindingChallenger<Witness = Poly64> + Clone,
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
            NativePolyIndexedInput {
                claims: proof.reader_claims.clone(),
                reduction,
            },
            output,
        ))
    }

    pub(super) fn authenticate<EF: Field + Eq + Hash>(
        &self,
        b: &mut CircuitBuilder<EF>,
        proof: &BinaryPolyIndexedLookupProofTargets,
        output: &BinaryPolyLogupStarOutput,
        main: &BinaryOpeningSchedule,
        main_evals: &[OpeningBatch<BinaryPoly192Target>],
        preprocessing: Option<(&BinaryOpeningSchedule, &[OpeningBatch<BinaryPoly192Target>])>,
    ) {
        let mut flat = 0;
        for (table, plan) in self.input.tables.iter().enumerate() {
            for (reader, placement) in plan.readers.iter().enumerate() {
                let current = main_evals[main.air_batch(placement.air)].current();
                for (claim, &column) in proof.reader_claims[flat].iter().zip(&placement.payload) {
                    poly_assert_equal(b, claim, &current[column]);
                }
                poly_assert_equal(
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
                poly_assert_equal(b, claim, opened);
            }
        }
    }
}

fn invalid(message: &'static str) -> VerificationError {
    VerificationError::InvalidProofShape(message.into())
}

#[cfg(test)]
mod tests {
    use p3_binary_field::BinaryField128;

    use super::*;
    use crate::verifier::{
        BinaryFractionGkrVerifier, BinaryLogupStarVerifier, BinaryPolyFractionGkrVerifier,
    };

    fn check(
        standalone: impl Fn(&VerifierLimits) -> Result<InputResourceUsage, VerificationError>,
        embedded: impl Fn(&VerifierLimits) -> Result<InputResourceUsage, VerificationError>,
    ) {
        let defaults = VerifierLimits::default();
        let normal = standalone(&defaults).unwrap();
        assert_eq!(normal.instances, 4); // One provider, two readers, one fraction reduction.
        let mut expected = normal;
        expected.instances = 0;
        let zero = VerifierLimits {
            max_instances: 0,
            ..defaults
        };
        assert_eq!(embedded(&zero).unwrap(), expected);
        assert!(standalone(&zero).is_err());
        assert!(
            standalone(&VerifierLimits {
                max_instances: 4,
                ..defaults
            })
            .is_ok()
        );
        assert!(
            standalone(&VerifierLimits {
                max_instances: 3,
                ..defaults
            })
            .is_err()
        );
        for limits in [
            VerifierLimits {
                max_total_scalar_elements: normal.scalar_elements - 1,
                ..zero
            },
            VerifierLimits {
                max_rounds: normal.rounds - 1,
                ..zero
            },
            VerifierLimits {
                max_metadata_entries: normal.metadata_entries - 1,
                ..zero
            },
        ] {
            assert!(embedded(&limits).is_err());
        }
    }

    #[test]
    fn embedded_tower_lookup_charges_work_without_an_extra_air_instance() {
        let tables = [LogupStarTableShape {
            num_variables: 1,
            width: 2,
            readers: vec![2, 1],
        }];
        check(
            |l| {
                BinaryLogupStarVerifier::<BinaryField128>::with_limits(&tables, 4, l)
                    .map(|v| v.input_resource_usage())
            },
            |l| {
                BinaryLogupStarVerifier::<BinaryField128>::with_embedded_indexed_limits(
                    &tables, 4, l,
                )
                .map(|v| v.input_resource_usage())
            },
        );
        let limits = VerifierLimits {
            max_instances: 0,
            ..VerifierLimits::default()
        };
        assert!(BinaryFractionGkrVerifier::<BinaryField128>::with_limits(2, 4, &limits).is_err());
        assert_eq!(
            BinaryFractionGkrVerifier::<BinaryField128>::with_embedded_logup_limits(2, 4, &limits)
                .unwrap()
                .input_resource_usage()
                .instances,
            0
        );
    }

    #[test]
    fn embedded_poly_lookup_charges_work_without_an_extra_air_instance() {
        let tables = [LogupStarTableShape {
            num_variables: 1,
            width: 2,
            readers: vec![2, 1],
        }];
        check(
            |l| {
                BinaryPolyLogupStarVerifier::with_limits(&tables, 4, l)
                    .map(|v| v.input_resource_usage())
            },
            |l| {
                BinaryPolyLogupStarVerifier::with_embedded_indexed_limits(&tables, 4, l)
                    .map(|v| v.input_resource_usage())
            },
        );
        let limits = VerifierLimits {
            max_instances: 0,
            ..VerifierLimits::default()
        };
        assert!(BinaryPolyFractionGkrVerifier::with_limits(2, 4, &limits).is_err());
        assert_eq!(
            BinaryPolyFractionGkrVerifier::with_embedded_logup_limits(2, 4, &limits)
                .unwrap()
                .input_resource_usage()
                .instances,
            0
        );
    }
}
