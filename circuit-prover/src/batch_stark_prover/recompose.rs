//! Recompose table prover: builds `RecomposeAir` instances for the batch STARK prover.

use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec::Vec;
use core::any::Any;

use hashbrown::HashMap;
use p3_baby_bear::BabyBear;
use p3_batch_stark::{StarkGenericConfig, Val};
use p3_circuit::ops::recompose::{RecomposeTrace, RecomposeTraceKind};
use p3_circuit::ops::{NonPrimitivePreprocessedMap, NpoTypeId};
use p3_circuit::tables::Traces;
use p3_circuit::{CircuitError, PreprocessedColumns};
use p3_field::extension::{BinomialExtensionField, QuinticTrinomialExtensionField};
use p3_field::{Algebra, ExtensionField, Field, PrimeCharacteristicRing, PrimeField64};
use p3_goldilocks::Goldilocks;
use p3_koala_bear::KoalaBear;
use p3_uni_stark::{SymbolicExpression, SymbolicExpressionExt};
use p3_util::log2_ceil_usize;

use super::dynamic_air::{
    BatchAir, BatchTableInstance, DynamicAirEntry, TableProver, transmute_traces,
};
use super::{AirVariant, NonPrimitiveTableEntry, TablePacking};
use crate::air::RecomposeAir;
use crate::common::{BuiltNpoTable, CircuitTableAir, NpoAirBuilder, NpoPreprocessor, NpoRelation};
use crate::config::StarkField;
use crate::{ConstraintProfile, impl_table_prover_batch_instances_from_base};

impl<SC, const D: usize> BatchAir<SC> for RecomposeAir<Val<SC>, D>
where
    SC: StarkGenericConfig + Send + Sync,
    Val<SC>: StarkField,
    SymbolicExpressionExt<Val<SC>, SC::Challenge>:
        Algebra<SymbolicExpression<Val<SC>>> + Algebra<SC::Challenge>,
{
}

/// Table prover for the recompose (BF→EF packing) NPO.
///
/// `lanes` controls how many operations are packed into a single AIR row.
/// Increasing this value reduces the trace height proportionally, at the cost of
/// a wider trace. Must be kept in sync with the corresponding [`RecomposeAirBuilder`].
pub struct RecomposeProver<const D: usize> {
    lanes: usize,
    /// When true, extra WitnessChecks receives are registered so a D=1 Poseidon2 inside a D>1
    /// circuit can read BF coefficients (per-coefficient receives per lane).
    coeff_lookups: bool,
}

impl<const D: usize> RecomposeProver<D> {
    /// Create a prover that packs `lanes` recompose operations per row.
    pub fn new(lanes: usize, coeff_lookups: bool) -> Self {
        Self {
            lanes: lanes.max(1),
            coeff_lookups,
        }
    }

    fn batch_instance_base<SC>(
        &self,
        _config: &SC,
        packing: &TablePacking,
        traces: &Traces<Val<SC>>,
    ) -> Option<BatchTableInstance<SC>>
    where
        SC: StarkGenericConfig + 'static + Send + Sync,
        Val<SC>: StarkField,
        SymbolicExpressionExt<Val<SC>, SC::Challenge>:
            Algebra<SymbolicExpression<Val<SC>>> + Algebra<SC::Challenge>,
    {
        let op_type = if self.coeff_lookups {
            NpoTypeId::recompose_with_coeff_lookups()
        } else {
            NpoTypeId::recompose()
        };
        let trace = traces.non_primitive_traces.get(&op_type)?;
        if trace.rows() == 0 {
            return None;
        }

        let t = trace.as_any().downcast_ref::<RecomposeTrace<Val<SC>>>()?;

        self.batch_instance_from_trace::<SC>(packing, t, None)
    }

    fn batch_instance_from_trace<SC>(
        &self,
        packing: &TablePacking,
        t: &RecomposeTrace<Val<SC>>,
        committed: Option<&[Val<SC>]>,
    ) -> Option<BatchTableInstance<SC>>
    where
        SC: StarkGenericConfig + 'static + Send + Sync,
        Val<SC>: StarkField,
        SymbolicExpressionExt<Val<SC>, SC::Challenge>:
            Algebra<SymbolicExpression<Val<SC>>> + Algebra<SC::Challenge>,
    {
        let op_type = if self.coeff_lookups {
            NpoTypeId::recompose_with_coeff_lookups()
        } else {
            NpoTypeId::recompose()
        };
        let num_ops = t.total_rows();
        if num_ops == 0 {
            return None;
        }
        // Prefer the per-op override from TablePacking; fall back to the prover's own default.
        let lanes = packing
            .npo_lanes(&op_type)
            .or_else(|| {
                if self.coeff_lookups {
                    packing.npo_lanes(&NpoTypeId::recompose())
                } else {
                    None
                }
            })
            .unwrap_or(self.lanes);
        let min_height = packing
            .npo_min_height(&op_type)
            .unwrap_or_else(|| packing.min_trace_height());

        let coeff_lookups = self.coeff_lookups;
        let preprocessed = committed.map_or_else(
            || {
                let prep_lane_width =
                    RecomposeAir::<Val<SC>, D>::preprocessed_lane_width_for(coeff_lookups);
                let mut preprocessed = Val::<SC>::zero_vec(num_ops * prep_lane_width);
                for (i, row) in t.operations.iter().enumerate() {
                    let base = i * prep_lane_width;
                    preprocessed[base] = row.output_wid.base_field_index::<Val<SC>, D>();
                    if coeff_lookups {
                        for (j, &coeff_wid) in row.input_wids.iter().enumerate().take(D) {
                            preprocessed[base + 2 + j * 2] =
                                coeff_wid.base_field_index::<Val<SC>, D>();
                        }
                    }
                }
                preprocessed
            },
            <[_]>::to_vec,
        );

        let air = RecomposeAir::<Val<SC>, D>::new_with_preprocessed(
            lanes,
            preprocessed,
            min_height,
            coeff_lookups,
        );
        let matrix = RecomposeAir::<Val<SC>, D>::trace_to_matrix(&t.operations, lanes);

        Some(BatchTableInstance {
            op_type,
            air: DynamicAirEntry::new(Box::new(air)),
            trace: matrix,
            public_values: Vec::new(),
            rows: num_ops,
            lanes,
        })
    }
}

impl<SC, const D: usize> TableProver<SC> for RecomposeProver<D>
where
    SC: StarkGenericConfig + 'static + Send + Sync,
    Val<SC>: StarkField,
    SymbolicExpressionExt<Val<SC>, SC::Challenge>:
        Algebra<SymbolicExpression<Val<SC>>> + Algebra<SC::Challenge>,
{
    fn op_type(&self) -> NpoTypeId {
        if self.coeff_lookups {
            NpoTypeId::recompose_with_coeff_lookups()
        } else {
            NpoTypeId::recompose()
        }
    }

    fn lanes(&self) -> usize {
        self.lanes
    }

    fn batch_instance_with_committed_preprocessed(
        &self,
        _config: &SC,
        packing: &TablePacking,
        traces: &[(&NpoTypeId, &dyn Any)],
        committed: &[Val<SC>],
        circuit_extension_degree: u32,
    ) -> Option<BatchTableInstance<SC>> {
        if circuit_extension_degree != D as u32 {
            return None;
        }
        let op_type = <Self as TableProver<SC>>::op_type(self);
        let trace = traces.iter().find(|(id, _)| **id == op_type)?.1;
        let trace = trace.downcast_ref::<RecomposeTrace<Val<SC>>>()?;
        let expected_kind = if self.coeff_lookups {
            RecomposeTraceKind::WithCoeffLookups
        } else {
            RecomposeTraceKind::Standard
        };
        if trace.kind != expected_kind {
            return None;
        }
        self.batch_instance_from_trace::<SC>(packing, trace, Some(committed))
    }

    impl_table_prover_batch_instances_from_base!(batch_instance_base);

    fn batch_air_from_table_entry(
        &self,
        _config: &SC,
        _degree: usize,
        _circuit_extension_degree: u32,
        table_entry: &NonPrimitiveTableEntry<SC>,
    ) -> Result<DynamicAirEntry<SC>, String> {
        let air = RecomposeAir::<Val<SC>, D>::new_with_preprocessed(
            table_entry.lanes,
            Vec::new(),
            1,
            self.coeff_lookups,
        );
        Ok(DynamicAirEntry::new(Box::new(air)))
    }

    fn air_with_committed_preprocessed(
        &self,
        committed_prep: Vec<Val<SC>>,
        min_height: usize,
        lanes: usize,
        _circuit_extension_degree: u32,
    ) -> Option<DynamicAirEntry<SC>> {
        let air = RecomposeAir::<Val<SC>, D>::new_with_preprocessed(
            lanes,
            committed_prep,
            min_height,
            self.coeff_lookups,
        );
        Some(DynamicAirEntry::new(Box::new(air)))
    }
}

// ============================================================================
// Preprocessor
// ============================================================================

/// NpoPreprocessor for the recompose table(s).
///
/// Converts EF preprocessed data to BF and sets `out_mult` from `ext_reads`.
/// When `split_coeff_tables` is true, emits separate base rows for `recompose` and `recompose/coeff`.
#[derive(Default, Clone)]
pub struct RecomposePreprocessor {
    pub split_coeff_tables: bool,
}

impl RecomposePreprocessor {
    pub const fn new(split_coeff_tables: bool) -> Self {
        Self { split_coeff_tables }
    }
}

impl NpoPreprocessor<KoalaBear> for RecomposePreprocessor {
    fn preprocess(
        &self,
        _circuit: &dyn core::any::Any,
        preprocessed: &mut dyn core::any::Any,
    ) -> Result<NonPrimitivePreprocessedMap<KoalaBear>, CircuitError> {
        type F = KoalaBear;
        let split = self.split_coeff_tables;
        if let Some(prep) =
            preprocessed.downcast_mut::<PreprocessedColumns<BinomialExtensionField<F, 4>, 4>>()
        {
            return recompose_preprocess_impl::<F, _, 4>(prep, split);
        }
        if let Some(prep) =
            preprocessed.downcast_mut::<PreprocessedColumns<QuinticTrinomialExtensionField<F>, 5>>()
        {
            return recompose_preprocess_impl::<F, _, 5>(prep, split);
        }
        if let Some(prep) = preprocessed.downcast_mut::<PreprocessedColumns<F, 1>>() {
            return recompose_preprocess_impl::<F, _, 1>(prep, split);
        }
        Ok(HashMap::new())
    }
}

impl NpoPreprocessor<BabyBear> for RecomposePreprocessor {
    fn preprocess(
        &self,
        _circuit: &dyn core::any::Any,
        preprocessed: &mut dyn core::any::Any,
    ) -> Result<NonPrimitivePreprocessedMap<BabyBear>, CircuitError> {
        type F = BabyBear;
        let split = self.split_coeff_tables;
        if let Some(prep) =
            preprocessed.downcast_mut::<PreprocessedColumns<BinomialExtensionField<F, 4>, 4>>()
        {
            return recompose_preprocess_impl::<F, _, 4>(prep, split);
        }
        if let Some(prep) = preprocessed.downcast_mut::<PreprocessedColumns<F, 1>>() {
            return recompose_preprocess_impl::<F, _, 1>(prep, split);
        }
        Ok(HashMap::new())
    }
}

impl NpoPreprocessor<Goldilocks> for RecomposePreprocessor {
    fn preprocess(
        &self,
        _circuit: &dyn core::any::Any,
        preprocessed: &mut dyn core::any::Any,
    ) -> Result<NonPrimitivePreprocessedMap<Goldilocks>, CircuitError> {
        type F = Goldilocks;
        let split = self.split_coeff_tables;
        if let Some(prep) =
            preprocessed.downcast_mut::<PreprocessedColumns<BinomialExtensionField<F, 2>, 2>>()
        {
            return recompose_preprocess_impl::<F, _, 2>(prep, split);
        }
        if let Some(prep) = preprocessed.downcast_mut::<PreprocessedColumns<F, 1>>() {
            return recompose_preprocess_impl::<F, _, 1>(prep, split);
        }
        Ok(HashMap::new())
    }
}

fn recompose_preprocess_impl<F, EF, const D: usize>(
    prep: &PreprocessedColumns<EF, D>,
    split_coeff_tables: bool,
) -> Result<NonPrimitivePreprocessedMap<F>, CircuitError>
where
    F: StarkField + PrimeField64,
    EF: Field + ExtensionField<F> + 'static,
{
    let mut result = HashMap::new();
    result.extend(recompose_preprocess_for_op::<F, EF, D>(
        prep,
        &NpoTypeId::recompose(),
        false,
    )?);
    if split_coeff_tables {
        result.extend(recompose_preprocess_for_op::<F, EF, D>(
            prep,
            &NpoTypeId::recompose_with_coeff_lookups(),
            true,
        )?);
    }
    Ok(result)
}

/// Extract preprocessed rows for one recompose `NpoTypeId` and set output / coeff multiplicities.
fn recompose_preprocess_for_op<F, EF, const D: usize>(
    prep: &PreprocessedColumns<EF, D>,
    op_type: &NpoTypeId,
    coeff_lookups: bool,
) -> Result<NonPrimitivePreprocessedMap<F>, CircuitError>
where
    F: StarkField + PrimeField64,
    EF: Field + ExtensionField<F> + 'static,
{
    let ef_data = match prep.non_primitive.get(op_type) {
        Some(d) if !d.is_empty() => d,
        _ => return Ok(HashMap::new()),
    };

    let prep_width = if coeff_lookups { 2 + 2 * D } else { 2 };

    let mut prep_base: Vec<F> = ef_data
        .iter()
        .map(|v| v.as_base().ok_or(CircuitError::InvalidPreprocessedValues))
        .collect::<Result<Vec<_>, CircuitError>>()?;

    if !prep_base.len().is_multiple_of(prep_width) {
        return Err(CircuitError::InvalidPreprocessedValues);
    }

    let neg_one = F::ZERO - F::ONE;
    let num_rows = prep_base.len() / prep_width;

    // Replays `generate_preprocessed_columns`'s coefficient arbitration: the rows below are in
    // the order the ops emitted them, so a coefficient whose creator is one of these rows is
    // created by its first occurrence here and read by every later one.
    let mut created_here: hashbrown::HashSet<u32> = hashbrown::HashSet::new();

    for row_idx in 0..num_rows {
        let row_start = row_idx * prep_width;

        let output_idx_val = prep_base[row_start];
        let out_wid = F::as_canonical_u64(&output_idx_val) as usize / D;

        let is_dup = prep
            .dup_npo_outputs
            .get(op_type)
            .and_then(|d| d.get(out_wid).copied())
            .unwrap_or(false);

        if is_dup {
            prep_base[row_start + 1] = neg_one;
        } else {
            let n_reads = prep.ext_reads.get(out_wid).copied().unwrap_or(0);
            prep_base[row_start + 1] = F::from_u32(n_reads);
        }

        if coeff_lookups {
            for i in 0..D {
                let coeff_idx_val = prep_base[row_start + 2 + i * 2];
                let coeff_wid = F::as_canonical_u64(&coeff_idx_val) as usize / D;
                let is_creator = prep
                    .recompose_coeff_creator_wids
                    .contains(&(coeff_wid as u32))
                    && created_here.insert(coeff_wid as u32);
                prep_base[row_start + 2 + i * 2 + 1] = if is_creator {
                    F::from_u32(prep.ext_reads.get(coeff_wid).copied().unwrap_or(0))
                } else {
                    neg_one
                };
            }
        }
    }

    // Every coefficient the circuit handed the creator role to must have been reached by one of
    // this table's rows; if it was not, the rows here are not the ones the arbitration saw.
    debug_assert!(
        !coeff_lookups
            || prep
                .recompose_coeff_creator_wids
                .iter()
                .all(|wid| created_here.contains(wid)),
        "a coefficient creator was arbitrated on a row this table does not carry"
    );

    let mut result = HashMap::new();
    result.insert(op_type.clone(), prep_base);
    Ok(result)
}

// ============================================================================
// AIR Builder
// ============================================================================

/// NpoAirBuilder for the recompose table.
///
/// `lanes` must match the value used in the paired [`RecomposeProver`].
#[derive(Clone)]
pub struct RecomposeAirBuilder<const D: usize> {
    lanes: usize,
    coeff_lookups: bool,
}

impl<const D: usize> RecomposeAirBuilder<D> {
    /// Create a builder that expects `lanes` operations packed per AIR row.
    pub fn new(lanes: usize, coeff_lookups: bool) -> Self {
        Self {
            lanes: lanes.max(1),
            coeff_lookups,
        }
    }
}

impl<SC, const D: usize> NpoAirBuilder<SC, D> for RecomposeAirBuilder<D>
where
    SC: StarkGenericConfig + 'static + Send + Sync,
    Val<SC>: StarkField,
    SymbolicExpressionExt<Val<SC>, SC::Challenge>:
        Algebra<SymbolicExpression<Val<SC>>> + Algebra<SC::Challenge>,
{
    fn lanes(&self) -> usize {
        self.lanes
    }

    fn try_build(
        &self,
        op_type: &NpoTypeId,
        prep_base: &[Val<SC>],
        min_height: usize,
        lanes: usize,
        _constraint_profile: ConstraintProfile,
    ) -> Option<(CircuitTableAir<SC, D>, usize)> {
        let matches = if !self.coeff_lookups {
            op_type.as_str() == "recompose"
        } else {
            op_type.as_str() == "recompose/coeff"
        };
        if !matches {
            return None;
        }

        let prep_lane_width =
            RecomposeAir::<Val<SC>, D>::preprocessed_lane_width_for(self.coeff_lookups);
        let num_ops = prep_base.len() / prep_lane_width;
        let num_rows = num_ops.div_ceil(lanes).max(1);

        let air = RecomposeAir::<Val<SC>, D>::new_with_preprocessed(
            lanes,
            prep_base.to_vec(),
            min_height,
            self.coeff_lookups,
        );

        let padded_rows = num_rows
            .next_power_of_two()
            .max(min_height.next_power_of_two());
        let degree = log2_ceil_usize(padded_rows);

        Some((
            CircuitTableAir::Dynamic(DynamicAirEntry::new(Box::new(air))),
            degree,
        ))
    }

    fn try_build_trusted(
        &self,
        op_type: &NpoTypeId,
        prep_base: &[Val<SC>],
        min_height: usize,
        lanes: usize,
        constraint_profile: ConstraintProfile,
    ) -> Option<BuiltNpoTable<SC, D>> {
        let built = self.try_build(op_type, prep_base, min_height, lanes, constraint_profile)?;
        let prep_lane_width =
            RecomposeAir::<Val<SC>, D>::preprocessed_lane_width_for(self.coeff_lookups);
        Some(BuiltNpoTable::new(
            built.0,
            built.1,
            NpoRelation::new(
                op_type.clone(),
                prep_base.len() / prep_lane_width,
                lanes,
                AirVariant::Baseline,
                Vec::new(),
            ),
        ))
    }
}

#[cfg(test)]
mod committed_materialization_tests {
    use p3_air::BaseAir;
    use p3_circuit::ops::recompose::RecomposeCircuitRow;
    use p3_circuit::types::WitnessId;

    use super::*;
    use crate::config::KoalaBearConfig;

    fn check_recompose<const D: usize>() {
        let config = crate::config::koala_bear();
        for coeff_lookups in [false, true] {
            let prover = RecomposeProver::<D>::new(1, coeff_lookups);
            let op_type = <RecomposeProver<D> as TableProver<KoalaBearConfig>>::op_type(&prover);
            for lanes in [1, 2, 4] {
                let packing = TablePacking::new(1, 1)
                    .with_npo_lanes(op_type.clone(), lanes)
                    .with_npo_min_height(op_type.clone(), 8);
                let trace = RecomposeTrace {
                    operations: (0..3)
                        .map(|row| RecomposeCircuitRow {
                            input_wids: (0..D)
                                .map(|i| WitnessId((row * D + i + 1) as u32))
                                .collect(),
                            output_wid: WitnessId((100 + row) as u32),
                            values: (0..D)
                                .map(|i| KoalaBear::from_usize(row * D + i + 1))
                                .collect(),
                        })
                        .collect(),
                    kind: if coeff_lookups {
                        RecomposeTraceKind::WithCoeffLookups
                    } else {
                        RecomposeTraceKind::Standard
                    },
                };
                let reference = prover
                    .batch_instance_from_trace::<KoalaBearConfig>(&packing, &trace, None)
                    .unwrap();
                let mut committed = reference.air.preprocessed_trace().unwrap().values;
                committed[1] = KoalaBear::from_u32(9);
                let expected_air = <RecomposeProver<D> as TableProver<KoalaBearConfig>>::air_with_committed_preprocessed(
                    &prover, committed.clone(), 8, lanes, D as u32,
                ).unwrap();
                let sources = [(&op_type, &trace as &dyn Any)];
                let direct = prover
                    .batch_instance_with_committed_preprocessed(
                        &config, &packing, &sources, &committed, D as u32,
                    )
                    .unwrap();
                assert_eq!(direct.op_type, op_type);
                assert_eq!(direct.rows, 3);
                assert_eq!(direct.lanes, lanes);
                assert_eq!(direct.trace, reference.trace);
                assert_eq!(
                    direct.air.preprocessed_trace(),
                    expected_air.preprocessed_trace()
                );
                assert!(
                    prover
                        .batch_instance_with_committed_preprocessed(
                            &config,
                            &packing,
                            &sources,
                            &committed,
                            D as u32 + 1,
                        )
                        .is_none()
                );
                let mut wrong_kind = trace.clone();
                wrong_kind.kind = if coeff_lookups {
                    RecomposeTraceKind::Standard
                } else {
                    RecomposeTraceKind::WithCoeffLookups
                };
                let wrong_sources = [(&op_type, &wrong_kind as &dyn Any)];
                assert!(
                    prover
                        .batch_instance_with_committed_preprocessed(
                            &config,
                            &packing,
                            &wrong_sources,
                            &committed,
                            D as u32,
                        )
                        .is_none()
                );
            }
        }
    }

    #[test]
    fn committed_recompose_materialization_preserves_packing_and_preprocessing() {
        check_recompose::<4>();
        check_recompose::<5>();
    }

    fn prove_packed_coeff_lookups<EF, const D: usize>()
    where
        EF: Field + ExtensionField<KoalaBear> + crate::field_params::ExtractBinomialW<KoalaBear>,
    {
        use p3_circuit::builder::CircuitBuilder;
        use p3_circuit::ops::generate_recompose_trace;

        use crate::batch_stark_prover::{BatchStarkProver, recompose_air_builders};

        let mut builder = CircuitBuilder::<EF>::new();
        builder.enable_recompose::<KoalaBear>(generate_recompose_trace::<KoalaBear, EF>);
        let mut inputs = Vec::new();
        for row in 0..5 {
            let input = builder.public_input();
            let coeffs = builder
                .decompose_ext_to_base_coeffs_with_coeff_lookups::<KoalaBear>(input)
                .unwrap();
            for (i, coeff) in coeffs.into_iter().enumerate() {
                let expected = builder.define_const(EF::from_u32((row * D + i + 1) as u32));
                builder.connect(coeff, expected);
            }
            inputs.push(EF::from_basis_coefficients_fn(|i| {
                KoalaBear::from_usize(row * D + i + 1)
            }));
        }
        let circuit = builder.build().unwrap();
        let mut runner = circuit.runner();
        runner.set_public_inputs(&inputs).unwrap();
        let traces = runner.run().unwrap();
        let op_type = NpoTypeId::recompose_with_coeff_lookups();
        for lanes in [2, 4] {
            let packing = TablePacking::new(1, 1).with_npo_lanes(op_type.clone(), lanes);
            let mut prover =
                BatchStarkProver::new(crate::config::koala_bear()).with_table_packing(packing);
            prover.register_table_prover(Box::new(RecomposeProver::<D>::new(1, true)));
            let prepared = prover
                .prepare_circuit::<EF, D>(
                    &circuit,
                    &[Box::new(RecomposePreprocessor::new(true))],
                    &recompose_air_builders::<KoalaBearConfig, D>(1, true),
                    ConstraintProfile::Standard,
                )
                .unwrap();
            let proof = prepared.prove(&traces).unwrap();
            prepared.verifier().verify(&proof, &[]).unwrap();
            let table = proof
                .non_primitives
                .iter()
                .find(|table| table.op_type == op_type)
                .unwrap();
            assert_eq!(table.lanes, lanes);
            assert_eq!(table.rows, 5);
        }
    }

    #[test]
    fn prepared_coeff_lookups_prove_partial_packed_rows() {
        prove_packed_coeff_lookups::<BinomialExtensionField<KoalaBear, 4>, 4>();
        prove_packed_coeff_lookups::<QuinticTrinomialExtensionField<KoalaBear>, 5>();
    }
}
