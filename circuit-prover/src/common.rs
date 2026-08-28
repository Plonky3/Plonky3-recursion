use alloc::boxed::Box;
use alloc::string::ToString;
use alloc::vec::Vec;
use core::any::Any;

use hashbrown::HashMap;
use p3_circuit::ops::{NonPrimitivePreprocessedMap, NpoTypeId, PrimitiveOpType};
use p3_circuit::{Circuit, CircuitError};
use p3_field::{Algebra, ExtensionField, Field, PrimeCharacteristicRing, PrimeField64};
use p3_uni_stark::{StarkGenericConfig, SymbolicExpression, SymbolicExpressionExt, Val};
use p3_util::log2_ceil_usize;

use crate::air::{AluAir, AluExtMulKind, ConstAir, PublicAir};
use crate::config::StarkField;
use crate::field_params::ExtractBinomialW;
use crate::{ConstraintProfile, DynamicAirEntry, ProofMetadataError, TablePacking};

/// Force a table's lane count to 1 when it holds only dummy data.
///
/// Multi-lane padding interacts incorrectly with lookup constraints during recursive
/// verification when a table has no real operations, so lanes are reduced to 1 (with a
/// warning) in that case.
pub(crate) fn reduce_lanes_if_dummy(
    table: &str,
    only_dummy: bool,
    configured_lanes: usize,
) -> usize {
    if only_dummy && configured_lanes > 1 {
        tracing::warn!(
            "{table} table holds only dummy operations but lanes={configured_lanes} > 1. \
             Reducing to lanes=1 to avoid recursive verification issues.",
        );
        1
    } else {
        configured_lanes
    }
}

/// Plugin trait for NPO-owned preprocessing over generic circuits.
///
/// Each implementation can update `PreprocessedColumns` (ext_reads, multiplicities, etc.)
/// and return base-field non-primitive preprocessed rows for its own `NpoTypeId`s.
pub trait NpoPreprocessor<F>: Send + Sync
where
    F: StarkField + PrimeField64,
{
    /// Run plugin-owned preprocessing over a generic circuit.
    ///
    /// `circuit` and `preprocessed` are type-erased; implementations downcast to the
    /// `PreprocessedColumns<ExtF>` shapes they support and return an empty map otherwise.
    fn preprocess(
        &self,
        circuit: &dyn Any,
        preprocessed: &mut dyn Any,
    ) -> Result<NonPrimitivePreprocessedMap<F>, CircuitError>;
}

/// Builds (AIR, degree) from preprocessed base data for a given NPO op_type.
/// Used by `get_airs_and_degrees_with_prep` so that AIR construction is plugin-driven
/// without requiring generic methods on the preprocessor trait (object safety).
pub trait NpoAirBuilder<SC, const D: usize>: Send + Sync
where
    SC: StarkGenericConfig,
    SymbolicExpressionExt<Val<SC>, SC::Challenge>: Algebra<SymbolicExpression<Val<SC>>>,
{
    /// Number of operations packed into a single AIR row for this NPO.
    ///
    /// Must match the `lanes` value returned by the corresponding [`TableProver`] implementation.
    /// Defaults to 1.
    fn lanes(&self) -> usize {
        1
    }

    /// Attempt to build an AIR and compute its degree from committed preprocessed data.
    ///
    /// The `lanes` argument is `self.lanes()` forwarded by the framework.
    fn try_build(
        &self,
        op_type: &NpoTypeId,
        prep_base: &[Val<SC>],
        min_height: usize,
        lanes: usize,
        constraint_profile: ConstraintProfile,
    ) -> Option<(CircuitTableAir<SC, D>, usize)>;
}

/// Enum wrapper to allow heterogeneous table AIRs in a single batch STARK aggregation.
///
/// This enables different AIR types to be collected into a single vector for
/// batch STARK proving/verification while maintaining type safety.
pub enum CircuitTableAir<SC, const D: usize>
where
    SC: StarkGenericConfig,
    SymbolicExpressionExt<Val<SC>, SC::Challenge>: Algebra<SymbolicExpression<Val<SC>>>,
{
    Const(ConstAir<Val<SC>, D>),
    Public(PublicAir<Val<SC>, D>),
    /// Unified ALU table for all arithmetic operations
    Alu(AluAir<Val<SC>, D>),
    Dynamic(DynamicAirEntry<SC>),
}

impl<SC, const D: usize> Clone for CircuitTableAir<SC, D>
where
    SC: StarkGenericConfig,
    SymbolicExpressionExt<Val<SC>, SC::Challenge>: Algebra<SymbolicExpression<Val<SC>>>,
{
    fn clone(&self) -> Self {
        match self {
            Self::Const(air) => Self::Const(air.clone()),
            Self::Public(air) => Self::Public(air.clone()),
            Self::Alu(air) => Self::Alu(air.clone()),
            Self::Dynamic(air) => Self::Dynamic(air.clone()),
        }
    }
}

/// Type alias for a vector of circuit table AIRs paired with their respective degrees (log of their trace height).
type CircuitAirsWithDegrees<SC, const D: usize> = Vec<(CircuitTableAir<SC, D>, usize)>;

/// Output of [`get_airs_and_degrees_with_prep`]: AIRs with degrees, primitive columns, and non-primitive columns.
type PrepOutput<SC, const D: usize> = (
    CircuitAirsWithDegrees<SC, D>,
    Vec<Vec<Val<SC>>>,
    NonPrimitivePreprocessedMap<Val<SC>>,
);

pub fn get_airs_and_degrees_with_prep<
    SC: StarkGenericConfig + 'static + Send + Sync,
    ExtF: Field + ExtensionField<Val<SC>> + ExtractBinomialW<Val<SC>>,
    const D: usize,
>(
    circuit: &Circuit<ExtF>,
    packing: &TablePacking,
    non_primitive_preprocessors: &[Box<dyn NpoPreprocessor<Val<SC>>>],
    non_primitive_air_builders: &[Box<dyn NpoAirBuilder<SC, D>>],
    constraint_profile: ConstraintProfile,
) -> Result<PrepOutput<SC, D>, CircuitError>
where
    SymbolicExpressionExt<Val<SC>, SC::Challenge>: Algebra<SymbolicExpression<Val<SC>>>,
    Val<SC>: StarkField,
{
    // Reject a misconfigured packing (e.g. a per-table override below the global
    // min-height floor) before any table height derived from it is used to build or
    // pad the preprocessed trace, rather than only catching it later via
    // `BatchStarkProof::validate`.
    packing.validate()?;

    let mut preprocessed = circuit.generate_preprocessed_columns::<D>()?;

    // Check if Public/Alu tables are empty and lanes > 1.
    // Using lanes > 1 with empty tables causes issues in recursive verification
    // due to a bug in how multi-lane padding interacts with lookup constraints.
    // We automatically reduce lanes to 1 in these cases with a warning.
    // IMPORTANT: This must be synchronized with prove_all_tables in batch_stark_prover.rs
    let public_idx = PrimitiveOpType::Public as usize;
    let alu_idx = PrimitiveOpType::Alu as usize;

    let public_rows = preprocessed.primitive[public_idx].len();
    let effective_public_lanes =
        reduce_lanes_if_dummy("Public", public_rows <= 1, packing.public_lanes());

    let alu_empty = preprocessed.primitive[alu_idx].is_empty();
    let effective_alu_lanes = reduce_lanes_if_dummy("ALU", alu_empty, packing.alu_lanes());

    let w_binomial = ExtF::extract_w();

    // First, get base field elements for the preprocessed primitive values.
    let mut base_prep: Vec<Vec<Val<SC>>> = preprocessed
        .primitive
        .iter()
        .map(|vals| {
            vals.iter()
                .map(|v| v.as_base().ok_or(CircuitError::InvalidPreprocessedValues))
                .collect::<Result<Vec<_>, CircuitError>>()
        })
        .collect::<Result<Vec<_>, CircuitError>>()?;

    // Let plugins handle non-primitive preprocessing (ext_reads, multiplicities, etc.).
    let mut non_primitive_base: NonPrimitivePreprocessedMap<Val<SC>> = HashMap::new();
    let circuit_any: &dyn Any = circuit;
    let preprocessed_any: &mut dyn Any = &mut preprocessed;
    for plugin in non_primitive_preprocessors {
        let plugin_prep = plugin.preprocess(circuit_any, preprocessed_any)?;
        non_primitive_base.extend(plugin_prep);
    }

    // Get min_height from packing configuration and pass it to AIRs
    let min_height = packing.min_trace_height();

    // Helper to compute degree that respects a per-table minimum height override, falling
    // back to the global `min_height` when no override is set for that table. When
    // `packing.is_strict()` is set, a table that naturally outgrows its configured height
    // is rejected instead of silently clamped (padded) up to fit.
    let compute_degree = |num_rows: usize,
                          table_override: Option<usize>,
                          table_name: &str|
     -> Result<usize, CircuitError> {
        let natural_height = num_rows.next_power_of_two();
        let effective_min = table_override.unwrap_or(min_height).next_power_of_two();
        if packing.is_strict() && natural_height > effective_min {
            return Err(CircuitError::from(ProofMetadataError::ProfileOverflow {
                table: table_name.to_string(),
                needed: natural_height,
                allowed: effective_min,
            }));
        }
        Ok(log2_ceil_usize(natural_height.max(effective_min)))
    };

    let mut table_preps: Vec<(CircuitTableAir<SC, D>, usize)> =
        Vec::with_capacity(base_prep.len() + non_primitive_base.len());

    #[allow(clippy::needless_range_loop)]
    for idx in 0..base_prep.len() {
        let table = PrimitiveOpType::from(idx);
        match table {
            PrimitiveOpType::Alu => {
                // ALU preprocessed per op from circuit.rs: 12 values
                // [sel_add_vs_mul, sel_bool, sel_muladd, sel_horner, a_idx, b_idx, c_idx, out_idx,
                //  mult_a_eff, b_is_creator, mult_c_eff, out_is_creator]
                //
                // mult_a_eff / mult_c_eff: -1 (reader or later unconstrained), or +N (first
                // unconstrained creator). We convert to 12 values for AluAir (same order, mult_c_eff last).
                let lane_12 = 12_usize;
                let neg_one = <Val<SC>>::ZERO - <Val<SC>>::ONE;

                let mut chunks = base_prep[idx].chunks_exact(lane_12);
                let mut prep_13col: Vec<Val<SC>> = Vec::with_capacity(
                    chunks.len() * lane_12 + if alu_empty { 0 } else { lane_12 },
                );
                for chunk in &mut chunks {
                    let sel1 = chunk[0];
                    let sel2 = chunk[1];
                    let sel3 = chunk[2];
                    let sel4 = chunk[3];
                    let a_idx = chunk[4];
                    let b_idx = chunk[5];
                    let c_idx = chunk[6];
                    let out_idx = chunk[7];
                    let a_state = chunk[8].as_canonical_u64();
                    let b_is_creator = chunk[9].as_canonical_u64() != 0;
                    let c_state = chunk[10].as_canonical_u64();
                    let out_is_creator = chunk[11].as_canonical_u64() != 0;

                    // mult_a = -1 for all active rows; active = -mult_a = 1 always.
                    // Effective a-lookup mult = mult_a * a_reader_col (in get_alu_index_lookups).
                    // Effective c-lookup mult = mult_a * c_reader_col (in get_alu_index_lookups).
                    //
                    // a_state / c_state encoding:
                    //   0 → skip: col = 0, eff = 0
                    //   1 → reader: col = 1, eff = (-1)*1 = -1
                    //   2 → private creator: col = -(n_reads), eff = (-1)*(-(n_reads)) = +n_reads
                    let mult_a = neg_one;
                    let a_reader_col = match a_state {
                        0 => <Val<SC>>::ZERO,
                        1 => <Val<SC>>::ONE,
                        2 => {
                            let a_wid = a_idx.as_canonical_u64() as usize / D;
                            let n_reads = preprocessed.ext_reads.get(a_wid).copied().unwrap_or(0);
                            <Val<SC>>::ZERO - <Val<SC>>::from_u32(n_reads)
                        }
                        _ => <Val<SC>>::ZERO,
                    };
                    let c_reader_col = match c_state {
                        0 => <Val<SC>>::ZERO,
                        1 => <Val<SC>>::ONE,
                        2 => {
                            let c_wid = c_idx.as_canonical_u64() as usize / D;
                            let n_reads = preprocessed.ext_reads.get(c_wid).copied().unwrap_or(0);
                            <Val<SC>>::ZERO - <Val<SC>>::from_u32(n_reads)
                        }
                        _ => <Val<SC>>::ZERO,
                    };

                    // b: creator if b_is_creator, reader otherwise.
                    let mult_b = if b_is_creator {
                        let b_wid = b_idx.as_canonical_u64() as usize / D;
                        let n_reads = preprocessed.ext_reads.get(b_wid).copied().unwrap_or(0);
                        <Val<SC>>::from_u32(n_reads)
                    } else {
                        neg_one
                    };

                    // out: creator if out_is_creator, reader otherwise.
                    let mult_out = if out_is_creator {
                        let out_wid = out_idx.as_canonical_u64() as usize / D;
                        let n_reads = preprocessed.ext_reads.get(out_wid).copied().unwrap_or(0);
                        <Val<SC>>::from_u32(n_reads)
                    } else {
                        neg_one
                    };

                    prep_13col.extend([
                        mult_a,
                        sel1,
                        sel2,
                        sel3,
                        sel4,
                        a_idx,
                        b_idx,
                        c_idx,
                        out_idx,
                        mult_b,
                        mult_out,
                        a_reader_col,
                        c_reader_col,
                    ]);
                }
                debug_assert!(chunks.remainder().is_empty());

                // If ALU was empty, add a dummy row (all zeros = padding, no logup contribution).
                if alu_empty {
                    prep_13col.extend([<Val<SC>>::ZERO; 13]);
                }

                let num_ops = prep_13col.len() / 13;
                let horner_k = packing.horner_packed_steps();
                // Store the converted 13-col format before building the AIR.
                base_prep[idx] = prep_13col;
                let reduction = AluExtMulKind::resolve(
                    D,
                    w_binomial,
                    D == 5 && ExtF::alu_is_quintic_trinomial(),
                )
                .expect(
                    "ALU preprocessed path needs binomial W when D>1 and the element field is \
                     not the quintic-trinomial ALU variant. Use D=1 for base-field circuits \
                     (ExtF = Val<SC>); for extension circuits use D = ExtF::DIMENSION and a \
                     binomial or supported quintic ExtF.",
                );
                let alu_air = AluAir::from_reduction_with_preprocessed(
                    num_ops,
                    effective_alu_lanes,
                    reduction,
                    base_prep[idx].clone(),
                    horner_k,
                )
                .with_min_height(packing.alu_min_height().unwrap_or(min_height));
                let num_entries = alu_air.scheduled_entry_count();
                let num_rows = num_entries.div_ceil(effective_alu_lanes);
                let alu_degree = compute_degree(num_rows, packing.alu_min_height(), "ALU")?;
                table_preps.push((CircuitTableAir::Alu(alu_air), alu_degree));
            }
            PrimitiveOpType::Public => {
                // Public preprocessed per op from circuit.rs: 1 value (D-scaled out_idx).
                // Convert to [ext_mult, out_idx] pairs using ext_reads.
                let mut prep_2col: Vec<Val<SC>> = Vec::with_capacity(base_prep[idx].len() * 2);
                for &out_idx in &base_prep[idx] {
                    let out_wid =
                        (<Val<SC> as PrimeField64>::as_canonical_u64(&out_idx) as usize) / D;
                    let n_reads = preprocessed.ext_reads.get(out_wid).copied().unwrap_or(0);
                    prep_2col.push(<Val<SC>>::from_u32(n_reads));
                    prep_2col.push(out_idx);
                }

                let num_ops = prep_2col.len() / 2;
                // Store the converted 2-col format before building the AIR.
                base_prep[idx] = prep_2col;
                let public_air = PublicAir::new_with_preprocessed(
                    num_ops,
                    effective_public_lanes,
                    base_prep[idx].clone(),
                )
                .with_min_height(packing.public_min_height().unwrap_or(min_height));
                let num_rows = num_ops.div_ceil(effective_public_lanes);
                let public_degree =
                    compute_degree(num_rows, packing.public_min_height(), "PUBLIC")?;
                table_preps.push((CircuitTableAir::Public(public_air), public_degree));
            }
            PrimitiveOpType::Const => {
                // Const preprocessed per op from circuit.rs: 1 value (D-scaled out_idx).
                // Convert to [ext_mult, out_idx] pairs using ext_reads.
                let mut prep_2col: Vec<Val<SC>> = Vec::with_capacity(base_prep[idx].len() * 2);
                for &out_idx in &base_prep[idx] {
                    let out_wid = out_idx.as_canonical_u64() as usize / D;
                    let n_reads = preprocessed.ext_reads.get(out_wid).copied().unwrap_or(0);
                    prep_2col.push(<Val<SC>>::from_u32(n_reads));
                    prep_2col.push(out_idx);
                }

                let height = prep_2col.len() / 2;
                // Store the converted 2-col format before building the AIR.
                base_prep[idx] = prep_2col;
                let const_air = ConstAir::new_with_preprocessed(height, base_prep[idx].clone())
                    .with_min_height(packing.const_min_height().unwrap_or(min_height));
                let const_degree = compute_degree(height, packing.const_min_height(), "CONST")?;
                table_preps.push((CircuitTableAir::Const(const_air), const_degree));
            }
        }
    }

    // Iterate air builders first (fixed registration order) so that the
    // resulting AIR ordering matches the prover's non_primitive_provers order.
    for builder in non_primitive_air_builders {
        for (op_type, prep_base) in non_primitive_base.iter() {
            // TablePacking overrides the builder's own default lane count.
            let lanes = packing
                .npo_lanes(op_type)
                .unwrap_or_else(|| builder.lanes());
            let npo_min_height = packing.npo_min_height(op_type).unwrap_or(min_height);
            if let Some((air, degree)) = builder.try_build(
                op_type,
                prep_base,
                npo_min_height,
                lanes,
                constraint_profile,
            ) {
                // Every current `NpoAirBuilder` impl computes `degree` as
                // `log2_ceil(max(natural_rows.next_pow2, npo_min_height.next_pow2))`, so the
                // built height exceeds the allowed height iff the table's natural row count
                // outgrew its configured minimum -- the same condition `compute_degree`
                // checks for the primitive tables, recovered here without needing
                // `try_build`'s internal `num_rows`.
                let allowed = npo_min_height.next_power_of_two();
                let built_height = 1usize << degree;
                if packing.is_strict() && built_height > allowed {
                    return Err(CircuitError::from(ProofMetadataError::ProfileOverflow {
                        table: op_type.to_string(),
                        needed: built_height,
                        allowed,
                    }));
                }
                table_preps.push((air, degree));
                break;
            }
        }
    }

    Ok((table_preps, base_prep, non_primitive_base))
}

#[cfg(test)]
mod per_table_height_tests {
    use p3_air::BaseAir;
    use p3_circuit::CircuitBuilder;
    use p3_field::PrimeCharacteristicRing;
    use p3_matrix::Matrix;
    use p3_test_utils::koala_bear_params::{F, MyConfig};

    use super::{CircuitTableAir, get_airs_and_degrees_with_prep};
    use crate::TablePacking;

    #[test]
    fn alu_min_height_override_forces_alu_table_taller_than_natural() {
        let mut builder = CircuitBuilder::<F>::new();
        let a = builder.define_const(F::from_u32(2));
        let b = builder.define_const(F::from_u32(3));
        let _c = builder.mul(a, b); // one ALU op -> natural height 1 (padded to 2 minimum)
        let circuit = builder.build().unwrap();

        let packing = TablePacking::new(1, 1).with_alu_min_height(64);
        let (airs_degrees, _, _) = get_airs_and_degrees_with_prep::<MyConfig, F, 1>(
            &circuit,
            &packing,
            &[],
            &[],
            Default::default(),
        )
        .unwrap();

        let alu_degree = airs_degrees
            .iter()
            .find_map(|(air, degree)| matches!(air, CircuitTableAir::Alu(_)).then_some(*degree))
            .expect("ALU air present");
        assert_eq!(1usize << alu_degree, 64);
    }

    /// Guards against the exact divergence this task exists to prevent: the height each
    /// primitive AIR reports via its returned `degree` must equal the actual height of the
    /// preprocessed trace it builds (`BaseAir::preprocessed_trace`). `ProverData::from_airs_and_degrees`
    /// (in `p3-batch-stark`) asserts this invariant when committing prep data; a per-table
    /// override that only fed `compute_degree` but not the AIR's own `with_min_height(..)` call
    /// would silently violate it the moment the two heights differ.
    #[test]
    fn const_public_alu_min_height_overrides_are_independent_and_consistent() {
        let mut builder = CircuitBuilder::<F>::new();
        let expected = builder.alloc_public_input("expected");
        let a = builder.define_const(F::from_u32(2));
        let b = builder.define_const(F::from_u32(3));
        let c = builder.mul(a, b);
        builder.connect(c, expected);
        let circuit = builder.build().unwrap();

        let packing = TablePacking::new(1, 1)
            .with_const_min_height(8)
            .with_public_min_height(16)
            .with_alu_min_height(32);
        let (airs_degrees, _, _) = get_airs_and_degrees_with_prep::<MyConfig, F, 1>(
            &circuit,
            &packing,
            &[],
            &[],
            Default::default(),
        )
        .unwrap();

        for (air, degree) in &airs_degrees {
            let expected_height = match air {
                CircuitTableAir::Const(_) => 8usize,
                CircuitTableAir::Public(_) => 16usize,
                CircuitTableAir::Alu(_) => 32usize,
                CircuitTableAir::Dynamic(_) => continue,
            };
            assert_eq!(
                1usize << degree,
                expected_height,
                "returned degree does not match the configured per-table override"
            );

            let prep_height = air
                .preprocessed_trace()
                .expect("primitive tables always carry preprocessed data")
                .height();
            assert_eq!(
                prep_height, expected_height,
                "preprocessed trace height must match the returned degree"
            );
        }
    }
}

#[cfg(test)]
mod strict_overflow_tests {
    use p3_circuit::{CircuitBuilder, CircuitError};
    use p3_field::PrimeCharacteristicRing;
    use p3_test_utils::koala_bear_params::{F, MyConfig};

    use super::get_airs_and_degrees_with_prep;
    use crate::TablePacking;

    /// Asserts `result` is `Err(CircuitError::ProfileOverflow { table, .. })` with the given
    /// table name, printing a descriptive message (not just `is_err()`) on any other outcome.
    fn assert_overflows_on(
        result: Result<super::PrepOutput<MyConfig, 1>, CircuitError>,
        expected_table: &str,
    ) {
        match result {
            Err(CircuitError::ProfileOverflow { table, .. }) => {
                assert_eq!(table, expected_table);
            }
            Ok(_) => panic!("expected ProfileOverflow on {expected_table}, got Ok"),
            Err(other) => {
                panic!(
                    "expected ProfileOverflow on {expected_table}, got a different error: {other}"
                )
            }
        }
    }

    #[test]
    fn strict_packing_rejects_a_table_that_outgrows_its_configured_height() {
        // A chain of 20 ALU (mul) ops: each step's output feeds the next `mul`, so every
        // op has a distinct operand and none constant-fold or CSE-collapse, while only ONE
        // const and ONE public input are ever defined. This isolates the overflow to ALU:
        // CONST's and PUBLIC's natural heights (1 each) stay far under the global floor,
        // while ALU's natural height (20 -> pow2 32) exceeds its own override.
        let mut builder = CircuitBuilder::<F>::new();
        let c = builder.define_const(F::from_u32(3));
        let mut acc = builder.public_input();
        for _ in 0..20 {
            acc = builder.mul(acc, c);
        }
        let _ = acc;
        let circuit = builder.build().unwrap();

        let packing = TablePacking::new(1, 1)
            .with_min_trace_height(4) // comfortably covers CONST/PUBLIC's natural height of 1
            .with_alu_min_height(8) // >= the floor (passes validate()), but < ALU's natural 32
            .with_strict_heights();

        let result = get_airs_and_degrees_with_prep::<MyConfig, F, 1>(
            &circuit,
            &packing,
            &[],
            &[],
            Default::default(),
        );

        assert_overflows_on(result, "ALU");
    }

    #[test]
    fn strict_packing_reports_const_as_the_overflowing_table() {
        // 10 distinct consts, never read by any ALU op: CONST's natural height (10 -> 16)
        // exceeds the global floor, while PUBLIC/ALU are both empty (dummy-padded to 1 row).
        let mut builder = CircuitBuilder::<F>::new();
        for i in 0u32..10 {
            let _ = builder.define_const(F::from_u32(i + 2));
        }
        let circuit = builder.build().unwrap();

        let packing = TablePacking::new(1, 1)
            .with_min_trace_height(4)
            .with_strict_heights();

        let result = get_airs_and_degrees_with_prep::<MyConfig, F, 1>(
            &circuit,
            &packing,
            &[],
            &[],
            Default::default(),
        );

        assert_overflows_on(result, "CONST");
    }

    #[test]
    fn strict_packing_reports_public_as_the_overflowing_table() {
        // 10 distinct public inputs: PUBLIC's natural height (10 -> 16) exceeds the global
        // floor, while CONST/ALU are both empty (dummy-padded to 1 row).
        let mut builder = CircuitBuilder::<F>::new();
        for _ in 0u32..10 {
            let _ = builder.public_input();
        }
        let circuit = builder.build().unwrap();

        let packing = TablePacking::new(1, 1)
            .with_min_trace_height(4)
            .with_strict_heights();

        let result = get_airs_and_degrees_with_prep::<MyConfig, F, 1>(
            &circuit,
            &packing,
            &[],
            &[],
            Default::default(),
        );

        assert_overflows_on(result, "PUBLIC");
    }

    #[test]
    fn non_strict_packing_still_clamps_up_as_before() {
        let mut builder = CircuitBuilder::<F>::new();
        let x = builder.public_input();
        let c = builder.define_const(F::from_u32(2));
        let _ = builder.mul(x, c);
        let circuit = builder.build().unwrap();

        let packing = TablePacking::new(1, 1).with_alu_min_height(2); // no with_strict_heights()

        let result = get_airs_and_degrees_with_prep::<MyConfig, F, 1>(
            &circuit,
            &packing,
            &[],
            &[],
            Default::default(),
        );

        assert!(result.is_ok());
    }
}

#[cfg(test)]
mod validate_in_prove_path_tests {
    use p3_circuit::CircuitBuilder;
    use p3_field::PrimeCharacteristicRing;
    use p3_test_utils::koala_bear_params::{F, MyConfig};

    use super::get_airs_and_degrees_with_prep;
    use crate::TablePacking;

    /// A per-table override below the global `min_trace_height` floor must be rejected
    /// where proving actually starts, not only later via `BatchStarkProof::validate` at
    /// verification time -- by then an inconsistent preprocessed-column commitment may
    /// already have been built.
    #[test]
    fn get_airs_and_degrees_with_prep_rejects_below_floor_override_before_building_prep() {
        let mut builder = CircuitBuilder::<F>::new();
        let a = builder.define_const(F::from_u32(2));
        let b = builder.define_const(F::from_u32(3));
        let _ = builder.mul(a, b);
        let circuit = builder.build().unwrap();

        let packing = TablePacking::new(1, 1)
            .with_min_trace_height(32)
            .with_alu_min_height(4); // valid power of two, but below the 32 floor

        let result = get_airs_and_degrees_with_prep::<MyConfig, F, 1>(
            &circuit,
            &packing,
            &[],
            &[],
            Default::default(),
        );

        assert!(
            result.is_err(),
            "a below-floor per-table override must be rejected before prep is built, \
             not silently used to commit an inconsistent preprocessed trace"
        );
    }
}
