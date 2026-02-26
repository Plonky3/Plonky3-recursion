use alloc::collections::btree_map::BTreeMap;
use alloc::vec::Vec;
use core::borrow::{Borrow, BorrowMut};

use hashbrown::HashMap;
use p3_circuit::op::{
    NonPrimitiveOpType, NonPrimitivePreprocessedMap, Poseidon2Config, PrimitiveOpType,
};
use p3_circuit::{Circuit, CircuitError, PreprocessedColumns};
use p3_field::{ExtensionField, PrimeCharacteristicRing, PrimeField64};
use p3_poseidon2_circuit_air::{Poseidon2PreprocessedRow, poseidon2_preprocessed_width};
use p3_uni_stark::{StarkGenericConfig, SymbolicExpression, Val};
use p3_util::log2_ceil_usize;

use crate::air::{AluAir, ConstAir, PublicAir};
use crate::config::StarkField;
use crate::constraint_profile::ConstraintProfile;
use crate::field_params::ExtractBinomialW;
use crate::{DynamicAirEntry, Poseidon2Prover, TablePacking};

/// Enum wrapper to allow heterogeneous table AIRs in a single batch STARK aggregation.
///
/// This enables different AIR types to be collected into a single vector for
/// batch STARK proving/verification while maintaining type safety.
pub enum CircuitTableAir<SC, const D: usize>
where
    SC: StarkGenericConfig,
    SymbolicExpression<SC::Challenge>: From<SymbolicExpression<Val<SC>>>,
{
    Const(ConstAir<Val<SC>, D>),
    Public(PublicAir<Val<SC>, D>),
    /// Unified ALU table for all arithmetic operations
    Alu(AluAir<Val<SC>, D>),
    Dynamic(DynamicAirEntry<SC>),
}

/// Non-primitive operation configurations.
///
/// This enables the preprocessing of preprocessing data depending on the non-primitive configurations.
pub enum NonPrimitiveConfig {
    Poseidon2(Poseidon2Config),
}

impl<SC, const D: usize> Clone for CircuitTableAir<SC, D>
where
    SC: StarkGenericConfig,
    SymbolicExpression<SC::Challenge>: From<SymbolicExpression<Val<SC>>>,
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

pub fn get_airs_and_degrees_with_prep<
    SC: StarkGenericConfig + 'static + Send + Sync,
    ExtF: ExtensionField<Val<SC>> + ExtractBinomialW<Val<SC>>,
    const D: usize,
>(
    circuit: &Circuit<ExtF>,
    packing: TablePacking,
    non_primitive_configs: Option<&[NonPrimitiveConfig]>,
    constraint_profile: ConstraintProfile,
) -> Result<(CircuitAirsWithDegrees<SC, D>, PreprocessedColumns<Val<SC>>), CircuitError>
where
    SymbolicExpression<SC::Challenge>: From<SymbolicExpression<Val<SC>>>,
    Val<SC>: StarkField,
{
    let mut preprocessed = circuit.generate_preprocessed_columns(D)?;

    // Check if Public/Alu tables are empty and lanes > 1.
    // Using lanes > 1 with empty tables causes issues in recursive verification
    // due to a bug in how multi-lane padding interacts with lookup constraints.
    // We automatically reduce lanes to 1 in these cases with a warning.
    // IMPORTANT: This must be synchronized with prove_all_tables in batch_stark_prover.rs
    let public_idx = PrimitiveOpType::Public as usize;
    let alu_idx = PrimitiveOpType::Alu as usize;

    let public_rows = preprocessed.primitive[public_idx].len();
    let public_trace_only_dummy = public_rows <= 1;
    let effective_public_lanes = if public_trace_only_dummy && packing.public_lanes() > 1 {
        tracing::warn!(
            "Public table has <=1 row but public_lanes={} > 1. Reducing to public_lanes=1 to avoid \
             recursive verification issues. Consider using public_lanes=1 when few public inputs \
             are expected.",
            packing.public_lanes()
        );
        1
    } else {
        packing.public_lanes()
    };

    let alu_empty = preprocessed.primitive[alu_idx].is_empty();
    let effective_alu_lanes = if alu_empty && packing.alu_lanes() > 1 {
        tracing::warn!(
            "ALU table is empty but alu_lanes={} > 1. Reducing to alu_lanes=1 to avoid \
             recursive verification issues. Consider using alu_lanes=1 when no additions \
             are expected.",
            packing.alu_lanes()
        );
        1
    } else {
        packing.alu_lanes()
    };

    let w_binomial = ExtF::extract_w();

    // First, get base field elements for the preprocessed values.
    let mut base_prep: Vec<Vec<Val<SC>>> = preprocessed
        .primitive
        .iter()
        .map(|vals| {
            vals.iter()
                .map(|v| v.as_base().ok_or(CircuitError::InvalidPreprocessedValues))
                .collect::<Result<Vec<_>, CircuitError>>()
        })
        .collect::<Result<Vec<_>, CircuitError>>()?;

    let prep_row_width = poseidon2_preprocessed_width();
    let neg_one = <Val<SC>>::NEG_ONE;

    // Phase 1: Scan Poseidon2 preprocessed data to count mmcs_index_sum conditional reads,
    // and update `ext_reads` accordingly. This must happen before computing multiplicities.
    for (op_type, prep) in preprocessed.non_primitive.iter() {
        if matches!(op_type, NonPrimitiveOpType::Poseidon2Perm(_)) {
            let prep_base: Vec<Val<SC>> = prep
                .iter()
                .map(|v| v.as_base().ok_or(CircuitError::InvalidPreprocessedValues))
                .collect::<Result<Vec<_>, CircuitError>>()?;

            let num_rows = prep_base.len() / prep_row_width;
            let trace_height = num_rows.next_power_of_two();
            let has_padding = trace_height > num_rows;

            for row_idx in 0..num_rows {
                let row_start = row_idx * prep_row_width;
                let row: &Poseidon2PreprocessedRow<Val<SC>> =
                    prep_base[row_start..row_start + prep_row_width].borrow();
                let current_mmcs_merkle_flag = row.mmcs_merkle_flag;

                // Check if next row exists and has new_start = 1.
                // The Poseidon2 AIR pads the trace and sets new_start = 1 in the first
                // padding row (only if padding exists), so the last real row can trigger a
                // lookup if its mmcs_merkle_flag = 1 and there is padding.
                let next_new_start = if row_idx + 1 < num_rows {
                    let next_start = (row_idx + 1) * prep_row_width;
                    let next_row: &Poseidon2PreprocessedRow<Val<SC>> =
                        prep_base[next_start..next_start + prep_row_width].borrow();
                    next_row.new_start
                } else if has_padding {
                    <Val<SC> as PrimeCharacteristicRing>::ONE
                } else {
                    let first_row: &Poseidon2PreprocessedRow<Val<SC>> =
                        prep_base[0..prep_row_width].borrow();
                    first_row.new_start
                };

                let multiplicity = current_mmcs_merkle_flag * next_new_start;
                if multiplicity != <Val<SC> as PrimeCharacteristicRing>::ZERO {
                    let mmcs_idx_u64 =
                        <Val<SC> as PrimeField64>::as_canonical_u64(&row.mmcs_index_sum_ctl_idx);
                    let mmcs_witness_idx = (mmcs_idx_u64 as usize) / D;

                    if mmcs_witness_idx >= preprocessed.ext_reads.len() {
                        preprocessed.ext_reads.resize(mmcs_witness_idx + 1, 0);
                    }
                    preprocessed.ext_reads[mmcs_witness_idx] += 1;
                }
            }
        }
    }

    // Phase 2: Update Poseidon2 out_ctl values in the base field preprocessed data.
    // in_ctl = +1 for active inputs (kept as-is from circuit.rs preprocessing).
    //
    // out_ctl placeholder from generate_preprocessed_columns:
    //   ZERO → private output (no bus contribution; skip)
    //   ONE  → active output (creator or duplicate reader; check poseidon2_dup_wids)
    //
    // Poseidon2 duplicate creators (from optimizer witness_rewrite deduplication)
    // are recorded in `preprocessed.poseidon2_dup_wids`. For those, out_ctl = -1
    // (reader contribution). For first-occurrence creators, out_ctl = +ext_reads[wid].
    let mut non_primitive_base: NonPrimitivePreprocessedMap<Val<SC>> = HashMap::new();
    for (op_type, prep) in preprocessed.non_primitive.iter() {
        if matches!(op_type, NonPrimitiveOpType::Poseidon2Perm(_)) {
            let mut prep_base: Vec<Val<SC>> = prep
                .iter()
                .map(|v| v.as_base().ok_or(CircuitError::InvalidPreprocessedValues))
                .collect::<Result<Vec<_>, CircuitError>>()?;

            let num_rows = prep_base.len() / prep_row_width;

            for row_idx in 0..num_rows {
                let row_start = row_idx * prep_row_width;
                let row: &mut Poseidon2PreprocessedRow<Val<SC>> =
                    prep_base[row_start..row_start + prep_row_width].borrow_mut();

                for out_limb in &mut row.output_limbs {
                    if out_limb.out_ctl != <Val<SC> as PrimeCharacteristicRing>::ZERO {
                        let out_wid =
                            <Val<SC> as PrimeField64>::as_canonical_u64(&out_limb.idx) as usize / D;
                        let is_dup = preprocessed
                            .poseidon2_dup_wids
                            .get(out_wid)
                            .copied()
                            .unwrap_or(false);
                        if is_dup {
                            out_limb.out_ctl = neg_one;
                        } else {
                            let n_reads = preprocessed.ext_reads.get(out_wid).copied().unwrap_or(0);
                            out_limb.out_ctl = <Val<SC>>::from_u32(n_reads);
                        }
                    }
                }
            }

            non_primitive_base.insert(*op_type, prep_base);
        }
    }

    // Get min_height from packing configuration and pass it to AIRs
    let min_height = packing.min_trace_height();

    // Helper to compute degree that respects min_height
    let compute_degree = |num_rows: usize| -> usize {
        let natural_height = num_rows.next_power_of_two();
        let min_rows = min_height.next_power_of_two();
        log2_ceil_usize(natural_height.max(min_rows))
    };

    let mut table_preps: Vec<(CircuitTableAir<SC, D>, usize)> = Vec::with_capacity(base_prep.len());

    #[allow(clippy::needless_range_loop)]
    for idx in 0..base_prep.len() {
        let table = PrimitiveOpType::from(idx);
        match table {
            PrimitiveOpType::Alu => {
                // ALU preprocessed per op from circuit.rs: 11 values
                // [sel_add_vs_mul, sel_bool, sel_muladd, a_idx, b_idx, c_idx, out_idx,
                //  mult_a_eff, b_is_creator, mult_c_eff, out_is_creator]
                //
                // mult_a_eff / mult_c_eff: -1 (reader or later unconstrained), or +N (first
                // unconstrained creator). We convert to 12 values for AluAir (same order, mult_c_eff last).
                let lane_11 = 11_usize;

                let mut prep_12col: Vec<Val<SC>> = base_prep[idx]
                    .chunks(lane_11)
                    .flat_map(|chunk| {
                        let sel1 = chunk[0];
                        let sel2 = chunk[1];
                        let sel3 = chunk[2];
                        let a_idx = chunk[3];
                        let b_idx = chunk[4];
                        let c_idx = chunk[5];
                        let out_idx = chunk[6];
                        let mult_a_eff = chunk[7];
                        let b_is_creator =
                            <Val<SC> as PrimeField64>::as_canonical_u64(&chunk[8]) != 0;
                        let mult_c_eff = chunk[9];
                        let out_is_creator =
                            <Val<SC> as PrimeField64>::as_canonical_u64(&chunk[10]) != 0;

                        let mult_b = if b_is_creator {
                            let b_wid =
                                <Val<SC> as PrimeField64>::as_canonical_u64(&b_idx) as usize / D;
                            let n_reads = preprocessed.ext_reads.get(b_wid).copied().unwrap_or(0);
                            <Val<SC>>::from_u32(n_reads)
                        } else {
                            neg_one
                        };

                        let mult_out = if out_is_creator {
                            let out_wid =
                                <Val<SC> as PrimeField64>::as_canonical_u64(&out_idx) as usize / D;
                            let n_reads = preprocessed.ext_reads.get(out_wid).copied().unwrap_or(0);
                            <Val<SC>>::from_u32(n_reads)
                        } else {
                            neg_one
                        };

                        [
                            <Val<SC>>::ONE, // active (1 for active row; padding rows are all zeros)
                            mult_a_eff,
                            sel1,
                            sel2,
                            sel3,
                            a_idx,
                            b_idx,
                            c_idx,
                            out_idx,
                            mult_b,
                            mult_out,
                            mult_c_eff,
                        ]
                    })
                    .collect();

                if alu_empty {
                    prep_12col.extend([<Val<SC>>::ZERO; 12]);
                }

                const ALU_PREP_WIDTH: usize = 12;
                let num_ops = prep_12col.len() / ALU_PREP_WIDTH;
                let alu_air = if D == 1 {
                    AluAir::new_with_preprocessed(num_ops, effective_alu_lanes, prep_12col.clone())
                        .with_min_height(min_height)
                } else {
                    let w = w_binomial.unwrap();
                    AluAir::new_binomial_with_preprocessed(
                        num_ops,
                        effective_alu_lanes,
                        w,
                        prep_12col.clone(),
                    )
                    .with_min_height(min_height)
                };
                let num_rows = num_ops.div_ceil(effective_alu_lanes);
                base_prep[idx] = prep_12col;
                table_preps.push((CircuitTableAir::Alu(alu_air), compute_degree(num_rows)));
            }
            PrimitiveOpType::Public => {
                // Public preprocessed per op from circuit.rs: 1 value (D-scaled out_idx).
                // Convert to [ext_mult, out_idx] pairs using ext_reads.
                let prep_2col: Vec<Val<SC>> = base_prep[idx]
                    .iter()
                    .flat_map(|&out_idx| {
                        let out_wid =
                            (<Val<SC> as PrimeField64>::as_canonical_u64(&out_idx) as usize) / D;
                        let n_reads = preprocessed.ext_reads.get(out_wid).copied().unwrap_or(0);
                        [<Val<SC>>::from_u32(n_reads), out_idx]
                    })
                    .collect();

                let num_ops = prep_2col.len() / 2;
                let public_air = PublicAir::new_with_preprocessed(
                    num_ops,
                    effective_public_lanes,
                    prep_2col.clone(),
                )
                .with_min_height(min_height);
                let num_rows = num_ops.div_ceil(effective_public_lanes);
                base_prep[idx] = prep_2col;
                table_preps.push((
                    CircuitTableAir::Public(public_air),
                    compute_degree(num_rows),
                ));
            }
            PrimitiveOpType::Const => {
                // Const preprocessed per op from circuit.rs: 1 value (D-scaled out_idx).
                // Convert to [ext_mult, out_idx] pairs using ext_reads.
                let prep_2col: Vec<Val<SC>> = base_prep[idx]
                    .iter()
                    .flat_map(|&out_idx| {
                        let out_wid =
                            (<Val<SC> as PrimeField64>::as_canonical_u64(&out_idx) as usize) / D;
                        let n_reads = preprocessed.ext_reads.get(out_wid).copied().unwrap_or(0);
                        [<Val<SC>>::from_u32(n_reads), out_idx]
                    })
                    .collect();

                let height = prep_2col.len() / 2;
                let const_air = ConstAir::new_with_preprocessed(height, prep_2col.clone())
                    .with_min_height(min_height);
                base_prep[idx] = prep_2col;
                table_preps.push((CircuitTableAir::Const(const_air), compute_degree(height)));
            }
        }
    }

    let mut config_map = BTreeMap::new();
    if let Some(configs) = non_primitive_configs {
        for config in configs {
            match config {
                NonPrimitiveConfig::Poseidon2(cfg) => {
                    let op_type = NonPrimitiveOpType::Poseidon2Perm(*cfg);
                    config_map.insert(op_type, *cfg);
                }
            }
        }
    }

    // Add non-primitive (Poseidon2) AIR entries using the updated base field preprocessed data.
    for (op_type, prep_base) in non_primitive_base.iter() {
        match op_type {
            NonPrimitiveOpType::Poseidon2Perm(_) => {
                let cfg = config_map
                    .get(op_type)
                    .copied()
                    .ok_or(CircuitError::InvalidPreprocessedValues)?;
                let poseidon2_prover = Poseidon2Prover::new(cfg, constraint_profile);
                let width = poseidon2_prover.preprocessed_width_from_config();
                let poseidon2_wrapper = poseidon2_prover
                    .wrapper_from_config_with_preprocessed(prep_base.clone(), min_height);
                let poseidon2_wrapper_air: CircuitTableAir<SC, D> =
                    CircuitTableAir::Dynamic(poseidon2_wrapper);
                let num_rows = prep_base.len().div_ceil(width);
                table_preps.push((poseidon2_wrapper_air, compute_degree(num_rows)));
            }
            NonPrimitiveOpType::Unconstrained => {}
        }
    }

    // Build base_prep for the output PreprocessedColumns (without Poseidon2 multiplicities).
    // The non_primitive_base already has the updated in_ctl/out_ctl values.
    let mut non_primitive_output: NonPrimitivePreprocessedMap<Val<SC>> = non_primitive_base;

    // Also include any non-primitive ops that weren't Poseidon2 (e.g. Unconstrained)
    for (op_type, prep) in preprocessed.non_primitive.iter() {
        if !matches!(op_type, NonPrimitiveOpType::Poseidon2Perm(_)) {
            let prep_base: Vec<Val<SC>> = prep
                .iter()
                .map(|v| v.as_base().ok_or(CircuitError::InvalidPreprocessedValues))
                .collect::<Result<Vec<_>, CircuitError>>()?;
            non_primitive_output.insert(*op_type, prep_base);
        }
    }

    let preprocessed_columns = PreprocessedColumns {
        primitive: base_prep,
        non_primitive: non_primitive_output,
        d: D,
        ext_reads: preprocessed.ext_reads,
        poseidon2_dup_wids: preprocessed.poseidon2_dup_wids,
    };

    Ok((table_preps, preprocessed_columns))
}
