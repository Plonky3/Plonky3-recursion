use alloc::collections::btree_map::BTreeMap;
use alloc::vec::Vec;

use hashbrown::HashMap;
use p3_circuit::op::{
    NonPrimitiveOpType, NonPrimitivePreprocessedMap, Poseidon2Config, PrimitiveOpType,
};
use p3_circuit::{Circuit, CircuitError, PreprocessedColumns};
use p3_field::{ExtensionField, PrimeCharacteristicRing, PrimeField64};
use p3_uni_stark::{StarkGenericConfig, SymbolicExpression, Val};
use p3_util::log2_ceil_usize;

use crate::air::{AluAir, ConstAir, PublicAir};
use crate::config::StarkField;
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

    // Poseidon2 preprocessing layout constants.
    // TODO: Update these indices once generic Poseidon2 is implemented.
    // Poseidon2 preprocessed row layout (24 fields per row):
    //   [0..16]  = 4 input limbs (each: in_idx, in_ctl, normal_chain_sel, merkle_chain_sel)
    //   [16..20] = 2 output limbs (each: out_idx, out_ctl)
    //   [20]     = mmcs_index_sum_ctl_idx
    //   [21]     = mmcs_merkle_flag (precomputed: mmcs_ctl * merkle_path)
    //   [22]     = new_start
    //   [23]     = merkle_path
    const POSEIDON2_PREP_ROW_WIDTH: usize = 24;
    const MMCS_INDEX_SUM_CTL_IDX_OFFSET: usize = 20;
    const MMCS_MERKLE_FLAG_OFFSET: usize = 21;
    const NEW_START_OFFSET: usize = 22;

    // Phase 1: Scan Poseidon2 preprocessed data to count mmcs_index_sum conditional reads,
    // and update `ext_reads` accordingly. This must happen before computing multiplicities.
    for (op_type, prep) in preprocessed.non_primitive.iter() {
        if matches!(op_type, NonPrimitiveOpType::Poseidon2Perm(_)) {
            let prep_base: Vec<Val<SC>> = prep
                .iter()
                .map(|v| v.as_base().ok_or(CircuitError::InvalidPreprocessedValues))
                .collect::<Result<Vec<_>, CircuitError>>()?;

            let num_rows = prep_base.len() / POSEIDON2_PREP_ROW_WIDTH;
            let trace_height = num_rows.next_power_of_two();
            let has_padding = trace_height > num_rows;

            for row_idx in 0..num_rows {
                let row_start = row_idx * POSEIDON2_PREP_ROW_WIDTH;
                let current_mmcs_merkle_flag = prep_base[row_start + MMCS_MERKLE_FLAG_OFFSET];

                // Check if next row exists and has new_start = 1.
                // The Poseidon2 AIR pads the trace and sets new_start = 1 in the first
                // padding row (only if padding exists), so the last real row can trigger a
                // lookup if its mmcs_merkle_flag = 1 and there is padding.
                let next_new_start = if row_idx + 1 < num_rows {
                    let next_row_start = (row_idx + 1) * POSEIDON2_PREP_ROW_WIDTH;
                    prep_base[next_row_start + NEW_START_OFFSET]
                } else if has_padding {
                    <Val<SC> as PrimeCharacteristicRing>::ONE
                } else {
                    prep_base[NEW_START_OFFSET]
                };

                let multiplicity = current_mmcs_merkle_flag * next_new_start;
                if multiplicity != <Val<SC> as PrimeCharacteristicRing>::ZERO {
                    let mmcs_idx = prep_base[row_start + MMCS_INDEX_SUM_CTL_IDX_OFFSET];
                    let mmcs_idx_u64 = <Val<SC> as PrimeField64>::as_canonical_u64(&mmcs_idx);
                    let mmcs_witness_idx = (mmcs_idx_u64 as usize) / D;

                    // Update ext_reads for the mmcs_index_sum witness read.
                    let idx = mmcs_witness_idx;
                    if idx >= preprocessed.ext_reads.len() {
                        preprocessed.ext_reads.resize(idx + 1, 0);
                    }
                    preprocessed.ext_reads[idx] += 1;
                }
            }
        }
    }

    // Phase 2: Update Poseidon2 out_ctl values in the base field preprocessed data.
    // in_ctl = +1 for active inputs (kept as-is from circuit.rs preprocessing).
    // out_ctl positions: 17, 19 (active → ext_reads[out_wid]).
    let mut non_primitive_base: NonPrimitivePreprocessedMap<Val<SC>> = HashMap::new();
    for (op_type, prep) in preprocessed.non_primitive.iter() {
        if matches!(op_type, NonPrimitiveOpType::Poseidon2Perm(_)) {
            let mut prep_base: Vec<Val<SC>> = prep
                .iter()
                .map(|v| v.as_base().ok_or(CircuitError::InvalidPreprocessedValues))
                .collect::<Result<Vec<_>, CircuitError>>()?;

            let num_rows = prep_base.len() / POSEIDON2_PREP_ROW_WIDTH;

            for row_idx in 0..num_rows {
                let row_start = row_idx * POSEIDON2_PREP_ROW_WIDTH;

                // in_ctl = +1 for active inputs (Direction::Send with +1 → -1 logup contribution).
                // No modification needed; the preprocessed data already has +1 from circuit.rs.

                // Set out_ctl for active rate outputs.
                // out_ctl placeholder from generate_preprocessed_columns:
                //   ZERO → private output (no bus contribution; skip)
                //   ONE  → active output (creator or duplicate reader; check poseidon2_dup_wids)
                //
                // Poseidon2 duplicate creators (from optimizer witness_rewrite deduplication)
                // are recorded in `preprocessed.poseidon2_dup_wids`. For those, out_ctl = -1
                // (reader contribution). For first-occurrence creators, out_ctl = +ext_reads[wid].
                let neg_one = <Val<SC>>::ZERO - <Val<SC>>::ONE;
                for out_limb in 0..2 {
                    let out_idx_offset = row_start + 16 + out_limb * 2;
                    let out_ctl_offset = out_idx_offset + 1;
                    if prep_base[out_ctl_offset] != <Val<SC> as PrimeCharacteristicRing>::ZERO {
                        let out_idx_val = prep_base[out_idx_offset];
                        let out_idx_u64 = <Val<SC> as PrimeField64>::as_canonical_u64(&out_idx_val);
                        let out_wid = (out_idx_u64 as usize) / D;
                        let is_dup = preprocessed
                            .poseidon2_dup_wids
                            .get(out_wid)
                            .copied()
                            .unwrap_or(false);
                        if is_dup {
                            // Duplicate (optimizer-merged): this op is a reader, out_ctl = -1.
                            prep_base[out_ctl_offset] = neg_one;
                        } else {
                            // Creator: set out_ctl = total read count.
                            let n_reads = preprocessed.ext_reads.get(out_wid).copied().unwrap_or(0);
                            prep_base[out_ctl_offset] = <Val<SC>>::from_u32(n_reads);
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
                // ALU preprocessed per op from circuit.rs (without multiplicities): 11 values
                // [sel_add_vs_mul, sel_bool, sel_muladd, a_idx, b_idx, c_idx, out_idx,
                //  a_is_reader, b_is_creator, c_is_reader, out_is_creator]
                //
                // We convert to 12 values per op for the AluAir:
                // [mult_a, sel1, sel2, sel3, a_idx, b_idx, c_idx, out_idx, mult_b, mult_out,
                //  a_is_reader, c_is_reader]
                //
                // Multiplicity convention (all use Direction::Receive):
                //   Reader (already defined): neg_one → logup contribution -1
                //   Creator (first occurrence): +ext_reads[wid] → logup contribution +N_reads
                //   Unconstrained: mult_a=-1 but effective mult = mult_a * is_reader_col = 0
                //
                // mult_a = -1 for ALL active rows (padding = 0). The actual bus contribution for
                // a is mult_a * a_is_reader and for c is mult_a * c_is_reader (computed in AIR).
                let lane_11 = 11_usize;
                let neg_one = <Val<SC>>::ZERO - <Val<SC>>::ONE;

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
                        let a_is_reader =
                            <Val<SC> as PrimeField64>::as_canonical_u64(&chunk[7]) != 0;
                        let b_is_creator =
                            <Val<SC> as PrimeField64>::as_canonical_u64(&chunk[8]) != 0;
                        let c_is_reader =
                            <Val<SC> as PrimeField64>::as_canonical_u64(&chunk[9]) != 0;
                        let out_is_creator =
                            <Val<SC> as PrimeField64>::as_canonical_u64(&chunk[10]) != 0;

                        // mult_a = -1 for all active rows; active = -mult_a = 1 always.
                        // Effective a-lookup mult = mult_a * a_is_reader_col (in get_alu_index_lookups).
                        // Effective c-lookup mult = mult_a * c_is_reader_col (in get_alu_index_lookups).
                        let mult_a = neg_one;
                        let a_reader_col = if a_is_reader {
                            <Val<SC>>::ONE
                        } else {
                            <Val<SC>>::ZERO
                        };
                        let c_reader_col = if c_is_reader {
                            <Val<SC>>::ONE
                        } else {
                            <Val<SC>>::ZERO
                        };

                        // b: creator if b_is_creator, reader otherwise.
                        let mult_b = if b_is_creator {
                            let b_wid =
                                <Val<SC> as PrimeField64>::as_canonical_u64(&b_idx) as usize / D;
                            let n_reads = preprocessed.ext_reads.get(b_wid).copied().unwrap_or(0);
                            <Val<SC>>::from_u32(n_reads)
                        } else {
                            neg_one
                        };

                        // out: creator if out_is_creator, reader otherwise.
                        let mult_out = if out_is_creator {
                            let out_wid =
                                <Val<SC> as PrimeField64>::as_canonical_u64(&out_idx) as usize / D;
                            let n_reads = preprocessed.ext_reads.get(out_wid).copied().unwrap_or(0);
                            <Val<SC>>::from_u32(n_reads)
                        } else {
                            neg_one
                        };

                        [
                            mult_a,
                            sel1,
                            sel2,
                            sel3,
                            a_idx,
                            b_idx,
                            c_idx,
                            out_idx,
                            mult_b,
                            mult_out,
                            a_reader_col,
                            c_reader_col,
                        ]
                    })
                    .collect();

                // If ALU was empty, add a dummy row (all zeros = padding, no logup contribution).
                if alu_empty {
                    prep_12col.extend([<Val<SC>>::ZERO; 12]);
                }

                let num_ops = prep_12col.len() / 12;
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
                // Store the converted 12-col format so the prover can use it directly.
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
                // Store the converted 2-col format.
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
                // Store the converted 2-col format.
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
                let poseidon2_prover = Poseidon2Prover::new(cfg);
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

    // Construct the PreprocessedColumns with base field elements.
    // base_prep now contains the converted [ext_mult, idx] pairs for Const/Public
    // and 10-col format for ALU — but wait, base_prep was the ORIGINAL format (before 10-col).
    // We need to store the converted data for the verifier.
    // For now, store the original 7-col ALU data and 1-col Const/Public data in base_prep,
    // and let the verifier reconstruct with ext_reads.
    let preprocessed_columns = PreprocessedColumns {
        primitive: base_prep,
        non_primitive: non_primitive_output,
        d: D,
        ext_reads: preprocessed.ext_reads,
        poseidon2_dup_wids: preprocessed.poseidon2_dup_wids,
    };

    Ok((table_preps, preprocessed_columns))
}
