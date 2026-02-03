use alloc::collections::btree_map::BTreeMap;
use alloc::vec;
use alloc::vec::Vec;

use p3_circuit::op::{NonPrimitiveOpType, Poseidon2Config, PrimitiveOpType};
use p3_circuit::{Circuit, CircuitError};
use p3_field::{ExtensionField, PrimeCharacteristicRing, PrimeField64};
use p3_uni_stark::{StarkGenericConfig, SymbolicExpression, Val};
use p3_util::log2_ceil_usize;

use crate::air::{AddAir, ConstAir, MulAir, PublicAir, WitnessAir};
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
    Witness(WitnessAir<Val<SC>, D>),
    Const(ConstAir<Val<SC>, D>),
    Public(PublicAir<Val<SC>, D>),
    Add(AddAir<Val<SC>, D>),
    Mul(MulAir<Val<SC>, D>),
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
            Self::Witness(air) => Self::Witness(air.clone()),
            Self::Const(air) => Self::Const(air.clone()),
            Self::Public(air) => Self::Public(air.clone()),
            Self::Add(air) => Self::Add(air.clone()),
            Self::Mul(air) => Self::Mul(air.clone()),
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
) -> Result<(CircuitAirsWithDegrees<SC, D>, Vec<Val<SC>>), CircuitError>
where
    SymbolicExpression<SC::Challenge>: From<SymbolicExpression<Val<SC>>>,
    Val<SC>: StarkField,
{
    let mut preprocessed = circuit.generate_preprocessed_columns()?;

    // Check if Public/Add/Mul tables are empty and lanes > 1.
    // Using lanes > 1 with empty tables causes issues in recursive verification
    // due to a bug in how multi-lane padding interacts with lookup constraints.
    // We automatically reduce lanes to 1 in these cases with a warning.
    // IMPORTANT: This must be synchronized with prove_all_tables in batch_stark_prover.rs
    let witness_idx = PrimitiveOpType::Witness as usize;
    let public_idx = PrimitiveOpType::Public as usize;
    let add_idx = PrimitiveOpType::Add as usize;
    let mul_idx = PrimitiveOpType::Mul as usize;

    let public_empty = preprocessed.primitive[public_idx].is_empty();
    let add_empty = preprocessed.primitive[add_idx].is_empty();
    let mul_empty = preprocessed.primitive[mul_idx].is_empty();

    let effective_public_lanes = if public_empty && packing.public_lanes() > 1 {
        tracing::warn!(
            "Public table is empty but public_lanes={} > 1. Reducing to public_lanes=1 to avoid \
             recursive verification issues. Consider using public_lanes=1 when few public inputs \
             are expected.",
            packing.public_lanes()
        );
        1
    } else {
        packing.public_lanes()
    };

    let effective_add_lanes = if add_empty && packing.add_lanes() > 1 {
        tracing::warn!(
            "Add table is empty but add_lanes={} > 1. Reducing to add_lanes=1 to avoid \
             recursive verification issues. Consider using add_lanes=1 when no additions \
             are expected.",
            packing.add_lanes()
        );
        1
    } else {
        packing.add_lanes()
    };

    let effective_mul_lanes = if mul_empty && packing.mul_lanes() > 1 {
        tracing::warn!(
            "Mul table is empty but mul_lanes={} > 1. Reducing to mul_lanes=1 to avoid \
             recursive verification issues. Consider using mul_lanes=1 when no multiplications \
             are expected.",
            packing.mul_lanes()
        );
        1
    } else {
        packing.mul_lanes()
    };

    // If Add or Mul tables are empty, we add a dummy row to avoid issues in the AIRs.
    // That means we need to update the witness multiplicities accordingly.
    if add_empty {
        let num_extra = AddAir::<Val<SC>, D>::lane_width() / D;

        preprocessed.primitive[witness_idx][0] += ExtF::from_usize(num_extra);
        preprocessed.primitive[add_idx].extend(vec![
            ExtF::ZERO;
            AddAir::<Val<SC>, D>::preprocessed_lane_width()
                - 1
        ]);
    }
    if mul_empty {
        let num_extra = MulAir::<Val<SC>, D>::lane_width() / D;
        preprocessed.primitive[witness_idx][0] += ExtF::from_usize(num_extra);
        preprocessed.primitive[mul_idx].extend(vec![
            ExtF::ZERO;
            MulAir::<Val<SC>, D>::preprocessed_lane_width()
                - 1
        ]);
    }

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

    // Pre-processing: Update witness multiplicities for mmcs_index_sum lookups.
    //
    // The Poseidon2 AIR sends an mmcs_index_sum lookup when:
    //   next_row.new_start * current_row.merkle_path = 1
    //
    // This lookup uses the witness index from mmcs_index_sum_ctl_idx (which is 0 when
    // mmcs_index_sum is not explicitly set). The preprocessing function doesn't update
    // witness multiplicities for this case because it processes operations one at a time
    // without knowing the next operation's new_start value.
    //
    // We fix this by scanning the Poseidon2 preprocessed data and incrementing the witness
    // multiplicity for each such lookup.
    //
    // This must be done BEFORE creating the Witness AIR so it captures the correct multiplicities.
    //
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
    #[allow(dead_code)]
    const MERKLE_PATH_OFFSET: usize = 23;

    let mut mmcs_lookup_count = 0usize;
    for (op_type, prep) in preprocessed.non_primitive.iter() {
        if matches!(op_type, NonPrimitiveOpType::Poseidon2Perm(_)) {
            let prep_base: Vec<Val<SC>> = prep
                .iter()
                .map(|v| v.as_base().ok_or(CircuitError::InvalidPreprocessedValues))
                .collect::<Result<Vec<_>, CircuitError>>()?;

            let num_rows = prep_base.len() / POSEIDON2_PREP_ROW_WIDTH;

            // Check if padding will be added (trace height is padded to power of two)
            let trace_height = num_rows.next_power_of_two();
            let has_padding = trace_height > num_rows;

            for row_idx in 0..num_rows {
                let row_start = row_idx * POSEIDON2_PREP_ROW_WIDTH;
                // mmcs_merkle_flag is precomputed as: mmcs_ctl * merkle_path
                let current_mmcs_merkle_flag = prep_base[row_start + MMCS_MERKLE_FLAG_OFFSET];

                // Check if next row exists and has new_start = 1
                // Note: The Poseidon2 AIR pads the trace and sets new_start = 1 in the first
                // padding row (only if padding exists). This means the LAST real row will
                // also trigger a lookup if its mmcs_merkle_flag = 1 and there is padding.
                let next_new_start = if row_idx + 1 < num_rows {
                    let next_row_start = (row_idx + 1) * POSEIDON2_PREP_ROW_WIDTH;
                    prep_base[next_row_start + NEW_START_OFFSET]
                } else if has_padding {
                    // Last real row with padding - the AIR sets new_start = 1 in first padding row
                    <Val<SC> as PrimeCharacteristicRing>::ONE
                } else {
                    // No padding - the AIR wraps around (cyclically), so next row is the first row
                    // The first row's new_start value determines the multiplicity
                    prep_base[NEW_START_OFFSET]
                };

                // If multiplicity = mmcs_merkle_flag * next_new_start != 0
                let multiplicity = current_mmcs_merkle_flag * next_new_start;
                if multiplicity != <Val<SC> as PrimeCharacteristicRing>::ZERO {
                    // Get the mmcs_index_sum witness index for this row
                    let mmcs_idx = prep_base[row_start + MMCS_INDEX_SUM_CTL_IDX_OFFSET];

                    // Convert to usize for indexing
                    // The witness index should be a small integer that fits in usize
                    let mmcs_idx_u64 = <Val<SC> as PrimeField64>::as_canonical_u64(&mmcs_idx);
                    let mmcs_idx_usize = mmcs_idx_u64 as usize;

                    // Ensure witness multiplicity vector is large enough
                    if mmcs_idx_usize >= base_prep[witness_idx].len() {
                        base_prep[witness_idx].resize(
                            mmcs_idx_usize + 1,
                            <Val<SC> as PrimeCharacteristicRing>::ZERO,
                        );
                    }

                    // Increment the multiplicity
                    base_prep[witness_idx][mmcs_idx_usize] += multiplicity;
                    mmcs_lookup_count += 1;
                }
            }
        }
    }
    if mmcs_lookup_count > 0 {
        tracing::debug!(
            "Updated {} mmcs_index_sum lookups in witness multiplicities",
            mmcs_lookup_count
        );
    }

    // Now create the AIRs with the updated multiplicities
    // Get min_height from packing configuration and pass it to AIRs
    let min_height = packing.min_trace_height();

    // Helper to compute degree that respects min_height
    let compute_degree = |num_rows: usize| -> usize {
        let natural_height = num_rows.next_power_of_two();
        let min_rows = min_height.next_power_of_two();
        log2_ceil_usize(natural_height.max(min_rows))
    };

    let default_air = WitnessAir::new(1, 1);
    let mut table_preps = (0..base_prep.len())
        .map(|_| (CircuitTableAir::Witness(default_air.clone()), 1))
        .collect::<Vec<_>>();
    base_prep
        .iter()
        .enumerate()
        .try_for_each(|(idx, prep)| -> Result<(), CircuitError> {
            let table = PrimitiveOpType::from(idx);
            match table {
                PrimitiveOpType::Add => {
                    // The `- 1` comes from the fact that the first preprocessing column is the multiplicity,
                    // which we do not need to compute here for `Add`.
                    let lane_without_multiplicities =
                        AddAir::<Val<SC>, D>::preprocessed_lane_width() - 1;
                    assert!(prep.len() % lane_without_multiplicities == 0);

                    let num_ops = prep.len().div_ceil(lane_without_multiplicities);
                    let add_air =
                        AddAir::new_with_preprocessed(num_ops, effective_add_lanes, prep.clone())
                            .with_min_height(min_height);
                    let num_rows = num_ops.div_ceil(effective_add_lanes);
                    table_preps[idx] = (CircuitTableAir::Add(add_air), compute_degree(num_rows));
                }
                PrimitiveOpType::Mul => {
                    // The `- 1` comes from the fact that the first preprocessing column is the multiplicity,
                    // which we do not need to compute here for `Mul`.
                    let lane_without_multiplicities =
                        MulAir::<Val<SC>, D>::preprocessed_lane_width() - 1;
                    assert!(prep.len() % lane_without_multiplicities == 0);
                    let num_ops = prep.len().div_ceil(lane_without_multiplicities);
                    let mul_air = if D == 1 {
                        MulAir::new_with_preprocessed(num_ops, effective_mul_lanes, prep.clone())
                            .with_min_height(min_height)
                    } else {
                        let w = w_binomial.unwrap();
                        MulAir::new_binomial_with_preprocessed(
                            num_ops,
                            effective_mul_lanes,
                            w,
                            prep.clone(),
                        )
                        .with_min_height(min_height)
                    };
                    let num_rows = num_ops.div_ceil(effective_mul_lanes);
                    table_preps[idx] = (CircuitTableAir::Mul(mul_air), compute_degree(num_rows));
                }
                PrimitiveOpType::Public => {
                    let num_ops = prep.len();
                    let public_air = PublicAir::new_with_preprocessed(
                        num_ops,
                        effective_public_lanes,
                        prep.clone(),
                    )
                    .with_min_height(min_height);
                    let num_rows = num_ops.div_ceil(effective_public_lanes);
                    table_preps[idx] = (
                        CircuitTableAir::Public(public_air),
                        compute_degree(num_rows),
                    );
                }
                PrimitiveOpType::Const => {
                    let height = prep.len();
                    let const_air = ConstAir::new_with_preprocessed(height, prep.clone())
                        .with_min_height(min_height);
                    table_preps[idx] = (CircuitTableAir::Const(const_air), compute_degree(height));
                }
                PrimitiveOpType::Witness => {
                    let num_witnesses = prep.len();
                    let witness_air = WitnessAir::new_with_preprocessed(
                        num_witnesses,
                        packing.witness_lanes(),
                        prep.clone(),
                    )
                    .with_min_height(min_height);
                    let num_rows = num_witnesses.div_ceil(packing.witness_lanes());
                    table_preps[idx] = (
                        CircuitTableAir::Witness(witness_air),
                        compute_degree(num_rows),
                    );
                }
            }

            Ok(())
        })?;

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
    for (op_type, prep) in preprocessed.non_primitive.iter() {
        match op_type {
            NonPrimitiveOpType::Poseidon2Perm(_) => {
                let cfg = config_map
                    .get(op_type)
                    .copied()
                    .ok_or(CircuitError::InvalidPreprocessedValues)?;
                let prep_base = prep
                    .iter()
                    .map(|v| v.as_base().ok_or(CircuitError::InvalidPreprocessedValues))
                    .collect::<Result<Vec<_>, CircuitError>>()?;
                let poseidon2_prover = Poseidon2Prover::new(cfg);
                let width = poseidon2_prover.preprocessed_width_from_config();
                let poseidon2_wrapper =
                    poseidon2_prover.wrapper_from_config_with_preprocessed(prep_base);
                let poseidon2_wrapper_air: CircuitTableAir<SC, D> =
                    CircuitTableAir::Dynamic(poseidon2_wrapper);
                let num_rows = prep.len().div_ceil(width);
                table_preps.push((poseidon2_wrapper_air, compute_degree(num_rows)));
            }
            // Unconstrained operations do not use tables
            NonPrimitiveOpType::Unconstrained => {}
        }
    }

    // Post-processing: Update witness multiplicities for mmcs_index_sum lookups.
    //
    // The Poseidon2 AIR sends an mmcs_index_sum lookup when:
    //   next_row.new_start * current_row.merkle_path = 1
    Ok((table_preps, base_prep[0].clone()))
}
