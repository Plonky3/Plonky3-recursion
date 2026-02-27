use alloc::boxed::Box;
use alloc::vec::Vec;
use core::any::Any;

use hashbrown::HashMap;
use p3_circuit::op::{NonPrimitivePreprocessedMap, PrimitiveOpType};
use p3_circuit::{Circuit, CircuitError, PreprocessedColumns};
use p3_field::{ExtensionField, PrimeCharacteristicRing, PrimeField64};
use p3_uni_stark::{StarkGenericConfig, SymbolicExpression, Val};
use p3_util::log2_ceil_usize;

use crate::air::{AluAir, ConstAir, PublicAir};
use crate::config::StarkField;
use crate::constraint_profile::ConstraintProfile;
use crate::field_params::ExtractBinomialW;
use crate::{DynamicAirEntry, TablePacking};

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
    non_primitive_preprocessors: &[Box<dyn NpoPreprocessor<Val<SC>>>],
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

    let neg_one = <Val<SC>>::NEG_ONE;

    // Let plugins handle non-primitive preprocessing (ext_reads, multiplicities, etc.).
    let mut non_primitive_base: NonPrimitivePreprocessedMap<Val<SC>> = HashMap::new();
    let circuit_any: &dyn Any = circuit;
    let preprocessed_any: &mut dyn Any = &mut preprocessed;
    for plugin in non_primitive_preprocessors {
        let plugin_prep = plugin.preprocess(circuit_any, preprocessed_any)?;
        for (op_type, prep_base) in plugin_prep {
            non_primitive_base.insert(op_type, prep_base);
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

    // Add non-primitive AIR entries using the updated base field preprocessed data.
    for (op_type, prep_base) in non_primitive_base.iter() {
        if op_type.as_str().starts_with("poseidon2_perm/") {
            // Recover config from type id.
            let suffix = op_type
                .as_str()
                .strip_prefix("poseidon2_perm/")
                .ok_or(CircuitError::InvalidPreprocessedValues)?;
            let cfg = crate::Poseidon2Config::from_variant_name(suffix)
                .ok_or(CircuitError::InvalidPreprocessedValues)?;
            let poseidon2_prover = crate::Poseidon2Prover::new(cfg, constraint_profile);
            let width = poseidon2_prover.preprocessed_width_from_config();
            let poseidon2_wrapper = poseidon2_prover
                .wrapper_from_config_with_preprocessed(prep_base.clone(), min_height);
            let poseidon2_wrapper_air: CircuitTableAir<SC, D> =
                CircuitTableAir::Dynamic(poseidon2_wrapper);
            let num_rows = prep_base.len().div_ceil(width);
            table_preps.push((poseidon2_wrapper_air, compute_degree(num_rows)));
        }
    }

    // Build base_prep for the output PreprocessedColumns (without Poseidon2 multiplicities).
    // The non_primitive_base already has the updated in_ctl/out_ctl values.
    let mut non_primitive_output: NonPrimitivePreprocessedMap<Val<SC>> = non_primitive_base;

    // Also include any non-primitive ops that weren't Poseidon2
    for (op_type, prep) in preprocessed.non_primitive.iter() {
        if !op_type.as_str().starts_with("poseidon2_perm/") {
            let prep_base: Vec<Val<SC>> = prep
                .iter()
                .map(|v| v.as_base().ok_or(CircuitError::InvalidPreprocessedValues))
                .collect::<Result<Vec<_>, CircuitError>>()?;
            non_primitive_output.insert(op_type.clone(), prep_base);
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
