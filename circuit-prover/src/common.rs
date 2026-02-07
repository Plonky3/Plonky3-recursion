use alloc::collections::btree_map::BTreeMap;
use alloc::vec;
use alloc::vec::Vec;

use hashbrown::HashMap;
use p3_circuit::op::{
    NonPrimitiveOpType, NonPrimitivePreprocessedMap, Poseidon2Config, PrimitiveOpType,
};
use p3_circuit::{Circuit, CircuitError, PreprocessedColumns};
use p3_field::ExtensionField;
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
) -> Result<(CircuitAirsWithDegrees<SC, D>, PreprocessedColumns<Val<SC>>), CircuitError>
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
    let base_prep: Vec<Vec<Val<SC>>> = preprocessed
        .primitive
        .iter()
        .map(|vals| {
            vals.iter()
                .map(|v| v.as_base().ok_or(CircuitError::InvalidPreprocessedValues))
                .collect::<Result<Vec<_>, CircuitError>>()
        })
        .collect::<Result<Vec<_>, CircuitError>>()?;

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
                        AddAir::new_with_preprocessed(num_ops, effective_add_lanes, prep.clone());
                    table_preps[idx] = (
                        CircuitTableAir::Add(add_air),
                        log2_ceil_usize(num_ops.div_ceil(effective_add_lanes)),
                    );
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
                    } else {
                        let w = w_binomial.unwrap();
                        MulAir::new_binomial_with_preprocessed(
                            num_ops,
                            effective_mul_lanes,
                            w,
                            prep.clone(),
                        )
                    };
                    table_preps[idx] = (
                        CircuitTableAir::Mul(mul_air),
                        log2_ceil_usize(num_ops.div_ceil(effective_mul_lanes)),
                    );
                }
                PrimitiveOpType::Public => {
                    let num_ops = prep.len();
                    let public_air = PublicAir::new_with_preprocessed(
                        num_ops,
                        effective_public_lanes,
                        prep.clone(),
                    );
                    table_preps[idx] = (
                        CircuitTableAir::Public(public_air),
                        log2_ceil_usize(num_ops.div_ceil(effective_public_lanes)),
                    );
                }
                PrimitiveOpType::Const => {
                    let height = prep.len();
                    let const_air = ConstAir::new_with_preprocessed(height, prep.clone());
                    table_preps[idx] = (CircuitTableAir::Const(const_air), log2_ceil_usize(height));
                }
                PrimitiveOpType::Witness => {
                    let num_witnesses = prep.len();
                    let witness_air = WitnessAir::new_with_preprocessed(
                        num_witnesses,
                        packing.witness_lanes(),
                        prep.clone(),
                    );
                    table_preps[idx] = (
                        CircuitTableAir::Witness(witness_air),
                        log2_ceil_usize(num_witnesses.div_ceil(packing.witness_lanes())),
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
    // Convert non-primitive preprocessed data to base field
    let mut non_primitive_base: NonPrimitivePreprocessedMap<Val<SC>> = HashMap::new();
    for (op_type, prep) in preprocessed.non_primitive.iter() {
        match op_type {
            NonPrimitiveOpType::Poseidon2Perm(_) => {
                let cfg = config_map
                    .get(op_type)
                    .copied()
                    .ok_or(CircuitError::InvalidPreprocessedValues)?;
                let prep_base: Vec<Val<SC>> = prep
                    .iter()
                    .map(|v| v.as_base().ok_or(CircuitError::InvalidPreprocessedValues))
                    .collect::<Result<Vec<_>, CircuitError>>()?;
                non_primitive_base.insert(*op_type, prep_base.clone());
                let poseidon2_prover = Poseidon2Prover::new(cfg);
                let width = poseidon2_prover.preprocessed_width_from_config();
                let poseidon2_wrapper =
                    poseidon2_prover.wrapper_from_config_with_preprocessed(prep_base);
                let poseidon2_wrapper_air: CircuitTableAir<SC, D> =
                    CircuitTableAir::Dynamic(poseidon2_wrapper);
                table_preps.push((
                    poseidon2_wrapper_air,
                    log2_ceil_usize(prep.len().div_ceil(width)),
                ));
            }
            // Unconstrained operations do not use tables
            NonPrimitiveOpType::Unconstrained => {}
        }
    }

    // Construct the PreprocessedColumns with base field elements
    let preprocessed_columns = PreprocessedColumns {
        primitive: base_prep,
        non_primitive: non_primitive_base,
    };

    Ok((table_preps, preprocessed_columns))
}
