use alloc::collections::btree_map::BTreeMap;
use alloc::vec;
use alloc::vec::Vec;

use p3_circuit::op::{NonPrimitiveOpType, Poseidon2Config, PrimitiveOpType};
use p3_circuit::{Circuit, CircuitError};
use p3_field::ExtensionField;
use p3_uni_stark::{StarkGenericConfig, SymbolicExpression, Val};
use p3_util::log2_ceil_usize;

use crate::air::{AddAir, AluAir, ConstAir, MulAir, PublicAir, WitnessAir};
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
    /// Unified ALU table (replaces Add and Mul)
    Alu(AluAir<Val<SC>, D>),
    /// Deprecated: Addition table (will be removed)
    Add(AddAir<Val<SC>, D>),
    /// Deprecated: Multiplication table (will be removed)
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
            Self::Alu(air) => Self::Alu(air.clone()),
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

    // If ALU table is empty, we add a dummy row to avoid issues in the AIR.
    // That means we need to update the witness multiplicities accordingly.
    let witness_idx = PrimitiveOpType::Witness as usize;
    let alu_idx = PrimitiveOpType::Alu as usize;
    if preprocessed.primitive[alu_idx].is_empty() {
        // ALU lane has 4 operands (a, b, c, out), each with D elements
        let num_extra = AluAir::<Val<SC>, D>::lane_width() / D;
        preprocessed.primitive[witness_idx][0] += ExtF::from_usize(num_extra);
        // Preprocessed width per op (excluding multiplicity): 8 values
        // [sel_add, sel_mul, sel_bool, sel_muladd, a_idx, b_idx, c_idx, out_idx]
        preprocessed.primitive[alu_idx].extend(vec![
            ExtF::ZERO;
            AluAir::<Val<SC>, D>::preprocessed_lane_width()
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
                PrimitiveOpType::Alu => {
                    // ALU preprocessed per op (excluding multiplicity): 8 values
                    // [sel_add, sel_mul, sel_bool, sel_muladd, a_idx, b_idx, c_idx, out_idx]
                    let lane_without_multiplicities =
                        AluAir::<Val<SC>, D>::preprocessed_lane_width() - 1;
                    assert!(
                        prep.len() % lane_without_multiplicities == 0,
                        "ALU preprocessed length {} is not a multiple of {}",
                        prep.len(),
                        lane_without_multiplicities
                    );

                    let num_ops = prep.len().div_ceil(lane_without_multiplicities);
                    let alu_air = if D == 1 {
                        AluAir::new_with_preprocessed(num_ops, packing.alu_lanes(), prep.clone())
                    } else {
                        let w = w_binomial.unwrap();
                        AluAir::new_binomial_with_preprocessed(
                            num_ops,
                            packing.alu_lanes(),
                            w,
                            prep.clone(),
                        )
                    };
                    table_preps[idx] = (
                        CircuitTableAir::Alu(alu_air),
                        log2_ceil_usize(num_ops.div_ceil(packing.alu_lanes())),
                    );
                }
                PrimitiveOpType::Public => {
                    let height = prep.len();
                    let public_air = PublicAir::new_with_preprocessed(height, prep.clone());
                    table_preps[idx] =
                        (CircuitTableAir::Public(public_air), log2_ceil_usize(height));
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
                table_preps.push((
                    poseidon2_wrapper_air,
                    log2_ceil_usize(prep.len().div_ceil(width)),
                ));
            }
            // Unconstrained operations do not use tables
            NonPrimitiveOpType::Unconstrained => {}
        }
    }

    Ok((table_preps, base_prep[0].clone()))
}
