use alloc::vec;
use alloc::vec::Vec;
use core::array;

use p3_circuit::op::PrimitiveOpType;
use p3_circuit::{Circuit, CircuitError};
use p3_field::ExtensionField;
use p3_uni_stark::{StarkGenericConfig, SymbolicExpression, Val};
use p3_util::log2_ceil_usize;
use strum::EnumCount;

use crate::air::{AddAir, ConstAir, MulAir, PublicAir, WitnessAir};
use crate::field_params::ExtractBinomialW;
use crate::{DynamicAirEntry, TablePacking};

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

impl<SC, const D: usize> Clone for CircuitTableAir<SC, D>
where
    SC: StarkGenericConfig,
    SymbolicExpression<SC::Challenge>: From<SymbolicExpression<Val<SC>>>,
{
    fn clone(&self) -> Self {
        match self {
            CircuitTableAir::Witness(air) => CircuitTableAir::Witness(air.clone()),
            CircuitTableAir::Const(air) => CircuitTableAir::Const(air.clone()),
            CircuitTableAir::Public(air) => CircuitTableAir::Public(air.clone()),
            CircuitTableAir::Add(air) => CircuitTableAir::Add(air.clone()),
            CircuitTableAir::Mul(air) => CircuitTableAir::Mul(air.clone()),
            CircuitTableAir::Dynamic(air) => CircuitTableAir::Dynamic(air.clone()),
        }
    }
}

pub fn get_airs_and_degrees_with_prep<
    SC: StarkGenericConfig,
    ExtF: ExtensionField<Val<SC>> + ExtractBinomialW<Val<SC>>,
    const D: usize,
>(
    cfg: &SC,
    circuit: &Circuit<ExtF>,
    packing: TablePacking,
) -> Result<
    (
        [(CircuitTableAir<SC, D>, usize); PrimitiveOpType::COUNT],
        Vec<Val<SC>>,
    ),
    CircuitError,
>
where
    SymbolicExpression<SC::Challenge>: From<SymbolicExpression<Val<SC>>>,
{
    let _ = cfg; // Simply to easily determine the type of SC in the function signature.
    let mut preprocessed: Vec<Vec<ExtF>> = circuit.generate_preprocessed_columns()?;

    // If Add or Mul tables are empty, we add a dummy row to avoid issues in the AIRs.
    // That means we need to update the witness multiplicities accordingly.
    let witness_idx = PrimitiveOpType::Witness as usize;
    let add_idx = PrimitiveOpType::Add as usize;
    if preprocessed[add_idx].is_empty() {
        // We add 3 * `lanes` to the multiplicity of 0.
        let num_extra = AddAir::<Val<SC>, D>::lane_width() * packing.add_lanes();
        preprocessed[witness_idx][0] += ExtF::from_usize(num_extra);
        preprocessed[add_idx].extend(vec![
            ExtF::ZERO;
            (AddAir::<Val<SC>, D>::preprocessed_lane_width() - 1)
                * packing.add_lanes()
        ]);
    }
    let mul_idx = PrimitiveOpType::Mul as usize;
    if preprocessed[mul_idx].is_empty() {
        // We add 3 * `lanes` to the multiplicity of 0.
        let num_extra = MulAir::<Val<SC>, D>::lane_width() * packing.mul_lanes();
        preprocessed[witness_idx][0] += ExtF::from_usize(num_extra);
        preprocessed[mul_idx].extend(vec![
            ExtF::ZERO;
            (MulAir::<Val<SC>, D>::preprocessed_lane_width() - 1)
                * packing.mul_lanes()
        ]);
    }

    let w_binomial = ExtF::extract_w();
    // First, get base field elements for the preprocessed values.
    let base_prep: Vec<Vec<Val<SC>>> = preprocessed
        .iter()
        .map(|vals| {
            vals.iter()
                .map(|v| v.as_base().ok_or(CircuitError::InvalidPreprocessedValues))
                .collect::<Result<Vec<_>, CircuitError>>()
        })
        .collect::<Result<Vec<_>, CircuitError>>()?;

    let default_air = WitnessAir::new(1, 1);
    let mut table_preps: [(CircuitTableAir<SC, D>, usize); PrimitiveOpType::COUNT] =
        array::from_fn(|_| (CircuitTableAir::Witness(default_air.clone()), 1));
    base_prep.iter().enumerate().for_each(|(idx, prep)| {
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
                    AddAir::new_with_preprocessed(num_ops, packing.add_lanes(), prep.clone());
                table_preps[idx] = (
                    CircuitTableAir::Add(add_air),
                    log2_ceil_usize(num_ops.div_ceil(packing.add_lanes())),
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
                    MulAir::new_with_preprocessed(num_ops, packing.mul_lanes(), prep.clone())
                } else {
                    let w = w_binomial.unwrap();
                    MulAir::new_binomial_with_preprocessed(
                        num_ops,
                        packing.mul_lanes(),
                        w,
                        prep.clone(),
                    )
                };
                table_preps[idx] = (
                    CircuitTableAir::Mul(mul_air),
                    log2_ceil_usize(num_ops.div_ceil(packing.mul_lanes())),
                );
            }
            PrimitiveOpType::Public => {
                let height = prep.len();
                let public_air = PublicAir::new_with_preprocessed(height, prep.clone());
                table_preps[idx] = (CircuitTableAir::Public(public_air), log2_ceil_usize(height));
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

        // TODO: Handle preprocessing for non-primitive tables as well.
    });

    Ok((table_preps, base_prep[0].clone()))
}
