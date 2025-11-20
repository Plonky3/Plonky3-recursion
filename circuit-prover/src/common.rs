use core::array;

use crate::DynamicAirEntry;
use crate::TablePacking;
use crate::air::AddAir;
use crate::air::MulAir;
use crate::air::PublicAir;
use crate::air::{ConstAir, WitnessAir};
use crate::field_params::ExtractBinomialW;
use alloc::vec::Vec;
use p3_circuit::Circuit;
use p3_circuit::CircuitError;
use p3_circuit::op::PrimitiveOpType;
use p3_field::ExtensionField;
use p3_uni_stark::StarkGenericConfig;
use p3_uni_stark::Val;
use p3_util::log2_ceil_usize;
use strum::EnumCount;

/// Enum wrapper to allow heterogeneous table AIRs in a single batch STARK aggregation.
///
/// This enables different AIR types to be collected into a single vector for
/// batch STARK proving/verification while maintaining type safety.
pub enum CircuitTableAir<SC, const D: usize>
where
    SC: StarkGenericConfig,
{
    Witness(WitnessAir<Val<SC>, D>),
    Const(ConstAir<Val<SC>, D>),
    Public(PublicAir<Val<SC>, D>),
    Add(AddAir<Val<SC>, D>),
    Mul(MulAir<Val<SC>, D>),
    Dynamic(DynamicAirEntry<SC>),
}

pub fn get_airs_and_degrees_with_prep<
    SC: StarkGenericConfig,
    ExtF: ExtensionField<Val<SC>> + ExtractBinomialW<Val<SC>>,
    const D: usize,
>(
    circuit: &Circuit<ExtF>,
    packing: TablePacking,
) -> Result<[(CircuitTableAir<SC, D>, usize); PrimitiveOpType::COUNT], CircuitError> {
    let preprocessed: Vec<Vec<ExtF>> = circuit.generate_preprocessed_columns()?;
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
    let mut table_preps: [(CircuitTableAir<_, _>, usize); PrimitiveOpType::COUNT] =
        array::from_fn(|_| (CircuitTableAir::Witness(default_air.clone()), 1));
    base_prep.iter().enumerate().for_each(|(idx, prep)| {
        let table = PrimitiveOpType::from(idx);
        match table {
            PrimitiveOpType::Add => {
                let num_ops = prep.len() / AddAir::<Val<SC>, D>::prep_lane_width();
                let add_air =
                    AddAir::new_with_preprocessed(num_ops, packing.add_lanes(), prep.clone());
                table_preps[idx] = (
                    CircuitTableAir::Add(add_air),
                    log2_ceil_usize(num_ops / packing.add_lanes()),
                )
            }
            PrimitiveOpType::Mul => {
                let num_ops = prep.len() / MulAir::<Val<SC>, D>::prep_lane_width();
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
                    log2_ceil_usize(num_ops / packing.mul_lanes()),
                )
            }
            PrimitiveOpType::Public => {
                let height = prep.len();
                let public_air = PublicAir::new_with_preprocessed(height, prep.clone());
                table_preps[idx] = (CircuitTableAir::Public(public_air), log2_ceil_usize(height))
            }
            PrimitiveOpType::Const => {
                let height = prep.len();
                let const_air = ConstAir::new_with_preprocessed(height, prep.clone());
                table_preps[idx] = (CircuitTableAir::Const(const_air), log2_ceil_usize(height))
            }
            PrimitiveOpType::Witness => {
                let num_witnesses = prep.len();
                let witness_air = WitnessAir::new(num_witnesses, packing.witness_lanes());
                table_preps[idx] = (
                    CircuitTableAir::Witness(witness_air),
                    log2_ceil_usize(num_witnesses / packing.witness_lanes()),
                )
            }
        }
    });

    Ok(table_preps)
}
