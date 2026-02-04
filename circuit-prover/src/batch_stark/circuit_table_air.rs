//! Air implementations for CircuitTableAir enum.

use alloc::vec::Vec;

use p3_air::{Air, AirBuilder, BaseAir};
#[cfg(debug_assertions)]
use p3_batch_stark::DebugConstraintBuilderWithLookups;
use p3_batch_stark::{StarkGenericConfig, Val};
use p3_field::PrimeField;
use p3_lookup::folder::{ProverConstraintFolderWithLookups, VerifierConstraintFolderWithLookups};
use p3_lookup::lookup_traits::Lookup;
use p3_matrix::dense::RowMajorMatrix;
use p3_uni_stark::{SymbolicAirBuilder, SymbolicExpression};

use super::dynamic_air::CloneableBatchAir;
use crate::common::CircuitTableAir;

impl<SC, const D: usize> BaseAir<Val<SC>> for CircuitTableAir<SC, D>
where
    SC: StarkGenericConfig,
    SymbolicExpression<SC::Challenge>: From<SymbolicExpression<Val<SC>>>,
{
    fn width(&self) -> usize {
        match self {
            Self::Witness(a) => a.width(),
            Self::Const(a) => a.width(),
            Self::Public(a) => a.width(),
            Self::Add(a) => a.width(),
            Self::Mul(a) => a.width(),
            Self::Dynamic(a) => <dyn CloneableBatchAir<SC> as BaseAir<Val<SC>>>::width(a.air()),
        }
    }

    fn preprocessed_trace(&self) -> Option<RowMajorMatrix<Val<SC>>> {
        match self {
            Self::Witness(a) => a.preprocessed_trace(),
            Self::Const(a) => a.preprocessed_trace(),
            Self::Public(a) => a.preprocessed_trace(),
            Self::Add(a) => a.preprocessed_trace(),
            Self::Mul(a) => a.preprocessed_trace(),
            Self::Dynamic(a) => {
                <dyn CloneableBatchAir<SC> as BaseAir<Val<SC>>>::preprocessed_trace(a.air())
            }
        }
    }
}

impl<SC, const D: usize> Air<SymbolicAirBuilder<Val<SC>, SC::Challenge>> for CircuitTableAir<SC, D>
where
    SC: StarkGenericConfig,
    Val<SC>: PrimeField,
    SymbolicExpression<SC::Challenge>: From<SymbolicExpression<Val<SC>>>,
{
    fn eval(&self, builder: &mut SymbolicAirBuilder<Val<SC>, SC::Challenge>) {
        match self {
            Self::Witness(a) => Air::<SymbolicAirBuilder<Val<SC>, SC::Challenge>>::eval(a, builder),
            Self::Const(a) => Air::<SymbolicAirBuilder<Val<SC>, SC::Challenge>>::eval(a, builder),
            Self::Public(a) => Air::<SymbolicAirBuilder<Val<SC>, SC::Challenge>>::eval(a, builder),
            Self::Add(a) => Air::<SymbolicAirBuilder<Val<SC>, SC::Challenge>>::eval(a, builder),
            Self::Mul(a) => Air::<SymbolicAirBuilder<Val<SC>, SC::Challenge>>::eval(a, builder),
            Self::Dynamic(a) => Air::<SymbolicAirBuilder<Val<SC>, SC::Challenge>>::eval(a, builder),
        }
    }

    fn add_lookup_columns(&mut self) -> Vec<usize> {
        match self {
            Self::Witness(a) => {
                Air::<SymbolicAirBuilder<Val<SC>, SC::Challenge>>::add_lookup_columns(a)
            }
            Self::Const(a) => {
                Air::<SymbolicAirBuilder<Val<SC>, SC::Challenge>>::add_lookup_columns(a)
            }
            Self::Public(a) => {
                Air::<SymbolicAirBuilder<Val<SC>, SC::Challenge>>::add_lookup_columns(a)
            }
            Self::Add(a) => {
                Air::<SymbolicAirBuilder<Val<SC>, SC::Challenge>>::add_lookup_columns(a)
            }
            Self::Mul(a) => {
                Air::<SymbolicAirBuilder<Val<SC>, SC::Challenge>>::add_lookup_columns(a)
            }
            Self::Dynamic(a) => {
                Air::<SymbolicAirBuilder<Val<SC>, SC::Challenge>>::add_lookup_columns(a)
            }
        }
    }

    fn get_lookups(
        &mut self,
    ) -> Vec<Lookup<<SymbolicAirBuilder<Val<SC>, SC::Challenge> as AirBuilder>::F>> {
        match self {
            Self::Witness(a) => Air::<SymbolicAirBuilder<Val<SC>, SC::Challenge>>::get_lookups(a),
            Self::Const(a) => Air::<SymbolicAirBuilder<Val<SC>, SC::Challenge>>::get_lookups(a),
            Self::Public(a) => Air::<SymbolicAirBuilder<Val<SC>, SC::Challenge>>::get_lookups(a),
            Self::Add(a) => Air::<SymbolicAirBuilder<Val<SC>, SC::Challenge>>::get_lookups(a),
            Self::Mul(a) => Air::<SymbolicAirBuilder<Val<SC>, SC::Challenge>>::get_lookups(a),
            Self::Dynamic(a) => Air::<SymbolicAirBuilder<Val<SC>, SC::Challenge>>::get_lookups(a),
        }
    }
}

#[cfg(debug_assertions)]
impl<'a, SC, const D: usize> Air<DebugConstraintBuilderWithLookups<'a, Val<SC>, SC::Challenge>>
    for CircuitTableAir<SC, D>
where
    SC: StarkGenericConfig,
    Val<SC>: PrimeField,
    SymbolicExpression<SC::Challenge>: From<SymbolicExpression<Val<SC>>>,
{
    fn eval(&self, builder: &mut DebugConstraintBuilderWithLookups<'a, Val<SC>, SC::Challenge>) {
        match self {
            Self::Witness(a) => {
                Air::<DebugConstraintBuilderWithLookups<'a, Val<SC>, SC::Challenge>>::eval(
                    a, builder,
                );
            }
            Self::Const(a) => {
                Air::<DebugConstraintBuilderWithLookups<'a, Val<SC>, SC::Challenge>>::eval(
                    a, builder,
                );
            }
            Self::Public(a) => {
                Air::<DebugConstraintBuilderWithLookups<'a, Val<SC>, SC::Challenge>>::eval(
                    a, builder,
                );
            }
            Self::Add(a) => {
                Air::<DebugConstraintBuilderWithLookups<'a, Val<SC>, SC::Challenge>>::eval(
                    a, builder,
                );
            }
            Self::Mul(a) => {
                Air::<DebugConstraintBuilderWithLookups<'a, Val<SC>, SC::Challenge>>::eval(
                    a, builder,
                );
            }
            Self::Dynamic(a) => {
                Air::<DebugConstraintBuilderWithLookups<'a, Val<SC>, SC::Challenge>>::eval(
                    a, builder,
                );
            }
        }
    }

    fn add_lookup_columns(&mut self) -> Vec<usize> {
        match self {
            Self::Witness(a) => Air::<
                DebugConstraintBuilderWithLookups<'a, Val<SC>, SC::Challenge>,
            >::add_lookup_columns(a),
            Self::Const(a) => Air::<
                DebugConstraintBuilderWithLookups<'a, Val<SC>, SC::Challenge>,
            >::add_lookup_columns(a),
            Self::Public(a) => Air::<
                DebugConstraintBuilderWithLookups<'a, Val<SC>, SC::Challenge>,
            >::add_lookup_columns(a),
            Self::Add(a) => Air::<
                DebugConstraintBuilderWithLookups<'a, Val<SC>, SC::Challenge>,
            >::add_lookup_columns(a),
            Self::Mul(a) => Air::<
                DebugConstraintBuilderWithLookups<'a, Val<SC>, SC::Challenge>,
            >::add_lookup_columns(a),
            Self::Dynamic(a) => {
                Air::<DebugConstraintBuilderWithLookups<'a, Val<SC>, SC::Challenge>>::add_lookup_columns(a)
            }
        }
    }

    fn get_lookups(
        &mut self,
    ) -> Vec<Lookup<<DebugConstraintBuilderWithLookups<'a, Val<SC>, SC::Challenge> as AirBuilder>::F>>
    {
        match self {
            Self::Witness(a) => {
                Air::<DebugConstraintBuilderWithLookups<'a, Val<SC>, SC::Challenge>>::get_lookups(a)
            }
            Self::Const(a) => {
                Air::<DebugConstraintBuilderWithLookups<'a, Val<SC>, SC::Challenge>>::get_lookups(a)
            }
            Self::Public(a) => {
                Air::<DebugConstraintBuilderWithLookups<'a, Val<SC>, SC::Challenge>>::get_lookups(a)
            }
            Self::Add(a) => {
                Air::<DebugConstraintBuilderWithLookups<'a, Val<SC>, SC::Challenge>>::get_lookups(a)
            }
            Self::Mul(a) => {
                Air::<DebugConstraintBuilderWithLookups<'a, Val<SC>, SC::Challenge>>::get_lookups(a)
            }
            Self::Dynamic(a) => {
                Air::<DebugConstraintBuilderWithLookups<'a, Val<SC>, SC::Challenge>>::get_lookups(a)
            }
        }
    }
}

impl<'a, SC, const D: usize> Air<ProverConstraintFolderWithLookups<'a, SC>>
    for CircuitTableAir<SC, D>
where
    SC: StarkGenericConfig,
    Val<SC>: PrimeField,
    SymbolicExpression<SC::Challenge>: From<SymbolicExpression<Val<SC>>>,
{
    fn eval(&self, builder: &mut ProverConstraintFolderWithLookups<'a, SC>) {
        match self {
            Self::Witness(a) => Air::<ProverConstraintFolderWithLookups<'a, SC>>::eval(a, builder),
            Self::Const(a) => Air::<ProverConstraintFolderWithLookups<'a, SC>>::eval(a, builder),
            Self::Public(a) => Air::<ProverConstraintFolderWithLookups<'a, SC>>::eval(a, builder),
            Self::Add(a) => Air::<ProverConstraintFolderWithLookups<'a, SC>>::eval(a, builder),
            Self::Mul(a) => Air::<ProverConstraintFolderWithLookups<'a, SC>>::eval(a, builder),
            Self::Dynamic(a) => {
                Air::<ProverConstraintFolderWithLookups<'a, SC>>::eval(a, builder);
            }
        }
    }

    fn add_lookup_columns(&mut self) -> Vec<usize> {
        match self {
            Self::Witness(a) => {
                Air::<ProverConstraintFolderWithLookups<'a, SC>>::add_lookup_columns(a)
            }
            Self::Const(a) => {
                Air::<ProverConstraintFolderWithLookups<'a, SC>>::add_lookup_columns(a)
            }
            Self::Public(a) => {
                Air::<ProverConstraintFolderWithLookups<'a, SC>>::add_lookup_columns(a)
            }
            Self::Add(a) => Air::<ProverConstraintFolderWithLookups<'a, SC>>::add_lookup_columns(a),
            Self::Mul(a) => Air::<ProverConstraintFolderWithLookups<'a, SC>>::add_lookup_columns(a),
            Self::Dynamic(a) => {
                Air::<ProverConstraintFolderWithLookups<'a, SC>>::add_lookup_columns(a)
            }
        }
    }

    fn get_lookups(
        &mut self,
    ) -> Vec<Lookup<<ProverConstraintFolderWithLookups<'a, SC> as AirBuilder>::F>> {
        match self {
            Self::Witness(a) => Air::<ProverConstraintFolderWithLookups<'a, SC>>::get_lookups(a),
            Self::Const(a) => Air::<ProverConstraintFolderWithLookups<'a, SC>>::get_lookups(a),
            Self::Public(a) => Air::<ProverConstraintFolderWithLookups<'a, SC>>::get_lookups(a),
            Self::Add(a) => Air::<ProverConstraintFolderWithLookups<'a, SC>>::get_lookups(a),
            Self::Mul(a) => Air::<ProverConstraintFolderWithLookups<'a, SC>>::get_lookups(a),
            Self::Dynamic(a) => Air::<ProverConstraintFolderWithLookups<'a, SC>>::get_lookups(a),
        }
    }
}

impl<'a, SC, const D: usize> Air<VerifierConstraintFolderWithLookups<'a, SC>>
    for CircuitTableAir<SC, D>
where
    SC: StarkGenericConfig,
    Val<SC>: PrimeField,
    SymbolicExpression<SC::Challenge>: From<SymbolicExpression<Val<SC>>>,
{
    fn eval(&self, builder: &mut VerifierConstraintFolderWithLookups<'a, SC>) {
        match self {
            Self::Witness(a) => {
                Air::<VerifierConstraintFolderWithLookups<'a, SC>>::eval(a, builder);
            }
            Self::Const(a) => Air::<VerifierConstraintFolderWithLookups<'a, SC>>::eval(a, builder),
            Self::Public(a) => Air::<VerifierConstraintFolderWithLookups<'a, SC>>::eval(a, builder),
            Self::Add(a) => Air::<VerifierConstraintFolderWithLookups<'a, SC>>::eval(a, builder),
            Self::Mul(a) => Air::<VerifierConstraintFolderWithLookups<'a, SC>>::eval(a, builder),
            Self::Dynamic(a) => {
                Air::<VerifierConstraintFolderWithLookups<'a, SC>>::eval(a, builder);
            }
        }
    }

    fn add_lookup_columns(&mut self) -> Vec<usize> {
        match self {
            Self::Witness(a) => {
                Air::<VerifierConstraintFolderWithLookups<'a, SC>>::add_lookup_columns(a)
            }
            Self::Const(a) => {
                Air::<VerifierConstraintFolderWithLookups<'a, SC>>::add_lookup_columns(a)
            }
            Self::Public(a) => {
                Air::<VerifierConstraintFolderWithLookups<'a, SC>>::add_lookup_columns(a)
            }
            Self::Add(a) => {
                Air::<VerifierConstraintFolderWithLookups<'a, SC>>::add_lookup_columns(a)
            }
            Self::Mul(a) => {
                Air::<VerifierConstraintFolderWithLookups<'a, SC>>::add_lookup_columns(a)
            }
            Self::Dynamic(a) => {
                Air::<VerifierConstraintFolderWithLookups<'a, SC>>::add_lookup_columns(a)
            }
        }
    }

    fn get_lookups(
        &mut self,
    ) -> Vec<Lookup<<VerifierConstraintFolderWithLookups<'a, SC> as AirBuilder>::F>> {
        match self {
            Self::Witness(a) => Air::<VerifierConstraintFolderWithLookups<'a, SC>>::get_lookups(a),
            Self::Const(a) => Air::<VerifierConstraintFolderWithLookups<'a, SC>>::get_lookups(a),
            Self::Public(a) => Air::<VerifierConstraintFolderWithLookups<'a, SC>>::get_lookups(a),
            Self::Add(a) => Air::<VerifierConstraintFolderWithLookups<'a, SC>>::get_lookups(a),
            Self::Mul(a) => Air::<VerifierConstraintFolderWithLookups<'a, SC>>::get_lookups(a),
            Self::Dynamic(a) => Air::<VerifierConstraintFolderWithLookups<'a, SC>>::get_lookups(a),
        }
    }
}
