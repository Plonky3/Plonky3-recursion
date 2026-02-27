use p3_air::SymbolicExpression;
use p3_fri_air::OpenInputAir;
use p3_uni_stark::{StarkGenericConfig, Val};

use crate::batch_stark_prover::BatchAir;
use crate::config::StarkField;

impl<SC, const D: usize> BatchAir<SC> for OpenInputAir<Val<SC>, D>
where
    SC: StarkGenericConfig + Send + Sync,
    Val<SC>: StarkField,
    SymbolicExpression<SC::Challenge>: From<SymbolicExpression<Val<SC>>>,
{
}
