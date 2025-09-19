use alloc::vec::Vec;

use p3_air::BaseAir;
use p3_circuit::test_utils::FibonacciAir;
use p3_circuit::utils::{ColumnsTargets, symbolic_to_circuit};
use p3_circuit::{CircuitBuilder, ExprId};
use p3_field::Field;
use p3_uni_stark::{SymbolicExpression, get_log_quotient_degree, get_symbolic_constraints};

use crate::recursive_traits::{RecursiveAir, RecursiveLagrangeSelectors};

impl<EF: Field> RecursiveAir<EF> for FibonacciAir {
    fn width(&self) -> usize {
        <Self as BaseAir<EF>>::width(self)
    }

    fn eval_folded_circuit(
        &self,
        builder: &mut CircuitBuilder<EF>,
        sels: &RecursiveLagrangeSelectors,
        alpha: &ExprId,
        columns: ColumnsTargets,
    ) -> ExprId {
        let symbolic_constraints: Vec<SymbolicExpression<EF>> =
            get_symbolic_constraints(&FibonacciAir {}, 0, columns.public_values.len());

        let mut acc = builder.add_const(EF::ZERO);
        for s_c in symbolic_constraints {
            let mul_prev = builder.mul(acc, *alpha);
            let constraints = symbolic_to_circuit(sels.row_selectors, &columns, &s_c, builder);
            acc = builder.add(mul_prev, constraints);
        }

        acc
    }

    fn get_log_quotient_degree(&self, num_public_values: usize, is_zk: usize) -> usize {
        let air = FibonacciAir {};
        get_log_quotient_degree::<EF, FibonacciAir>(&air, 0, num_public_values, is_zk)
    }
}
