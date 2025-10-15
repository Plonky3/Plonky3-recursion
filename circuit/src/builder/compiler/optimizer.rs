use alloc::vec::Vec;

use crate::op::Op;

/// Responsible for performing optimization passes on primitive operations.
#[derive(Debug, Default)]
pub struct Optimizer;

impl Optimizer {
    /// Creates a new optimizer.
    pub const fn new() -> Self {
        Self
    }

    /// Optimizes primitive operations.
    ///
    /// Future passes that can be added here:
    /// - Dead code elimination
    /// - Common subexpression elimination
    /// - Instruction combining
    /// - Constant folding
    pub fn optimize<F>(&self, primitive_ops: Vec<Op<F>>) -> Vec<Op<F>> {
        // For now, return operations unchanged
        // Future optimization passes will be added here
        primitive_ops
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec;

    use super::*;

    #[test]
    fn test_optimizer_passthrough() {
        use p3_baby_bear::BabyBear;
        use p3_field::PrimeCharacteristicRing;

        use crate::types::WitnessId;

        let optimizer = Optimizer::new();

        let ops = vec![
            Op::Const {
                out: WitnessId(0),
                val: BabyBear::ZERO,
            },
            Op::Add {
                a: WitnessId(0),
                b: WitnessId(1),
                out: WitnessId(2),
            },
        ];

        let optimized = optimizer.optimize(ops.clone());
        assert_eq!(optimized, ops);
    }
}
