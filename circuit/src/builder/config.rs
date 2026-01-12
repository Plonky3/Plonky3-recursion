use hashbrown::HashMap;

use crate::op::{NonPrimitiveOpConfig, NonPrimitiveOpType};

/// Configuration for the circuit builder.
#[derive(Debug)]
pub struct BuilderConfig<F> {
    /// Enabled non-primitive operation types with their respective configuration.
    enabled_ops: HashMap<NonPrimitiveOpType, NonPrimitiveOpConfig<F>>,
}

impl<F> Default for BuilderConfig<F> {
    fn default() -> Self {
        Self::new()
    }
}

impl<F> Clone for BuilderConfig<F> {
    fn clone(&self) -> Self {
        Self {
            enabled_ops: self.enabled_ops.clone(),
        }
    }
}

impl<F> BuilderConfig<F> {
    /// Creates a new builder configuration.
    pub fn new() -> Self {
        Self {
            enabled_ops: HashMap::new(),
        }
    }

    /// Enables a non-primitive operation type with its configuration.
    pub fn enable_op(&mut self, op: NonPrimitiveOpType, cfg: NonPrimitiveOpConfig<F>) {
        self.enabled_ops.insert(op, cfg);
    }

    /// Checks whether an operation type is enabled.
    pub fn is_op_enabled(&self, op: &NonPrimitiveOpType) -> bool {
        self.enabled_ops.contains_key(op)
    }

    /// Gets the configuration for an operation type, if enabled.
    pub fn get_op_config(&self, op: &NonPrimitiveOpType) -> Option<&NonPrimitiveOpConfig<F>> {
        self.enabled_ops.get(op)
    }

    /// Consumes the config and returns the enabled operations map.
    pub fn into_enabled_ops(self) -> HashMap<NonPrimitiveOpType, NonPrimitiveOpConfig<F>> {
        self.enabled_ops
    }
}

#[cfg(test)]
mod tests {
    use p3_baby_bear::BabyBear;

    use super::*;
    use crate::op::Poseidon2Config;

    type F = BabyBear;

    #[test]
    fn test_builder_config_default() {
        let config = BuilderConfig::<F>::default();
        assert!(!config.is_op_enabled(&NonPrimitiveOpType::Poseidon2Perm(
            Poseidon2Config::BabyBearD4Width16,
        )));
    }

    #[test]
    fn test_builder_config_enable_op() {
        let mut config = BuilderConfig::<F>::new();

        config.enable_op(
            NonPrimitiveOpType::Poseidon2Perm(Poseidon2Config::BabyBearD4Width16),
            NonPrimitiveOpConfig::None,
        );

        assert!(config.is_op_enabled(&NonPrimitiveOpType::Poseidon2Perm(
            Poseidon2Config::BabyBearD4Width16,
        )));
    }
}
