use hashbrown::HashMap;

use crate::op::{NonPrimitiveOpConfig, NonPrimitiveOpType};

/// Configuration for the circuit builder.
#[derive(Debug, Clone)]
pub struct BuilderConfig<F> {
    /// Enabled non-primitive operation types with their respective configuration.
    enabled_ops: HashMap<NonPrimitiveOpType, NonPrimitiveOpConfig<F>>,
}

impl<F> Default for BuilderConfig<F> {
    fn default() -> Self {
        Self::new()
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
    use super::*;

    #[test]
    fn test_builder_config_default() {
        use p3_baby_bear::BabyBear;
        let config: BuilderConfig<BabyBear> = BuilderConfig::default();
        assert!(!config.is_op_enabled(&NonPrimitiveOpType::PoseidonPerm));
    }

    #[test]
    fn test_builder_config_multiple_ops() {
        use p3_baby_bear::BabyBear;
        let mut config: BuilderConfig<BabyBear> = BuilderConfig::new();

        let op_type = NonPrimitiveOpType::PoseidonPerm;
        config.enable_op(op_type.clone(), NonPrimitiveOpConfig::None);

        assert!(config.is_op_enabled(&op_type));
    }
}
