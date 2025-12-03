use hashbrown::HashMap;

use crate::op::{NonPrimitiveOpConfig, NonPrimitiveOpType};
use crate::ops::MmcsVerifyConfig;

/// Configuration for the circuit builder.
#[derive(Debug, Clone, Default)]
pub struct BuilderConfig {
    /// Enabled non-primitive operation types with their respective configuration.
    enabled_ops: HashMap<NonPrimitiveOpType, NonPrimitiveOpConfig>,
}

impl BuilderConfig {
    /// Creates a new builder configuration.
    pub fn new() -> Self {
        Self {
            enabled_ops: HashMap::new(),
        }
    }

    /// Enables a non-primitive operation type with its configuration.
    pub fn enable_op(&mut self, op: NonPrimitiveOpType, cfg: NonPrimitiveOpConfig) {
        self.enabled_ops.insert(op, cfg);
    }

    /// Enables MMCS verification operations with the given configuration.
    pub fn enable_mmcs(&mut self, mmcs_config: &MmcsVerifyConfig) {
        self.enable_op(
            NonPrimitiveOpType::MmcsVerify,
            NonPrimitiveOpConfig::MmcsVerifyConfig(mmcs_config.clone()),
        );
    }

    /// Enables Poseidon permutation operations (D=4 only).
    pub fn enable_poseidon_perm(&mut self) {
        self.enable_op(NonPrimitiveOpType::PoseidonPerm, NonPrimitiveOpConfig::None);
    }

    /// Checks whether an operation type is enabled.
    pub fn is_op_enabled(&self, op: &NonPrimitiveOpType) -> bool {
        self.enabled_ops.contains_key(op)
    }

    /// Gets the configuration for an operation type, if enabled.
    pub fn get_op_config(&self, op: &NonPrimitiveOpType) -> Option<&NonPrimitiveOpConfig> {
        self.enabled_ops.get(op)
    }

    /// Consumes the config and returns the enabled operations map.
    pub fn into_enabled_ops(self) -> HashMap<NonPrimitiveOpType, NonPrimitiveOpConfig> {
        self.enabled_ops
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_builder_config_default() {
        let config = BuilderConfig::default();
        assert!(!config.is_op_enabled(&NonPrimitiveOpType::MmcsVerify));
    }

    #[test]
    fn test_builder_config_enable_mmcs() {
        let mut config = BuilderConfig::new();
        let mmcs_config = MmcsVerifyConfig::mock_config();

        assert!(!config.is_op_enabled(&NonPrimitiveOpType::MmcsVerify));

        config.enable_mmcs(&mmcs_config);

        assert!(config.is_op_enabled(&NonPrimitiveOpType::MmcsVerify));
        assert!(
            config
                .get_op_config(&NonPrimitiveOpType::MmcsVerify)
                .is_some()
        );
    }

    #[test]
    fn test_builder_config_multiple_ops() {
        let mut config = BuilderConfig::new();
        let mmcs_config = MmcsVerifyConfig::mock_config();

        config.enable_mmcs(&mmcs_config);
        config.enable_poseidon_perm();

        assert!(config.is_op_enabled(&NonPrimitiveOpType::MmcsVerify));
        assert!(config.is_op_enabled(&NonPrimitiveOpType::PoseidonPerm));
    }
}
