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
    ///
    /// Inserts all combinations of the transparent flags (new_start, merkle_path, mmcs_bit)
    /// so that per-row control bits are accepted.
    pub fn enable_poseidon_perm(&mut self) {
        for &new_start in &[false, true] {
            for &merkle_path in &[false, true] {
                for &mmcs_bit in &[false, true] {
                    self.enable_op(
                        NonPrimitiveOpType::PoseidonPerm {
                            new_start,
                            merkle_path,
                            mmcs_bit,
                        },
                        NonPrimitiveOpConfig::None,
                    );
                }
            }
        }
    }

    /// Enables FRI verification operations.
    pub const fn enable_fri(&mut self) {
        // TODO: Add FRI ops when available.
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
        assert!(!config.is_op_enabled(&NonPrimitiveOpType::FriVerify));
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
        config.enable_op(NonPrimitiveOpType::FriVerify, NonPrimitiveOpConfig::None);

        assert!(config.is_op_enabled(&NonPrimitiveOpType::MmcsVerify));
        assert!(config.is_op_enabled(&NonPrimitiveOpType::FriVerify));
    }
}
