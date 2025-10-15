use hashbrown::HashMap;

use crate::op::{NonPrimitiveOpConfig, NonPrimitiveOpType};

#[derive(Debug, Clone, Default)]
pub struct BuilderConfig {
    enabled_ops: HashMap<NonPrimitiveOpType, NonPrimitiveOpConfig>,
}

impl BuilderConfig {
    pub fn new() -> Self {
        Self {
            enabled_ops: HashMap::new(),
        }
    }

    pub fn enable_op(&mut self, op: NonPrimitiveOpType, cfg: NonPrimitiveOpConfig) {
        self.enabled_ops.insert(op, cfg);
    }

    pub fn enable_mmcs(&mut self, mmcs_config: &crate::ops::MmcsVerifyConfig) {
        self.enable_op(
            NonPrimitiveOpType::MmcsVerify,
            NonPrimitiveOpConfig::MmcsVerifyConfig(mmcs_config.clone()),
        );
    }

    pub fn enable_fri(&mut self) {
        // TODO when available
    }

    pub fn is_op_enabled(&self, op: &NonPrimitiveOpType) -> bool {
        self.enabled_ops.contains_key(op)
    }

    pub fn get_op_config(&self, op: &NonPrimitiveOpType) -> Option<&NonPrimitiveOpConfig> {
        self.enabled_ops.get(op)
    }

    pub fn into_enabled_ops(self) -> HashMap<NonPrimitiveOpType, NonPrimitiveOpConfig> {
        self.enabled_ops
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ops::MmcsVerifyConfig;

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
