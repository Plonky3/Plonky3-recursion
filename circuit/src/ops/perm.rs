//! Permutation-agnostic config and call wrapper over Poseidon1 / Poseidon2.
//!
//! Lets MMCS/FRI code build perm rows without naming a specific hash: dispatch
//! is centralized in [`CircuitBuilder::add_perm`] and [`perm_private_data`].

use alloc::vec::Vec;

use p3_field::Field;

use crate::CircuitBuilderError;
use crate::builder::CircuitBuilder;
use crate::ops::poseidon1_perm::{Poseidon1Config, Poseidon1PermCall, Poseidon1PermPrivateData};
use crate::ops::poseidon2_perm::{Poseidon2Config, Poseidon2PermCall, Poseidon2PermPrivateData};
use crate::ops::{NpoPrivateData, NpoTypeId};
use crate::types::{ExprId, NonPrimitiveOpId};

/// Challenger/MMCS permutation config: either Poseidon1 or Poseidon2.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum PermConfig {
    Poseidon1(Poseidon1Config),
    Poseidon2(Poseidon2Config),
}

impl PermConfig {
    pub const fn poseidon1(c: Poseidon1Config) -> Self {
        Self::Poseidon1(c)
    }

    pub const fn poseidon2(c: Poseidon2Config) -> Self {
        Self::Poseidon2(c)
    }

    pub const fn d(self) -> usize {
        match self {
            Self::Poseidon1(c) => c.d(),
            Self::Poseidon2(c) => c.d(),
        }
    }

    pub const fn rate(self) -> usize {
        match self {
            Self::Poseidon1(c) => c.rate(),
            Self::Poseidon2(c) => c.rate(),
        }
    }

    pub const fn rate_ext(self) -> usize {
        match self {
            Self::Poseidon1(c) => c.rate_ext(),
            Self::Poseidon2(c) => c.rate_ext(),
        }
    }

    pub const fn capacity_ext(self) -> usize {
        match self {
            Self::Poseidon1(c) => c.capacity_ext(),
            Self::Poseidon2(c) => c.capacity_ext(),
        }
    }

    pub const fn width_ext(self) -> usize {
        match self {
            Self::Poseidon1(c) => c.width_ext(),
            Self::Poseidon2(c) => c.width_ext(),
        }
    }

    /// Returns `true` for the arity-4 compression shape (`4·capacity_ext == width_ext`).
    pub const fn is_arity4_shape(self) -> bool {
        4 * self.capacity_ext() == self.width_ext()
    }

    pub const fn as_poseidon1(self) -> Option<Poseidon1Config> {
        match self {
            Self::Poseidon1(c) => Some(c),
            Self::Poseidon2(_) => None,
        }
    }

    pub const fn as_poseidon2(self) -> Option<Poseidon2Config> {
        match self {
            Self::Poseidon2(c) => Some(c),
            Self::Poseidon1(_) => None,
        }
    }

    /// NPO type id for the perm table backing this config.
    pub fn npo_type_id(self) -> NpoTypeId {
        match self {
            Self::Poseidon1(c) => NpoTypeId::poseidon1_perm(c),
            Self::Poseidon2(c) => NpoTypeId::poseidon2_perm(c),
        }
    }
}

impl From<Poseidon1Config> for PermConfig {
    fn from(c: Poseidon1Config) -> Self {
        Self::Poseidon1(c)
    }
}

impl From<Poseidon2Config> for PermConfig {
    fn from(c: Poseidon2Config) -> Self {
        Self::Poseidon2(c)
    }
}

/// Config-less perm-row arguments, shared by Poseidon1 and Poseidon2.
#[derive(Clone)]
pub struct PermCall {
    pub new_start: bool,
    pub merkle_path: bool,
    pub mmcs_bit: Option<ExprId>,
    pub mmcs_bit2: Option<ExprId>,
    pub inputs: Vec<Option<ExprId>>,
    pub out_ctl: Vec<bool>,
    pub return_all_outputs: bool,
    pub mmcs_index_sum: Option<ExprId>,
}

/// Private (witness) data for one perm row, typed for the configured hash so the
/// runner downcasts it to the matching executor's expected type.
pub fn perm_private_data<F: 'static + Send + Sync>(
    cfg: impl Into<PermConfig>,
    sibling: Vec<F>,
) -> NpoPrivateData {
    match cfg.into() {
        PermConfig::Poseidon1(_) => NpoPrivateData::new(Poseidon1PermPrivateData { sibling }),
        PermConfig::Poseidon2(_) => NpoPrivateData::new(Poseidon2PermPrivateData { sibling }),
    }
}

impl<F: Field> CircuitBuilder<F> {
    /// Add a perm row, dispatching to the Poseidon1 or Poseidon2 op per `cfg`.
    pub fn add_perm(
        &mut self,
        cfg: PermConfig,
        call: &PermCall,
    ) -> Result<(NonPrimitiveOpId, Vec<Option<ExprId>>), CircuitBuilderError> {
        match cfg {
            PermConfig::Poseidon1(config) => self.add_poseidon1_perm(&Poseidon1PermCall {
                config,
                new_start: call.new_start,
                merkle_path: call.merkle_path,
                mmcs_bit: call.mmcs_bit,
                mmcs_bit2: None,
                inputs: call.inputs.clone(),
                out_ctl: call.out_ctl.clone(),
                return_all_outputs: call.return_all_outputs,
                mmcs_index_sum: call.mmcs_index_sum,
            }),
            PermConfig::Poseidon2(config) => self.add_poseidon2_perm(&Poseidon2PermCall {
                config,
                new_start: call.new_start,
                merkle_path: call.merkle_path,
                mmcs_bit: call.mmcs_bit,
                mmcs_bit2: call.mmcs_bit2,
                inputs: call.inputs.clone(),
                out_ctl: call.out_ctl.clone(),
                return_all_outputs: call.return_all_outputs,
                mmcs_index_sum: call.mmcs_index_sum,
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec::Vec;
    use alloc::{format, vec};

    use p3_baby_bear::BabyBear;
    use proptest::prelude::*;

    use super::*;
    use crate::ops::{Poseidon1Config, Poseidon2Config};

    type F = BabyBear;

    #[test]
    fn test_perm_config_poseidon1_accessors() {
        let cfg = PermConfig::Poseidon1(Poseidon1Config::BABY_BEAR_D1_W16);
        assert_eq!(cfg.d(), 1);
        assert_eq!(cfg.width_ext(), cfg.rate_ext() + cfg.capacity_ext());
        assert!(cfg.as_poseidon1().is_some());
        assert!(cfg.as_poseidon2().is_none());
    }

    #[test]
    fn test_perm_config_poseidon2_accessors() {
        let cfg = PermConfig::Poseidon2(Poseidon2Config::BABY_BEAR_D1_W16);
        assert_eq!(cfg.d(), 1);
        assert_eq!(cfg.width_ext(), cfg.rate_ext() + cfg.capacity_ext());
        assert!(cfg.as_poseidon1().is_none());
        assert!(cfg.as_poseidon2().is_some());
    }

    #[test]
    fn test_perm_config_from_poseidon1() {
        let cfg = PermConfig::from(Poseidon1Config::BABY_BEAR_D1_W16);
        assert_eq!(
            cfg,
            PermConfig::Poseidon1(Poseidon1Config::BABY_BEAR_D1_W16)
        );
        assert!(cfg.as_poseidon1().is_some());
    }

    #[test]
    fn test_perm_config_from_poseidon2() {
        let cfg = PermConfig::from(Poseidon2Config::BABY_BEAR_D1_W16);
        assert_eq!(
            cfg,
            PermConfig::Poseidon2(Poseidon2Config::BABY_BEAR_D1_W16)
        );
        assert!(cfg.as_poseidon2().is_some());
    }

    #[test]
    fn test_is_arity4_shape_false_for_standard() {
        assert!(!PermConfig::Poseidon2(Poseidon2Config::BABY_BEAR_D1_W16).is_arity4_shape());
    }

    #[test]
    fn test_is_arity4_shape_true() {
        assert!(PermConfig::Poseidon2(Poseidon2Config::KOALA_BEAR_D1_W32).is_arity4_shape());
    }

    #[test]
    fn test_width_ext_equals_rate_ext_plus_capacity_ext() {
        let configs = [
            PermConfig::Poseidon1(Poseidon1Config::BABY_BEAR_D1_W16),
            PermConfig::Poseidon1(Poseidon1Config::BABY_BEAR_D4_W16),
            PermConfig::Poseidon2(Poseidon2Config::BABY_BEAR_D1_W16),
            PermConfig::Poseidon2(Poseidon2Config::KOALA_BEAR_D1_W32),
            PermConfig::Poseidon2(Poseidon2Config::KOALA_BEAR_D4_W32),
        ];
        for cfg in configs {
            assert_eq!(cfg.width_ext(), cfg.rate_ext() + cfg.capacity_ext());
        }
    }

    #[test]
    fn test_perm_private_data_poseidon1_type() {
        let _ = perm_private_data(Poseidon1Config::BABY_BEAR_D1_W16, Vec::<F>::new());
    }

    #[test]
    fn test_perm_private_data_poseidon2_type() {
        let _ = perm_private_data(Poseidon2Config::BABY_BEAR_D1_W16, Vec::<F>::new());
    }

    #[test]
    fn test_poseidon1_constructor_helper() {
        let cfg = PermConfig::poseidon1(Poseidon1Config::BABY_BEAR_D1_W16);
        assert_eq!(
            cfg,
            PermConfig::Poseidon1(Poseidon1Config::BABY_BEAR_D1_W16)
        );
    }

    #[test]
    fn test_poseidon2_constructor_helper() {
        let cfg = PermConfig::poseidon2(Poseidon2Config::BABY_BEAR_D1_W16);
        assert_eq!(
            cfg,
            PermConfig::Poseidon2(Poseidon2Config::BABY_BEAR_D1_W16)
        );
    }

    #[test]
    fn test_permconfig_debug() {
        let cfg = PermConfig::Poseidon2(Poseidon2Config::BABY_BEAR_D1_W16);
        let s = format!("{cfg:?}");
        assert!(!s.is_empty());
    }

    proptest! {
        #[test]
        fn perm_config_width_ext_invariant(
            cfg in prop_oneof![
                Just(PermConfig::Poseidon1(Poseidon1Config::BABY_BEAR_D1_W16)),
                Just(PermConfig::Poseidon1(Poseidon1Config::BABY_BEAR_D4_W16)),
                Just(PermConfig::Poseidon1(Poseidon1Config::BABY_BEAR_D4_W24)),
                Just(PermConfig::Poseidon1(Poseidon1Config::KOALA_BEAR_D1_W16)),
                Just(PermConfig::Poseidon1(Poseidon1Config::KOALA_BEAR_D4_W16)),
                Just(PermConfig::Poseidon1(Poseidon1Config::KOALA_BEAR_D4_W24)),
                Just(PermConfig::Poseidon1(Poseidon1Config::GOLDILOCKS_D2_W8)),
                Just(PermConfig::Poseidon2(Poseidon2Config::BABY_BEAR_D1_W16)),
                Just(PermConfig::Poseidon2(Poseidon2Config::BABY_BEAR_D4_W16)),
                Just(PermConfig::Poseidon2(Poseidon2Config::BABY_BEAR_D4_W24)),
                Just(PermConfig::Poseidon2(Poseidon2Config::BABY_BEAR_D4_W32)),
                Just(PermConfig::Poseidon2(Poseidon2Config::KOALA_BEAR_D1_W16)),
                Just(PermConfig::Poseidon2(Poseidon2Config::KOALA_BEAR_D4_W16)),
                Just(PermConfig::Poseidon2(Poseidon2Config::KOALA_BEAR_D4_W24)),
                Just(PermConfig::Poseidon2(Poseidon2Config::GOLDILOCKS_D2_W8)),
                Just(PermConfig::Poseidon2(Poseidon2Config::KOALA_BEAR_D1_W32)),
                Just(PermConfig::Poseidon2(Poseidon2Config::KOALA_BEAR_D4_W32)),
                Just(PermConfig::Poseidon2(Poseidon2Config::GOLDILOCKS_D2_W16)),
            ]
        ) {
            prop_assert_eq!(cfg.width_ext(), cfg.rate_ext() + cfg.capacity_ext());
        }
    }

    proptest! {
        #[test]
        fn perm_config_arity4_shape_consistent(
            cfg in prop_oneof![
                Just(PermConfig::Poseidon1(Poseidon1Config::BABY_BEAR_D1_W16)),
                Just(PermConfig::Poseidon1(Poseidon1Config::BABY_BEAR_D4_W16)),
                Just(PermConfig::Poseidon1(Poseidon1Config::BABY_BEAR_D4_W24)),
                Just(PermConfig::Poseidon1(Poseidon1Config::KOALA_BEAR_D1_W16)),
                Just(PermConfig::Poseidon1(Poseidon1Config::KOALA_BEAR_D4_W16)),
                Just(PermConfig::Poseidon1(Poseidon1Config::KOALA_BEAR_D4_W24)),
                Just(PermConfig::Poseidon1(Poseidon1Config::GOLDILOCKS_D2_W8)),
                Just(PermConfig::Poseidon2(Poseidon2Config::BABY_BEAR_D1_W16)),
                Just(PermConfig::Poseidon2(Poseidon2Config::BABY_BEAR_D4_W16)),
                Just(PermConfig::Poseidon2(Poseidon2Config::BABY_BEAR_D4_W24)),
                Just(PermConfig::Poseidon2(Poseidon2Config::BABY_BEAR_D4_W32)),
                Just(PermConfig::Poseidon2(Poseidon2Config::KOALA_BEAR_D1_W16)),
                Just(PermConfig::Poseidon2(Poseidon2Config::KOALA_BEAR_D4_W16)),
                Just(PermConfig::Poseidon2(Poseidon2Config::KOALA_BEAR_D4_W24)),
                Just(PermConfig::Poseidon2(Poseidon2Config::GOLDILOCKS_D2_W8)),
                Just(PermConfig::Poseidon2(Poseidon2Config::KOALA_BEAR_D1_W32)),
                Just(PermConfig::Poseidon2(Poseidon2Config::KOALA_BEAR_D4_W32)),
                Just(PermConfig::Poseidon2(Poseidon2Config::GOLDILOCKS_D2_W16)),
            ]
        ) {
            prop_assert_eq!(
                cfg.is_arity4_shape(),
                4 * cfg.capacity_ext() == cfg.width_ext()
            );
        }
    }
}
