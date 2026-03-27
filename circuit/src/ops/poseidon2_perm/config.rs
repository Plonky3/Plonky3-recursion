//! Poseidon2 configuration types and execution closures.

use alloc::format;
use alloc::sync::Arc;
use alloc::vec::Vec;

use p3_field::Field;
use serde::{Deserialize, Serialize};

use crate::CircuitBuilderError;
use crate::builder::NpoLoweringContext;
use crate::types::{ExprId, WitnessId};

/// Identifies the base field for a Poseidon2 configuration.
///
/// Used internally for dispatching to concrete field-specific AIR types.
/// When adding support for a new prime field, add a variant here.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Ord, PartialOrd, Serialize, Deserialize)]
pub enum Poseidon2FieldId {
    /// BabyBear (31-bit, p = 2^31 - 2^27 + 1).
    BabyBear,
    /// KoalaBear (31-bit, p = 2^31 - 2^24 + 1).
    KoalaBear,
    /// Goldilocks (64-bit, p = 2^64 - 2^32 + 1).
    Goldilocks,
}

/// Poseidon2 configuration: a field-agnostic parameter bundle.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Ord, PartialOrd, Serialize, Deserialize)]
pub struct Poseidon2Config {
    /// Identifies which prime field this configuration targets.
    pub field_id: Poseidon2FieldId,
    /// Extension degree (1 = base field challenges, 2 = quadratic, 4 = quartic).
    pub d: usize,
    /// Permutation state width in base field elements (e.g. 8, 16, 24).
    pub width: usize,
    /// S-box polynomial degree.
    pub sbox_degree: u64,
    /// Number of S-box intermediate registers.
    pub sbox_registers: usize,
    /// Number of half full rounds.
    pub half_full_rounds: usize,
    /// Number of partial rounds.
    pub partial_rounds: usize,
}

impl Poseidon2Config {
    /// BabyBear with extension degree D=1 (base field challenges), width 16.
    pub const BABY_BEAR_D1_W16: Self = Self {
        field_id: Poseidon2FieldId::BabyBear,
        d: 1,
        width: 16,
        sbox_degree: 7,
        sbox_registers: 1,
        half_full_rounds: 4,
        partial_rounds: 13,
    };

    /// BabyBear with quartic extension (D=4), width 16.
    pub const BABY_BEAR_D4_W16: Self = Self {
        field_id: Poseidon2FieldId::BabyBear,
        d: 4,
        width: 16,
        sbox_degree: 7,
        sbox_registers: 1,
        half_full_rounds: 4,
        partial_rounds: 13,
    };

    /// BabyBear with quartic extension (D=4), width 24.
    pub const BABY_BEAR_D4_W24: Self = Self {
        field_id: Poseidon2FieldId::BabyBear,
        d: 4,
        width: 24,
        sbox_degree: 7,
        sbox_registers: 1,
        half_full_rounds: 4,
        partial_rounds: 21,
    };

    /// KoalaBear with extension degree D=1 (base field challenges), width 16.
    pub const KOALA_BEAR_D1_W16: Self = Self {
        field_id: Poseidon2FieldId::KoalaBear,
        d: 1,
        width: 16,
        sbox_degree: 3,
        sbox_registers: 0,
        half_full_rounds: 4,
        partial_rounds: 20,
    };

    /// KoalaBear with quartic extension (D=4), width 16.
    pub const KOALA_BEAR_D4_W16: Self = Self {
        field_id: Poseidon2FieldId::KoalaBear,
        d: 4,
        width: 16,
        sbox_degree: 3,
        sbox_registers: 0,
        half_full_rounds: 4,
        partial_rounds: 20,
    };

    /// KoalaBear with quartic extension (D=4), width 24.
    pub const KOALA_BEAR_D4_W24: Self = Self {
        field_id: Poseidon2FieldId::KoalaBear,
        d: 4,
        width: 24,
        sbox_degree: 3,
        sbox_registers: 0,
        half_full_rounds: 4,
        partial_rounds: 23,
    };

    /// Goldilocks with quadratic extension (D=2), width 8.
    pub const GOLDILOCKS_D2_W8: Self = Self {
        field_id: Poseidon2FieldId::Goldilocks,
        d: 2,
        width: 8,
        sbox_degree: 7,
        sbox_registers: 1,
        half_full_rounds: 4,
        partial_rounds: 22,
    };
}

impl Poseidon2Config {
    /// Extension degree.
    pub const fn d(self) -> usize {
        self.d
    }

    /// Permutation state width in base field elements.
    pub const fn width(self) -> usize {
        self.width
    }

    /// Rate in extension field elements.
    ///
    /// For D=1: `width / 2`. For D>1: `width / d - capacity_ext`.
    pub const fn rate_ext(self) -> usize {
        if self.d == 1 {
            self.width / 2
        } else {
            self.width / self.d - self.capacity_ext()
        }
    }

    /// Rate in base field elements (`rate_ext * d`).
    pub const fn rate(self) -> usize {
        self.rate_ext() * self.d
    }

    /// Capacity in extension field elements.
    ///
    /// For D=1: `width / 2`. For D>1: always 2.
    pub const fn capacity_ext(self) -> usize {
        if self.d == 1 { self.width / 2 } else { 2 }
    }

    /// S-box polynomial degree.
    pub const fn sbox_degree(self) -> u64 {
        self.sbox_degree
    }

    /// Number of S-box intermediate registers.
    pub const fn sbox_registers(self) -> usize {
        self.sbox_registers
    }

    /// Number of half full rounds.
    pub const fn half_full_rounds(self) -> usize {
        self.half_full_rounds
    }

    /// Number of partial rounds.
    pub const fn partial_rounds(self) -> usize {
        self.partial_rounds
    }

    /// Width in extension field elements (`rate_ext + capacity_ext`).
    pub const fn width_ext(self) -> usize {
        self.rate_ext() + self.capacity_ext()
    }

    /// Stable string name for this configuration, used to build `NpoTypeId`.
    ///
    /// The format is `{field}_d{d}_w{width}`, matching the legacy enum variant names.
    pub const fn variant_name(self) -> &'static str {
        match self.field_id {
            Poseidon2FieldId::BabyBear => match (self.d, self.width) {
                (1, 16) => "baby_bear_d1_w16",
                (4, 16) => "baby_bear_d4_w16",
                (4, 24) => "baby_bear_d4_w24",
                _ => panic!("unknown BabyBear Poseidon2 config"),
            },
            Poseidon2FieldId::KoalaBear => match (self.d, self.width) {
                (1, 16) => "koala_bear_d1_w16",
                (4, 16) => "koala_bear_d4_w16",
                (4, 24) => "koala_bear_d4_w24",
                _ => panic!("unknown KoalaBear Poseidon2 config"),
            },
            Poseidon2FieldId::Goldilocks => match (self.d, self.width) {
                (2, 8) => "goldilocks_d2_w8",
                _ => panic!("unknown Goldilocks Poseidon2 config"),
            },
        }
    }

    /// Parse a `Poseidon2Config` from a variant name string.
    pub fn from_variant_name(name: &str) -> Option<Self> {
        match name {
            "baby_bear_d1_w16" => Some(Self::BABY_BEAR_D1_W16),
            "baby_bear_d4_w16" => Some(Self::BABY_BEAR_D4_W16),
            "baby_bear_d4_w24" => Some(Self::BABY_BEAR_D4_W24),
            "koala_bear_d1_w16" => Some(Self::KOALA_BEAR_D1_W16),
            "koala_bear_d4_w16" => Some(Self::KOALA_BEAR_D4_W16),
            "koala_bear_d4_w24" => Some(Self::KOALA_BEAR_D4_W24),
            "goldilocks_d2_w8" => Some(Self::GOLDILOCKS_D2_W8),
            _ => None,
        }
    }

    /// Check that input and output counts match this config's expected layout.
    ///
    /// - For D=1: expects `width` inputs and `rate` or `width` outputs.
    /// - For D>1: expects `width_ext + 2` inputs and `rate_ext` or `width_ext` outputs.
    ///
    /// # Errors
    ///
    /// Returns `NonPrimitiveOpArity` if counts do not match.
    pub fn validate_io_counts(
        self,
        input_count: usize,
        output_count: usize,
    ) -> Result<(), CircuitBuilderError> {
        let is_d1 = self.d == 1;
        let expected_inputs = if is_d1 {
            self.width()
        } else {
            self.width_ext() + 2
        };
        if input_count != expected_inputs {
            return Err(CircuitBuilderError::NonPrimitiveOpArity {
                op: "Poseidon2Perm",
                expected: format!("{expected_inputs} inputs"),
                got: input_count,
            });
        }

        let valid_output_count = if is_d1 {
            output_count == self.rate() || output_count == self.width()
        } else {
            output_count == self.rate_ext() || output_count == self.width_ext()
        };
        if !valid_output_count {
            return Err(CircuitBuilderError::NonPrimitiveOpArity {
                op: "Poseidon2Perm",
                expected: if is_d1 {
                    format!("{} or {} outputs for D=1 mode", self.rate(), self.width())
                } else {
                    format!(
                        "{} or {} outputs for D>1 mode",
                        self.rate_ext(),
                        self.width_ext()
                    )
                },
                got: output_count,
            });
        }

        Ok(())
    }

    /// Convert input expressions to witness indices according to this config's layout.
    ///
    /// - D=1: all 16 inputs are independent flat slots.
    /// - D>1: `width_ext` limb slots, followed by the MMCS index accumulator and the MMCS direction bit.
    pub fn lower_inputs<F: Field>(
        self,
        input_exprs: &[Vec<ExprId>],
        ctx: &NpoLoweringContext<'_, F>,
    ) -> Result<Vec<Vec<WitnessId>>, CircuitBuilderError> {
        if self.d == 1 {
            ctx.lower_expr_slots(input_exprs, "Poseidon2Perm", "D=1 input")
        } else {
            let width_ext = self.width_ext();
            let mut widx =
                ctx.lower_expr_slots(&input_exprs[..width_ext], "Poseidon2Perm", "input limb")?;

            let [mmcs_sum] = ctx
                .lower_expr_slots(
                    &input_exprs[width_ext..=width_ext],
                    "Poseidon2Perm",
                    "mmcs_index_sum",
                )?
                .try_into()
                .expect("single-element slice must yield single-element vec");
            widx.push(mmcs_sum);

            let [mmcs_bit] = ctx
                .lower_expr_slots(
                    &input_exprs[width_ext + 1..=width_ext + 1],
                    "Poseidon2Perm",
                    "mmcs_bit",
                )?
                .try_into()
                .expect("single-element slice must yield single-element vec");
            widx.push(mmcs_bit);

            Ok(widx)
        }
    }
}

/// Poseidon2 permutation execution closure.
///
/// Takes `width_ext` field elements and returns `width_ext` output elements.
/// For D=1 mode, `width_ext == width` and the elements are base field values.
pub type Poseidon2PermExec<F> = Arc<dyn Fn(&[F]) -> Vec<F> + Send + Sync>;

/// Config data stored inside `NpoConfig` for Poseidon2 operations.
///
/// Stored behind `NpoConfig(Arc<dyn Any>)`, so cloning happens at the Arc level.
pub struct Poseidon2PermConfigData<F> {
    pub exec: Poseidon2PermExec<F>,
}

#[cfg(test)]
mod tests {
    use alloc::vec;
    use alloc::vec::Vec;

    use hashbrown::HashMap;
    use p3_test_utils::baby_bear_params::BabyBear;

    use super::*;
    use crate::builder::NpoLoweringContext;

    const ALL_CONFIGS: [Poseidon2Config; 7] = [
        Poseidon2Config::BABY_BEAR_D1_W16,
        Poseidon2Config::BABY_BEAR_D4_W16,
        Poseidon2Config::BABY_BEAR_D4_W24,
        Poseidon2Config::KOALA_BEAR_D1_W16,
        Poseidon2Config::KOALA_BEAR_D4_W16,
        Poseidon2Config::KOALA_BEAR_D4_W24,
        Poseidon2Config::GOLDILOCKS_D2_W8,
    ];

    type F = BabyBear;

    #[test]
    fn validate_io_counts_d4_w16_ok() {
        let cfg = Poseidon2Config::BABY_BEAR_D4_W16;
        // width_ext=4, rate_ext=2
        assert!(cfg.validate_io_counts(4 + 2, 2).is_ok()); // inputs=6, outputs=rate
        assert!(cfg.validate_io_counts(6, 4).is_ok()); // outputs=width
    }

    #[test]
    fn validate_io_counts_d1_w16_ok() {
        let cfg = Poseidon2Config::BABY_BEAR_D1_W16;
        assert!(cfg.validate_io_counts(16, 8).is_ok());
        assert!(cfg.validate_io_counts(16, 16).is_ok());
    }

    #[test]
    fn validate_io_counts_wrong_inputs_errors() {
        let cfg = Poseidon2Config::BABY_BEAR_D4_W16;
        let Err(CircuitBuilderError::NonPrimitiveOpArity { op, expected, got }) =
            cfg.validate_io_counts(3, 2)
        else {
            panic!("expected NonPrimitiveOpArity");
        };
        assert_eq!(op, "Poseidon2Perm");
        assert_eq!(expected, "6 inputs");
        assert_eq!(got, 3);
    }

    #[test]
    fn validate_io_counts_wrong_outputs_errors() {
        let cfg = Poseidon2Config::BABY_BEAR_D4_W16;
        let Err(CircuitBuilderError::NonPrimitiveOpArity { op, expected, got }) =
            cfg.validate_io_counts(6, 3)
        else {
            panic!("expected NonPrimitiveOpArity");
        };
        assert_eq!(op, "Poseidon2Perm");
        assert_eq!(expected, "2 or 4 outputs for D>1 mode");
        assert_eq!(got, 3);
    }

    #[test]
    fn validate_io_counts_d1_wrong_outputs_errors() {
        let cfg = Poseidon2Config::BABY_BEAR_D1_W16;
        let Err(CircuitBuilderError::NonPrimitiveOpArity { op, expected, got }) =
            cfg.validate_io_counts(16, 5)
        else {
            panic!("expected NonPrimitiveOpArity");
        };
        assert_eq!(op, "Poseidon2Perm");
        assert_eq!(expected, "8 or 16 outputs for D=1 mode");
        assert_eq!(got, 5);
    }

    #[test]
    fn lower_inputs_d4_produces_correct_structure() {
        let cfg = Poseidon2Config::BABY_BEAR_D4_W16;

        let mut map = HashMap::new();
        for i in 0u32..6 {
            map.insert(ExprId(i), WitnessId(100 + i));
        }
        let mut counter = 200u32;
        let mut alloc = |_: usize| {
            let id = WitnessId(counter);
            counter += 1;
            id
        };
        let ctx = NpoLoweringContext::<F>::new(&mut map, &mut alloc);

        let input_exprs: Vec<Vec<ExprId>> = (0u32..6).map(|i| vec![ExprId(i)]).collect();
        let result = cfg.lower_inputs(&input_exprs, &ctx).unwrap();

        let expected: Vec<Vec<WitnessId>> = (0u32..6).map(|i| vec![WitnessId(100 + i)]).collect();
        assert_eq!(result, expected);
    }

    #[test]
    fn lower_inputs_d1_produces_flat_structure() {
        let cfg = Poseidon2Config::BABY_BEAR_D1_W16;

        let mut map = HashMap::new();
        for i in 0u32..16 {
            map.insert(ExprId(i), WitnessId(i));
        }
        let mut counter = 100u32;
        let mut alloc = |_: usize| {
            let id = WitnessId(counter);
            counter += 1;
            id
        };
        let ctx = NpoLoweringContext::<F>::new(&mut map, &mut alloc);

        let input_exprs: Vec<Vec<ExprId>> = (0u32..16).map(|i| vec![ExprId(i)]).collect();
        let result = cfg.lower_inputs(&input_exprs, &ctx).unwrap();

        let expected: Vec<Vec<WitnessId>> = (0u32..16).map(|i| vec![WitnessId(i)]).collect();
        assert_eq!(result, expected);
    }

    #[test]
    fn lower_inputs_d4_with_empty_slots() {
        let cfg = Poseidon2Config::BABY_BEAR_D4_W16;

        let mut map = HashMap::new();
        map.insert(ExprId(10), WitnessId(50));
        map.insert(ExprId(11), WitnessId(51));
        let mut counter = 200u32;
        let mut alloc = |_: usize| {
            let id = WitnessId(counter);
            counter += 1;
            id
        };
        let ctx = NpoLoweringContext::<F>::new(&mut map, &mut alloc);

        let mut input_exprs: Vec<Vec<ExprId>> = vec![vec![]; cfg.width_ext()];
        input_exprs.push(vec![ExprId(10)]);
        input_exprs.push(vec![ExprId(11)]);

        let result = cfg.lower_inputs(&input_exprs, &ctx).unwrap();

        assert_eq!(
            result,
            vec![
                vec![],
                vec![],
                vec![],
                vec![],
                vec![WitnessId(50)],
                vec![WitnessId(51)],
            ]
        );
    }

    #[test]
    fn variant_name_roundtrip_all_configs() {
        for cfg in ALL_CONFIGS {
            let name = cfg.variant_name();
            let parsed = Poseidon2Config::from_variant_name(name);
            assert_eq!(parsed, Some(cfg), "roundtrip failed for {name}");
        }
    }

    #[test]
    fn from_variant_name_unknown_returns_none() {
        assert_eq!(Poseidon2Config::from_variant_name("unknown"), None);
    }
}
