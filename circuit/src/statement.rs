use alloc::format;
use alloc::vec::Vec;

use p3_field::PrimeField64;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::ExprId;

/// One ordered value exported by a circuit's statement table.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StatementExport {
    /// Export a value promised to lie in the base field.
    Base(ExprId),
    /// Export every canonical base-field coefficient of an extension-field value.
    Extension(ExprId),
}

/// Semantic field description retained independently of the flattened base values.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum StatementField {
    Base,
    Extension { degree: usize },
}

/// Ordered statement schema with an overflow-checked flattened base-field width.
///
/// Raw flattened statement targets cannot be installed through the public builder API. Trusted
/// integrations must hold the opaque verified-target capability instead.
///
/// ```compile_fail
/// use p3_baby_bear::BabyBear;
/// use p3_circuit::{CircuitBuilder, StatementSchema};
///
/// let mut builder = CircuitBuilder::<BabyBear>::new();
/// let target = builder.public_input();
/// unsafe {
///     builder.set_statement_base_targets::<BabyBear>(StatementSchema::default(), &[target]);
/// }
/// ```
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct StatementSchema {
    fields: Vec<StatementField>,
    base_len: usize,
}

/// Ordered two-child statement boundary retained with an aggregation relation.
///
/// Construction checks both redundant fields so neither an incorrect split nor an unrelated
/// flattened schema can be attached to the trusted parent relation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct AggregationStatementLayout {
    left: StatementSchema,
    right: StatementSchema,
    split_at: usize,
    output: StatementSchema,
}

/// A compact two-child transition relation with statement order
/// `[initial state, final state, count]` for each child and parent.
///
/// The authorized leaf relation defines what a count means. Zero is permitted.
/// The application must retain this layout alongside its pinned verifier relation;
/// an ordinary statement schema alone cannot describe transition semantics.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StateTransitionLayout {
    state_schema: StatementSchema,
    statement_schema: StatementSchema,
    count_bits: u8,
}

/// Errors in transition layout validation or composition of canonical statements.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum StateTransitionError {
    #[error("transition state schema must be nonempty")]
    EmptyState,
    #[error("transition count bit width must be in 1..=63, got {bits}")]
    InvalidCountBits { bits: u8 },
    #[error("transition layout schema is invalid: {0}")]
    InvalidSchema(#[from] StatementError),
    #[error("transition child {child} schema differs from the exact transition schema")]
    ChildSchemaMismatch { child: usize },
    #[error("transition child {child} statement length mismatch: expected {expected}, got {got}")]
    StatementLength {
        child: usize,
        expected: usize,
        got: usize,
    },
    #[error("transition state differs at flattened coefficient {coefficient}")]
    DiscontinuousState { coefficient: usize },
    #[error("transition child {child} count {count} exceeds {max}")]
    CountOutOfRange { child: usize, count: u64, max: u64 },
    #[error("transition count sum {sum} exceeds {max}")]
    CountOverflow { sum: u128, max: u64 },
    #[error("transition count capacity for {bits} bits exceeds field modulus {modulus}")]
    CountCapacityExceeded { bits: u8, modulus: u64 },
}

impl StateTransitionLayout {
    /// Construct the semantic endpoint and whole-statement schemas.
    pub fn try_new(
        state_schema: StatementSchema,
        count_bits: u8,
    ) -> Result<Self, StateTransitionError> {
        if state_schema.base_len() == 0 {
            return Err(StateTransitionError::EmptyState);
        }
        if !(1..=63).contains(&count_bits) {
            return Err(StateTransitionError::InvalidCountBits { bits: count_bits });
        }
        let endpoints = StatementSchema::concat(&state_schema, &state_schema)?;
        let statement_schema = StatementSchema::concat(
            &endpoints,
            &StatementSchema::try_new(alloc::vec![StatementField::Base])?,
        )?;
        Ok(Self {
            state_schema,
            statement_schema,
            count_bits,
        })
    }

    /// Construct a state with `width` individual base-field coefficients.
    pub fn base(width: usize, count_bits: u8) -> Result<Self, StateTransitionError> {
        if width == 0 {
            return Err(StateTransitionError::EmptyState);
        }
        Self::try_new(
            StatementSchema::try_new(alloc::vec![StatementField::Base; width])?,
            count_bits,
        )
    }

    pub const fn state_schema(&self) -> &StatementSchema {
        &self.state_schema
    }
    pub const fn statement_schema(&self) -> &StatementSchema {
        &self.statement_schema
    }
    pub const fn count_bits(&self) -> u8 {
        self.count_bits
    }
    pub const fn state_width(&self) -> usize {
        self.state_schema.base_len()
    }

    /// Ensure adding two maximal canonical counts cannot wrap the base field.
    pub fn validate_field<BF: PrimeField64>(&self) -> Result<(), StateTransitionError> {
        if 2u128 * u128::from(self.max_count()) >= u128::from(BF::ORDER_U64) {
            return Err(StateTransitionError::CountCapacityExceeded {
                bits: self.count_bits,
                modulus: BF::ORDER_U64,
            });
        }
        Ok(())
    }

    pub const fn max_count(&self) -> u64 {
        (1u64 << self.count_bits) - 1
    }

    /// Predict a parent statement from canonical child values, after checking every endpoint
    /// coefficient and the integer count bounds. Circuit constraints enforce the same relation.
    pub fn compose_statement<BF: PrimeField64>(
        &self,
        left: &[BF],
        right: &[BF],
    ) -> Result<Vec<BF>, StateTransitionError> {
        self.validate_field::<BF>()?;
        for (child, values) in [left, right].into_iter().enumerate() {
            if values.len() != self.statement_schema.base_len() {
                return Err(StateTransitionError::StatementLength {
                    child,
                    expected: self.statement_schema.base_len(),
                    got: values.len(),
                });
            }
        }
        let width = self.state_width();
        for coefficient in 0..width {
            if left[width + coefficient] != right[coefficient] {
                return Err(StateTransitionError::DiscontinuousState { coefficient });
            }
        }
        let max = self.max_count();
        let counts = [
            left[2 * width].as_canonical_u64(),
            right[2 * width].as_canonical_u64(),
        ];
        for (child, count) in counts.into_iter().enumerate() {
            if count > max {
                return Err(StateTransitionError::CountOutOfRange { child, count, max });
            }
        }
        let sum = u128::from(counts[0]) + u128::from(counts[1]);
        if sum > u128::from(max) {
            return Err(StateTransitionError::CountOverflow { sum, max });
        }
        let mut output = Vec::with_capacity(self.statement_schema.base_len());
        output.extend_from_slice(&left[..width]);
        output.extend_from_slice(&right[width..2 * width]);
        output.push(BF::from_u64(sum as u64));
        Ok(output)
    }
}

#[derive(Deserialize)]
#[serde(rename = "AggregationStatementLayout")]
struct UncheckedAggregationStatementLayout {
    left: StatementSchema,
    right: StatementSchema,
    split_at: usize,
    output: StatementSchema,
}

impl<'de> Deserialize<'de> for AggregationStatementLayout {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let unchecked = UncheckedAggregationStatementLayout::deserialize(deserializer)?;
        Self::try_new(
            unchecked.left,
            unchecked.right,
            unchecked.split_at,
            unchecked.output,
        )
        .map_err(serde::de::Error::custom)
    }
}

#[derive(Deserialize)]
#[serde(rename = "StatementSchema")]
struct UncheckedStatementSchema {
    fields: Vec<StatementField>,
    base_len: usize,
}

impl<'de> Deserialize<'de> for StatementSchema {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let unchecked = UncheckedStatementSchema::deserialize(deserializer)?;
        let schema = Self::try_new(unchecked.fields).map_err(serde::de::Error::custom)?;
        if schema.base_len != unchecked.base_len {
            return Err(serde::de::Error::custom(format!(
                "statement schema base_len mismatch: expected {}, got {}",
                schema.base_len, unchecked.base_len
            )));
        }
        Ok(schema)
    }
}

impl StatementSchema {
    /// Build a schema from its ordered semantic fields, checking every flattened width.
    pub fn try_new(fields: Vec<StatementField>) -> Result<Self, StatementError> {
        let base_len = fields.iter().try_fold(0usize, |len, field| {
            let width = match field {
                StatementField::Base => 1,
                StatementField::Extension { degree: 0 } => {
                    return Err(StatementError::ZeroExtensionDegree);
                }
                StatementField::Extension { degree } => *degree,
            };
            len.checked_add(width).ok_or(StatementError::LengthOverflow)
        })?;
        Ok(Self { fields, base_len })
    }

    /// Ordered semantic fields in this statement.
    pub fn fields(&self) -> &[StatementField] {
        &self.fields
    }

    /// Number of base-field values in the flattened statement.
    pub const fn base_len(&self) -> usize {
        self.base_len
    }

    /// Concatenate two schemas without losing their semantic field boundary/order.
    pub fn concat(left: &Self, right: &Self) -> Result<Self, StatementError> {
        left.base_len
            .checked_add(right.base_len)
            .ok_or(StatementError::LengthOverflow)?;
        let mut fields = Vec::with_capacity(left.fields.len() + right.fields.len());
        fields.extend_from_slice(&left.fields);
        fields.extend_from_slice(&right.fields);
        Self::try_new(fields)
    }

    /// Check a flattened statement value vector against this schema.
    pub const fn validate_values<F>(&self, values: &[F]) -> Result<(), StatementError> {
        if values.len() != self.base_len {
            return Err(StatementError::ValueLengthMismatch {
                expected: self.base_len,
                got: values.len(),
            });
        }
        Ok(())
    }
}

impl AggregationStatementLayout {
    /// Reconstruct an ordered aggregation boundary after checking every redundant field.
    pub fn try_new(
        left: StatementSchema,
        right: StatementSchema,
        split_at: usize,
        output: StatementSchema,
    ) -> Result<Self, StatementError> {
        if split_at != left.base_len() {
            return Err(StatementError::AggregationSplitMismatch {
                expected: left.base_len(),
                got: split_at,
            });
        }
        let output_base_len = left
            .base_len()
            .checked_add(right.base_len())
            .ok_or(StatementError::LengthOverflow)?;
        let output_field_len = left
            .fields()
            .len()
            .checked_add(right.fields().len())
            .ok_or(StatementError::LengthOverflow)?;
        if output.base_len() != output_base_len
            || output.fields().len() != output_field_len
            || output.fields()[..left.fields().len()] != *left.fields()
            || output.fields()[left.fields().len()..] != *right.fields()
        {
            return Err(StatementError::AggregationOutputSchemaMismatch);
        }
        Ok(Self {
            left,
            right,
            split_at,
            output,
        })
    }

    /// Schema of the authorized left child.
    pub const fn left(&self) -> &StatementSchema {
        &self.left
    }

    /// Schema of the authorized right child.
    pub const fn right(&self) -> &StatementSchema {
        &self.right
    }

    /// Flattened base-field index at which the right child begins.
    pub const fn split_at(&self) -> usize {
        self.split_at
    }

    /// Exact ordered `left || right` output schema.
    pub const fn output(&self) -> &StatementSchema {
        &self.output
    }
}

/// Schema-level statement errors independent of a circuit's field type.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum StatementError {
    #[error("statement extension degree must be nonzero")]
    ZeroExtensionDegree,
    #[error("statement flattened length overflow")]
    LengthOverflow,
    #[error("statement value length mismatch: expected {expected}, got {got}")]
    ValueLengthMismatch { expected: usize, got: usize },
    #[error("aggregation statement split mismatch: expected {expected}, got {got}")]
    AggregationSplitMismatch { expected: usize, got: usize },
    #[error("aggregation statement output schema is not the exact ordered child concatenation")]
    AggregationOutputSchemaMismatch,
}

#[cfg(test)]
mod tests {
    use alloc::vec;
    use core::cell::Cell;

    use p3_baby_bear::BabyBear;
    use p3_field::PrimeCharacteristicRing;
    use p3_goldilocks::Goldilocks;
    use p3_koala_bear::KoalaBear;

    use super::{
        AggregationStatementLayout, StateTransitionError, StateTransitionLayout, StatementError,
        StatementField, StatementSchema,
    };

    struct SchemaNameProbe<'a>(&'a Cell<Option<&'static str>>);

    impl<'de> serde::Deserializer<'de> for SchemaNameProbe<'_> {
        type Error = serde::de::value::Error;

        fn deserialize_any<V>(self, _visitor: V) -> Result<V::Value, Self::Error>
        where
            V: serde::de::Visitor<'de>,
        {
            Err(<Self::Error as serde::de::Error>::custom(
                "schema-name probe stops before visiting fields",
            ))
        }

        fn deserialize_struct<V>(
            self,
            name: &'static str,
            _fields: &'static [&'static str],
            _visitor: V,
        ) -> Result<V::Value, Self::Error>
        where
            V: serde::de::Visitor<'de>,
        {
            self.0.set(Some(name));
            Err(<Self::Error as serde::de::Error>::custom(
                "schema-name probe stops before visiting fields",
            ))
        }

        serde::forward_to_deserialize_any! {
            bool i8 i16 i32 i64 i128 u8 u16 u32 u64 u128 f32 f64 char str string
            bytes byte_buf option unit unit_struct newtype_struct seq tuple tuple_struct map
            enum identifier ignored_any
        }
    }

    #[test]
    fn schema_deserialization_uses_its_public_type_name() {
        let observed = Cell::new(None);
        let result =
            <StatementSchema as serde::Deserialize>::deserialize(SchemaNameProbe(&observed));

        assert!(result.is_err());
        assert_eq!(observed.get(), Some("StatementSchema"));
    }

    #[test]
    fn schema_concat_preserves_fields_and_checks_flattened_values() {
        let left = StatementSchema::try_new(vec![
            StatementField::Base,
            StatementField::Extension { degree: 2 },
        ])
        .unwrap();
        let right = StatementSchema::try_new(vec![StatementField::Base]).unwrap();
        let combined = StatementSchema::concat(&left, &right).unwrap();

        assert_eq!(
            combined.fields(),
            &[
                StatementField::Base,
                StatementField::Extension { degree: 2 },
                StatementField::Base,
            ]
        );
        assert_eq!(combined.base_len(), 4);
        assert_eq!(combined.validate_values(&[1, 2, 3, 4]), Ok(()));
        assert_eq!(
            combined.validate_values(&[1, 2, 3]),
            Err(StatementError::ValueLengthMismatch {
                expected: 4,
                got: 3,
            })
        );
    }

    #[test]
    fn schema_rejects_flattened_length_overflow() {
        assert_eq!(
            StatementSchema::try_new(vec![
                StatementField::Extension { degree: usize::MAX },
                StatementField::Base,
            ]),
            Err(StatementError::LengthOverflow)
        );
    }

    #[test]
    fn aggregation_layout_retains_exact_ordered_boundary_and_output_schema() {
        let left = StatementSchema::try_new(vec![
            StatementField::Base,
            StatementField::Extension { degree: 2 },
        ])
        .unwrap();
        let right = StatementSchema::try_new(vec![StatementField::Base]).unwrap();
        let output = StatementSchema::try_new(vec![
            StatementField::Base,
            StatementField::Extension { degree: 2 },
            StatementField::Base,
        ])
        .unwrap();

        let layout =
            AggregationStatementLayout::try_new(left.clone(), right.clone(), 3, output.clone())
                .unwrap();

        assert_eq!(layout.left(), &left);
        assert_eq!(layout.right(), &right);
        assert_eq!(layout.split_at(), 3);
        assert_eq!(layout.output(), &output);
    }

    #[test]
    fn aggregation_layout_rejects_wrong_boundary_or_output_schema() {
        let left = StatementSchema::try_new(vec![StatementField::Extension { degree: 2 }]).unwrap();
        let right = StatementSchema::try_new(vec![StatementField::Base]).unwrap();
        let output = StatementSchema::try_new(vec![
            StatementField::Extension { degree: 2 },
            StatementField::Base,
        ])
        .unwrap();

        assert_eq!(
            AggregationStatementLayout::try_new(left.clone(), right.clone(), 1, output),
            Err(StatementError::AggregationSplitMismatch {
                expected: 2,
                got: 1,
            })
        );
        assert_eq!(
            AggregationStatementLayout::try_new(
                left,
                right,
                2,
                StatementSchema::try_new(vec![StatementField::Base; 3]).unwrap(),
            ),
            Err(StatementError::AggregationOutputSchemaMismatch)
        );
    }

    #[test]
    fn transition_layout_preserves_endpoint_semantics_and_composes_values() {
        let state = StatementSchema::try_new(vec![
            StatementField::Base,
            StatementField::Extension { degree: 2 },
        ])
        .unwrap();
        let layout = StateTransitionLayout::try_new(state.clone(), 4).unwrap();
        assert_eq!(layout.state_schema(), &state);
        assert_eq!(layout.statement_schema().base_len(), 7);
        assert_eq!(
            layout.statement_schema().fields(),
            &[
                StatementField::Base,
                StatementField::Extension { degree: 2 },
                StatementField::Base,
                StatementField::Extension { degree: 2 },
                StatementField::Base,
            ]
        );
        let left = [10, 20, 30, 11, 22, 33, 7].map(BabyBear::from_u32);
        let right = [11, 22, 33, 13, 26, 39, 8].map(BabyBear::from_u32);
        assert_eq!(
            layout.compose_statement(&left, &right).unwrap(),
            [10, 20, 30, 13, 26, 39, 15].map(BabyBear::from_u32)
        );
        let mut broken = right;
        broken[2] = BabyBear::from_u32(34);
        assert_eq!(
            layout.compose_statement(&left, &broken),
            Err(StateTransitionError::DiscontinuousState { coefficient: 2 })
        );
    }

    #[test]
    fn transition_layout_rejects_invalid_counts_and_shapes() {
        let schema = StatementSchema::try_new(vec![StatementField::Base]).unwrap();
        assert_eq!(
            StateTransitionLayout::try_new(StatementSchema::default(), 4),
            Err(StateTransitionError::EmptyState)
        );
        assert_eq!(
            StateTransitionLayout::try_new(schema.clone(), 0),
            Err(StateTransitionError::InvalidCountBits { bits: 0 })
        );
        let layout = StateTransitionLayout::try_new(schema, 4).unwrap();
        assert!(matches!(
            layout.compose_statement(&[BabyBear::from_u32(1)], &[]),
            Err(StateTransitionError::StatementLength { .. })
        ));
        let left = [1, 8, 8].map(BabyBear::from_u32);
        let right = [8, 9, 8].map(BabyBear::from_u32);
        assert_eq!(
            layout.compose_statement(&left, &right),
            Err(StateTransitionError::CountOverflow { sum: 16, max: 15 })
        );
        let left = [1, 8, 16].map(BabyBear::from_u32);
        assert_eq!(
            layout.compose_statement(&left, &right),
            Err(StateTransitionError::CountOutOfRange {
                child: 0,
                count: 16,
                max: 15
            })
        );
        let zero = [1, 1, 0].map(BabyBear::from_u32);
        assert_eq!(layout.compose_statement(&zero, &zero).unwrap(), zero);
    }

    #[test]
    fn transition_count_capacity_is_strictly_below_modulus() {
        let schema = StatementSchema::try_new(vec![StatementField::Base]).unwrap();
        let bb = StateTransitionLayout::try_new(schema.clone(), 29).unwrap();
        bb.validate_field::<BabyBear>().unwrap();
        bb.validate_field::<KoalaBear>().unwrap();
        let too_wide = StateTransitionLayout::try_new(schema.clone(), 30).unwrap();
        assert!(matches!(
            too_wide.validate_field::<BabyBear>(),
            Err(StateTransitionError::CountCapacityExceeded { .. })
        ));
        let gl = StateTransitionLayout::try_new(schema.clone(), 62).unwrap();
        gl.validate_field::<Goldilocks>().unwrap();
        assert!(matches!(
            StateTransitionLayout::try_new(schema, 63)
                .unwrap()
                .validate_field::<Goldilocks>(),
            Err(StateTransitionError::CountCapacityExceeded { .. })
        ));
    }
}
