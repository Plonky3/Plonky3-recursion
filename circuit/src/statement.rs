use alloc::format;
use alloc::vec::Vec;

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
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct StatementSchema {
    fields: Vec<StatementField>,
    base_len: usize,
}

#[derive(Deserialize)]
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
        let schema = Self::new(unchecked.fields).map_err(serde::de::Error::custom)?;
        if schema.base_len != unchecked.base_len {
            return Err(serde::de::Error::custom(format!(
                "statement schema base_len mismatch: expected {}, got {}",
                schema.base_len, unchecked.base_len
            )));
        }
        Ok(schema)
    }
}

impl Default for StatementSchema {
    fn default() -> Self {
        Self {
            fields: Vec::new(),
            base_len: 0,
        }
    }
}

impl StatementSchema {
    pub(crate) fn new(fields: Vec<StatementField>) -> Result<Self, StatementError> {
        let base_len = fields.iter().try_fold(0usize, |len, field| {
            let width = match field {
                StatementField::Base => 1,
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
        Self::new(fields)
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

/// Schema-level statement errors independent of a circuit's field type.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum StatementError {
    #[error("statement flattened length overflow")]
    LengthOverflow,
    #[error("statement value length mismatch: expected {expected}, got {got}")]
    ValueLengthMismatch { expected: usize, got: usize },
}

#[cfg(test)]
mod tests {
    use alloc::vec;

    use super::{StatementError, StatementField, StatementSchema};

    #[test]
    fn schema_concat_preserves_fields_and_checks_flattened_values() {
        let left = StatementSchema::new(vec![
            StatementField::Base,
            StatementField::Extension { degree: 2 },
        ])
        .unwrap();
        let right = StatementSchema::new(vec![StatementField::Base]).unwrap();
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
            StatementSchema::new(vec![
                StatementField::Extension { degree: usize::MAX },
                StatementField::Base,
            ]),
            Err(StatementError::LengthOverflow)
        );
    }
}
