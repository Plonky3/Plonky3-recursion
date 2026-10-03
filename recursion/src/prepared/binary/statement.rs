//! Closed statement representations used by complete binary prepared circuits.
use super::*;
use core::hash::Hash;
use p3_binary_field::{Poly64, TowerLevel};
use p3_circuit::ExprId;
use p3_circuit::ops::{BinaryPoly64Target, BinaryTower128Target};

pub(super) trait ClosedStatement<F>: Sized {
    type Target;
    fn with_limits(counts: &[usize], limits: &VerifierLimits) -> Result<Self, VerificationError>;
    fn schema(&self) -> &StatementSchema;
    fn allocate_public<BF, EF>(
        &self,
        b: &mut CircuitBuilder<EF>,
    ) -> Result<(Vec<Vec<Self::Target>>, Vec<ExprId>), VerificationError>
    where
        BF: PrimeField64,
        EF: ExtensionField<BF> + Eq + Hash;
    fn pack<OF: PrimeField64>(&self, public: &[Vec<F>]) -> Result<Vec<OF>, VerificationError>;
}

/// AIR order, public-value order, then four little-endian u16 limbs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BinaryPolyStatementLayout {
    counts: Vec<usize>,
    schema: StatementSchema,
}
impl BinaryPolyStatementLayout {
    pub fn with_limits(
        counts: &[usize],
        limits: &VerifierLimits,
    ) -> Result<Self, VerificationError> {
        let mut usage = InputResourceUsage::default();
        usage.add_instances(limits, counts.len())?;
        usage.add_metadata_entries(limits, counts.len())?;
        let fields = counts
            .iter()
            .try_fold(0usize, |total, &count| total.checked_add(count))
            .ok_or(VerificationError::ResourceArithmeticOverflow {
                component: "binary statement fields",
            })?;
        let limbs = fields
            .checked_mul(4)
            .ok_or(VerificationError::ResourceArithmeticOverflow {
                component: "binary statement limbs",
            })?;
        usage.add_scalar_elements(limits, limbs)?;
        usage.add_metadata_entries(limits, limbs)?;
        if limbs != 0 {
            usage.check_matrix_width(
                limits,
                limbs
                    .checked_add(1)
                    .ok_or(VerificationError::ResourceArithmeticOverflow {
                        component: "binary statement table width",
                    })?,
            )?;
        }
        let schema = StatementSchema::try_new(vec![StatementField::Base; limbs])
            .map_err(|error| VerificationError::InvalidProofShape(error.to_string()))?;
        Ok(Self {
            counts: counts.to_vec(),
            schema,
        })
    }

    pub fn public_value_counts(&self) -> &[usize] {
        &self.counts
    }
    pub fn schema(&self) -> &StatementSchema {
        &self.schema
    }
    pub const fn field_bits(&self) -> usize {
        64
    }

    pub fn pack<OF: PrimeField64>(
        &self,
        public: &[Vec<Poly64>],
    ) -> Result<Vec<OF>, VerificationError> {
        if public.len() != self.counts.len()
            || public
                .iter()
                .zip(&self.counts)
                .any(|(values, &count)| values.len() != count)
        {
            return Err(invalid("binary prepared public value shape mismatch"));
        }
        if OF::ORDER_U64 <= u16::MAX as u64 {
            return Err(invalid(
                "binary statement host field cannot encode u16 limbs",
            ));
        }
        Ok(public
            .iter()
            .flatten()
            .flat_map(|value| {
                let raw = value.to_repr();
                (0..4).map(move |i| OF::from_u16((raw >> (16 * i)) as u16))
            })
            .collect())
    }
}

impl<F: RecursiveBinaryTowerField> ClosedStatement<F> for BinaryStatementLayout<F> {
    type Target = BinaryTower128Target;
    fn with_limits(counts: &[usize], limits: &VerifierLimits) -> Result<Self, VerificationError> {
        Self::with_limits(counts, limits)
    }
    fn schema(&self) -> &StatementSchema {
        self.schema()
    }
    fn pack<OF: PrimeField64>(&self, public: &[Vec<F>]) -> Result<Vec<OF>, VerificationError> {
        self.pack(public)
    }
    fn allocate_public<BF, EF>(
        &self,
        b: &mut CircuitBuilder<EF>,
    ) -> Result<(Vec<Vec<Self::Target>>, Vec<ExprId>), VerificationError>
    where
        BF: PrimeField64,
        EF: ExtensionField<BF> + Eq + Hash,
    {
        let mut original_limbs = Vec::with_capacity(self.schema.base_len());
        let public = self
            .counts
            .iter()
            .map(|&count| {
                (0..count)
                    .map(|_| {
                        let limbs: [ExprId; 8] = core::array::from_fn(|_| b.public_input());
                        original_limbs.extend(limbs);
                        b.binary128_from_limbs::<BF>(limbs)
                            .map_err(VerificationError::from)
                    })
                    .collect::<Result<Vec<_>, _>>()
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok((public, original_limbs))
    }
}

impl ClosedStatement<Poly64> for BinaryPolyStatementLayout {
    type Target = BinaryPoly64Target;
    fn with_limits(counts: &[usize], limits: &VerifierLimits) -> Result<Self, VerificationError> {
        Self::with_limits(counts, limits)
    }
    fn schema(&self) -> &StatementSchema {
        self.schema()
    }
    fn pack<OF: PrimeField64>(&self, public: &[Vec<Poly64>]) -> Result<Vec<OF>, VerificationError> {
        self.pack(public)
    }
    fn allocate_public<BF, EF>(
        &self,
        b: &mut CircuitBuilder<EF>,
    ) -> Result<(Vec<Vec<Self::Target>>, Vec<ExprId>), VerificationError>
    where
        BF: PrimeField64,
        EF: ExtensionField<BF> + Eq + Hash,
    {
        let mut original_limbs = Vec::with_capacity(self.schema.base_len());
        let public = self
            .counts
            .iter()
            .map(|&count| {
                (0..count)
                    .map(|_| {
                        let limbs: [ExprId; 4] = core::array::from_fn(|_| b.public_input());
                        original_limbs.extend(limbs);
                        b.binary_poly64_from_limbs::<BF>(limbs)
                            .map_err(VerificationError::from)
                    })
                    .collect::<Result<Vec<_>, _>>()
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok((public, original_limbs))
    }
}
