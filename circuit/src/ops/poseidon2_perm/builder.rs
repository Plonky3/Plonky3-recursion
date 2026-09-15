//! Inherent `CircuitBuilder` methods for adding Poseidon2 permutation rows.

use alloc::format;
use alloc::string::ToString;
use alloc::vec::Vec;

use p3_field::Field;

use crate::CircuitBuilderError;
use crate::builder::CircuitBuilder;
use crate::ops::poseidon2_perm::call::{Poseidon2PermCall, Poseidon2PermCallBase};
use crate::types::{ExprId, NonPrimitiveOpId};

impl<F: Field> CircuitBuilder<F> {
    /// Add a Poseidon2 perm row (one permutation) for D>=2 extension field.
    ///
    /// Returns `(op_id, outputs)` where outputs has length `width_ext`:
    /// - `outputs[0..rate_ext]`: present if `out_ctl[i]` is true (CTL-verified)
    /// - `outputs[rate_ext..]`: present if `return_all_outputs` is true (capacity, not CTL-verified)
    pub fn add_poseidon2_perm(
        &mut self,
        call: &Poseidon2PermCall,
    ) -> Result<(NonPrimitiveOpId, Vec<Option<ExprId>>), CircuitBuilderError> {
        call.config.validate_merkle_geometry(call.merkle_path)?;
        if call.merkle_path && call.mmcs_bit.is_none() {
            return Err(CircuitBuilderError::Poseidon2MerkleMissingMmcsBit);
        }
        if !call.merkle_path && call.mmcs_bit.is_some() {
            return Err(CircuitBuilderError::Poseidon2NonMerkleWithMmcsBit);
        }

        let arity4_merkle = call.config.is_arity4_shape() && call.merkle_path;
        if arity4_merkle && call.mmcs_bit2.is_none() {
            return Err(CircuitBuilderError::Poseidon2Arity4MissingMmcsBit2);
        }
        if !arity4_merkle && call.mmcs_bit2.is_some() {
            return Err(CircuitBuilderError::Poseidon2UnexpectedMmcsBit2);
        }

        self.add_poseidon_perm_inner(
            call,
            "poseidon2_perm_out",
            "poseidon2_perm_out_capacity",
            "poseidon2_perm",
        )
    }

    /// Add a Poseidon2 perm row (one permutation) for D=1 base field.
    ///
    /// Returns `(op_id, outputs)` where outputs is `[Option<ExprId>; 16]`:
    /// - `outputs[0..8]`: present if `out_ctl[i]` is true (CTL-verified, rate elements)
    /// - `outputs[8..16]`: present if `return_all_outputs` is true (capacity, not CTL-verified)
    pub fn add_poseidon2_perm_base(
        &mut self,
        call: &Poseidon2PermCallBase,
    ) -> Result<(NonPrimitiveOpId, [Option<ExprId>; 16]), CircuitBuilderError> {
        if call.config.d() != 1 {
            return Err(CircuitBuilderError::Poseidon2ConfigMismatch {
                expected: "D=1 configuration".to_string(),
                got: format!("D={} configuration", call.config.d()),
            });
        }

        self.add_poseidon_perm_base_inner(
            call,
            "poseidon2_perm_base_out",
            "poseidon2_perm_base_out_capacity",
            "poseidon2_perm_base",
        )
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec;

    use p3_field::PrimeCharacteristicRing;
    use p3_field::extension::BinomialExtensionField;
    use p3_test_utils::baby_bear_params::BabyBear;

    use super::*;
    use crate::ops::Poseidon2Config;

    #[test]
    fn add_poseidon2_perm_rejects_w24_binary_merkle_before_row_creation() {
        type Ext4 = BinomialExtensionField<BabyBear, 4>;

        let mut builder = CircuitBuilder::<Ext4>::new();
        let zero = builder.define_const(Ext4::ZERO);
        let call = Poseidon2PermCall {
            config: Poseidon2Config::BABY_BEAR_D4_W24,
            new_start: true,
            merkle_path: true,
            mmcs_bit: Some(zero),
            mmcs_bit2: None,
            inputs: vec![Some(zero); 6],
            out_ctl: vec![true; 4],
            return_all_outputs: false,
            mmcs_index_sum: None,
            absorb_len: 0,
        };

        let Err(CircuitBuilderError::Poseidon2ConfigMismatch { .. }) =
            builder.add_poseidon2_perm(&call)
        else {
            panic!("W24 binary Merkle mode must be rejected before row creation");
        };
    }

    #[test]
    fn add_mmcs_verify_rejects_w24_binary_merkle_path_before_execution() {
        type Ext4 = BinomialExtensionField<BabyBear, 4>;

        let mut builder = CircuitBuilder::<Ext4>::new();
        let zero = builder.define_const(Ext4::ZERO);
        let openings = vec![vec![zero; 4], vec![zero; 4]];
        let directions = vec![zero];
        let root = vec![zero; 4];

        let Err(CircuitBuilderError::Poseidon2ConfigMismatch { .. }) = builder.add_mmcs_verify(
            Poseidon2Config::BABY_BEAR_D4_W24,
            &openings,
            &directions,
            &root,
        ) else {
            panic!("W24 binary MMCS must return a configuration error");
        };
    }
}
