//! Inherent `CircuitBuilder` methods for adding Poseidon1 permutation rows.

use alloc::format;
use alloc::string::ToString;
use alloc::vec::Vec;

use p3_field::Field;

use crate::CircuitBuilderError;
use crate::builder::CircuitBuilder;
use crate::ops::poseidon1_perm::call::{Poseidon1PermCall, Poseidon1PermCallBase};
use crate::types::{ExprId, NonPrimitiveOpId};

impl<F: Field> CircuitBuilder<F> {
    /// Add a Poseidon1 perm row (one permutation) for D>=2 extension field.
    ///
    /// Returns `(op_id, outputs)` where outputs has length `width_ext`:
    /// - `outputs[0..rate_ext]`: present if `out_ctl[i]` is true (CTL-verified)
    /// - `outputs[rate_ext..]`: present if `return_all_outputs` is true (capacity, not CTL-verified)
    pub fn add_poseidon1_perm(
        &mut self,
        call: &Poseidon1PermCall,
    ) -> Result<(NonPrimitiveOpId, Vec<Option<ExprId>>), CircuitBuilderError> {
        if call.merkle_path && call.mmcs_bit.is_none() {
            return Err(CircuitBuilderError::Poseidon1MerkleMissingMmcsBit);
        }
        if !call.merkle_path && call.mmcs_bit.is_some() {
            return Err(CircuitBuilderError::Poseidon1NonMerkleWithMmcsBit);
        }

        self.add_poseidon_perm_inner(
            call,
            "poseidon1_perm_out",
            "poseidon1_perm_out_capacity",
            "poseidon1_perm",
        )
    }

    /// Add a Poseidon1 perm row (one permutation) for D=1 base field.
    ///
    /// Returns `(op_id, outputs)` where outputs is `[Option<ExprId>; 16]`:
    /// - `outputs[0..8]`: present if `out_ctl[i]` is true (CTL-verified, rate elements)
    /// - `outputs[8..16]`: present if `return_all_outputs` is true (capacity, not CTL-verified)
    pub fn add_poseidon1_perm_base(
        &mut self,
        call: &Poseidon1PermCallBase,
    ) -> Result<(NonPrimitiveOpId, [Option<ExprId>; 16]), CircuitBuilderError> {
        if call.config.d() != 1 {
            return Err(CircuitBuilderError::Poseidon1ConfigMismatch {
                expected: "D=1 configuration".to_string(),
                got: format!("D={} configuration", call.config.d()),
            });
        }

        self.add_poseidon_perm_base_inner(
            call,
            "poseidon1_perm_base_out",
            "poseidon1_perm_base_out_capacity",
            "poseidon1_perm_base",
        )
    }
}
