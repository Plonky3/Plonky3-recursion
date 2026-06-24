//! Shared `CircuitBuilder` helpers for adding Poseidon permutation rows.

use alloc::vec;
use alloc::vec::Vec;

use p3_field::Field;

use super::{PoseidonConfigApi, PoseidonPermCall, PoseidonPermCallBase, PoseidonVariant};
use crate::CircuitBuilderError;
use crate::builder::CircuitBuilder;
use crate::types::{ExprId, NonPrimitiveOpId};

impl<F: Field> CircuitBuilder<F> {
    /// Shared body for the extension-mode `add_*_perm` builder methods.
    ///
    /// The caller validates the `mmcs_bit`/`merkle_path` pairing and supplies the
    /// variant-specific CTL output labels and op tag.
    pub(crate) fn add_poseidon_perm_inner<V: PoseidonVariant>(
        &mut self,
        call: &PoseidonPermCall<V>,
        out_label: &'static str,
        out_capacity_label: &'static str,
        tag: &'static str,
    ) -> Result<(NonPrimitiveOpId, Vec<Option<ExprId>>), CircuitBuilderError> {
        let op_type = V::npo_type_id(call.config);
        self.ensure_op_enabled(&op_type)?;

        let width_ext = call.config.width_ext();
        let rate_ext = call.config.rate_ext();

        let mut input_exprs: Vec<Vec<ExprId>> = Vec::with_capacity(width_ext + 2);
        for limb in &call.inputs {
            input_exprs.push(limb.map_or_else(Vec::new, |v| vec![v]));
        }
        input_exprs.push(call.mmcs_index_sum.map_or_else(Vec::new, |v| vec![v]));
        input_exprs.push(call.mmcs_bit.map_or_else(Vec::new, |v| vec![v]));

        let mut output_labels: Vec<Option<&'static str>> = Vec::with_capacity(width_ext);
        for i in 0..rate_ext {
            let expose = call.out_ctl.get(i).copied().unwrap_or(false);
            output_labels.push(expose.then_some(out_label));
        }
        for _ in rate_ext..width_ext {
            output_labels.push(call.return_all_outputs.then_some(out_capacity_label));
        }

        let (op_id, _call_expr_id, outputs) = self.push_non_primitive_op_with_outputs(
            op_type,
            input_exprs,
            output_labels,
            // Extension-field perm rows carry no sponge length tag (the ext-field challenger
            // applies prefix-free padding at the challenger level, not in the AIR).
            Some(V::perm_op_params::<F>(call.new_start, call.merkle_path, 0)),
            tag,
        );
        Ok((op_id, outputs))
    }

    /// Shared body for the D=1 base-field `add_*_perm_base` builder methods.
    ///
    /// The caller validates that the config is D=1 and supplies the
    /// variant-specific CTL output labels and op tag.
    pub(crate) fn add_poseidon_perm_base_inner<V: PoseidonVariant>(
        &mut self,
        call: &PoseidonPermCallBase<V>,
        out_label: &'static str,
        out_capacity_label: &'static str,
        tag: &'static str,
    ) -> Result<(NonPrimitiveOpId, [Option<ExprId>; 16]), CircuitBuilderError> {
        let op_type = V::npo_type_id(call.config);
        self.ensure_op_enabled(&op_type)?;

        let input_exprs: [Vec<ExprId>; 16] = call
            .inputs
            .map(|opt| opt.map_or_else(Vec::new, |v| vec![v]));

        let output_labels: [Option<&'static str>; 16] = core::array::from_fn(|i| match i {
            0..8 if call.out_ctl[i] => Some(out_label),
            8..16 if call.return_all_outputs => Some(out_capacity_label),
            _ => None,
        });

        let (op_id, _call_expr_id, outputs) = self.push_non_primitive_op_with_outputs(
            op_type,
            input_exprs.into(),
            output_labels.into(),
            Some(V::perm_op_params::<F>(
                call.new_start,
                false,
                call.absorb_len,
            )),
            tag,
        );

        let outputs: [Option<ExprId>; 16] = outputs
            .try_into()
            .expect("push_non_primitive_op_with_outputs must return exactly 16 outputs");
        Ok((op_id, outputs))
    }
}
