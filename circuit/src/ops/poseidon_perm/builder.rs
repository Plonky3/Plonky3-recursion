//! Shared `CircuitBuilder` helpers for adding Poseidon permutation rows.

use alloc::vec;
use alloc::vec::Vec;

use p3_field::Field;

use super::{PoseidonConfigApi, PoseidonPermCall, PoseidonPermCallBase, PoseidonVariant};
use crate::CircuitBuilderError;
use crate::builder::CircuitBuilder;
use crate::types::{ExprId, NonPrimitiveOpId};

/// Number of leading input lanes a chain-start row must take from the witness bus.
///
/// A non-challenger chain start begins from the zero state, which the executor reproduces for an
/// empty lane. No AIR constraint pins those lanes except the capacity of a compact D=1 sponge
/// start, so every other empty lane is fed a bus-checked zero. An arity-2 Merkle chain start
/// holds its sibling in the capacity, so only its rate is fed; challenger tables pin their own
/// chain starts.
///
/// Returns `None` for a length-tagged start on a table that neither pins its capacity nor is a
/// challenger table: the executor applies the tag to a capacity lane no constraint would bind.
fn zero_fed_start_lanes<C: PoseidonConfigApi>(
    config: C,
    new_start: bool,
    merkle_path: bool,
    absorb_len: usize,
) -> Option<usize> {
    if !new_start || config.is_challenger() {
        return Some(0);
    }
    let (d, width_ext, rate_ext) = (config.d(), config.width_ext(), config.rate_ext());
    let compact =
        p3_poseidon_circuit_cols::poseidon_uses_compact_d1_preprocessed(d, width_ext, rate_ext);
    if compact || (merkle_path && !config.is_arity4_shape()) {
        Some(rate_ext)
    } else if absorb_len > 0 {
        None
    } else {
        Some(width_ext)
    }
}

impl<F: Field> CircuitBuilder<F> {
    /// Feed a bus-checked zero to the empty lanes among the first `lanes` inputs.
    fn zero_fill_lanes(&mut self, inputs: &mut [Option<ExprId>], lanes: usize) {
        if lanes == 0 {
            return;
        }
        let zero = self.define_const(F::ZERO);
        for lane in inputs.iter_mut().take(lanes) {
            lane.get_or_insert(zero);
        }
    }

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

        let mut inputs = call.inputs.clone();
        let start_lanes = zero_fed_start_lanes(
            call.config,
            call.new_start,
            call.merkle_path,
            call.absorb_len,
        )
        .ok_or_else(|| CircuitBuilderError::InvalidNonPrimitiveOpConfiguration {
            op: op_type.clone(),
        })?;
        self.zero_fill_lanes(&mut inputs, start_lanes);

        let mut input_exprs: Vec<Vec<ExprId>> = Vec::with_capacity(width_ext + 3);
        for limb in &inputs {
            input_exprs.push(limb.map_or_else(Vec::new, |v| vec![v]));
        }
        input_exprs.push(call.mmcs_index_sum.map_or_else(Vec::new, |v| vec![v]));
        input_exprs.push(call.mmcs_bit.map_or_else(Vec::new, |v| vec![v]));
        if call.config.is_arity4_shape() && call.merkle_path {
            input_exprs.push(call.mmcs_bit2.map_or_else(Vec::new, |v| vec![v]));
        }

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
            Some(V::perm_op_params::<F>(
                call.new_start,
                call.merkle_path,
                call.absorb_len,
            )),
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

        let mut inputs = call.inputs;
        let start_lanes = zero_fed_start_lanes(call.config, call.new_start, false, call.absorb_len)
            .ok_or_else(|| CircuitBuilderError::InvalidNonPrimitiveOpConfiguration {
                op: op_type.clone(),
            })?;
        self.zero_fill_lanes(&mut inputs, start_lanes);

        let input_exprs: [Vec<ExprId>; 16] =
            inputs.map(|opt| opt.map_or_else(Vec::new, |v| vec![v]));

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
