use alloc::string::ToString;
use alloc::vec::Vec;
use core::iter;

use p3_field::Field;

use crate::op::Poseidon2Config;
use crate::ops::Poseidon2PermCall;
use crate::ops::poseidon2_perm::Poseidon2PermOps;
use crate::{CircuitBuilder, CircuitBuilderError, ExprId, NonPrimitiveOpId};

pub fn add_hash_squeeze<F: Field>(
    builder: &mut CircuitBuilder<F>,
    poseidon2_config: &Poseidon2Config,
    inputs: &[ExprId],
    reset: bool,
) -> Result<Vec<ExprId>, CircuitBuilderError> {
    let chunks = inputs.chunks(4);
    let last_idx = chunks.len() - 1;
    let mut outputs = [None, None];
    let mut last_op_id = NonPrimitiveOpId(0);
    for (i, input) in chunks.enumerate() {
        let is_first = i == 0;
        let is_last = i == last_idx;
        let (op_id, maybe_outputs) = builder.add_poseidon2_perm(Poseidon2PermCall {
            config: *poseidon2_config,
            new_start: if is_first { reset } else { false },
            merkle_path: false,
            mmcs_bit: None,
            inputs: input
                .iter()
                .cloned()
                .map(Some)
                .chain(iter::repeat(None))
                .take(4)
                .collect::<Vec<_>>()
                .try_into()
                .expect("We have already taken 4 elements"),
            out_ctl: [is_last, is_last],
            mmcs_index_sum: None,
        })?;
        outputs = maybe_outputs;
        last_op_id = op_id;
    }

    outputs
        .into_iter()
        .map(|o| {
            o.ok_or_else(|| CircuitBuilderError::MalformedNonPrimitiveOutputs {
                op_id: last_op_id,
                details: "".to_string(),
            })
        })
        .collect()
}
