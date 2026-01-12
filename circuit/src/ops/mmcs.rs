use alloc::string::ToString;
use alloc::vec::Vec;
use alloc::{format, vec};
use core::cmp::Reverse;
use core::hash::Hash;
use core::ops::Range;

use itertools::Itertools;
use p3_field::{ExtensionField, Field};
use p3_matrix::Dimensions;

use crate::builder::{CircuitBuilder, CircuitBuilderError};
use crate::op::{NonPrimitiveOpType, Poseidon2Config};
use crate::ops::Poseidon2PermCall;
use crate::ops::poseidon2_perm::Poseidon2PermOps;
use crate::types::ExprId;
use crate::{CircuitError, NonPrimitiveOpId};

/// Configuration parameters for Mmcs verification operations. When
/// `base_field_digest_elems > ext_field_digest_elems`, we say the configuration
/// is packing digests into extension field elements.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct MmcsVerifyConfig {
    /// The operation type (should be NonPrimitiveOpType::Poseidon2Perm).
    pub op_type: NonPrimitiveOpType,
    /// The number of base field elements required for representing a digest.
    pub base_field_digest_elems: usize,
    /// The number of extension field elements required for representing a digest.
    pub ext_field_digest_elems: usize,
    /// The maximum height of the mmcs
    pub max_tree_height: usize,
}

impl MmcsVerifyConfig {
    /// Returns the range in which valid number of inputs lie. The minimum is 3,
    /// a single leaf, a vector of directions, and a root, or self.max_tree_height leaves
    /// and a vector of directions and root.
    pub const fn input_size(&self) -> Range<usize> {
        3..self.max_tree_height + 2 + 1
    }

    /// Returns the number of inputs (witness elements) received.
    pub const fn leaves_size(&self) -> Range<usize> {
        // `ext_field_digest_elems` for the leaf and root and 1 for the index
        self.directions_size()
    }

    pub const fn directions_size(&self) -> Range<usize> {
        1..self.max_tree_height + 1
    }

    pub const fn root_size(&self) -> usize {
        self.ext_field_digest_elems
    }

    /// MMCS verify is an assert-only op and does not produce outputs.
    pub const fn output_size(&self) -> usize {
        0
    }

    /// Convert a digest represented as extension field elements into base field elements.
    pub fn ext_to_base<F, EF, const DIGEST_ELEMS: usize>(
        &self,
        digest: &[EF],
    ) -> Result<[F; DIGEST_ELEMS], CircuitError>
    where
        F: Field,
        EF: ExtensionField<F> + Clone,
    {
        // Ensure the number of extension limbs matches the configuration.
        if digest.len() != self.ext_field_digest_elems {
            return Err(CircuitError::IncorrectNonPrimitiveOpPrivateDataSize {
                op: self.op_type,
                expected: self.ext_field_digest_elems.to_string(),
                got: digest.len(),
            });
        }

        let flattened: Vec<F> = digest
            .iter()
            .flat_map(|limb| {
                if self.is_packing() {
                    limb.as_basis_coefficients_slice()
                } else {
                    &limb.as_basis_coefficients_slice()[0..1]
                }
            })
            .copied()
            .collect();

        // Ensure the flattened base representation matches the expected compile-time size.
        let len = flattened.len();
        let arr: [F; DIGEST_ELEMS] = flattened.try_into().map_err(|_| {
            CircuitError::IncorrectNonPrimitiveOpPrivateDataSize {
                op: self.op_type,
                expected: DIGEST_ELEMS.to_string(),
                got: len,
            }
        })?;
        // Sanity check that runtime config aligns with compile-time expectations.
        debug_assert!(
            (!self.is_packing() && DIGEST_ELEMS == self.ext_field_digest_elems)
                || (self.is_packing()
                    && DIGEST_ELEMS == self.ext_field_digest_elems * EF::DIMENSION),
            "Config/base length mismatch (packing or EF::DIMENSION?)",
        );
        Ok(arr)
    }

    /// Convert a digest represented as base field elements into extension field elements.
    pub fn base_to_ext<F, EF>(&self, digest: &[F]) -> Result<Vec<EF>, CircuitError>
    where
        F: Field,
        EF: ExtensionField<F> + Clone,
    {
        if digest.len() != self.base_field_digest_elems {
            return Err(CircuitError::IncorrectNonPrimitiveOpPrivateDataSize {
                op: self.op_type,
                expected: self.base_field_digest_elems.to_string(),
                got: digest.len(),
            });
        }
        if self.is_packing() {
            // Validate divisibility and config alignment with EF::DIMENSION
            if !self.base_field_digest_elems.is_multiple_of(EF::DIMENSION)
                || self.ext_field_digest_elems * EF::DIMENSION != self.base_field_digest_elems
            {
                return Err(CircuitError::InvalidNonPrimitiveOpConfiguration { op: self.op_type });
            }
            Ok(digest
                .chunks(EF::DIMENSION)
                .map(|v| {
                    // Safe due to the checks above
                    EF::from_basis_coefficients_slice(v).expect("chunk size equals EF::DIMENSION")
                })
                .collect())
        } else {
            Ok(digest.iter().map(|&x| EF::from(x)).collect())
        }
    }

    /// Given a vector with the openings and dimesions it formats the openings
    /// into a vec of size `max_height`, where each entry contains the openings
    /// corresponding to that height. Openigns for for heights that do not exist
    /// in the input are empty vectors.
    pub fn format_openings<T: Clone + alloc::fmt::Debug>(
        &self,
        openings: &[Vec<T>],
        dimensions: &[Dimensions],
        max_height_log: usize,
    ) -> Result<Vec<Vec<T>>, CircuitError> {
        if openings.len() > 1 << max_height_log {
            return Err(CircuitError::IncorrectNonPrimitiveOpPrivateDataSize {
                op: self.op_type,
                expected: format!("at most {}", max_height_log),
                got: openings.len(),
            });
        }

        let mut heights_tallest_first = dimensions
            .iter()
            .enumerate()
            .sorted_by_key(|(_, dims)| Reverse(dims.height))
            .peekable();

        // Matrix heights that round up to the same power of two must be equal
        if !heights_tallest_first
            .clone()
            .map(|(_, dims)| dims.height)
            .tuple_windows()
            .all(|(curr, next)| {
                curr == next || curr.next_power_of_two() != next.next_power_of_two()
            })
        {
            panic!("Heights that round up to the same power of two must be equal"); //TODO: Add errors
        }

        let mut formatted_openings = vec![vec![]; max_height_log];
        for (curr_height, opening) in formatted_openings
            .iter_mut()
            .enumerate()
            .map(|(i, leaf)| (1 << (max_height_log - i), leaf))
        {
            // Get the initial height padded to a power of two. As heights_tallest_first is sorted,
            // the initial height will be the maximum height.
            // Returns an error if either:
            //              1. proof.len() != log_max_height
            //              2. heights_tallest_first is empty.
            let new_opening = heights_tallest_first
                .peeking_take_while(|(_, dims)| dims.height.next_power_of_two() == curr_height)
                .flat_map(|(i, _)| openings[i].clone())
                .collect();
            *opening = new_opening;
        }
        Ok(formatted_openings)
    }

    pub const fn mock_config() -> Self {
        Self {
            op_type: NonPrimitiveOpType::Poseidon2Perm(Poseidon2Config::BabyBearD4Width16),
            base_field_digest_elems: 1,
            ext_field_digest_elems: 1,
            max_tree_height: 1,
        }
    }

    pub const fn babybear_default() -> Self {
        Self {
            op_type: NonPrimitiveOpType::Poseidon2Perm(Poseidon2Config::BabyBearD4Width16),
            base_field_digest_elems: 8,
            ext_field_digest_elems: 8,
            max_tree_height: 32,
        }
    }

    // TODO: For now we are not considering packed inputs for BabyBear.
    pub const fn babybear_quartic_extension_default() -> Self {
        let packing = false;
        Self {
            op_type: NonPrimitiveOpType::Poseidon2Perm(Poseidon2Config::BabyBearD4Width16),
            base_field_digest_elems: 8,
            ext_field_digest_elems: if packing { 2 } else { 8 },
            max_tree_height: 32,
        }
    }

    pub const fn koalabear_default() -> Self {
        Self {
            op_type: NonPrimitiveOpType::Poseidon2Perm(Poseidon2Config::KoalaBearD4Width16),
            base_field_digest_elems: 8,
            ext_field_digest_elems: 8,
            max_tree_height: 32,
        }
    }

    // TODO: For now we are not considering packed inputs for KoalaBear.
    pub const fn koalabear_quartic_extension_default() -> Self {
        let packing = false;
        Self {
            op_type: NonPrimitiveOpType::Poseidon2Perm(Poseidon2Config::KoalaBearD4Width16),
            base_field_digest_elems: 8,
            ext_field_digest_elems: if packing { 2 } else { 8 },
            max_tree_height: 32,
        }
    }

    // TODO: Add support for Goldilocks.

    // pub const fn goldilocks_default() -> Self {
    //     Self {
    //         op_type: NonPrimitiveOpType::Poseidon2Perm(Poseidon2Config::GoldilocksD2Width8),
    //         base_field_digest_elems: 4,
    //         ext_field_digest_elems: 4,
    //         max_tree_height: 32,
    //     }
    // }

    // // TODO: For now we are not considering packed inputs for Goldilocks.
    // pub const fn goldilocks_quadratic_extension_default() -> Self {
    //     let packing = false;
    //     Self {
    //         op_type: NonPrimitiveOpType::Poseidon2Perm(Poseidon2Config::GoldilocksD2Width8),
    //         base_field_digest_elems: 4,
    //         ext_field_digest_elems: if packing { 1 } else { 4 },
    //         max_tree_height: 32,
    //     }
    // }

    /// Returns whether digests are packed into extension field elements or not.
    pub const fn is_packing(&self) -> bool {
        self.base_field_digest_elems > self.ext_field_digest_elems
    }
}

pub fn add_mmcs_verify<F: Field>(
    builder: &mut CircuitBuilder<F>,
    permutation_config: Poseidon2Config,
    openings_expr: &[Vec<ExprId>],
    directions_expr: &[ExprId],
    root_expr: &[ExprId],
) -> Result<Vec<NonPrimitiveOpId>, CircuitBuilderError> {
    // We return only the operations that require private data.
    let mut op_ids = Vec::with_capacity(openings_expr.len());
    let mut output = [None, None];
    for (i, (row_digest, direction)) in openings_expr.iter().zip(directions_expr).enumerate() {
        let is_first = i == 0;
        let is_last = i == directions_expr.len() - 1;
        let (op_id, maybe_output) = builder.add_poseidon2_perm(Poseidon2PermCall {
            config: permutation_config,
            new_start: is_first,
            merkle_path: true,
            mmcs_bit: Some(*direction),
            inputs: if is_first {
                [Some(row_digest[0]), Some(row_digest[0]), None, None]
            } else {
                [None, None, None, None]
            },
            out_ctl: [is_last, is_last],
            mmcs_index_sum: None,
        })?;
        op_ids.push(op_id);
        output = maybe_output;
        // Check if there's an extra row at this leve
        if !is_first && !row_digest.is_empty() {
            let _ = builder.add_poseidon2_perm(Poseidon2PermCall {
                config: permutation_config,
                new_start: false,
                merkle_path: true,
                mmcs_bit: None,
                inputs: [None, None, Some(row_digest[0]), Some(row_digest[1])],
                out_ctl: [false, false],
                mmcs_index_sum: None,
            })?;
        }
    }
    let output = output
        .into_iter()
        .map(|x| {
            x.ok_or_else(|| CircuitBuilderError::MalformedNonPrimitiveOutputs {
                op_id: *op_ids.last().unwrap(),
                details: "Expected output from last Poseidon2Perm call".to_string(),
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    builder.connect(output[0], root_expr[0]);
    builder.connect(output[1], root_expr[1]);
    Ok(op_ids)
}
