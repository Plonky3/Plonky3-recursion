//! [`AddAir`] defines the AIR for proving addition and subtraction over both base and extension fields.
//!
//! Conceptually, each row of the trace encodes one or more addition constraints of the form
//!
//! ```text
//!     lhs + rhs = result
//! ```
//!
//! When the circuit wants to prove a subtraction, it is expressed as an addition by rewriting
//!
//! ```text
//!     a - b = c
//! ```
//!
//! as
//!
//! ```text
//!     b + c = a
//! ```
//!
//! so that subtraction is handled uniformly as an addition gate in the AIR.
//!
//! The AIR is generic over an extension degree `D`. Each operand and result is treated as
//! an element of an extension field of degree `D` over the base field. Internally, this is
//! represented as `D` base-field coordinates (basis coefficients), and the addition is
//! checked component-wise. The runtime parameter `lanes` controls how many independent
//! additions are packed side-by-side in a single row of the trace.
//!
//! # Column layout
//!
//! For each logical operation (lane) we allocate `3 * D + 3` base-field columns. These are
//! grouped as:
//!
//! - `D` columns for the left operand (lhs) basis coefficients,
//! - `D` columns for the right operand (rhs) basis coefficients,
//! - `D` columns for the result operand basis coefficients,
//!
//! In other words, for a single lane the layout is:
//!
//! ```text
//!     [lhs[0..D), rhs[0..D), result[0..D)]
//! ```
//!
//! We also allocate 3 preprocessed base-field columns:
//!
//! - 1 column for the lhs operand index within the `Witness` table,
//! - 1 column for the rhs operand index,
//! - 1 column for the result operand index,
//!
//! A single row can pack several of these lanes side-by-side, so the full row layout is
//! this pattern repeated `lanes` times.
//!
//! # Constraints
//!
//! Let `left[i]`, `right[i]`, and `output[i]` denote the `i`-th basis coordinate of the
//! left, right and result extension field elements respectively. For each operation and
//! each coordinate `i` in `0..D`, the AIR enforces the linear constraint
//!
//! $$
//! left[i] + right[i] - output[i] = 0.
//! $$
//!
//! Since extension addition is coordinate-wise, these constraints are sufficient to show
//! that the full extension elements satisfy
//!
//! $$
//! left + right = output.
//! $$
//!
//! # Global interactions
//!
//! Each operation (lane) has three interactions with the global witness bus:
//!
//! - send `(index_left,  left)`
//! - send `(index_right, right)`
//! - send `(index_output, result)`
//!
//! The AIR defined here focuses on the algebraic relation between the operands. The
//! correctness of the indices with respect to the global witness bus is enforced by the
//! bus interaction logic elsewhere in the system.

use alloc::string::ToString;
use alloc::vec;
use alloc::vec::Vec;
use core::iter;
use core::marker::PhantomData;

use itertools::Itertools;
use p3_air::{
    Air, AirBuilder, AirBuilderWithPublicValues, BaseAir, PairBuilder, PermutationAirBuilder,
};
use p3_circuit::tables::AddTrace;
use p3_circuit::utils::pad_to_power_of_two;
use p3_field::{BasedVectorSpace, Field, PrimeCharacteristicRing};
use p3_lookup::lookup_traits::{AirLookupHandler, Direction, Kind, Lookup};
use p3_matrix::Matrix;
use p3_matrix::dense::RowMajorMatrix;
use p3_uni_stark::SymbolicAirBuilder;

use crate::air::utils::get_index_lookups;

/// AIR for proving addition gates of the form `lhs + rhs = result`.
///
/// The type is generic over:
///
/// - `F`: the base field,
/// - `D`: the degree of the extension field; each operand is represented by `D` coordinates.
///
/// At runtime, a `lanes` parameter specifies how many addition gates are packed into each
/// trace row.
#[derive(Debug, Clone)]
pub struct AddAir<F, const D: usize = 1> {
    /// Total number of logical addition operations (gates) in the trace.
    pub num_ops: usize,
    /// Number of independent addition gates packed per trace row.
    ///
    /// The last row is padded if the number of operations is not a multiple of this value.
    pub lanes: usize,
    /// Flattened values of preprocessed columns. They are used for generating the common data,
    /// as well as by the prover, to compute the constraint polynomial.
    ///
    /// Note that the verifier does not need those values.
    /// When providing instances to the verifier, this field can be left empty.
    /// Preprocessed values correspond to the indices of the inputs and outputs within the `Witness`.
    pub preprocessed: Vec<F>,
    /// Number of lookup columns registered by this AIR so far.
    pub num_lookup_columns: usize,
    /// Marker tying this AIR to its base field.
    _phantom: PhantomData<F>,
}

impl<F: Field + PrimeCharacteristicRing, const D: usize> AddAir<F, D> {
    /// Construct a new `AddAir` instance.
    ///
    /// - `num_ops`: total number of addition operations to be proven,
    /// - `lanes`: how many operations are packed side-by-side in each row.
    ///
    /// Panics if `lanes == 0` because we always need at least one lane per row.
    pub const fn new(num_ops: usize, lanes: usize) -> Self {
        assert!(lanes > 0, "lane count must be non-zero");
        Self {
            num_ops,
            lanes,
            preprocessed: Vec::new(),
            num_lookup_columns: 0,
            _phantom: PhantomData,
        }
    }

    /// Construct a new `AddAir` instance.
    ///
    /// - `num_ops`: total number of addition operations to be proven,
    /// - `lanes`: how many operations are packed side-by-side in each row.
    ///
    /// Panics if `lanes == 0` because we always need at least one lane per row.
    pub const fn new_with_preprocessed(num_ops: usize, lanes: usize, preprocessed: Vec<F>) -> Self {
        assert!(lanes > 0, "lane count must be non-zero");
        Self {
            num_ops,
            lanes,
            preprocessed,
            num_lookup_columns: 0,
            _phantom: PhantomData,
        }
    }

    /// Number of base-field columns occupied by a single lane.
    ///
    /// Each lane stores:
    /// - `3 * D` coordinates (for `lhs`, `rhs`, and `result`),
    ///
    /// The total width of a single row is `3 * D`
    pub const fn lane_width() -> usize {
        3 * D
    }

    /// Total number of columns in the main trace for this AIR instance.
    pub const fn total_width(&self) -> usize {
        self.lanes * Self::lane_width()
    }

    /// Number of preprocessed base-field columns occupied by a single lane.
    ///
    /// Each lane stores 3 indices (one for each operand), as well as the multiplicity.
    /// The multiplicity is 1 for addition operations and 0 for padding.
    pub const fn preprocessed_lane_width() -> usize {
        4
    }

    /// Number of preprocessed columns for this AIR instance.
    ///
    /// Each lane stores 3 indices (one for each operand)
    pub const fn preprocessed_width(&self) -> usize {
        self.lanes * Self::preprocessed_lane_width()
    }

    /// Number of preprocessed columns excluding the multiplicity column.
    pub const fn preprocessed_width_without_multiplicity(&self) -> usize {
        self.lanes * (Self::preprocessed_lane_width() - 1)
    }

    /// Convert an `AddTrace` into a `RowMajorMatrix` suitable for the STARK prover.
    ///
    /// This function is responsible for:
    ///
    /// 1. Taking the logical operations from the `AddTrace`:
    ///    - `lhs_values`, `rhs_values`, `result_values` (extension elements),
    ///    - `lhs_index`, `rhs_index`, `result_index` (witness-bus indices),
    /// 2. Decomposing each extension element into its `D` basis coordinates,
    /// 3. Packing `lanes` operations side-by-side in each row,
    /// 4. Padding the trace to have a power-of-two number of rows for FFT-friendly
    ///    execution by the STARK prover.
    ///
    /// The resulting matrix has:
    ///
    /// - width `= lanes * LANE_WIDTH`,
    /// - height equal to the number of rows after packing and padding.
    ///
    /// The layout within a row is:
    ///
    /// ```text
    ///     [lhs[D], lhs_idx, rhs[D], rhs_idx, result[D], result_idx] repeated `lanes` times.
    /// ```
    pub fn trace_to_matrix<ExtF: BasedVectorSpace<F>>(
        trace: &AddTrace<ExtF>,
        lanes: usize,
    ) -> RowMajorMatrix<F> {
        // Lanes must be strictly positive.
        //
        // Zero lanes would make it impossible to construct a row.
        assert!(lanes > 0, "lane count must be non-zero");

        // Per-lane width in base-field columns.
        let lane_width = Self::lane_width();
        // Total width of each row once all lanes are packed.
        let width = lane_width * lanes;
        // Number of logical operations we need to pack into the trace.
        let op_count = trace.lhs_values.len();
        // Number of rows needed to hold `op_count` operations when each row carries `lanes` of them.
        let row_count = op_count.div_ceil(lanes);

        // Pre-allocate the entire trace as a flat vector in row-major order.
        //
        // We start with `row_count` rows, each of width `width`, and fill it with zeros.
        // This automatically provides a clean padding for any unused lanes in the final row.
        let mut values = F::zero_vec(width * row_count.max(1));

        // Iterate over all operations in lockstep across the trace arrays.
        for (op_idx, ((lhs_val, rhs_val), res_val)) in trace
            .lhs_values
            .iter()
            .zip(trace.rhs_values.iter())
            .zip(trace.result_values.iter())
            .enumerate()
        {
            // Determine the target row index.
            let row = op_idx / lanes;
            // Determine which lane within that row this operation occupies.
            let lane = op_idx % lanes;

            // Compute the starting column index (cursor) for this lane within the flat vector.
            //
            // Row-major layout means:
            //   row_offset = row * width,
            //   lane_offset = lane * lane_width.
            let mut cursor = (row * width) + (lane * lane_width);

            // Write LHS coordinates and LHS witness index.
            //
            // Extract the basis coefficients of the lhs extension element.
            let lhs_coeffs = lhs_val.as_basis_coefficients_slice();
            // Sanity check: the extension degree must match the generic parameter `D`.
            assert_eq!(
                lhs_coeffs.len(),
                D,
                "Extension field degree mismatch for lhs"
            );
            // Copy the `D` lhs coordinates into the trace row.
            values[cursor..cursor + D].copy_from_slice(lhs_coeffs);
            cursor += D;

            // Write RHS coordinates and RHS witness index.
            //
            // Extract the basis coefficients of the rhs extension element.
            let rhs_coeffs = rhs_val.as_basis_coefficients_slice();
            // Sanity check: the extension degree must match the generic parameter `D`.
            assert_eq!(
                rhs_coeffs.len(),
                D,
                "Extension field degree mismatch for rhs"
            );
            // Copy the `D` rhs coordinates into the trace row.
            values[cursor..cursor + D].copy_from_slice(rhs_coeffs);
            cursor += D;

            // Write result coordinates and result witness index.
            //
            // Extract the basis coefficients of the result extension element.
            let res_coeffs = res_val.as_basis_coefficients_slice();
            debug_assert_eq!(
                res_coeffs.len(),
                D,
                "Extension field degree mismatch for result"
            );
            // Copy the `D` result coordinates into the trace row.
            values[cursor..cursor + D].copy_from_slice(res_coeffs);
        }

        // Pad the matrix to a power-of-two height.
        pad_to_power_of_two(&mut values, width, row_count);

        // Build the row-major matrix with the computed width.
        RowMajorMatrix::new(values, width)
    }

    pub fn trace_to_preprocessed<ExtF: BasedVectorSpace<F>>(
        trace: &AddTrace<ExtF>,
        lanes: usize,
    ) -> Vec<F> {
        let total_len = trace.lhs_index.len() * Self::preprocessed_lane_width() * lanes;
        let mut preprocessed_values = Vec::with_capacity(total_len);
        for (lhs_idx, rhs_idx, res_idx) in trace
            .lhs_index
            .iter()
            .zip(trace.rhs_index.iter())
            .zip(trace.result_index.iter())
            .map(|((l, r), o)| (l, r, o))
        {
            preprocessed_values.extend(&[
                F::from_u32(lhs_idx.0),
                F::from_u32(rhs_idx.0),
                F::from_u32(res_idx.0),
            ]);
        }

        preprocessed_values
    }
}

impl<F: Field, const D: usize> BaseAir<F> for AddAir<F, D> {
    fn width(&self) -> usize {
        self.total_width()
    }

    fn preprocessed_trace(&self) -> Option<RowMajorMatrix<F>> {
        // At this point, the preprocessed trace should be set.
        let original_height = self.num_ops.div_ceil(self.lanes);

        if original_height > 0 {
            assert!(!self.preprocessed.is_empty());
        }

        // Add the multiplicity to the preprocessed values.
        let mut preprocessed_values = self
            .preprocessed
            .iter()
            .chunks(Self::preprocessed_lane_width() - 1)
            .into_iter()
            .flat_map(|chunk| iter::once(F::ONE).chain(chunk.into_iter().cloned()))
            .collect::<Vec<F>>();

        debug_assert!(
            preprocessed_values.len() % Self::preprocessed_lane_width() == 0,
            "Preprocessed trace length mismatch for AddAir: Got {} values, expected multiple of {}",
            preprocessed_values.len(),
            Self::preprocessed_lane_width()
        );

        let padding_len =
            self.preprocessed_width() - preprocessed_values.len() % self.preprocessed_width();
        if padding_len != self.preprocessed_width() {
            preprocessed_values.extend(vec![F::ZERO; padding_len]);
        }
        pad_to_power_of_two(
            &mut preprocessed_values,
            self.preprocessed_width(),
            original_height,
        );
        Some(RowMajorMatrix::new(
            preprocessed_values,
            self.preprocessed_width(),
        ))
    }
}

impl<AB: PairBuilder, const D: usize> Air<AB> for AddAir<AB::F, D>
where
    AB::F: Field,
{
    fn eval(&self, builder: &mut AB) {
        // Access the main trace view from the builder.
        let main = builder.main();

        // Make sure that the matrix width matches what this AIR expects.
        debug_assert_eq!(main.width(), self.total_width(), "column width mismatch");

        // Get the evaluation at evaluation point `zeta`
        let local = main.row_slice(0).expect("matrix must be non-empty");
        let lane_width = Self::lane_width();

        // Iterate over the row in fixed-size chunks, each chunk describing one lane:
        //
        // [lhs[0..D), lhs_idx, rhs[0..D), rhs_idx, result[0..D), result_idx]
        for lane_data in local.chunks_exact(lane_width) {
            // First, split off the lhs block and its index:
            //
            //   lhs_and_idx = [lhs[0..D), lhs_idx]
            //   rest        = [rhs[0..D), rhs_idx, result[0..D), result_idx]
            let (lhs_slice, rest) = lane_data.split_at(D);
            // Next, split the remaining data into:
            //
            //   rhs_and_idx    = [rhs[0..D), rhs_idx]
            //   result_and_idx = [result[0..D), result_idx]
            let (rhs_slice, result_slice) = rest.split_at(D);

            // Enforce coordinate-wise addition for each basis coordinate `i` in `0..D`.
            //
            // For each `i`, we add the constraint:
            //
            //     lhs_slice[i] + rhs_slice[i] - result_slice[i] = 0.
            for ((lhs, rhs), result) in lhs_slice
                .iter()
                .zip(rhs_slice.iter())
                .zip(result_slice.iter())
            {
                // Push a single linear constraint into the builder.
                builder.assert_zero(lhs.clone() + rhs.clone() - result.clone());
            }
        }
    }
}

impl<AB: PermutationAirBuilder + PairBuilder + AirBuilderWithPublicValues, const D: usize>
    AirLookupHandler<AB> for AddAir<AB::F, D>
{
    fn add_lookup_columns(&mut self) -> Vec<usize> {
        let new_idx = self.num_lookup_columns;
        self.num_lookup_columns += 1;
        vec![new_idx]
    }

    fn get_lookups(&mut self) -> Vec<Lookup<<AB>::F>> {
        let mut lookups = Vec::new();
        self.num_lookup_columns = 0;
        let preprocessed_width = self.preprocessed_width();

        // Create symbolic air builder to access symbolic variables
        let symbolic_air_builder = SymbolicAirBuilder::<AB::F>::new(
            preprocessed_width,
            BaseAir::<AB::F>::width(self),
            0,
            0, // Here, we do not need the permutation trace
            0,
        );

        let symbolic_main = symbolic_air_builder.main();
        let symbolic_main_local = symbolic_main.row_slice(0).unwrap();

        let preprocessed = symbolic_air_builder.preprocessed();
        let preprocessed_local = preprocessed.row_slice(0).unwrap();

        for lane in 0..self.lanes {
            let lane_offset = lane * Self::lane_width();
            let preprocessed_lane_offset = lane * Self::preprocessed_lane_width();

            // There are 3 lookups per lane: lhs, rhs, result, with the same multiplicity.
            let lane_lookup_inputs = get_index_lookups::<AB, D>(
                lane_offset,
                preprocessed_lane_offset,
                3,
                &symbolic_main_local,
                &preprocessed_local,
                Direction::Send,
            );
            lookups.extend(lane_lookup_inputs.into_iter().map(|inps| {
                AirLookupHandler::<AB>::register_lookup(
                    self,
                    Kind::Global("WitnessChecks".to_string()),
                    &[inps],
                )
            }));
        }
        lookups
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec;
    use alloc::vec::Vec;

    use p3_baby_bear::BabyBear as Val;
    use p3_circuit::WitnessId;
    use p3_field::extension::BinomialExtensionField;
    use p3_uni_stark::{prove_with_preprocessed, setup_preprocessed, verify_with_preprocessed};
    use p3_util::log2_ceil_usize;

    use super::*;
    use crate::air::test_utils::build_test_config;

    #[test]
    fn prove_verify_add_base_field() {
        let n = 8;
        let lhs_values = vec![Val::from_u64(3); n];
        let rhs_values = vec![Val::from_u64(5); n];
        let result_values = vec![Val::from_u64(8); n];
        let lhs_index = vec![WitnessId(1); n];
        let rhs_index = vec![WitnessId(2); n];
        let result_index = vec![WitnessId(3); n];

        // Get preprocessed index values.
        let mut preprocessed_values = Vec::with_capacity(n * 3);
        lhs_index
            .iter()
            .zip(rhs_index.iter())
            .zip(result_index.iter())
            .for_each(|((lhs_idx, rhs_idx), result_idx)| {
                preprocessed_values.extend(&[
                    Val::from_u32(lhs_idx.0),
                    Val::from_u32(rhs_idx.0),
                    Val::from_u32(result_idx.0),
                ]);
            });

        let trace = AddTrace {
            lhs_values,
            lhs_index,
            rhs_values,
            rhs_index,
            result_values,
            result_index,
        };

        let matrix: RowMajorMatrix<Val> = AddAir::<Val, 1>::trace_to_matrix(&trace, 1);
        assert_eq!(matrix.width(), 3);

        let config = build_test_config();
        let pis: Vec<Val> = vec![];

        let air = AddAir::<Val, 1>::new_with_preprocessed(n, 1, preprocessed_values);
        let (prover_data, verifier_data) =
            setup_preprocessed(&config, &air, log2_ceil_usize(matrix.height())).unwrap();
        let proof = prove_with_preprocessed(&config, &air, matrix, &pis, Some(&prover_data));
        verify_with_preprocessed(&config, &air, &proof, &pis, Some(&verifier_data))
            .expect("verification failed");
    }

    #[test]
    fn prove_verify_add_extension_field_d4() {
        type ExtField = BinomialExtensionField<Val, 4>;
        let n = 4;

        // Build genuine degree-4 elements via explicit coefficients with ALL non-zero values:
        // a = a0 + a1 x + a2 x^2 + a3 x^3
        let lhs = ExtField::from_basis_coefficients_slice(&[
            Val::from_u64(7), // a0
            Val::from_u64(3), // a1
            Val::from_u64(4), // a2
            Val::from_u64(5), // a3
        ])
        .unwrap();

        let rhs = ExtField::from_basis_coefficients_slice(&[
            Val::from_u64(11), // b0
            Val::from_u64(2),  // b1
            Val::from_u64(9),  // b2
            Val::from_u64(6),  // b3
        ])
        .unwrap();

        let result = lhs + rhs;

        // Sanity: basis length is D
        assert_eq!(
            <ExtField as BasedVectorSpace<Val>>::as_basis_coefficients_slice(&lhs).len(),
            4
        );

        let lhs_values = vec![lhs; n];
        let rhs_values = vec![rhs; n];
        let result_values = vec![result; n];
        let lhs_index = vec![WitnessId(1); n];
        let rhs_index = vec![WitnessId(2); n];
        let result_index = vec![WitnessId(3); n];

        // Get preprocessed index values.
        let mut preprocessed_values = Vec::with_capacity(n * 3);
        lhs_index
            .iter()
            .zip(rhs_index.iter())
            .zip(result_index.iter())
            .for_each(|((lhs_idx, rhs_idx), result_idx)| {
                preprocessed_values.extend(&[
                    Val::from_u32(lhs_idx.0),
                    Val::from_u32(rhs_idx.0),
                    Val::from_u32(result_idx.0),
                ]);
            });

        let trace = AddTrace {
            lhs_values,
            lhs_index,
            rhs_values,
            rhs_index,
            result_values,
            result_index,
        };

        let matrix: RowMajorMatrix<Val> = AddAir::<Val, 4>::trace_to_matrix(&trace, 1);
        assert_eq!(matrix.height(), n);
        assert_eq!(matrix.width(), AddAir::<Val, 4>::lane_width());

        let config = build_test_config();
        let pis: Vec<Val> = vec![];

        let air = AddAir::<Val, 4>::new_with_preprocessed(n, 1, preprocessed_values);
        let (prover_data, verifier_data) =
            setup_preprocessed(&config, &air, log2_ceil_usize(matrix.height())).unwrap();
        let proof = prove_with_preprocessed(&config, &air, matrix, &pis, Some(&prover_data));
        verify_with_preprocessed(&config, &air, &proof, &pis, Some(&verifier_data))
            .expect("extension field verification failed");
    }

    #[test]
    fn trace_to_matrix_packs_multiple_lanes() {
        let n = 3;
        let lanes = 2;
        let lhs_values = vec![Val::from_u64(1); n];
        let rhs_values = vec![Val::from_u64(2); n];
        let result_values = vec![Val::from_u64(3); n];
        let lhs_index = vec![WitnessId(10); n];
        let rhs_index = vec![WitnessId(20); n];
        let result_index = vec![WitnessId(30); n];

        let trace = AddTrace {
            lhs_values,
            lhs_index,
            rhs_values,
            rhs_index,
            result_values,
            result_index,
        };

        let matrix: RowMajorMatrix<Val> = AddAir::<Val, 1>::trace_to_matrix(&trace, lanes);
        assert_eq!(matrix.width(), AddAir::<Val, 1>::lane_width() * lanes);
        assert_eq!(matrix.height(), 2);
    }

    #[test]
    fn test_add_air_padding() {
        let n = 5;
        let lanes = 2;
        let lhs_values = vec![Val::from_u64(3); n];
        let rhs_values = vec![Val::from_u64(5); n];
        let result_values = vec![Val::from_u64(8); n];
        let lhs_index = vec![WitnessId(1); n];
        let rhs_index = vec![WitnessId(2); n];
        let result_index = vec![WitnessId(3); n];

        // Get preprocessed index values.
        let mut preprocessed_values = Vec::with_capacity(n * 3);
        lhs_index
            .iter()
            .zip(rhs_index.iter())
            .zip(result_index.iter())
            .for_each(|((lhs_idx, rhs_idx), result_idx)| {
                preprocessed_values.extend(&[
                    Val::from_u32(lhs_idx.0),
                    Val::from_u32(rhs_idx.0),
                    Val::from_u32(result_idx.0),
                ]);
            });

        let trace = AddTrace {
            lhs_values,
            lhs_index: lhs_index.clone(),
            rhs_values,
            rhs_index: rhs_index.clone(),
            result_values,
            result_index: result_index.clone(),
        };

        let matrix: RowMajorMatrix<Val> = AddAir::<Val, 1>::trace_to_matrix(&trace, lanes);
        assert_eq!(matrix.width(), 6);

        let config = build_test_config();
        let pis: Vec<Val> = vec![];

        let air = AddAir::<Val, 1>::new_with_preprocessed(n, lanes, preprocessed_values);

        // Check the preprocessed trace has been padded correctly.
        let preprocessed_trace = air.preprocessed_trace().unwrap();
        assert_eq!(preprocessed_trace.height(), 4);

        let lane_width = AddAir::<Val, 1>::preprocessed_lane_width();
        let preprocessed_width = air.preprocessed_width();
        for i in 0..preprocessed_trace.height() {
            for j in 0..lanes {
                let lane_idx = i * lanes + j;
                if lane_idx < n {
                    assert_eq!(
                        preprocessed_trace.values[i * preprocessed_width + lane_width * j],
                        Val::ONE
                    );
                    assert_eq!(
                        preprocessed_trace.values[i * preprocessed_width + lane_width * j + 1],
                        Val::from_u32(lhs_index[lane_idx].0)
                    );
                    assert_eq!(
                        preprocessed_trace.values[i * preprocessed_width + lane_width * j + 2],
                        Val::from_u32(rhs_index[lane_idx].0)
                    );
                    assert_eq!(
                        preprocessed_trace.values[i * preprocessed_width + lane_width * j + 3],
                        Val::from_u32(result_index[lane_idx].0)
                    );
                } else {
                    assert_eq!(
                        preprocessed_trace.values[i * preprocessed_width + lane_width * j
                            ..i * preprocessed_width + lane_width * (j + 1)],
                        [Val::ZERO; 4]
                    );
                }
            }
        }

        let (prover_data, verifier_data) =
            setup_preprocessed(&config, &air, log2_ceil_usize(matrix.height())).unwrap();
        let proof = prove_with_preprocessed(&config, &air, matrix, &pis, Some(&prover_data));
        verify_with_preprocessed(&config, &air, &proof, &pis, Some(&verifier_data))
            .expect("verification failed");
    }
}
