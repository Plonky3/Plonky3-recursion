//! [`WitnessAir`] defines the AIR for the global witness bus used by all other circuit tables.
//!
//! Each logical witness element is stored once in this table together with its witness index.
//! The generic parameter `D` allows the AIR to handle values from an extension field of degree
//! `D` over the base field, while the runtime parameter `lanes` controls how many witness
//! elements are packed side-by-side in every row of the trace.
//!
//! # Column layout
//!
//! For each witness element (lane) we allocate `D` base-field columns, corresponding to:
//!
//! - `D` columns to store the value, where `D` is the degree extension of the used field compared to the current field
//!
//! We also allocate two preprocessing columns:
//!
//! - 1 column for the indices of the witness elements
//! - 1 column for the multiplicity at which each witness element appears in the circuit
//!
//! A single row can pack several of these lanes side-by-side, so the full row layout is
//! this pattern repeated `lanes` times:
//!
//! ```text
//!     [value[0..D), index] repeated `lanes` times.
//! ```
//!
//! The logical ordering of witnesses matches the physical ordering of lanes: lane `ℓ + 1`
//! always stores the witness with index `index_lane_ℓ + 1`, and the first lane of the next row
//! continues the same sequence. When the final row is not completely filled, unused lanes are
//! padded by repeating the last witness value and extending the index sequence.
//!
//! # Constraints
//!
//!  - In the first row, lane 0: `index = 0`.
//!  - Within a row: for every adjacent pair of lanes, `index_next - index_current - 1 = 0`.
//!  - Across rows: the index in the first lane of row `r + 1` must equal that of the last lane of row `r` plus 1.
//!
//! # Global Interactions
//!
//! This table acts as the canonical bus that other chips read from. The registers of all the other circuit
//! tables receive interactions of the form `(index, value)`, guaranteeing that they fetch
//! a value consistent with the witness bus maintained by this AIR.

use alloc::string::ToString;
use alloc::vec;
use alloc::vec::Vec;
use core::marker::PhantomData;

use p3_air::{
    Air, AirBuilder, AirBuilderWithPublicValues, BaseAir, PairBuilder, PermutationAirBuilder,
};
use p3_circuit::tables::WitnessTrace;
use p3_field::{BasedVectorSpace, Field, PrimeCharacteristicRing};
use p3_lookup::lookup_traits::{AirLookupHandler, Direction, Kind, Lookup};
use p3_matrix::Matrix;
use p3_matrix::dense::RowMajorMatrix;
use p3_uni_stark::{SymbolicAirBuilder, SymbolicExpression};

use crate::air::utils::get_index_lookups;

/// AIR enforcing a monotonically increasing witness index column for the global bus.
/// Layout per row: `[value[0..D), index]` repeated `lanes` times.
///
/// Constraints:
///  - first index (lane 0, row 0) equals 0.
///  - indices increase by 1 between consecutive lanes.
///  - index of last lane of row *r* plus 1 equals index of first lane of row *r + 1*.
#[derive(Debug, Clone)]
pub struct WitnessAir<F, const D: usize = 1> {
    /// Total number of logical witness entries (before packing into lanes).
    pub num_witnesses: usize,
    /// Number of witness entries packed side-by-side in every row.
    pub lanes: usize,
    /// Multiplicities: number of times each witness index is used in the circuit.
    pub multiplicities: Vec<F>,
    /// Number of currently registered lookup columns.
    pub num_lookup_columns: usize,
    _phantom: PhantomData<F>,
}

impl<F: Field, const D: usize> WitnessAir<F, D> {
    /// Construct a new `WitnessAir`.
    ///
    /// - `num_witnesses`: total number of logical witness entries.
    /// - `lanes`: how many witness entries are packed side-by-side in each trace row.
    /// - `multiplicities`: vector of multiplicities for each witness index. It is only used by the prover.
    pub const fn new(num_witnesses: usize, lanes: usize) -> Self {
        assert!(lanes > 0, "lane count must be non-zero");

        Self {
            num_witnesses,
            lanes,
            multiplicities: Vec::new(),
            num_lookup_columns: 0,
            _phantom: PhantomData,
        }
    }

    /// Construct a new `WitnessAir` with given multiplicities.
    ///
    /// - `num_witnesses`: total number of logical witness entries.
    /// - `lanes`: how many witness entries are packed side-by-side in each trace row.
    /// - `multiplicities`: vector of multiplicities for each witness index. It is only used by the prover.
    pub const fn new_with_preprocessed(
        num_witnesses: usize,
        lanes: usize,
        multiplicities: Vec<F>,
    ) -> Self {
        assert!(lanes > 0, "lane count must be non-zero");

        Self {
            num_witnesses,
            lanes,
            multiplicities,
            num_lookup_columns: 0,
            _phantom: PhantomData,
        }
    }

    #[inline]
    pub const fn lane_width() -> usize {
        D
    }

    #[inline]
    pub const fn total_width(&self) -> usize {
        self.lanes * Self::lane_width()
    }

    #[inline]
    pub const fn preprocessed_lane_width() -> usize {
        2
    }

    #[inline]
    pub const fn preprocessed_width(&self) -> usize {
        self.lanes * Self::preprocessed_lane_width()
    }

    /// Convert a [`WitnessTrace`] into a [`RowMajorMatrix`] suitable for the STARK prover.
    ///
    /// This function is responsible for:
    ///
    /// 1. Decomposing each witness value into its `D` base-field coordinates,
    /// 2. Packing `lanes` witnesses side-by-side per row, maintaining the natural witness order,
    /// 3. Padding the trace to have a power-of-two number of rows for FFT-friendly
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
    ///     [value[0..D), index] repeated `lanes` times.
    pub fn trace_to_matrix<ExtF: BasedVectorSpace<F>>(
        trace: &WitnessTrace<ExtF>,
        lanes: usize,
    ) -> RowMajorMatrix<F> {
        assert!(lanes > 0, "lane count must be non-zero");

        let witness_count = trace.values.len();
        assert_eq!(
            witness_count,
            trace.index.len(),
            "WitnessTrace column length mismatch"
        );
        assert!(
            witness_count > 0,
            "WitnessTrace must contain at least one witness entry"
        );

        let lane_width = Self::lane_width();
        let width = lane_width * lanes;
        let logical_rows = witness_count.div_ceil(lanes).max(1);
        let padded_rows = logical_rows.next_power_of_two();
        let total_slots = padded_rows * lanes;

        let mut values = F::zero_vec(width * padded_rows);

        // Prepare last value coefficients for padding lanes/rows.
        let last_coeffs = trace
            .values
            .last()
            .expect("non-empty trace")
            .as_basis_coefficients_slice();
        assert_eq!(
            last_coeffs.len(),
            D,
            "Extension field degree mismatch for witness value"
        );
        let last_coeffs = last_coeffs.to_vec();

        let mut next_virtual_index = trace
            .index
            .last()
            .expect("non-empty trace")
            .0
            .checked_add(1)
            .expect("witness index overflow");

        for slot in 0..total_slots {
            let row = slot / lanes;
            let lane = slot % lanes;
            let cursor = row * width + lane * lane_width;

            if slot < witness_count {
                let coeffs = trace.values[slot].as_basis_coefficients_slice();
                assert_eq!(
                    coeffs.len(),
                    D,
                    "Extension field degree mismatch for witness value"
                );
                values[cursor..cursor + D].copy_from_slice(coeffs);
            } else {
                // padding: copy last value coefficients and increment virtual index
                values[cursor..cursor + D].copy_from_slice(&last_coeffs);
                next_virtual_index = next_virtual_index
                    .checked_add(1)
                    .expect("witness index overflow");
            }
        }

        RowMajorMatrix::new(values, width)
    }
}

impl<F: Field, const D: usize> BaseAir<F> for WitnessAir<F, D> {
    fn width(&self) -> usize {
        self.total_width()
    }

    fn preprocessed_trace(&self) -> Option<RowMajorMatrix<F>> {
        debug_assert!(
            self.num_witnesses == self.multiplicities.len(),
            "Mismatch between the number of witnesses ({}) and the length of the provided multiplicities ({})",
            self.num_witnesses,
            self.multiplicities.len()
        );
        let height = (self.num_witnesses.div_ceil(self.lanes)).next_power_of_two() * self.lanes;
        let all_vals = (0..height)
            .flat_map(|i| {
                if i >= self.multiplicities.len() {
                    return vec![F::from_u32(i as u32), F::ZERO];
                }
                vec![F::from_u32(i as u32), self.multiplicities[i]]
            })
            .collect::<Vec<_>>();

        Some(RowMajorMatrix::new(
            all_vals,
            self.lanes * Self::preprocessed_lane_width(),
        ))
    }
}

impl<AB: PairBuilder, const D: usize> Air<AB> for WitnessAir<AB::F, D>
where
    AB::F: Field,
{
    fn eval(&self, builder: &mut AB) {
        let lanes = self.lanes;

        // First row: index == 0
        {
            let preprocessed = builder.preprocessed();
            let local_prep = preprocessed
                .row_slice(0)
                .expect("Preprocessed matrix should be non-empty");
            // The index is in the first preprocessed column.
            let index0 = local_prep[0].clone();
            builder.when_first_row().assert_zero(index0);
        }

        // Enforce sequential indices within each row (lanes) and across rows.
        {
            let mut b = builder.when_transition();
            let preprocessed = b.preprocessed();
            let cur_prep = preprocessed.row_slice(0).expect("non-empty");

            let nxt_prep = preprocessed.row_slice(1).expect("has next row");
            let mut prev_idx = cur_prep[0].clone();
            for lane in 1..lanes {
                // The index is in the first column of each lane's preprocessed data.
                let idx = cur_prep[lane * Self::preprocessed_lane_width()].clone();
                // between consecutive lanes in the same row: index_next - index_current - 1
                b.assert_zero(idx.clone() - prev_idx.clone() - AB::Expr::ONE);
                prev_idx = idx;
            }
            let next_first_idx = nxt_prep[0].clone();
            // between the last lane of a row and the first lane of the next row: index_next - index_current - 1
            b.assert_zero(next_first_idx - prev_idx - AB::Expr::ONE);
        }

        if self.lanes > 1 {
            let mut b = builder.when_last_row();
            let preprocessed = b.preprocessed();
            let last_prep = preprocessed.row_slice(0).expect("non-empty");
            let mut prev_idx = last_prep[0].clone();
            for lane in 1..lanes {
                let idx = last_prep[lane * Self::preprocessed_lane_width()].clone();
                // between consecutive lanes in the same row: index_next - index_current - 1
                b.assert_zero(idx.clone() - prev_idx.clone() - AB::Expr::ONE);
                prev_idx = idx;
            }
        }
    }
}

impl<AB: PermutationAirBuilder + PairBuilder + AirBuilderWithPublicValues, const D: usize>
    AirLookupHandler<AB> for WitnessAir<AB::F, D>
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

            // There is only 1 lookup per lane: the witness index and its value.
            // The multiplicity is stored in the second preprocessed column of the lane.

            let multiplicities =
                SymbolicExpression::from(preprocessed_local[preprocessed_lane_offset + 1]);

            let lane_lookup_inputs = get_index_lookups::<AB, D>(
                lane_offset,
                preprocessed_lane_offset,
                1,
                &[multiplicities],
                &symbolic_main_local,
                &preprocessed_local,
                Direction::Receive,
            );

            lookups.push(AirLookupHandler::<AB>::register_lookup(
                self,
                Kind::Global("WitnessChecks".to_string()),
                &lane_lookup_inputs[0],
            ));
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
    fn prove_verify_witness_index_monotone() {
        let n = 8usize;
        // Use D=1; values can be arbitrary (unused by constraints)
        let values: Vec<Val> = vec![Val::from_u64(123); n];
        let indices: Vec<WitnessId> = (0..n as u32).map(WitnessId).collect();
        let multiplicities: Vec<Val> = vec![Val::ONE; n];

        let trace = WitnessTrace {
            values,
            index: indices,
        };
        let matrix = WitnessAir::<Val, 1>::trace_to_matrix(&trace, 1);
        assert_eq!(matrix.height(), n);
        assert_eq!(matrix.width(), 1);

        let config = build_test_config();
        let air = WitnessAir::<Val, 1>::new_with_preprocessed(n, 1, multiplicities);
        let (prover_data, verifier_data) =
            setup_preprocessed(&config, &air, log2_ceil_usize(matrix.height())).unwrap();
        let pis: Vec<Val> = vec![];

        let proof = prove_with_preprocessed(&config, &air, matrix, &pis, Some(&prover_data));
        verify_with_preprocessed(&config, &air, &proof, &pis, Some(&verifier_data))
            .expect("verification failed");
    }

    #[test]
    fn test_witness_air_extension_field() {
        type Ext4 = BinomialExtensionField<Val, 4>;

        let a = Ext4::from_basis_coefficients_slice(&[
            Val::from_u64(1),
            Val::from_u64(2),
            Val::from_u64(3),
            Val::from_u64(4),
        ])
        .unwrap();

        let b = Ext4::from_basis_coefficients_slice(&[
            Val::from_u64(5),
            Val::from_u64(6),
            Val::from_u64(7),
            Val::from_u64(8),
        ])
        .unwrap();

        let values = vec![a, b];
        let indices = vec![WitnessId(0), WitnessId(1)];
        let multiplicities = vec![Val::from_u64(1); indices.len()];

        let trace = WitnessTrace {
            values,
            index: indices,
        };
        let matrix = WitnessAir::<Val, 4>::trace_to_matrix(&trace, 1);

        // Verify dimensions: D = 4 columns
        assert_eq!(matrix.width(), 4);
        assert_eq!(matrix.height(), 2);

        // Check first row layout: [a_coeffs[0..3], index]
        {
            let row0 = matrix.row_slice(0).unwrap();
            let a_coeffs = a.as_basis_coefficients_slice();
            assert_eq!(&row0[0..4], a_coeffs);
        }

        let config = build_test_config();
        let air = WitnessAir::<Val, 4>::new_with_preprocessed(2, 1, multiplicities);
        let (prover_data, verifier_data) =
            setup_preprocessed(&config, &air, log2_ceil_usize(matrix.height())).unwrap();

        let preprocessed_matrix = air.preprocessed_trace().unwrap();
        assert_eq!(preprocessed_matrix.height(), 2);
        let row = preprocessed_matrix.row_slice(0).unwrap();
        assert_eq!(row[0], Val::from_u64(0)); // index
        let row = preprocessed_matrix.row_slice(1).unwrap();
        assert_eq!(row[0], Val::from_u64(1)); // index

        let pis: Vec<Val> = vec![];

        let proof = prove_with_preprocessed(&config, &air, matrix, &pis, Some(&prover_data));
        verify_with_preprocessed(&config, &air, &proof, &pis, Some(&verifier_data))
            .expect("Extension field verification failed");
    }

    #[test]
    fn test_witness_air_single_element() {
        let values = vec![Val::from_u64(42)];
        let indices = vec![WitnessId(0)];

        let trace = WitnessTrace {
            values,
            index: indices,
        };
        let matrix = WitnessAir::<Val, 1>::trace_to_matrix(&trace, 1);
        let multiplicity = vec![Val::ONE; 1];

        // Should be padded to power of two
        assert!(matrix.height().is_power_of_two());
        assert_eq!(matrix.width(), 1);

        // Check the single element
        {
            let row0 = matrix.row_slice(0).unwrap();
            assert_eq!(row0[0], Val::from_u64(42)); // value
        }

        let config = build_test_config();
        let air = WitnessAir::<Val, 1>::new_with_preprocessed(1, 1, multiplicity);
        let (prover_data, verifier_data) =
            setup_preprocessed(&config, &air, log2_ceil_usize(matrix.height())).unwrap();

        let preprocessed_matrix = air.preprocessed_trace().unwrap();
        assert_eq!(preprocessed_matrix.height(), matrix.height());
        for i in 0..matrix.height() {
            let row = preprocessed_matrix.row_slice(i).unwrap();
            assert_eq!(row[0], Val::from_u64(i as u64)); // index
        }

        let pis: Vec<Val> = vec![];

        let proof = prove_with_preprocessed(&config, &air, matrix, &pis, Some(&prover_data));
        verify_with_preprocessed(&config, &air, &proof, &pis, Some(&verifier_data))
            .expect("Single element verification failed");
    }

    #[test]
    fn test_witness_air_matrix_padding() {
        let n = 3; // Not a power of two
        let values: Vec<Val> = (1..=n as u64).map(Val::from_u64).collect();
        let indices: Vec<WitnessId> = (0..n as u32).map(WitnessId).collect();
        let multiplicities: Vec<Val> = vec![Val::ONE; n];

        let trace = WitnessTrace {
            values,
            index: indices,
        };
        let matrix = WitnessAir::<Val, 1>::trace_to_matrix(&trace, 1);

        // Should be padded to next power of two (4)
        assert_eq!(matrix.height(), 4);
        assert!(matrix.height().is_power_of_two());

        // Original rows should be preserved
        for i in 0..n {
            let row = matrix.row_slice(i).unwrap();
            assert_eq!(row[0], Val::from_u64((i + 1) as u64)); // value
        }

        // Padded row should continue monotonic sequence
        {
            let last_row = matrix.row_slice(3).unwrap();
            assert_eq!(last_row[0], Val::from_u64(3)); // last value repeated
        }

        let config = build_test_config();
        let air = WitnessAir::<Val, 1>::new_with_preprocessed(3, 1, multiplicities);
        let (prover_data, verifier_data) =
            setup_preprocessed(&config, &air, log2_ceil_usize(matrix.height())).unwrap();

        let preprocessed_matrix = air.preprocessed_trace().unwrap();
        assert_eq!(preprocessed_matrix.height(), matrix.height());
        for i in 0..matrix.height() {
            let row = preprocessed_matrix.row_slice(i).unwrap();
            assert_eq!(row[0], Val::from_u64(i as u64)); // index
        }
        let pis: Vec<Val> = vec![];

        let proof = prove_with_preprocessed(&config, &air, matrix, &pis, Some(&prover_data));
        verify_with_preprocessed(&config, &air, &proof, &pis, Some(&verifier_data))
            .expect("Padding verification failed");
    }

    #[test]
    fn witness_air_multi_lane_packs_sequential_indices() {
        let values: Vec<Val> = vec![
            Val::from_u64(10),
            Val::from_u64(20),
            Val::from_u64(30),
            Val::from_u64(40),
            Val::from_u64(50),
        ];
        let multiplicities = vec![
            Val::from_u64(3),
            Val::from_u64(4),
            Val::from_u64(5),
            Val::from_u64(6),
            Val::from_u64(7),
        ];
        let indices: Vec<WitnessId> = (0..values.len() as u32).map(WitnessId).collect();
        let trace = WitnessTrace {
            values: values.clone(),
            index: indices,
        };

        let lanes = 2;
        let matrix = WitnessAir::<Val, 1>::trace_to_matrix(&trace, lanes);

        // Width doubles because each row now contains two lanes.
        assert_eq!(matrix.width(), lanes * WitnessAir::<Val, 1>::lane_width());
        // 5 witnesses -> ceil(5 / 2) = 3 logical rows -> padded to 4.
        assert_eq!(matrix.height(), 4);

        // Row 0 holds witnesses 0 and 1.
        let row0 = matrix.row_slice(0).unwrap();
        assert_eq!(row0[0], values[0]);
        assert_eq!(row0[1], values[1]);

        // Row 1 holds witnesses 2 and 3.
        let row1 = matrix.row_slice(1).unwrap();
        assert_eq!(row1[0], values[2]);
        assert_eq!(row1[1], values[3]);

        // Row 2 holds witness 4 and a virtual filler lane continuing the sequence.
        let row2 = matrix.row_slice(2).unwrap();
        assert_eq!(row2[0], values[4]);
        assert_eq!(row2[1], values[4]);

        let air = WitnessAir::<Val, 1>::new_with_preprocessed(
            values.len(),
            lanes,
            multiplicities.clone(),
        );
        let preprocessed_matrix = air.preprocessed_trace().unwrap();
        assert_eq!(preprocessed_matrix.height(), matrix.height());

        // Check that the indices and multiplicities in the preprocessed matrix are correct.
        let preprocessed_width = WitnessAir::<Val, 1>::preprocessed_lane_width();
        for i in 0..matrix.height() {
            let row = preprocessed_matrix.row_slice(i).unwrap();
            for j in 0..lanes {
                assert_eq!(
                    row[j * preprocessed_width],
                    Val::from_u64((i * lanes + j) as u64)
                );
                assert_eq!(
                    row[j * preprocessed_width + 1],
                    if i * lanes + j < values.len() {
                        multiplicities[i * lanes + j]
                    } else {
                        Val::ZERO
                    }
                );
            }
        }

        assert_eq!(air.total_width(), matrix.width());
    }
}
