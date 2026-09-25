//! [`KeccakF1600Air`] proves the circuit's Keccak-f\[1600\] calls.
//!
//! The main trace is exactly `p3-keccak-air`'s [`KeccakAir`] trace, 24 rows per call, and the
//! permutation constraints are that AIR's own. This wrapper adds the witness-bus lookups that
//! tie each call's limbs to the circuit's witness table.
//!
//! # Preprocessed columns
//!
//! Per trace row: `in_active`, `idx_0 … idx_99`, `out_mult_0 … out_mult_99`.
//!
//! - The first row of a call carries `in_active = 1` and the input limb indices.
//! - The last row of a call carries the output limb indices and their multiplicities.
//! - Every other row, and every padding row, is zero, which disables all lookups.
//!
//! # Lookups (per row, on the `WitnessChecks` bus)
//!
//! - **Send** `[idx_j, preimage limb j, 0, …]` with multiplicity `-in_active`: the call reads
//!   input limb `j`. `KeccakAir` forces the preimage to equal the round-0 state, whose limbs its
//!   bit decompositions bound below `2^16`.
//! - **Receive** `[idx_j, output limb j, 0, …]` with multiplicity `out_mult_j`: the call creates
//!   output limb `j`, the final-round state limb.
//!
//! Limb `j = 4·i + k` is limb `k` of lane `i = x + 5·y`, matching the circuit operation.

use alloc::vec;
use alloc::vec::Vec;
use core::borrow::Borrow;
use core::marker::PhantomData;

use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_circuit::ops::{
    KECCAK_LANES, KECCAK_LIMBS_PER_LANE, KECCAK_STATE_LIMBS, KeccakF1600CircuitRow,
};
use p3_field::{PrimeCharacteristicRing, PrimeField64};
use p3_keccak_air::{KeccakAir, KeccakCols, NUM_KECCAK_COLS, NUM_ROUNDS, generate_trace_rows};
use p3_lookup::{Count, InteractionBuilder};
use p3_matrix::dense::RowMajorMatrix;

/// Preprocessed values the circuit emits per call: `[active, in_idx × 100, (out_idx, out_mult) × 100]`.
pub const KECCAK_PREP_OP_WIDTH: usize = 1 + KECCAK_STATE_LIMBS + 2 * KECCAK_STATE_LIMBS;
/// Preprocessed columns per trace row: `[in_active, idx × 100, out_mult × 100]`.
pub const KECCAK_PREP_ROW_WIDTH: usize = 1 + 2 * KECCAK_STATE_LIMBS;
/// Trace rows per Keccak-f call.
pub const KECCAK_ROWS_PER_OP: usize = NUM_ROUNDS;

/// `(y, x, k)` of limb `j` in `KeccakCols`' y-major state layout.
const fn limb_position(j: usize) -> (usize, usize, usize) {
    let lane = j / KECCAK_LIMBS_PER_LANE;
    (lane / 5, lane % 5, j % KECCAK_LIMBS_PER_LANE)
}

/// AIR for the Keccak-f\[1600\] table.
#[derive(Debug, Clone)]
pub struct KeccakF1600Air<F, const D: usize> {
    /// Per-call preprocessed values, [`KECCAK_PREP_OP_WIDTH`] per call.
    pub(crate) preprocessed: Vec<F>,
    pub(crate) min_height: usize,
    _phantom: PhantomData<F>,
}

impl<F: PrimeField64, const D: usize> KeccakF1600Air<F, D> {
    /// An AIR over the given per-call preprocessed values.
    pub const fn new_with_preprocessed(preprocessed: Vec<F>, min_height: usize) -> Self {
        Self {
            preprocessed,
            min_height,
            _phantom: PhantomData,
        }
    }

    /// Calls described by the preprocessed values.
    pub const fn num_ops(&self) -> usize {
        self.preprocessed.len() / KECCAK_PREP_OP_WIDTH
    }

    /// Trace height for `num_ops` calls: a power of two holding every call, at least
    /// `min_height`.
    pub fn height_for(num_ops: usize, min_height: usize) -> usize {
        (num_ops * KECCAK_ROWS_PER_OP)
            .max(1)
            .next_power_of_two()
            .max(min_height.next_power_of_two())
    }

    /// Main trace for the given calls at exactly `height` rows.
    ///
    /// Rows past the last call run zero-input permutations, the last possibly truncated,
    /// exactly as `KeccakAir`'s own trace generation pads; their preprocessed rows are zero,
    /// so they touch no lookup.
    ///
    /// # Panics
    ///
    /// If `height` is not a power of two holding every call.
    pub fn trace_to_matrix(ops: &[KeccakF1600CircuitRow], height: usize) -> RowMajorMatrix<F> {
        assert!(height.is_power_of_two() && height >= ops.len() * KECCAK_ROWS_PER_OP);
        // `generate_trace_rows` pads to the next power of two above `24·n`; `n = height / 24`
        // whole permutations land exactly on `height` (and never fewer than the real calls).
        let num_perms = (height / KECCAK_ROWS_PER_OP).max(ops.len()).max(1);
        let mut inputs: Vec<[u64; KECCAK_LANES]> = ops.iter().map(|op| op.input).collect();
        inputs.resize(num_perms, [0; KECCAK_LANES]);
        let mut matrix = generate_trace_rows::<F>(inputs, 0);
        if matrix.values.len() > height * NUM_KECCAK_COLS {
            matrix.values.truncate(height * NUM_KECCAK_COLS);
        }
        debug_assert_eq!(matrix.values.len(), height * NUM_KECCAK_COLS);
        matrix
    }
}

impl<F: PrimeField64, const D: usize> BaseAir<F> for KeccakF1600Air<F, D> {
    fn width(&self) -> usize {
        NUM_KECCAK_COLS
    }

    fn preprocessed_width(&self) -> usize {
        KECCAK_PREP_ROW_WIDTH
    }

    fn preprocessed_trace(&self) -> Option<RowMajorMatrix<F>> {
        let height = Self::height_for(self.num_ops(), self.min_height);
        let mut values = F::zero_vec(height * KECCAK_PREP_ROW_WIDTH);
        for (op, prep) in self
            .preprocessed
            .chunks_exact(KECCAK_PREP_OP_WIDTH)
            .enumerate()
        {
            let first = op * KECCAK_ROWS_PER_OP * KECCAK_PREP_ROW_WIDTH;
            let last = first + (KECCAK_ROWS_PER_OP - 1) * KECCAK_PREP_ROW_WIDTH;
            let (active, rest) = prep.split_first().expect("a call has an active flag");
            let (in_idx, outputs) = rest.split_at(KECCAK_STATE_LIMBS);

            values[first] = *active;
            values[first + 1..first + 1 + KECCAK_STATE_LIMBS].copy_from_slice(in_idx);
            for (j, pair) in outputs.chunks_exact(2).enumerate() {
                values[last + 1 + j] = pair[0];
                values[last + 1 + KECCAK_STATE_LIMBS + j] = pair[1];
            }
        }
        Some(RowMajorMatrix::new(values, KECCAK_PREP_ROW_WIDTH))
    }

    fn preprocessed_next_row_columns(&self) -> Vec<usize> {
        vec![]
    }
}

impl<AB, const D: usize> Air<AB> for KeccakF1600Air<AB::F, D>
where
    AB: AirBuilder + InteractionBuilder,
    AB::F: PrimeField64,
{
    fn eval(&self, builder: &mut AB) {
        KeccakAir {}.eval(builder);

        let main = builder.main();
        let local: &KeccakCols<AB::Var> = main.current_slice().borrow();
        let prep = builder.preprocessed().clone();
        let prep_local = prep.current_slice();

        let in_active: AB::Expr = prep_local[0].into();
        for j in 0..KECCAK_STATE_LIMBS {
            let (y, x, k) = limb_position(j);
            let idx: AB::Expr = prep_local[1 + j].into();
            let out_mult: AB::Expr = prep_local[1 + KECCAK_STATE_LIMBS + j].into();

            let tuple = |limb: AB::Var| {
                let mut values: Vec<AB::Expr> = Vec::with_capacity(1 + D);
                values.push(idx.clone());
                values.push(limb.into());
                values.resize(1 + D, AB::Expr::ZERO);
                values
            };
            builder.push_interaction(
                "WitnessChecks",
                tuple(local.preimage[y][x][k]),
                Count::bounded(-in_active.clone(), 1),
            );
            builder.push_interaction(
                "WitnessChecks",
                tuple(local.a_prime_prime_prime(y, x, k)),
                Count::bounded(out_mult, 1),
            );
        }
    }
}
