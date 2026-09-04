//! Stacked-layout geometry for a WHIR commitment holding several tables.
//!
//! A WHIR commitment stacks every committed column into one multilinear
//! polynomial: each column occupies a contiguous slot of `2^arity` hypercube
//! points, addressed by a boolean selector. Prover and verifier must agree on
//! that assignment bit for bit; this module reproduces the assignment so the
//! recursive verifier can emit the selector bits as circuit constants.
//!
//! # Layout mode
//!
//! `p3_sumcheck::layout` supports two stacking modes: `SuffixProver`
//! (`Witness::new`, selector bits unreversed and prepended before the local
//! point) and `PrefixProver` (`Witness::new_interleaved`, selector bits
//! bit-reversed and appended after the local point). Every consumer of this
//! module targets `PrefixProver`, so [`StackedPlan::new`] stores each
//! selector's index already bit-reversed, and [`StackedSelector::lift_prefix`]
//! appends those bits as a suffix of the local point — mirroring what
//! `Verifier::constraint` calls (`Selector::lift_suffix`) whenever
//! `LayoutStrategy::reverse_selectors` is set, which `PrefixProver::strategy()`
//! sets. The method keeps the name `lift_prefix` to match its call sites;
//! "prefix" names the residual sumcheck's prefix-first variable-binding
//! order, not the selector's position within the point.

use alloc::vec::Vec;

use p3_util::{log2_ceil_usize, reverse_bits_len};

/// A table's arity after normalising to the protocol's preprocessing depth.
///
/// Can only be constructed through [`padded_arity`], so a caller cannot pass
/// [`StackedPlan::new`] a raw, unpadded arity by mistake.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PaddedArity(usize);

impl PaddedArity {
    /// Returns the padded arity as a plain integer.
    pub const fn get(self) -> usize {
        self.0
    }
}

/// Arity a table of `2^log_height` rows occupies once normalised to the
/// protocol's preprocessing depth.
///
/// A table shorter than the first round's folding factor is zero-padded up to
/// it, exactly as `Table::pad_zeros` does before stacking (both `Witness::new`
/// and `Witness::new_interleaved` apply it). Zero-extending a hypercube
/// evaluation table changes which multilinear polynomial it represents — the
/// guarantee this function provides is only that prover and verifier derive
/// the identical padded arity from the same `(log_height, folding)` inputs,
/// since both sides apply this same normalisation.
pub const fn padded_arity(log_height: usize, folding: usize) -> PaddedArity {
    PaddedArity(if log_height > folding {
        log_height
    } else {
        folding
    })
}

/// Boolean selector addressing one column's slot in the stacked polynomial.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StackedSelector {
    /// Number of selector bits, i.e. stacked arity minus the table's arity.
    pub num_variables: usize,
    /// Slot index, read as a `num_variables`-bit integer, already bit-reversed
    /// relative to the raw placement offset (see the module docs).
    pub index: usize,
}

impl StackedSelector {
    /// Builds a selector over `num_variables` bits pointing at slot `index`.
    ///
    /// # Panics
    /// Panics if `index` does not fit in `num_variables` bits.
    pub const fn new(num_variables: usize, index: usize) -> Self {
        assert!(
            index < (1 << num_variables),
            "selector index out of range for its bit-width"
        );
        Self {
            num_variables,
            index,
        }
    }

    /// Lifts `local` into the full stacked-point space by appending this
    /// selector's boolean bits after it, big-endian.
    ///
    /// Bit `num_variables - 1 - i` of `index` lands at output coordinate
    /// `local.len() + i`, matching
    /// `p3_multilinear_util::point::Point::hypercube`.
    pub fn lift_prefix<F: Clone>(&self, local: &[F], zero: F, one: F) -> Vec<F> {
        let mut out = Vec::with_capacity(local.len() + self.num_variables);
        out.extend_from_slice(local);
        for i in 0..self.num_variables {
            let bit = (self.index >> (self.num_variables - 1 - i)) & 1 == 1;
            out.push(if bit { one.clone() } else { zero.clone() });
        }
        out
    }
}

/// One source table's slots inside the stacked polynomial.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StackedPlacement {
    /// Index of the source table this placement describes.
    pub table_idx: usize,
    /// One selector per column, in source-column order.
    pub selectors: Vec<StackedSelector>,
}

/// The full stacked-layout assignment for a set of tables.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StackedPlan {
    /// Arity of the stacked polynomial.
    pub num_variables: usize,
    /// Placements in layout order: largest table first.
    pub placements: Vec<StackedPlacement>,
}

impl StackedPlan {
    /// Plans the layout for `shapes`, each entry a `(padded arity, width)`
    /// pair produced by [`padded_arity`].
    ///
    /// Tables are sorted by arity ascending and placed in reverse, so the
    /// largest land at the lowest offsets; each column claims one contiguous
    /// slot of `2^arity` points. Ties keep their original relative order
    /// (a stable sort), then land in reverse, so the later-indexed table of
    /// an equal-arity pair is placed first. Each selector's slot index is
    /// stored bit-reversed within its own bit-width, matching what
    /// `PrefixProver`'s native stacking does before appending it as a suffix
    /// of the local point (see [`StackedSelector::lift_prefix`]).
    pub fn new(shapes: &[(PaddedArity, usize)]) -> Self {
        let mut order: Vec<usize> = (0..shapes.len()).collect();
        order.sort_by_key(|&i| shapes[i].0.get());

        let num_variables = log2_ceil_usize(
            shapes
                .iter()
                .map(|&(arity, width)| width * (1usize << arity.get()))
                .sum::<usize>(),
        );

        let mut offset = 0usize;
        let mut placements = Vec::with_capacity(shapes.len());
        for &table_idx in order.iter().rev() {
            let (arity, width) = shapes[table_idx];
            let arity = arity.get();
            let slot_size = 1usize << arity;
            let selector_variables = num_variables - arity;
            let selectors = (0..width)
                .map(|_| {
                    let raw_index = offset >> arity;
                    let index = reverse_bits_len(raw_index, selector_variables);
                    let selector = StackedSelector::new(selector_variables, index);
                    offset += slot_size;
                    selector
                })
                .collect();
            placements.push(StackedPlacement {
                table_idx,
                selectors,
            });
        }

        Self {
            num_variables,
            placements,
        }
    }

    /// Arity of the source table at `table_idx`.
    ///
    /// Returns the full stacked arity if that table has no columns (mirrors
    /// `p3_sumcheck::layout::Verifier::num_variables_table`'s `unwrap_or(0)`
    /// fallback for an empty selector list).
    ///
    /// # Panics
    /// Panics if no placement carries that table index.
    pub fn table_num_variables(&self, table_idx: usize) -> usize {
        let placement = self
            .placements
            .iter()
            .find(|p| p.table_idx == table_idx)
            .expect("every source table has a placement");
        let selector_variables = placement
            .selectors
            .first()
            .map(|s| s.num_variables)
            .unwrap_or(0);
        self.num_variables - selector_variables
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use alloc::vec;
    use alloc::vec::Vec;

    use p3_baby_bear::BabyBear;
    use p3_field::PrimeCharacteristicRing;
    use p3_matrix::dense::RowMajorMatrix;
    use p3_multilinear_util::point::Point;
    use p3_multilinear_util::poly::Poly;
    use p3_sumcheck::layout::{Layout, PrefixProver, Table, Verifier, Witness};
    use rand::SeedableRng;
    use rand::rngs::SmallRng;

    use super::{PaddedArity, StackedPlan, padded_arity};

    type F = BabyBear;

    /// Builds a `Table` whose row `j` is column `j`'s hypercube evaluations.
    fn rand_table(rng: &mut SmallRng, width: usize, arity: usize) -> Table<F> {
        Table::rand(rng, width, arity)
    }

    /// The port must agree with the native planner on the stacked arity,
    /// under the `PrefixProver` layout mode every downstream consumer uses.
    #[test]
    fn stacked_arity_matches_native_witness() {
        let mut rng = SmallRng::seed_from_u64(7);
        // Mixed arities and widths, including a table below the folding depth.
        let raw = [(4usize, 2usize), (2, 3), (5, 1)];
        let folding = 3;

        let tables: Vec<Table<F>> = raw
            .iter()
            .map(|&(arity, width)| rand_table(&mut rng, width, arity))
            .collect();
        let witness: Witness<F> = PrefixProver::<F, F>::new_witness(tables, folding);

        let shapes: Vec<(PaddedArity, usize)> = raw
            .iter()
            .map(|&(arity, width)| (padded_arity(arity, folding), width))
            .collect();
        let plan = StackedPlan::new(&shapes);

        assert_eq!(plan.num_variables, witness.num_variables());
    }

    /// The port must agree with the native `Verifier` on each table's arity,
    /// with both sides built from the same (`PrefixProver`) layout mode.
    #[test]
    fn table_arity_matches_native_verifier() {
        let raw = [(4usize, 2usize), (2, 3), (5, 1)];
        let folding = 3;

        let mut rng = SmallRng::seed_from_u64(9);
        let tables: Vec<Table<F>> = raw
            .iter()
            .map(|&(arity, width)| rand_table(&mut rng, width, arity))
            .collect();
        let witness: Witness<F> = PrefixProver::<F, F>::new_witness(tables, folding);
        let verifier: Verifier<F, F> =
            Verifier::new(&witness.table_shapes(), PrefixProver::<F, F>::strategy());

        let shapes: Vec<(PaddedArity, usize)> = raw
            .iter()
            .map(|&(arity, width)| (padded_arity(arity, folding), width))
            .collect();
        let plan = StackedPlan::new(&shapes);

        for table_idx in 0..raw.len() {
            assert_eq!(
                plan.table_num_variables(table_idx),
                verifier.num_variables_table(table_idx),
                "table {table_idx}"
            );
        }
    }

    /// The decisive check: our selectors must address the same slots the
    /// native `PrefixProver` stacking (`Witness::new_interleaved`) wrote
    /// into. Evaluating the stacked polynomial at
    /// `selector.lift_prefix(local)` must equal evaluating the source column
    /// at `local` — this pins bit order (including the selector-index
    /// reversal), slot index, and placement order at once, against the exact
    /// layout mode every downstream consumer uses.
    #[test]
    fn selector_lift_addresses_the_native_slot() {
        let mut rng = SmallRng::seed_from_u64(11);
        let raw = [(4usize, 2usize), (2, 3), (5, 1)];
        let folding = 3;

        let tables: Vec<Table<F>> = raw
            .iter()
            .map(|&(arity, width)| rand_table(&mut rng, width, arity))
            .collect();
        let witness: Witness<F> = PrefixProver::<F, F>::new_witness(tables.clone(), folding);
        let stacked: &Poly<F> = witness.poly();

        let shapes: Vec<(PaddedArity, usize)> = raw
            .iter()
            .map(|&(arity, width)| (padded_arity(arity, folding), width))
            .collect();
        let plan = StackedPlan::new(&shapes);

        for placement in &plan.placements {
            let table = &tables[placement.table_idx];
            let arity = plan.table_num_variables(placement.table_idx);
            for (col, selector) in placement.selectors.iter().enumerate() {
                // A fixed non-boolean local point: boolean points would not
                // distinguish a wrong-but-adjacent slot from the right one.
                let local: Vec<F> = (0..arity).map(|i| F::from_u32(3 + i as u32)).collect();
                let lifted = selector.lift_prefix(&local, F::ZERO, F::ONE);

                let got = stacked.eval_base::<F>(&Point::new(lifted));
                // `Table::poly(col)` is column `col`'s evaluation table; zero-pad
                // it to the padded arity exactly as `Witness::new_interleaved` does.
                let mut padded: Vec<F> = table.poly(col).as_slice().to_vec();
                padded.resize(1usize << arity, F::ZERO);
                let want = Poly::new(padded).eval_base::<F>(&Point::new(local));
                assert_eq!(got, want, "table {} col {col}", placement.table_idx);
            }
        }
    }

    /// Equal-arity tables must tie-break by a stable sort followed by
    /// reverse placement: the later-indexed table lands first. The other
    /// fixtures all use distinct arities, so this path would otherwise go
    /// untested.
    #[test]
    fn equal_arity_ties_place_the_later_table_first() {
        let folding = 3;
        let shapes = [
            (padded_arity(3, folding), 1usize),
            (padded_arity(3, folding), 1usize),
        ];

        let plan = StackedPlan::new(&shapes);

        let order: Vec<usize> = plan.placements.iter().map(|p| p.table_idx).collect();
        assert_eq!(order, vec![1, 0]);
    }

    /// `RowMajorMatrix` sanity: a `Table` row is one polynomial.
    #[test]
    fn table_row_is_one_polynomial() {
        let values = vec![F::ONE, F::TWO, F::ZERO, F::ONE];
        let table = Table::new(RowMajorMatrix::new(values, 4));
        assert_eq!(table.num_polys(), 1);
        assert_eq!(table.num_variables(), 2);
    }
}
