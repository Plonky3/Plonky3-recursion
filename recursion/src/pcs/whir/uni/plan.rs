//! Stacked-layout geometry for a WHIR commitment holding several tables.
//!
//! A WHIR commitment stacks every committed column into one multilinear
//! polynomial: each column occupies a contiguous slot of `2^arity` hypercube
//! points, addressed by a boolean selector prefix. Prover and verifier must
//! agree on that assignment bit for bit; this module reproduces the assignment
//! so the recursive verifier can emit the selector bits as circuit constants.

use alloc::vec::Vec;

use p3_util::log2_ceil_usize;

/// Boolean prefix addressing one column's slot in the stacked polynomial.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StackedSelector {
    /// Number of selector bits, i.e. stacked arity minus the table's arity.
    pub num_variables: usize,
    /// Slot index, read as a `num_variables`-bit integer.
    pub index: usize,
}

impl StackedSelector {
    /// Prefixes `local` with this selector's bits, big-endian.
    ///
    /// Bit `num_variables - 1 - i` of `index` lands at output coordinate `i`,
    /// matching `p3_multilinear_util::point::Point::hypercube`.
    pub fn lift_prefix<F: Clone>(&self, local: &[F], zero: F, one: F) -> Vec<F> {
        let mut out = Vec::with_capacity(self.num_variables + local.len());
        for i in 0..self.num_variables {
            let bit = (self.index >> (self.num_variables - 1 - i)) & 1 == 1;
            out.push(if bit { one.clone() } else { zero.clone() });
        }
        out.extend_from_slice(local);
        out
    }
}

/// One source table's slots inside the stacked polynomial.
#[derive(Clone, Debug)]
pub struct StackedPlacement {
    /// Index of the source table this placement describes.
    pub table_idx: usize,
    /// One selector per column, in source-column order.
    pub selectors: Vec<StackedSelector>,
}

/// The full stacked-layout assignment for a set of tables.
#[derive(Clone, Debug)]
pub struct StackedPlan {
    /// Arity of the stacked polynomial.
    pub num_variables: usize,
    /// Placements in layout order: largest table first.
    pub placements: Vec<StackedPlacement>,
}

/// Arity a table of `2^log_height` rows occupies once normalised to the
/// protocol's preprocessing depth.
///
/// A table shorter than the first round's folding factor is zero-padded up to
/// it. Zero-padding a coefficient vector leaves the underlying univariate
/// polynomial unchanged, so the padding is transparent to opening claims.
pub const fn padded_arity(log_height: usize, folding: usize) -> usize {
    if log_height > folding {
        log_height
    } else {
        folding
    }
}

impl StackedPlan {
    /// Plans the layout for `shapes`, each entry a `(padded arity, width)` pair.
    ///
    /// Tables are sorted by arity ascending and placed in reverse, so the
    /// largest land at the lowest slots; each column claims one contiguous
    /// slot of `2^arity` points.
    pub fn new(shapes: &[(usize, usize)]) -> Self {
        let mut order: Vec<usize> = (0..shapes.len()).collect();
        order.sort_by_key(|&i| shapes[i].0);

        let num_variables = log2_ceil_usize(
            shapes
                .iter()
                .map(|&(arity, width)| width * (1usize << arity))
                .sum::<usize>(),
        );

        let mut offset = 0usize;
        let mut placements = Vec::with_capacity(shapes.len());
        for &table_idx in order.iter().rev() {
            let (arity, width) = shapes[table_idx];
            let slot_size = 1usize << arity;
            let selectors = (0..width)
                .map(|_| {
                    let selector = StackedSelector {
                        num_variables: num_variables - arity,
                        index: offset >> arity,
                    };
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
    /// # Panics
    /// Panics if no placement carries that table index.
    pub fn table_num_variables(&self, table_idx: usize) -> usize {
        let placement = self
            .placements
            .iter()
            .find(|p| p.table_idx == table_idx)
            .expect("every source table has a placement");
        self.num_variables - placement.selectors[0].num_variables
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

    use super::{StackedPlan, padded_arity};

    type F = BabyBear;

    /// Builds a `Table` whose row `j` is column `j`'s hypercube evaluations.
    fn rand_table(rng: &mut SmallRng, width: usize, arity: usize) -> Table<F> {
        Table::rand(rng, width, arity)
    }

    /// The port must agree with the native planner on the stacked arity.
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
        let witness = Witness::new(tables, folding);

        let shapes: Vec<(usize, usize)> = raw
            .iter()
            .map(|&(arity, width)| (padded_arity(arity, folding), width))
            .collect();
        let plan = StackedPlan::new(&shapes);

        assert_eq!(plan.num_variables, witness.num_variables());
    }

    /// The port must agree with the native `Verifier` on each table's arity.
    #[test]
    fn table_arity_matches_native_verifier() {
        let raw = [(4usize, 2usize), (2, 3), (5, 1)];
        let folding = 3;

        let mut rng = SmallRng::seed_from_u64(9);
        let tables: Vec<Table<F>> = raw
            .iter()
            .map(|&(arity, width)| rand_table(&mut rng, width, arity))
            .collect();
        let witness = Witness::new(tables, folding);
        let verifier: Verifier<F, F> =
            Verifier::new(&witness.table_shapes(), PrefixProver::<F, F>::strategy());

        let shapes: Vec<(usize, usize)> = raw
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

    /// The decisive check: our selectors must address the same slots the native
    /// stacking wrote into. Evaluating the stacked polynomial at
    /// `selector.lift_prefix(local)` must equal evaluating the source column at
    /// `local` — this pins bit order, slot index, and placement order at once.
    #[test]
    fn selector_lift_addresses_the_native_slot() {
        let mut rng = SmallRng::seed_from_u64(11);
        let raw = [(4usize, 2usize), (2, 3), (5, 1)];
        let folding = 3;

        let tables: Vec<Table<F>> = raw
            .iter()
            .map(|&(arity, width)| rand_table(&mut rng, width, arity))
            .collect();
        let witness = Witness::new(tables.clone(), folding);
        let stacked: &Poly<F> = witness.poly();

        let shapes: Vec<(usize, usize)> = raw
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
                // it to the padded arity exactly as `Witness::new` does.
                let mut padded: Vec<F> = table.poly(col).as_slice().to_vec();
                padded.resize(1usize << arity, F::ZERO);
                let want = Poly::new(padded).eval_base::<F>(&Point::new(local));
                assert_eq!(got, want, "table {} col {col}", placement.table_idx);
            }
        }
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
