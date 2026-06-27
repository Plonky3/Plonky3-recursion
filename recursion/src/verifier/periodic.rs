//! In-circuit evaluation of periodic columns.
//!
//! Periodic columns are verifier-recomputable AIR constants (never committed):
//! a length-`period` evaluation vector that repeats every `period` rows. The
//! verifier needs their value at the out-of-domain opening point `point`, which
//! is the native [`PolynomialSpace::evaluate_periodic_column_at`] specialized to
//! a two-adic multiplicative coset:
//!
//! ```text
//! folds      = log_n - log_period
//! sub_shift  = shift^(2^folds)
//! value      = P(point^(2^folds))
//! ```
//!
//! where `P` is the unique degree-`<period` polynomial interpolating the column
//! over the order-`period` sub-coset `sub_shift · ⟨h⟩`.
//!
//! Because the column and the sub-coset are circuit-build-time constants, `P`'s
//! monomial coefficients are constants too (an inverse coset-DFT of the column).
//! The in-circuit work is then just `folds` squarings to form `point^(2^folds)`
//! followed by a Horner evaluation over those constant coefficients — no
//! inversions, no hints.
//!
//! [`PolynomialSpace::evaluate_periodic_column_at`]: p3_commit::PolynomialSpace::evaluate_periodic_column_at

use alloc::format;
use alloc::vec::Vec;

use p3_circuit::CircuitBuilder;
use p3_dft::{Radix2Dit, TwoAdicSubgroupDft};
use p3_field::coset::TwoAdicMultiplicativeCoset;
use p3_field::{ExtensionField, TwoAdicField};
use p3_util::log2_strict_usize;

use crate::Target;
use crate::verifier::VerificationError;

/// Build the in-circuit evaluation of each periodic column at `point`.
///
/// `point` is the opening point (e.g. `zeta`); the returned targets are aligned
/// with `periodic_columns`. The result matches the native
/// [`p3_commit::PolynomialSpace::evaluate_periodic_column_at`] over `domain`.
///
/// Each column's length is validated to be a power of two not exceeding the
/// trace domain size, mirroring `check_periodic_column_lengths`. These are
/// build-time constants, so a malformed column is rejected at circuit
/// construction rather than producing an unsound gadget.
pub(crate) fn evaluate_periodic_columns_circuit<Val, Challenge>(
    circuit: &mut CircuitBuilder<Challenge>,
    domain: &TwoAdicMultiplicativeCoset<Val>,
    periodic_columns: &[Vec<Val>],
    point: Target,
) -> Result<Vec<Target>, VerificationError>
where
    Val: TwoAdicField,
    Challenge: ExtensionField<Val>,
{
    periodic_columns
        .iter()
        .map(|col| evaluate_one(circuit, domain, col, point))
        .collect()
}

/// Evaluate a single periodic column's interpolant at `point`, in-circuit.
fn evaluate_one<Val, Challenge>(
    circuit: &mut CircuitBuilder<Challenge>,
    domain: &TwoAdicMultiplicativeCoset<Val>,
    col: &[Val],
    point: Target,
) -> Result<Target, VerificationError>
where
    Val: TwoAdicField,
    Challenge: ExtensionField<Val>,
{
    let period = col.len();
    if !period.is_power_of_two() {
        return Err(VerificationError::InvalidProofShape(format!(
            "periodic column length must be a power of two, got {period}"
        )));
    }
    if period > domain.size() {
        return Err(VerificationError::InvalidProofShape(format!(
            "periodic column length {period} exceeds trace domain size {}",
            domain.size()
        )));
    }

    let log_period = log2_strict_usize(period);
    let folds = domain.log_size() - log_period;

    // Monomial coefficients (ascending) of the interpolant of `col` over the
    // order-`period` sub-coset `sub_shift · ⟨h⟩`.
    let sub_shift = domain.shift().exp_power_of_2(folds);
    let coeffs: Vec<Val> = Radix2Dit::default().coset_idft(col.to_vec(), sub_shift);

    // A period-1 column is constant: the interpolant does not depend on `point`.
    let (&leading, rest) = coeffs
        .split_last()
        .expect("a power-of-two periodic column has at least one coefficient");
    let mut acc = circuit.define_const(Challenge::from(leading));
    if rest.is_empty() {
        return Ok(acc);
    }

    // zp = point^(2^folds); evaluate `P(zp)` by Horner over the constant coeffs.
    let zp = circuit.exp_power_of_2(point, folds);
    for &c in rest.iter().rev() {
        let c_target = circuit.define_const(Challenge::from(c));
        acc = circuit.mul_add(acc, zp, c_target);
    }
    Ok(acc)
}

#[cfg(test)]
mod tests {
    use alloc::vec;
    use alloc::vec::Vec;

    use p3_baby_bear::BabyBear;
    use p3_circuit::CircuitBuilder;
    use p3_commit::PolynomialSpace;
    use p3_field::coset::TwoAdicMultiplicativeCoset;
    use p3_field::extension::BinomialExtensionField;
    use p3_field::{BasedVectorSpace, Field, PrimeCharacteristicRing};

    use super::evaluate_periodic_columns_circuit;

    type Val = BabyBear;
    type Challenge = BinomialExtensionField<BabyBear, 4>;

    /// A handful of deterministic full-extension opening points.
    fn sample_points() -> Vec<Challenge> {
        (0..4)
            .map(|i| {
                Challenge::from_basis_coefficients_fn(|j| Val::from_u64(i * 37 + j as u64 * 7 + 1))
            })
            .collect()
    }

    /// A deterministic period-length column.
    fn make_col(period: usize) -> Vec<Val> {
        (0..period)
            .map(|i| Val::from_u64((i as u64) * 11 + 3))
            .collect()
    }

    /// Run the gadget for `col` over `domain` at `point` and return whether the
    /// circuit (which asserts the gadget output equals `expected`) is satisfied.
    fn gadget_matches(
        domain: &TwoAdicMultiplicativeCoset<Val>,
        col: &[Val],
        point: Challenge,
        expected: Challenge,
    ) -> bool {
        let mut circuit = CircuitBuilder::<Challenge>::new();
        let z = circuit.public_input();
        let cols = vec![col.to_vec()];
        let outs =
            evaluate_periodic_columns_circuit::<Val, Challenge>(&mut circuit, domain, &cols, z)
                .expect("valid periodic column");
        let expected_const = circuit.define_const(expected);
        circuit.connect(outs[0], expected_const);

        let built = circuit.build().expect("build");
        let mut runner = built.runner();
        runner.set_public_inputs(&[point]).expect("set inputs");
        runner.run().is_ok()
    }

    /// The gadget reproduces the native `evaluate_periodic_column_at` bit-for-bit
    /// across periods, trace heights, coset shifts, and opening points.
    #[test]
    fn matches_native_oracle() {
        let shifts = [Val::ONE, Val::GENERATOR];
        // (log_n, period): includes period==1 (constant), period==n (folds==0),
        // and intermediate periods.
        let shapes = [(3, 1), (3, 2), (4, 4), (4, 16), (5, 8)];

        for shift in shifts {
            for (log_n, period) in shapes {
                let domain = TwoAdicMultiplicativeCoset::new(shift, log_n).unwrap();
                let col = make_col(period);
                for point in sample_points() {
                    let expected = domain.evaluate_periodic_column_at(&col, point);
                    assert!(
                        gadget_matches(&domain, &col, point, expected),
                        "gadget disagreed with native oracle (shift={shift:?}, log_n={log_n}, period={period}, point={point:?})"
                    );
                }
            }
        }
    }

    /// The equivalence check has teeth: a wrong expected value fails the circuit.
    #[test]
    fn rejects_wrong_value() {
        let domain = TwoAdicMultiplicativeCoset::new(Val::ONE, 4).unwrap();
        let col = make_col(4);
        let point = sample_points()[1];
        let expected = domain.evaluate_periodic_column_at(&col, point);
        let wrong = expected + Challenge::ONE;
        assert!(gadget_matches(&domain, &col, point, expected));
        assert!(!gadget_matches(&domain, &col, point, wrong));
    }

    /// Non-power-of-two periods are rejected at circuit-build time.
    #[test]
    fn rejects_non_power_of_two_period() {
        let domain = TwoAdicMultiplicativeCoset::new(Val::ONE, 4).unwrap();
        let mut circuit = CircuitBuilder::<Challenge>::new();
        let z = circuit.public_input();
        let cols = vec![make_col(3)];
        assert!(
            evaluate_periodic_columns_circuit::<Val, Challenge>(&mut circuit, &domain, &cols, z)
                .is_err()
        );
    }

    /// A period larger than the trace domain is rejected at circuit-build time.
    #[test]
    fn rejects_oversized_period() {
        let domain = TwoAdicMultiplicativeCoset::new(Val::ONE, 2).unwrap();
        let mut circuit = CircuitBuilder::<Challenge>::new();
        let z = circuit.public_input();
        let cols = vec![make_col(8)];
        assert!(
            evaluate_periodic_columns_circuit::<Val, Challenge>(&mut circuit, &domain, &cols, z)
                .is_err()
        );
    }
}
