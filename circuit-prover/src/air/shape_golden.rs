//! Column-count golden snapshots for the primitive circuit-table AIRs.
//!
//! These pin [`BaseAir::width`] and [`BaseAir::preprocessed_width`] for the Const,
//! Public, and ALU tables across extension degrees and lane counts. A table
//! unification or extension-arithmetic refactor that perturbs a column count
//! changes trace width/height and therefore the commitment cost; these snapshots
//! turn such a drift into an immediate, reviewable test failure instead of a
//! silent regression.
//!
//! Re-bless the literals only alongside a deliberate, reviewed layout change.

use p3_air::BaseAir;
use p3_baby_bear::BabyBear;
use p3_field::PrimeCharacteristicRing;

use super::{AluAir, ConstAir, PublicAir};

type F = BabyBear;

/// `(main_width, preprocessed_width)` for a `ConstAir` of degree `D`.
fn const_shape<const D: usize>() -> (usize, usize) {
    let air = ConstAir::<F, D>::new(8);
    (air.width(), air.preprocessed_width())
}

/// `(main_width, preprocessed_width)` for a `PublicAir` of degree `D` and `lanes`.
fn public_shape<const D: usize>(lanes: usize) -> (usize, usize) {
    let air = PublicAir::<F, D>::new(0, lanes);
    (air.width(), air.preprocessed_width())
}

#[test]
fn const_air_shape_is_stable() {
    assert_eq!(const_shape::<1>(), (1, 2));
    assert_eq!(const_shape::<4>(), (4, 2));
    assert_eq!(const_shape::<5>(), (5, 2));
}

#[test]
fn public_air_shape_is_stable() {
    assert_eq!(public_shape::<1>(1), (1, 2));
    assert_eq!(public_shape::<4>(1), (4, 2));
    assert_eq!(public_shape::<4>(2), (8, 4));
}

#[test]
fn alu_base_air_shape_is_stable() {
    let lane1 = AluAir::<F, 1>::new(0, 1);
    let lane2 = AluAir::<F, 1>::new(0, 2);
    assert_eq!((lane1.width(), lane1.preprocessed_width()), (7, 20));
    assert_eq!((lane2.width(), lane2.preprocessed_width()), (11, 33));
}

#[test]
fn alu_binomial_air_shape_is_stable() {
    let d2 = AluAir::<F, 2>::new_binomial(0, 1, F::ONE);
    let d4_lane1 = AluAir::<F, 4>::new_binomial(0, 1, F::ONE);
    let d4_lane2 = AluAir::<F, 4>::new_binomial(0, 2, F::ONE);
    assert_eq!((d2.width(), d2.preprocessed_width()), (14, 20));
    assert_eq!((d4_lane1.width(), d4_lane1.preprocessed_width()), (28, 20));
    assert_eq!((d4_lane2.width(), d4_lane2.preprocessed_width()), (44, 33));
}

#[test]
fn alu_quintic_trinomial_air_shape_is_stable() {
    let d5 = AluAir::<F, 5>::new_quintic_trinomial(0, 1);
    assert_eq!((d5.width(), d5.preprocessed_width()), (35, 20));
}
