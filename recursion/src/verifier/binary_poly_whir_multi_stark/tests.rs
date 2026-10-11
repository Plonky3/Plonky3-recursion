//! Relation-level bit-table flags: only an AIR whose table the main commitment stores as bits
//! may assume a Boolean trace, since no other commitment enforces its booleanity.

use alloc::vec;

use p3_air::{AirBuilder, BaseAir, WindowAccess};

use super::*;

const LOG_HEIGHT: usize = 4;
const MAX_TAU_DRAWS: usize = 32;
const BIT_REFUSAL: &str = "binary AIR requires a Boolean trace commitment";
const SHAPE_REFUSAL: &str = "polynomial MultiStark trusted instance shape mismatch";

/// One column constrained to `{0, 1}`; `boolean` states whether the AIR assumes a Boolean trace.
#[derive(Clone, Copy)]
struct BitAir {
    boolean: bool,
}

impl<F> BaseAir<F> for BitAir {
    fn width(&self) -> usize {
        1
    }
    fn assumes_boolean_trace(&self) -> bool {
        self.boolean
    }
}

impl<AB: AirBuilder> Air<AB> for BitAir {
    fn eval(&self, b: &mut AB) {
        let x = b.main().current_slice()[0];
        b.assert_zero(x * x - x);
    }
}

const PLAIN: BitAir = BitAir { boolean: false };
const BOOLEAN: BitAir = BitAir { boolean: true };

/// Builds the relation through the dense entry point.
fn dense(airs: &[BitAir]) -> Result<(), VerificationError> {
    let airs: Vec<_> = airs.iter().collect();
    let heights = vec![LOG_HEIGHT; airs.len()];
    let limits = VerifierLimits::default();
    PolyMultiStarkRelation::build(&airs, &heights, 0, MAX_TAU_DRAWS, false, &limits).map(|_| ())
}

/// Builds the relation with `bits[i]` stating that AIR `i`'s table is committed as bits.
fn flagged(airs: &[BitAir], bits: &[bool]) -> Result<(), VerificationError> {
    let airs: Vec<_> = airs.iter().collect();
    let heights = vec![LOG_HEIGHT; airs.len()];
    let limits = VerifierLimits::default();
    PolyMultiStarkRelation::build_with_bit_tables(
        &airs,
        &heights,
        bits,
        0,
        MAX_TAU_DRAWS,
        false,
        &limits,
    )
    .map(|_| ())
}

fn refused(result: Result<(), VerificationError>, expected: &str) -> bool {
    matches!(result, Err(VerificationError::InvalidProofShape(message)) if message == expected)
}

#[test]
fn dense_relation_refuses_a_boolean_assuming_air() {
    dense(&[PLAIN]).unwrap();
    assert!(refused(dense(&[BOOLEAN]), BIT_REFUSAL));
    assert!(refused(dense(&[PLAIN, BOOLEAN]), BIT_REFUSAL));
}

#[test]
fn each_bit_flag_reaches_its_own_air() {
    let airs = [PLAIN, BOOLEAN];
    flagged(&airs, &[false, true]).unwrap();
    assert!(refused(flagged(&airs, &[true, false]), BIT_REFUSAL));
    assert!(refused(flagged(&airs, &[false, false]), BIT_REFUSAL));
}

#[test]
fn bit_flags_must_cover_every_air_exactly() {
    let airs = [PLAIN, BOOLEAN];
    assert!(refused(flagged(&airs, &[false]), SHAPE_REFUSAL));
    assert!(refused(flagged(&airs, &[]), SHAPE_REFUSAL));
    assert!(refused(flagged(&airs, &[false, true, true]), SHAPE_REFUSAL));
}
