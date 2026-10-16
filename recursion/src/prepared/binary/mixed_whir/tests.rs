//! Witness generation of the prime circuit the layer prepares for a mixed native authority,
//! without preparing its prover.

use alloc::vec;
use alloc::vec::Vec;

use p3_air::{AirBuilder, BaseAir, WindowAccess};
use p3_circuit::CircuitError;
use p3_matrix::dense::RowMajorMatrix;
use p3_sumcheck::TableShape;
use p3_sumcheck::layout::{Table, plan_stacked_layout};
use p3_whir::{FoldingFactor, ProtocolParameters, SecurityAssumption};
use rand::rngs::SmallRng;
use rand::{RngExt, SeedableRng};

use super::*;
use crate::artifact::{
    ArtifactLimits, BinaryNativeMixedWhirPcsParameters, BinaryNativeMixedWhirProver,
    BinaryNativeVerifierSpec, BinaryNativeWhirPcsParameters,
};
use crate::builtin_config::BabyBearD4Poseidon2BinaryConfig;

type F = BinaryField128;
type Core = BinaryPreparedCore<
    F,
    F,
    BabyBearD4Poseidon2BinaryConfig,
    4,
    BinaryMixedWhirMultiStarkVerifier,
    BinaryMixedWhirMultiStarkInputShape,
>;

const HASH: ByteHash = ByteHash::Keccak256;
const FOLDING: usize = 2;
const CAP_HEIGHT: usize = 1;
/// The row variables one field element of the packed commitment absorbs.
const ABSORBED_VARIABLES: usize = 7;
/// Above the absorbed variables, so the packed opening has one row variable left.
const BIT_VARIABLES: usize = 8;
const SQUARE_VARIABLES: usize = FOLDING;
const BIT_WIDTH: usize = 8;
const PACKED_TABLE: usize = 1;

/// Dense squares around a Boolean table, which is bit-committed.
///
/// ```text
///     square   first row a = public value;   b = a·a + 1
///     bits     c = a·b
/// ```
#[derive(Clone)]
enum TestAir {
    Square,
    Bits,
}

impl BaseAir<F> for TestAir {
    fn width(&self) -> usize {
        match self {
            Self::Square => 2,
            Self::Bits => BIT_WIDTH,
        }
    }
    fn num_public_values(&self) -> usize {
        usize::from(matches!(self, Self::Square))
    }
    fn main_next_row_columns(&self) -> Vec<usize> {
        vec![]
    }
    fn assumes_boolean_trace(&self) -> bool {
        matches!(self, Self::Bits)
    }
}

impl<AB: AirBuilder<F = F>> p3_air::Air<AB> for TestAir {
    fn eval(&self, b: &mut AB) {
        let cur = b.main().current_slice().to_vec();
        match self {
            Self::Square => {
                let first = b.public_values()[0];
                b.when_first_row().assert_eq(cur[0], first);
                b.assert_eq(cur[1], cur[0] * cur[0] + AB::Expr::ONE);
            }
            Self::Bits => b.assert_eq(cur[2], cur[0] * cur[1]),
        }
    }
}

fn square_rows(first: F) -> Table<F> {
    let mut rng = SmallRng::seed_from_u64(5);
    let a: Vec<F> = core::iter::once(first)
        .chain((1..1 << SQUARE_VARIABLES).map(|_| rng.random()))
        .collect();
    let b = a.iter().map(|&a| a * a + F::ONE).collect::<Vec<_>>();
    Table::new(RowMajorMatrix::new([a, b].concat(), 1 << SQUARE_VARIABLES))
}

fn bit_rows() -> Table<F> {
    let mut rng = SmallRng::seed_from_u64(7);
    let cells: Vec<F> = (0..1 << BIT_VARIABLES)
        .flat_map(|_| {
            let mut row: Vec<bool> = (0..BIT_WIDTH).map(|_| rng.random()).collect();
            row[2] = row[0] & row[1];
            row.into_iter().map(F::from_bool)
        })
        .collect();
    Table::new(RowMajorMatrix::new(cells, BIT_WIDTH).transpose())
}

fn whir(num_variables: usize) -> BinaryNativeWhirPcsParameters<F> {
    BinaryNativeWhirPcsParameters::new(
        num_variables,
        ProtocolParameters {
            security_level: 8,
            pow_bits: 0,
            round_log_inv_rates: vec![],
            folding_factor: FoldingFactor::Constant(FOLDING),
            soundness_type: SecurityAssumption::JohnsonBound,
            starting_log_inv_rate: 2,
        },
        HASH,
        CAP_HEIGHT,
    )
    .unwrap()
}

fn setup() -> (
    BinaryNativeMixedWhirProver<TestAir>,
    BinaryNativeMixedWhirAuthority<TestAir>,
) {
    let dense = [SQUARE_VARIABLES; 2].map(|height| TableShape::new(height, 2));
    let bits = plan_stacked_layout(&[TableShape::new(BIT_VARIABLES, BIT_WIDTH)]).0;
    let spec = BinaryNativeVerifierSpec {
        main: BinaryNativeMixedWhirPcsParameters::with_packed_table(
            whir(plan_stacked_layout(&dense).0),
            whir(bits - ABSORBED_VARIABLES),
            PACKED_TABLE,
            bits,
        )
        .unwrap(),
        preprocessed: None,
        transcript_hash: HASH,
        initial_bytes: vec![7, 19, 13],
        sumcheck_pow_bits: 0,
        max_tau_draws: 32,
        security_bits: 1,
    };
    BinaryNativeMixedWhirAuthority::setup_with_artifact_limits(
        vec![TestAir::Square, TestAir::Bits, TestAir::Square],
        vec![SQUARE_VARIABLES, BIT_VARIABLES, SQUARE_VARIABLES],
        spec,
        ArtifactLimits::default(),
    )
    .unwrap()
}

/// A token for the statement whose first square starts at `first`.
fn verified(
    prover: &BinaryNativeMixedWhirProver<TestAir>,
    authority: &BinaryNativeMixedWhirAuthority<TestAir>,
    first: F,
) -> VerifiedBinaryNativeMixedWhirProof {
    let public = vec![vec![first], vec![], vec![F::ZERO]];
    let tables = vec![square_rows(first), bit_rows(), square_rows(F::ZERO)];
    let proof = prover.prove_tables(&public, tables).unwrap();
    authority.verify_native(&proof, &public).unwrap()
}

/// The circuit `from_native_authority` prepares, built from the same authority values, accepts
/// two honest tokens. Each token's input fails witness generation under the other token's
/// statement: the statement reaches the circuit through its packed limbs and the transcript.
#[test]
#[ignore = "builds a prime-field mixed verifier circuit: about 7.8 GB and 130 s in debug; run explicitly"]
fn layer_circuit_accepts_honest_tokens_and_refuses_swapped_statements() {
    let (prover, authority) = setup();
    let two = verified(&prover, &authority, F::ONE + F::ONE);
    let three = verified(&prover, &authority, F::ONE + F::ONE + F::ONE);
    let (shape, layout, circuit) = Core::circuit(
        authority.recursive_verifier(),
        authority.transcript_hash(),
        authority.initial_bytes(),
        &authority.artifact_limits().verifier,
    )
    .unwrap();
    // The Boolean table has no public values, so the statement has an empty middle instance.
    assert_eq!(layout.public_value_counts(), [1, 0, 1]);
    let run = |token: &VerifiedBinaryNativeMixedWhirProof, public: &[Vec<F>]| {
        Core::run(&circuit, &layout, &shape, &token.input, public)
    };
    for token in [&two, &three] {
        run(token, &token.public).unwrap();
    }
    for (token, statement) in [(&two, &three), (&three, &two)] {
        assert!(matches!(
            run(token, &statement.public),
            Err(VerificationError::Circuit(
                CircuitError::WitnessConflict { .. }
            ))
        ));
    }
}
