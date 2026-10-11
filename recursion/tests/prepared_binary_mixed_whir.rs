//! Prime-field wrap of a native proof whose Boolean table is committed as packed bits.

use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_binary_field::BinaryField128;
use p3_circuit::ops::ByteHash;
use p3_field::PrimeCharacteristicRing;
use p3_matrix::dense::RowMajorMatrix;
use p3_recursion::artifact::{
    ArtifactLimits, BinaryNativeMixedWhirAuthority, BinaryNativeMixedWhirPcsParameters,
    BinaryNativeVerifierSpec, BinaryNativeWhirPcsParameters, VerifiedBinaryNativeMixedWhirProof,
};
use p3_recursion::builtin_config::{
    BabyBearD4Poseidon2BinaryConfig, FriConfigV1, SuiteIdV1, baby_bear_d4_poseidon2_binary,
};
use p3_recursion::prepared::PreparedBinaryMixedWhirMultiStarkLayer;
use p3_recursion::{ProveNextLayerParams, VerificationError};
use p3_sumcheck::TableShape;
use p3_sumcheck::layout::{Table, plan_stacked_layout};
use p3_whir::{FoldingFactor, ProtocolParameters, SecurityAssumption};
use rand::rngs::SmallRng;
use rand::{RngExt, SeedableRng};

type F = BinaryField128;
type C = BabyBearD4Poseidon2BinaryConfig;
type Authority = BinaryNativeMixedWhirAuthority<TestAir>;

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

impl<AB: AirBuilder<F = F>> Air<AB> for TestAir {
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

fn heights() -> Vec<usize> {
    vec![SQUARE_VARIABLES, BIT_VARIABLES, SQUARE_VARIABLES]
}

fn airs() -> Vec<TestAir> {
    vec![TestAir::Square, TestAir::Bits, TestAir::Square]
}

fn spec(initial_bytes: Vec<u8>) -> BinaryNativeVerifierSpec<BinaryNativeMixedWhirPcsParameters> {
    let dense = [SQUARE_VARIABLES; 2].map(|height| TableShape::new(height, 2));
    let bits = plan_stacked_layout(&[TableShape::new(BIT_VARIABLES, BIT_WIDTH)]).0;
    BinaryNativeVerifierSpec {
        main: BinaryNativeMixedWhirPcsParameters::with_packed_table(
            whir(plan_stacked_layout(&dense).0),
            whir(bits - ABSORBED_VARIABLES),
            PACKED_TABLE,
            bits,
        )
        .unwrap(),
        preprocessed: None,
        transcript_hash: HASH,
        initial_bytes,
        sumcheck_pow_bits: 0,
        max_tau_draws: 32,
        security_bits: 1,
    }
}

fn setup(
    initial_bytes: Vec<u8>,
) -> (
    p3_recursion::artifact::BinaryNativeMixedWhirProver<TestAir>,
    Authority,
) {
    Authority::setup_with_artifact_limits(
        airs(),
        heights(),
        spec(initial_bytes),
        ArtifactLimits::default(),
    )
    .unwrap()
}

fn public() -> Vec<Vec<F>> {
    vec![vec![F::ONE + F::ONE], vec![], vec![F::ZERO]]
}

fn token(initial_bytes: Vec<u8>) -> (Authority, VerifiedBinaryNativeMixedWhirProof) {
    let (prover, authority) = setup(initial_bytes);
    let public = public();
    let tables = vec![
        square_rows(public[0][0]),
        bit_rows(),
        square_rows(public[2][0]),
    ];
    let proof = prover.prove_tables(&public, tables).unwrap();
    let token = authority.verify_native(&proof, &public).unwrap();
    (authority, token)
}

fn config() -> C {
    baby_bear_d4_poseidon2_binary(
        &FriConfigV1::new(
            SuiteIdV1::BabyBearD4Poseidon2BinaryFri,
            1,
            0,
            2,
            2,
            0,
            0,
            0,
            0,
            0,
            0,
        ),
        &ArtifactLimits::default().verifier,
    )
    .unwrap()
}

fn layer(authority: &Authority) -> PreparedBinaryMixedWhirMultiStarkLayer<C, 4> {
    PreparedBinaryMixedWhirMultiStarkLayer::<C, 4>::from_native_authority(
        authority,
        config(),
        ProveNextLayerParams::default(),
    )
    .unwrap()
}

/// The prime circuit of even the smallest mixed relation has tens of millions of operations,
/// above 12 GB in a debug build.
#[test]
#[ignore = "builds a prime-field mixed verifier: above 12 GB in debug; run explicitly"]
fn wrap_binds_the_native_identity_and_statement() {
    let (authority, token) = token(vec![7, 19, 13]);
    let layer = layer(&authority);
    assert_eq!(
        layer.native_verifier_identity(),
        Some(authority.canonical_verifier_bytes())
    );

    let (_, foreign) = self::token(vec![7, 19, 13, 0]);
    assert!(matches!(
        layer.prove_verified(&foreign),
        Err(VerificationError::InvalidProofShape(message))
            if message == "binary verified input belongs to another native authority"
    ));

    let mut wrong = token.public_values().to_vec();
    wrong[0][0] += F::ONE;
    assert!(layer.prove(token.native_input(), &wrong).is_err());
}
