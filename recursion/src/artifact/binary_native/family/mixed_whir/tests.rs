//! The Boolean-trace assumption against the commitment that must supply it.

use core::array::from_fn;
use core::borrow::{Borrow, BorrowMut};

use p3_binary_pcs::BooleanTraceCommitmentError;
use p3_binary_pcs::whir::BinaryWhirDomain;
use p3_commit::MultilinearPcs;
use p3_field::{Field, PrimeCharacteristicRing};
use p3_keccak_air::{
    KeccakBinaryAir, KeccakBinaryCols, NUM_KECCAK_BINARY_COLS, NUM_ROUNDS, RC,
    generate_binary_trace_rows,
};
use p3_multi_stark::{ProverInstance, ProverInstances, prove, setup};
use p3_sumcheck::TableShape;
use p3_sumcheck::layout::{Table, plan_stacked_layout};
use p3_whir::{ProtocolParameters, SecurityAssumption, WhirProver};

use super::*;
use crate::artifact::binary_native::config::{BinaryNativeWhirConfig, MixedWhirError};
use crate::artifact::binary_native::lifecycle::check_boolean_assumptions;

type Dense = WhirFamily<SuffixProver<E, E>>;

const HASH: ByteHash = ByteHash::Keccak256;
/// One permutation fills 25 rows, padded to 32.
const KECCAK_VARIABLES: usize = 5;
const DENSE_VARIABLES: usize = 4;
/// The row variables one field element of the packed commitment absorbs.
const ABSORBED_VARIABLES: usize = 7;

/// Keccak rotation offsets, `ROTATIONS[x][y]` for lane `(x, y)`.
const ROTATIONS: [[usize; 5]; 5] = [
    [0, 36, 3, 41, 18],
    [1, 44, 10, 45, 2],
    [62, 6, 43, 15, 61],
    [28, 55, 25, 21, 56],
    [27, 20, 39, 8, 14],
];

fn whir_with_rate(num_variables: usize, rate: usize) -> BinaryNativeWhirPcsParameters<E> {
    BinaryNativeWhirPcsParameters::new(
        num_variables,
        ProtocolParameters {
            security_level: 32,
            pow_bits: 0,
            round_log_inv_rates: vec![],
            folding_factor: FoldingFactor::Constant(2),
            soundness_type: SecurityAssumption::JohnsonBound,
            starting_log_inv_rate: rate,
        },
        HASH,
        0,
    )
    .unwrap()
}

fn whir(num_variables: usize) -> BinaryNativeWhirPcsParameters<E> {
    whir_with_rate(num_variables, 1)
}

/// Bit arity of the Keccak table of one permutation.
fn bit_variables() -> usize {
    plan_stacked_layout(&[TableShape::new(KECCAK_VARIABLES, NUM_KECCAK_BINARY_COLS)]).0
}

/// Mixed parameters bit-committing `table`, a Keccak table of one permutation.
fn mixed(table: usize) -> BinaryNativeMixedWhirPcsParameters {
    let bits = bit_variables();
    BinaryNativeMixedWhirPcsParameters::with_packed_table(
        whir(DENSE_VARIABLES),
        whir(bits - ABSORBED_VARIABLES),
        table,
        bits,
    )
    .unwrap()
}

#[test]
fn boolean_assumptions_must_fall_on_bit_committed_tables() {
    // The default AIR constrains its cells to bits; the other leaves that to the commitment.
    let constrained = [KeccakBinaryAir::default()];
    let assuming = [KeccakBinaryAir::assuming_boolean_trace()];
    let assuming_first = [
        KeccakBinaryAir::assuming_boolean_trace(),
        KeccakBinaryAir::default(),
    ];
    let assuming_second = [
        KeccakBinaryAir::default(),
        KeccakBinaryAir::assuming_boolean_trace(),
    ];
    let dense = whir(DENSE_VARIABLES);

    // A dense family commits no table as bits.
    check_boolean_assumptions::<E, E, _, Dense>(&constrained, &dense).unwrap();
    assert!(check_boolean_assumptions::<E, E, _, Dense>(&assuming, &dense).is_err());
    let dense_only = BinaryNativeMixedWhirPcsParameters::dense(whir(DENSE_VARIABLES));
    assert!(check_boolean_assumptions::<E, E, _, MixedWhirFamily>(&assuming, &dense_only).is_err());

    // The mixed family admits the assumption on its bit-committed table only, at any index.
    check_boolean_assumptions::<E, E, _, MixedWhirFamily>(&assuming, &mixed(0)).unwrap();
    check_boolean_assumptions::<E, E, _, MixedWhirFamily>(&assuming_first, &mixed(0)).unwrap();
    check_boolean_assumptions::<E, E, _, MixedWhirFamily>(&assuming_second, &mixed(1)).unwrap();
    assert!(
        check_boolean_assumptions::<E, E, _, MixedWhirFamily>(&assuming_first, &mixed(1)).is_err()
    );
    assert!(
        check_boolean_assumptions::<E, E, _, MixedWhirFamily>(&assuming_second, &mixed(0)).is_err()
    );
}

#[test]
fn parameter_identity_binds_the_packed_table_and_both_parts() {
    let bytes = |p: &BinaryNativeMixedWhirPcsParameters| {
        let mut w = Writer::new(1 << 16);
        MixedWhirFamily::write_parameters(&mut w, p).unwrap();
        w.finish().unwrap()
    };
    let bits = bit_variables();
    let with = |dense, packed, table, bits| {
        BinaryNativeMixedWhirPcsParameters::with_packed_table(dense, packed, table, bits).unwrap()
    };
    // Each variant differs from the first in one quantity: the packed table, the bit arity,
    // the packed rate, the dense rate, and the presence of a packed part.
    let packed = whir(bits - ABSORBED_VARIABLES);
    let variants = [
        mixed(1),
        mixed(0),
        with(whir(DENSE_VARIABLES), packed.clone(), 1, bits + 1),
        with(
            whir(DENSE_VARIABLES),
            whir_with_rate(bits - ABSORBED_VARIABLES, 2),
            1,
            bits,
        ),
        with(whir_with_rate(DENSE_VARIABLES, 2), packed, 1, bits),
        BinaryNativeMixedWhirPcsParameters::dense(whir(DENSE_VARIABLES)),
    ]
    .map(|p| bytes(&p));
    for (i, first) in variants.iter().enumerate() {
        for second in &variants[i + 1..] {
            assert_ne!(first, second);
        }
    }
}

#[test]
fn mixed_parameters_refuse_parts_on_other_trees() {
    let bits = bit_variables();
    let other_cap = BinaryNativeWhirPcsParameters::new(
        bits - ABSORBED_VARIABLES,
        whir(bits - ABSORBED_VARIABLES).config.params().clone(),
        HASH,
        1,
    )
    .unwrap();
    let other_hash = BinaryNativeWhirPcsParameters::new(
        bits - ABSORBED_VARIABLES,
        whir(bits - ABSORBED_VARIABLES).config.params().clone(),
        ByteHash::Blake3,
        0,
    )
    .unwrap();
    for packed in [other_cap, other_hash] {
        assert!(
            BinaryNativeMixedWhirPcsParameters::with_packed_table(
                whir(DENSE_VARIABLES),
                packed,
                0,
                bits
            )
            .is_err()
        );
    }
}

fn row(trace: &RowMajorMatrix<E>, r: usize) -> &KeccakBinaryCols<E> {
    trace.values[r * NUM_KECCAK_BINARY_COLS..(r + 1) * NUM_KECCAK_BINARY_COLS].borrow()
}

fn row_mut(trace: &mut RowMajorMatrix<E>, r: usize) -> &mut KeccakBinaryCols<E> {
    trace.values[r * NUM_KECCAK_BINARY_COLS..(r + 1) * NUM_KECCAK_BINARY_COLS].borrow_mut()
}

/// One round of the Keccak AIR's round map on field elements rather than bits.
fn field_round(a: &[[[E; 64]; 5]; 5], round: usize) -> [[[E; 64]; 5]; 5] {
    // Theta, as sums.
    let c: [[E; 64]; 5] = from_fn(|x| from_fn(|z| (0..5).map(|y| a[y][x][z]).sum()));
    let theta: [[[E; 64]; 5]; 5] = from_fn(|y| {
        from_fn(|x| from_fn(|z| a[y][x][z] + c[(x + 4) % 5][z] + c[(x + 1) % 5][(z + 63) % 64]))
    });
    // Rho and pi, as the permutation: lane (x, y) is lane (x + 3y, x), rotated.
    let b = |x: usize, y: usize, z: usize| {
        let source = (x + 3 * y) % 5;
        theta[x][source][(z + 64 - ROTATIONS[source][x]) % 64]
    };
    // Chi as a + (1 + b)·c, then iota adds the round constant to lane (0, 0).
    from_fn(|y| {
        from_fn(|x| {
            from_fn(|z| {
                let chi = b(x, y, z) + (E::ONE + b((x + 1) % 5, y, z)) * b((x + 2) % 5, y, z);
                let constant = x == 0 && y == 0 && (RC[round] >> z) & 1 == 1;
                chi + E::from_bool(constant)
            })
        })
    })
}

/// A permutation whose round-0 input holds one non-bit, run through the round map over the
/// field. Every constraint of the Boolean-assuming Keccak AIR holds on it.
fn non_bit_keccak_trace() -> RowMajorMatrix<E> {
    let input: [u64; 25] = from_fn(|i| 0x0123_4567_89ab_cdefu64.rotate_left(5 * i as u32));
    let mut trace = generate_binary_trace_rows::<E>(vec![input], 0);
    for round in 0..NUM_ROUNDS {
        assert_eq!(
            field_round(&row(&trace, round).a, round),
            row(&trace, round + 1).a
        );
    }
    let non_bit = E::GENERATOR;
    assert!(non_bit != E::ZERO && non_bit != E::ONE);
    row_mut(&mut trace, 0).a[1][2][3] = non_bit;
    for round in 0..NUM_ROUNDS {
        let next = field_round(&row(&trace, round).a, round);
        row_mut(&mut trace, round + 1).a = next;
    }
    trace
}

fn challenger() -> BinaryNativeChallenger<E> {
    BinaryNativeChallenger::fresh(vec![3, 1, 4], HASH)
}

/// A non-bit Keccak state run through the round map meets every constraint of the
/// Boolean-assuming AIR over the field, so only the commitment can refuse it. The multi-STARK
/// prover refuses that AIR under a dense WHIR commitment, whose bit region is empty; setup's
/// check refuses the pairing; and the bit commitment refuses the trace before binding it.
#[test]
fn non_bit_state_meets_the_constraints_and_every_commitment_refuses_it() {
    let air = KeccakBinaryAir::assuming_boolean_trace();
    let trace = non_bit_keccak_trace();
    p3_air::check_constraints(&air, &trace, &[]);

    let dense = whir(bit_variables());
    let config = BinaryNativeWhirConfig::<E, SuffixProver<E, E>> {
        main: WhirProver::new(
            dense.config.clone(),
            BinaryWhirDomain::<E>::default(),
            tree(HASH, 0),
        ),
        preprocessed: None,
    };
    let (proving, _) = setup(&config, &[&air], &mut challenger()).unwrap();
    let table = || Table::new(trace.clone().transpose());
    let Err(refused) = std::panic::catch_unwind(core::panic::AssertUnwindSafe(|| {
        prove(
            &config,
            ProverInstances::new(vec![ProverInstance::new(&air, table(), &proving, &[])]),
            0,
            &mut challenger(),
        )
    })) else {
        panic!("the prover refuses a Boolean-assuming AIR under a dense commitment");
    };
    let message = refused
        .downcast_ref::<std::string::String>()
        .map_or("", |message| message.as_str());
    assert!(message.contains("bit columns"), "{message}");

    assert!(check_boolean_assumptions::<E, E, _, Dense>(&[air], &dense).is_err());

    let bits = bit_variables();
    let mixed = MixedWhirPcs::from_parameters(
        &whir(DENSE_VARIABLES),
        Some((&whir(bits - ABSORBED_VARIABLES), 0, bits)),
    )
    .unwrap();
    assert!(matches!(
        mixed.commit(vec![table()], &mut challenger()),
        Err(MixedWhirError::Packed(
            BooleanTraceCommitmentError::NonBooleanCell { table: 0, .. }
        ))
    ));
}
