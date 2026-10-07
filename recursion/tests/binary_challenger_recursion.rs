//! Bound byte-transcript statements, a real hash-table proof, and a trusted recursive layer.

use p3_binary_field::{BinaryChallenger, BinaryField128, TowerLevel};
use p3_blake3::Blake3;
use p3_challenger::{CanObserve, CanSample, CanSampleBits, GrindingChallenger};
use p3_circuit::ops::ByteHash;
use p3_circuit::{CircuitBuilder, CircuitError, StatementExport};
use p3_circuit_prover::ConstraintProfile;
use p3_circuit_prover::batch_stark_prover::{
    BatchStarkProver, Blake3CompressAirBuilder, Blake3CompressPreprocessor, Blake3CompressProver,
    KeccakF1600AirBuilder, KeccakF1600Preprocessor, KeccakF1600Prover, StatementAirBuilder,
    StatementPreprocessor, StatementProver,
};
use p3_circuit_prover::common::{NpoAirBuilder, NpoPreprocessor};
use p3_field::PrimeCharacteristicRing;
use p3_keccak::Keccak256Hash;
use p3_recursion::{
    BatchOnly, BinaryTower128Challenger, ProveNextLayerParams, TrustedPreparedInput,
    TrustedPreparedLayer, TrustedPreparedSource,
};
use p3_symmetric::Hash;
use p3_test_utils::koala_bear_params::F;

use crate::common;

const OBSERVED_RAW: u128 = 0x21bade026a6ae768f2ed66ffdcc99396;
const INITIAL: [u16; 2] = [0x1234, 0xabcd];
const DIGEST: [u8; 32] = [
    0x07, 0x1a, 0x2d, 0x40, 0x53, 0x66, 0x79, 0x8c, 0x9f, 0xb2, 0xc5, 0xd8, 0xeb, 0xfe, 0x11, 0x24,
    0x37, 0x4a, 0x5d, 0x70, 0x83, 0x96, 0xa9, 0xbc, 0xcf, 0xe2, 0xf5, 0x08, 0x1b, 0x2e, 0x41, 0x54,
];

fn tower_limbs(raw: u128) -> [F; 8] {
    core::array::from_fn(|i| F::from_u16((raw >> (16 * i)) as u16))
}

fn digest_limbs() -> [F; 16] {
    core::array::from_fn(|i| F::from_u16(u16::from_le_bytes([DIGEST[2 * i], DIGEST[2 * i + 1]])))
}

fn initial_bytes() -> Vec<u8> {
    INITIAL.into_iter().flat_map(u16::to_le_bytes).collect()
}

fn expected_from_native<H>(hasher: H) -> (Vec<F>, Vec<F>, Vec<F>)
where
    H: p3_symmetric::CryptographicHasher<u8, [u8; 32]>,
    BinaryChallenger<BinaryField128, p3_challenger::HashChallenger<u8, H, 32>>:
        GrindingChallenger<Witness = BinaryField128>,
{
    let mut native = BinaryChallenger::<BinaryField128, _>::from_hasher(initial_bytes(), hasher);
    native.observe(BinaryField128::from_repr(OBSERVED_RAW));
    let first: BinaryField128 = native.sample();
    CanObserve::<Hash<BinaryField128, u8, 32>>::observe(&mut native, Hash::from(DIGEST)); // Drops the remaining 16 bytes.
    let sampled_bits = [
        native.sample_bits(1),
        native.sample_bits(2),
        native.sample_bits(3),
    ];
    let second: BinaryField128 = native.sample(); // Last 8 bytes, then a chained refill.
    assert_eq!(native.sample_bits(0), 0); // Advances eight bytes despite returning no bits.
    let third: BinaryField128 = native.sample(); // The next 16 bytes reveal that advance.
    let before_pow = native.clone();
    let witness = native.grind(2);
    assert!(before_pow.clone().check_witness(2, witness));

    let bad = (0u128..)
        .map(BinaryField128::from_repr)
        .find(|candidate| !before_pow.clone().check_witness(2, *candidate))
        .expect("a two-bit PoW must have an invalid candidate");

    // Statement order: initial[2], observed tower[8], observed digest[16],
    // PoW witness[8], first sample[8], bit draws[1,2,3], cross-refill sample[8],
    // sample following a zero-width bit draw[8].
    let statement: Vec<F> = INITIAL
        .map(F::from_u16)
        .into_iter()
        .chain(tower_limbs(OBSERVED_RAW))
        .chain(digest_limbs())
        .chain(tower_limbs(witness.to_repr()))
        .chain(tower_limbs(first.to_repr()))
        .chain(
            sampled_bits
                .into_iter()
                .enumerate()
                .flat_map(|(draw, value)| {
                    (0..draw + 1).map(move |i| F::from_bool((value >> i) & 1 == 1))
                }),
        )
        .chain(tower_limbs(second.to_repr()))
        .chain(tower_limbs(third.to_repr()))
        .collect();
    assert_eq!(statement.len(), 64);

    let honest_inputs: Vec<F> = INITIAL
        .map(F::from_u16)
        .into_iter()
        .chain(tower_limbs(OBSERVED_RAW))
        .chain(digest_limbs())
        .chain(tower_limbs(witness.to_repr()))
        .collect();
    let bad_inputs: Vec<F> = INITIAL
        .map(F::from_u16)
        .into_iter()
        .chain(tower_limbs(OBSERVED_RAW))
        .chain(digest_limbs())
        .chain(tower_limbs(bad.to_repr()))
        .collect();
    (statement, honest_inputs, bad_inputs)
}

fn prove_relation(hash: ByteHash, recurse: bool) {
    let (config, backend) = common::koala_bear_d4_recursion_config_and_backend();
    let mut builder = CircuitBuilder::<F>::new();
    match hash {
        ByteHash::Keccak256 => builder.enable_keccak_f1600::<F>(),
        ByteHash::Blake3 => builder.enable_blake3_compress::<F>(),
    }

    let initial = builder.alloc_private_input_array::<2>("initial transcript limbs");
    let observed = builder.alloc_private_input_array::<8>("observed tower limbs");
    let digest = builder.alloc_private_input_array::<16>("observed digest limbs");
    let pow = builder.alloc_private_input_array::<8>("PoW witness limbs");
    let observed_tower = builder.binary128_from_limbs::<F>(observed).unwrap();
    let pow_tower = builder.binary128_from_limbs::<F>(pow).unwrap();
    let mut challenger =
        BinaryTower128Challenger::with_initial_limbs::<F, F>(&mut builder, hash, &initial).unwrap();
    challenger
        .observe::<F, F>(&mut builder, &observed_tower)
        .unwrap();
    let first = challenger.sample::<F, F>(&mut builder).unwrap();
    challenger
        .observe_digest::<F, F>(&mut builder, &digest)
        .unwrap();
    let mut sampled_bits = Vec::new();
    for width in [1, 2, 3] {
        sampled_bits.extend(challenger.sample_bits::<F, F>(&mut builder, width).unwrap());
    }
    let second = challenger.sample::<F, F>(&mut builder).unwrap();
    assert!(
        challenger
            .sample_bits::<F, F>(&mut builder, 0)
            .unwrap()
            .is_empty()
    );
    let third = challenger.sample::<F, F>(&mut builder).unwrap();
    challenger
        .check_witness::<F, F>(&mut builder, 2, &pow_tower)
        .unwrap();
    let first_limbs = builder.binary128_to_limbs::<F>(&first).unwrap();
    let second_limbs = builder.binary128_to_limbs::<F>(&second).unwrap();
    let third_limbs = builder.binary128_to_limbs::<F>(&third).unwrap();

    // All supplied transcript material and all returned samples are bound, in native order.
    let exports: Vec<_> = initial
        .into_iter()
        .chain(observed)
        .chain(digest)
        .chain(pow)
        .chain(first_limbs)
        .chain(sampled_bits)
        .chain(second_limbs)
        .chain(third_limbs)
        .map(StatementExport::Base)
        .collect();
    let schema = builder.set_statement_exports::<F>(&exports).unwrap();
    assert_eq!(schema.base_len(), 64);
    let circuit = builder.build().unwrap();

    let mut preprocessors: Vec<Box<dyn NpoPreprocessor<F>>> =
        vec![Box::new(StatementPreprocessor::new(schema.clone()))];
    let mut air_builders: Vec<Box<dyn NpoAirBuilder<common::KoalaBearD4RecursionConfig, 1>>> =
        vec![Box::new(StatementAirBuilder::<1>::new(schema.clone()))];
    let mut prover = BatchStarkProver::new(config.clone());
    prover.register_table_prover(Box::new(StatementProver::<1>::new(schema)));
    match hash {
        ByteHash::Keccak256 => {
            preprocessors.push(Box::new(KeccakF1600Preprocessor));
            air_builders.push(Box::new(KeccakF1600AirBuilder::<1>));
            prover.register_table_prover(Box::new(KeccakF1600Prover::<1>));
        }
        ByteHash::Blake3 => {
            preprocessors.push(Box::new(Blake3CompressPreprocessor));
            air_builders.push(Box::new(Blake3CompressAirBuilder::<1>));
            prover.register_table_prover(Box::new(Blake3CompressProver::<1>));
        }
    }
    let prepared = prover
        .prepare_circuit::<F, 1>(
            &circuit,
            &preprocessors,
            &air_builders,
            ConstraintProfile::Standard,
        )
        .unwrap();
    let (expected, honest_inputs, bad_inputs) = match hash {
        ByteHash::Keccak256 => expected_from_native(Keccak256Hash),
        ByteHash::Blake3 => expected_from_native(Blake3),
    };
    let mut runner = circuit.runner();
    runner.set_private_inputs(&honest_inputs).unwrap();
    let proof = prepared.prove(&runner.run().unwrap()).unwrap();
    let verifier = prepared.verifier();
    verifier.verify(&proof, &expected).unwrap();

    let mut changed_sample = expected.clone();
    changed_sample[34] += F::ONE; // The first returned tower limb.
    assert!(verifier.verify(&proof, &changed_sample).is_err());
    let mut changed_bit = expected.clone();
    changed_bit[42] = F::ONE - changed_bit[42]; // First returned bit.
    assert!(verifier.verify(&proof, &changed_bit).is_err());

    let mut bad_runner = circuit.runner();
    bad_runner.set_private_inputs(&bad_inputs).unwrap();
    assert!(matches!(
        bad_runner.run(),
        Err(CircuitError::WitnessConflict { .. })
    ));

    if recurse {
        let owner = TrustedPreparedLayer::<_, _, BatchOnly, _, 4>::new(
            TrustedPreparedSource::BatchStark {
                verifier,
                proof: &proof,
                statement: &expected,
            },
            config,
            backend,
            ProveNextLayerParams::default(),
        )
        .unwrap();
        let parent = owner
            .prove(TrustedPreparedInput::BatchStark {
                proof: &proof,
                statement: &expected,
            })
            .unwrap();
        owner.verifier().verify(&parent.0, &expected).unwrap();
        assert!(owner.verifier().verify(&parent.0, &changed_sample).is_err());
        assert!(owner.verifier().verify(&parent.0, &changed_bit).is_err());
    }
}

#[test]
fn keccak_binary_challenger_statement_proves_and_recurses() {
    prove_relation(ByteHash::Keccak256, true);
}

#[test]
fn blake3_binary_challenger_statement_proves() {
    prove_relation(ByteHash::Blake3, false);
}
