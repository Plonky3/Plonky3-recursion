//! The composite over Poly64 values and Poly192 challenges: a native bus whose Keccak-f table is
//! committed as bits packed sixty-four per Poly64 element, beside dense Poly64 tables.

use alloc::vec::Vec;

use p3_circuit_prover::direct::DirectCircuitLimits;
use p3_circuit_prover::native_bus::{KeccakCommitment, NativeBusCircuit, NativeBusTrace};
use p3_field::PrimeCharacteristicRing;
use p3_multi_stark::config::PcsError;
use p3_multi_stark::{
    MultiStarkProof, ProverInstance, ProverInstances, VerificationError as StarkError,
    VerifierInstance, VerifierInstances, VerifyingKey, prove_with_security, verify_with_security,
};
use p3_whir::{FoldingFactor, ProtocolParameters, SecurityAssumption};

use super::*;
use crate::verifier::VerifierLimits;

type F = Poly64;
type E = Poly192;
type Config = BinaryNativePolyMixedWhirConfig;

const HASH: ByteHash = ByteHash::Keccak256;
/// One level of cap, so the two arities give caps of different lengths.
const CAP_HEIGHT: usize = 1;
const POW_BITS: usize = 0;
const TARGET_BITS: usize = 20;
/// Three permutations fill 75 rows, padded to 128: two Poly64 elements of rows per column, so
/// the next row crosses an element and the reduction sends carry and last.
const CALLS: usize = 3;

fn challenger() -> BinaryNativeChallenger<F> {
    BinaryNativeChallenger::fresh(vec![5, 0, 9], HASH)
}

fn whir(num_variables: usize, arity: MerkleArity) -> BinaryNativePolyWhirPcsParameters {
    whir_with_cap(num_variables, arity, CAP_HEIGHT)
}

fn whir_with_cap(
    num_variables: usize,
    arity: MerkleArity,
    cap_height: usize,
) -> BinaryNativePolyWhirPcsParameters {
    BinaryNativePolyWhirPcsParameters::with_limits(
        num_variables,
        ProtocolParameters {
            security_level: 32,
            pow_bits: POW_BITS,
            round_log_inv_rates: vec![],
            folding_factor: FoldingFactor::Constant(2),
            soundness_type: SecurityAssumption::JohnsonBound,
            starting_log_inv_rate: 1,
        },
        HASH,
        arity,
        cap_height,
        &VerifierLimits::default(),
    )
    .unwrap()
}

/// Seven variables of rows is the 128 rows of three permutations; the other tables are padded
/// to at least that height.
fn bus() -> (NativeBusCircuit<F>, Vec<Vec<F>>, Vec<Table<F>>) {
    let (circuit, statement) = super::super::poly_packed_tests::keccak_chain(CALLS);
    let bus = NativeBusCircuit::with_options(
        &circuit,
        "poly-mixed",
        7,
        DirectCircuitLimits::default(),
        KeccakCommitment::Bits,
    )
    .unwrap();
    let mut runner = circuit.runner();
    runner.set_public_inputs(&statement).unwrap();
    let witness = runner.run().unwrap().witness_trace;
    let public = bus.public_values(&statement).unwrap();
    let tables = bus
        .trace_tables(&witness)
        .unwrap()
        .into_iter()
        .map(|trace| match trace {
            NativeBusTrace::Dense(matrix) => Table::new(matrix.transpose()),
            NativeBusTrace::PackedBits { words, log_height } => {
                Table::from_packed_bits(words, log_height)
            }
        })
        .collect();
    (bus, public, tables)
}

/// The main commitment bit-commits the Keccak table on trees of `arity`; preprocessing is dense.
fn config(bus: &NativeBusCircuit<F>, arity: MerkleArity) -> Config {
    let keccak = bus.keccak_table_index().unwrap();
    let bits = bus.packed_bit_variables().unwrap();
    let absorbed = BinaryNativePolyMixedWhirPcsParameters::ABSORBED_VARIABLES;
    let main = NativeMixedWhirPcs::from_parameters(
        &whir(bus.main_variables(), arity),
        Some((&whir(bits - absorbed, arity), keccak, bits)),
    )
    .unwrap();
    let preprocessed = NativeMixedWhirPcs::from_parameters(
        &whir(bus.preprocessed_variables().unwrap(), arity),
        None,
    )
    .unwrap();
    Config::new(main, Some(preprocessed)).unwrap()
}

/// Verifies a proof of the chain under `config` and its verifying key.
fn verify_chain(
    bus: &NativeBusCircuit<F>,
    public: &[Vec<F>],
    config: &Config,
    verifying: &VerifyingKey<Config>,
    proof: &MultiStarkProof<Config>,
) -> Result<(), StarkError<PcsError<Config>>> {
    verify_with_security(
        config,
        VerifierInstances::new(
            bus.airs()
                .iter()
                .zip(bus.log_heights())
                .zip(public)
                .map(|((air, &height), public)| {
                    VerifierInstance::new(air, verifying, height, public)
                })
                .collect(),
        ),
        proof,
        POW_BITS,
        TARGET_BITS,
        &mut challenger(),
    )
}

/// A packed element absorbs the base-two logarithm of its bit count in row variables, so the
/// packed WHIR of a Poly64 table runs over one variable more than a Tower128 table's would.
#[test]
fn absorbed_variables_follow_the_packing_field() {
    assert_eq!(BinaryNativeMixedWhirPcsParameters::ABSORBED_VARIABLES, 7);
    assert_eq!(
        BinaryNativePolyMixedWhirPcsParameters::ABSORBED_VARIABLES,
        6
    );
}

/// The Keccak table travels as packed bits at either tree arity: each part's cap holds
/// `arity^c` roots, the dense opening carries every other table, and the packed opening
/// authenticates the Keccak values on its own. A proof on trees of one arity carries caps of
/// the other's length, which the configuration at the other arity binds whole: every challenge
/// after the cap parts from the prover's, and the bus argument refuses the proof before the
/// opening is read.
#[test]
fn poly_nativebus_bits_round_trip_at_both_arities() {
    let (bus, public, tables) = bus();
    let airs = bus.airs().iter().collect::<Vec<_>>();
    let mut runs = Vec::new();
    for arity in [MerkleArity::Two, MerkleArity::Four] {
        let config = config(&bus, arity);
        let (proving, verifying) =
            p3_multi_stark::setup(&config, &airs, &mut challenger()).unwrap();
        let proof = prove_with_security(
            &config,
            ProverInstances::new(
                airs.iter()
                    .zip(tables.clone())
                    .zip(&public)
                    .map(|((air, table), public)| {
                        ProverInstance::new(*air, table, &proving, public)
                    })
                    .collect(),
            ),
            POW_BITS,
            TARGET_BITS,
            &mut challenger(),
        )
        .unwrap();
        let verify = |proof: &MultiStarkProof<Config>| {
            verify_chain(&bus, &public, &config, &verifying, proof)
        };
        verify(&proof).unwrap();

        let roots = arity.cap_roots(CAP_HEIGHT).unwrap();
        assert_eq!(proof.commitment.num_roots(), 2 * roots, "{arity:?}");
        assert_eq!(proof.opening.dense.evals.len(), airs.len() - 1, "{arity:?}");
        let mut tampered: MultiStarkProof<Config> =
            postcard::from_bytes(&postcard::to_allocvec(&proof).unwrap()).unwrap();
        tampered.opening.packed.as_mut().unwrap().values[0] += E::ONE;
        assert!(
            matches!(
                verify(&tampered),
                Err(StarkError::Opening(MixedWhirError::Packed(_)))
            ),
            "{arity:?}"
        );
        runs.push((arity, config, verifying, proof));
    }

    for ((arity, config, verifying, _), (_, _, _, proof)) in
        [(&runs[0], &runs[1]), (&runs[1], &runs[0])]
    {
        assert!(
            matches!(
                verify_chain(&bus, &public, config, verifying, proof),
                Err(StarkError::BusArgument(_))
            ),
            "{arity:?}"
        );
    }
}

/// Both parts share one hash, tree arity and cap height, and the packed WHIR folds exactly the
/// elements the bit table packs into.
#[test]
fn poly_parts_on_other_trees_are_refused() {
    let (bus, ..) = bus();
    let keccak = bus.keccak_table_index().unwrap();
    let bits = bus.packed_bit_variables().unwrap();
    let packed_variables = bits - BinaryNativePolyMixedWhirPcsParameters::ABSORBED_VARIABLES;
    let dense = whir(bus.main_variables(), MerkleArity::Four);
    let with_packed = |packed| {
        BinaryNativePolyMixedWhirPcsParameters::with_packed_table(
            dense.clone(),
            packed,
            keccak,
            bits,
        )
    };

    assert!(with_packed(whir(packed_variables, MerkleArity::Four)).is_ok());
    assert!(with_packed(whir(packed_variables, MerkleArity::Two)).is_err());
    assert!(
        with_packed(whir_with_cap(
            packed_variables,
            MerkleArity::Four,
            CAP_HEIGHT + 1
        ))
        .is_err()
    );
    let blake3 = BinaryNativePolyWhirPcsParameters::with_limits(
        packed_variables,
        dense.configuration().params().clone(),
        ByteHash::Blake3,
        MerkleArity::Four,
        CAP_HEIGHT,
        &VerifierLimits::default(),
    )
    .unwrap();
    assert!(with_packed(blake3).is_err());

    let build = |packed: &BinaryNativePolyWhirPcsParameters, bits| {
        NativeMixedWhirPcs::from_parameters(&dense, Some((packed, keccak, bits)))
    };
    let packed = whir(packed_variables, MerkleArity::Four);
    assert!(build(&packed, bits).is_ok());
    assert!(build(&packed, bits + 1).is_err());
    assert!(build(&whir(packed_variables, MerkleArity::Two), bits).is_err());
    assert!(
        build(
            &whir_with_cap(packed_variables, MerkleArity::Four, CAP_HEIGHT + 1),
            bits
        )
        .is_err()
    );
}
