//! Bit readings over Poly64 packings with Poly192 challenges verified in the native Poly64
//! carrier: the bit ring switch with every sumcheck round, closed against the packed WHIR
//! opening, checked against the released ring switch and WHIR commitment.

use p3_binary_field::{Poly64, Poly192};
use p3_binary_pcs::whir::{BinaryWhirDomain, BooleanWhirProof};
use p3_circuit::ops::binary_encoding::{BinaryCircuitEncoding, NativeBinaryEncoding};
use p3_circuit::ops::{ByteHash, NativePoly192Target, bytes_to_limbs};
use p3_circuit::{Circuit, CircuitBuilder};
use p3_commit::MultilinearPcs;
use p3_field::PrimeCharacteristicRing;
use p3_matrix::dense::RowMajorMatrix;
use p3_multilinear_util::point::Point;
use p3_multilinear_util::poly::Poly;
use p3_recursion::BinaryTower128Challenger;
use p3_recursion::pcs::binary::{
    BinaryPolyBitRingVerifier, BinaryPolyBooleanWhirVerifier, BinaryPolyWhirVerifier,
    BinaryRingClaimSpec, NativePolyBitRingReading,
};
use p3_sumcheck::layout::{Layout, SuffixProver, Table};
use p3_sumcheck::ring_switch::bits::{BitPacking, BitRingSwitch, BitRingSwitchClaims};
use p3_sumcheck::{OpeningBatch, OpeningProtocol, PrescribedPointPcs, TableShape, TableSpec};
use p3_test_utils::binary_field_params::keccak;
use p3_whir::{FoldingFactor, ProtocolParameters, SecurityAssumption, WhirConfig, WhirProver};

type F = Poly64;
type E = Poly192;
type H = NativeBinaryEncoding;
type Ch = keccak::LevelChallenger<F>;
/// Trees whose nodes compress two digests.
type PairMmcs = keccak::LevelMmcs<F>;

/// Bit variables one packed Poly64 element absorbs.
const ABSORBED: usize = 6;
/// Bytes every transcript here starts from, natively and in each circuit.
const INITIAL: [u8; 4] = [7, 19, 13, 29];

/// Deterministic SplitMix64 stream of words and full-width field elements.
struct Sampler(u64);

impl Sampler {
    const fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }

    const fn base(&mut self) -> F {
        F::new(self.next_u64())
    }

    fn bases(&mut self, count: usize) -> Vec<F> {
        (0..count).map(|_| self.base()).collect()
    }

    const fn ext(&mut self) -> E {
        E::new([self.base(), self.base(), self.base()])
    }

    fn point(&mut self, variables: usize) -> Point<E> {
        Point::new((0..variables).map(|_| self.ext()).collect())
    }
}

fn challenger() -> Ch {
    Ch::from_hasher(INITIAL.to_vec(), keccak::byte_hash())
}

const fn pair_mmcs(cap_height: usize) -> PairMmcs {
    PairMmcs::new(
        keccak::FieldHash::new(keccak::byte_hash()),
        keccak::Compress::new(keccak::byte_hash()),
        cap_height,
    )
}

/// The packed WHIR configuration the tests open with: small security, so the circuits stay
/// small, and folds of two once the packing has that many variables.
fn packed_config(variables: usize) -> WhirConfig<E, F, Ch> {
    whir_config(variables, 8, 2, if variables >= 4 { 2 } else { 1 })
}

fn whir_config(
    variables: usize,
    security: usize,
    rate: usize,
    fold: usize,
) -> WhirConfig<E, F, Ch> {
    WhirConfig::new_with_domain(
        variables,
        ProtocolParameters {
            security_level: security,
            pow_bits: 0,
            round_log_inv_rates: vec![],
            folding_factor: FoldingFactor::Constant(fold),
            soundness_type: SecurityAssumption::JohnsonBound,
            starting_log_inv_rate: rate,
        },
        &BinaryWhirDomain::<F>::default(),
    )
    .unwrap()
}

fn public_value(b: &mut CircuitBuilder<F>) -> NativePoly192Target {
    let coefficients = core::array::from_fn(|_| b.public_input());
    b.native_poly192_from_coefficients(coefficients)
}

fn native_challenger(b: &mut CircuitBuilder<F>) -> BinaryTower128Challenger {
    let initial = INITIAL.map(|byte| b.define_const(H::encode_u16(u16::from(byte)).unwrap()));
    BinaryTower128Challenger::with_initial_bytes_with_host::<H, F>(b, ByteHash::Keccak256, &initial)
        .unwrap()
}

fn accepts(circuit: &Circuit<F>, public: &[F], private: &[F]) -> bool {
    let mut runner = circuit.runner();
    runner
        .set_public_inputs(public)
        .and_then(|()| runner.set_private_inputs(private))
        .and_then(|()| runner.run())
        .is_ok()
}

/// The surviving value of the ring switch is constrained equal to the packed opening's
/// evaluation, the one link from the readings to the commitment. A ring switch run on another
/// packing, closed at its own surviving value, followed by the committed packing's opening at
/// that surviving point, passes every other check: each part imports on its own, the whole
/// proof does not, and the circuit refuses it.
#[test]
fn the_surviving_value_is_the_packed_evaluation() {
    let variables = 9;
    let high = variables - ABSORBED;
    let config = packed_config(high);
    let mmcs = pair_mmcs(0);
    let inner = WhirProver::<E, F, _, _, Ch, SuffixProver<F, E>>::new(
        config.clone(),
        BinaryWhirDomain::<F>::default(),
        mmcs.clone(),
    );
    let specs = vec![BinaryRingClaimSpec {
        current: true,
        next_rows: None,
    }];
    let verifier =
        BinaryPolyBooleanWhirVerifier::new(&config, specs.clone(), ByteHash::Keccak256, 0).unwrap();
    let ring = BinaryPolyBitRingVerifier::new(variables, specs).unwrap();
    let protocol = OpeningProtocol::new(vec![TableSpec::new(
        TableShape::new(high, 1),
        vec![OpeningBatch::new(vec![0], vec![])],
    )]);
    let whir = BinaryPolyWhirVerifier::new(
        &config,
        protocol.clone(),
        SuffixProver::<F, E>::variable_order(),
        ByteHash::Keccak256,
        0,
    )
    .unwrap();

    let mut b = CircuitBuilder::<F>::new();
    b.enable_native_keccak_f1600().unwrap();
    let cap = vec![
        b.alloc_public_input_array::<16>("packed commitment root")
            .to_vec(),
    ];
    let reading = NativePolyBitRingReading {
        point: (0..variables).map(|_| public_value(&mut b)).collect(),
        current: Some(public_value(&mut b)),
        next: None,
    };
    let targets = verifier
        .input_shape()
        .allocate_native_targets(&mut b)
        .unwrap();
    let mut ch = native_challenger(&mut b);
    verifier
        .observe_commitment_native(&mut b, &mut ch, &cap)
        .unwrap();
    verifier
        .verify_readings_native(&mut b, ch, &cap, core::slice::from_ref(&reading), &targets)
        .unwrap();
    let circuit = b.build().unwrap();

    let mut sampler = Sampler(0x5e1f);
    let point = sampler.point(variables);
    let committed = sampler.bases(1 << high);
    let mut other = committed.clone();
    other[0] += F::ONE;
    for (switched, honest) in [(&committed, true), (&other, false)] {
        let mut prover = challenger();
        let table = Table::new(RowMajorMatrix::new(committed.clone(), committed.len()));
        let witness =
            SuffixProver::<F, E>::new_witness(vec![table], config.round_folding_factor(0));
        let (commitment, data) = inner.commit(witness, &mut prover).unwrap();
        let entry = prover.clone();
        let claims =
            BitRingSwitchClaims::new(vec![BitRingSwitch::<F, E>::new(&point).unwrap()]).unwrap();
        let packing = BitPacking::from_packed(Poly::new(switched.clone())).unwrap();
        let (reduction, survivor, value) = claims.prove::<E, _, _>(&packing, &mut prover);
        let current = claims.reductions()[0].incoming_claim(&reduction.claims[0].tensor);
        let opening = inner
            .open_at(
                data,
                &protocol,
                core::slice::from_ref(&survivor),
                &mut prover,
            )
            .unwrap();
        assert_eq!(opening.evals[0].current()[0] == value, honest);

        let readings = [(Some(current), None)];
        let (ring_input, imported, mut rest) = ring
            .import_native(
                core::slice::from_ref(&point),
                &readings,
                &reduction,
                entry.clone(),
            )
            .unwrap();
        assert_eq!(imported, survivor);
        let whir_input = whir
            .import_native(
                &config,
                &mmcs,
                &commitment,
                &[survivor],
                &opening,
                &mut rest,
            )
            .unwrap();
        let mut private = ring_input
            .private_native_values(&ring.input_shape())
            .unwrap();
        private.extend(
            whir_input
                .private_native_values(&whir.input_shape())
                .unwrap(),
        );
        let whole = verifier.import_native(
            &config,
            &mmcs,
            &commitment,
            core::slice::from_ref(&point),
            &readings,
            &BooleanWhirProof { reduction, opening },
            &mut entry.clone(),
        );
        if honest {
            let whole = whole
                .unwrap()
                .private_native_values(&verifier.input_shape())
                .unwrap();
            assert_eq!(whole, private);
        } else {
            assert!(whole.is_err());
        }

        let mut public: Vec<F> = bytes_to_limbs(&commitment.roots()[0])
            .into_iter()
            .map(|word| H::encode_u16(word).unwrap())
            .collect();
        public.extend(point.iter().flat_map(|x| x.coefficients()));
        public.extend(current.coefficients());
        assert_eq!(accepts(&circuit, &public, &private), honest);
    }
}
