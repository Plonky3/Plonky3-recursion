//! Canonical indexed placements across unequal AIRs and independent providers.
use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_baby_bear::BabyBear;
use p3_binary_field::{Poly64, Poly192};
use p3_bus::BusInteractionBuilder;
use p3_circuit::{CircuitBuilder, ops::ByteHash};
use p3_field::PrimeCharacteristicRing;
use p3_lookup::{IndexedLookupBuilder, indexed::TraceWindow};
use p3_matrix::dense::RowMajorMatrix;
use p3_recursion::artifact::{
    BinaryNativePolyWhirAuthority, BinaryNativePolyWhirLayout, BinaryNativePolyWhirPcsParameters,
    BinaryNativeVerifierSpec, CanonicalBinaryStatement, ExpectedVerifierArtifact,
};
use p3_recursion::{BinaryTower128Challenger, VerifierLimits};
use p3_sumcheck::layout::{PrefixProver, SuffixProver};
use p3_whir::{FoldingFactor, ProtocolParameters, SecurityAssumption};

#[derive(Clone)]
struct IndexedAir {
    width: usize,
    read: Option<(&'static str, Vec<usize>)>,
    provide: Option<(&'static str, Vec<usize>)>,
    preprocessed: bool,
}
fn dense(raw: u64) -> Poly64 {
    Poly64::new(raw.wrapping_mul(0x9157_acde_1234_5678))
}
fn provider_a() -> Vec<Poly64> {
    [2, 7, 3, 11].map(dense).to_vec()
}
impl BaseAir<Poly64> for IndexedAir {
    fn width(&self) -> usize {
        self.width
    }
    fn num_public_values(&self) -> usize {
        1
    }
    fn main_next_row_columns(&self) -> Vec<usize> {
        vec![]
    }
    fn preprocessed_width(&self) -> usize {
        if self.preprocessed { 2 } else { 0 }
    }
    fn preprocessed_next_row_columns(&self) -> Vec<usize> {
        vec![]
    }
    fn preprocessed_trace(&self) -> Option<RowMajorMatrix<Poly64>> {
        self.preprocessed
            .then(|| RowMajorMatrix::new(provider_a(), 2))
    }
}
impl<AB: AirBuilder<F = Poly64> + IndexedLookupBuilder + BusInteractionBuilder> Air<AB>
    for IndexedAir
{
    fn eval(&self, b: &mut AB) {
        let value = b.main().current_slice()[0];
        let public = b.public_values()[0];
        b.when_first_row().assert_eq(value, public);
        if let Some((name, columns)) = &self.provide {
            b.push_indexed_table(
                name,
                if self.preprocessed {
                    TraceWindow::Preprocessed
                } else {
                    TraceWindow::Main
                },
                columns.iter().copied(),
            );
        }
        if let Some((name, payload)) = &self.read {
            b.push_indexed_read(name, 0, payload.iter().copied());
        }
    }
}
fn exercise<L: BinaryNativePolyWhirLayout>(preprocessed: bool) {
    let airs = vec![
        IndexedAir {
            width: 2,
            read: Some(("z", vec![1])),
            provide: None,
            preprocessed: false,
        },
        IndexedAir {
            width: 2,
            read: None,
            provide: Some(("a", vec![1, 0])),
            preprocessed,
        },
        IndexedAir {
            width: 3,
            read: Some(("a", vec![1, 2])),
            provide: None,
            preprocessed: false,
        },
        IndexedAir {
            width: 1,
            read: None,
            provide: Some(("z", vec![0])),
            preprocessed: false,
        },
        IndexedAir {
            width: 2,
            read: Some(("z", vec![1])),
            provide: None,
            preprocessed: false,
        },
    ];
    let params = |n, hash, cap| {
        BinaryNativePolyWhirPcsParameters::new(
            n,
            ProtocolParameters {
                security_level: 24,
                pow_bits: 0,
                round_log_inv_rates: vec![],
                folding_factor: FoldingFactor::Constant(1),
                soundness_type: SecurityAssumption::JohnsonBound,
                starting_log_inv_rate: 2,
            },
            hash,
            cap,
        )
        .unwrap()
    };
    let spec = BinaryNativeVerifierSpec {
        main: params(6, ByteHash::Blake3, 0),
        preprocessed: preprocessed.then(|| params(2, ByteHash::Keccak256, 1)),
        transcript_hash: ByteHash::Blake3,
        initial_bytes: vec![7, 19, 13],
        sumcheck_pow_bits: 0,
        max_tau_draws: 8,
        security_bits: 8,
    };
    let (prover, authority) = BinaryNativePolyWhirAuthority::<_, L>::setup(
        airs,
        vec![3, 1, 2, 2, 1],
        spec,
        &VerifierLimits {
            max_instances: 5,
            ..VerifierLimits::default()
        },
    )
    .unwrap();
    let z = [5, 10, 19, 27].map(dense);
    let a = provider_a();
    let rows = vec![
        [0usize, 1, 3, 2, 2, 0, 1, 3]
            .into_iter()
            .flat_map(|p| [Poly64::new(p as u64), z[p]])
            .collect(),
        a.clone(),
        [0usize, 1, 1, 0]
            .into_iter()
            .flat_map(|p| [Poly64::new(p as u64), a[2 * p + 1], a[2 * p]])
            .collect(),
        z.to_vec(),
        [0usize, 3]
            .into_iter()
            .flat_map(|p| [Poly64::new(p as u64), z[p]])
            .collect(),
    ];
    let public: Vec<_> = rows.iter().map(|r: &Vec<Poly64>| vec![r[0]]).collect();
    let widths = [2, 2, 3, 1, 2];
    let traces = rows
        .into_iter()
        .zip(widths)
        .map(|(r, w)| RowMajorMatrix::new(r, w))
        .collect();
    let mut proof = prover.prove(&public, traces).unwrap();
    let bytes = authority.encode_native_proof(&proof, &public).unwrap();
    let statement = authority.encode_statement(&public).unwrap();
    let identity = authority.canonical_verifier_bytes();
    let checked = authority
        .decode_and_verify(
            identity,
            ExpectedVerifierArtifact::from_trusted_bytes(identity),
            &bytes,
            CanonicalBinaryStatement::new(&statement, 5),
        )
        .unwrap();
    let recursive = authority.recursive_verifier();
    assert_eq!(recursive.input_resource_usage().instances, 5);
    let shape = recursive.input_shape();
    let mut b = CircuitBuilder::<BabyBear>::new();
    b.enable_blake3_compress::<BabyBear>();
    if preprocessed {
        b.enable_keccak_f1600::<BabyBear>();
    }
    let public_targets = (0..5)
        .map(|_| {
            let limbs = core::array::from_fn(|_| b.public_input());
            vec![b.binary_poly64_from_limbs::<BabyBear>(limbs).unwrap()]
        })
        .collect::<Vec<_>>();
    let targets = shape
        .allocate_targets::<BabyBear, BabyBear>(&mut b)
        .unwrap();
    let initial = [7, 19, 13].map(|v| b.define_const(BabyBear::from_u8(v)));
    let ch = BinaryTower128Challenger::with_initial_bytes::<BabyBear, BabyBear>(
        &mut b,
        ByteHash::Blake3,
        &initial,
    )
    .unwrap();
    let _continuation = recursive
        .verify::<BabyBear, BabyBear>(&mut b, ch, &public_targets, &targets)
        .unwrap();
    let circuit = b.build().unwrap();
    let pack =
        |v: Poly64| (0..4).map(move |i| BabyBear::from_u16((v.to_bits() >> (16 * i)) as u16));
    let private = checked
        .native_input()
        .private_values::<BabyBear>(&shape)
        .unwrap();
    let public_limbs = public
        .iter()
        .flatten()
        .copied()
        .flat_map(pack)
        .collect::<Vec<_>>();
    let mut runner = circuit.runner();
    runner.set_private_inputs(&private).unwrap();
    runner.set_public_inputs(&public_limbs).unwrap();
    runner.run().unwrap();
    let saved = proof.indexed.clone();
    for table in 0..2 {
        let claim = &mut proof.indexed.as_mut().unwrap().reduction.column_claims[table][0];
        let mut c = claim.coefficients();
        c[2] += Poly64::ONE;
        *claim = Poly192::new(c);
        assert!(authority.verify_native(&proof, &public).is_err());
        proof.indexed = saved.clone();
    }
}
#[test]
fn mixed_height_providers_preserve_name_and_column_order() {
    exercise::<PrefixProver<Poly64, Poly192>>(false);
    exercise::<SuffixProver<Poly64, Poly192>>(true);
}
