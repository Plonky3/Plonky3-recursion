//! Closed native grouped owners retain their AIR and independent PCS policies.

use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_binary_field::{BinaryField8, BinaryField64, BinaryField128, TowerLevel};
use p3_binary_pcs::{BinaryPcsConfig, BinaryPcsParams};
use p3_bus::{BusActivation, BusDirection, BusInteractionBuilder, BusName};
use p3_circuit::ops::ByteHash;
use p3_field::PrimeCharacteristicRing;
use p3_lookup::IndexedLookupBuilder;
use p3_lookup::indexed::TraceWindow;
use p3_matrix::dense::RowMajorMatrix;
use p3_recursion::artifact::{
    BinaryNativeGroupedAuthority, BinaryNativeGroupedPcsParameters,
    BinaryNativeGroupedVerifierSpec, BinaryNativePcsParameters,
};
use p3_recursion::pcs::binary::{BinaryCodewordGrouping, RecursiveBinaryTowerField};
use p3_recursion::verifier::{VerificationError, VerifierLimits};

struct ConstantAir;
impl<F> BaseAir<F> for ConstantAir {
    fn width(&self) -> usize {
        1
    }
    fn num_public_values(&self) -> usize {
        1
    }
}
impl<AB: AirBuilder> Air<AB> for ConstantAir {
    fn eval(&self, b: &mut AB) {
        b.assert_eq(b.main().current_slice()[0], b.public_values()[0]);
    }
}

macro_rules! check {
    ($f:ty, $e:ty, $security:expr, $target:expr) => {{
        type F = $f;
        type E = $e;
        for hash in [ByteHash::Keccak256, ByteHash::Blake3] {
            let main = BinaryNativeGroupedPcsParameters {
                pcs: BinaryNativePcsParameters {
                    config: BinaryPcsConfig::try_new::<F, E>(
                        1,
                        BinaryPcsParams {
                            log_inv_rate: 2,
                            pow_bits: 0,
                            security_level: $security,
                        },
                    )
                    .unwrap(),
                    hash,
                    cap_height: 0,
                    max_query_draws: 128,
                },
                base_grouping: BinaryCodewordGrouping::Codeword(8),
                round_grouping: BinaryCodewordGrouping::Folding,
            };
            let (prover, authority) = BinaryNativeGroupedAuthority::<F, E, _>::setup(
                vec![ConstantAir],
                vec![1],
                BinaryNativeGroupedVerifierSpec {
                    main,
                    preprocessed: None,
                    transcript_hash: hash,
                    initial_bytes: vec![0, 19, 255],
                    sumcheck_pow_bits: 0,
                    max_tau_draws: 8,
                    security_bits: $target,
                },
                &VerifierLimits::default(),
            )
            .unwrap();
            for raw in [0xabu128, u128::MAX] {
                let value =
                    F::from_le_byte_iter(raw.to_le_bytes().into_iter().take(F::RAW_BITS / 8));
                let public = vec![vec![value]];
                let proof = prover
                    .prove(&public, vec![RowMajorMatrix::new(vec![value; 2], 1)])
                    .unwrap();
                let token = authority.verify_native(&proof, &public).unwrap();
                assert_eq!(token.public_values(), public);
                assert_eq!(
                    token.canonical_verifier_bytes(),
                    authority.canonical_verifier_bytes()
                );
                token
                    .native_input()
                    .private_values::<p3_baby_bear::BabyBear>(
                        &authority.recursive_verifier().input_shape(),
                    )
                    .unwrap();
                let mut wrong = public.clone();
                wrong[0][0] += F::ONE;
                assert!(authority.verify_native(&proof, &wrong).is_err());
                assert!(authority.verify_native(&proof, &[]).is_err());
                assert!(
                    prover
                        .prove(&public, vec![RowMajorMatrix::new(vec![value; 4], 1)])
                        .is_err()
                );
            }
        }
    }};
}

#[test]
fn native_grouped_owners_verify_narrow_and_wide_fields_under_both_hashes() {
    check!(BinaryField8, BinaryField64, 24, 16);
    check!(BinaryField128, BinaryField128, 8, 4);
}

struct CoupledAir {
    provider: bool,
}
impl BaseAir<BinaryField8> for CoupledAir {
    fn width(&self) -> usize {
        3
    }
    fn num_public_values(&self) -> usize {
        1
    }
    fn preprocessed_width(&self) -> usize {
        usize::from(self.provider)
    }
    fn preprocessed_trace(&self) -> Option<RowMajorMatrix<BinaryField8>> {
        self.provider
            .then(|| RowMajorMatrix::new((7u8..15).map(BinaryField8::from_repr).collect(), 1))
    }
}
impl<AB: AirBuilder<F = BinaryField8> + IndexedLookupBuilder + BusInteractionBuilder> Air<AB>
    for CoupledAir
{
    fn eval(&self, b: &mut AB) {
        b.assert_eq(b.main().current_slice()[2], b.public_values()[0]);
        let (payload, direction) = if self.provider {
            b.push_indexed_table("payload", TraceWindow::Preprocessed, [0]);
            (b.preprocessed().current_slice()[0], BusDirection::Pull)
        } else {
            b.push_indexed_read("payload", 0, [1]);
            (b.main().current_slice()[1], BusDirection::Push)
        };
        b.push_bus_interaction(
            BusName::new("payload"),
            direction,
            [payload],
            BusActivation::Always,
        );
    }
}

#[derive(serde::Deserialize)]
struct GroupedView<T> {
    inner: p3_merkle_tree::PrunedMerklePaths<u8, 32>,
    missing_symbols: Vec<T>,
}
fn frontier_count<T: serde::de::DeserializeOwned>(p: &impl serde::Serialize) -> usize {
    let bytes = postcard::to_allocvec(p).unwrap();
    let view: GroupedView<T> = postcard::from_bytes(&bytes).unwrap();
    assert!(view.missing_symbols.len() <= 256);
    view.inner.sibling_hashes.len()
}

#[test]
fn native_grouped_authority_authenticates_bus_indexed_and_independent_preprocessing() {
    type F = BinaryField8;
    type E = BinaryField64;
    let pcs = |n, hash, cap_height| BinaryNativeGroupedPcsParameters {
        pcs: BinaryNativePcsParameters {
            config: BinaryPcsConfig::try_new::<F, E>(
                n,
                BinaryPcsParams {
                    log_inv_rate: if n == 3 { 5 } else { 2 },
                    pow_bits: 0,
                    security_level: 24,
                },
            )
            .unwrap()
            .try_with_folding(2)
            .unwrap(),
            hash,
            cap_height,
            max_query_draws: 512,
        },
        base_grouping: BinaryCodewordGrouping::Message(8),
        round_grouping: BinaryCodewordGrouping::Folding,
    };
    let spec = BinaryNativeGroupedVerifierSpec {
        main: pcs(6, ByteHash::Keccak256, 0),
        preprocessed: Some(pcs(3, ByteHash::Blake3, 1)),
        transcript_hash: ByteHash::Blake3,
        initial_bytes: vec![7, 19, 13],
        sumcheck_pow_bits: 0,
        max_tau_draws: 8,
        security_bits: 16,
    };
    let airs = || {
        vec![
            CoupledAir { provider: false },
            CoupledAir { provider: true },
        ]
    };
    let (prover, authority) = BinaryNativeGroupedAuthority::<F, E, _>::setup(
        airs(),
        vec![3, 3],
        spec.clone(),
        &VerifierLimits::default(),
    )
    .unwrap();
    let public = vec![vec![F::from_repr(0x53)], vec![F::from_repr(0x97)]];
    let reader = (0u8..8)
        .flat_map(|i| [F::from_repr(i), F::from_repr(i + 7), public[0][0]])
        .collect();
    let provider = (0u8..8)
        .flat_map(|i| [F::from_repr(i), F::from_repr(27), public[1][0]])
        .collect();
    let mut proof = prover
        .prove(
            &public,
            vec![
                RowMajorMatrix::new(reader, 3),
                RowMajorMatrix::new(provider, 3),
            ],
        )
        .unwrap();
    assert!(proof.bus.is_some() && proof.indexed.is_some() && proof.preprocessed_opening.is_some());
    let token = authority.verify_native(&proof, &public).unwrap();
    assert_eq!(token.public_values(), public);
    let count = |p: &p3_multi_stark::config::PcsProof<
        p3_recursion::artifact::BinaryNativeGroupedConfig<F, E>,
    >| {
        frontier_count::<F>(&p.base_multi_proof)
            + p.rounds
                .iter()
                .map(|r| frontier_count::<E>(&r.multi_proof))
                .sum::<usize>()
    };
    let main = count(&proof.opening);
    let pp = count(proof.preprocessed_opening.as_ref().unwrap());
    assert!(
        main > 0 && pp > 0,
        "main frontiers: {main}, preprocessing frontiers: {pp}"
    );
    let limits = VerifierLimits {
        max_compressed_frontier_hashes: main + pp - 1,
        ..VerifierLimits::default()
    };
    let (_, bounded) =
        BinaryNativeGroupedAuthority::<F, E, _>::setup(airs(), vec![3, 3], spec, &limits).unwrap();
    assert!(matches!(
        bounded.verify_native(&proof, &public),
        Err(VerificationError::ResourceLimitExceeded {
            component: "compressed frontier hashes",
            ..
        })
    ));
    proof.bus.as_mut().unwrap().product.roots[0] += E::ONE;
    assert!(authority.verify_native(&proof, &public).is_err());
}
