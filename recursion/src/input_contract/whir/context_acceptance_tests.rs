use alloc::vec::Vec;
use alloc::{format, vec};

use p3_baby_bear::BabyBear;
use p3_field::PrimeCharacteristicRing;
use p3_field::extension::BinomialExtensionField;
use p3_merkle_tree::{MerkleCap, PrunedMerklePaths};
use p3_multilinear_util::poly::Poly;
use p3_sumcheck::OpeningBatch;
use p3_sumcheck::strategy::VariableOrder;
use p3_whir::parameters::{FoldingFactor, ProtocolParameters, SecurityAssumption};
use p3_whir::pcs::proof::{QueryOpenings, SharedProofOpening, WhirRoundProof};

use super::{CheckedWhirOpening, ValidatedWhirContext, validate_sumcheck};
use crate::input_contract::stark_layout::{InstanceLayout, NativeStarkLayout};
use crate::pcs::fri::MerkleCapTargets;
use crate::pcs::whir::uni::WhirUniVerifierParams;
use crate::pcs::whir::uni::pcs::WhirUniProof;
use crate::pcs::whir::uni::pcs::tests::MyMmcs;
use crate::pcs::whir::uni::recursive_pcs::DummyChallenger;
use crate::pcs::whir::uni::targets::WhirUniProofTargets;
use crate::verifier::VerificationError;

type F = BabyBear;
type EF = BinomialExtensionField<F, 4>;
type Proof = WhirUniProof<F, EF, MyMmcs>;
type Cap = MerkleCap<F, [F; 8]>;
type Targets = WhirUniProofTargets<F, EF, MyMmcs, 8>;
type CapTargets = MerkleCapTargets<F, 8>;

fn cap(roots: usize) -> Cap {
    MerkleCap::new(vec![[F::ZERO; 8]; roots])
}

fn frontier() -> PrunedMerklePaths<F, 8> {
    PrunedMerklePaths {
        sibling_hashes: vec![],
    }
}

fn sumcheck(rounds: usize, witnesses: usize) -> p3_sumcheck::SumcheckData<F, EF> {
    p3_sumcheck::SumcheckData {
        polynomial_evaluations: vec![[EF::ZERO; 2]; rounds],
        pow_witnesses: vec![F::ZERO; witnesses],
    }
}

fn base_opening(queries: usize, width: usize) -> QueryOpenings<F, EF, PrunedMerklePaths<F, 8>> {
    QueryOpenings::Base(SharedProofOpening {
        rows: vec![vec![F::ZERO; width]; queries],
        proof: frontier(),
    })
}

fn extension_opening(
    queries: usize,
    width: usize,
) -> QueryOpenings<F, EF, PrunedMerklePaths<F, 8>> {
    QueryOpenings::Extension(SharedProofOpening {
        rows: vec![vec![EF::ZERO; width]; queries],
        proof: frontier(),
    })
}

struct Fixture {
    proof: Proof,
    params: WhirUniVerifierParams<F>,
    layout: NativeStarkLayout<'static>,
    caps: Vec<Cap>,
    retained: ValidatedWhirContext<F>,
}

impl Fixture {
    fn canonical() -> Self {
        let protocol = ProtocolParameters {
            starting_log_inv_rate: 6,
            round_log_inv_rates: vec![],
            folding_factor: FoldingFactor::Constant(8),
            soundness_type: SecurityAssumption::CapacityBound,
            security_level: 32,
            pow_bits: 0,
        };
        let params = WhirUniVerifierParams::new(
            protocol,
            VariableOrder::Prefix,
            crate::Poseidon2Config::BABY_BEAR_D4_W16,
        )
        .expect("the canonical test protocol is supported");
        let layout = NativeStarkLayout::new(
            vec![InstanceLayout {
                challenge_width: 4,
                ext_log: 8,
                base_log: 8,
                trace_width: 3,
                trace_next: true,
                pre_width: 0,
                pre_next: false,
                quotient_log: 5,
                quotient_chunks: 32,
                permutation_width: 0,
            }],
            &[],
            false,
            false,
            false,
        )
        .expect("the synthetic trace/quotient route is internally consistent");
        let trace = p3_whir::pcs::proof::PcsProof {
            whir: p3_whir::pcs::proof::WhirProof {
                initial_ood_answers: vec![EF::ZERO],
                initial_sumcheck: sumcheck(8, 0),
                rounds: vec![],
                final_poly: Some(Poly::new(vec![EF::ZERO; 4])),
                final_pow_witness: F::ZERO,
                final_openings: base_opening(6, 256),
                final_sumcheck: Some(sumcheck(2, 0)),
            },
            evals: vec![
                OpeningBatch::new(vec![EF::ZERO; 3], vec![]),
                OpeningBatch::new(vec![EF::ZERO; 3], vec![]),
            ],
        };
        let quotient = p3_whir::pcs::proof::PcsProof {
            whir: p3_whir::pcs::proof::WhirProof {
                initial_ood_answers: vec![EF::ZERO],
                initial_sumcheck: sumcheck(8, 0),
                rounds: vec![WhirRoundProof {
                    commitment: Some(cap(1)),
                    ood_answers: vec![EF::ZERO],
                    pow_witness: F::ZERO,
                    openings: base_opening(6, 256),
                    sumcheck: sumcheck(7, 0),
                }],
                final_poly: Some(Poly::new(vec![EF::ZERO; 1])),
                final_pow_witness: F::ZERO,
                final_openings: extension_opening(3, 128),
                final_sumcheck: None,
            },
            evals: (0..32)
                .map(|_| OpeningBatch::new(vec![EF::ZERO; 4], vec![]))
                .collect(),
        };
        let proof = WhirUniProof {
            rounds: vec![trace, quotient],
        };
        let caps = vec![cap(1), cap(1)];
        let cap_refs = caps.iter().collect::<Vec<_>>();
        let retained = <Targets as CheckedWhirOpening<F, EF, CapTargets>>::validate_whir_context(
            &proof,
            &params,
            layout.opening_view(),
            &cap_refs,
        )
        .expect("the canonical N=10/N=15 contextual shape validates");
        Self {
            proof,
            params,
            layout,
            caps,
            retained,
        }
    }

    fn fresh(
        &self,
        proof: &Proof,
        caps: &[Cap],
    ) -> Result<ValidatedWhirContext<F>, VerificationError> {
        let cap_refs = caps.iter().collect::<Vec<_>>();
        <Targets as CheckedWhirOpening<F, EF, CapTargets>>::validate_whir_context(
            proof,
            &self.params,
            self.layout.opening_view(),
            &cap_refs,
        )
    }

    fn replacement(&self, proof: &Proof, caps: &[Cap]) -> Result<(), VerificationError> {
        let cap_refs = caps.iter().collect::<Vec<_>>();
        <Targets as CheckedWhirOpening<F, EF, CapTargets>>::validate_whir_replacement(
            proof,
            &self.retained,
            self.layout.opening_view(),
            &cap_refs,
        )
    }

    fn assert_rejected(&self, proof: &Proof, caps: &[Cap], component: &str) {
        let fresh = match self.fresh(proof, caps) {
            Ok(_) => panic!("fresh WHIR context accepted malformed {component}"),
            Err(error) => error,
        };
        let replacement = self
            .replacement(proof, caps)
            .expect_err("retained WHIR context accepted malformed replacement");
        for (stage, error) in [("fresh", fresh), ("retained", replacement)] {
            assert!(
                matches!(error, VerificationError::InvalidProofShape(_)),
                "{stage} {component} returned the wrong error variant: {error:?}"
            );
            let message = format!("{error:?}");
            assert!(
                message.contains(component),
                "{stage} error did not identify {component}: {message}"
            );
        }
    }

    fn assert_accepted(&self, proof: &Proof, caps: &[Cap], description: &str) {
        self.fresh(proof, caps)
            .unwrap_or_else(|error| panic!("fresh {description} rejected: {error:?}"));
        self.replacement(proof, caps)
            .unwrap_or_else(|error| panic!("retained {description} rejected: {error:?}"));
    }
}

fn replace_batch(batch: &mut OpeningBatch<EF>, current: usize, next: usize) {
    *batch = OpeningBatch::new(vec![EF::ZERO; current], vec![EF::ZERO; next]);
}

fn set_rows(
    openings: &mut QueryOpenings<F, EF, PrunedMerklePaths<F, 8>>,
    rows: usize,
    width: usize,
) {
    *openings = match openings {
        QueryOpenings::Base(_) => base_opening(rows, width),
        QueryOpenings::Extension(_) => extension_opening(rows, width),
    };
}

fn flip_field(openings: &mut QueryOpenings<F, EF, PrunedMerklePaths<F, 8>>) {
    *openings = match openings {
        QueryOpenings::Base(opening) => {
            extension_opening(opening.rows.len(), opening.rows[0].len())
        }
        QueryOpenings::Extension(opening) => {
            base_opening(opening.rows.len(), opening.rows[0].len())
        }
    };
}

fn add_frontier_hash(openings: &mut QueryOpenings<F, EF, PrunedMerklePaths<F, 8>>, value: F) {
    match openings {
        QueryOpenings::Base(opening) => opening.proof.sibling_hashes.push([value; 8]),
        QueryOpenings::Extension(opening) => opening.proof.sibling_hashes.push([value; 8]),
    }
}

#[test]
fn n10_n15_opening_batches_bind_every_later_width_and_partition() {
    let fixture = Fixture::canonical();

    for width in [3, 5] {
        let mut proof = fixture.proof.clone();
        replace_batch(&mut proof.rounds[1].evals[31], width, 0);
        fixture.assert_rejected(&proof, &fixture.caps, "opening batch 31");
    }

    let mut nonfirst_point = fixture.proof.clone();
    replace_batch(&mut nonfirst_point.rounds[0].evals[1], 2, 0);
    fixture.assert_rejected(&nonfirst_point, &fixture.caps, "opening batch 1");

    let mut next = fixture.proof.clone();
    replace_batch(&mut next.rounds[1].evals[31], 4, 1);
    fixture.assert_rejected(&next, &fixture.caps, "uni openings");

    let mut extra_batch = fixture.proof.clone();
    extra_batch.rounds[1]
        .evals
        .push(OpeningBatch::new(vec![EF::ZERO; 4], vec![]));
    fixture.assert_rejected(&extra_batch, &fixture.caps, "opening batch count");
}

#[test]
fn n15_intermediate_phase_binds_field_queries_width_ood_and_next_fold() {
    let fixture = Fixture::canonical();

    let mut flipped = fixture.proof.clone();
    flip_field(&mut flipped.rounds[1].whir.rounds[0].openings);
    fixture.assert_rejected(&flipped, &fixture.caps, "intermediate");

    for queries in [5, 7] {
        let mut proof = fixture.proof.clone();
        set_rows(&mut proof.rounds[1].whir.rounds[0].openings, queries, 256);
        fixture.assert_rejected(&proof, &fixture.caps, "intermediate");
    }
    for width in [255, 257] {
        let mut proof = fixture.proof.clone();
        set_rows(&mut proof.rounds[1].whir.rounds[0].openings, 6, 256);
        match &mut proof.rounds[1].whir.rounds[0].openings {
            QueryOpenings::Base(opening) => opening.rows[5] = vec![F::ZERO; width],
            QueryOpenings::Extension(_) => unreachable!(),
        }
        fixture.assert_rejected(&proof, &fixture.caps, "intermediate");
    }

    for ood_answers in [0, 2] {
        let mut proof = fixture.proof.clone();
        proof.rounds[1].whir.rounds[0].ood_answers = vec![EF::ZERO; ood_answers];
        fixture.assert_rejected(&proof, &fixture.caps, "intermediate round 0 OOD");
    }

    let mut truncated_next_fold = fixture.proof.clone();
    truncated_next_fold.rounds[1].whir.rounds[0].sumcheck = sumcheck(6, 0);
    fixture.assert_rejected(&truncated_next_fold, &fixture.caps, "intermediate sumcheck");

    for intermediate_rounds in [0, 2] {
        let mut proof = fixture.proof.clone();
        proof.rounds[1].whir.rounds = if intermediate_rounds == 0 {
            vec![]
        } else {
            vec![proof.rounds[1].whir.rounds[0].clone(); 2]
        };
        fixture.assert_rejected(&proof, &fixture.caps, "intermediate round count");
    }
}

#[test]
fn n10_n15_final_phase_binds_field_queries_width_polynomial_and_required_sumcheck() {
    let fixture = Fixture::canonical();

    for argument in [0, 1] {
        let mut proof = fixture.proof.clone();
        flip_field(&mut proof.rounds[argument].whir.final_openings);
        fixture.assert_rejected(&proof, &fixture.caps, "final");
    }

    for queries in [2, 4] {
        let mut proof = fixture.proof.clone();
        set_rows(&mut proof.rounds[1].whir.final_openings, queries, 128);
        fixture.assert_rejected(&proof, &fixture.caps, "final");
    }
    for width in [127, 129, 256] {
        let mut proof = fixture.proof.clone();
        set_rows(&mut proof.rounds[1].whir.final_openings, 3, 128);
        match &mut proof.rounds[1].whir.final_openings {
            QueryOpenings::Extension(opening) => opening.rows[2] = vec![EF::ZERO; width],
            QueryOpenings::Base(_) => unreachable!(),
        }
        fixture.assert_rejected(&proof, &fixture.caps, "final");
    }

    let mut confused_with_plain_sumcheck = fixture.proof.clone();
    set_rows(
        &mut confused_with_plain_sumcheck.rounds[0].whir.final_openings,
        6,
        4,
    );
    fixture.assert_rejected(&confused_with_plain_sumcheck, &fixture.caps, "final");

    for poly_len in [2, 8] {
        let mut proof = fixture.proof.clone();
        proof.rounds[0].whir.final_poly = Some(Poly::new(vec![EF::ZERO; poly_len]));
        fixture.assert_rejected(&proof, &fixture.caps, "final polynomial");
    }

    let mut missing = fixture.proof.clone();
    missing.rounds[0].whir.final_sumcheck = None;
    fixture.assert_rejected(&missing, &fixture.caps, "final sumcheck");
    for rounds in [1, 3] {
        let mut proof = fixture.proof.clone();
        proof.rounds[0].whir.final_sumcheck = Some(sumcheck(rounds, 0));
        fixture.assert_rejected(&proof, &fixture.caps, "final sumcheck");
    }
}

#[test]
fn n10_n15_caps_bind_following_tree_geometry_for_fresh_and_retained_inputs() {
    let fixture = Fixture::canonical();

    // `MerkleCap` refuses an empty or non-power-of-two root count on every construction
    // path, the wire decoder included, so only a well-formed cap taller than the tree it
    // commits to can reach validation.
    for bytes in [
        postcard::to_allocvec(&Vec::<[F; 8]>::new()),
        postcard::to_allocvec(&vec![[F::ZERO; 8]; 3]),
    ] {
        let bytes = bytes.expect("the raw cap payload serializes");
        assert!(postcard::from_bytes::<Cap>(&bytes).is_err());
    }
    let roots = 1 << 16;
    let mut caps = fixture.caps.clone();
    caps[1] = cap(roots);
    fixture.assert_rejected(&fixture.proof, &caps, "cap");

    let mut proof = fixture.proof.clone();
    proof.rounds[1].whir.rounds[0].commitment = Some(cap(roots));
    fixture.assert_rejected(&proof, &fixture.caps, "cap");
}

#[test]
fn n10_n15_additional_initial_counts_reject_at_the_named_phase() {
    let fixture = Fixture::canonical();

    let mut extra_ood = fixture.proof.clone();
    extra_ood.rounds[1].whir.initial_ood_answers = vec![EF::ZERO; 2];
    fixture.assert_rejected(&extra_ood, &fixture.caps, "initial OOD");

    for rounds in [7, 9] {
        let mut proof = fixture.proof.clone();
        proof.rounds[1].whir.initial_sumcheck = sumcheck(rounds, 0);
        fixture.assert_rejected(&proof, &fixture.caps, "initial sumcheck");
    }
}

#[test]
fn n10_n15_zero_pow_payloads_are_fresh_semantic_but_retained_allocation_state() {
    let fixture = Fixture::canonical();

    let cases: [(usize, usize, usize); 11] = [
        (0, 0, 1),
        (0, 0, 8),
        (0, 0, 9),
        (0, 2, 1),
        (0, 2, 2),
        (0, 2, 3),
        (1, 0, 8),
        (1, 0, 9),
        (1, 1, 1),
        (1, 1, 7),
        (1, 1, 8),
    ];
    for (argument, phase, witnesses) in cases {
        let mut proof = fixture.proof.clone();
        match (argument, phase) {
            (0, 0) | (1, 0) => {
                proof.rounds[argument].whir.initial_sumcheck.pow_witnesses =
                    vec![F::ZERO; witnesses];
            }
            (1, 1) => {
                proof.rounds[1].whir.rounds[0].sumcheck.pow_witnesses = vec![F::ZERO; witnesses];
            }
            (0, 2) => {
                proof.rounds[0]
                    .whir
                    .final_sumcheck
                    .as_mut()
                    .unwrap()
                    .pow_witnesses = vec![F::ZERO; witnesses];
            }
            _ => unreachable!(),
        }
        fixture
            .fresh(&proof, &fixture.caps)
            .unwrap_or_else(|error| panic!("zero-PoW payload rejected: {error:?}"));
        let error = fixture
            .replacement(&proof, &fixture.caps)
            .expect_err("changed ignored payload allocation must not replace retained targets");
        assert!(format!("{error:?}").contains("allocation or cap authority"));
    }

    let mut scalar_only = fixture.proof.clone();
    scalar_only.rounds[1].whir.rounds[0].pow_witness = F::ONE;
    scalar_only.rounds[0].whir.final_pow_witness = F::ONE;
    fixture.assert_accepted(
        &scalar_only,
        &fixture.caps,
        "ignored zero-PoW scalar-value change",
    );
}

#[test]
fn n10_n15_dynamic_frontiers_remain_compatible_with_retained_allocation() {
    let fixture = Fixture::canonical();

    for phase in 0..3 {
        let mut proof = fixture.proof.clone();
        match phase {
            0 => add_frontier_hash(&mut proof.rounds[0].whir.final_openings, F::ONE),
            1 => add_frontier_hash(&mut proof.rounds[1].whir.rounds[0].openings, F::ONE),
            2 => add_frontier_hash(&mut proof.rounds[1].whir.final_openings, F::ONE),
            _ => unreachable!(),
        }
        fixture.assert_accepted(&proof, &fixture.caps, "dynamic frontier change");
    }
}

#[test]
fn consumed_pow_companion_requires_one_witness_per_consumed_sumcheck_round() {
    let protocol = ProtocolParameters {
        starting_log_inv_rate: 8,
        round_log_inv_rates: vec![],
        folding_factor: FoldingFactor::Constant(8),
        soundness_type: SecurityAssumption::UniqueDecoding,
        security_level: 124,
        pow_bits: 24,
    };
    let params = WhirUniVerifierParams::<F>::new(
        protocol,
        VariableOrder::Prefix,
        crate::Poseidon2Config::BABY_BEAR_D4_W16,
    )
    .expect("the consumed-PoW companion protocol is supported");
    let n10 = params
        .round_params::<EF, DummyChallenger<F>>(10)
        .expect("N=10 companion parameters derive");
    let n15 = params
        .round_params::<EF, DummyChallenger<F>>(15)
        .expect("N=15 companion parameters derive");

    assert_eq!(n10.starting_folding_pow_bits(), 18);
    assert_eq!(n15.starting_folding_pow_bits(), 23);
    assert_eq!(n15.round_params()[0].pow_bits(), 24);
    assert_eq!(n15.round_params()[0].folding_pow_bits(), 22);
    assert_eq!(n10.final_pow_bits(), 24);
    assert_eq!(n10.final_folding_pow_bits(), 1);
    assert_eq!(n15.final_folding_pow_bits(), 1);

    for (label, rounds, pow_bits) in [
        ("N=10 initial", 8, n10.starting_folding_pow_bits()),
        ("N=15 initial", 8, n15.starting_folding_pow_bits()),
        (
            "N=15 intermediate",
            7,
            n15.round_params()[0].folding_pow_bits(),
        ),
        ("N=10 final", 2, n10.final_folding_pow_bits()),
    ] {
        validate_sumcheck(&sumcheck(rounds, rounds), rounds, pow_bits, label)
            .unwrap_or_else(|error| panic!("canonical consumed witnesses rejected: {error:?}"));
        for witnesses in [rounds - 1, rounds + 1] {
            let error = validate_sumcheck(&sumcheck(rounds, witnesses), rounds, pow_bits, label)
                .expect_err("missing or extra consumed witness must reject");
            assert!(matches!(error, VerificationError::InvalidProofShape(_)));
            assert!(format!("{error:?}").contains(label));
        }
    }
}
