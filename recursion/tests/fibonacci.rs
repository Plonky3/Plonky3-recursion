use core::borrow::Borrow;

use p3_air::{Air, AirBuilder, AirBuilderWithPublicValues, BaseAir};
use p3_baby_bear::{BabyBear, Poseidon2BabyBear};
use p3_challenger::DuplexChallenger;
use p3_circuit::utils::{ColumnsTargets, symbolic_to_circuit};
use p3_circuit::{CircuitBuilder, CircuitError, ExprId};
use p3_commit::ExtensionMmcs;
use p3_dft::Radix2DitParallel;
use p3_field::extension::BinomialExtensionField;
use p3_field::{Field, PrimeCharacteristicRing, PrimeField64};
use p3_fri::{TwoAdicFriPcs, create_test_fri_params};
use p3_matrix::Matrix;
use p3_matrix::dense::RowMajorMatrix;
use p3_merkle_tree::MerkleTreeMmcs;
use p3_recursion::recursive_pcs::{
    FriProofTargets, HashTargets, InputProofTargets, RecExtensionValMmcs, RecValMmcs, Witness,
};
use p3_recursion::recursive_traits::{
    ProofTargets, Recursive, RecursiveAir, RecursiveLagrangeSelectors,
};
use p3_symmetric::{PaddingFreeSponge, TruncatedPermutation};
use p3_uni_stark::{
    StarkConfig, SymbolicExpression, get_log_quotient_degree, get_symbolic_constraints, prove,
    verify,
};
use rand::SeedableRng;
use rand::rngs::SmallRng;

/// For testing the public values feature
pub struct FibonacciAir {}

impl<F> BaseAir<F> for FibonacciAir {
    fn width(&self) -> usize {
        NUM_FIBONACCI_COLS
    }
}

impl<AB: AirBuilderWithPublicValues> Air<AB> for FibonacciAir {
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();

        let pis = builder.public_values();

        let a = pis[0];
        let b = pis[1];
        let x = pis[2];

        let (local, next) = (
            main.row_slice(0).expect("Matrix is empty?"),
            main.row_slice(1).expect("Matrix only has 1 row?"),
        );
        let local: &FibonacciRow<AB::Var> = (*local).borrow();
        let next: &FibonacciRow<AB::Var> = (*next).borrow();

        let mut when_first_row = builder.when_first_row();

        when_first_row.assert_eq(local.left.clone(), a);
        when_first_row.assert_eq(local.right.clone(), b);

        let mut when_transition = builder.when_transition();

        // a' <- b
        when_transition.assert_eq(local.right.clone(), next.left.clone());

        // b' <- a + b
        when_transition.assert_eq(local.left.clone() + local.right.clone(), next.right.clone());

        builder.when_last_row().assert_eq(local.right.clone(), x);
    }
}

pub fn generate_trace_rows<F: PrimeField64>(a: u64, b: u64, n: usize) -> RowMajorMatrix<F> {
    assert!(n.is_power_of_two());

    let mut trace = RowMajorMatrix::new(F::zero_vec(n * NUM_FIBONACCI_COLS), NUM_FIBONACCI_COLS);

    let (prefix, rows, suffix) = unsafe { trace.values.align_to_mut::<FibonacciRow<F>>() };
    assert!(prefix.is_empty(), "Alignment should match");
    assert!(suffix.is_empty(), "Alignment should match");
    assert_eq!(rows.len(), n);

    rows[0] = FibonacciRow::new(F::from_u64(a), F::from_u64(b));

    for i in 1..n {
        rows[i].left = rows[i - 1].right;
        rows[i].right = rows[i - 1].left + rows[i - 1].right;
    }

    trace
}

impl<EF: Field> RecursiveAir<EF> for FibonacciAir {
    fn width(&self) -> usize {
        <Self as BaseAir<F>>::width(self)
    }

    fn eval_folded_circuit(
        &self,
        builder: &mut CircuitBuilder<EF>,
        sels: &RecursiveLagrangeSelectors,
        alpha: &ExprId,
        columns: ColumnsTargets,
    ) -> ExprId {
        let symbolic_constraints: Vec<SymbolicExpression<EF>> =
            get_symbolic_constraints(&FibonacciAir {}, 0, columns.public_values.len());

        let mut acc = builder.add_const(EF::ZERO);
        for s_c in symbolic_constraints {
            let mul_prev = builder.mul(acc, *alpha);
            let constraints = symbolic_to_circuit(sels.row_selectors, &columns, &s_c, builder);
            acc = builder.add(mul_prev, constraints);
        }

        acc
    }

    fn get_log_quotient_degree(&self, num_public_values: usize, is_zk: usize) -> usize {
        let air = FibonacciAir {};
        get_log_quotient_degree::<F, FibonacciAir>(&air, 0, num_public_values, is_zk)
    }
}

const NUM_FIBONACCI_COLS: usize = 2;

pub struct FibonacciRow<F> {
    pub left: F,
    pub right: F,
}

impl<F> FibonacciRow<F> {
    const fn new(left: F, right: F) -> Self {
        Self { left, right }
    }
}

impl<F> Borrow<FibonacciRow<F>> for [F] {
    fn borrow(&self) -> &FibonacciRow<F> {
        debug_assert_eq!(self.len(), NUM_FIBONACCI_COLS);
        let (prefix, shorts, suffix) = unsafe { self.align_to::<FibonacciRow<F>>() };
        debug_assert!(prefix.is_empty(), "Alignment should match");
        debug_assert!(suffix.is_empty(), "Alignment should match");
        debug_assert_eq!(shorts.len(), 1);
        &shorts[0]
    }
}

type F = BabyBear;
const D: usize = 4;
type Challenge = BinomialExtensionField<F, D>;
type Dft = Radix2DitParallel<F>;
type Perm = Poseidon2BabyBear<16>;
type MyHash = PaddingFreeSponge<Perm, 16, 8, 8>;
type MyCompress = TruncatedPermutation<Perm, 2, 8, 16>;
type ValMmcs = MerkleTreeMmcs<<F as Field>::Packing, <F as Field>::Packing, MyHash, MyCompress, 8>;
type ChallengeMmcs = ExtensionMmcs<F, Challenge, ValMmcs>;
type Challenger = DuplexChallenger<F, Perm, 16, 8>;
type MyPcs = TwoAdicFriPcs<F, Dft, ValMmcs, ChallengeMmcs>;
type MyConfig = StarkConfig<MyPcs, Challenge, Challenger>;

#[test]
fn test_fibonacci_verifier() -> Result<(), CircuitError> {
    let mut rng = SmallRng::seed_from_u64(1);
    let n = 1 << 3;
    let x = 21;

    let perm = Perm::new_from_rng_128(&mut rng);
    let hash = MyHash::new(perm.clone());
    let compress = MyCompress::new(perm.clone());
    let val_mmcs = ValMmcs::new(hash, compress);
    let challenge_mmcs = ChallengeMmcs::new(val_mmcs.clone());
    let dft = Dft::default();
    let trace = generate_trace_rows::<F>(0, 1, n);
    let fri_params = create_test_fri_params(challenge_mmcs, 1);
    let pcs = MyPcs::new(dft, val_mmcs, fri_params);
    let challenger = Challenger::new(perm);

    let config = MyConfig::new(pcs, challenger);
    let pis = vec![BabyBear::ZERO, BabyBear::ONE, BabyBear::from_u64(x)];

    let proof = prove(&config, &FibonacciAir {}, trace, &pis);
    assert!(verify(&config, &FibonacciAir {}, &proof, &pis).is_ok());

    const DIGEST_ELEMS: usize = 8;

    // Initialize the circuit builder.
    let mut circuit_builder = CircuitBuilder::<Challenge>::new();

    // Determine the lengths of all the vectors within the proof.
    let mut all_lens = ProofTargets::<
        MyConfig,
        HashTargets<F, DIGEST_ELEMS>,
        FriProofTargets<
            F,
            Challenge,
            RecExtensionValMmcs<
                F,
                Challenge,
                DIGEST_ELEMS,
                RecValMmcs<F, DIGEST_ELEMS, MyHash, MyCompress>,
            >,
            InputProofTargets<F, Challenge, RecValMmcs<F, DIGEST_ELEMS, MyHash, MyCompress>>,
            Witness<F>,
        >,
    >::lens(&proof);

    // Add the wires for the proof.
    let proof_circuit = ProofTargets::<
        MyConfig,
        HashTargets<F, DIGEST_ELEMS>,
        FriProofTargets<
            F,
            Challenge,
            RecExtensionValMmcs<
                F,
                Challenge,
                DIGEST_ELEMS,
                RecValMmcs<F, DIGEST_ELEMS, MyHash, MyCompress>,
            >,
            InputProofTargets<F, Challenge, RecValMmcs<F, DIGEST_ELEMS, MyHash, MyCompress>>,
            Witness<F>,
        >,
    >::new(&mut circuit_builder, &mut all_lens, proof.degree_bits);

    let all_proof_values = ProofTargets::<
        MyConfig,
        HashTargets<F, DIGEST_ELEMS>,
        FriProofTargets<
            F,
            Challenge,
            RecExtensionValMmcs<
                F,
                Challenge,
                DIGEST_ELEMS,
                RecValMmcs<F, DIGEST_ELEMS, MyHash, MyCompress>,
            >,
            InputProofTargets<F, Challenge, RecValMmcs<F, DIGEST_ELEMS, MyHash, MyCompress>>,
            Witness<F>,
        >,
    >::get_values(&proof);

    println!(
        "proof wires: {:?}",
        proof_circuit.commitments_targets.trace_targets.hash_targets
    );
    let circuit = circuit_builder.build().unwrap();
    let mut runner = circuit.runner();
    runner.set_public_inputs(&all_proof_values)
}
