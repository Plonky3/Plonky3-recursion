use p3_air::{Air, BaseAir};
use p3_baby_bear::{BabyBear, Poseidon2BabyBear};
use p3_challenger::DuplexChallenger;
use p3_circuit::utils::{ColumnsTargets, RowSelectorsTargets, symbolic_to_circuit};
use p3_circuit::{CircuitBuilder, CircuitError};
use p3_circuit_prover::air::{AddAir, ConstAir, MulAir, PublicAir, WitnessAir};
use p3_commit::ExtensionMmcs;
use p3_dft::Radix2DitParallel;
use p3_field::{Field, PrimeCharacteristicRing};
use p3_fri::TwoAdicFriPcs;
use p3_matrix::dense::RowMajorMatrixView;
use p3_matrix::stack::VerticalPair;
use p3_merkle_tree::MerkleTreeMmcs;
use p3_poseidon2_air::RoundConstants;
use p3_poseidon2_circuit_air::Poseidon2CircuitAirBabyBearD4Width16;
use p3_symmetric::{PaddingFreeSponge, TruncatedPermutation};
use p3_uni_stark::{
    SymbolicAirBuilder, SymbolicExpression, VerifierConstraintFolder, get_symbolic_constraints,
};
use rand::rngs::SmallRng;
use rand::{Rng, RngCore, SeedableRng};

type F = BabyBear;

const RATE: usize = 8;
type Dft = Radix2DitParallel<F>;
type Perm = Poseidon2BabyBear<16>;
type MyHash = PaddingFreeSponge<Perm, 16, RATE, 8>;
type MyCompress = TruncatedPermutation<Perm, 2, 8, 16>;
type ValMmcs =
    MerkleTreeMmcs<<F as Field>::Packing, <F as Field>::Packing, MyHash, MyCompress, 8>;
type ChallengeMmcs = ExtensionMmcs<F, F, ValMmcs>;
type Challenger = DuplexChallenger<F, Perm, 16, RATE>;
type MyPcs = TwoAdicFriPcs<F, Dft, ValMmcs, ChallengeMmcs>;
type MyConfig = p3_uni_stark::StarkConfig<MyPcs, F, Challenger>;

fn run_recursive<A>(
    air: &A,
    preprocessed_width: usize,
    num_public_values: usize,
    rng: &mut SmallRng,
) -> Result<(), CircuitError>
where
    A: BaseAir<F>
        + Air<SymbolicAirBuilder<F>>
        + for<'a> Air<VerifierConstraintFolder<'a, MyConfig>>,
{
    let width = air.width();

    let mut trace_local: Vec<F> = (0..width).map(|_| rng.random()).collect();
    let mut trace_next: Vec<F> = (0..width).map(|_| rng.random()).collect();
    let mut preprocessed_local: Vec<F> = (0..preprocessed_width).map(|_| rng.random()).collect();
    let mut preprocessed_next: Vec<F> = (0..preprocessed_width).map(|_| rng.random()).collect();
    let public_values: Vec<F> = (0..num_public_values)
        .map(|_| F::from_u32(rng.next_u32()))
        .collect();
    let selectors: [F; 3] = [rng.random(), rng.random(), rng.random()];
    let alpha: F = rng.random();

    let symbolic_constraints = get_symbolic_constraints(air, preprocessed_width, num_public_values);

    // Native folded value using the verifier folder (avoids deep recursion).
    let main = VerticalPair::new(
        RowMajorMatrixView::new_row(&trace_local),
        RowMajorMatrixView::new_row(&trace_next),
    );
    let preprocessed = if preprocessed_width > 0 {
        Some(VerticalPair::new(
            RowMajorMatrixView::new_row(&preprocessed_local),
            RowMajorMatrixView::new_row(&preprocessed_next),
        ))
    } else {
        None
    };
    let mut folder: VerifierConstraintFolder<'_, MyConfig> = VerifierConstraintFolder {
        main,
        preprocessed,
        public_values: &public_values,
        is_first_row: selectors[0],
        is_last_row: selectors[1],
        is_transition: selectors[2],
        alpha,
        accumulator: F::ZERO,
    };
    air.eval(&mut folder);
    let folded_value = folder.accumulator;

    let mut folded_expr = SymbolicExpression::<F>::Constant(F::ZERO);
    for sym in symbolic_constraints.iter() {
        folded_expr = SymbolicExpression::Constant(alpha) * folded_expr + sym.clone();
    }

    let mut builder = CircuitBuilder::<F>::new();
    let selector_targets = [
        builder.add_public_input(),
        builder.add_public_input(),
        builder.add_public_input(),
    ];
    let public_targets: Vec<_> = (0..num_public_values)
        .map(|_| builder.add_public_input())
        .collect();

    let pre_local_targets: Vec<_> = (0..preprocessed_width)
        .map(|_| builder.add_public_input())
        .collect();
    let pre_next_targets: Vec<_> = (0..preprocessed_width)
        .map(|_| builder.add_public_input())
        .collect();
    let local_targets: Vec<_> = (0..width).map(|_| builder.add_public_input()).collect();
    let next_targets: Vec<_> = (0..width).map(|_| builder.add_public_input()).collect();

    let row_selectors = RowSelectorsTargets {
        is_first_row: selector_targets[0],
        is_last_row: selector_targets[1],
        is_transition: selector_targets[2],
    };

    let columns = ColumnsTargets {
        challenges: &[],
        public_values: &public_targets,
        local_prep_values: &pre_local_targets,
        next_prep_values: &pre_next_targets,
        local_values: &local_targets,
        next_values: &next_targets,
    };

    let sum = symbolic_to_circuit(row_selectors, &columns, &folded_expr, &mut builder);
    let const_target = builder.add_const(folded_value);
    builder.connect(const_target, sum);

    let mut all_public_inputs = Vec::new();
    all_public_inputs.extend_from_slice(&selectors);
    all_public_inputs.extend_from_slice(&public_values);
    all_public_inputs.append(&mut preprocessed_local);
    all_public_inputs.append(&mut preprocessed_next);
    all_public_inputs.append(&mut trace_local);
    all_public_inputs.append(&mut trace_next);

    tracing::info!("Building circuit...");
    let circuit = builder
        .build()
        .map_err(|e| CircuitError::InvalidCircuit { error: e })?;
    let mut runner = circuit.runner();
    runner.set_public_inputs(&all_public_inputs)?;
    runner.run()?;

    Ok(())
}

#[test]
fn primitive_airs_symbolic_to_circuit() -> Result<(), CircuitError> {
    let mut rng = SmallRng::seed_from_u64(7);

    let add_air =
        AddAir::<F, 1>::new_with_preprocessed(1, 1, vec![F::ZERO, F::ONE, F::from_u64(2)]);
    run_recursive(&add_air, add_air.preprocessed_width(), 0, &mut rng)?;

    let mul_air = MulAir::<F, 1>::new_with_preprocessed(1, 1, vec![F::ONE; 3]);
    run_recursive(&mul_air, mul_air.preprocessed_width(), 0, &mut rng)?;

    let const_air = ConstAir::<F, 1>::new_with_preprocessed(1, vec![F::from_u64(3)]);
    run_recursive(&const_air, 1, 0, &mut rng)?;

    let public_air = PublicAir::<F, 1>::new_with_preprocessed(1, vec![F::from_u64(4)]);
    run_recursive(&public_air, 1, 1, &mut rng)?;

    let witness_air = WitnessAir::<F, 1>::new_with_preprocessed(1, 1, vec![F::ONE]);
    run_recursive(&witness_air, witness_air.preprocessed_width(), 0, &mut rng)?;

    Ok(())
}

#[test]
fn poseidon_perm_air_symbolic_to_circuit() -> Result<(), CircuitError> {
    let mut rng = SmallRng::seed_from_u64(9);

    let constants = RoundConstants::new(rng.random(), rng.random(), rng.random());
    let air = Poseidon2CircuitAirBabyBearD4Width16::new(constants);

    run_recursive(&air, 0, 0, &mut rng)
}
