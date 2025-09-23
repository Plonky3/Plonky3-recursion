use std::env;

/// Fibonacci circuit: Compute F(n) and prove correctness
/// Public input: expected_result (F(n))
use p3_baby_bear::BabyBear;
use p3_circuit::config::babybear_config::BabyBearQuarticExtensionCircuitBuilder;
use p3_circuit_prover::config::babybear_config::build_standard_config_babybear;
use p3_circuit_prover::prover::ProverError;
use p3_circuit_prover::{MultiTableProver, TablePacking};
use p3_field::PrimeCharacteristicRing;
use p3_field::extension::BinomialExtensionField;

type F = BinomialExtensionField<BabyBear, 4>;

fn main() -> Result<(), ProverError> {
    let n = env::args()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(100);

    let mut builder = BabyBearQuarticExtensionCircuitBuilder::new();

    // Public input: expected F(n)
    let expected_result = builder.add_public_input();

    // Compute F(n) iteratively
    let mut a = builder.add_const(F::ZERO); // F(0)
    let mut b = builder.add_const(F::ONE); // F(1)

    for _i in 2..=n {
        let next = builder.add(a, b);
        a = b;
        b = next;
    }

    // Assert computed F(n) equals expected result
    builder.connect(b, expected_result);

    let circuit = builder.build()?;
    let mut runner = circuit.runner();

    // Set public input
    let expected_fib = compute_fibonacci_classical(n);
    runner.set_public_inputs(&[expected_fib])?;

    let traces = runner.run()?;
    let config = build_standard_config_babybear();
    let table_packing = TablePacking::from_counts(4, 1);
    let multi_prover = MultiTableProver::new(config).with_table_packing(table_packing);
    let proof = multi_prover.prove_all_tables(&traces)?;
    multi_prover.verify_all_tables(&proof)
}

fn compute_fibonacci_classical(n: usize) -> F {
    if n == 0 {
        return F::ZERO;
    }
    if n == 1 {
        return F::ONE;
    }

    let mut a = F::ZERO;
    let mut b = F::ONE;

    for _i in 2..=n {
        let next = a + b;
        a = b;
        b = next;
    }

    b
}
