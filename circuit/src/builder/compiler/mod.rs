//! Circuit compilation and lowering subsystem.

mod lowerer;
mod optimizer;

pub use lowerer::{ExpressionLowerer, LoweringResult};
pub use optimizer::Optimizer;

#[cfg(test)]
mod assurance_tests {
    extern crate std;

    use alloc::string::String;
    use alloc::vec::Vec;
    use alloc::{format, vec};

    use p3_test_utils::baby_bear_params::{BabyBear as F, PrimeCharacteristicRing};
    use p3_test_utils::corpus::{
        CaseRng, CorpusSpec, DEFAULT_CASES, MAX_CASES, derive_family_seed,
    };

    use crate::CircuitBuilder;

    const FAMILY_TAG: u64 = 0x434f_4d50_4441_4701;
    const MAX_DAG_OPS: usize = 32;

    fn parse_corpus_spec(
        start_seed: Option<&str>,
        cases: Option<&str>,
    ) -> Result<CorpusSpec, String> {
        let start_seed = start_seed
            .map_or(Ok(0), str::parse::<u64>)
            .map_err(|_| String::from("P3_ASSURANCE_START_SEED must be a u64"))?;
        let cases = cases
            .map_or(Ok(DEFAULT_CASES), str::parse::<u32>)
            .map_err(|_| String::from("P3_ASSURANCE_CASES must be a u32"))?;
        if !(1..=MAX_CASES).contains(&cases) {
            return Err(format!(
                "P3_ASSURANCE_CASES must be in 1..={MAX_CASES}, got {cases}"
            ));
        }
        Ok(CorpusSpec { start_seed, cases })
    }

    fn corpus_spec_from_env() -> Result<CorpusSpec, String> {
        let start_seed = std::env::var("P3_ASSURANCE_START_SEED").ok();
        let cases = std::env::var("P3_ASSURANCE_CASES").ok();
        parse_corpus_spec(start_seed.as_deref(), cases.as_deref())
    }

    fn tagged(
        builder: &mut CircuitBuilder<F>,
        tags: &mut Vec<(String, F)>,
        expr: crate::ExprId,
        value: F,
        seed: u64,
        op: usize,
    ) {
        let tag = format!("assurance-compiler-dag-{seed}-{op}");
        builder.tag(expr, tag.clone()).unwrap_or_else(|error| {
            panic!(
                "family=compiler-dag field=BabyBear/D1 seed={seed} op={op} mutation=none expected-stage=tag-output error={error:?}"
            )
        });
        tags.push((tag, value));
    }

    fn run_dag_case(case_seed: u64) {
        let mut rng = CaseRng::new(derive_family_seed(case_seed, FAMILY_TAG));
        let public_value = F::from_u64(rng.next_u64());
        let private_value = F::from_u64(rng.next_u64());
        let bool_value = F::from_u64(case_seed & 1);
        let mut divisor_value = F::from_u64(rng.next_u64());
        if divisor_value == F::ZERO {
            divisor_value = F::ONE;
        }

        let mut builder = CircuitBuilder::<F>::new();
        let public = builder.alloc_public_input("assurance-dag-public");
        let boolean = builder.alloc_public_input("assurance-dag-boolean");
        let private = builder.alloc_private_input("assurance-dag-private");
        let divisor = builder.alloc_const(divisor_value, "assurance-dag-nonzero-divisor");
        let zero = builder.define_const(F::ZERO);
        let mut nodes = vec![(public, public_value), (private, private_value)];
        let mut tags = Vec::with_capacity(MAX_DAG_OPS);

        let sum = builder.add(public, private);
        let sum_value = public_value + private_value;
        tagged(&mut builder, &mut tags, sum, sum_value, case_seed, 0);
        nodes.push((sum, sum_value));

        // A repeated expression must remain observable through two aliases after optimization.
        let alias = builder.add(public, private);
        builder.connect(sum, alias);
        tagged(&mut builder, &mut tags, alias, sum_value, case_seed, 1);

        // Division lowers to a multiplication whose unknown output is solved backwards.
        let quotient = builder.div(sum, divisor);
        let quotient_value = sum_value / divisor_value;
        tagged(
            &mut builder,
            &mut tags,
            quotient,
            quotient_value,
            case_seed,
            2,
        );
        nodes.push((quotient, quotient_value));

        let mul_add = builder.mul_add(public, private, sum);
        let mul_add_value = public_value * private_value + sum_value;
        tagged(
            &mut builder,
            &mut tags,
            mul_add,
            mul_add_value,
            case_seed,
            3,
        );
        nodes.push((mul_add, mul_add_value));

        let horner_head = builder.horner_acc_step(zero, divisor, public, private);
        let horner_head_value = public_value - private_value;
        tagged(
            &mut builder,
            &mut tags,
            horner_head,
            horner_head_value,
            case_seed,
            4,
        );
        let horner_mid = builder.horner_acc_step(horner_head, divisor, private, public);
        let horner_mid_value = horner_head_value * divisor_value + private_value - public_value;
        tagged(
            &mut builder,
            &mut tags,
            horner_mid,
            horner_mid_value,
            case_seed,
            5,
        );
        nodes.push((horner_mid, horner_mid_value));

        // Resetting to a zero head must not inherit the preceding chain accumulator.
        let horner_reset = builder.horner_acc_step(zero, divisor, private, public);
        let horner_reset_value = private_value - public_value;
        tagged(
            &mut builder,
            &mut tags,
            horner_reset,
            horner_reset_value,
            case_seed,
            6,
        );
        nodes.push((horner_reset, horner_reset_value));
        builder.assert_bool(boolean);

        for op in 7..MAX_DAG_OPS {
            let left = (rng.next_u64() as usize) % nodes.len();
            let right = (rng.next_u64() as usize) % nodes.len();
            let (lhs, lhs_value) = nodes[left];
            let (rhs, rhs_value) = nodes[right];
            let (expr, value) = match rng.next_u64() % 5 {
                0 => (builder.add(lhs, rhs), lhs_value + rhs_value),
                1 => (builder.sub(lhs, rhs), lhs_value - rhs_value),
                2 => (builder.mul(lhs, rhs), lhs_value * rhs_value),
                3 => (
                    builder.mul_add(lhs, rhs, public),
                    lhs_value * rhs_value + public_value,
                ),
                _ => (
                    builder.horner_acc_step(lhs, divisor, rhs, private),
                    lhs_value * divisor_value + rhs_value - private_value,
                ),
            };
            tagged(&mut builder, &mut tags, expr, value, case_seed, op);
            nodes.push((expr, value));
        }
        assert_eq!(
            tags.len(),
            MAX_DAG_OPS,
            "family=compiler-dag field=BabyBear/D1 seed={case_seed} op=count mutation=none expected-stage=dag-bound"
        );

        let circuit = builder.build().unwrap_or_else(|error| {
            panic!(
                "family=compiler-dag field=BabyBear/D1 seed={case_seed} op=build mutation=none expected-stage=build-success error={error:?}"
            )
        });
        let mut runner = circuit.runner();
        runner
            .set_public_inputs(&[public_value, bool_value])
            .unwrap_or_else(|error| {
                panic!(
                    "family=compiler-dag field=BabyBear/D1 seed={case_seed} op=inputs mutation=none expected-stage=set-public-inputs error={error:?}"
                )
            });
        runner
            .set_private_inputs(&[private_value])
            .unwrap_or_else(|error| {
                panic!(
                    "family=compiler-dag field=BabyBear/D1 seed={case_seed} op=inputs mutation=none expected-stage=set-private-inputs error={error:?}"
                )
            });
        let traces = runner.run().unwrap_or_else(|error| {
            panic!(
                "family=compiler-dag field=BabyBear/D1 seed={case_seed} op=run mutation=none expected-stage=runner-success error={error:?}"
            )
        });

        for (op, (tag, expected)) in tags.iter().enumerate() {
            assert_eq!(
                traces.probe(tag),
                Some(expected),
                "family=compiler-dag field=BabyBear/D1 seed={case_seed} op={op} mutation=none expected-stage=direct-field-equality tag={tag}"
            );
        }
    }

    #[test]
    fn assurance_corpus_env_bounds() {
        assert_eq!(
            parse_corpus_spec(None, None).unwrap(),
            CorpusSpec {
                start_seed: 0,
                cases: DEFAULT_CASES,
            }
        );
        assert_eq!(
            parse_corpus_spec(Some("91"), Some("2")).unwrap().start_seed,
            91
        );
        for invalid in ["", "nope", "0", "1025"] {
            assert!(
                parse_corpus_spec(Some("7"), Some(invalid)).is_err(),
                "family=compiler-dag field=BabyBear/D1 seed=7 mutation=cases-{invalid} expected-stage=config-rejection"
            );
        }
        assert!(parse_corpus_spec(Some("invalid"), Some("1")).is_err());
    }

    #[test]
    fn assurance_compiler_dag_reference_babybear_d1() {
        let spec = corpus_spec_from_env().expect("assurance corpus environment must be valid");
        p3_test_utils::corpus::for_each_case(spec, run_dag_case);
    }
}
