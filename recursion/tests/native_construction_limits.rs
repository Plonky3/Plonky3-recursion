//! Native recursive kernels fail at bounded construction checkpoints.

use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_binary_field::{BinaryField128 as F, Poly64, TowerLevel};
use p3_bus::ProductGkrRootShape;
use p3_circuit::{CircuitBuilder, CircuitBuilderError, CircuitConstructionLimits};
use p3_recursion::pcs::binary::BinaryGenericSumcheckVerifier;
use p3_recursion::verifier::{
    BinaryAirConstraintPlan, BinaryPolyProductGkrVerifier, BinaryProductGkrVerifier,
    VerificationError,
};

const fn limits(nodes: usize) -> CircuitConstructionLimits {
    CircuitConstructionLimits {
        max_expression_nodes: nodes,
        max_pending_connects: 4096,
        max_non_primitive_calls: 4096,
        max_non_primitive_slots: 65536,
    }
}
const fn budget_error<T>(result: &Result<T, VerificationError>) -> bool {
    matches!(
        result,
        Err(VerificationError::CircuitBuilder(
            CircuitBuilderError::ConstructionLimitExceeded { .. }
        ))
    )
}

#[test]
fn native_input_allocators_stop_at_individual_field_boundaries() {
    let product =
        BinaryProductGkrVerifier::<F, F>::new(3, 3, ProductGkrRootShape::Distinct).unwrap();
    let mut b = CircuitBuilder::<F>::with_construction_limits(limits(4)).unwrap();
    assert!(budget_error(
        &product.input_shape().allocate_native_targets(&mut b)
    ));
    assert_eq!(b.construction_usage().unwrap().expression_nodes, 5);

    let sumcheck = BinaryGenericSumcheckVerifier::<F, F>::new(4, 5, 0).unwrap();
    let mut b = CircuitBuilder::<F>::with_construction_limits(limits(4)).unwrap();
    assert!(budget_error(
        &sumcheck.input_shape().allocate_native_targets(&mut b)
    ));
    assert_eq!(b.construction_usage().unwrap().expression_nodes, 5);

    let product = BinaryPolyProductGkrVerifier::new(3, 3, ProductGkrRootShape::Distinct).unwrap();
    let mut b = CircuitBuilder::<Poly64>::with_construction_limits(limits(4)).unwrap();
    assert!(budget_error(
        &product.input_shape().allocate_native_targets(&mut b)
    ));
    assert_eq!(b.construction_usage().unwrap().expression_nodes, 7);
}

struct WideAir;
impl BaseAir<F> for WideAir {
    fn width(&self) -> usize {
        4
    }
    fn main_next_row_columns(&self) -> Vec<usize> {
        vec![]
    }
}
impl<AB: AirBuilder<F = F>> Air<AB> for WideAir {
    fn eval(&self, b: &mut AB) {
        let main = b.main();
        let m = main.current_slice();
        for i in 2..=65 {
            b.assert_zero(m[0] * m[1] + m[2] * F::from_repr(i) + m[3]);
        }
    }
}

#[test]
fn native_air_stops_inside_the_program_before_build() {
    let plan = BinaryAirConstraintPlan::<F, F>::from_air(&WideAir, 2).unwrap();
    let mut b = CircuitBuilder::<F>::with_construction_limits(limits(32)).unwrap();
    let mut scalar = || {
        let value = b.public_input();
        b.native_tower128_from_expr(value)
    };
    let point = [scalar(), scalar()];
    let current = [scalar(), scalar(), scalar(), scalar()];
    let alpha = scalar();
    assert!(budget_error(&plan.evaluate_native(
        &mut b,
        &point,
        &current,
        &[],
        &[],
        &alpha
    )));
    assert!(b.construction_usage().unwrap().expression_nodes <= 35);
    assert!(b.build().is_err());
}

#[derive(Clone)]
struct ConstantAir;
impl BaseAir<Poly64> for ConstantAir {
    fn width(&self) -> usize {
        1
    }
    fn num_public_values(&self) -> usize {
        1
    }
}
impl<AB: AirBuilder<F = Poly64>> Air<AB> for ConstantAir {
    fn eval(&self, b: &mut AB) {
        let main = b.main();
        b.assert_eq(main.current_slice()[0], b.public_values()[0]);
    }
}

#[test]
fn prepared_poly_budget_stops_input_allocation_before_lowering_and_keys() {
    use p3_circuit::ops::ByteHash;
    use p3_circuit_prover::direct::DirectCircuitLimits;
    use p3_recursion::artifact::{
        ArtifactLimits, BinaryNativePolyWhirAuthority, BinaryNativePolyWhirPcsParameters,
        BinaryNativeVerifierSpec,
    };
    use p3_recursion::prepared::{NativeBinaryRecursionOptions, PreparedNativeBinaryPolyWhirLayer};
    use p3_recursion::verifier::VerifierLimits;
    use p3_whir::{FoldingFactor, ProtocolParameters, SecurityAssumption};
    let protocol = || ProtocolParameters {
        security_level: 8,
        pow_bits: 0,
        round_log_inv_rates: vec![],
        folding_factor: FoldingFactor::Constant(1),
        soundness_type: SecurityAssumption::JohnsonBound,
        starting_log_inv_rate: 1,
    };
    let spec = BinaryNativeVerifierSpec {
        main: BinaryNativePolyWhirPcsParameters::new(1, protocol(), ByteHash::Keccak256, 0)
            .unwrap(),
        preprocessed: None,
        transcript_hash: ByteHash::Keccak256,
        initial_bytes: vec![1],
        sumcheck_pow_bits: 0,
        max_tau_draws: 8,
        security_bits: 4,
    };
    let (_, authority) = BinaryNativePolyWhirAuthority::<_>::setup(
        vec![ConstantAir],
        vec![1],
        spec,
        &VerifierLimits::default(),
    )
    .unwrap();
    let options = NativeBinaryRecursionOptions {
        main: protocol(),
        preprocessed: protocol(),
        cap_height: 0,
        initial_bytes: vec![2],
        sumcheck_pow_bits: 0,
        max_tau_draws: 32,
        security_bits: 4,
        max_pcs_codeword_cells: 0,
        artifact_limits: ArtifactLimits::default(),
    };
    assert!(matches!(
        PreparedNativeBinaryPolyWhirLayer::from_native_authority_with_construction_limits(
            &authority, options, &DirectCircuitLimits::default(), &limits(16)
        ),
        Err(VerificationError::CircuitBuilder(CircuitBuilderError::ConstructionLimitExceeded {
            component: "expression nodes", actual, limit: 16,
        })) if actual <= 32
    ));
}
