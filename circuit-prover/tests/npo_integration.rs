use core::marker::PhantomData;

use p3_baby_bear::BabyBear;
use p3_circuit::{CircuitBuilderError, WitnessId};
use p3_circuit::builder::{
    CircuitBuilder, NonPrimitiveOperationData, NpoCircuitPlugin, NpoLoweringContext,
};
use p3_circuit::op::{ExecutionContext, NonPrimitiveExecutor, NpoConfig, NpoTypeId, Op, OpStateMap};
use p3_circuit::tables::{NonPrimitiveTrace, TraceGeneratorFn};
use p3_circuit::CircuitError;
use p3_field::{Field, PrimeCharacteristicRing};

// Simple non-primitive "cube" op: y = x^3
const CUBE_TYPE_ID: &str = "cube_simple/x_cubed";

fn cube_trace_generator<F>(
    _op_states: &OpStateMap,
) -> Result<Option<Box<dyn NonPrimitiveTrace<F>>>, CircuitError> {
    // This simple example does not produce its own dedicated table trace.
    Ok(None)
}

/// Circuit-side plugin for the cube op.
#[derive(Clone)]
struct CubeCircuitPlugin<F> {
    _phantom: PhantomData<F>,
}

impl<F> CubeCircuitPlugin<F> {
    fn new() -> Self {
        Self {
            _phantom: PhantomData,
        }
    }
}

impl<F> NpoCircuitPlugin<F> for CubeCircuitPlugin<F>
where
    F: Field + PrimeCharacteristicRing,
{
    fn type_id(&self) -> NpoTypeId {
        NpoTypeId::new(CUBE_TYPE_ID)
    }

    fn lower(
        &self,
        data: &NonPrimitiveOperationData<F>,
        output_exprs: &[(u32, p3_circuit::types::ExprId)],
        ctx: &mut NpoLoweringContext<'_, F>,
    ) -> Result<Op<F>, CircuitBuilderError> {
        // For this example, expect exactly one input and one output.
        let input_expr = data.input_exprs[0][0];
        let output_expr = output_exprs[0].1;

        // Map expressions to witness IDs (allocate if necessary).
        let in_wid = *ctx
            .expr_to_widx
            .entry(input_expr)
            .or_insert_with(|| (ctx.alloc_witness_id)(1));
        let out_wid = *ctx
            .expr_to_widx
            .entry(output_expr)
            .or_insert_with(|| (ctx.alloc_witness_id)(1));

        // Build a non-primitive op with a cube executor.
        Ok(Op::NonPrimitiveOpWithExecutor {
            inputs: vec![vec![in_wid]],
            outputs: vec![vec![out_wid]],
            executor: Box::new(CubeExecutor::default()),
            op_id: data.op_id,
        })
    }

    fn trace_generator(&self) -> TraceGeneratorFn<F> {
        // For this demo we don't build a separate cube table trace; a real plugin
        // would record rows in OpExecutionState and use them here.
        cube_trace_generator::<F>
    }

    fn config(&self) -> NpoConfig {
        // No special config for this simple example.
        NpoConfig::new(())
    }
}

/// Executor that computes y = x^3 inside the runtime execution context.
#[derive(Clone)]
struct CubeExecutor<F> {
    op_type: NpoTypeId,
    _phantom: PhantomData<F>,
}

impl<F> Default for CubeExecutor<F> {
    fn default() -> Self {
        Self {
            op_type: NpoTypeId::new(CUBE_TYPE_ID),
            _phantom: PhantomData,
        }
    }
}

impl<F> core::fmt::Debug for CubeExecutor<F> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("CubeExecutor")
    }
}

impl<F> NonPrimitiveExecutor<F> for CubeExecutor<F>
where
    F: Field + PrimeCharacteristicRing,
{
    fn execute(
        &self,
        inputs: &[Vec<WitnessId>],
        outputs: &[Vec<WitnessId>],
        ctx: &mut ExecutionContext<'_, F>,
    ) -> Result<(), p3_circuit::CircuitError> {
        let in_id = inputs[0][0];
        let out_id = outputs[0][0];

        let x = ctx.get_witness(in_id)?;
        let x2 = x * x;
        let x3 = x2 * x;

        ctx.set_witness(out_id, x3)?;
        Ok(())
    }

    fn op_type(&self) -> &NpoTypeId {
        &self.op_type
    }

    fn as_any(&self) -> &dyn core::any::Any {
        self
    }

    fn preprocess(
        &self,
        _inputs: &[Vec<WitnessId>],
        _outputs: &[Vec<WitnessId>],
        _preprocessed: &mut p3_circuit::PreprocessedColumns<F>,
    ) -> Result<(), p3_circuit::CircuitError> {
        // This simple example doesn't need preprocessed data.
        Ok(())
    }

    fn boxed(&self) -> Box<dyn NonPrimitiveExecutor<F>> {
        Box::new(self.clone())
    }
}

/// Integration-style test: register a cube NPO plugin, use it in a circuit,
/// and run the circuit to check y = x^3.
#[test]
fn cube_npo_integration_flow() {
    type F = BabyBear;

    // Build circuit with the cube plugin.
    let mut builder = CircuitBuilder::<F>::new();
    builder.register_npo(CubeCircuitPlugin::<F>::new());

    // Public input x and expected output y.
    let x = builder.public_input();
    let y_expected = builder.public_input();

    // Create a single cube non-primitive op that maps x -> y.
    let cube_type = NpoTypeId::new(CUBE_TYPE_ID);
    let (_op_id, _call_expr, outputs) = builder.push_non_primitive_op_with_outputs(
        cube_type,
        vec![vec![x]],
        vec![Some("cube_out")],
        None,
        "cube_call",
    );
    let y_expr = outputs[0].expect("cube op should have one output");

    // Connect cube_out to expected output.
    builder.connect(y_expr, y_expected);

    let circuit = builder.build().expect("build cube circuit");
    let out_wid = circuit
        .expr_to_widx
        .get(&y_expr)
        .copied()
        .expect("y_expr mapped to witness");

    // Run with a simple x value and check we get x^3.
    let mut runner = circuit.runner();
    let x_val = F::from_u64(3); // 3
    let y_val = x_val * x_val * x_val; // 27
    runner
        .set_public_inputs(&[x_val, y_val])
        .expect("set public inputs");

    let traces = runner.run().expect("run cube circuit");
    let out_val = traces
        .witness_trace
        .get_value(out_wid)
        .expect("output witness set");

    assert_eq!(*out_val, y_val);
}
