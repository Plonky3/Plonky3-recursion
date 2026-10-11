//! Turns a resource-limit failure of a native recursion layer into a message that names the
//! command-line flag raising the limit and the value the layer needs.

use std::error::Error;
use std::fmt;

use p3_circuit::CircuitBuilderError;
use p3_circuit_prover::direct::DirectCircuitError;
use p3_circuit_prover::indexed::IndexedCircuitError;
use p3_circuit_prover::native_binary::NativeBinaryCircuitError;
use p3_circuit_prover::native_bus::NativeBusCircuitError;
use p3_recursion::verifier::VerificationError;

/// A limit failure of one layer with the flag that raises it. The original error is the cause.
struct LimitHint {
    message: String,
    source: VerificationError,
}

impl fmt::Display for LimitHint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl fmt::Debug for LimitHint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}\n  cause: {}", self.message, self.source)
    }
}

impl Error for LimitHint {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(&self.source)
    }
}

/// The flag of the example that sets the limit, when it has one.
fn flag_for_verifier_component(component: &str) -> Option<&'static str> {
    match component {
        "native recursive PCS codeword cells" | "native folding PCS codeword cells" => {
            Some("--max-pcs-codeword-cells")
        }
        "rounds" => Some("--max-verifier-rounds"),
        _ => None,
    }
}

fn flag_for_construction_component(component: &str) -> Option<&'static str> {
    match component {
        "expression nodes" => Some("--max-expression-nodes"),
        "pending connections" => Some("--max-pending-connects"),
        "non-primitive calls" => Some("--max-non-primitive-calls"),
        "non-primitive slots" => Some("--max-non-primitive-slots"),
        _ => None,
    }
}

fn flag_for_circuit_component(component: &str) -> Option<&'static str> {
    match component {
        "witnesses" => Some("--max-witnesses"),
        "operations" => Some("--max-operations"),
        c if c.contains("trace cells") || c.contains("temporary cells") => {
            Some("--max-trace-cells")
        }
        _ => None,
    }
}

/// The message for a limit crossed by `actual`: the total the layer needs when `exact`, else
/// the count at which the check first failed, which a larger layer may exceed.
fn requirement(
    stage: &str,
    component: &str,
    actual: usize,
    limit: usize,
    flag: Option<&str>,
    exact: bool,
) -> String {
    let (verb, caveat) = if exact {
        ("needs", "")
    } else {
        (
            "reached",
            "; the layer may need more than the count at which the check failed",
        )
    };
    let remedy = flag.map_or_else(
        || "this limit is fixed in the example's options".to_owned(),
        |flag| format!("rerun with {flag} {actual} or more{caveat}"),
    );
    format!("{stage} {verb} {actual} {component} (limit {limit}); {remedy}")
}

fn circuit_message(stage: &str, error: &DirectCircuitError) -> Option<String> {
    match error {
        DirectCircuitError::ResourceLimit {
            component,
            actual,
            limit,
        } => Some(requirement(
            stage,
            component,
            *actual,
            *limit,
            flag_for_circuit_component(component),
            true,
        )),
        _ => None,
    }
}

fn indexed_message(stage: &str, error: &IndexedCircuitError) -> Option<String> {
    match error {
        IndexedCircuitError::Primitive(error) => circuit_message(stage, error),
        _ => None,
    }
}

fn native_bus_message(stage: &str, error: &NativeBusCircuitError) -> Option<String> {
    match error {
        NativeBusCircuitError::Primitive(error) => circuit_message(stage, error),
        NativeBusCircuitError::Layout(error)
        | NativeBusCircuitError::Hash(NativeBinaryCircuitError::Indexed(error)) => {
            indexed_message(stage, error)
        }
        _ => None,
    }
}

fn message(stage: &str, error: &VerificationError) -> Option<String> {
    match error {
        VerificationError::ResourceLimitExceeded {
            component,
            actual,
            limit,
        } => Some(requirement(
            stage,
            component,
            *actual,
            *limit,
            flag_for_verifier_component(component),
            component.ends_with("codeword cells"),
        )),
        VerificationError::CircuitBuilder(CircuitBuilderError::ConstructionLimitExceeded {
            component,
            actual,
            limit,
        }) => Some(requirement(
            stage,
            component,
            *actual,
            *limit,
            flag_for_construction_component(component),
            false,
        )),
        VerificationError::NativeBusCircuit(error) => native_bus_message(stage, error),
        _ => None,
    }
}

/// Wraps `error` of `stage` (for example `layer 2`) with the flag to raise when it is a limit
/// failure; any other error is returned unchanged.
pub fn explain(stage: impl fmt::Display, error: VerificationError) -> Box<dyn Error> {
    match message(&stage.to_string(), &error) {
        Some(message) => Box::new(LimitHint {
            message,
            source: error,
        }),
        None => Box::new(error),
    }
}

/// `explain` for the error of layer `depth`, for use in `map_err`.
pub fn at_layer(depth: usize) -> impl Fn(VerificationError) -> Box<dyn Error> {
    move |error| explain(format!("layer {depth}"), error)
}
