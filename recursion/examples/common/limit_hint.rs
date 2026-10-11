//! Turns a resource-limit failure of a native recursion layer into a message that names the
//! command-line flag that raises the limit, or lowers the demand when the field or domain
//! bounds it. The value is what the layer needs when the count is a total, else a starting
//! point, because construction and verifier checks stop at the first count over the limit.

use std::error::Error;
use std::fmt;

use p3_circuit::CircuitBuilderError;
use p3_circuit_prover::direct::DirectCircuitError;
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

/// What the user can change to cross a limit.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Knob {
    /// A flag that sets the limit itself.
    Raise(&'static str),
    /// A flag that lowers the demand, because the field bounds the limit.
    Lower(&'static str),
    /// A `VerifierLimits` field that the example does not expose as a flag.
    Field(&'static str),
    /// A limit that no flag of the example reaches.
    Fixed,
}

fn verifier_knob(component: &str) -> Knob {
    match component {
        "native recursive PCS codeword cells" | "native folding PCS codeword cells" => {
            Knob::Raise("--max-pcs-codeword-cells")
        }
        "rounds" => Knob::Raise("--max-verifier-rounds"),
        "binary native WHIR grinding bits" | "binary native grinding bits" => {
            Knob::Lower("--pow-bits")
        }
        "instances" => Knob::Field("max_instances"),
        "scalar elements" => Knob::Field("max_total_scalar_elements"),
        "metadata entries" => Knob::Field("max_metadata_entries"),
        "metadata string bytes" => Knob::Field("max_metadata_string_bytes"),
        "compressed frontier hashes" => Knob::Field("max_compressed_frontier_hashes"),
        "restored authentication-path hashes" => {
            Knob::Field("max_restored_authentication_path_hashes")
        }
        "cap roots" => Knob::Field("max_cap_roots"),
        "final polynomial evaluations" => Knob::Field("max_final_poly_evaluations"),
        "binary native WHIR domain bits" => Knob::Field("max_log_domain_or_degree"),
        _ => Knob::Fixed,
    }
}

fn construction_knob(component: &str) -> Knob {
    match component {
        "expression nodes" => Knob::Raise("--max-expression-nodes"),
        "pending connections" => Knob::Raise("--max-pending-connects"),
        "non-primitive calls" => Knob::Raise("--max-non-primitive-calls"),
        "non-primitive slots" => Knob::Raise("--max-non-primitive-slots"),
        _ => Knob::Fixed,
    }
}

fn circuit_knob(component: &str) -> Knob {
    match component {
        "witnesses" | "public values" => Knob::Raise("--max-witnesses"),
        "operations" => Knob::Raise("--max-operations"),
        "native bus traces, preprocessing and temporary cells"
        | "native bus dense traces, preprocessing and temporary cells" => {
            Knob::Raise("--max-trace-cells")
        }
        _ => Knob::Fixed,
    }
}

/// A value above both `limit` doubled and the next power of two over `reached`.
fn bumped(reached: usize, limit: usize) -> usize {
    let power = reached
        .saturating_add(1)
        .checked_next_power_of_two()
        .unwrap_or(usize::MAX);
    limit.saturating_mul(2).max(power)
}

/// The message for a limit crossed by `actual`. When `exact`, `actual` is the total the layer
/// needs; otherwise it is the count at which the check first failed, a lower bound.
fn requirement(
    stage: &str,
    component: &str,
    actual: usize,
    limit: usize,
    knob: Knob,
    exact: bool,
) -> String {
    let verb = if exact { "needs" } else { "reached" };
    let remedy = match knob {
        Knob::Raise(flag) if exact => format!("rerun with {flag} {actual} or more"),
        Knob::Raise(flag) => format!(
            "the layer needs at least that much; rerun with {flag} {} and raise it again if the \
             layer still exceeds it",
            bumped(actual, limit)
        ),
        Knob::Lower(flag) => {
            format!("the field bounds it; lower {flag}")
        }
        Knob::Field(field) => {
            format!("it is VerifierLimits::{field}, which no flag of this example sets")
        }
        Knob::Fixed => "no flag of this example sets this limit".to_owned(),
    };
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
            circuit_knob(component),
            true,
        )),
        _ => None,
    }
}

fn native_bus_message(stage: &str, error: &NativeBusCircuitError) -> Option<String> {
    match error {
        NativeBusCircuitError::Primitive(error) => circuit_message(stage, error),
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
            verifier_knob(component),
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
            construction_knob(component),
            false,
        )),
        VerificationError::NativeBusCircuit(error) => native_bus_message(stage, error),
        _ => None,
    }
}

/// Wraps `error` of `stage` (for example `layer 2`) with the flag to raise when it is a limit
/// failure; any other error is returned unchanged.
fn explain(stage: impl fmt::Display, error: VerificationError) -> Box<dyn Error> {
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

#[cfg(test)]
mod tests {
    use p3_binary_field::Poly64;
    use p3_circuit::CircuitBuilder;
    use p3_circuit::ops::ByteHash;
    use p3_circuit_prover::direct::DirectCircuitLimits;
    use p3_circuit_prover::native_bus::NativeBusCircuit;
    use p3_recursion::artifact::BinaryNativePolyWhirPcsParameters;
    use p3_whir::{FoldingFactor, ProtocolParameters, SecurityAssumption};

    use super::*;

    fn verifier(component: &'static str) -> VerificationError {
        VerificationError::ResourceLimitExceeded {
            component,
            actual: 70,
            limit: 64,
        }
    }

    fn construction(component: &'static str) -> VerificationError {
        VerificationError::CircuitBuilder(CircuitBuilderError::ConstructionLimitExceeded {
            component,
            actual: 70,
            limit: 64,
        })
    }

    fn circuit(component: &'static str) -> VerificationError {
        VerificationError::NativeBusCircuit(NativeBusCircuitError::Primitive(
            DirectCircuitError::ResourceLimit {
                component,
                actual: 70,
                limit: 64,
            },
        ))
    }

    fn text(error: &VerificationError) -> String {
        message("layer 2", error).expect("a limit failure has a message")
    }

    #[test]
    fn verifier_components_name_their_flag() {
        for (component, flag) in [
            (
                "native recursive PCS codeword cells",
                "--max-pcs-codeword-cells",
            ),
            (
                "native folding PCS codeword cells",
                "--max-pcs-codeword-cells",
            ),
            ("rounds", "--max-verifier-rounds"),
        ] {
            assert!(text(&verifier(component)).contains(flag), "{component}");
        }
    }

    #[test]
    fn construction_components_name_their_flag() {
        for (component, flag) in [
            ("expression nodes", "--max-expression-nodes"),
            ("pending connections", "--max-pending-connects"),
            ("non-primitive calls", "--max-non-primitive-calls"),
            ("non-primitive slots", "--max-non-primitive-slots"),
        ] {
            assert!(text(&construction(component)).contains(flag), "{component}");
        }
    }

    #[test]
    fn circuit_components_name_their_flag() {
        for (component, flag) in [
            ("witnesses", "--max-witnesses"),
            ("public values", "--max-witnesses"),
            ("operations", "--max-operations"),
            (
                "native bus traces, preprocessing and temporary cells",
                "--max-trace-cells",
            ),
            (
                "native bus dense traces, preprocessing and temporary cells",
                "--max-trace-cells",
            ),
        ] {
            assert!(text(&circuit(component)).contains(flag), "{component}");
        }
    }

    #[test]
    fn field_bounded_components_point_at_the_demand() {
        for component in [
            "binary native WHIR grinding bits",
            "binary native grinding bits",
        ] {
            let grinding = text(&verifier(component));
            assert!(grinding.contains("lower --pow-bits"), "{grinding}");
        }
        let domain = text(&verifier("binary native WHIR domain bits"));
        assert!(
            domain.contains("VerifierLimits::max_log_domain_or_degree"),
            "{domain}"
        );
    }

    #[test]
    fn unflagged_limits_are_not_blamed_on_a_flag() {
        let field = text(&verifier("cap roots"));
        assert!(field.contains("VerifierLimits::max_cap_roots"), "{field}");
        let fixed = text(&verifier("no such component"));
        assert!(fixed.contains("no flag of this example"), "{fixed}");
    }

    #[test]
    fn partial_counts_are_lower_bounds_with_a_multiplicative_bump() {
        let partial = text(&construction("expression nodes"));
        assert!(partial.contains("reached 70"), "{partial}");
        assert!(partial.contains("--max-expression-nodes 128"), "{partial}");
        let exact = text(&verifier("native recursive PCS codeword cells"));
        assert!(exact.contains("needs 70"), "{exact}");
        assert!(
            exact.contains("--max-pcs-codeword-cells 70 or more"),
            "{exact}"
        );
    }

    #[test]
    fn bump_exceeds_the_reached_count_and_doubles_the_limit() {
        assert_eq!(bumped(64, 63), 128);
        assert_eq!(bumped(65, 64), 128);
        assert_eq!(bumped(100, 1000), 2000);
        assert_eq!(bumped(usize::MAX, 1), usize::MAX);
    }

    #[test]
    fn upstream_circuit_strings_still_map_to_their_flags() {
        let mut builder = CircuitBuilder::<Poly64>::new();
        let a = builder.public_input();
        let b = builder.public_input();
        let sum = builder.add(a, b);
        builder.connect(sum, a);
        let built = builder.build().unwrap();
        for (limits, flag) in [
            (
                DirectCircuitLimits {
                    max_witnesses: 0,
                    ..DirectCircuitLimits::default()
                },
                "--max-witnesses",
            ),
            (
                DirectCircuitLimits {
                    max_operations: 0,
                    ..DirectCircuitLimits::default()
                },
                "--max-operations",
            ),
            (
                DirectCircuitLimits {
                    max_trace_cells: 0,
                    ..DirectCircuitLimits::default()
                },
                "--max-trace-cells",
            ),
        ] {
            let error = NativeBusCircuit::with_limits(&built, "recursion", limits)
                .err()
                .expect("a limit failure");
            let message = text(&VerificationError::NativeBusCircuit(error));
            assert!(message.contains(flag), "{message}");
        }
    }

    #[test]
    fn upstream_whir_strings_still_map_to_their_knobs() {
        let protocol = |security_level, pow_bits| ProtocolParameters {
            security_level,
            pow_bits,
            round_log_inv_rates: vec![],
            folding_factor: FoldingFactor::Constant(4),
            soundness_type: SecurityAssumption::JohnsonBound,
            starting_log_inv_rate: 1,
        };
        // 60 grinding bits exceed the 56 the Poly64 challenger supports; 40 variables at rate 1
        // exceed the default 32 domain bits.
        for (num_variables, parameters, expected) in [
            (8, protocol(100, 60), "lower --pow-bits"),
            (
                40,
                protocol(32, 24),
                "VerifierLimits::max_log_domain_or_degree",
            ),
        ] {
            let error = BinaryNativePolyWhirPcsParameters::new(
                num_variables,
                parameters,
                ByteHash::Keccak256,
                0,
            )
            .err()
            .expect("a limit failure");
            let message = text(&error);
            assert!(message.contains(expected), "{message}");
        }
    }
}
