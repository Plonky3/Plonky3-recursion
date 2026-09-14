#[cfg(debug_assertions)]
use std::any::Any;
use std::fmt;
#[cfg(debug_assertions)]
use std::panic::AssertUnwindSafe;

use p3_circuit_prover::BatchStarkProverError;
#[cfg(debug_assertions)]
pub(crate) use p3_test_utils::rejection_oracle::DebugRejectionKind;
#[cfg(debug_assertions)]
use p3_test_utils::rejection_oracle::classify_debug_diagnostic;

#[derive(Debug)]
pub(crate) enum ProofCheckError {
    Prove(BatchStarkProverError),
    Verify(BatchStarkProverError),
    #[cfg(debug_assertions)]
    DebugPanic(DebugRejectionKind),
}

impl fmt::Display for ProofCheckError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Prove(error) => write!(f, "prover error: {error}"),
            Self::Verify(error) => write!(f, "verifier error: {error}"),
            #[cfg(debug_assertions)]
            Self::DebugPanic(kind) => write!(f, "debug rejection: {kind:?}"),
        }
    }
}

#[cfg(debug_assertions)]
fn classify_debug_panic(payload: &(dyn Any + Send)) -> Option<DebugRejectionKind> {
    let message = payload
        .downcast_ref::<String>()
        .map(String::as_str)
        .or_else(|| payload.downcast_ref::<&str>().copied())?;

    classify_debug_diagnostic(message)
}

#[cfg(debug_assertions)]
pub(crate) fn run_with_debug_oracle<T>(f: impl FnOnce() -> T) -> Result<T, DebugRejectionKind> {
    match std::panic::catch_unwind(AssertUnwindSafe(f)) {
        Ok(value) => Ok(value),
        Err(payload) => {
            if let Some(kind) = classify_debug_panic(payload.as_ref()) {
                return Err(kind);
            }
            std::panic::resume_unwind(payload)
        }
    }
}

pub(crate) fn assert_rejected(result: &Result<(), ProofCheckError>, context: &str) {
    #[cfg(debug_assertions)]
    assert!(
        matches!(
            result,
            Err(ProofCheckError::DebugPanic(
                DebugRejectionKind::Constraint | DebugRejectionKind::Lookup
            ))
        ),
        "{context}: forged trace must hit a recognized debug rejection"
    );

    #[cfg(not(debug_assertions))]
    assert!(
        matches!(
            result,
            Err(ProofCheckError::Verify(BatchStarkProverError::Verify(_)))
        ),
        "{context}: forged trace must prove and reach verifier algebraic rejection"
    );
}

#[cfg(debug_assertions)]
#[cfg(test)]
mod tests {
    fn assert_unknown_panic_propagates(message: &'static str) {
        let outcome = std::panic::catch_unwind(|| {
            let _ = super::run_with_debug_oracle(|| std::panic::panic_any(message));
        });
        let payload = outcome.expect_err("an unknown diagnostic must propagate out of the oracle");
        assert_eq!(payload.downcast_ref::<&str>().copied(), Some(message));
    }

    #[test]
    fn near_miss_constraint_diagnostic_is_not_accepted() {
        assert_unknown_panic_propagates("constraints not satisfied on row unrelated");
    }

    #[test]
    fn near_miss_lookup_diagnostic_is_not_accepted() {
        assert_unknown_panic_propagates("Lookup mismatch (unrelated)");
    }

    #[test]
    fn oversized_constraint_index_is_not_accepted() {
        assert_unknown_panic_propagates(
            "constraints not satisfied on row 1: failed constraints = [#18446744073709551616]",
        );
    }

    #[test]
    fn noncanonical_debug_escape_is_not_accepted() {
        assert_unknown_panic_propagates(
            "constraints not satisfied on row 1: failed constraints = [#0 \"bad\\q\"]",
        );
    }

    #[test]
    fn raw_control_after_debug_escape_is_not_accepted() {
        assert_unknown_panic_propagates(
            "constraints not satisfied on row 1: failed constraints = [#0 \"bad\\\x01\"]",
        );
    }

    #[test]
    fn canonical_debug_label_is_accepted() {
        let label = "quote \" slash \\ newline\n control\u{7} unicode λ";
        let message =
            format!("constraints not satisfied on row 1: failed constraints = [#0 {label:?}]");
        assert_eq!(
            super::classify_debug_panic(&message),
            Some(super::DebugRejectionKind::Constraint)
        );
    }
}
