#[cfg(debug_assertions)]
use std::any::Any;
use std::fmt;
#[cfg(debug_assertions)]
use std::panic::AssertUnwindSafe;

use p3_circuit_prover::BatchStarkProverError;

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
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum DebugRejectionKind {
    Constraint,
    Lookup,
}

#[cfg(debug_assertions)]
fn classify_debug_panic(payload: &(dyn Any + Send)) -> Option<DebugRejectionKind> {
    let message = payload
        .downcast_ref::<String>()
        .map(String::as_str)
        .or_else(|| payload.downcast_ref::<&str>().copied())?;

    if message.starts_with("constraints not satisfied on row ") {
        Some(DebugRejectionKind::Constraint)
    } else if message.starts_with("Lookup mismatch (") {
        Some(DebugRejectionKind::Lookup)
    } else {
        None
    }
}

#[cfg(debug_assertions)]
pub(crate) fn run_with_debug_oracle<T>(f: impl FnOnce() -> T) -> Result<T, DebugRejectionKind> {
    match std::panic::catch_unwind(AssertUnwindSafe(f)) {
        Ok(value) => Ok(value),
        Err(payload) => match classify_debug_panic(payload.as_ref()) {
            Some(kind) => Err(kind),
            None => std::panic::resume_unwind(payload),
        },
    }
}

pub(crate) fn assert_rejected(result: Result<(), ProofCheckError>, context: &str) {
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
