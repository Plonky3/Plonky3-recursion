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

    if is_constraint_diagnostic(message) {
        Some(DebugRejectionKind::Constraint)
    } else if is_lookup_diagnostic(message) {
        Some(DebugRejectionKind::Lookup)
    } else {
        None
    }
}

#[cfg(debug_assertions)]
fn is_constraint_diagnostic(message: &str) -> bool {
    let Some(rest) = message.strip_prefix("constraints not satisfied on row ") else {
        return false;
    };
    let Some((row, failures)) = rest.split_once(": failed constraints = ") else {
        return false;
    };
    is_usize_decimal(row) && is_constraint_failures(failures)
}

#[cfg(debug_assertions)]
fn is_constraint_failures(rendered: &str) -> bool {
    let Some(mut entries) = rendered
        .strip_prefix('[')
        .and_then(|rendered| rendered.strip_suffix(']'))
    else {
        return false;
    };
    if entries.is_empty() {
        return false;
    }

    loop {
        let Some(after_hash) = entries.strip_prefix('#') else {
            return false;
        };
        let Some((_, mut tail)) = take_decimal(after_hash) else {
            return false;
        };

        if tail.starts_with(' ') {
            let Some((_, after_label)) = take_debug_quoted(&tail[1..]) else {
                return false;
            };
            tail = after_label;
        }

        if tail.is_empty() {
            return true;
        }
        let Some(after_separator) = tail.strip_prefix(", ") else {
            return false;
        };
        entries = after_separator;
    }
}

#[cfg(debug_assertions)]
fn is_lookup_diagnostic(message: &str) -> bool {
    let Some(rest) = message.strip_prefix("Lookup mismatch (") else {
        return false;
    };
    let Some((label, rest)) = rest.split_once("): tuple ") else {
        return false;
    };
    if label.is_empty() {
        return false;
    }
    let Some((tuple, rest)) = rest.split_once(" has net multiplicity ") else {
        return false;
    };
    let Some((multiplicity, locations)) = rest.split_once(". Locations: ") else {
        return false;
    };

    is_field_debug_list(tuple) && is_canonical_decimal(multiplicity) && is_locations_list(locations)
}

#[cfg(debug_assertions)]
fn is_field_debug_list(rendered: &str) -> bool {
    let Some(mut entries) = rendered
        .strip_prefix('[')
        .and_then(|rendered| rendered.strip_suffix(']'))
    else {
        return false;
    };
    if entries.is_empty() {
        return true;
    }

    loop {
        let Some((value, tail)) = take_debug_quoted(entries) else {
            return false;
        };
        if !is_canonical_decimal(value) {
            return false;
        }
        if tail.is_empty() {
            return true;
        }
        let Some(after_separator) = tail.strip_prefix(", ") else {
            return false;
        };
        entries = after_separator;
    }
}

#[cfg(debug_assertions)]
fn is_locations_list(rendered: &str) -> bool {
    let Some(mut entries) = rendered
        .strip_prefix('[')
        .and_then(|rendered| rendered.strip_suffix(']'))
    else {
        return false;
    };
    if entries.is_empty() {
        return false;
    }

    loop {
        let Some(rest) = entries.strip_prefix("Location { instance: ") else {
            return false;
        };
        let Some((instance, rest)) = take_decimal(rest) else {
            return false;
        };
        let Some(rest) = rest.strip_prefix(", lookup: ") else {
            return false;
        };
        let Some((lookup, rest)) = take_decimal(rest) else {
            return false;
        };
        let Some(rest) = rest.strip_prefix(", row: ") else {
            return false;
        };
        let Some((row, rest)) = take_decimal(rest) else {
            return false;
        };
        if !is_usize_decimal(instance) || !is_usize_decimal(lookup) || !is_usize_decimal(row) {
            return false;
        }
        let Some(rest) = rest.strip_prefix(" }") else {
            return false;
        };
        if rest.is_empty() {
            return true;
        }
        let Some(after_separator) = rest.strip_prefix(", ") else {
            return false;
        };
        entries = after_separator;
    }
}

#[cfg(debug_assertions)]
fn take_decimal(input: &str) -> Option<(&str, &str)> {
    let length = input.bytes().take_while(u8::is_ascii_digit).count();
    if length == 0 {
        return None;
    }
    let number = &input[..length];
    is_canonical_decimal(number).then_some((number, &input[length..]))
}

#[cfg(debug_assertions)]
fn is_usize_decimal(input: &str) -> bool {
    is_canonical_decimal(input) && input.parse::<usize>().is_ok()
}

#[cfg(debug_assertions)]
fn is_canonical_decimal(input: &str) -> bool {
    !input.is_empty()
        && input.bytes().all(|byte| byte.is_ascii_digit())
        && (input == "0" || !input.starts_with('0'))
}

#[cfg(debug_assertions)]
fn take_debug_quoted(input: &str) -> Option<(&str, &str)> {
    if !input.starts_with('"') {
        return None;
    }

    let mut escaped = false;
    for (offset, byte) in input.bytes().enumerate().skip(1) {
        if escaped {
            escaped = false;
            continue;
        }
        match byte {
            b'\\' => escaped = true,
            b'"' => return Some((&input[1..offset], &input[offset + 1..])),
            byte if byte.is_ascii_control() => return None,
            _ => {}
        }
    }
    None
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
}
