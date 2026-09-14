//! Strict parser for the debug-only diagnostics emitted by batch-STARK checks.
//!
//! This module deliberately parses only the diagnostic text. Crate-specific test
//! wrappers remain responsible for catching panics and checking release errors.

/// A recognized algebraic rejection emitted by a debug build.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DebugRejectionKind {
    Constraint,
    Lookup,
}

/// Classifies an exact upstream batch-STARK diagnostic.
pub fn classify_debug_diagnostic(message: &str) -> Option<DebugRejectionKind> {
    if is_constraint_diagnostic(message) {
        Some(DebugRejectionKind::Constraint)
    } else if is_lookup_diagnostic(message) {
        Some(DebugRejectionKind::Lookup)
    } else {
        None
    }
}

fn is_constraint_diagnostic(message: &str) -> bool {
    let Some(rest) = message.strip_prefix("constraints not satisfied on row ") else {
        return false;
    };
    let Some((row, failures)) = rest.split_once(": failed constraints = ") else {
        return false;
    };
    is_usize_decimal(row) && is_constraint_failures(failures)
}

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
        let Some((index, mut tail)) = take_decimal(after_hash) else {
            return false;
        };
        if !is_usize_decimal(index) {
            return false;
        }
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

fn take_decimal(input: &str) -> Option<(&str, &str)> {
    let length = input.bytes().take_while(u8::is_ascii_digit).count();
    if length == 0 {
        return None;
    }
    let number = &input[..length];
    is_canonical_decimal(number).then_some((number, &input[length..]))
}

fn is_usize_decimal(input: &str) -> bool {
    is_canonical_decimal(input) && input.parse::<usize>().is_ok()
}

fn is_canonical_decimal(input: &str) -> bool {
    !input.is_empty()
        && input.bytes().all(|byte| byte.is_ascii_digit())
        && (input == "0" || !input.starts_with('0'))
}

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
            b'"' => {
                let token = &input[..offset + 1];
                let decoded = decode_debug_string(&input[1..offset])?;
                if alloc::format!("{decoded:?}") == token {
                    return Some((&input[1..offset], &input[offset + 1..]));
                }
                return None;
            }
            byte if byte.is_ascii_control() => return None,
            _ => {}
        }
    }
    None
}

fn decode_debug_string(raw: &str) -> Option<alloc::string::String> {
    let mut decoded = alloc::string::String::new();
    let mut chars = raw.chars();
    while let Some(character) = chars.next() {
        if character != '\\' {
            if character.is_control() {
                return None;
            }
            decoded.push(character);
            continue;
        }
        match chars.next()? {
            '\\' => decoded.push('\\'),
            '"' => decoded.push('"'),
            '0' => decoded.push('\0'),
            'n' => decoded.push('\n'),
            'r' => decoded.push('\r'),
            't' => decoded.push('\t'),
            'u' => {
                if chars.next()? != '{' {
                    return None;
                }
                let mut digits = alloc::string::String::new();
                loop {
                    let character = chars.next()?;
                    if character == '}' {
                        break;
                    }
                    if !character.is_ascii_hexdigit() || digits.len() == 6 {
                        return None;
                    }
                    digits.push(character);
                }
                let code_point = u32::from_str_radix(&digits, 16).ok()?;
                decoded.push(char::from_u32(code_point)?);
            }
            _ => return None,
        }
    }
    Some(decoded)
}

#[cfg(test)]
mod tests {
    use super::{DebugRejectionKind, classify_debug_diagnostic};

    #[test]
    fn accepts_canonical_constraint_diagnostic() {
        let label = "quote \" slash \\ newline\n control\u{7} unicode λ";
        let message = alloc::format!(
            "constraints not satisfied on row 1: failed constraints = [#0 {label:?}]"
        );
        assert_eq!(
            classify_debug_diagnostic(&message),
            Some(DebugRejectionKind::Constraint)
        );
    }

    #[test]
    fn accepts_canonical_lookup_diagnostic() {
        assert_eq!(
            classify_debug_diagnostic(
                "Lookup mismatch (WitnessChecks): tuple [\"1\", \"2\"] has net multiplicity 1. Locations: [Location { instance: 0, lookup: 3, row: 4 }]"
            ),
            Some(DebugRejectionKind::Lookup)
        );
    }

    #[test]
    fn rejects_near_miss_and_malformed_diagnostics() {
        for message in [
            "constraints not satisfied on row unrelated",
            "Lookup mismatch (unrelated)",
            "constraints not satisfied on row 1: failed constraints = [#18446744073709551616]",
            "constraints not satisfied on row 1: failed constraints = [#0 \"bad\\q\"]",
            "constraints not satisfied on row 1: failed constraints = [#0 \"bad\\\u{1}\"]",
        ] {
            assert_eq!(
                classify_debug_diagnostic(message),
                None,
                "accepted {message:?}"
            );
        }
    }
}
