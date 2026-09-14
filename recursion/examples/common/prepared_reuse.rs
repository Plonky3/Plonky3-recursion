use p3_recursion::VerificationError;

/// Identify the one validation result that permits an example to reprepare its local owner.
/// Malformed, configuration, and proving errors remain caller-visible.
pub(crate) const fn is_prepared_input_mismatch(error: &VerificationError) -> bool {
    matches!(error, VerificationError::PreparedInputMismatch { .. })
}
