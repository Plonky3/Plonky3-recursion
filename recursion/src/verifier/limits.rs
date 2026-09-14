//! Verifier-owned operational budgets.
//!
//! These limits are intentionally finite compatibility defaults.  They bound
//! work the built-in verifier asks the circuit builder and restoration helpers
//! to perform; they are not a wall-clock or process-memory guarantee for
//! arbitrary custom AIR or backend code.

use crate::verifier::VerificationError;

/// Finite ceilings for proof-facing verifier work.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VerifierLimits {
    pub max_instances: usize,
    pub max_rounds: usize,
    pub max_queries_per_round: usize,
    pub max_log_domain_or_degree: usize,
    pub max_matrix_width: usize,
    pub max_final_poly_evaluations: usize,
    pub max_cap_roots: usize,
    pub max_total_scalar_elements: usize,
    pub max_metadata_entries: usize,
    pub max_metadata_string_bytes: usize,
    pub max_compressed_frontier_hashes: usize,
    pub max_restored_authentication_path_hashes: usize,
}

impl Default for VerifierLimits {
    fn default() -> Self {
        Self {
            max_instances: 4096,
            max_rounds: 64,
            max_queries_per_round: 4096,
            max_log_domain_or_degree: 32,
            max_matrix_width: 1 << 20,
            max_final_poly_evaluations: 1 << 20,
            max_cap_roots: 1 << 16,
            max_total_scalar_elements: 1 << 24,
            max_metadata_entries: 1 << 16,
            max_metadata_string_bytes: 1 << 20,
            max_compressed_frontier_hashes: 1 << 20,
            max_restored_authentication_path_hashes: 1 << 22,
        }
    }
}

/// Allocation-free counters used by audited built-in input walks.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct InputResourceUsage {
    pub instances: usize,
    pub rounds: usize,
    pub queries: usize,
    pub scalar_elements: usize,
    pub metadata_entries: usize,
    pub metadata_string_bytes: usize,
    pub compressed_frontier_hashes: usize,
    pub restored_authentication_path_hashes: usize,
}

impl InputResourceUsage {
    pub fn checked_add(
        component: &'static str,
        current: usize,
        value: usize,
    ) -> Result<usize, VerificationError> {
        current
            .checked_add(value)
            .ok_or(VerificationError::ResourceArithmeticOverflow { component })
    }

    pub fn check(self, limits: &VerifierLimits) -> Result<(), VerificationError> {
        let checks = [
            ("instances", self.instances, limits.max_instances),
            ("rounds", self.rounds, limits.max_rounds),
            ("queries", self.queries, limits.max_queries_per_round),
            (
                "scalar elements",
                self.scalar_elements,
                limits.max_total_scalar_elements,
            ),
            (
                "metadata entries",
                self.metadata_entries,
                limits.max_metadata_entries,
            ),
            (
                "metadata string bytes",
                self.metadata_string_bytes,
                limits.max_metadata_string_bytes,
            ),
            (
                "compressed frontier hashes",
                self.compressed_frontier_hashes,
                limits.max_compressed_frontier_hashes,
            ),
            (
                "restored authentication-path hashes",
                self.restored_authentication_path_hashes,
                limits.max_restored_authentication_path_hashes,
            ),
        ];
        for (component, actual, limit) in checks {
            if actual > limit {
                return Err(VerificationError::ResourceLimitExceeded {
                    component,
                    actual,
                    limit,
                });
            }
        }
        Ok(())
    }
}
