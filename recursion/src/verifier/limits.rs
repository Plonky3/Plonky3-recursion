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
    pub cap_roots: usize,
    pub final_poly_evaluations: usize,
    /// Maximum sum of WHIR opening-batch widths for one commitment.
    ///
    /// This is retained as allocation-free geometry for the backend's
    /// conservative stacked-domain restoration bound; it is not itself a
    /// separately configured policy axis.
    #[doc(hidden)]
    pub max_whir_opening_width_sum: usize,
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
            ("cap roots", self.cap_roots, limits.max_cap_roots),
            (
                "final polynomial evaluations",
                self.final_poly_evaluations,
                limits.max_final_poly_evaluations,
            ),
        ];
        for (component, actual, limit) in checks {
            check_limit(component, actual, limit)?;
        }
        Ok(())
    }

    /// Record one proof round's query axis. The configured ceiling is per round;
    /// the checked aggregate is retained only for overflow detection and diagnostics.
    pub fn add_query_round(
        &mut self,
        limits: &VerifierLimits,
        count: usize,
    ) -> Result<(), VerificationError> {
        if count > limits.max_queries_per_round {
            return Err(VerificationError::ResourceLimitExceeded {
                component: "queries per round",
                actual: count,
                limit: limits.max_queries_per_round,
            });
        }
        self.queries = Self::checked_add("aggregate query rows", self.queries, count)?;
        Ok(())
    }

    pub fn add_rounds(
        &mut self,
        limits: &VerifierLimits,
        count: usize,
    ) -> Result<(), VerificationError> {
        self.rounds = Self::checked_add("rounds", self.rounds, count)?;
        check_limit("rounds", self.rounds, limits.max_rounds)
    }

    pub fn add_instances(
        &mut self,
        limits: &VerifierLimits,
        count: usize,
    ) -> Result<(), VerificationError> {
        self.instances = Self::checked_add("instances", self.instances, count)?;
        check_limit("instances", self.instances, limits.max_instances)
    }

    pub fn add_metadata_entries(
        &mut self,
        limits: &VerifierLimits,
        count: usize,
    ) -> Result<(), VerificationError> {
        self.metadata_entries =
            Self::checked_add("metadata entries", self.metadata_entries, count)?;
        check_limit(
            "metadata entries",
            self.metadata_entries,
            limits.max_metadata_entries,
        )
    }

    pub fn add_metadata_string_bytes(
        &mut self,
        limits: &VerifierLimits,
        count: usize,
    ) -> Result<(), VerificationError> {
        self.metadata_string_bytes =
            Self::checked_add("metadata string bytes", self.metadata_string_bytes, count)?;
        check_limit(
            "metadata string bytes",
            self.metadata_string_bytes,
            limits.max_metadata_string_bytes,
        )
    }

    pub fn add_scalar_elements(
        &mut self,
        limits: &VerifierLimits,
        count: usize,
    ) -> Result<(), VerificationError> {
        self.scalar_elements = Self::checked_add("scalar elements", self.scalar_elements, count)?;
        check_limit(
            "scalar elements",
            self.scalar_elements,
            limits.max_total_scalar_elements,
        )
    }

    pub fn add_cap_roots(
        &mut self,
        limits: &VerifierLimits,
        count: usize,
    ) -> Result<(), VerificationError> {
        self.cap_roots = Self::checked_add("cap roots", self.cap_roots, count)?;
        check_limit("cap roots", self.cap_roots, limits.max_cap_roots)
    }

    pub fn add_final_poly_evaluations(
        &mut self,
        limits: &VerifierLimits,
        count: usize,
    ) -> Result<(), VerificationError> {
        check_limit(
            "final polynomial evaluations",
            count,
            limits.max_final_poly_evaluations,
        )?;
        self.final_poly_evaluations = self.final_poly_evaluations.max(count);
        Ok(())
    }

    pub fn add_compressed_frontier_hashes(
        &mut self,
        limits: &VerifierLimits,
        count: usize,
    ) -> Result<(), VerificationError> {
        self.compressed_frontier_hashes = Self::checked_add(
            "compressed frontier hashes",
            self.compressed_frontier_hashes,
            count,
        )?;
        check_limit(
            "compressed frontier hashes",
            self.compressed_frontier_hashes,
            limits.max_compressed_frontier_hashes,
        )
    }

    pub fn add_restored_authentication_path_hashes(
        &mut self,
        limits: &VerifierLimits,
        queries: usize,
        depth: usize,
    ) -> Result<(), VerificationError> {
        let count =
            queries
                .checked_mul(depth)
                .ok_or(VerificationError::ResourceArithmeticOverflow {
                    component: "restored authentication-path hashes",
                })?;
        self.restored_authentication_path_hashes = Self::checked_add(
            "restored authentication-path hashes",
            self.restored_authentication_path_hashes,
            count,
        )?;
        check_limit(
            "restored authentication-path hashes",
            self.restored_authentication_path_hashes,
            limits.max_restored_authentication_path_hashes,
        )
    }

    pub const fn check_matrix_width(
        &self,
        limits: &VerifierLimits,
        width: usize,
    ) -> Result<(), VerificationError> {
        check_limit("matrix or row width", width, limits.max_matrix_width)
    }

    pub const fn check_log_degree(
        &self,
        limits: &VerifierLimits,
        value: usize,
    ) -> Result<(), VerificationError> {
        check_limit(
            "log domain or degree",
            value,
            limits.max_log_domain_or_degree,
        )
    }

    pub fn merge(&mut self, limits: &VerifierLimits, other: Self) -> Result<(), VerificationError> {
        self.add_instances(limits, other.instances)?;
        self.add_rounds(limits, other.rounds)?;
        self.queries = Self::checked_add("aggregate query rows", self.queries, other.queries)?;
        self.add_scalar_elements(limits, other.scalar_elements)?;
        self.add_metadata_entries(limits, other.metadata_entries)?;
        self.add_metadata_string_bytes(limits, other.metadata_string_bytes)?;
        self.add_compressed_frontier_hashes(limits, other.compressed_frontier_hashes)?;
        self.restored_authentication_path_hashes = Self::checked_add(
            "restored authentication-path hashes",
            self.restored_authentication_path_hashes,
            other.restored_authentication_path_hashes,
        )?;
        check_limit(
            "restored authentication-path hashes",
            self.restored_authentication_path_hashes,
            limits.max_restored_authentication_path_hashes,
        )?;
        self.add_cap_roots(limits, other.cap_roots)?;
        self.add_final_poly_evaluations(limits, other.final_poly_evaluations)?;
        self.max_whir_opening_width_sum = self
            .max_whir_opening_width_sum
            .max(other.max_whir_opening_width_sum);
        Ok(())
    }
}

/// Reject `actual` when it exceeds the configured `limit` for `component`.
pub(crate) const fn check_limit(
    component: &'static str,
    actual: usize,
    limit: usize,
) -> Result<(), VerificationError> {
    if actual > limit {
        Err(VerificationError::ResourceLimitExceeded {
            component,
            actual,
            limit,
        })
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_match_the_operational_policy() {
        let limits = VerifierLimits::default();
        assert_eq!(limits.max_instances, 4096);
        assert_eq!(limits.max_rounds, 64);
        assert_eq!(limits.max_queries_per_round, 4096);
        assert_eq!(limits.max_log_domain_or_degree, 32);
        assert_eq!(limits.max_matrix_width, 1 << 20);
        assert_eq!(limits.max_final_poly_evaluations, 1 << 20);
        assert_eq!(limits.max_cap_roots, 1 << 16);
        assert_eq!(limits.max_total_scalar_elements, 1 << 24);
        assert_eq!(limits.max_metadata_entries, 1 << 16);
        assert_eq!(limits.max_metadata_string_bytes, 1 << 20);
        assert_eq!(limits.max_compressed_frontier_hashes, 1 << 20);
        assert_eq!(limits.max_restored_authentication_path_hashes, 1 << 22);
    }

    #[test]
    fn boundaries_and_overflow_are_typed() {
        let limits = VerifierLimits {
            max_instances: 2,
            ..VerifierLimits::default()
        };
        let mut usage = InputResourceUsage {
            instances: 2,
            ..InputResourceUsage::default()
        };
        usage.check(&limits).expect("exact boundary is accepted");
        usage.instances = 3;
        assert!(matches!(
            usage.check(&limits),
            Err(VerificationError::ResourceLimitExceeded {
                component: "instances",
                actual: 3,
                limit: 2
            })
        ));
        assert!(matches!(
            InputResourceUsage::checked_add("queries", usize::MAX, 1),
            Err(VerificationError::ResourceArithmeticOverflow {
                component: "queries"
            })
        ));
    }

    #[test]
    fn query_limit_is_per_round_not_an_aggregate_ceiling() {
        let limits = VerifierLimits {
            max_queries_per_round: 2,
            ..VerifierLimits::default()
        };
        let mut usage = InputResourceUsage::default();

        usage
            .add_query_round(&limits, 2)
            .expect("first round is exactly at the boundary");
        usage
            .add_query_round(&limits, 2)
            .expect("a second in-budget round is not compared as an aggregate");
        usage
            .check(&limits)
            .expect("combined query count is bounded by its axes");

        assert!(matches!(
            usage.add_query_round(&limits, 3),
            Err(VerificationError::ResourceLimitExceeded {
                component: "queries per round",
                actual: 3,
                limit: 2,
            })
        ));
    }

    #[test]
    fn every_counter_accepts_exact_and_rejects_one_below() {
        let exact = VerifierLimits {
            max_instances: 2,
            max_rounds: 2,
            max_queries_per_round: 2,
            max_log_domain_or_degree: 2,
            max_matrix_width: 2,
            max_final_poly_evaluations: 2,
            max_cap_roots: 2,
            max_total_scalar_elements: 2,
            max_metadata_entries: 2,
            max_metadata_string_bytes: 2,
            max_compressed_frontier_hashes: 2,
            max_restored_authentication_path_hashes: 2,
        };
        let mut usage = InputResourceUsage::default();
        usage.add_instances(&exact, 2).unwrap();
        usage.add_rounds(&exact, 2).unwrap();
        usage.add_query_round(&exact, 2).unwrap();
        usage.check_log_degree(&exact, 2).unwrap();
        usage.check_matrix_width(&exact, 2).unwrap();
        usage.add_final_poly_evaluations(&exact, 2).unwrap();
        usage.add_cap_roots(&exact, 2).unwrap();
        usage.add_scalar_elements(&exact, 2).unwrap();
        usage.add_metadata_entries(&exact, 2).unwrap();
        usage.add_metadata_string_bytes(&exact, 2).unwrap();
        usage.add_compressed_frontier_hashes(&exact, 2).unwrap();
        usage
            .add_restored_authentication_path_hashes(&exact, 1, 2)
            .unwrap();

        let below = VerifierLimits {
            max_instances: 1,
            max_rounds: 1,
            max_queries_per_round: 1,
            max_log_domain_or_degree: 1,
            max_matrix_width: 1,
            max_final_poly_evaluations: 1,
            max_cap_roots: 1,
            max_total_scalar_elements: 1,
            max_metadata_entries: 1,
            max_metadata_string_bytes: 1,
            max_compressed_frontier_hashes: 1,
            max_restored_authentication_path_hashes: 1,
        };
        let mut one = InputResourceUsage::default();
        assert!(matches!(
            one.add_instances(&below, 2),
            Err(VerificationError::ResourceLimitExceeded {
                component: "instances",
                ..
            })
        ));
        let mut one = InputResourceUsage::default();
        assert!(matches!(
            one.add_rounds(&below, 2),
            Err(VerificationError::ResourceLimitExceeded {
                component: "rounds",
                ..
            })
        ));
        let mut one = InputResourceUsage::default();
        assert!(matches!(
            one.add_query_round(&below, 2),
            Err(VerificationError::ResourceLimitExceeded {
                component: "queries per round",
                ..
            })
        ));
        assert!(matches!(
            one.check_log_degree(&below, 2),
            Err(VerificationError::ResourceLimitExceeded {
                component: "log domain or degree",
                ..
            })
        ));
        assert!(matches!(
            one.check_matrix_width(&below, 2),
            Err(VerificationError::ResourceLimitExceeded {
                component: "matrix or row width",
                ..
            })
        ));
        assert!(matches!(
            one.add_final_poly_evaluations(&below, 2),
            Err(VerificationError::ResourceLimitExceeded {
                component: "final polynomial evaluations",
                ..
            })
        ));
        let mut one = InputResourceUsage::default();
        assert!(matches!(
            one.add_cap_roots(&below, 2),
            Err(VerificationError::ResourceLimitExceeded {
                component: "cap roots",
                ..
            })
        ));
        let mut one = InputResourceUsage::default();
        assert!(matches!(
            one.add_scalar_elements(&below, 2),
            Err(VerificationError::ResourceLimitExceeded {
                component: "scalar elements",
                ..
            })
        ));
        let mut one = InputResourceUsage::default();
        assert!(matches!(
            one.add_metadata_entries(&below, 2),
            Err(VerificationError::ResourceLimitExceeded {
                component: "metadata entries",
                ..
            })
        ));
        let mut one = InputResourceUsage::default();
        assert!(matches!(
            one.add_metadata_string_bytes(&below, 2),
            Err(VerificationError::ResourceLimitExceeded {
                component: "metadata string bytes",
                ..
            })
        ));
        let mut one = InputResourceUsage::default();
        assert!(matches!(
            one.add_compressed_frontier_hashes(&below, 2),
            Err(VerificationError::ResourceLimitExceeded {
                component: "compressed frontier hashes",
                ..
            })
        ));
        let mut one = InputResourceUsage::default();
        assert!(matches!(
            one.add_restored_authentication_path_hashes(&below, 1, 2),
            Err(VerificationError::ResourceLimitExceeded {
                component: "restored authentication-path hashes",
                ..
            })
        ));
    }

    #[test]
    fn final_polynomial_limit_is_per_polynomial_not_aggregate() {
        let limits = VerifierLimits {
            max_final_poly_evaluations: 2,
            max_total_scalar_elements: 4,
            ..VerifierLimits::default()
        };
        let mut usage = InputResourceUsage::default();

        usage.add_final_poly_evaluations(&limits, 2).unwrap();
        usage.add_scalar_elements(&limits, 2).unwrap();
        usage.add_final_poly_evaluations(&limits, 2).unwrap();
        usage.add_scalar_elements(&limits, 2).unwrap();

        assert_eq!(usage.final_poly_evaluations, 2);
        assert_eq!(usage.scalar_elements, 4);
    }

    #[test]
    fn whir_width_summary_defaults_to_zero_and_merges_by_max() {
        let limits = VerifierLimits::default();
        let mut usage = InputResourceUsage::default();
        assert_eq!(usage.max_whir_opening_width_sum, 0);

        let other = InputResourceUsage {
            max_whir_opening_width_sum: 7,
            ..InputResourceUsage::default()
        };
        other
            .check(&limits)
            .expect("the geometry summary is checked by the WHIR backend, not as a direct axis");
        usage.merge(&limits, other).unwrap();

        assert_eq!(usage.max_whir_opening_width_sum, 7);
    }

    #[test]
    fn combined_totals_and_products_use_checked_arithmetic() {
        let limits = VerifierLimits {
            max_cap_roots: 1,
            max_total_scalar_elements: usize::MAX,
            max_restored_authentication_path_hashes: usize::MAX,
            ..VerifierLimits::default()
        };
        let mut usage = InputResourceUsage::default();
        usage.add_cap_roots(&limits, 1).unwrap();
        assert!(matches!(
            usage.add_cap_roots(&limits, 1),
            Err(VerificationError::ResourceLimitExceeded {
                component: "cap roots",
                actual: 2,
                limit: 1
            })
        ));

        let mut usage = InputResourceUsage::default();
        assert!(matches!(
            usage.add_restored_authentication_path_hashes(&limits, usize::MAX, 2),
            Err(VerificationError::ResourceArithmeticOverflow {
                component: "restored authentication-path hashes"
            })
        ));
        usage.queries = usize::MAX;
        assert!(matches!(
            usage.add_query_round(&limits, 1),
            Err(VerificationError::ResourceArithmeticOverflow {
                component: "aggregate query rows"
            })
        ));
    }
}
