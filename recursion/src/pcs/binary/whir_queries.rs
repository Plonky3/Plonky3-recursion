//! Proof-independent stratified sampling for released additive WHIR.

use alloc::vec::Vec;
use core::hash::Hash;

use p3_circuit::ops::binary_encoding::PrimeBinaryEncoding;
use p3_circuit::ops::binary_host::BinaryCircuitHost;
use p3_circuit::{CircuitBuilder, ExprId};
use p3_field::{ExtensionField, Field, PrimeField64};

use crate::BinaryTower128Challenger;
use crate::verifier::{InputResourceUsage, VerificationError, VerifierLimits};

/// Checked geometry of one native WHIR query site. `query_draws == 0`
/// enumerates the complete folded domain without consuming transcript output.
/// Otherwise the positive draw count must be smaller than the domain, and
/// its binary summands fix the deepest-first stratum partitions. Sampling
/// preserves order and repeated positions across different partitions.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BinaryWhirQueryPlan {
    index_bits: usize,
    query_draws: usize,
    num_queries: usize,
    depths: Vec<usize>,
}

impl BinaryWhirQueryPlan {
    pub fn new(index_bits: usize, query_draws: usize) -> Result<Self, VerificationError> {
        Self::with_limits(index_bits, query_draws, &VerifierLimits::default())
    }

    /// Applies finite query, bit-width, metadata and generated-scalar budgets
    /// before allocating a query schedule. The enclosing verifier obtains
    /// these arguments from its trusted native `WhirShape`.
    pub fn with_limits(
        index_bits: usize,
        query_draws: usize,
        limits: &VerifierLimits,
    ) -> Result<Self, VerificationError> {
        let limit = limits
            .max_log_domain_or_degree
            .min(usize::BITS as usize - 1);
        if index_bits > limit {
            return Err(VerificationError::ResourceLimitExceeded {
                component: "binary WHIR query index bits",
                actual: index_bits,
                limit,
            });
        }
        let domain_size = 1usize << index_bits;
        if query_draws >= domain_size {
            return Err(VerificationError::InvalidProofShape(
                "binary WHIR saturated query site must have zero draws".into(),
            ));
        }
        let num_queries = if query_draws == 0 {
            domain_size
        } else {
            query_draws
        };
        let mut usage = InputResourceUsage::default();
        usage.add_query_round(limits, num_queries)?;
        usage.add_scalar_elements(
            limits,
            num_queries.checked_mul(index_bits).ok_or(
                VerificationError::ResourceArithmeticOverflow {
                    component: "binary WHIR query bits",
                },
            )?,
        )?;
        usage.add_metadata_entries(limits, query_draws.count_ones() as usize)?;
        let depths = (0..index_bits)
            .rev()
            .filter(|&depth| (query_draws >> depth) & 1 != 0)
            .collect();
        Ok(Self {
            index_bits,
            query_draws,
            num_queries,
            depths,
        })
    }

    pub const fn index_bits(&self) -> usize {
        self.index_bits
    }

    pub const fn num_queries(&self) -> usize {
        self.num_queries
    }

    /// Returns little-endian index bits in native query order. The fixed draw
    /// schedule leaves the ordinary challenger at its exact continuation.
    /// On error the challenger is unchanged; the builder may retain emitted
    /// expressions. Every target belongs to this builder.
    pub fn sample<BF, EF>(
        &self,
        circuit: &mut CircuitBuilder<EF>,
        challenger: &mut BinaryTower128Challenger,
    ) -> Result<Vec<Vec<ExprId>>, VerificationError>
    where
        BF: PrimeField64,
        EF: ExtensionField<BF> + Eq + Hash,
    {
        self.sample_with_host::<PrimeBinaryEncoding<BF>, EF>(circuit, challenger)
    }

    pub fn sample_with_host<H, CF>(
        &self,
        circuit: &mut CircuitBuilder<CF>,
        challenger: &mut BinaryTower128Challenger,
    ) -> Result<Vec<Vec<ExprId>>, VerificationError>
    where
        CF: Field + Eq + Hash,
        H: BinaryCircuitHost<CF>,
    {
        H::check_carrier()?;
        let zero = circuit.define_const(CF::ZERO);
        let one = circuit.define_const(CF::ONE);
        if self.query_draws == 0 {
            return Ok((0..self.num_queries)
                .map(|index| {
                    (0..self.index_bits)
                        .map(|bit| if (index >> bit) & 1 == 0 { zero } else { one })
                        .collect()
                })
                .collect());
        }
        let mut staged = challenger.clone();
        let mut indices = Vec::with_capacity(self.num_queries);
        for &depth in &self.depths {
            let low_bits = self.index_bits - depth;
            for stratum in 0..1usize << depth {
                // Native uniform sampling consumes eight bytes even if the
                // width is zero; no duplicate rejection or sorting follows.
                let mut bits = staged.sample_bits_with_host::<H, CF>(circuit, low_bits)?;
                bits.extend((0..depth).map(
                    |bit| {
                        if (stratum >> bit) & 1 == 0 { zero } else { one }
                    },
                ));
                indices.push(bits);
            }
        }
        *challenger = staged;
        Ok(indices)
    }
}
