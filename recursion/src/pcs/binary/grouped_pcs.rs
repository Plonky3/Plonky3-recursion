//! Full binary PCS relation with verifier-owned adjacent-symbol grouping.

use alloc::vec::Vec;
use core::hash::Hash;

use p3_binary_pcs::BinaryPcsConfig;
use p3_binary_pcs::transcript::BinaryPcsShape;
use p3_circuit::ops::{BinaryTower128Target, ByteHash};
use p3_circuit::{CircuitBuilder, ExprId};
use p3_field::{ExtensionField, PrimeField64};
use p3_sumcheck::OpeningProtocol;

use super::input::{alloc_digest, alloc_field};
use super::verifier::batches;
use super::whir_plan::invalid;
use super::{
    BinaryGroupedOraclePlan, BinaryPcs128ProofTargets, BinaryPcsInputShape, BinaryPcsVerifier,
    RecursiveBinaryChallengeField, RecursiveBinaryTowerField,
};
use crate::verifier::{InputResourceUsage, VerificationError, VerifierLimits};
use crate::{BinaryQueryContinuation, BinaryTower128Challenger};

/// Matches the released grouping constructors. The effective leaf width is
/// derived independently at each commitment; it never comes from proof bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BinaryCodewordGrouping {
    /// `GroupedCodewordMmcs::new`: cap at the codeword length.
    Codeword(usize),
    /// `GroupedCodewordMmcs::with_group_size`: cap at the message length.
    Message(usize),
    /// `GroupedCodewordMmcs::for_folding`: one next-fold coset per leaf.
    Folding,
}

impl BinaryCodewordGrouping {
    pub(super) fn effective(
        self,
        config: &BinaryPcsConfig,
        symbol_bits: usize,
    ) -> Result<usize, VerificationError> {
        let (size, limit_bits) = match self {
            Self::Codeword(size) => (size, symbol_bits),
            Self::Message(size) => (
                size,
                symbol_bits
                    .checked_sub(config.log_inv_rate())
                    .ok_or_else(|| invalid("binary grouping message depth underflow"))?,
            ),
            Self::Folding => (
                1usize << config.log_folding_factor(),
                symbol_bits
                    .checked_sub(config.log_inv_rate())
                    .ok_or_else(|| invalid("binary grouping message depth underflow"))?,
            ),
        };
        if !size.is_power_of_two() {
            return Err(invalid("binary grouping size must be a power of two"));
        }
        Ok(size.min(1usize << limit_bits))
    }
}

/// Complete grouped leaves and paths, one per logical queried symbol. Fixed
/// duplication keeps the circuit independent of native multiproof deduplication.
#[derive(Clone, Debug)]
pub struct BinaryGroupedOpeningTargets {
    pub leaves: Vec<Vec<BinaryTower128Target>>,
    pub paths: Vec<Vec<Vec<ExprId>>>,
}

#[derive(Clone, Debug)]
pub struct BinaryGroupedPcsProofTargets {
    /// Sumcheck, logical symbol rows, caps and query indices. Ordinary paths
    /// have fixed empty contents; authentication lives in the grouped openings.
    pub opening: BinaryPcs128ProofTargets,
    /// Base commitment first, then intermediate commitments in native order.
    pub oracles: Vec<BinaryGroupedOpeningTargets>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BinaryGroupedPcsInputShape {
    pub(super) core: BinaryPcsInputShape,
    pub(super) geometry: Vec<(usize, usize, usize)>, // symbol count, leaf width, path depth
}

impl BinaryGroupedPcsInputShape {
    pub(crate) fn native_decode_shape(
        &self,
    ) -> crate::artifact::binary_native::codec::PcsDecode<
        crate::artifact::binary_native::codec::GroupedOracleDecode,
    > {
        use crate::artifact::binary_native::codec::{GroupedOracleDecode, PcsDecode};
        let core = self.core.native_scalar_geometry();
        let log_domain = self.core.config.num_variables() + self.core.config.log_inv_rate();
        let mut oracles = batches(&self.core.config).zip(&self.geometry).map(
            |((start, arity), &(rows, group_size, path_len))| GroupedOracleDecode {
                rows,
                group_size,
                path_len,
                symbol_bits: log_domain - start,
                coset_width: 1usize << arity,
            },
        );
        let base = oracles.next().expect("validated nonempty grouped PCS");
        PcsDecode {
            cap_roots: core.cap_roots,
            sumcheck_rounds: core.sumcheck_rounds,
            eval_widths: core.eval_widths,
            rounds: oracles.collect(),
            base,
            final_codeword: core.final_codeword,
        }
    }

    pub fn allocate_targets<BF, EF>(
        &self,
        b: &mut CircuitBuilder<EF>,
    ) -> Result<BinaryGroupedPcsProofTargets, VerificationError>
    where
        BF: PrimeField64,
        EF: ExtensionField<BF> + Eq + Hash,
    {
        let opening = self.core.allocate_targets::<BF, EF>(b)?;
        let oracles = self
            .geometry
            .iter()
            .map(|&(count, width, depth)| {
                Ok(BinaryGroupedOpeningTargets {
                    leaves: (0..count)
                        .map(|_| (0..width).map(|_| alloc_field::<BF, EF>(b)).collect())
                        .collect::<Result<_, VerificationError>>()?,
                    paths: (0..count)
                        .map(|_| (0..depth).map(|_| alloc_digest(b)).collect())
                        .collect(),
                })
            })
            .collect::<Result<_, VerificationError>>()?;
        Ok(BinaryGroupedPcsProofTargets { opening, oracles })
    }
}

/// Closed grouped authentication frontend over the ordinary transcript and
/// fold relation. Its unauthenticated arithmetic core remains private.
#[derive(Clone, Debug)]
pub struct BinaryGroupedPcsVerifier<F, E> {
    pub(super) inner: BinaryPcsVerifier<F, E>,
    pub(super) base: BinaryGroupedOraclePlan<F>,
    pub(super) rounds: Vec<BinaryGroupedOraclePlan<E>>,
}

impl<F, E> BinaryGroupedPcsVerifier<F, E>
where
    F: RecursiveBinaryTowerField,
    E: RecursiveBinaryChallengeField + ExtensionField<F>,
{
    pub fn new(
        config: BinaryPcsConfig,
        protocol: OpeningProtocol,
        hash: ByteHash,
        cap_height: usize,
        max_query_draws: usize,
        base: BinaryCodewordGrouping,
        rounds: BinaryCodewordGrouping,
    ) -> Result<Self, VerificationError> {
        Self::with_limits(
            config,
            protocol,
            hash,
            cap_height,
            max_query_draws,
            base,
            rounds,
            &VerifierLimits::default(),
        )
    }

    pub fn with_limits(
        config: BinaryPcsConfig,
        protocol: OpeningProtocol,
        hash: ByteHash,
        cap_height: usize,
        max_query_draws: usize,
        base: BinaryCodewordGrouping,
        rounds: BinaryCodewordGrouping,
        limits: &VerifierLimits,
    ) -> Result<Self, VerificationError> {
        // All aggregate geometry and allocation bounds are checked before
        // constructing the per-site plans or retaining their metadata.
        let inner = BinaryPcsVerifier::with_grouping(
            config,
            protocol,
            hash,
            cap_height,
            max_query_draws,
            limits,
            Some([base, rounds]),
        )?;
        let log_domain = config.num_variables() + config.log_inv_rate();
        let base = BinaryGroupedOraclePlan::with_limits(
            log_domain,
            base.effective(&config, log_domain)?,
            hash,
            cap_height,
            limits,
        )?;
        let rounds = batches(&config)
            .skip(1)
            .map(|(start, _)| {
                BinaryGroupedOraclePlan::with_limits(
                    log_domain - start,
                    rounds.effective(&config, log_domain - start)?,
                    hash,
                    cap_height,
                    limits,
                )
            })
            .collect::<Result<_, _>>()?;
        Ok(Self {
            inner,
            base,
            rounds,
        })
    }

    pub const fn input_resource_usage(&self) -> InputResourceUsage {
        self.inner.input_resource_usage()
    }

    pub fn input_shape(&self) -> BinaryGroupedPcsInputShape {
        let shape = BinaryPcsShape::new(&self.inner.config);
        BinaryGroupedPcsInputShape {
            core: self.inner.input_shape(),
            geometry: batches(&self.inner.config)
                .enumerate()
                .map(|(i, (_, arity))| {
                    let (width, depth) = if i == 0 {
                        (self.base.group_size(), self.base.path_len())
                    } else {
                        (
                            self.rounds[i - 1].group_size(),
                            self.rounds[i - 1].path_len(),
                        )
                    };
                    (shape.num_pairs << arity, width, depth)
                })
                .collect(),
        }
    }

    pub fn observe_commitment<BF, EF>(
        &self,
        b: &mut CircuitBuilder<EF>,
        ch: &mut BinaryTower128Challenger,
        cap: &[Vec<ExprId>],
    ) -> Result<(), VerificationError>
    where
        BF: PrimeField64,
        EF: ExtensionField<BF> + Eq + Hash,
    {
        self.inner.observe_commitment::<BF, EF>(b, ch, cap)
    }

    pub fn sample_challenge<BF, EF>(
        &self,
        b: &mut CircuitBuilder<EF>,
        ch: &mut BinaryTower128Challenger,
    ) -> Result<BinaryTower128Target, VerificationError>
    where
        BF: PrimeField64,
        EF: ExtensionField<BF> + Eq + Hash,
    {
        self.inner.sample_challenge::<BF, EF>(b, ch)
    }

    pub fn verify_at<BF, EF>(
        &self,
        b: &mut CircuitBuilder<EF>,
        ch: BinaryTower128Challenger,
        cap: &[Vec<ExprId>],
        points: &[Vec<BinaryTower128Target>],
        proof: &BinaryGroupedPcsProofTargets,
    ) -> Result<(), VerificationError>
    where
        BF: PrimeField64,
        EF: ExtensionField<BF> + Eq + Hash,
    {
        self.verify_at_with_continuation::<BF, EF>(b, ch, cap, points, proof)
            .map(|_| ())
    }

    pub fn verify_at_with_continuation<BF, EF>(
        &self,
        b: &mut CircuitBuilder<EF>,
        ch: BinaryTower128Challenger,
        cap: &[Vec<ExprId>],
        points: &[Vec<BinaryTower128Target>],
        proof: &BinaryGroupedPcsProofTargets,
    ) -> Result<BinaryQueryContinuation, VerificationError>
    where
        BF: PrimeField64,
        EF: ExtensionField<BF> + Eq + Hash,
    {
        self.check_targets(cap, points, proof)?;
        let next =
            self.inner
                .verify_at_with_continuation::<BF, EF>(b, ch, cap, points, &proof.opening)?;
        self.authenticate::<BF, EF>(b, cap, proof)?;
        Ok(next)
    }

    pub fn verify_at_after_queries<BF, EF>(
        &self,
        b: &mut CircuitBuilder<EF>,
        next: BinaryQueryContinuation,
        cap: &[Vec<ExprId>],
        points: &[Vec<BinaryTower128Target>],
        proof: &BinaryGroupedPcsProofTargets,
    ) -> Result<BinaryQueryContinuation, VerificationError>
    where
        BF: PrimeField64,
        EF: ExtensionField<BF> + Eq + Hash,
    {
        self.check_targets(cap, points, proof)?;
        let next =
            self.inner
                .verify_at_after_queries::<BF, EF>(b, next, cap, points, &proof.opening)?;
        self.authenticate::<BF, EF>(b, cap, proof)?;
        Ok(next)
    }

    pub(crate) fn check_targets(
        &self,
        cap: &[Vec<ExprId>],
        points: &[Vec<BinaryTower128Target>],
        proof: &BinaryGroupedPcsProofTargets,
    ) -> Result<(), VerificationError> {
        self.inner.check_targets(cap, points, &proof.opening)?;
        let shape = self.input_shape();
        if proof.oracles.len() != shape.geometry.len()
            || proof
                .oracles
                .iter()
                .zip(shape.geometry)
                .any(|(oracle, (count, width, depth))| {
                    oracle.leaves.len() != count
                        || oracle.leaves.iter().any(|row| row.len() != width)
                        || oracle.paths.len() != count
                        || oracle
                            .paths
                            .iter()
                            .any(|path| path.len() != depth || path.iter().any(|d| d.len() != 16))
                })
        {
            return Err(invalid("binary grouped PCS leaf or path shape mismatch"));
        }
        Ok(())
    }

    fn authenticate<BF, EF>(
        &self,
        b: &mut CircuitBuilder<EF>,
        cap: &[Vec<ExprId>],
        proof: &BinaryGroupedPcsProofTargets,
    ) -> Result<(), VerificationError>
    where
        BF: PrimeField64,
        EF: ExtensionField<BF> + Eq + Hash,
    {
        for (q, query) in proof.opening.query_indices.iter().enumerate() {
            let mut index = alloc::vec![ExprId::ZERO; self.inner.config.log_folding_factor()];
            index.extend(query);
            for (batch, (start, arity)) in batches(&self.inner.config).enumerate() {
                let count = 1usize << arity;
                let oracle = &proof.oracles[batch];
                let (rows, cap) = if batch == 0 {
                    (&proof.opening.base_rows, cap)
                } else {
                    (
                        &proof.opening.rounds[batch - 1].rows,
                        proof.opening.rounds[batch - 1].cap.as_slice(),
                    )
                };
                for offset in 0..count {
                    let mut at = index[start..].to_vec();
                    for (bit, target) in at[..arity].iter_mut().enumerate() {
                        *target = b.define_const(EF::from_bool(offset >> bit & 1 != 0));
                    }
                    let i = q * count + offset;
                    if batch == 0 {
                        self.base.verify_symbol::<BF, EF>(
                            b,
                            &at,
                            &rows[i],
                            &oracle.leaves[i],
                            &oracle.paths[i],
                            cap,
                        )?;
                    } else {
                        self.rounds[batch - 1].verify_symbol::<BF, EF>(
                            b,
                            &at,
                            &rows[i],
                            &oracle.leaves[i],
                            &oracle.paths[i],
                            cap,
                        )?;
                    }
                }
            }
        }
        Ok(())
    }
}
