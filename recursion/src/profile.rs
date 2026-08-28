//! A fixed, verifier-owned description of a recursion layer's committed shape.
//!
//! Replaces deriving the verification circuit's shape from whatever the previous
//! proof happens to look like: every layer >= 2 is built from one
//! [`RecursionLayerProfile`]. `solve_fixed_point` computes a single convergence pass
//! against one externally-supplied previous proof — it does not by itself derive a
//! profile whose own output proof conforms to itself across layers. Reaching that
//! cross-layer fixed point is the caller's responsibility: solve, build/prove a layer
//! under the resolved profile, then re-solve against *that* layer's proof, repeating
//! until the profile stops changing. See [`solve_fixed_point`]'s own doc comment for
//! the precise contract of what one call computes.

use alloc::format;
use alloc::rc::Rc;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use p3_air::{SymbolicExpression, SymbolicExpressionExt};
use p3_batch_stark::ProverData;
use p3_circuit::ops::NpoTypeId;
use p3_circuit::{Circuit, CircuitError};
use p3_circuit_prover::common::get_airs_and_degrees_with_prep;
use p3_circuit_prover::config::StarkField;
use p3_circuit_prover::field_params::ExtractBinomialW;
use p3_circuit_prover::{BatchStarkProof, CircuitProverData, ConstraintProfile, TablePacking};
use p3_commit::Pcs;
use p3_field::{Algebra, BasedVectorSpace, ExtensionField, PrimeField64};
use p3_lookup::logup::LogUpGadget;
use p3_uni_stark::{StarkGenericConfig, Val};
use tracing::instrument;

use crate::recursion::{
    BatchOnly, NextLayerPrepCache, PcsRecursionBackend, ProveNextLayerParams, RecursionInput,
    RecursionOutput, build_layer_prover, build_next_layer_circuit, build_next_layer_prep,
    prove_next_layer, run_aggregation_verification_circuit,
};
use crate::traits::RecursiveAir;
use crate::verifier::VerificationError;

/// Which Merkle-tree fan-out a recursion layer's commitments use.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MerkleArity {
    Two,
    Four,
}

/// Which Merkle hashing configuration a recursion layer's commitments use: the tree's fan-out
/// and its cap height. The Merkle cap of height `h` is the `h`-th layer from the root -- a cap
/// of height 0 is the root itself, and increasing `cap_height` shortens each opening proof's
/// authentication path by that many elements (see [`crate::pcs::mmcs`]'s "Merkle Cap Support"
/// section for the full accounting).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HashProfile {
    pub arity: MerkleArity,
    pub cap_height: usize,
}

impl Default for HashProfile {
    fn default() -> Self {
        Self {
            arity: MerkleArity::Two,
            cap_height: 0,
        }
    }
}

/// Which Fiat-Shamir transcript a recursion layer's verifier circuit replays.
///
/// [`BaseDuplex`](TranscriptKind::BaseDuplex) is the base-field duplex sponge
/// ([`CircuitChallenger`](crate::CircuitChallenger)): the sponge's rate holds base elements, so
/// observing an extension element decomposes it into its `D` coefficients and sampling one
/// recomposes `D` squeezed elements. [`ExtLimbDuplex`](TranscriptKind::ExtLimbDuplex) names an
/// extension-limb sponge whose rate holds whole `D`-coefficient limbs and which therefore needs
/// neither decomposition around the sponge, but has no implementation wired into this profile
/// path yet -- selecting it is not supported.
///
/// A layer verifying a proof produced outside this recursion tree has no choice: it must replay
/// the transcript that proof was generated under, which is `BaseDuplex`. Only a layer verifying a
/// previous recursion layer -- whose transcript this profile also governs -- can pick either.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum TranscriptKind {
    #[default]
    BaseDuplex,
    ExtLimbDuplex,
}

/// Everything a recursion-layer verifier circuit's *table shape* depends on.
///
/// Comparing two profiles with `==` is the prep-cache validity check — this
/// mirrors how `AggregationCircuitFingerprint` is already compared today (a
/// single cached slot, not a hash-map key).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecursionLayerProfile {
    pub table_packing: TablePacking,
    pub hash: HashProfile,
    pub transcript: TranscriptKind,
}

/// Returned (formatted into a [`VerificationError::InvalidProofShape`]) when
/// [`solve_fixed_point`] exhausts `max_iterations` without finding a profile whose committed
/// table heights accommodate its own verifier circuit.
#[derive(Debug, Clone)]
pub struct FixedPointError {
    /// Number of iterations attempted before giving up.
    pub iterations: usize,
    /// Every height bump applied during the run, in order: `(table, previous height, height
    /// it needed to grow to)`. Lets a caller see whether the search was making steady
    /// progress or oscillating instead of converging.
    pub last_growth: Vec<(String, usize, usize)>,
}

/// Compute one convergence pass of a [`RecursionLayerProfile`] against a single,
/// externally-supplied `prev` proof: building this layer's verifier circuit's prep with the
/// candidate `TablePacking` (in strict mode) succeeds, i.e. no table's natural row count
/// (as driven by `prev`) exceeds the height the profile commits to for it.
///
/// **This is not by itself a cross-layer fixed point.** It only guarantees the returned
/// profile fits the *one* verifier circuit built from `prev`/`config`/`backend` here; it never
/// proves a layer under the candidate profile and re-derives from that layer's own proof. A
/// true fixed point — a profile whose own output proof, when recursively verified, again
/// resolves to that same profile — requires the caller to iterate this function: solve, build
/// and prove a layer under the resolved profile, then call `solve_fixed_point` again against
/// *that* layer's proof, repeating until the profile stops changing. Wiring that outer loop is
/// the caller's responsibility (e.g. the next recursion layer's driver), not this function's.
///
/// The verifier circuit built from `prev`, `config`, and `backend` has a fixed op-list shape
/// that does not depend on the table packing, so it is built once; only the packing changes
/// across iterations, each one bumping whichever table [`build_next_layer_prep`] reports as
/// overflowing (via strict-mode `CircuitError::ProfileOverflow`) until a probe succeeds. This
/// converges in at most (number of tables that overflow the seed) + 1 probes: one bump per
/// overflowing table, plus a final clean re-probe that finds nothing left to bump.
///
/// `constraint_profile` is threaded into every internal probe and is not itself recorded on
/// the returned [`RecursionLayerProfile`]: the resolved heights are only valid for
/// proving/verifying under this same `ConstraintProfile`, since it affects table shape
/// (`ConstraintProfile::RecursionOptimized` maps to a different AIR variant than `Standard`).
/// Callers must remember which one they solved with.
pub fn solve_fixed_point<SC, A, B, const D: usize>(
    seed: RecursionLayerProfile,
    prev: &RecursionInput<'_, SC, A>,
    config: &SC,
    backend: &B,
    constraint_profile: ConstraintProfile,
    max_iterations: usize,
) -> Result<RecursionLayerProfile, VerificationError>
where
    SC: StarkGenericConfig + Send + Sync + Clone + 'static,
    A: RecursiveAir<Val<SC>, SC::Challenge, LogUpGadget>,
    B: PcsRecursionBackend<SC, A, D>,
    Val<SC>: PrimeField64 + StarkField,
    SC::Challenge: BasedVectorSpace<Val<SC>>
        + From<Val<SC>>
        + ExtensionField<Val<SC>>
        + ExtractBinomialW<Val<SC>>,
    SymbolicExpressionExt<Val<SC>, SC::Challenge>:
        Algebra<SymbolicExpression<Val<SC>>> + Algebra<SC::Challenge>,
{
    let (circuit, _verifier_result) =
        build_next_layer_circuit::<SC, A, B, D>(prev, config, backend)?;

    let mut table_packing = seed.table_packing.with_strict_heights();
    let mut last_growth: Vec<(String, usize, usize)> = Vec::new();

    for iteration in 0..max_iterations {
        let params = ProveNextLayerParams {
            table_packing: table_packing.clone(),
            constraint_profile,
        };

        match build_next_layer_prep::<SC, A, B, D>(&circuit, config, backend, &params) {
            Ok(_) => {
                tracing::info!(
                    iteration,
                    growth_events = last_growth.len(),
                    "solve_fixed_point converged"
                );
                return Ok(RecursionLayerProfile {
                    table_packing,
                    hash: seed.hash,
                    transcript: seed.transcript,
                });
            }
            Err(VerificationError::Circuit(CircuitError::ProfileOverflow {
                table,
                needed,
                allowed,
            })) => {
                tracing::info!(
                    iteration,
                    table = %table,
                    allowed,
                    needed,
                    "solve_fixed_point: table overflowed its configured height, bumping"
                );
                last_growth.push((table.clone(), allowed, needed));
                table_packing = bump_table_height(table_packing, &table, needed);
            }
            Err(other) => return Err(other),
        }
    }

    Err(VerificationError::InvalidProofShape(format!(
        "solve_fixed_point did not converge: {:?}",
        FixedPointError {
            iterations: max_iterations,
            last_growth,
        }
    )))
}

/// Apply one table's `ProfileOverflow` growth to a `TablePacking`, returning an updated copy.
fn bump_table_height(packing: TablePacking, table: &str, needed: usize) -> TablePacking {
    match table {
        "ALU" => packing.with_alu_min_height(needed),
        "PUBLIC" => packing.with_public_min_height(needed),
        "CONST" => packing.with_const_min_height(needed),
        other => packing.with_npo_min_height(NpoTypeId::new(other), needed),
    }
}

impl RecursionLayerProfile {
    /// Reject a proof whose committed table packing doesn't match this profile's, before the
    /// recursive verifier circuit built for this profile ever runs on it.
    pub fn check_proof_shape<SC: StarkGenericConfig>(
        &self,
        proof: &BatchStarkProof<SC>,
    ) -> Result<(), VerificationError> {
        if proof.table_packing != self.table_packing {
            return Err(VerificationError::InvalidProofShape(format!(
                "proof's table_packing {:?} does not match this RecursionLayerProfile's table_packing {:?}",
                proof.table_packing, self.table_packing
            )));
        }
        Ok(())
    }
}

/// Prep cache for the profile path, keyed by the [`RecursionLayerProfile`] it was built under.
///
/// Wraps a [`NextLayerPrepCache`] with the profile it was built from so [`prove_layer`] can
/// detect a stale cache (built under a different profile) and fall back to the uncached path
/// instead of silently proving under a table packing that doesn't match the requested profile.
pub struct ProfilePrepCache<SC: StarkGenericConfig + 'static> {
    pub profile: RecursionLayerProfile,
    pub inner: NextLayerPrepCache<SC>,
}

/// Build a recursion layer's verifier circuit for the profile path.
///
/// The verifier circuit's op-list shape does not depend on `profile` today (only the table
/// packing used to prove it does, which is applied later by [`prove_layer`]); the parameter is
/// kept so a future profile field that does change the circuit shape has a natural home to
/// branch on.
pub fn build_layer_circuit<SC, A, B, const D: usize>(
    profile: &RecursionLayerProfile,
    prev: &RecursionInput<'_, SC, A>,
    config: &SC,
    backend: &B,
) -> Result<(Circuit<SC::Challenge>, B::VerifierResult), VerificationError>
where
    SC: StarkGenericConfig + Send + Sync + Clone + 'static,
    A: RecursiveAir<Val<SC>, SC::Challenge, LogUpGadget>,
    B: PcsRecursionBackend<SC, A, D>,
    Val<SC>: PrimeField64 + StarkField,
    SC::Challenge: BasedVectorSpace<Val<SC>>
        + From<Val<SC>>
        + ExtensionField<Val<SC>>
        + ExtractBinomialW<Val<SC>>,
    SymbolicExpressionExt<Val<SC>, SC::Challenge>:
        Algebra<SymbolicExpression<Val<SC>>> + Algebra<SC::Challenge>,
{
    let _ = profile;
    build_next_layer_circuit::<SC, A, B, D>(prev, config, backend)
}

/// Prove a recursion layer for the profile path.
///
/// Runs the verifier circuit and proves it with batch STARK under `profile`'s table packing,
/// then rejects the resulting proof (via [`RecursionLayerProfile::check_proof_shape`]) if its
/// committed shape doesn't actually match `profile` -- this guards against a caller-supplied
/// `prep` or backend silently producing a proof under a different packing than requested.
///
/// `prep`, if supplied, is only reused when it was built under this same `profile`; a prep
/// cache from a different profile is ignored and the uncached path in [`prove_next_layer`] runs
/// instead, mirroring how a stale [`AggregationPrepCache`](crate::recursion::AggregationPrepCache)
/// is ignored when its fingerprint no longer matches.
pub fn prove_layer<SC, A, B, const D: usize>(
    profile: &RecursionLayerProfile,
    prev: &RecursionInput<'_, SC, A>,
    verification_circuit: &Circuit<SC::Challenge>,
    verifier_result: &B::VerifierResult,
    config: &SC,
    backend: &B,
    prep: Option<&ProfilePrepCache<SC>>,
) -> Result<RecursionOutput<SC>, VerificationError>
where
    SC: StarkGenericConfig + Send + Sync + Clone + 'static,
    A: RecursiveAir<Val<SC>, SC::Challenge, LogUpGadget>,
    B: PcsRecursionBackend<SC, A, D>,
    Val<SC>: PrimeField64 + StarkField,
    SC::Challenge: BasedVectorSpace<Val<SC>>
        + From<Val<SC>>
        + ExtensionField<Val<SC>>
        + ExtractBinomialW<Val<SC>>,
    SymbolicExpressionExt<Val<SC>, SC::Challenge>:
        Algebra<SymbolicExpression<Val<SC>>> + Algebra<SC::Challenge>,
    <SC::Pcs as Pcs<SC::Challenge, SC::Challenger>>::Domain: Send + Sync,
    SC::Pcs: Sync,
    <SC::Pcs as Pcs<SC::Challenge, SC::Challenger>>::ProverData: Sync,
    <SC::Pcs as Pcs<SC::Challenge, SC::Challenger>>::Commitment: Sync,
{
    let params = ProveNextLayerParams {
        table_packing: profile.table_packing.clone(),
        constraint_profile: ConstraintProfile::default(),
    };

    let valid_prep = prep.filter(|cached| &cached.profile == profile);

    let output = prove_next_layer::<SC, A, B, D>(
        prev,
        verification_circuit,
        verifier_result,
        config,
        backend,
        &params,
        valid_prep.map(|cached| &cached.inner),
    )?;

    profile.check_proof_shape(&output.0)?;

    Ok(output)
}

/// Prove a 2-to-1 aggregation layer for the profile path.
///
/// Mirrors [`prove_layer`] for the aggregation entry point: runs both `left`'s and `right`'s
/// verifier constraints (already compiled into `verification_circuit` by
/// [`build_aggregation_layer_circuit`](crate::recursion::build_aggregation_layer_circuit)) and
/// proves the result with batch STARK under `profile`'s table packing, then rejects the
/// resulting proof (via [`RecursionLayerProfile::check_proof_shape`]) if its committed shape
/// doesn't actually match `profile`.
///
/// `prep`, if supplied, is only reused when it was built under this same `profile`; a prep
/// cache from a different profile is ignored and this function rebuilds the prover data from
/// scratch instead, mirroring [`prove_layer`]'s own stale-cache handling. Unlike
/// [`prove_aggregation_layer`](crate::recursion::prove_aggregation_layer)'s self-managing
/// [`AggregationPrepCache`](crate::recursion::AggregationPrepCache) (keyed by a circuit-shape
/// fingerprint), validity here is `profile` equality, matching [`ProfilePrepCache`].
#[instrument(skip_all)]
#[allow(clippy::too_many_arguments)]
pub fn prove_aggregation_layer_with_profile<SC, A1, A2, B, const D: usize>(
    profile: &RecursionLayerProfile,
    left: &RecursionInput<'_, SC, A1>,
    right: &RecursionInput<'_, SC, A2>,
    left_result: &<B as PcsRecursionBackend<SC, A1, D>>::VerifierResult,
    right_result: &<B as PcsRecursionBackend<SC, A2, D>>::VerifierResult,
    verification_circuit: &Circuit<SC::Challenge>,
    config: &SC,
    backend: &B,
    prep: Option<&ProfilePrepCache<SC>>,
) -> Result<RecursionOutput<SC>, VerificationError>
where
    SC: StarkGenericConfig + Send + Sync + Clone + 'static,
    A1: RecursiveAir<Val<SC>, SC::Challenge, LogUpGadget>,
    A2: RecursiveAir<Val<SC>, SC::Challenge, LogUpGadget>,
    B: PcsRecursionBackend<SC, A1, D> + PcsRecursionBackend<SC, A2, D>,
    Val<SC>: PrimeField64 + StarkField,
    SC::Challenge: BasedVectorSpace<Val<SC>>
        + From<Val<SC>>
        + ExtensionField<Val<SC>>
        + ExtractBinomialW<Val<SC>>,
    SymbolicExpressionExt<Val<SC>, SC::Challenge>:
        Algebra<SymbolicExpression<Val<SC>>> + Algebra<SC::Challenge>,
    <SC::Pcs as Pcs<SC::Challenge, SC::Challenger>>::Domain: Send + Sync,
    SC::Pcs: Sync,
    <SC::Pcs as Pcs<SC::Challenge, SC::Challenger>>::ProverData: Sync,
    <SC::Pcs as Pcs<SC::Challenge, SC::Challenger>>::Commitment: Sync,
{
    let params = ProveNextLayerParams {
        table_packing: profile.table_packing.clone(),
        constraint_profile: ConstraintProfile::default(),
    };

    let valid_prep = prep.filter(|cached| &cached.profile == profile);

    let output = if let Some(cached) = valid_prep {
        let traces = run_aggregation_verification_circuit::<SC, A1, A2, B, D>(
            left,
            right,
            left_result,
            right_result,
            verification_circuit,
            config,
            backend,
        )?;
        let proof = cached
            .inner
            .prover
            .prove_all_tables(&traces, &cached.inner.circuit_prover_data)
            .map_err(|e| VerificationError::InvalidProofShape(e.to_string()))?;
        RecursionOutput(proof, Rc::clone(&cached.inner.circuit_prover_data))
    } else {
        let (airs_degrees, primitive_columns, non_primitive_columns) = {
            let preprocessors =
                <B as PcsRecursionBackend<SC, A1, D>>::non_primitive_preprocessors(backend);
            let air_builders =
                <B as PcsRecursionBackend<SC, A1, D>>::non_primitive_air_builders(backend);
            get_airs_and_degrees_with_prep::<SC, SC::Challenge, D>(
                verification_circuit,
                &params.table_packing,
                &preprocessors,
                &air_builders,
                params.constraint_profile,
            )
            .map_err(VerificationError::Circuit)?
        };

        let (airs, degrees): (Vec<_>, Vec<_>) = airs_degrees.into_iter().unzip();
        let ext_degrees: Vec<usize> = degrees.iter().map(|&d| d + config.is_zk()).collect();

        let traces = run_aggregation_verification_circuit::<SC, A1, A2, B, D>(
            left,
            right,
            left_result,
            right_result,
            verification_circuit,
            config,
            backend,
        )?;

        let circuit_prover_data = {
            let prover_data = ProverData::from_airs_and_degrees(config, &airs, &ext_degrees);
            CircuitProverData::new(prover_data, primitive_columns, non_primitive_columns)
        };

        let prover = build_layer_prover(
            config,
            &params.table_packing,
            params.constraint_profile,
            <B as PcsRecursionBackend<SC, A1, D>>::non_primitive_provers(backend, D),
        );
        let proof = prover
            .prove_all_tables(&traces, &circuit_prover_data)
            .map_err(|e| VerificationError::InvalidProofShape(e.to_string()))?;

        RecursionOutput(proof, Rc::new(circuit_prover_data))
    };

    profile.check_proof_shape(&output.0)?;

    Ok(output)
}

/// Prove a 2-to-1 aggregation layer for the profile path while verifying the input proofs
/// under `input_config` and committing the aggregated proof under `output_config`.
///
/// Mirrors [`prove_aggregation_layer_with_profile`] but splits the verifier config from the
/// output proof config, exactly as
/// [`prove_aggregation_layer_cross`](crate::recursion::prove_aggregation_layer_cross) does for
/// the non-profile path.
#[instrument(skip_all)]
#[allow(clippy::too_many_arguments)]
pub fn prove_aggregation_layer_cross_with_profile<InSC, OutSC, A1, A2, B, const D: usize>(
    profile: &RecursionLayerProfile,
    left: &RecursionInput<'_, InSC, A1>,
    right: &RecursionInput<'_, InSC, A2>,
    left_result: &<B as PcsRecursionBackend<InSC, A1, D>>::VerifierResult,
    right_result: &<B as PcsRecursionBackend<InSC, A2, D>>::VerifierResult,
    verification_circuit: &Circuit<InSC::Challenge>,
    input_config: &InSC,
    output_config: &OutSC,
    backend: &B,
    prep: Option<&ProfilePrepCache<OutSC>>,
) -> Result<RecursionOutput<OutSC>, VerificationError>
where
    InSC: StarkGenericConfig + Send + Sync + Clone + 'static,
    OutSC: StarkGenericConfig<Challenge = InSC::Challenge> + Send + Sync + Clone + 'static,
    A1: RecursiveAir<Val<InSC>, InSC::Challenge, LogUpGadget>,
    A2: RecursiveAir<Val<InSC>, InSC::Challenge, LogUpGadget>,
    B: PcsRecursionBackend<InSC, A1, D>
        + PcsRecursionBackend<InSC, A2, D>
        + PcsRecursionBackend<OutSC, BatchOnly, D>,
    Val<InSC>: PrimeField64,
    InSC::Challenge: BasedVectorSpace<Val<InSC>> + From<Val<InSC>>,
    Val<OutSC>: PrimeField64 + StarkField,
    OutSC::Challenge: BasedVectorSpace<Val<OutSC>>
        + From<Val<OutSC>>
        + ExtensionField<Val<OutSC>>
        + ExtractBinomialW<Val<OutSC>>,
    SymbolicExpressionExt<Val<OutSC>, OutSC::Challenge>:
        Algebra<SymbolicExpression<Val<OutSC>>> + Algebra<OutSC::Challenge>,
    <OutSC::Pcs as Pcs<OutSC::Challenge, OutSC::Challenger>>::Domain: Send + Sync,
    OutSC::Pcs: Sync,
    <OutSC::Pcs as Pcs<OutSC::Challenge, OutSC::Challenger>>::ProverData: Sync,
    <OutSC::Pcs as Pcs<OutSC::Challenge, OutSC::Challenger>>::Commitment: Sync,
{
    let params = ProveNextLayerParams {
        table_packing: profile.table_packing.clone(),
        constraint_profile: ConstraintProfile::default(),
    };

    let valid_prep = prep.filter(|cached| &cached.profile == profile);

    let output = if let Some(cached) = valid_prep {
        let traces = run_aggregation_verification_circuit::<InSC, A1, A2, B, D>(
            left,
            right,
            left_result,
            right_result,
            verification_circuit,
            input_config,
            backend,
        )?;
        let proof = cached
            .inner
            .prover
            .prove_all_tables(&traces, &cached.inner.circuit_prover_data)
            .map_err(|e| VerificationError::InvalidProofShape(e.to_string()))?;
        RecursionOutput(proof, Rc::clone(&cached.inner.circuit_prover_data))
    } else {
        let (airs_degrees, primitive_columns, non_primitive_columns) = {
            let preprocessors =
                <B as PcsRecursionBackend<OutSC, BatchOnly, D>>::non_primitive_preprocessors(
                    backend,
                );
            let air_builders =
                <B as PcsRecursionBackend<OutSC, BatchOnly, D>>::non_primitive_air_builders(
                    backend,
                );
            get_airs_and_degrees_with_prep::<OutSC, OutSC::Challenge, D>(
                verification_circuit,
                &params.table_packing,
                &preprocessors,
                &air_builders,
                params.constraint_profile,
            )
            .map_err(VerificationError::Circuit)?
        };

        let (airs, degrees): (Vec<_>, Vec<_>) = airs_degrees.into_iter().unzip();
        let ext_degrees: Vec<usize> = degrees.iter().map(|&d| d + output_config.is_zk()).collect();

        let traces = run_aggregation_verification_circuit::<InSC, A1, A2, B, D>(
            left,
            right,
            left_result,
            right_result,
            verification_circuit,
            input_config,
            backend,
        )?;

        let circuit_prover_data = {
            let prover_data = ProverData::from_airs_and_degrees(output_config, &airs, &ext_degrees);
            CircuitProverData::new(prover_data, primitive_columns, non_primitive_columns)
        };

        let prover = build_layer_prover(
            output_config,
            &params.table_packing,
            params.constraint_profile,
            <B as PcsRecursionBackend<OutSC, BatchOnly, D>>::non_primitive_provers(backend, D),
        );
        let proof = prover
            .prove_all_tables(&traces, &circuit_prover_data)
            .map_err(|e| VerificationError::InvalidProofShape(e.to_string()))?;

        RecursionOutput(proof, Rc::new(circuit_prover_data))
    };

    profile.check_proof_shape(&output.0)?;

    Ok(output)
}

#[cfg(test)]
mod tests {
    use p3_circuit_prover::TablePacking;

    use super::*;

    #[test]
    fn identical_table_packings_produce_equal_profiles() {
        let a = RecursionLayerProfile {
            table_packing: TablePacking::new(1, 3),
            hash: HashProfile::default(),
            transcript: TranscriptKind::default(),
        };
        let b = RecursionLayerProfile {
            table_packing: TablePacking::new(1, 3),
            hash: HashProfile::default(),
            transcript: TranscriptKind::default(),
        };
        assert_eq!(a, b);
    }

    #[test]
    fn different_alu_lanes_produce_unequal_profiles() {
        let a = RecursionLayerProfile {
            table_packing: TablePacking::new(1, 3),
            hash: HashProfile::default(),
            transcript: TranscriptKind::default(),
        };
        let b = RecursionLayerProfile {
            table_packing: TablePacking::new(1, 4),
            hash: HashProfile::default(),
            transcript: TranscriptKind::default(),
        };
        assert_ne!(a, b);
    }

    #[test]
    fn different_alu_min_height_produces_unequal_profiles() {
        let a = RecursionLayerProfile {
            table_packing: TablePacking::new(1, 3),
            hash: HashProfile::default(),
            transcript: TranscriptKind::default(),
        };
        let b = RecursionLayerProfile {
            table_packing: TablePacking::new(1, 3).with_alu_min_height(65536),
            hash: HashProfile::default(),
            transcript: TranscriptKind::default(),
        };
        assert_ne!(a, b);
    }

    #[test]
    fn default_hash_profile_matches_todays_arity_2_no_cap_behavior() {
        let profile = RecursionLayerProfile {
            table_packing: TablePacking::new(1, 3),
            hash: HashProfile::default(),
            transcript: TranscriptKind::default(),
        };
        assert_eq!(profile.hash.arity, MerkleArity::Two);
        assert_eq!(profile.hash.cap_height, 0);
    }

    #[test]
    fn transcript_kind_defaults_to_base_duplex() {
        let profile = RecursionLayerProfile {
            table_packing: TablePacking::new(1, 3),
            hash: HashProfile::default(),
            transcript: TranscriptKind::default(),
        };
        assert_eq!(profile.transcript, TranscriptKind::BaseDuplex);
    }

    #[test]
    fn different_transcript_kinds_produce_unequal_profiles() {
        let a = RecursionLayerProfile {
            table_packing: TablePacking::new(1, 3),
            hash: HashProfile::default(),
            transcript: TranscriptKind::BaseDuplex,
        };
        let b = RecursionLayerProfile {
            transcript: TranscriptKind::ExtLimbDuplex,
            ..a.clone()
        };
        assert_ne!(a, b);
    }
}
