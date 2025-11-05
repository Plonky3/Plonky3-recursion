use alloc::string::ToString;
use alloc::vec::Vec;
use alloc::{format, vec};
use core::marker::PhantomData;

use p3_circuit::CircuitBuilder;
use p3_circuit::op::{NonPrimitiveOpConfig, NonPrimitiveOpType};
use p3_circuit::utils::ColumnsTargets;
use p3_commit::{Pcs, PolynomialSpace};
use p3_field::{BasedVectorSpace, Field, PrimeCharacteristicRing};
use p3_batch_stark::BatchProof;
use p3_uni_stark::{OpenedValues, StarkGenericConfig};
use p3_util::zip_eq::zip_eq;

use super::{ObservableCommitment, VerificationError, recompose_quotient_from_chunks_circuit};
use crate::Target;
use crate::challenger::CircuitChallenger;
use crate::traits::{Recursive, RecursiveAir, RecursiveChallenger, RecursivePcs};
use crate::types::{CommitmentTargets, OpenedValuesTargets, ProofTargets};

/// Type alias for PCS verifier parameters.
type PcsVerifierParams<SC, InputProof, OpeningProof, Comm> =
    <<SC as StarkGenericConfig>::Pcs as RecursivePcs<
        SC,
        InputProof,
        OpeningProof,
        Comm,
        <<SC as StarkGenericConfig>::Pcs as Pcs<
            <SC as StarkGenericConfig>::Challenge,
            <SC as StarkGenericConfig>::Challenger,
        >>::Domain,
    >>::VerifierParams;

/// Opened values for a single STARK instance within the multi-proof.
#[derive(Clone)]
pub struct InstanceOpenedValuesTargets<SC: StarkGenericConfig> {
    pub trace_local: Vec<Target>,
    pub trace_next: Vec<Target>,
    pub quotient_chunks: Vec<Vec<Target>>,
    _phantom: PhantomData<SC>,
}

/// Recursive targets for a multi-STARK proof.
///
/// The `flattened` field stores the aggregated commitments, opened values, and opening proof in the
/// same layout expected by single-instance PCS logic. The `instances` field retains per-instance
/// opened values so that AIR constraints can be enforced individually.
pub struct BatchProofTargets<
    SC: StarkGenericConfig,
    Comm: Recursive<SC::Challenge>,
    OpeningProof: Recursive<SC::Challenge>,
> {
    pub flattened: ProofTargets<SC, Comm, OpeningProof>,
    pub instances: Vec<InstanceOpenedValuesTargets<SC>>,
    pub degree_bits: Vec<usize>,
}

impl<
    SC: StarkGenericConfig,
    Comm: Recursive<SC::Challenge, Input = <SC::Pcs as Pcs<SC::Challenge, SC::Challenger>>::Commitment>,
    OpeningProof: Recursive<SC::Challenge, Input = <SC::Pcs as Pcs<SC::Challenge, SC::Challenger>>::Proof>,
> Recursive<SC::Challenge> for BatchProofTargets<SC, Comm, OpeningProof>
{
    type Input = BatchProof<SC>;

    fn new(circuit: &mut CircuitBuilder<SC::Challenge>, input: &Self::Input) -> Self {
        let trace_targets = Comm::new(circuit, &input.commitments.main);
        let quotient_chunks_targets = Comm::new(circuit, &input.commitments.quotient_chunks);

        // Flattened opened values are ordered as:
        // 1. All `trace_local` rows per instance (instance 0 .. N)
        // 2. All `trace_next` rows per instance (instance 0 .. N)
        // 3. Quotient chunks for each instance in commit order
        let mut aggregated_trace_local = Vec::new();
        let mut aggregated_trace_next = Vec::new();
        let mut aggregated_quotient_chunks = Vec::new();
        let mut instances = Vec::with_capacity(input.opened_values.instances.len());

        for inst in &input.opened_values.instances {
            let trace_local =
                circuit.alloc_public_inputs(inst.trace_local.len(), "trace local values");
            aggregated_trace_local.extend(trace_local.iter().copied());

            let trace_next =
                circuit.alloc_public_inputs(inst.trace_next.len(), "trace next values");
            aggregated_trace_next.extend(trace_next.iter().copied());

            let mut quotient_chunks = Vec::with_capacity(inst.quotient_chunks.len());
            for chunk in &inst.quotient_chunks {
                let chunk_targets =
                    circuit.alloc_public_inputs(chunk.len(), "quotient chunk values");
                aggregated_quotient_chunks.push(chunk_targets.clone());
                quotient_chunks.push(chunk_targets);
            }

            instances.push(InstanceOpenedValuesTargets {
                trace_local,
                trace_next,
                quotient_chunks,
                _phantom: PhantomData,
            });
        }

        let opened_values_targets = OpenedValuesTargets {
            trace_local_targets: aggregated_trace_local,
            trace_next_targets: aggregated_trace_next,
            quotient_chunks_targets: aggregated_quotient_chunks,
            random_targets: None,
            _phantom: PhantomData,
        };

        let flattened = ProofTargets {
            commitments_targets: CommitmentTargets {
                trace_targets,
                quotient_chunks_targets,
                random_commit: None,
                _phantom: PhantomData,
            },
            opened_values_targets,
            opening_proof: OpeningProof::new(circuit, &input.opening_proof),
            degree_bits: 0,
        };

        Self {
            flattened,
            instances,
            degree_bits: input.degree_bits.clone(),
        }
    }

    fn get_values(input: &Self::Input) -> Vec<SC::Challenge> {
        let commitments = p3_uni_stark::Commitments {
            trace: input.commitments.main.clone(),
            quotient_chunks: input.commitments.quotient_chunks.clone(),
            random: None,
        };

        let mut trace_local = Vec::new();
        let mut trace_next = Vec::new();
        let mut quotient_chunks = Vec::new();
        for inst in &input.opened_values.instances {
            trace_local.extend(&inst.trace_local);
            trace_next.extend(&inst.trace_next);
            quotient_chunks.extend(inst.quotient_chunks.iter().cloned());
        }

        let opened_values = OpenedValues {
            trace_local,
            trace_next,
            quotient_chunks,
            random: None,
        };

        CommitmentTargets::<SC::Challenge, Comm>::get_values(&commitments)
            .into_iter()
            .chain(OpenedValuesTargets::<SC>::get_values(&opened_values))
            .chain(OpeningProof::get_values(&input.opening_proof))
            .collect()
    }
}

/// Verify a multi-STARK proof inside a recursive circuit.
pub fn verify_batch_circuit<
    A,
    SC: StarkGenericConfig,
    Comm: Recursive<
            SC::Challenge,
            Input = <SC::Pcs as Pcs<SC::Challenge, SC::Challenger>>::Commitment,
        > + Clone
        + ObservableCommitment,
    InputProof: Recursive<SC::Challenge>,
    OpeningProof: Recursive<SC::Challenge>,
    const RATE: usize,
>(
    config: &SC,
    airs: &[A],
    circuit: &mut CircuitBuilder<SC::Challenge>,
    proof_targets: &BatchProofTargets<SC, Comm, OpeningProof>,
    public_values: &[Vec<Target>],
    pcs_params: &PcsVerifierParams<SC, InputProof, OpeningProof, Comm>,
) -> Result<(), VerificationError>
where
    A: RecursiveAir<SC::Challenge>,
    <SC as StarkGenericConfig>::Pcs: RecursivePcs<
            SC,
            InputProof,
            OpeningProof,
            Comm,
            <SC::Pcs as Pcs<SC::Challenge, SC::Challenger>>::Domain,
        >,
    SC::Challenge: PrimeCharacteristicRing,
    <<SC as StarkGenericConfig>::Pcs as Pcs<SC::Challenge, SC::Challenger>>::Domain: Clone,
{
    debug_assert_eq!(config.is_zk(), 0, "batch/multi recursion assumes non-ZK");
    if airs.is_empty() {
        return Err(VerificationError::InvalidProofShape(
            "multi-STARK verification requires at least one instance".to_string(),
        ));
    }

    if SC::Pcs::ZK {
        return Err(VerificationError::InvalidProofShape(
            "ZK mode is not supported for multi-STARK recursion".to_string(),
        ));
    }

    // Enable hash operations for CircuitChallenger
    circuit.enable_op(
        NonPrimitiveOpType::HashAbsorb { reset: true },
        NonPrimitiveOpConfig::None,
    );
    circuit.enable_op(NonPrimitiveOpType::HashSqueeze, NonPrimitiveOpConfig::None);

    if airs.len() != proof_targets.instances.len()
        || airs.len() != public_values.len()
        || airs.len() != proof_targets.degree_bits.len()
    {
        return Err(VerificationError::InvalidProofShape(
            "Mismatch between number of AIRs, instances, public values, or degree bits".to_string(),
        ));
    }

    let pcs = config.pcs();

    let flattened = &proof_targets.flattened;
    let commitments_targets = &flattened.commitments_targets;
    let opened_values_targets = &flattened.opened_values_targets;
    let opening_proof = &flattened.opening_proof;
    let instances = &proof_targets.instances;
    let degree_bits = &proof_targets.degree_bits;

    if commitments_targets.random_commit.is_some() {
        return Err(VerificationError::InvalidProofShape(
            "Multi-STARK verifier does not support random commitments".to_string(),
        ));
    }

    let n_instances = airs.len();

    // Pre-compute per-instance quotient degrees and validate proof shape.
    let mut log_quotient_degrees = Vec::with_capacity(n_instances);
    let mut quotient_degrees = Vec::with_capacity(n_instances);
    for ((air, instance), public_vals) in airs.iter().zip(instances.iter()).zip(public_values) {
        let air_width = A::width(air);
        if instance.trace_local.len() != air_width || instance.trace_next.len() != air_width {
            return Err(VerificationError::InvalidProofShape(format!(
                "Instance has incorrect trace width: expected {}, got {} / {}",
                air_width,
                instance.trace_local.len(),
                instance.trace_next.len()
            )));
        }

        let log_qd = A::get_log_quotient_degree(air, public_vals.len(), config.is_zk());
        let quotient_degree = 1 << (log_qd + config.is_zk());

        if instance.quotient_chunks.len() != quotient_degree {
            return Err(VerificationError::InvalidProofShape(format!(
                "Instance quotient chunk count mismatch: expected {}, got {}",
                quotient_degree,
                instance.quotient_chunks.len()
            )));
        }

        if instance
            .quotient_chunks
            .iter()
            .any(|chunk| chunk.len() != SC::Challenge::DIMENSION)
        {
            return Err(VerificationError::InvalidProofShape(format!(
                "Invalid quotient chunk length: expected {}",
                SC::Challenge::DIMENSION
            )));
        }

        log_quotient_degrees.push(log_qd);
        quotient_degrees.push(quotient_degree);
    }

    // Challenger initialisation mirrors the native multi-STARK verifier transcript.
    let mut challenger = CircuitChallenger::<RATE>::new();
    let inst_count_target = circuit.alloc_const(
        SC::Challenge::from_usize(n_instances),
        "number of instances",
    );
    challenger.observe(circuit, inst_count_target);

    for ((&ext_db, quotient_degree), air) in degree_bits
        .iter()
        .zip(quotient_degrees.iter())
        .zip(airs.iter())
    {
        let base_db = ext_db.checked_sub(config.is_zk()).ok_or_else(|| {
            VerificationError::InvalidProofShape(
                "Extended degree bits smaller than ZK adjustment".to_string(),
            )
        })?;
        let base_db_target =
            circuit.alloc_const(SC::Challenge::from_usize(base_db), "base degree bits");
        let ext_db_target =
            circuit.alloc_const(SC::Challenge::from_usize(ext_db), "extended degree bits");
        let width_target =
            circuit.alloc_const(SC::Challenge::from_usize(A::width(air)), "air width");
        let quotient_chunks_target = circuit.alloc_const(
            SC::Challenge::from_usize(*quotient_degree),
            "quotient chunk count",
        );

        challenger.observe(circuit, ext_db_target);
        challenger.observe(circuit, base_db_target);
        challenger.observe(circuit, width_target);
        challenger.observe(circuit, quotient_chunks_target);
    }

    challenger.observe_slice(
        circuit,
        &commitments_targets.trace_targets.to_observation_targets(),
    );
    for pv in public_values {
        challenger.observe_slice(circuit, pv);
    }
    let alpha = challenger.sample(circuit);

    challenger.observe_slice(
        circuit,
        &commitments_targets
            .quotient_chunks_targets
            .to_observation_targets(),
    );
    let zeta = challenger.sample(circuit);

    // Build per-instance domains.
    let mut trace_domains = Vec::with_capacity(n_instances);
    let mut ext_trace_domains = Vec::with_capacity(n_instances);
    for &ext_db in degree_bits {
        let base_db = ext_db - config.is_zk();
        trace_domains.push(pcs.natural_domain_for_degree(1 << base_db));
        ext_trace_domains.push(pcs.natural_domain_for_degree(1 << ext_db));
    }

    // Collect commitments with opening points for PCS verification.
    let mut coms_to_verify = vec![];

    let trace_round: Vec<_> = ext_trace_domains
        .iter()
        .zip(instances.iter())
        .map(|(ext_dom, inst)| {
            let first_point = pcs.first_point(ext_dom);
            let next_point = ext_dom.next_point(first_point).ok_or_else(|| {
                VerificationError::InvalidProofShape(
                    "Trace domain does not provide next point".to_string(),
                )
            })?;
            let generator = next_point * first_point.inverse();
            let generator_const = circuit.add_const(generator);
            let zeta_next = circuit.mul(zeta, generator_const);
            Ok((
                *ext_dom,
                vec![
                    (zeta, inst.trace_local.clone()),
                    (zeta_next, inst.trace_next.clone()),
                ],
            ))
        })
        .collect::<Result<_, VerificationError>>()?;
    coms_to_verify.push((commitments_targets.trace_targets.clone(), trace_round));

    let quotient_domains: Vec<Vec<_>> = degree_bits
        .iter()
        .zip(ext_trace_domains.iter())
        .zip(log_quotient_degrees.iter())
        .map(|((&ext_db, ext_dom), &log_qd)| {
            let base_db = ext_db - config.is_zk();
            let q_domain = ext_dom.create_disjoint_domain(1 << (base_db + log_qd + config.is_zk()));
            q_domain.split_domains(1 << (log_qd + config.is_zk()))
        })
        .collect();

    let mut quotient_round = Vec::new();
    for (domains, inst) in quotient_domains.iter().zip(instances.iter()) {
        for (domain, values) in zip_eq(
            domains.iter(),
            inst.quotient_chunks.iter(),
            VerificationError::InvalidProofShape(
                "Quotient chunk count mismatch across domains".to_string(),
            ),
        )? {
            quotient_round.push((*domain, vec![(zeta, values.clone())]));
        }
    }
    coms_to_verify.push((
        commitments_targets.quotient_chunks_targets.clone(),
        quotient_round,
    ));

    // Generate PCS-specific challenges after observing all opened values.
    opened_values_targets.observe(circuit, &mut challenger);
    let pcs_challenges = SC::Pcs::get_challenges_circuit::<RATE>(
        circuit,
        &mut challenger,
        flattened,
        opened_values_targets,
        pcs_params,
    );

    pcs.verify_circuit(
        circuit,
        &pcs_challenges,
        &coms_to_verify,
        opening_proof,
        pcs_params,
    )?;

    // Verify AIR constraints per instance.
    for i in 0..n_instances {
        let air = &airs[i];
        let inst = &instances[i];
        let trace_domain = &trace_domains[i];
        let public_vals = &public_values[i];
        let domains = &quotient_domains[i];

        let quotient = recompose_quotient_from_chunks_circuit::<SC, _, _, _, _>(
            circuit,
            domains,
            &inst.quotient_chunks,
            zeta,
            pcs,
        );

        let sels = pcs.selectors_at_point_circuit(circuit, trace_domain, &zeta);
        let columns_targets = ColumnsTargets {
            challenges: &[],
            public_values: public_vals,
            local_prep_values: &[],
            next_prep_values: &[],
            local_values: &inst.trace_local,
            next_values: &inst.trace_next,
        };
        let folded_constraints = air.eval_folded_circuit(circuit, &sels, &alpha, columns_targets);

        let folded_mul = circuit.mul(folded_constraints, sels.inv_vanishing);
        circuit.connect(folded_mul, quotient);
    }

    Ok(())
}
