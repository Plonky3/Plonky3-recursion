use alloc::vec;
use alloc::vec::Vec;

use itertools::{Itertools, zip_eq};
use p3_circuit::utils::ColumnsTargets;
use p3_circuit::{CircuitBuilder, ExprId};
use p3_commit::Pcs;
use p3_field::{BasedVectorSpace, Field, PrimeCharacteristicRing};
use p3_uni_stark::StarkGenericConfig;

use crate::recursive_traits::{
    CommitmentTargets, OpenedValuesTargets, ProofTargets, Recursive, RecursiveAir, RecursivePcs,
};

#[derive(Debug)]
pub enum VerificationError {
    InvalidProofShape,
    RandomizationError,
}

impl core::fmt::Display for VerificationError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            VerificationError::InvalidProofShape => write!(f, "Invalid proof shape"),
            VerificationError::RandomizationError => write!(
                f,
                "Missing random opened values for existing random commitment"
            ),
        }
    }
}

// Method to get all the challenge wires.
fn get_circuit_challenges<
    SC: StarkGenericConfig,
    Comm: Recursive<SC::Challenge, Input = <SC::Pcs as Pcs<SC::Challenge, SC::Challenger>>::Commitment>,
    InputProof: Recursive<SC::Challenge>,
    OpeningProof: Recursive<SC::Challenge>,
>(
    proof_targets: &ProofTargets<SC, Comm, OpeningProof>,
    circuit: &mut CircuitBuilder<SC::Challenge>,
) -> Vec<ExprId>
where
    SC::Pcs: RecursivePcs<
            SC,
            InputProof,
            OpeningProof,
            Comm,
            <SC::Pcs as Pcs<SC::Challenge, SC::Challenger>>::Domain,
        >,
{
    let mut challenges = vec![];
    // TODO: Observe degree bits and degree_bits - is_zk.
    // TODO: Observe local wires.
    // TODO: Observe public values.
    // First Fiat-Shamir challenge `alpha`.
    challenges.push(circuit.add_public_input());
    // TODO: Observe quotient chunks.
    // TODO: Observe random commitment if any.
    // zeta and zeta_next
    challenges.push(circuit.add_public_input());
    challenges.push(circuit.add_public_input());

    let pcs_challenges = <SC::Pcs as RecursivePcs<
        SC,
        InputProof,
        OpeningProof,
        Comm,
        <SC::Pcs as Pcs<SC::Challenge, SC::Challenger>>::Domain,
    >>::get_challenges_circuit(circuit, proof_targets);

    challenges.extend(pcs_challenges);

    challenges
}

pub fn verify_circuit<
    A,
    SC: StarkGenericConfig,
    Comm: Recursive<
            SC::Challenge,
            Input = <SC::Pcs as Pcs<SC::Challenge, SC::Challenger>>::Commitment,
        > + Clone,
    InputProof: Recursive<SC::Challenge> + Clone,
    OpeningProof: Recursive<SC::Challenge>,
>(
    config: &SC,
    air: &A,
    circuit: &mut CircuitBuilder<SC::Challenge>,
    proof_targets: &ProofTargets<SC, Comm, OpeningProof>,
    public_values: &[ExprId],
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
{
    let ProofTargets {
        commitments_targets:
            CommitmentTargets {
                trace_targets,
                quotient_chunks_targets,
                random_commit,
                ..
            },
        opened_values_targets:
            OpenedValuesTargets {
                trace_local_targets: opened_trace_local_targets,
                trace_next_targets: opened_trace_next_targets,
                quotient_chunks_targets: opened_quotient_chunks_targets,
                random_targets: opened_random,
                ..
            },
        opening_proof,
        degree_bits,
    } = proof_targets;
    let degree = 1 << degree_bits;
    let log_quotient_degree = A::get_log_quotient_degree(air, public_values.len(), config.is_zk());
    let quotient_degree = 1 << (log_quotient_degree + config.is_zk());

    let pcs = config.pcs();
    let trace_domain = pcs.natural_domain_for_degree(degree);
    let init_trace_domain = pcs.natural_domain_for_degree(degree >> (config.is_zk()));

    let quotient_domain =
        pcs.create_disjoint_domain(trace_domain, 1 << (degree_bits + log_quotient_degree));
    let quotient_chunks_domains = pcs.split_domains(&quotient_domain, quotient_degree);

    let randomized_quotient_chunks_domains = quotient_chunks_domains
        .iter()
        .map(|domain| pcs.natural_domain_for_degree(pcs.size(domain) << (config.is_zk())))
        .collect_vec();

    // Challenger is called here. But we don't have the interactions or hash tables yet.
    let challenge_targets =
        get_circuit_challenges::<SC, Comm, InputProof, OpeningProof>(proof_targets, circuit);

    // Verify shape.
    let air_width = A::width(air);
    let validate_shape = opened_trace_local_targets.len() == air_width
        && opened_trace_next_targets.len() == air_width
        && opened_quotient_chunks_targets.len() == quotient_degree
        && opened_quotient_chunks_targets
            .iter()
            .all(|opened_chunk| opened_chunk.len() == SC::Challenge::DIMENSION);
    if !validate_shape {
        return Err(VerificationError::InvalidProofShape);
    }

    let alpha = challenge_targets[0];
    let zeta = challenge_targets[1];
    let zeta_next = challenge_targets[2];

    // Need to simulate Fri here.
    let mut coms_to_verify = if let Some(r_commit) = &random_commit {
        let random_values = opened_random
            .as_ref()
            .ok_or(VerificationError::RandomizationError)?;
        vec![(
            r_commit.clone(),
            vec![(trace_domain, vec![(zeta, random_values.clone())])],
        )]
    } else {
        vec![]
    };
    coms_to_verify.extend(vec![
        (
            trace_targets.clone(),
            vec![(
                trace_domain,
                vec![
                    (zeta, opened_trace_local_targets.clone()),
                    (zeta_next, opened_trace_next_targets.clone()),
                ],
            )],
        ),
        (
            quotient_chunks_targets.clone(),
            // Check the commitment on the randomized domains.
            zip_eq(
                randomized_quotient_chunks_domains.iter(),
                opened_quotient_chunks_targets,
            )
            .map(|(domain, values)| (*domain, vec![(zeta, values.clone())]))
            .collect_vec(),
        ),
    ]);
    pcs.verify_circuit(
        circuit,
        &challenge_targets[3..],
        &coms_to_verify,
        opening_proof,
    );

    let zero = circuit.add_const(SC::Challenge::ZERO);
    let one = circuit.add_const(SC::Challenge::ONE);
    let zps = quotient_chunks_domains
        .iter()
        .enumerate()
        .map(|(i, domain)| {
            let mut total = one;
            quotient_chunks_domains
                .iter()
                .enumerate()
                .filter(|(j, _)| *j != i)
                .for_each(|(_, other_domain)| {
                    let v_n = vanishing_poly_at_point_circuit::<
                        SC,
                        InputProof,
                        OpeningProof,
                        Comm,
                        <SC::Pcs as Pcs<SC::Challenge, SC::Challenger>>::Domain,
                    >(config, *other_domain, zeta, circuit);

                    let first_point = circuit.add_const(pcs.first_point(domain));
                    let other_v_n =
                        vanishing_poly_at_point_circuit::<
                            SC,
                            InputProof,
                            OpeningProof,
                            Comm,
                            <SC::Pcs as Pcs<SC::Challenge, SC::Challenger>>::Domain,
                        >(config, *other_domain, first_point, circuit);
                    let div = circuit.div(v_n, other_v_n);

                    total = circuit.mul(total, div);
                });
            total
        })
        .collect_vec();

    let mut quotient = zero;
    for (i, chunk) in opened_quotient_chunks_targets.iter().enumerate() {
        let zp = zps[i];

        let mut cur_s = zero;
        for (e_i, c) in chunk.iter().enumerate() {
            let e_i_wire = circuit.add_const(SC::Challenge::ith_basis_element(e_i).unwrap());
            let inner_mul = circuit.mul(e_i_wire, *c);
            cur_s = circuit.add(cur_s, inner_mul);
        }
        let mul = circuit.mul(cur_s, zp);
        quotient = circuit.add(quotient, mul);
    }

    let sels = pcs.selectors_at_point_circuit(circuit, &init_trace_domain, &zeta);
    let columns_targets = ColumnsTargets {
        challenges: &[],
        public_values,
        local_prep_values: &[],
        next_prep_values: &[],
        local_values: opened_trace_local_targets,
        next_values: opened_trace_next_targets,
    };
    let folded_constraints = air.eval_folded_circuit(circuit, &sels, &alpha, columns_targets);

    // Compute folded_constraints * sels.inv_vanishing.
    let folded_mul = circuit.mul(folded_constraints, sels.inv_vanishing);

    // Check that folded_constraints * sels.inv_vanishing == quotient
    let check = circuit.sub(folded_mul, quotient);
    circuit.assert_zero(check);

    Ok(())
}

fn vanishing_poly_at_point_circuit<
    SC: StarkGenericConfig,
    InputProof: Recursive<SC::Challenge>,
    OpeningProof: Recursive<SC::Challenge>,
    Comm: Recursive<SC::Challenge>,
    Domain,
>(
    config: &SC,
    domain: Domain,
    zeta: ExprId,
    circuit: &mut CircuitBuilder<SC::Challenge>,
) -> ExprId
where
    <SC as StarkGenericConfig>::Pcs: RecursivePcs<SC, InputProof, OpeningProof, Comm, Domain>,
{
    let pcs = config.pcs();
    let inv = circuit.add_const(pcs.first_point(&domain).inverse());
    let mul = circuit.mul(zeta, inv);
    let exp = exp_power_of_2(circuit, mul, pcs.log_size(&domain));
    let one = circuit.add_const(SC::Challenge::ONE);

    circuit.sub(exp, one)
}

fn exp_power_of_2<F: Field>(
    circuit: &mut CircuitBuilder<F>,
    base: ExprId,
    power_log: usize,
) -> ExprId {
    let mut res = base;
    for _ in 0..power_log {
        let square = circuit.mul(res, res);
        res = square;
    }
    res
}
