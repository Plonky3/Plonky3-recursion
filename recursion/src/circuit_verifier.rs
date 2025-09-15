use itertools::{Itertools, zip_eq};
use p3_circuit::{CircuitBuilder, ExprId};
use p3_commit::Pcs;
use p3_field::{BasedVectorSpace, Field, PrimeCharacteristicRing};
use p3_uni_stark::StarkGenericConfig;

use crate::recursive_traits::{
    CommitmentWires, OpenedValuesWires, ProofWires, Recursive, RecursiveAir, RecursivePcs,
};

// Method to get all the challenge wires.
fn get_circuit_challenges<
    SC: StarkGenericConfig,
    Comm: Recursive<SC::Challenge, Input = <SC::Pcs as Pcs<SC::Challenge, SC::Challenger>>::Commitment>,
    InputProof: Recursive<SC::Challenge>,
    OpeningProof: Recursive<SC::Challenge>,
    const D: usize,
>(
    proof_wires: &ProofWires<SC, Comm, OpeningProof>,
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
    // Observe degree bits and degree_bits - is_zk.
    // Observe local wires.
    // Observe public values.
    challenges.push(circuit.add_public_input());
    // Observe quotient chunks.
    // Observe random commitment if any.
    // zeta and zeta_next
    challenges.push(circuit.add_public_input());
    challenges.push(circuit.add_public_input());

    let pcs_challenges = <SC::Pcs as RecursivePcs<
        SC,
        InputProof,
        OpeningProof,
        Comm,
        <SC::Pcs as Pcs<SC::Challenge, SC::Challenger>>::Domain,
    >>::get_challenges_circuit(circuit, proof_wires);

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
    const D: usize,
    const DIGEST_ELEMS: usize,
>(
    config: &SC,
    air: &A,
    proof_wires: &ProofWires<SC, Comm, OpeningProof>,
    public_values: &[ExprId],
) -> Result<CircuitBuilder<SC::Challenge>, String>
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
    let ProofWires {
        commitments_wires:
            CommitmentWires {
                trace_wires,
                quotient_chunks_wires,
                random_commit,
                ..
            },
        opened_values_wires:
            OpenedValuesWires {
                trace_local_wires: opened_trace_local_wires,
                trace_next_wires: opened_trace_next_wires,
                quotient_chunks_wires: opened_quotient_chunks_wires,
                random_wires: opened_random,
                ..
            },
        opening_proof,
        degree_bits,
    } = proof_wires;
    let degree = 1 << degree_bits;
    let log_quotient_degree =
        A::get_log_quotient_degree(air, 0, public_values.len(), config.is_zk());
    let quotient_degree = 1 << (log_quotient_degree + config.is_zk());

    let pcs = config.pcs();
    let trace_domain = pcs.natural_domain_for_degree(degree);
    let init_trace_domain = pcs.natural_domain_for_degree(degree >> (config.is_zk()));
    let mut circuit = CircuitBuilder::<SC::Challenge>::new();

    let quotient_domain =
        pcs.create_disjoint_domain(trace_domain, 1 << (degree_bits + log_quotient_degree));
    let quotient_chunks_domains = pcs.split_domains(&quotient_domain, quotient_degree);

    let randomized_quotient_chunks_domains = quotient_chunks_domains
        .iter()
        .map(|domain| pcs.natural_domain_for_degree(pcs.size(domain) << (config.is_zk())))
        .collect_vec();

    // Challenger is called here. But we don't have the interactions or hash tables yet.
    let challenge_wires =
        get_circuit_challenges::<SC, Comm, InputProof, OpeningProof, D>(proof_wires, &mut circuit);

    // Verify shape.
    let air_width = A::width(air);
    let validate_shape = opened_trace_local_wires.len() == air_width
        && opened_trace_next_wires.len() == air_width
        && opened_quotient_chunks_wires.len() == quotient_degree
        && opened_quotient_chunks_wires
            .iter()
            .all(|opened_chunk| opened_chunk.len() == SC::Challenge::DIMENSION);
    if !validate_shape {
        return Err("Invalid proof shape".to_string());
    }

    let alpha = challenge_wires[0];
    let zeta = challenge_wires[1];
    let zeta_next = challenge_wires[2];

    // Need to simulate Fri here.
    let mut coms_to_verify = if let Some(r_commit) = &random_commit {
        let random_values = opened_random.as_ref().ok_or("Randomization error")?;
        vec![(
            r_commit.clone(),
            vec![(trace_domain, vec![(zeta, random_values.clone())])],
        )]
    } else {
        vec![]
    };
    coms_to_verify.extend(vec![
        (
            trace_wires.clone(),
            vec![(
                trace_domain,
                vec![
                    (zeta, opened_trace_local_wires.clone()),
                    (zeta_next, opened_trace_next_wires.clone()),
                ],
            )],
        ),
        (
            quotient_chunks_wires.clone(),
            // Check the commitment on the randomized domains.
            zip_eq(
                randomized_quotient_chunks_domains.iter(),
                opened_quotient_chunks_wires,
            )
            .map(|(domain, values)| (*domain, vec![(zeta, values.clone())]))
            .collect_vec(),
        ),
    ]);
    pcs.verify_circuit(
        &mut circuit,
        &challenge_wires[3..],
        &coms_to_verify,
        opening_proof,
    );

    let zero = circuit.add_const(SC::Challenge::ZERO);
    let zps = quotient_chunks_domains
        .iter()
        .enumerate()
        .map(|(i, domain)| {
            let mut total = zero;
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
                    >(config, *other_domain, zeta, &mut circuit);

                    let first_point = circuit.add_const(pcs.first_point(domain));
                    let other_v_n =
                        vanishing_poly_at_point_circuit::<
                            SC,
                            InputProof,
                            OpeningProof,
                            Comm,
                            <SC::Pcs as Pcs<SC::Challenge, SC::Challenger>>::Domain,
                        >(config, *other_domain, first_point, &mut circuit);
                    let div = circuit.div(v_n, other_v_n);

                    total = circuit.mul(total, div);
                });
            total
        })
        .collect_vec();

    let mut quotient = zero;
    for (i, chunk) in opened_quotient_chunks_wires.iter().enumerate() {
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

    let sels = pcs.selectors_at_point_circuit(&mut circuit, &init_trace_domain, &zeta);
    let folded_constraints = air.eval_folded_circuit(
        &mut circuit,
        &sels,
        &alpha,
        &[],
        &[],
        opened_trace_local_wires,
        opened_trace_next_wires,
        public_values,
    );

    // Compute folded_constraints * sels.inv_vanishing.
    let folded_mul = circuit.add(folded_constraints, sels.inv_vanishing);

    // Check that folded_constraints * sels.inv_vanishing == quotient
    let check = circuit.sub(folded_mul, quotient);
    circuit.assert_zero(check);

    Ok(circuit)
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
    let mul = circuit.add(zeta, inv);
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
