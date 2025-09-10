use itertools::Itertools;
use itertools::zip_eq;
use p3_commit::Pcs;
use p3_field::BasedVectorSpace;
use p3_field::Field;
use p3_field::PrimeCharacteristicRing;
use p3_field::extension::BinomiallyExtendable;

use p3_uni_stark::StarkGenericConfig;
use p3_uni_stark::Val;

use crate::circuit_builder::CircuitError;
use crate::circuit_builder::ExtensionWireId;
use crate::circuit_builder::{CircuitBuilder, WireId};
use crate::gates::arith_gates::AddExtensionGate;
use crate::gates::arith_gates::MulExtensionGate;
use crate::gates::arith_gates::SubExtensionGate;
use crate::recursive_traits::CommitmentWires;
use crate::recursive_traits::OpenedValuesWires;
use crate::recursive_traits::ProofWires;
use crate::recursive_traits::Recursive;
use crate::recursive_traits::RecursiveAir;
use crate::recursive_traits::RecursivePcs;

// Method to get all the challenge wires.
fn get_circuit_challenges<
    SC: StarkGenericConfig,
    Comm: Recursive<Val<SC>, D, Input = <SC::Pcs as Pcs<SC::Challenge, SC::Challenger>>::Commitment>,
    InputProof: Recursive<Val<SC>, D>,
    OpeningProof: Recursive<Val<SC>, D>,
    const D: usize,
>(
    proof_wires: &ProofWires<SC, Comm, OpeningProof, D>,
    circuit: &mut CircuitBuilder<Val<SC>, D>,
) -> Vec<ExtensionWireId<D>>
where
    SC::Pcs: RecursivePcs<
            SC,
            InputProof,
            OpeningProof,
            Comm,
            <SC::Pcs as Pcs<SC::Challenge, SC::Challenger>>::Domain,
            D,
        >,
{
    let mut challenges = vec![];
    // Observe degree bits and degree_bits - is_zk.
    // Observe local wires.
    // Observe public values.
    challenges.push(circuit.new_extension_wires());
    // Observe quotient chunks.
    // Observe random commitment if any.
    // zeta and zeta_next
    challenges.push(circuit.new_extension_wires());
    challenges.push(circuit.new_extension_wires());

    let pcs_challenges = <SC::Pcs as RecursivePcs<
        SC,
        InputProof,
        OpeningProof,
        Comm,
        <SC::Pcs as Pcs<SC::Challenge, SC::Challenger>>::Domain,
        D,
    >>::get_challenges_circuit(circuit, proof_wires);

    challenges.extend(pcs_challenges);

    challenges
}

pub fn verify_circuit<
    A,
    SC: StarkGenericConfig + Clone,
    Comm: Recursive<Val<SC>, D, Input = <SC::Pcs as Pcs<SC::Challenge, SC::Challenger>>::Commitment>
        + Clone,
    InputProof: Recursive<Val<SC>, D>,
    OpeningProof: Recursive<Val<SC>, D, Input = <SC::Pcs as Pcs<SC::Challenge, SC::Challenger>>::Proof> + Clone,
    const D: usize,
    const DIGEST_ELEMS: usize,
>(
    config: &SC,
    air: &A,
    public_values: &Vec<WireId>,
    lens: &mut impl Iterator<Item = usize>,
    degree_bits: usize,
) -> Result<CircuitBuilder<Val<SC>, D>, CircuitError>
where
    Val<SC>: BinomiallyExtendable<D>,
    A: RecursiveAir<Val<SC>, D>,
    InputProof: Clone,
    <SC as StarkGenericConfig>::Pcs: RecursivePcs<
            SC,
            InputProof,
            OpeningProof,
            Comm,
            <SC::Pcs as Pcs<SC::Challenge, SC::Challenger>>::Domain,
            D,
        >,
{
    let mut circuit = CircuitBuilder::<Val<SC>, D>::new();
    let proof_wires = ProofWires::<SC, Comm, OpeningProof, D>::new(&mut circuit, lens, degree_bits);
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
    } = proof_wires.clone();
    let degree = 1 << degree_bits;
    let log_quotient_degree =
        A::get_log_quotient_degree(air, 0, public_values.len(), config.is_zk());
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
    let challenge_wires =
        get_circuit_challenges::<SC, Comm, InputProof, OpeningProof, D>(&proof_wires, &mut circuit);

    // Verify shape.
    let air_width = A::width(air);
    let validate_shape = opened_trace_local_wires.len() == air_width
        && opened_trace_next_wires.len() == air_width
        && opened_quotient_chunks_wires.len() == quotient_degree
        && opened_quotient_chunks_wires
            .iter()
            .all(|opened_chunk| opened_chunk.len() == SC::Challenge::DIMENSION);
    if !validate_shape {
        return Err(CircuitError::InvalidProofShape);
    }

    let alpha: ExtensionWireId<D> = challenge_wires[0];
    let zeta: ExtensionWireId<D> = challenge_wires[1];
    let zeta_next: ExtensionWireId<D> = challenge_wires[2];

    // Need to simulate Fri here.
    let mut coms_to_verify = if let Some(r_commit) = &random_commit {
        let random_values = opened_random
            .as_ref()
            .ok_or(CircuitError::RandomizationError)?;
        vec![(
            r_commit,
            vec![(trace_domain, vec![(zeta, random_values.clone())])],
        )]
    } else {
        vec![]
    };
    coms_to_verify.extend(vec![
        (
            &trace_wires,
            vec![(
                trace_domain,
                vec![
                    (zeta, opened_trace_local_wires.clone()),
                    (zeta_next, opened_trace_next_wires.clone()),
                ],
            )],
        ),
        (
            &quotient_chunks_wires,
            // Check the commitment on the randomized domains.
            zip_eq(
                randomized_quotient_chunks_domains.iter(),
                opened_quotient_chunks_wires.clone(),
            )
            .map(|(domain, values)| (*domain, vec![(zeta, values.clone())]))
            .collect_vec(),
        ),
    ]);
    pcs.verify_circuit(
        &mut circuit,
        &challenge_wires[3..],
        &coms_to_verify,
        &opening_proof,
    );

    let zero = circuit.add_extension_constant(SC::Challenge::ZERO);
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
                        D,
                    >(config, *other_domain, zeta, &mut circuit);

                    let first_point = circuit
                        .add_extension_constant(SC::Challenge::from(pcs.first_point(domain)));
                    let other_v_n =
                        vanishing_poly_at_point_circuit::<
                            SC,
                            InputProof,
                            OpeningProof,
                            Comm,
                            <SC::Pcs as Pcs<SC::Challenge, SC::Challenger>>::Domain,
                            D,
                        >(config, *other_domain, first_point, &mut circuit);
                    let div = circuit.new_extension_wires();
                    MulExtensionGate::<Val<SC>, D>::add_to_circuit(
                        &mut circuit,
                        other_v_n,
                        div,
                        v_n,
                    );

                    let new_total = circuit.new_extension_wires();
                    MulExtensionGate::<Val<SC>, D>::add_to_circuit(
                        &mut circuit,
                        total,
                        v_n,
                        new_total,
                    );
                    total = new_total;
                });
            total
        })
        .collect_vec();

    let mut quotient = zero;
    for (i, chunk) in opened_quotient_chunks_wires.iter().enumerate() {
        let zp = zps[i];

        let mut cur_s = zero;
        for (e_i, c) in chunk.iter().enumerate() {
            let e_i_wire =
                circuit.add_extension_constant(SC::Challenge::ith_basis_element(e_i).unwrap());
            let inner_mul = circuit.new_extension_wires();
            MulExtensionGate::<Val<SC>, D>::add_to_circuit(&mut circuit, e_i_wire, *c, inner_mul);
            let new_s = circuit.new_extension_wires();
            AddExtensionGate::<Val<SC>, D>::add_to_circuit(&mut circuit, cur_s, inner_mul, new_s);
            cur_s = inner_mul;
        }
        let mul = circuit.new_extension_wires();
        MulExtensionGate::<Val<SC>, D>::add_to_circuit(&mut circuit, cur_s, zp, mul);
        let add_wire = circuit.new_extension_wires();
        AddExtensionGate::<Val<SC>, D>::add_to_circuit(&mut circuit, quotient, mul, add_wire);
        quotient = add_wire;
    }

    let sels = pcs.selectors_at_point_circuit(&mut circuit, &init_trace_domain, &zeta);
    let folded_constraints = air.eval_folded_circuit::<SC::Challenge>(
        &mut circuit,
        &sels,
        &alpha,
        &vec![],
        &vec![],
        &opened_trace_local_wires,
        &opened_trace_next_wires,
        &public_values,
    );

    // Compute folded_constraints * sels.inv_vanishing.
    let folded_mul = circuit.new_extension_wires();
    MulExtensionGate::<Val<SC>, D>::add_to_circuit(
        &mut circuit,
        folded_constraints,
        sels.inv_vanishing,
        folded_mul,
    );

    // Check that folded_constraints * sels.inv_vanishing == quotient
    SubExtensionGate::<Val<SC>, D>::add_to_circuit(&mut circuit, folded_mul, quotient, zero);

    Ok(circuit)
}

fn vanishing_poly_at_point_circuit<
    SC: StarkGenericConfig,
    InputProof: Recursive<Val<SC>, D>,
    OpeningProof: Recursive<Val<SC>, D>,
    Comm: Recursive<Val<SC>, D>,
    Domain,
    const D: usize,
>(
    config: &SC,
    domain: Domain,
    zeta: ExtensionWireId<D>,
    circuit: &mut CircuitBuilder<Val<SC>, D>,
) -> ExtensionWireId<D>
where
    Val<SC>: BinomiallyExtendable<D>,
    <SC as StarkGenericConfig>::Pcs: RecursivePcs<SC, InputProof, OpeningProof, Comm, Domain, D>,
{
    let pcs = config.pcs();
    let inv =
        circuit.add_extension_constant(SC::Challenge::from(pcs.first_point(&domain).inverse()));

    let mul = circuit.new_extension_wires();
    MulExtensionGate::<Val<SC>, D>::add_to_circuit(circuit, zeta, inv, mul);
    let size_wire = circuit.add_extension_constant(SC::Challenge::from_usize(pcs.size(&domain)));
    let exp = circuit.new_extension_wires();
    MulExtensionGate::<Val<SC>, D>::add_to_circuit(circuit, mul, size_wire, exp);

    let one = circuit.add_extension_constant(SC::Challenge::ONE);
    let v_n = circuit.new_extension_wires();
    SubExtensionGate::<Val<SC>, D>::add_to_circuit(circuit, exp, one, v_n);

    v_n
}
