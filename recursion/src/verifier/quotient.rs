use alloc::vec::Vec;

use itertools::Itertools;
use p3_circuit::CircuitBuilder;
use p3_field::{BasedVectorSpace, Field, PrimeCharacteristicRing};
use p3_uni_stark::StarkGenericConfig;

use crate::Target;
use crate::traits::{Recursive, RecursivePcs};

/// Circuit analogue of `recompose_quotient_from_chunks`, returning quotient(zeta).
pub fn recompose_quotient_from_chunks_circuit<
    SC: StarkGenericConfig,
    InputProof: Recursive<SC::Challenge>,
    OpeningProof: Recursive<SC::Challenge>,
    Comm: Recursive<SC::Challenge>,
    Domain: Copy,
>(
    circuit: &mut CircuitBuilder<SC::Challenge>,
    quotient_chunks_domains: &[Domain],
    quotient_chunks: &[Vec<Target>],
    zeta: Target,
    pcs: &SC::Pcs,
) -> Target
where
    <SC as StarkGenericConfig>::Pcs: RecursivePcs<SC, InputProof, OpeningProof, Comm, Domain>,
    SC::Challenge: PrimeCharacteristicRing,
{
    let zero = circuit.add_const(SC::Challenge::ZERO);
    let one = circuit.add_const(SC::Challenge::ONE);

    let zps = compute_quotient_chunk_products::<SC, InputProof, OpeningProof, Comm, Domain>(
        circuit,
        quotient_chunks_domains,
        zeta,
        one,
        pcs,
    );

    compute_quotient_evaluation::<SC>(circuit, quotient_chunks, &zps, zero)
}

/// Compute the product terms for quotient chunk reconstruction.
///
/// For each chunk i, computes: ∏_{j≠i} (Z_{domain_j}(zeta) / Z_{domain_j}(first_point_i))
fn compute_quotient_chunk_products<
    SC: StarkGenericConfig,
    InputProof: Recursive<SC::Challenge>,
    OpeningProof: Recursive<SC::Challenge>,
    Comm: Recursive<SC::Challenge>,
    Domain: Copy,
>(
    circuit: &mut CircuitBuilder<SC::Challenge>,
    quotient_chunks_domains: &[Domain],
    zeta: Target,
    one: Target,
    pcs: &<SC as StarkGenericConfig>::Pcs,
) -> Vec<Target>
where
    <SC as StarkGenericConfig>::Pcs: RecursivePcs<SC, InputProof, OpeningProof, Comm, Domain>,
{
    quotient_chunks_domains
        .iter()
        .enumerate()
        .map(|(i, domain)| {
            quotient_chunks_domains
                .iter()
                .enumerate()
                .filter(|(j, _)| *j != i)
                .fold(one, |total, (_, other_domain)| {
                    let vp_zeta = vanishing_poly_at_point_circuit::<
                        SC,
                        InputProof,
                        OpeningProof,
                        Comm,
                        Domain,
                    >(pcs, *other_domain, zeta, circuit);

                    let first_point = circuit.add_const(pcs.first_point(domain));
                    let vp_first_point = vanishing_poly_at_point_circuit::<
                        SC,
                        InputProof,
                        OpeningProof,
                        Comm,
                        Domain,
                    >(
                        pcs, *other_domain, first_point, circuit
                    );
                    let div = circuit.div(vp_zeta, vp_first_point);

                    circuit.mul(total, div)
                })
        })
        .collect_vec()
}

/// Compute the quotient polynomial evaluation from chunks.
///
/// quotient(zeta) = ∑_i (∑_j e_j · chunk_i[j]) · zps[i]
fn compute_quotient_evaluation<SC: StarkGenericConfig>(
    circuit: &mut CircuitBuilder<SC::Challenge>,
    opened_quotient_chunks: &[Vec<Target>],
    zps: &[Target],
    zero: Target,
) -> Target
where
    SC::Challenge: PrimeCharacteristicRing,
{
    opened_quotient_chunks
        .iter()
        .enumerate()
        .fold(zero, |quotient, (i, chunk)| {
            let zp = zps[i];

            // Sum chunk elements weighted by basis elements: ∑_j e_j · chunk[j]
            let inner_result = chunk.iter().enumerate().fold(zero, |cur_s, (e_i, c)| {
                let e_i_target = circuit.add_const(SC::Challenge::ith_basis_element(e_i).unwrap());
                let inner_mul = circuit.mul(e_i_target, *c);
                circuit.add(cur_s, inner_mul)
            });

            let mul = circuit.mul(inner_result, zp);
            circuit.add(quotient, mul)
        })
}

/// Compute the vanishing polynomial Z_H(point) = point^n - 1 at a given point.
///
/// # Parameters
/// - `pcs`: Polynomial commitment scheme for domain metadata
/// - `domain`: The domain (defines n)
/// - `point`: The evaluation point
/// - `circuit`: Circuit builder
///
/// # Returns
/// Target representing Z_H(point)
fn vanishing_poly_at_point_circuit<
    SC: StarkGenericConfig,
    InputProof: Recursive<SC::Challenge>,
    OpeningProof: Recursive<SC::Challenge>,
    Comm: Recursive<SC::Challenge>,
    Domain,
>(
    pcs: &<SC as StarkGenericConfig>::Pcs,
    domain: Domain,
    point: Target,
    circuit: &mut CircuitBuilder<SC::Challenge>,
) -> Target
where
    <SC as StarkGenericConfig>::Pcs: RecursivePcs<SC, InputProof, OpeningProof, Comm, Domain>,
{
    // Normalize point: point' = point / first_point
    let inv = circuit.add_const(pcs.first_point(&domain).inverse());
    let mul = circuit.mul(point, inv);

    // Compute (point')^n
    let exp = circuit.exp_power_of_2(mul, pcs.log_size(&domain));

    // Return (point')^n - 1
    let one = circuit.add_const(SC::Challenge::ONE);
    circuit.sub(exp, one)
}
