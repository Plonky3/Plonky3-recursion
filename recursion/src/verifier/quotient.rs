use alloc::vec::Vec;

use p3_circuit::CircuitBuilder;
use p3_field::{BasedVectorSpace, Field, PrimeCharacteristicRing};
use p3_uni_stark::StarkGenericConfig;

use crate::Target;
use crate::traits::{Recursive, RecursivePcs};

/// Compute the product terms for quotient chunk reconstruction.
///
/// For each chunk i, computes: ∏_{j≠i} (Z_{domain_j}(zeta) / Z_{domain_j}(first_point_i))
pub fn compute_quotient_chunk_products_circuit<
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
        .map(|(i, domain_i)| {
            let first_point_i = circuit.add_const(pcs.first_point(domain_i));
            quotient_chunks_domains
                .iter()
                .enumerate()
                .filter(|(j, _)| *j != i)
                .fold(one, |total, (_, domain_j)| {
                    let vp_zeta = vanishing_poly_at_point_circuit::<
                        SC,
                        InputProof,
                        OpeningProof,
                        Comm,
                        Domain,
                    >(circuit, *domain_j, zeta, pcs);
                    let vp_first = vanishing_poly_at_point_circuit::<
                        SC,
                        InputProof,
                        OpeningProof,
                        Comm,
                        Domain,
                    >(circuit, *domain_j, first_point_i, pcs);
                    let div = circuit.div(vp_zeta, vp_first);
                    circuit.mul(total, div)
                })
        })
        .collect()
}

/// Compute the quotient polynomial evaluation from chunks.
///
/// quotient(zeta) = ∑_i (∑_j e_j · chunk_i[j]) · zps[i]
pub fn compute_quotient_evaluation_circuit<SC: StarkGenericConfig>(
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

            let inner_result = chunk.iter().enumerate().fold(zero, |cur_s, (e_i, c)| {
                let basis = circuit.add_const(SC::Challenge::ith_basis_element(e_i).unwrap());
                let inner_mul = circuit.mul(basis, *c);
                circuit.add(cur_s, inner_mul)
            });

            let mul = circuit.mul(inner_result, zp);
            circuit.add(quotient, mul)
        })
}

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
    let one = circuit.add_const(SC::Challenge::ONE);
    let zps = compute_quotient_chunk_products_circuit::<SC, InputProof, OpeningProof, Comm, _>(
        circuit,
        quotient_chunks_domains,
        zeta,
        one,
        pcs,
    );
    let zero = circuit.add_const(SC::Challenge::ZERO);
    compute_quotient_evaluation_circuit::<SC>(circuit, quotient_chunks, &zps, zero)
}

fn vanishing_poly_at_point_circuit<
    SC: StarkGenericConfig,
    InputProof: Recursive<SC::Challenge>,
    OpeningProof: Recursive<SC::Challenge>,
    Comm: Recursive<SC::Challenge>,
    Domain: Copy,
>(
    circuit: &mut CircuitBuilder<SC::Challenge>,
    domain: Domain,
    point: Target,
    pcs: &SC::Pcs,
) -> Target
where
    <SC as StarkGenericConfig>::Pcs: RecursivePcs<SC, InputProof, OpeningProof, Comm, Domain>,
{
    let inv = circuit.add_const(pcs.first_point(&domain).inverse());
    let normalized_point = circuit.mul(point, inv);
    let pow = circuit.exp_power_of_2(normalized_point, pcs.log_size(&domain));
    let one = circuit.add_const(SC::Challenge::ONE);
    circuit.sub(pow, one)
}
