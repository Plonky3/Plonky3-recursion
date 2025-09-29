use alloc::vec::Vec;
use itertools::zip_eq;
use p3_circuit::CircuitBuilder;
use p3_commit::Pcs;
use p3_uni_stark::StarkGenericConfig;

use crate::{
    Target,
    circuit_verifier::{VerificationError, verify_circuit},
    recursive_traits::{ProofTargets, Recursive, RecursiveAir, RecursivePcs},
};

pub fn verify_multitable_circuit<
    SC: StarkGenericConfig,
    Comm: Recursive<
            SC::Challenge,
            Input = <SC::Pcs as Pcs<SC::Challenge, SC::Challenger>>::Commitment,
        > + Clone,
    InputProof: Recursive<SC::Challenge>,
    OpeningProof: Recursive<SC::Challenge>,
>(
    config: &SC,
    airs: &[&dyn RecursiveAir<SC::Challenge>],
    circuit: &mut CircuitBuilder<SC::Challenge>,
    proof_targets: &[ProofTargets<SC, Comm, OpeningProof>],
    // Each `Vec` corresponds to the public inputs for one AIR.
    all_public_values: &[Vec<Target>],
) -> Result<(), VerificationError>
where
    <SC as StarkGenericConfig>::Pcs: RecursivePcs<
            SC,
            InputProof,
            OpeningProof,
            Comm,
            <SC::Pcs as Pcs<SC::Challenge, SC::Challenger>>::Domain,
        >,
{
    for (air, (proof_target, public_values)) in
        zip_eq(airs, zip_eq(proof_targets, all_public_values))
    {
        verify_circuit(config, *air, circuit, proof_target, public_values)?;
    }
    Ok(())
}
