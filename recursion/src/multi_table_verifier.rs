use itertools::zip_eq;
use p3_circuit::CircuitBuilder;
use p3_commit::Pcs;
use p3_uni_stark::StarkGenericConfig;

use crate::{
    circuit_verifier::{ProofTargetsWithPVs, VerificationError, verify_circuit},
    lookup::RecursiveAirWithLookupVerification,
    recursive_traits::{Recursive, RecursivePcs},
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
    airs: &[&dyn RecursiveAirWithLookupVerification<SC::Challenge, Comm>],
    circuit: &mut CircuitBuilder<SC::Challenge>,
    proof_targets: &[ProofTargetsWithPVs<SC, Comm, OpeningProof>],
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
    // TODO: Deal with recursive lookups.
    for (air, proof_targets_pvs_cum_sum) in zip_eq(airs, proof_targets) {
        verify_circuit(config, *air, circuit, &proof_targets_pvs_cum_sum, &[], &[])?;
    }
    Ok(())
}
