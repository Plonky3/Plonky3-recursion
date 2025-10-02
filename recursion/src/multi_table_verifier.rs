use alloc::vec::Vec;

use itertools::zip_eq;
use p3_circuit::CircuitBuilder;
use p3_commit::Pcs;
use p3_uni_stark::StarkGenericConfig;

use crate::circuit_verifier::{ProofTargetsWithPVs, VerificationError, verify_circuit};
use crate::lookup::{
    GlobalLookup, LocalLookup, RecursiveLookupVerification, RecursivePermutationAir,
};
use crate::recursive_traits::{Recursive, RecursivePcs};

type ProofTargetsWithLookups<'a, SC, Comm, OpeningProof> = (
    ProofTargetsWithPVs<'a, SC, Comm, OpeningProof>,
    Vec<LocalLookup<'a>>,
    Vec<GlobalLookup<'a>>,
);

pub fn verify_multitable_circuit<
    SC: StarkGenericConfig,
    Comm: Recursive<
            SC::Challenge,
            Input = <SC::Pcs as Pcs<SC::Challenge, SC::Challenger>>::Commitment,
        > + Clone,
    InputProof: Recursive<SC::Challenge>,
    OpeningProof: Recursive<SC::Challenge>,
    RecursiveLookup: RecursiveLookupVerification<SC::Challenge>,
>(
    config: &SC,
    airs: &[&dyn RecursivePermutationAir<SC::Challenge>],
    circuit: &mut CircuitBuilder<SC::Challenge>,
    proof_targets: &[ProofTargetsWithLookups<'_, SC, Comm, OpeningProof>],
    lookup_gadget: &RecursiveLookup,
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
    // TODO: observe all tables here (and not in the individual verifications) so that we can already get global lookup challenges.
    // Retrieve all global lookups across all tables. This will be used to get the necessary challenge targets and to verify the global lookups.
    let all_global_lookups = proof_targets
        .iter()
        .flat_map(|(_, _, global_lookups)| global_lookups.iter().cloned())
        .collect::<Vec<_>>();

    // The first thing we do is to generate the challenges for cross-table interactions.
    let global_challenges =
        lookup_gadget.get_global_lookup_challenges_circuit(circuit, &all_global_lookups);

    // First, verify each recursive AIR individually.
    for (air, (proof_targets_pvs, local_lookups, global_lookups)) in zip_eq(airs, proof_targets) {
        verify_circuit(
            config,
            *air,
            circuit,
            proof_targets_pvs,
            local_lookups,
            global_lookups,
            &global_challenges,
            lookup_gadget,
        )?;
    }

    // Then, verify the cross-table interactions.
    lookup_gadget.eval_global_final_value(circuit, &all_global_lookups, &global_challenges);

    Ok(())
}
