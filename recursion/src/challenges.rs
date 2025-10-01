use alloc::vec::Vec;

use crate::Target;

pub struct ProofChallengesTargets {
    pub alpha: Target,
    pub zeta: Target,
    pub zeta_next: Target,
    pub pcs_challenges: Vec<Target>,
    pub local_lookup_challenges: Vec<Vec<Target>>,
}

pub struct MultiProofChallenges {
    pub proof_challenges: Vec<ProofChallengesTargets>,
    pub global_lookup_challenges: Vec<Vec<Target>>,
}
