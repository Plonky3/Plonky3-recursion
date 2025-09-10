use p3_air::AirBuilder;
use p3_uni_stark::{PcsError, StarkGenericConfig, VerificationError};

use crate::air::asic::Asic;
use crate::prover::RecursiveProof;

pub fn verify<AB: AirBuilder, SC: StarkGenericConfig>(
    config: &SC,
    asic: &Asic<SC, AB>,
    proof: RecursiveProof<SC>,
) -> Result<(), VerificationError<PcsError<SC>>> {
    asic.verify_chips(config, proof)
}
