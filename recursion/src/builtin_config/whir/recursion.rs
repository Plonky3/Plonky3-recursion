use p3_baby_bear::{BabyBear, Poseidon2BabyBear, default_babybear_poseidon2_16};
use p3_circuit::ops::{generate_poseidon2_trace, generate_recompose_trace};
use p3_circuit::{CircuitBuilder, CircuitRunner, NonPrimitiveOpId};
use p3_field::extension::BinomialExtensionField;
use p3_koala_bear::{KoalaBear, Poseidon2KoalaBear, default_koalabear_poseidon2_16};
use p3_lookup::logup::LogUpGadget;
use p3_merkle_tree::MerkleTreeMmcs;
use p3_poseidon2_circuit_air::{BabyBearD4Width16, KoalaBearD4Width16};
use p3_symmetric::{PaddingFreeSponge, TruncatedPermutation};

use super::{BabyBearD4Poseidon2WhirConfig, KoalaBearD4Poseidon2WhirConfig, WhirMmcs};
use crate::backend::whir::WhirRecursionConfig;
use crate::generation::OpeningTranscript;
use crate::pcs::fri::MerkleCapTargets;
use crate::pcs::set_whir_mmcs_private_data;
use crate::pcs::whir::uni::{
    WhirUniProof, WhirUniProofTargets, WhirUniVerifierParams, restore_whir_recursion_paths,
    whir_round_paths_op_count,
};
use crate::recursion::RecursionInput;
use crate::traits::RecursiveAir;
use crate::{Poseidon2Config, VerificationError};

macro_rules! whir_recursion_config {
    ($config:ty, $field:ty, $challenge:ty, $perm:ty, $air:ty, $perm_factory:path, $poseidon:expr) => {
        impl WhirRecursionConfig for $config {
            type Commitment = MerkleCapTargets<$field, 8>;
            type InputProof = ();
            type OpeningProof = WhirUniProofTargets<$field, $challenge, WhirMmcs<$field, $perm>, 8>;
            type RawOpeningProof = WhirUniProof<$field, $challenge, WhirMmcs<$field, $perm>>;

            fn with_whir_opening_proof<'a, A, R>(
                prev: &RecursionInput<'a, Self, A>,
                f: impl FnOnce(&Self::RawOpeningProof) -> R,
            ) -> R
            where
                A: RecursiveAir<$field, $challenge, LogUpGadget>,
            {
                match prev {
                    RecursionInput::UniStark { proof, .. } => f(&proof.opening_proof),
                    RecursionInput::BatchStark { proof, .. } => f(&proof.proof.opening_proof),
                }
            }

            fn prepare_circuit_for_verification(
                &self,
                circuit: &mut CircuitBuilder<$challenge>,
            ) -> Result<(), VerificationError> {
                circuit.enable_poseidon2_perm::<$air, _>(
                    generate_poseidon2_trace::<$challenge, $air>,
                    $perm_factory(),
                );
                circuit.enable_recompose::<$field>(generate_recompose_trace::<$field, $challenge>);
                Ok(())
            }

            fn pcs_verifier_params(&self) -> &WhirUniVerifierParams<$field> {
                self.whir_verifier_params()
            }

            fn set_whir_private_data(
                config: &Self,
                runner: &mut CircuitRunner<'_, $challenge>,
                op_ids: &[NonPrimitiveOpId],
                opening_proof: &Self::RawOpeningProof,
                transcript: OpeningTranscript<Self>,
            ) -> Result<(), &'static str> {
                let perm = $perm_factory();
                let mmcs: WhirMmcs<$field, $perm> = MerkleTreeMmcs::new(
                    PaddingFreeSponge::new(perm.clone()),
                    TruncatedPermutation::new(perm),
                    config.descriptor().cap_height() as usize,
                );
                let params = config.pcs_verifier_params();
                let paths = restore_whir_recursion_paths::<Self, _, _, _, _, _, 8>(
                    &mmcs,
                    transcript,
                    opening_proof,
                    params.protocol_params(),
                    params.folding(),
                    params.variable_order(),
                )
                .map_err(|_| "Failed to restore WHIR Merkle paths")?;

                let mut offset = 0;
                for round_paths in &paths {
                    let count = whir_round_paths_op_count(round_paths);
                    let op_ids_slice = op_ids
                        .get(offset..offset + count)
                        .ok_or("Not enough op_ids for the restored WHIR Merkle paths")?;
                    set_whir_mmcs_private_data::<$field, $challenge, 8>(
                        runner,
                        op_ids_slice,
                        &round_paths.rounds,
                        &round_paths.final_paths,
                        $poseidon,
                    )?;
                    offset += count;
                }
                if offset != op_ids.len() {
                    return Err("op-id accounting mismatch in built-in WHIR private data");
                }
                Ok(())
            }
        }
    };
}

whir_recursion_config!(
    BabyBearD4Poseidon2WhirConfig,
    BabyBear,
    BinomialExtensionField<BabyBear, 4>,
    Poseidon2BabyBear<16>,
    BabyBearD4Width16,
    default_babybear_poseidon2_16,
    Poseidon2Config::BABY_BEAR_D4_W16
);

whir_recursion_config!(
    KoalaBearD4Poseidon2WhirConfig,
    KoalaBear,
    BinomialExtensionField<KoalaBear, 4>,
    Poseidon2KoalaBear<16>,
    KoalaBearD4Width16,
    default_koalabear_poseidon2_16,
    Poseidon2Config::KOALA_BEAR_D4_W16
);
