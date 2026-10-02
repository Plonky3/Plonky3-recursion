//! Local Goldilocks degree-two WHIR configuration for recursion integration tests.

use p3_challenger::DuplexChallenger;
use p3_circuit::ops::{GoldilocksD2Width8, generate_poseidon2_trace, generate_recompose_trace};
use p3_circuit::{CircuitBuilder, CircuitRunner, NonPrimitiveOpId};
use p3_dft::Radix2DFTSmallBatch;
use p3_field::Field;
use p3_field::extension::BinomialExtensionField;
use p3_goldilocks::{Goldilocks, Poseidon2Goldilocks};
use p3_lookup::logup::LogUpGadget;
use p3_merkle_tree::MerkleTreeMmcs;
use p3_recursion::backend::whir::WhirRecursionConfig;
use p3_recursion::builtin_config::fixed_goldilocks_poseidon2_8;
use p3_recursion::generation::OpeningTranscript;
use p3_recursion::pcs::fri::MerkleCapTargets;
use p3_recursion::pcs::set_whir_mmcs_private_data;
use p3_recursion::pcs::whir::uni::{
    WhirUniPcs, WhirUniProof, WhirUniProofTargets, WhirUniVerifierParams,
    restore_whir_recursion_paths, whir_round_paths_op_count,
};
use p3_recursion::recursion::RecursionInput;
use p3_recursion::traits::RecursiveAir;
use p3_recursion::{Poseidon2Config, VerificationError};
use p3_sumcheck::layout::{Layout, PrefixProver};
use p3_symmetric::{PaddingFreeSponge, TruncatedPermutation};
use p3_uni_stark::StarkGenericConfig;
use p3_whir::parameters::{FoldingFactor, ProtocolParameters, SecurityAssumption};

pub type GoldF = Goldilocks;
pub type GoldEF = BinomialExtensionField<GoldF, 2>;
pub type GoldPerm = Poseidon2Goldilocks<8>;
pub type GoldHash = PaddingFreeSponge<GoldPerm, 8, 4, 4>;
pub type GoldCompress = TruncatedPermutation<GoldPerm, 2, 4, 8>;
pub type GoldPacked = <GoldF as Field>::Packing;
pub type GoldMmcs = MerkleTreeMmcs<GoldPacked, GoldPacked, GoldHash, GoldCompress, 2, 4>;
pub type GoldDft = Radix2DFTSmallBatch<GoldF>;
pub type GoldChallenger = DuplexChallenger<GoldF, GoldPerm, 8, 4>;
pub type GoldWhirPcs =
    WhirUniPcs<GoldEF, GoldF, GoldDft, GoldMmcs, GoldChallenger, PrefixProver<GoldF, GoldEF>>;

pub const GOLD_DIGEST_ELEMS: usize = 4;

pub fn gold_whir_mmcs() -> GoldMmcs {
    let perm = fixed_goldilocks_poseidon2_8();
    GoldMmcs::new(GoldHash::new(perm.clone()), GoldCompress::new(perm), 0)
}

pub const fn gold_whir_protocol_params() -> ProtocolParameters {
    ProtocolParameters {
        security_level: 32,
        pow_bits: 0,
        round_log_inv_rates: vec![],
        folding_factor: FoldingFactor::Constant(4),
        soundness_type: SecurityAssumption::CapacityBound,
        starting_log_inv_rate: 1,
    }
}

#[derive(Clone)]
pub struct GoldWhirConfig {
    pcs: GoldWhirPcs,
    challenger: GoldChallenger,
    verifier_params: WhirUniVerifierParams<GoldF>,
}

pub fn gold_whir_config() -> GoldWhirConfig {
    let protocol = gold_whir_protocol_params();
    let perm = fixed_goldilocks_poseidon2_8();
    let challenger = GoldChallenger::new(perm);
    let pcs = GoldWhirPcs::new(
        protocol.clone(),
        GoldDft::default(),
        gold_whir_mmcs(),
        challenger.clone(),
        20,
    );
    let verifier_params = WhirUniVerifierParams::<GoldF>::new(
        protocol,
        PrefixProver::<GoldF, GoldEF>::variable_order(),
        Poseidon2Config::GOLDILOCKS_D2_W8,
    )
    .expect("valid Goldilocks WHIR protocol");
    GoldWhirConfig {
        pcs,
        challenger,
        verifier_params,
    }
}

impl StarkGenericConfig for GoldWhirConfig {
    type Pcs = GoldWhirPcs;
    type Challenge = GoldEF;
    type Challenger = GoldChallenger;

    fn pcs(&self) -> &Self::Pcs {
        &self.pcs
    }

    fn initialise_challenger(&self) -> Self::Challenger {
        self.challenger.clone()
    }
}

impl WhirRecursionConfig for GoldWhirConfig {
    type Commitment = MerkleCapTargets<GoldF, GOLD_DIGEST_ELEMS>;
    type InputProof = ();
    type OpeningProof = WhirUniProofTargets<GoldF, GoldEF, GoldMmcs, GOLD_DIGEST_ELEMS>;
    type RawOpeningProof = WhirUniProof<GoldF, GoldEF, GoldMmcs>;

    fn with_whir_opening_proof<'a, A, R>(
        prev: &RecursionInput<'a, Self, A>,
        f: impl FnOnce(&Self::RawOpeningProof) -> R,
    ) -> R
    where
        A: RecursiveAir<GoldF, GoldEF, LogUpGadget>,
    {
        match prev {
            RecursionInput::UniStark { proof, .. } => f(&proof.opening_proof),
            RecursionInput::BatchStark { proof, .. } => f(&proof.proof.opening_proof),
        }
    }

    fn prepare_circuit_for_verification(
        &self,
        circuit: &mut CircuitBuilder<GoldEF>,
    ) -> Result<(), VerificationError> {
        circuit.enable_poseidon2_perm_width_8::<GoldilocksD2Width8, _>(
            generate_poseidon2_trace::<GoldEF, GoldilocksD2Width8>,
            fixed_goldilocks_poseidon2_8(),
        );
        circuit.enable_recompose::<GoldF>(generate_recompose_trace::<GoldF, GoldEF>);
        Ok(())
    }

    fn pcs_verifier_params(&self) -> &WhirUniVerifierParams<GoldF> {
        &self.verifier_params
    }

    fn set_whir_private_data(
        config: &Self,
        runner: &mut CircuitRunner<'_, GoldEF>,
        op_ids: &[NonPrimitiveOpId],
        opening_proof: &Self::RawOpeningProof,
        transcript: OpeningTranscript<Self>,
    ) -> Result<(), &'static str> {
        let params = config.pcs_verifier_params();
        let paths = restore_whir_recursion_paths::<Self, _, _, _, _, _, GOLD_DIGEST_ELEMS>(
            &gold_whir_mmcs(),
            transcript,
            &config.initialise_challenger(),
            opening_proof,
            params.protocol_params(),
            params.folding(),
            params.variable_order(),
        )
        .map_err(|_| "Failed to restore Goldilocks WHIR Merkle paths")?;

        let mut offset = 0;
        for round_paths in &paths {
            let count = whir_round_paths_op_count(round_paths);
            let round_ids = op_ids
                .get(offset..offset + count)
                .ok_or("Not enough op_ids for Goldilocks WHIR paths")?;
            set_whir_mmcs_private_data::<GoldF, GoldEF, GOLD_DIGEST_ELEMS>(
                runner,
                round_ids,
                &round_paths.rounds,
                &round_paths.final_paths,
                Poseidon2Config::GOLDILOCKS_D2_W8,
            )?;
            offset += count;
        }
        if offset != op_ids.len() {
            return Err("op-id accounting mismatch in GoldWhirConfig::set_whir_private_data");
        }
        Ok(())
    }
}
