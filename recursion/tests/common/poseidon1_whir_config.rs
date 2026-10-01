//! Local BabyBear D4 and Goldilocks D2 Poseidon1 WHIR configurations.

use p3_baby_bear::{BabyBear, Poseidon1BabyBear, default_babybear_poseidon1_16};
use p3_challenger::DuplexChallenger;
use p3_circuit::ops::poseidon1_perm::{BabyBearD4Width16, GoldilocksD2Width8};
use p3_circuit::ops::{Poseidon1Config, generate_poseidon1_trace, generate_recompose_trace};
use p3_circuit::{CircuitBuilder, CircuitRunner, NonPrimitiveOpId};
use p3_dft::Radix2DFTSmallBatch;
use p3_field::Field;
use p3_field::extension::BinomialExtensionField;
use p3_goldilocks::Goldilocks;
use p3_goldilocks::poseidon1::{Poseidon1Goldilocks, default_goldilocks_poseidon1_8};
use p3_lookup::logup::LogUpGadget;
use p3_merkle_tree::MerkleTreeMmcs;
use p3_recursion::VerificationError;
use p3_recursion::backend::whir::WhirRecursionConfig;
use p3_recursion::generation::OpeningTranscript;
use p3_recursion::pcs::fri::MerkleCapTargets;
use p3_recursion::pcs::set_whir_mmcs_private_data;
use p3_recursion::pcs::whir::uni::{
    WhirUniPcs, WhirUniProof, WhirUniProofTargets, WhirUniVerifierParams,
    restore_whir_recursion_paths, whir_round_paths_op_count,
};
use p3_recursion::recursion::RecursionInput;
use p3_recursion::traits::RecursiveAir;
use p3_sumcheck::layout::{Layout, PrefixProver};
use p3_symmetric::{PaddingFreeSponge, TruncatedPermutation};
use p3_uni_stark::StarkGenericConfig;
use p3_whir::parameters::{FoldingFactor, ProtocolParameters, SecurityAssumption};

pub type BabyF = BabyBear;
pub type BabyEF = BinomialExtensionField<BabyF, 4>;
pub type BabyPerm = Poseidon1BabyBear<16>;
pub type BabyHash = PaddingFreeSponge<BabyPerm, 16, 8, 8>;
pub type BabyCompress = TruncatedPermutation<BabyPerm, 2, 8, 16>;
pub type BabyPacked = <BabyF as Field>::Packing;
pub type BabyMmcs = MerkleTreeMmcs<BabyPacked, BabyPacked, BabyHash, BabyCompress, 2, 8>;
pub type BabyDft = Radix2DFTSmallBatch<BabyF>;
pub type BabyChallenger = DuplexChallenger<BabyF, BabyPerm, 16, 8>;
pub type BabyPcs =
    WhirUniPcs<BabyEF, BabyF, BabyDft, BabyMmcs, BabyChallenger, PrefixProver<BabyF, BabyEF>>;
pub const BABY_DIGEST_ELEMS: usize = 8;

pub type GoldF = Goldilocks;
pub type GoldEF = BinomialExtensionField<GoldF, 2>;
pub type GoldPerm = Poseidon1Goldilocks<8>;
pub type GoldHash = PaddingFreeSponge<GoldPerm, 8, 4, 4>;
pub type GoldCompress = TruncatedPermutation<GoldPerm, 2, 4, 8>;
pub type GoldPacked = <GoldF as Field>::Packing;
pub type GoldMmcs = MerkleTreeMmcs<GoldPacked, GoldPacked, GoldHash, GoldCompress, 2, 4>;
pub type GoldDft = Radix2DFTSmallBatch<GoldF>;
pub type GoldChallenger = DuplexChallenger<GoldF, GoldPerm, 8, 4>;
pub type GoldPcs =
    WhirUniPcs<GoldEF, GoldF, GoldDft, GoldMmcs, GoldChallenger, PrefixProver<GoldF, GoldEF>>;
pub const GOLD_DIGEST_ELEMS: usize = 4;

pub const fn protocol_params() -> ProtocolParameters {
    ProtocolParameters {
        security_level: 32,
        pow_bits: 0,
        round_log_inv_rates: vec![],
        folding_factor: FoldingFactor::Constant(4),
        soundness_type: SecurityAssumption::CapacityBound,
        starting_log_inv_rate: 1,
    }
}

pub fn baby_mmcs() -> BabyMmcs {
    let perm = default_babybear_poseidon1_16();
    BabyMmcs::new(BabyHash::new(perm.clone()), BabyCompress::new(perm), 0)
}

pub fn gold_mmcs() -> GoldMmcs {
    let perm = default_goldilocks_poseidon1_8();
    GoldMmcs::new(GoldHash::new(perm.clone()), GoldCompress::new(perm), 0)
}

#[derive(Clone)]
pub struct BabyP1WhirConfig {
    pcs: BabyPcs,
    challenger: BabyChallenger,
    verifier_params: WhirUniVerifierParams<BabyF>,
}

pub fn baby_p1_whir_config() -> BabyP1WhirConfig {
    let protocol = protocol_params();
    let challenger = BabyChallenger::new(default_babybear_poseidon1_16());
    let pcs = BabyPcs::new(
        protocol.clone(),
        BabyDft::default(),
        baby_mmcs(),
        challenger.clone(),
        20,
    );
    let verifier_params = WhirUniVerifierParams::<BabyF>::new(
        protocol,
        PrefixProver::<BabyF, BabyEF>::variable_order(),
        Poseidon1Config::BABY_BEAR_D4_W16,
    )
    .expect("valid BabyBear Poseidon1 WHIR protocol");
    BabyP1WhirConfig {
        pcs,
        challenger,
        verifier_params,
    }
}

impl StarkGenericConfig for BabyP1WhirConfig {
    type Pcs = BabyPcs;
    type Challenge = BabyEF;
    type Challenger = BabyChallenger;

    fn pcs(&self) -> &Self::Pcs {
        &self.pcs
    }

    fn initialise_challenger(&self) -> Self::Challenger {
        self.challenger.clone()
    }
}

impl WhirRecursionConfig for BabyP1WhirConfig {
    type Commitment = MerkleCapTargets<BabyF, BABY_DIGEST_ELEMS>;
    type InputProof = ();
    type OpeningProof = WhirUniProofTargets<BabyF, BabyEF, BabyMmcs, BABY_DIGEST_ELEMS>;
    type RawOpeningProof = WhirUniProof<BabyF, BabyEF, BabyMmcs>;

    fn with_whir_opening_proof<'a, A, R>(
        prev: &RecursionInput<'a, Self, A>,
        f: impl FnOnce(&Self::RawOpeningProof) -> R,
    ) -> R
    where
        A: RecursiveAir<BabyF, BabyEF, LogUpGadget>,
    {
        match prev {
            RecursionInput::UniStark { proof, .. } => f(&proof.opening_proof),
            RecursionInput::BatchStark { proof, .. } => f(&proof.proof.opening_proof),
        }
    }

    fn prepare_circuit_for_verification(
        &self,
        circuit: &mut CircuitBuilder<BabyEF>,
    ) -> Result<(), VerificationError> {
        circuit.enable_poseidon1_perm::<BabyBearD4Width16, _>(
            generate_poseidon1_trace::<BabyEF, BabyBearD4Width16>,
            default_babybear_poseidon1_16(),
        );
        circuit.enable_recompose::<BabyF>(generate_recompose_trace::<BabyF, BabyEF>);
        Ok(())
    }

    fn pcs_verifier_params(&self) -> &WhirUniVerifierParams<BabyF> {
        &self.verifier_params
    }

    fn set_whir_private_data(
        config: &Self,
        runner: &mut CircuitRunner<'_, BabyEF>,
        op_ids: &[NonPrimitiveOpId],
        opening_proof: &Self::RawOpeningProof,
        transcript: OpeningTranscript<Self>,
    ) -> Result<(), &'static str> {
        let params = config.pcs_verifier_params();
        let paths = restore_whir_recursion_paths::<Self, _, _, _, _, _, BABY_DIGEST_ELEMS>(
            &baby_mmcs(),
            transcript,
            opening_proof,
            params.protocol_params(),
            params.folding(),
            params.variable_order(),
        )
        .map_err(|_| "Failed to restore BabyBear Poseidon1 WHIR Merkle paths")?;

        let mut offset = 0usize;
        for round_paths in &paths {
            let count = whir_round_paths_op_count(round_paths);
            let ids = op_ids
                .get(offset..offset + count)
                .ok_or("Not enough op_ids for BabyBear Poseidon1 WHIR paths")?;
            set_whir_mmcs_private_data::<BabyF, BabyEF, BABY_DIGEST_ELEMS>(
                runner,
                ids,
                &round_paths.rounds,
                &round_paths.final_paths,
                Poseidon1Config::BABY_BEAR_D4_W16,
            )?;
            offset += count;
        }
        if offset != op_ids.len() {
            return Err("op-id accounting mismatch in BabyP1WhirConfig");
        }
        Ok(())
    }
}

#[derive(Clone)]
pub struct GoldP1WhirConfig {
    pcs: GoldPcs,
    challenger: GoldChallenger,
    verifier_params: WhirUniVerifierParams<GoldF>,
}

pub fn gold_p1_whir_config() -> GoldP1WhirConfig {
    let protocol = protocol_params();
    let challenger = GoldChallenger::new(default_goldilocks_poseidon1_8());
    let pcs = GoldPcs::new(
        protocol.clone(),
        GoldDft::default(),
        gold_mmcs(),
        challenger.clone(),
        20,
    );
    let verifier_params = WhirUniVerifierParams::<GoldF>::new(
        protocol,
        PrefixProver::<GoldF, GoldEF>::variable_order(),
        Poseidon1Config::GOLDILOCKS_D2_W8,
    )
    .expect("valid Goldilocks Poseidon1 WHIR protocol");
    GoldP1WhirConfig {
        pcs,
        challenger,
        verifier_params,
    }
}

impl StarkGenericConfig for GoldP1WhirConfig {
    type Pcs = GoldPcs;
    type Challenge = GoldEF;
    type Challenger = GoldChallenger;

    fn pcs(&self) -> &Self::Pcs {
        &self.pcs
    }

    fn initialise_challenger(&self) -> Self::Challenger {
        self.challenger.clone()
    }
}

impl WhirRecursionConfig for GoldP1WhirConfig {
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
        circuit.enable_poseidon1_perm_width_8::<GoldilocksD2Width8, _>(
            generate_poseidon1_trace::<GoldEF, GoldilocksD2Width8>,
            default_goldilocks_poseidon1_8(),
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
            &gold_mmcs(),
            transcript,
            opening_proof,
            params.protocol_params(),
            params.folding(),
            params.variable_order(),
        )
        .map_err(|_| "Failed to restore Goldilocks Poseidon1 WHIR Merkle paths")?;

        let mut offset = 0usize;
        for round_paths in &paths {
            let count = whir_round_paths_op_count(round_paths);
            let ids = op_ids
                .get(offset..offset + count)
                .ok_or("Not enough op_ids for Goldilocks Poseidon1 WHIR paths")?;
            set_whir_mmcs_private_data::<GoldF, GoldEF, GOLD_DIGEST_ELEMS>(
                runner,
                ids,
                &round_paths.rounds,
                &round_paths.final_paths,
                Poseidon1Config::GOLDILOCKS_D2_W8,
            )?;
            offset += count;
        }
        if offset != op_ids.len() {
            return Err("op-id accounting mismatch in GoldP1WhirConfig");
        }
        Ok(())
    }
}
