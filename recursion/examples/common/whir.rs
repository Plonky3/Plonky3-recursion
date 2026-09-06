//! WHIR-backed `StarkGenericConfig` types shared by the WHIR recursive examples.
//!
//! Examples cannot import from `recursion/tests/common/whir_config.rs` (tests and examples are
//! separate Cargo compilation targets), so this module mirrors it for the `examples/` target.

use p3_baby_bear::{BabyBear, Poseidon2BabyBear, default_babybear_poseidon2_16};
use p3_challenger::DuplexChallenger;
use p3_circuit::ops::{generate_poseidon2_trace, generate_recompose_trace};
use p3_circuit::{CircuitBuilder, CircuitRunner, NonPrimitiveOpId};
use p3_dft::Radix2DFTSmallBatch;
use p3_field::Field;
use p3_field::extension::BinomialExtensionField;
use p3_koala_bear::{KoalaBear, Poseidon2KoalaBear, default_koalabear_poseidon2_16};
use p3_lookup::logup::LogUpGadget;
use p3_merkle_tree::MerkleTreeMmcs;
use p3_poseidon2_circuit_air::{BabyBearD4Width16, KoalaBearD4Width16};
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
use p3_recursion::{Poseidon2Config, VerificationError};
use p3_sumcheck::layout::{Layout, PrefixProver};
use p3_symmetric::{PaddingFreeSponge, TruncatedPermutation};
use p3_uni_stark::StarkGenericConfig;
use p3_whir::parameters::{FoldingFactor, ProtocolParameters, SecurityAssumption};

/// The base field for BabyBear WHIR example configurations.
pub type BbF = BabyBear;
/// The extension field WHIR-backed proofs are challenged and opened over.
pub type BbEF = BinomialExtensionField<BabyBear, 4>;
/// The Poseidon2 permutation shared by the hasher, compressor and challenger.
pub type BbPerm = Poseidon2BabyBear<16>;
/// The leaf hasher for the Merkle commitment scheme WHIR example configurations use.
pub type BbHash = PaddingFreeSponge<BbPerm, 16, 8, 8>;
/// The two-to-one compressor for the Merkle commitment scheme WHIR example configurations use.
pub type BbCompress = TruncatedPermutation<BbPerm, 2, 8, 16>;
/// The base field's packed SIMD representation, as required by [`BbMmcs`].
pub type BbPacked = <BbF as Field>::Packing;
/// The Merkle commitment scheme WHIR example configurations use.
pub type BbMmcs = MerkleTreeMmcs<BbPacked, BbPacked, BbHash, BbCompress, 2, 8>;
/// The FFT engine WHIR example configurations use to encode committed codewords.
pub type BbDft = Radix2DFTSmallBatch<BbF>;
/// The Fiat-Shamir challenger WHIR example configurations use.
pub type BbChallenger = DuplexChallenger<BbF, BbPerm, 16, 8>;
/// The WHIR-backed univariate polynomial commitment scheme under example.
pub type BbWhirPcs = WhirUniPcs<BbEF, BbF, BbDft, BbMmcs, BbChallenger, PrefixProver<BbF, BbEF>>;

/// Number of base-field elements in one Merkle digest.
pub const BB_DIGEST_ELEMS: usize = 8;

/// Permutation shared by the hasher, compressor and challenger.
///
/// These are the canonical BabyBear width-16 round constants, the ones
/// [`BabyBearD4Width16::round_constants`] hard-codes into the Poseidon2 AIR. A configuration
/// whose circuit is proven — not merely witness-checked — has to use them: the AIR recomputes
/// every permutation row from its own constants, so a different permutation makes each row's
/// output disagree with the witness the circuit built from it, and the challenger table's
/// sponge chain (each row's capacity input against the previous row's capacity output) is the
/// first constraint to break.
pub fn bb_whir_perm() -> BbPerm {
    default_babybear_poseidon2_16()
}

/// Merkle scheme used by every WHIR commitment in the examples.
pub fn bb_whir_mmcs() -> BbMmcs {
    let perm = bb_whir_perm();
    BbMmcs::new(BbHash::new(perm.clone()), BbCompress::new(perm), 0)
}

/// WHIR protocol parameters; the length of `round_log_inv_rates` fixes the
/// number of intermediate WHIR rounds.
pub const fn bb_whir_protocol_params(round_log_inv_rates: Vec<usize>) -> ProtocolParameters {
    ProtocolParameters {
        security_level: 32,
        pow_bits: 0,
        round_log_inv_rates,
        folding_factor: FoldingFactor::Constant(4),
        soundness_type: SecurityAssumption::CapacityBound,
        starting_log_inv_rate: 1,
    }
}

/// STARK configuration backed by WHIR.
#[derive(Clone)]
pub struct BbWhirConfig {
    pcs: BbWhirPcs,
    challenger: BbChallenger,
    /// Shared WHIR verifier parameters, held so [`WhirRecursionConfig::pcs_verifier_params`] and
    /// [`WhirRecursionConfig::set_whir_private_data`] can both read the round schedule the
    /// config's own `pcs` was built with.
    whir_verifier_params: WhirUniVerifierParams<BbF>,
}

/// Builds the configuration for the given WHIR round schedule. Pass `vec![]` to auto-derive the
/// round schedule per commit, which is required whenever a config serves commits of more than
/// one round-count bucket (e.g. a small base proof's opening and a larger verifier circuit's own
/// trace).
pub fn bb_whir_config(round_log_inv_rates: Vec<usize>) -> BbWhirConfig {
    let perm = bb_whir_perm();
    let challenger = BbChallenger::new(perm);
    let protocol_params = bb_whir_protocol_params(round_log_inv_rates);
    let pcs = WhirUniPcs::new(
        protocol_params.clone(),
        BbDft::default(),
        bb_whir_mmcs(),
        challenger.clone(),
        20,
    );
    let whir_verifier_params = WhirUniVerifierParams::<BbF>::new(
        protocol_params,
        PrefixProver::<BbF, BbEF>::variable_order(),
        Some(Poseidon2Config::BABY_BEAR_D4_W16.into()),
    );
    BbWhirConfig {
        pcs,
        challenger,
        whir_verifier_params,
    }
}

impl StarkGenericConfig for BbWhirConfig {
    type Pcs = BbWhirPcs;
    type Challenge = BbEF;
    type Challenger = BbChallenger;

    fn pcs(&self) -> &Self::Pcs {
        &self.pcs
    }

    fn initialise_challenger(&self) -> Self::Challenger {
        self.challenger.clone()
    }
}

impl WhirRecursionConfig for BbWhirConfig {
    type Commitment = MerkleCapTargets<BbF, BB_DIGEST_ELEMS>;
    type InputProof = ();
    type OpeningProof = WhirUniProofTargets<BbF, BbEF, BbMmcs, BB_DIGEST_ELEMS>;
    type RawOpeningProof = WhirUniProof<BbF, BbEF, BbMmcs>;

    fn with_whir_opening_proof<'a, A, R>(
        prev: &RecursionInput<'a, Self, A>,
        f: impl FnOnce(&Self::RawOpeningProof) -> R,
    ) -> R
    where
        A: RecursiveAir<BbF, BbEF, LogUpGadget>,
    {
        match prev {
            RecursionInput::UniStark { proof, .. } => f(&proof.opening_proof),
            RecursionInput::BatchStark { .. } => {
                panic!("with_whir_opening_proof called on a batch-STARK recursion input")
            }
        }
    }

    fn prepare_circuit_for_verification(
        &self,
        circuit: &mut CircuitBuilder<BbEF>,
    ) -> Result<(), VerificationError> {
        circuit.enable_poseidon2_perm::<BabyBearD4Width16, _>(
            generate_poseidon2_trace::<BbEF, BabyBearD4Width16>,
            bb_whir_perm(),
        );
        circuit.enable_recompose::<BbF>(generate_recompose_trace::<BbF, BbEF>);
        Ok(())
    }

    fn pcs_verifier_params(&self) -> &WhirUniVerifierParams<BbF> {
        &self.whir_verifier_params
    }

    fn set_whir_private_data(
        config: &Self,
        runner: &mut CircuitRunner<'_, BbEF>,
        op_ids: &[NonPrimitiveOpId],
        opening_proof: &Self::RawOpeningProof,
        transcript: OpeningTranscript<Self>,
    ) -> Result<(), &'static str> {
        let mmcs = bb_whir_mmcs();
        let params = config.pcs_verifier_params();
        let paths = restore_whir_recursion_paths::<Self, _, _, _, _, _, BB_DIGEST_ELEMS>(
            &mmcs,
            transcript,
            opening_proof,
            &params.protocol_params,
            params.folding,
            params.variable_order,
        )
        .map_err(|_| "Failed to restore WHIR Merkle paths")?;

        let mut offset = 0usize;
        for round_paths in &paths {
            let count = whir_round_paths_op_count(round_paths);
            let op_ids_slice = op_ids
                .get(offset..offset + count)
                .ok_or("Not enough op_ids for the restored WHIR Merkle paths")?;
            set_whir_mmcs_private_data::<BbF, BbEF, BB_DIGEST_ELEMS>(
                runner,
                op_ids_slice,
                &round_paths.rounds,
                &round_paths.final_paths,
                Poseidon2Config::BABY_BEAR_D4_W16,
            )?;
            offset += count;
        }
        if offset != op_ids.len() {
            return Err("op-id accounting mismatch in BbWhirConfig::set_whir_private_data");
        }
        Ok(())
    }
}

/// The base field for KoalaBear WHIR example configurations.
pub type KbF = KoalaBear;
/// The extension field WHIR-backed proofs are challenged and opened over.
pub type KbEF = BinomialExtensionField<KoalaBear, 4>;
/// The Poseidon2 permutation shared by the hasher, compressor and challenger.
pub type KbPerm = Poseidon2KoalaBear<16>;
/// The leaf hasher for the Merkle commitment scheme WHIR example configurations use.
pub type KbHash = PaddingFreeSponge<KbPerm, 16, 8, 8>;
/// The two-to-one compressor for the Merkle commitment scheme WHIR example configurations use.
pub type KbCompress = TruncatedPermutation<KbPerm, 2, 8, 16>;
/// The base field's packed SIMD representation, as required by [`KbMmcs`].
pub type KbPacked = <KbF as Field>::Packing;
/// The Merkle commitment scheme WHIR example configurations use.
pub type KbMmcs = MerkleTreeMmcs<KbPacked, KbPacked, KbHash, KbCompress, 2, 8>;
/// The FFT engine WHIR example configurations use to encode committed codewords.
pub type KbDft = Radix2DFTSmallBatch<KbF>;
/// The Fiat-Shamir challenger WHIR example configurations use.
pub type KbChallenger = DuplexChallenger<KbF, KbPerm, 16, 8>;
/// The WHIR-backed univariate polynomial commitment scheme under example.
pub type KbWhirPcs = WhirUniPcs<KbEF, KbF, KbDft, KbMmcs, KbChallenger, PrefixProver<KbF, KbEF>>;

/// Number of base-field elements in one Merkle digest.
pub const KB_DIGEST_ELEMS: usize = 8;

/// Permutation shared by the hasher, compressor and challenger.
///
/// The canonical KoalaBear width-16 round constants, for the reason [`bb_whir_perm`] documents.
pub fn kb_whir_perm() -> KbPerm {
    default_koalabear_poseidon2_16()
}

/// Merkle scheme used by every WHIR commitment in the examples.
pub fn kb_whir_mmcs() -> KbMmcs {
    let perm = kb_whir_perm();
    KbMmcs::new(KbHash::new(perm.clone()), KbCompress::new(perm), 0)
}

/// WHIR protocol parameters; the length of `round_log_inv_rates` fixes the
/// number of intermediate WHIR rounds.
pub const fn kb_whir_protocol_params(round_log_inv_rates: Vec<usize>) -> ProtocolParameters {
    ProtocolParameters {
        security_level: 32,
        pow_bits: 0,
        round_log_inv_rates,
        folding_factor: FoldingFactor::Constant(4),
        soundness_type: SecurityAssumption::CapacityBound,
        starting_log_inv_rate: 1,
    }
}

/// STARK configuration backed by WHIR.
#[derive(Clone)]
pub struct KbWhirConfig {
    pcs: KbWhirPcs,
    challenger: KbChallenger,
    /// Shared WHIR verifier parameters, held so [`WhirRecursionConfig::pcs_verifier_params`] and
    /// [`WhirRecursionConfig::set_whir_private_data`] can both read the round schedule the
    /// config's own `pcs` was built with.
    whir_verifier_params: WhirUniVerifierParams<KbF>,
}

/// Builds the configuration for the given WHIR round schedule. Pass `vec![]` to auto-derive the
/// round schedule per commit, which is required whenever a config serves commits of more than
/// one round-count bucket (e.g. a small base proof's opening and a larger verifier circuit's own
/// trace).
pub fn kb_whir_config(round_log_inv_rates: Vec<usize>) -> KbWhirConfig {
    let perm = kb_whir_perm();
    let challenger = KbChallenger::new(perm);
    let protocol_params = kb_whir_protocol_params(round_log_inv_rates);
    let pcs = WhirUniPcs::new(
        protocol_params.clone(),
        KbDft::default(),
        kb_whir_mmcs(),
        challenger.clone(),
        20,
    );
    let whir_verifier_params = WhirUniVerifierParams::<KbF>::new(
        protocol_params,
        PrefixProver::<KbF, KbEF>::variable_order(),
        Some(Poseidon2Config::KOALA_BEAR_D4_W16.into()),
    );
    KbWhirConfig {
        pcs,
        challenger,
        whir_verifier_params,
    }
}

impl StarkGenericConfig for KbWhirConfig {
    type Pcs = KbWhirPcs;
    type Challenge = KbEF;
    type Challenger = KbChallenger;

    fn pcs(&self) -> &Self::Pcs {
        &self.pcs
    }

    fn initialise_challenger(&self) -> Self::Challenger {
        self.challenger.clone()
    }
}

impl WhirRecursionConfig for KbWhirConfig {
    type Commitment = MerkleCapTargets<KbF, KB_DIGEST_ELEMS>;
    type InputProof = ();
    type OpeningProof = WhirUniProofTargets<KbF, KbEF, KbMmcs, KB_DIGEST_ELEMS>;
    type RawOpeningProof = WhirUniProof<KbF, KbEF, KbMmcs>;

    fn with_whir_opening_proof<'a, A, R>(
        prev: &RecursionInput<'a, Self, A>,
        f: impl FnOnce(&Self::RawOpeningProof) -> R,
    ) -> R
    where
        A: RecursiveAir<KbF, KbEF, LogUpGadget>,
    {
        match prev {
            RecursionInput::UniStark { proof, .. } => f(&proof.opening_proof),
            RecursionInput::BatchStark { .. } => {
                panic!("with_whir_opening_proof called on a batch-STARK recursion input")
            }
        }
    }

    fn prepare_circuit_for_verification(
        &self,
        circuit: &mut CircuitBuilder<KbEF>,
    ) -> Result<(), VerificationError> {
        circuit.enable_poseidon2_perm::<KoalaBearD4Width16, _>(
            generate_poseidon2_trace::<KbEF, KoalaBearD4Width16>,
            kb_whir_perm(),
        );
        circuit.enable_recompose::<KbF>(generate_recompose_trace::<KbF, KbEF>);
        Ok(())
    }

    fn pcs_verifier_params(&self) -> &WhirUniVerifierParams<KbF> {
        &self.whir_verifier_params
    }

    fn set_whir_private_data(
        config: &Self,
        runner: &mut CircuitRunner<'_, KbEF>,
        op_ids: &[NonPrimitiveOpId],
        opening_proof: &Self::RawOpeningProof,
        transcript: OpeningTranscript<Self>,
    ) -> Result<(), &'static str> {
        let mmcs = kb_whir_mmcs();
        let params = config.pcs_verifier_params();
        let paths = restore_whir_recursion_paths::<Self, _, _, _, _, _, KB_DIGEST_ELEMS>(
            &mmcs,
            transcript,
            opening_proof,
            &params.protocol_params,
            params.folding,
            params.variable_order,
        )
        .map_err(|_| "Failed to restore WHIR Merkle paths")?;

        let mut offset = 0usize;
        for round_paths in &paths {
            let count = whir_round_paths_op_count(round_paths);
            let op_ids_slice = op_ids
                .get(offset..offset + count)
                .ok_or("Not enough op_ids for the restored WHIR Merkle paths")?;
            set_whir_mmcs_private_data::<KbF, KbEF, KB_DIGEST_ELEMS>(
                runner,
                op_ids_slice,
                &round_paths.rounds,
                &round_paths.final_paths,
                Poseidon2Config::KOALA_BEAR_D4_W16,
            )?;
            offset += count;
        }
        if offset != op_ids.len() {
            return Err("op-id accounting mismatch in KbWhirConfig::set_whir_private_data");
        }
        Ok(())
    }
}
