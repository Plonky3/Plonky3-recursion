use alloc::vec::Vec;

use p3_challenger::DuplexChallenger;
use p3_circuit::ops::{generate_poseidon2_trace, generate_recompose_trace};
use p3_circuit::{CircuitBuilder, CircuitRunner, NonPrimitiveOpId};
use p3_commit::{ExtensionMmcs, Pcs};
use p3_field::extension::BinomialExtensionField;
use p3_fri::FriParameters;
use p3_koala_bear::{KoalaBear, Poseidon2KoalaBear, default_koalabear_poseidon2_16};
use p3_lookup::logup::LogUpGadget;
use p3_merkle_tree::MerkleTreeMmcs;
use p3_poseidon2_circuit_air::KoalaBearD4Width16;
use p3_symmetric::{PaddingFreeSponge, TruncatedPermutation};
use p3_uni_stark::Val;

use super::{KoalaBearD4Poseidon2BinaryConfig, OrdinaryMmcs, OrdinaryPcs};
use crate::FriRecursionConfig;
use crate::generation::{OpeningTranscript, observe_opened_values};
use crate::ops::Poseidon2Config;
use crate::pcs::fri::{
    FriProofTargets, InputProofTargets, MerkleCapTargets, RecExtensionValMmcs, RecValMmcs, Witness,
};
use crate::pcs::{restore_fri_query_paths, set_fri_mmcs_private_data};
use crate::recursion::RecursionInput;
use crate::traits::{RecursiveAir, RecursivePcs};
use crate::verifier::VerificationError;

type F = KoalaBear;
type Challenge = BinomialExtensionField<F, 4>;
type Perm = Poseidon2KoalaBear<16>;
type Challenger = DuplexChallenger<F, Perm, 16, 8>;
type NativeMmcs = OrdinaryMmcs<F, Perm, 16, 8, 8, 2>;
type NativePcs = OrdinaryPcs<F, Challenge, Perm, 16, 8, 8, 2>;
type RecHash = PaddingFreeSponge<Perm, 16, 8, 8>;
type RecCompress = TruncatedPermutation<Perm, 2, 8, 16>;
type RecMmcs = RecValMmcs<F, 8, RecHash, RecCompress>;
type InputProof = InputProofTargets<F, Challenge, RecMmcs>;
type OpeningProof = FriProofTargets<
    F,
    Challenge,
    RecExtensionValMmcs<F, Challenge, 8, RecMmcs>,
    InputProof,
    Witness<F>,
>;
type CommitMmcs = ExtensionMmcs<F, Challenge, NativeMmcs>;

fn native_restore_components(
    config: &KoalaBearD4Poseidon2BinaryConfig,
) -> (NativeMmcs, NativeMmcs, FriParameters<CommitMmcs>) {
    let descriptor = config.descriptor();
    let input_perm = default_koalabear_poseidon2_16();
    let input_mmcs = MerkleTreeMmcs::new(
        PaddingFreeSponge::new(input_perm.clone()),
        TruncatedPermutation::new(input_perm),
        descriptor.input_cap_height() as usize,
    );
    let commit_perm = default_koalabear_poseidon2_16();
    let commit_mmcs = MerkleTreeMmcs::new(
        PaddingFreeSponge::new(commit_perm.clone()),
        TruncatedPermutation::new(commit_perm),
        descriptor.commit_cap_height() as usize,
    );
    let fri_params = FriParameters {
        max_log_arity: descriptor.max_log_arity() as usize,
        log_blowup: descriptor.log_blowup() as usize,
        log_final_poly_len: descriptor.log_final_poly_len() as usize,
        num_queries: descriptor.num_queries() as usize,
        batch_proof_of_work_bits: 0,
        commit_proof_of_work_bits: descriptor.commit_pow_bits() as usize,
        query_proof_of_work_bits: descriptor.query_pow_bits() as usize,
        mmcs: ExtensionMmcs::new(commit_mmcs.clone()),
    };
    (input_mmcs, commit_mmcs, fri_params)
}

impl FriRecursionConfig for KoalaBearD4Poseidon2BinaryConfig
where
    NativePcs: RecursivePcs<
            Self,
            InputProof,
            OpeningProof,
            MerkleCapTargets<F, 8>,
            <NativePcs as Pcs<Challenge, Challenger>>::Domain,
        >,
{
    type Commitment = MerkleCapTargets<F, 8>;
    type InputProof = InputProof;
    type OpeningProof = OpeningProof;
    type RawOpeningProof = <NativePcs as Pcs<Challenge, Challenger>>::Proof;

    const DIGEST_ELEMS: usize = 8;

    fn native_fri_validation_params(&self) -> Option<crate::pcs::fri::NativeFriParams> {
        Some(self.native_fri_params)
    }

    fn with_fri_opening_proof<'a, A, R>(
        prev: &RecursionInput<'a, Self, A>,
        f: impl FnOnce(&Self::RawOpeningProof) -> R,
    ) -> R
    where
        A: RecursiveAir<Val<Self>, Self::Challenge, LogUpGadget>,
    {
        match prev {
            RecursionInput::UniStark { proof, .. } => f(&proof.opening_proof),
            RecursionInput::BatchStark { proof, .. } => f(&proof.proof.opening_proof),
        }
    }

    fn prepare_circuit_for_verification(
        &self,
        circuit: &mut CircuitBuilder<Challenge>,
    ) -> Result<(), VerificationError> {
        circuit.enable_poseidon2_perm::<KoalaBearD4Width16, _>(
            generate_poseidon2_trace::<Challenge, KoalaBearD4Width16>,
            default_koalabear_poseidon2_16(),
        );
        circuit.enable_recompose::<F>(generate_recompose_trace::<F, Challenge>);
        Ok(())
    }

    fn pcs_verifier_params(
        &self,
    ) -> &<NativePcs as RecursivePcs<
        Self,
        InputProof,
        OpeningProof,
        MerkleCapTargets<F, 8>,
        <NativePcs as Pcs<Challenge, Challenger>>::Domain,
    >>::VerifierParams {
        &self.fri_verifier_params
    }

    fn set_fri_private_data(
        config: &Self,
        runner: &mut CircuitRunner<'_, Challenge>,
        op_ids: &[NonPrimitiveOpId],
        opening_proof: &Self::RawOpeningProof,
        transcript: OpeningTranscript<Self>,
    ) -> Result<(), &'static str> {
        let OpeningTranscript {
            mut challenger,
            commitments_with_opening_points,
        } = transcript;
        let (input_mmcs, commit_mmcs, fri_params) = native_restore_components(config);
        observe_opened_values::<Self>(
            &mut challenger,
            &commitments_with_opening_points,
            fri_params.batch_proof_of_work_bits,
        );
        let claims: Vec<_> = commitments_with_opening_points
            .into_iter()
            .map(Into::into)
            .collect();
        let query_paths = restore_fri_query_paths(
            &fri_params,
            &input_mmcs,
            &commit_mmcs,
            opening_proof,
            &mut challenger,
            &claims,
        )
        .map_err(|_| "Failed to restore the FRI proof's per-query Merkle paths")?;
        set_fri_mmcs_private_data::<F, Challenge, 8>(
            runner,
            op_ids,
            &query_paths,
            Poseidon2Config::KOALA_BEAR_D4_W16,
        )
    }
}
