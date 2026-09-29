use alloc::vec::Vec;

use p3_baby_bear::{
    BabyBear, Poseidon1BabyBear, Poseidon2BabyBear, default_babybear_poseidon1_16,
    default_babybear_poseidon2_16, default_babybear_poseidon2_32,
};
use p3_challenger::DuplexChallenger;
use p3_circuit::ops::{
    generate_poseidon1_trace, generate_poseidon2_trace, generate_recompose_trace,
};
use p3_circuit::{CircuitBuilder, CircuitRunner, NonPrimitiveOpId};
use p3_commit::{ExtensionMmcs, Pcs};
use p3_field::extension::{BinomialExtensionField, QuinticTrinomialExtensionField};
use p3_field::{BasedVectorSpace, PrimeCharacteristicRing};
use p3_fri::FriParameters;
use p3_goldilocks::{Goldilocks, Poseidon2Goldilocks};
use p3_koala_bear::{
    KoalaBear, Poseidon1KoalaBear, Poseidon2KoalaBear, default_koalabear_poseidon1_16,
    default_koalabear_poseidon2_16, default_koalabear_poseidon2_32,
};
use p3_lookup::logup::LogUpGadget;
use p3_merkle_tree::{MerkleTreeHidingMmcs, MerkleTreeMmcs};
use p3_symmetric::{PaddingFreeSponge, Permutation, TruncatedPermutation};
use p3_uni_stark::Val;
use rand::{CryptoRng, SeedableRng};

use super::*;
use crate::FriRecursionConfig;
use crate::generation::{OpeningTranscript, merge_hiding_random_openings, observe_opened_values};
use crate::ops::Poseidon2Config;
use crate::pcs::fri::{
    FriProofTargets, HidingFriProofTargets, InputProofTargets, MerkleCapTargets,
    RecExtensionValMmcs, RecExtensionValMmcsArity4, RecValHidingMmcs, RecValMmcs, RecValMmcsArity4,
    Witness,
};
use crate::pcs::{
    restore_fri_query_paths, restore_hiding_fri_query_paths, set_fri_mmcs_private_data,
    set_fri_mmcs_private_data_arity4,
};
use crate::recursion::RecursionInput;
use crate::traits::{RecursiveAir, RecursivePcs};
use crate::verifier::VerificationError;

// The D5 Poseidon AIRs operate on base-field lanes. A quintic verifier circuit
// carries each such lane in the constant coefficient of an extension element.
#[derive(Clone)]
struct LiftPermToQuintic<P, const WIDTH: usize> {
    perm: P,
}

impl<P, const WIDTH: usize> LiftPermToQuintic<P, WIDTH> {
    const fn new(perm: P) -> Self {
        Self { perm }
    }
}

impl<P, const WIDTH: usize> Permutation<[QuinticTrinomialExtensionField<KoalaBear>; WIDTH]>
    for LiftPermToQuintic<P, WIDTH>
where
    P: Permutation<[KoalaBear; WIDTH]>,
{
    fn permute(
        &self,
        input: [QuinticTrinomialExtensionField<KoalaBear>; WIDTH],
    ) -> [QuinticTrinomialExtensionField<KoalaBear>; WIDTH] {
        let bases = core::array::from_fn(|i| input[i].as_basis_coefficients_slice()[0]);
        let output = self.perm.permute(bases);
        core::array::from_fn(|i| {
            QuinticTrinomialExtensionField::new([
                output[i],
                KoalaBear::ZERO,
                KoalaBear::ZERO,
                KoalaBear::ZERO,
                KoalaBear::ZERO,
            ])
        })
    }
}

macro_rules! opening_targets {
    (ordinary, $field:ty, $challenge:ty, $digest:expr, $rec_ext:ident, $rec_mmcs:ty) => {
        FriProofTargets<
            $field,
            $challenge,
            $rec_ext<$field, $challenge, $digest, $rec_mmcs>,
            InputProof,
            Witness<$field>,
        >
    };
    (random, $field:ty, $challenge:ty, $digest:expr, $rec_ext:ident, $rec_mmcs:ty) => {
        HidingFriProofTargets<
            $field,
            $challenge,
            $rec_ext<$field, $challenge, $digest, $rec_mmcs>,
            InputProof,
            Witness<$field>,
        >
    };
}

macro_rules! merge_random_openings {
    (ordinary, $config:ty, $claims:ident, $proof:ident) => {};
    (random, $config:ty, $claims:ident, $proof:ident) => {
        merge_hiding_random_openings::<$config>(&mut $claims, &$proof.0)
            .map_err(|_| "Failed to merge hiding FRI random openings")?;
    };
}

macro_rules! inner_fri_proof {
    (ordinary, $proof:ident) => {
        $proof
    };
    (random, $proof:ident) => {
        &$proof.1
    };
}

// Ordinary binary and quaternary FRI and random-codeword hiding use the
// same descriptor-exact native tree reconstruction. The latter adds random
// openings before replaying the FRI transcript.
macro_rules! impl_plain_fri {
    (
        $module:ident, $config:ty, [$($generics:tt)*], [$($bounds:tt)*],
        $mode:ident, $field:ty, $challenge:ty, $challenger_perm:ty,
        $mmcs_perm:ty, $native_pcs:ty,
        $challenger_width:expr, $challenger_rate:expr,
        $mmcs_width:expr, $mmcs_rate:expr, $digest:expr, $arity:expr,
        $rec_mmcs:ident, $rec_ext:ident, $setter:ident,
        $mmcs_config:expr, $mmcs_perm_expr:expr,
        |$circuit:ident| $prepare:block
    ) => {
        mod $module {
            use super::*;

            type Challenger = DuplexChallenger<
                $field, $challenger_perm, $challenger_width, $challenger_rate,
            >;
            type NativeMmcs = OrdinaryMmcs<
                $field, $mmcs_perm, $mmcs_width, $mmcs_rate, $digest, $arity,
            >;
            type CommitMmcs = ExtensionMmcs<$field, $challenge, NativeMmcs>;
            type RecHash = PaddingFreeSponge<$mmcs_perm, $mmcs_width, $mmcs_rate, $digest>;
            type RecCompress =
                TruncatedPermutation<$mmcs_perm, $arity, $digest, $mmcs_width>;
            type RecMmcs = $rec_mmcs<$field, $digest, RecHash, RecCompress>;
            type InputProof = InputProofTargets<$field, $challenge, RecMmcs>;
            type OpeningProof =
                opening_targets!($mode, $field, $challenge, $digest, $rec_ext, RecMmcs);

            impl $($generics)* FriRecursionConfig for $config
            where
                $($bounds)*
                $native_pcs: RecursivePcs<
                    Self,
                    InputProof,
                    OpeningProof,
                    MerkleCapTargets<$field, $digest>,
                    <$native_pcs as Pcs<$challenge, Challenger>>::Domain,
                    VerifierParams = crate::pcs::fri::FriVerifierParams,
                >,
            {
                type Commitment = MerkleCapTargets<$field, $digest>;
                type InputProof = InputProof;
                type OpeningProof = OpeningProof;
                type RawOpeningProof = <$native_pcs as Pcs<$challenge, Challenger>>::Proof;

                const DIGEST_ELEMS: usize = $digest;

                fn native_fri_validation_params(&self) -> Option<crate::pcs::fri::NativeFriParams> {
                    Some(self.native_fri_params)
                }

                fn with_fri_opening_proof<'a, A, T>(
                    prev: &RecursionInput<'a, Self, A>,
                    f: impl FnOnce(&Self::RawOpeningProof) -> T,
                ) -> T
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
                    $circuit: &mut CircuitBuilder<$challenge>,
                ) -> Result<(), VerificationError> $prepare

                fn pcs_verifier_params(
                    &self,
                ) -> &<$native_pcs as RecursivePcs<
                    Self,
                    InputProof,
                    OpeningProof,
                    MerkleCapTargets<$field, $digest>,
                    <$native_pcs as Pcs<$challenge, Challenger>>::Domain,
                >>::VerifierParams {
                    &self.fri_verifier_params
                }

                fn set_fri_private_data(
                    config: &Self,
                    runner: &mut CircuitRunner<'_, $challenge>,
                    op_ids: &[NonPrimitiveOpId],
                    opening_proof: &Self::RawOpeningProof,
                    transcript: OpeningTranscript<Self>,
                ) -> Result<(), &'static str> {
                    let descriptor = config.descriptor();
                    let make_mmcs = |cap_height: usize| -> NativeMmcs {
                        let perm: $mmcs_perm = $mmcs_perm_expr;
                        MerkleTreeMmcs::new(
                            PaddingFreeSponge::new(perm.clone()),
                            TruncatedPermutation::new(perm),
                            cap_height,
                        )
                    };
                    let input_mmcs = make_mmcs(descriptor.input_cap_height() as usize);
                    let commit_mmcs = make_mmcs(descriptor.commit_cap_height() as usize);
                    let fri_params = FriParameters::<CommitMmcs> {
                        max_log_arity: descriptor.max_log_arity() as usize,
                        log_blowup: descriptor.log_blowup() as usize,
                        log_final_poly_len: descriptor.log_final_poly_len() as usize,
                        num_queries: descriptor.num_queries() as usize,
                        batch_proof_of_work_bits: 0,
                        commit_proof_of_work_bits: descriptor.commit_pow_bits() as usize,
                        query_proof_of_work_bits: descriptor.query_pow_bits() as usize,
                        mmcs: ExtensionMmcs::new(commit_mmcs.clone()),
                    };
                    #[allow(unused_mut)]
                    let OpeningTranscript {
                        mut challenger,
                        mut commitments_with_opening_points,
                    } = transcript;
                    merge_random_openings!(
                        $mode, Self, commitments_with_opening_points, opening_proof
                    );
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
                        inner_fri_proof!($mode, opening_proof),
                        &mut challenger,
                        &claims,
                    )
                    .map_err(|_| "Failed to restore FRI query paths")?;
                    $setter::<$field, $challenge, $digest>(
                        runner, op_ids, &query_paths, $mmcs_config,
                    )
                }
            }
        }
    };
}

macro_rules! binary_fri {
    (
        $module:ident, $config:ty, $field:ty, $challenge:ty, $perm:ty,
        $width:expr, $rate:expr, $digest:expr, $mmcs_config:expr,
        $perm_expr:expr, |$circuit:ident| $prepare:block
    ) => {
        impl_plain_fri!(
            $module, $config, [], [], ordinary, $field, $challenge, $perm, $perm,
            OrdinaryPcs<$field, $challenge, $perm, $width, $rate, $digest, 2>,
            $width, $rate, $width, $rate, $digest, 2,
            RecValMmcs, RecExtensionValMmcs, set_fri_mmcs_private_data,
            $mmcs_config, $perm_expr, |$circuit| $prepare
        );
    };
}

macro_rules! quaternary_fri {
    (
        $module:ident, $config:ty, $field:ty, $challenge:ty,
        $challenger_perm:ty, $mmcs_perm:ty,
        $challenger_width:expr, $challenger_rate:expr,
        $mmcs_width:expr, $mmcs_rate:expr, $digest:expr,
        $mmcs_config:expr, $mmcs_perm_expr:expr,
        |$circuit:ident| $prepare:block
    ) => {
        impl_plain_fri!(
            $module, $config, [], [], ordinary, $field, $challenge,
            $challenger_perm, $mmcs_perm,
            OrdinaryPcs<$field, $challenge, $mmcs_perm, $mmcs_width, $mmcs_rate, $digest, 4>,
            $challenger_width, $challenger_rate, $mmcs_width, $mmcs_rate, $digest, 4,
            RecValMmcsArity4, RecExtensionValMmcsArity4, set_fri_mmcs_private_data_arity4,
            $mmcs_config, $mmcs_perm_expr, |$circuit| $prepare
        );
    };
}

macro_rules! random_codeword_fri {
    (
        $module:ident, $config:ty, $field:ty, $challenge:ty, $perm:ty,
        $width:expr, $rate:expr, $digest:expr, $mmcs_config:expr,
        $perm_expr:expr, |$circuit:ident| $prepare:block
    ) => {
        impl_plain_fri!(
            $module, $config, [<R>], [R: CryptoRng + SeedableRng + Send + Sync + 'static,],
            random, $field, $challenge, $perm, $perm,
            RandomCodewordPcs<$field, $challenge, $perm, R, $width, $rate, $digest>,
            $width, $rate, $width, $rate, $digest, 2,
            RecValMmcs, RecExtensionValMmcs, set_fri_mmcs_private_data,
            $mmcs_config, $perm_expr, |$circuit| $prepare
        );
    };
}

binary_fri!(
    baby_bear_d4_poseidon2_binary, BabyBearD4Poseidon2BinaryConfig,
    BabyBear, BinomialExtensionField<BabyBear, 4>, Poseidon2BabyBear<16>,
    16, 8, 8, Poseidon2Config::BABY_BEAR_D4_W16, default_babybear_poseidon2_16(),
    |circuit| {
        circuit.enable_poseidon2_perm::<p3_poseidon2_circuit_air::BabyBearD4Width16, _>(
            generate_poseidon2_trace::<BinomialExtensionField<BabyBear, 4>, p3_poseidon2_circuit_air::BabyBearD4Width16>,
            default_babybear_poseidon2_16(),
        );
        circuit.enable_recompose::<BabyBear>(
            generate_recompose_trace::<BabyBear, BinomialExtensionField<BabyBear, 4>>,
        );
        Ok(())
    }
);

binary_fri!(
    baby_bear_d4_poseidon1_binary, BabyBearD4Poseidon1BinaryConfig,
    BabyBear, BinomialExtensionField<BabyBear, 4>, Poseidon1BabyBear<16>,
    16, 8, 8, p3_circuit::ops::Poseidon1Config::BABY_BEAR_D4_W16,
    default_babybear_poseidon1_16(),
    |circuit| {
        circuit.enable_poseidon1_perm::<p3_circuit::ops::poseidon1_perm::BabyBearD4Width16, _>(
            generate_poseidon1_trace::<BinomialExtensionField<BabyBear, 4>, p3_circuit::ops::poseidon1_perm::BabyBearD4Width16>,
            default_babybear_poseidon1_16(),
        );
        circuit.enable_recompose::<BabyBear>(
            generate_recompose_trace::<BabyBear, BinomialExtensionField<BabyBear, 4>>,
        );
        Ok(())
    }
);

binary_fri!(
    koala_bear_d4_poseidon2_binary, KoalaBearD4Poseidon2BinaryConfig,
    KoalaBear, BinomialExtensionField<KoalaBear, 4>, Poseidon2KoalaBear<16>,
    16, 8, 8, Poseidon2Config::KOALA_BEAR_D4_W16, default_koalabear_poseidon2_16(),
    |circuit| {
        circuit.enable_poseidon2_perm::<p3_poseidon2_circuit_air::KoalaBearD4Width16, _>(
            generate_poseidon2_trace::<BinomialExtensionField<KoalaBear, 4>, p3_poseidon2_circuit_air::KoalaBearD4Width16>,
            default_koalabear_poseidon2_16(),
        );
        circuit.enable_recompose::<KoalaBear>(
            generate_recompose_trace::<KoalaBear, BinomialExtensionField<KoalaBear, 4>>,
        );
        Ok(())
    }
);

binary_fri!(
    koala_bear_d4_poseidon1_binary, KoalaBearD4Poseidon1BinaryConfig,
    KoalaBear, BinomialExtensionField<KoalaBear, 4>, Poseidon1KoalaBear<16>,
    16, 8, 8, p3_circuit::ops::Poseidon1Config::KOALA_BEAR_D4_W16,
    default_koalabear_poseidon1_16(),
    |circuit| {
        circuit.enable_poseidon1_perm::<p3_circuit::ops::poseidon1_perm::KoalaBearD4Width16, _>(
            generate_poseidon1_trace::<BinomialExtensionField<KoalaBear, 4>, p3_circuit::ops::poseidon1_perm::KoalaBearD4Width16>,
            default_koalabear_poseidon1_16(),
        );
        circuit.enable_recompose::<KoalaBear>(
            generate_recompose_trace::<KoalaBear, BinomialExtensionField<KoalaBear, 4>>,
        );
        Ok(())
    }
);

binary_fri!(
    goldilocks_d2_poseidon2_binary, GoldilocksD2Poseidon2BinaryConfig,
    Goldilocks, BinomialExtensionField<Goldilocks, 2>, Poseidon2Goldilocks<8>,
    8, 4, 4, Poseidon2Config::GOLDILOCKS_D2_W8, fixed_goldilocks_poseidon2_8(),
    |circuit| {
        circuit.enable_poseidon2_perm_width_8::<p3_circuit::ops::GoldilocksD2Width8, _>(
            generate_poseidon2_trace::<BinomialExtensionField<Goldilocks, 2>, p3_circuit::ops::GoldilocksD2Width8>,
            fixed_goldilocks_poseidon2_8(),
        );
        circuit.enable_recompose::<Goldilocks>(
            generate_recompose_trace::<Goldilocks, BinomialExtensionField<Goldilocks, 2>>,
        );
        Ok(())
    }
);

binary_fri!(
    goldilocks_d2_poseidon1_binary, GoldilocksD2Poseidon1BinaryConfig,
    Goldilocks, BinomialExtensionField<Goldilocks, 2>,
    p3_goldilocks::poseidon1::Poseidon1Goldilocks<8>,
    8, 4, 4, p3_circuit::ops::Poseidon1Config::GOLDILOCKS_D2_W8,
    p3_goldilocks::poseidon1::default_goldilocks_poseidon1_8(),
    |circuit| {
        circuit.enable_poseidon1_perm_width_8::<p3_circuit::ops::poseidon1_perm::GoldilocksD2Width8, _>(
            generate_poseidon1_trace::<BinomialExtensionField<Goldilocks, 2>, p3_circuit::ops::poseidon1_perm::GoldilocksD2Width8>,
            p3_goldilocks::poseidon1::default_goldilocks_poseidon1_8(),
        );
        circuit.enable_recompose::<Goldilocks>(
            generate_recompose_trace::<Goldilocks, BinomialExtensionField<Goldilocks, 2>>,
        );
        Ok(())
    }
);

binary_fri!(
    koala_bear_d5_poseidon2_binary,
    KoalaBearD5Poseidon2BinaryConfig,
    KoalaBear,
    QuinticTrinomialExtensionField<KoalaBear>,
    Poseidon2KoalaBear<16>,
    16,
    8,
    8,
    Poseidon2Config::KOALA_BEAR_D1_W16,
    default_koalabear_poseidon2_16(),
    |circuit| {
        circuit.enable_poseidon2_perm_base::<p3_poseidon2_circuit_air::KoalaBearD1Width16, _>(
            generate_poseidon2_trace::<
                QuinticTrinomialExtensionField<KoalaBear>,
                p3_poseidon2_circuit_air::KoalaBearD1Width16,
            >,
            LiftPermToQuintic::new(default_koalabear_poseidon2_16()),
        );
        circuit.enable_recompose::<KoalaBear>(
            generate_recompose_trace::<KoalaBear, QuinticTrinomialExtensionField<KoalaBear>>,
        );
        circuit.set_recompose_coeff_ctl_for_decompose_links(true);
        Ok(())
    }
);

binary_fri!(
    koala_bear_d5_poseidon1_binary,
    KoalaBearD5Poseidon1BinaryConfig,
    KoalaBear,
    QuinticTrinomialExtensionField<KoalaBear>,
    Poseidon1KoalaBear<16>,
    16,
    8,
    8,
    p3_circuit::ops::Poseidon1Config::KOALA_BEAR_D1_W16,
    default_koalabear_poseidon1_16(),
    |circuit| {
        circuit
            .enable_poseidon1_perm_base::<p3_circuit::ops::poseidon1_perm::KoalaBearD1Width16, _>(
                generate_poseidon1_trace::<
                    QuinticTrinomialExtensionField<KoalaBear>,
                    p3_circuit::ops::poseidon1_perm::KoalaBearD1Width16,
                >,
                LiftPermToQuintic::new(default_koalabear_poseidon1_16()),
            );
        circuit.enable_recompose::<KoalaBear>(
            generate_recompose_trace::<KoalaBear, QuinticTrinomialExtensionField<KoalaBear>>,
        );
        circuit.set_recompose_coeff_ctl_for_decompose_links(true);
        Ok(())
    }
);

quaternary_fri!(
    baby_bear_d4_poseidon2_quaternary, BabyBearD4Poseidon2QuaternaryConfig,
    BabyBear, BinomialExtensionField<BabyBear, 4>,
    Poseidon2BabyBear<16>, Poseidon2BabyBear<32>,
    16, 8, 32, 24, 8, Poseidon2Config::BABY_BEAR_D4_W32,
    default_babybear_poseidon2_32(),
    |circuit| {
        circuit.enable_poseidon2_perm::<p3_poseidon2_circuit_air::BabyBearD4Width16, _>(
            generate_poseidon2_trace::<BinomialExtensionField<BabyBear, 4>, p3_poseidon2_circuit_air::BabyBearD4Width16>,
            default_babybear_poseidon2_16(),
        );
        circuit.enable_poseidon2_perm_width_32::<p3_poseidon2_circuit_air::BabyBearD4Width32, _>(
            generate_poseidon2_trace::<BinomialExtensionField<BabyBear, 4>, p3_poseidon2_circuit_air::BabyBearD4Width32>,
            default_babybear_poseidon2_32(),
        );
        circuit.enable_recompose::<BabyBear>(
            generate_recompose_trace::<BabyBear, BinomialExtensionField<BabyBear, 4>>,
        );
        Ok(())
    }
);

quaternary_fri!(
    koala_bear_d4_poseidon2_quaternary, KoalaBearD4Poseidon2QuaternaryConfig,
    KoalaBear, BinomialExtensionField<KoalaBear, 4>,
    Poseidon2KoalaBear<16>, Poseidon2KoalaBear<32>,
    16, 8, 32, 24, 8, Poseidon2Config::KOALA_BEAR_D4_W32,
    default_koalabear_poseidon2_32(),
    |circuit| {
        circuit.enable_poseidon2_perm::<p3_poseidon2_circuit_air::KoalaBearD4Width16, _>(
            generate_poseidon2_trace::<BinomialExtensionField<KoalaBear, 4>, p3_poseidon2_circuit_air::KoalaBearD4Width16>,
            default_koalabear_poseidon2_16(),
        );
        circuit.enable_poseidon2_perm_width_32::<p3_poseidon2_circuit_air::KoalaBearD4Width32, _>(
            generate_poseidon2_trace::<BinomialExtensionField<KoalaBear, 4>, p3_poseidon2_circuit_air::KoalaBearD4Width32>,
            default_koalabear_poseidon2_32(),
        );
        circuit.enable_recompose::<KoalaBear>(
            generate_recompose_trace::<KoalaBear, BinomialExtensionField<KoalaBear, 4>>,
        );
        Ok(())
    }
);

quaternary_fri!(
    goldilocks_d2_poseidon2_quaternary, GoldilocksD2Poseidon2QuaternaryConfig,
    Goldilocks, BinomialExtensionField<Goldilocks, 2>,
    Poseidon2Goldilocks<8>, Poseidon2Goldilocks<16>,
    8, 4, 16, 12, 4, Poseidon2Config::GOLDILOCKS_D2_W16,
    fixed_goldilocks_poseidon2_16(),
    |circuit| {
        circuit.enable_poseidon2_perm_width_8::<p3_circuit::ops::GoldilocksD2Width8, _>(
            generate_poseidon2_trace::<BinomialExtensionField<Goldilocks, 2>, p3_circuit::ops::GoldilocksD2Width8>,
            fixed_goldilocks_poseidon2_8(),
        );
        circuit.enable_poseidon2_perm::<p3_poseidon2_circuit_air::GoldilocksD2Width16, _>(
            generate_poseidon2_trace::<BinomialExtensionField<Goldilocks, 2>, p3_poseidon2_circuit_air::GoldilocksD2Width16>,
            fixed_goldilocks_poseidon2_16(),
        );
        circuit.enable_recompose::<Goldilocks>(
            generate_recompose_trace::<Goldilocks, BinomialExtensionField<Goldilocks, 2>>,
        );
        Ok(())
    }
);

quaternary_fri!(
    koala_bear_d5_poseidon2_quaternary,
    KoalaBearD5Poseidon2QuaternaryConfig,
    KoalaBear,
    QuinticTrinomialExtensionField<KoalaBear>,
    Poseidon2KoalaBear<16>,
    Poseidon2KoalaBear<32>,
    16,
    8,
    32,
    24,
    8,
    Poseidon2Config::KOALA_BEAR_D1_W32,
    default_koalabear_poseidon2_32(),
    |circuit| {
        circuit.enable_poseidon2_perm_base::<p3_poseidon2_circuit_air::KoalaBearD1Width16, _>(
            generate_poseidon2_trace::<
                QuinticTrinomialExtensionField<KoalaBear>,
                p3_poseidon2_circuit_air::KoalaBearD1Width16,
            >,
            LiftPermToQuintic::new(default_koalabear_poseidon2_16()),
        );
        circuit
            .enable_poseidon2_perm_base_width_32::<p3_poseidon2_circuit_air::KoalaBearD1Width32, _>(
                generate_poseidon2_trace::<
                    QuinticTrinomialExtensionField<KoalaBear>,
                    p3_poseidon2_circuit_air::KoalaBearD1Width32,
                >,
                LiftPermToQuintic::new(default_koalabear_poseidon2_32()),
            );
        circuit.enable_recompose::<KoalaBear>(
            generate_recompose_trace::<KoalaBear, QuinticTrinomialExtensionField<KoalaBear>>,
        );
        circuit.set_recompose_coeff_ctl_for_decompose_links(true);
        Ok(())
    }
);

random_codeword_fri!(
    baby_bear_d4_poseidon2_random, BabyBearD4Poseidon2RandomCodewordConfig<R>,
    BabyBear, BinomialExtensionField<BabyBear, 4>, Poseidon2BabyBear<16>,
    16, 8, 8, Poseidon2Config::BABY_BEAR_D4_W16, default_babybear_poseidon2_16(),
    |circuit| {
        circuit.enable_poseidon2_perm::<p3_poseidon2_circuit_air::BabyBearD4Width16, _>(
            generate_poseidon2_trace::<BinomialExtensionField<BabyBear, 4>, p3_poseidon2_circuit_air::BabyBearD4Width16>,
            default_babybear_poseidon2_16(),
        );
        circuit.enable_recompose::<BabyBear>(
            generate_recompose_trace::<BabyBear, BinomialExtensionField<BabyBear, 4>>,
        );
        Ok(())
    }
);

random_codeword_fri!(
    baby_bear_d4_poseidon1_random, BabyBearD4Poseidon1RandomCodewordConfig<R>,
    BabyBear, BinomialExtensionField<BabyBear, 4>, Poseidon1BabyBear<16>,
    16, 8, 8, p3_circuit::ops::Poseidon1Config::BABY_BEAR_D4_W16,
    default_babybear_poseidon1_16(),
    |circuit| {
        circuit.enable_poseidon1_perm::<p3_circuit::ops::poseidon1_perm::BabyBearD4Width16, _>(
            generate_poseidon1_trace::<BinomialExtensionField<BabyBear, 4>, p3_circuit::ops::poseidon1_perm::BabyBearD4Width16>,
            default_babybear_poseidon1_16(),
        );
        circuit.enable_recompose::<BabyBear>(
            generate_recompose_trace::<BabyBear, BinomialExtensionField<BabyBear, 4>>,
        );
        Ok(())
    }
);

random_codeword_fri!(
    koala_bear_d4_poseidon2_random, KoalaBearD4Poseidon2RandomCodewordConfig<R>,
    KoalaBear, BinomialExtensionField<KoalaBear, 4>, Poseidon2KoalaBear<16>,
    16, 8, 8, Poseidon2Config::KOALA_BEAR_D4_W16, default_koalabear_poseidon2_16(),
    |circuit| {
        circuit.enable_poseidon2_perm::<p3_poseidon2_circuit_air::KoalaBearD4Width16, _>(
            generate_poseidon2_trace::<BinomialExtensionField<KoalaBear, 4>, p3_poseidon2_circuit_air::KoalaBearD4Width16>,
            default_koalabear_poseidon2_16(),
        );
        circuit.enable_recompose::<KoalaBear>(
            generate_recompose_trace::<KoalaBear, BinomialExtensionField<KoalaBear, 4>>,
        );
        Ok(())
    }
);

random_codeword_fri!(
    koala_bear_d4_poseidon1_random, KoalaBearD4Poseidon1RandomCodewordConfig<R>,
    KoalaBear, BinomialExtensionField<KoalaBear, 4>, Poseidon1KoalaBear<16>,
    16, 8, 8, p3_circuit::ops::Poseidon1Config::KOALA_BEAR_D4_W16,
    default_koalabear_poseidon1_16(),
    |circuit| {
        circuit.enable_poseidon1_perm::<p3_circuit::ops::poseidon1_perm::KoalaBearD4Width16, _>(
            generate_poseidon1_trace::<BinomialExtensionField<KoalaBear, 4>, p3_circuit::ops::poseidon1_perm::KoalaBearD4Width16>,
            default_koalabear_poseidon1_16(),
        );
        circuit.enable_recompose::<KoalaBear>(
            generate_recompose_trace::<KoalaBear, BinomialExtensionField<KoalaBear, 4>>,
        );
        Ok(())
    }
);

random_codeword_fri!(
    goldilocks_d2_poseidon2_random, GoldilocksD2Poseidon2RandomCodewordConfig<R>,
    Goldilocks, BinomialExtensionField<Goldilocks, 2>, Poseidon2Goldilocks<8>,
    8, 4, 4, Poseidon2Config::GOLDILOCKS_D2_W8, fixed_goldilocks_poseidon2_8(),
    |circuit| {
        circuit.enable_poseidon2_perm_width_8::<p3_circuit::ops::GoldilocksD2Width8, _>(
            generate_poseidon2_trace::<BinomialExtensionField<Goldilocks, 2>, p3_circuit::ops::GoldilocksD2Width8>,
            fixed_goldilocks_poseidon2_8(),
        );
        circuit.enable_recompose::<Goldilocks>(
            generate_recompose_trace::<Goldilocks, BinomialExtensionField<Goldilocks, 2>>,
        );
        Ok(())
    }
);

random_codeword_fri!(
    goldilocks_d2_poseidon1_random, GoldilocksD2Poseidon1RandomCodewordConfig<R>,
    Goldilocks, BinomialExtensionField<Goldilocks, 2>,
    p3_goldilocks::poseidon1::Poseidon1Goldilocks<8>,
    8, 4, 4, p3_circuit::ops::Poseidon1Config::GOLDILOCKS_D2_W8,
    p3_goldilocks::poseidon1::default_goldilocks_poseidon1_8(),
    |circuit| {
        circuit.enable_poseidon1_perm_width_8::<p3_circuit::ops::poseidon1_perm::GoldilocksD2Width8, _>(
            generate_poseidon1_trace::<BinomialExtensionField<Goldilocks, 2>, p3_circuit::ops::poseidon1_perm::GoldilocksD2Width8>,
            p3_goldilocks::poseidon1::default_goldilocks_poseidon1_8(),
        );
        circuit.enable_recompose::<Goldilocks>(
            generate_recompose_trace::<Goldilocks, BinomialExtensionField<Goldilocks, 2>>,
        );
        Ok(())
    }
);

// Salted MMCS openings carry private leaf salts as well as pruned paths.
// Reconstruct the plain trees separately so the restoration can hash each
// opened row with its supplied salt at the descriptor's respective cap height.
mod koala_bear_d4_poseidon2_salted {
    use super::*;

    type F = KoalaBear;
    type Challenge = BinomialExtensionField<F, 4>;
    type Perm = Poseidon2KoalaBear<16>;
    type Challenger = DuplexChallenger<F, Perm, 16, 8>;
    type NativeMmcs<R> = SaltedMmcs<F, Perm, R, 16, 8, 8>;
    type PlainMmcs = OrdinaryMmcs<F, Perm, 16, 8, 8, 2>;
    type NativePcs<R> = SaltedPcs<F, Challenge, Perm, R, 16, 8, 8>;
    type CommitMmcs<R> = ExtensionMmcs<F, Challenge, NativeMmcs<R>>;
    type RecHash = PaddingFreeSponge<Perm, 16, 8, 8>;
    type RecCompress = TruncatedPermutation<Perm, 2, 8, 16>;
    type RecMmcs<R> = RecValHidingMmcs<F, 8, 4, RecHash, RecCompress, R>;
    type InputProof<R> = InputProofTargets<F, Challenge, RecMmcs<R>>;
    type OpeningProof<R> = HidingFriProofTargets<
        F,
        Challenge,
        RecExtensionValMmcs<F, Challenge, 8, RecMmcs<R>>,
        InputProof<R>,
        Witness<F>,
    >;

    impl<R> FriRecursionConfig for KoalaBearD4Poseidon2SaltedConfig<R>
    where
        R: CryptoRng + SeedableRng + Send + Sync + 'static,
        NativePcs<R>: RecursivePcs<
                Self,
                InputProof<R>,
                OpeningProof<R>,
                MerkleCapTargets<F, 8>,
                <NativePcs<R> as Pcs<Challenge, Challenger>>::Domain,
                VerifierParams = crate::pcs::fri::FriVerifierParams,
            >,
    {
        type Commitment = MerkleCapTargets<F, 8>;
        type InputProof = InputProof<R>;
        type OpeningProof = OpeningProof<R>;
        type RawOpeningProof = <NativePcs<R> as Pcs<Challenge, Challenger>>::Proof;

        const DIGEST_ELEMS: usize = 8;

        fn native_fri_validation_params(&self) -> Option<crate::pcs::fri::NativeFriParams> {
            Some(self.native_fri_params)
        }

        fn with_fri_opening_proof<'a, A, T>(
            prev: &RecursionInput<'a, Self, A>,
            f: impl FnOnce(&Self::RawOpeningProof) -> T,
        ) -> T
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
            circuit.enable_poseidon2_perm::<p3_poseidon2_circuit_air::KoalaBearD4Width16, _>(
                generate_poseidon2_trace::<Challenge, p3_poseidon2_circuit_air::KoalaBearD4Width16>,
                default_koalabear_poseidon2_16(),
            );
            circuit.enable_recompose::<F>(generate_recompose_trace::<F, Challenge>);
            circuit.set_recompose_coeff_ctl_for_decompose_links(true);
            Ok(())
        }

        fn pcs_verifier_params(
            &self,
        ) -> &<NativePcs<R> as RecursivePcs<
            Self,
            InputProof<R>,
            OpeningProof<R>,
            MerkleCapTargets<F, 8>,
            <NativePcs<R> as Pcs<Challenge, Challenger>>::Domain,
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
            let descriptor = config.descriptor();
            let make_plain = |cap_height: usize| -> PlainMmcs {
                let perm = default_koalabear_poseidon2_16();
                MerkleTreeMmcs::new(
                    PaddingFreeSponge::new(perm.clone()),
                    TruncatedPermutation::new(perm),
                    cap_height,
                )
            };
            let make_hiding = |cap_height: usize| -> NativeMmcs<R> {
                let perm = default_koalabear_poseidon2_16();
                MerkleTreeHidingMmcs::new(
                    PaddingFreeSponge::new(perm.clone()),
                    TruncatedPermutation::new(perm),
                    cap_height,
                    // Verification only: this instance never commits or draws randomness.
                    R::seed_from_u64(0),
                )
            };
            let input_hiding_mmcs = make_hiding(descriptor.input_cap_height() as usize);
            let commit_hiding_mmcs = make_hiding(descriptor.commit_cap_height() as usize);
            let input_tree = make_plain(descriptor.input_cap_height() as usize);
            let commit_tree = make_plain(descriptor.commit_cap_height() as usize);
            let fri_params = FriParameters::<CommitMmcs<R>> {
                max_log_arity: descriptor.max_log_arity() as usize,
                log_blowup: descriptor.log_blowup() as usize,
                log_final_poly_len: descriptor.log_final_poly_len() as usize,
                num_queries: descriptor.num_queries() as usize,
                batch_proof_of_work_bits: 0,
                commit_proof_of_work_bits: descriptor.commit_pow_bits() as usize,
                query_proof_of_work_bits: descriptor.query_pow_bits() as usize,
                mmcs: ExtensionMmcs::new(commit_hiding_mmcs),
            };
            let OpeningTranscript {
                mut challenger,
                mut commitments_with_opening_points,
            } = transcript;
            merge_hiding_random_openings::<Self>(
                &mut commitments_with_opening_points,
                &opening_proof.0,
            )
            .map_err(|_| "Failed to merge hiding FRI random openings")?;
            observe_opened_values::<Self>(
                &mut challenger,
                &commitments_with_opening_points,
                fri_params.batch_proof_of_work_bits,
            );
            let claims: Vec<_> = commitments_with_opening_points
                .into_iter()
                .map(Into::into)
                .collect();
            let query_paths = restore_hiding_fri_query_paths(
                &fri_params,
                &input_hiding_mmcs,
                &input_tree,
                &commit_tree,
                &opening_proof.1,
                &mut challenger,
                &claims,
            )
            .map_err(|_| "Failed to restore salted FRI query paths")?;
            set_fri_mmcs_private_data::<F, Challenge, 8>(
                runner,
                op_ids,
                &query_paths,
                Poseidon2Config::KOALA_BEAR_D4_W16,
            )
        }
    }
}
