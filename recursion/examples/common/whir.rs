//! PCS selection and WHIR configuration shared by the recursive examples.

use p3_recursion::pcs::whir::uni::WhirRatePolicy;
use p3_whir::parameters::{FoldingFactor, SecurityAssumption};

use super::{ClapArgs, FriParams, TablePacking, ValueEnum};

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum, Default)]
pub enum PcsOption {
    #[default]
    Fri,
    Whir,
}

#[derive(Debug, Clone, Copy, ClapArgs)]
pub struct PcsOptions {
    /// Polynomial commitment scheme for base proofs and recursive layers.
    #[arg(long, value_enum, ignore_case = true, default_value_t = PcsOption::Fri)]
    pub pcs: PcsOption,

    /// Number of variables folded per WHIR round (with --pcs whir).
    #[arg(long, default_value_t = 4)]
    pub whir_folding_factor: usize,

    /// Variables folded in WHIR's initial round (defaults to --whir-folding-factor).
    #[arg(long)]
    pub whir_first_folding_factor: Option<usize>,

    /// Bits by which to shrink the first intermediate WHIR domain.
    #[arg(
        long,
        help = "First intermediate WHIR domain reduction in bits [default: 2, clamped for small folds; 1 uses native rates]"
    )]
    pub whir_first_round_domain_reduction: Option<usize>,
}

impl PcsOptions {
    pub fn first_folding_factor(&self) -> usize {
        self.whir_first_folding_factor
            .unwrap_or(self.whir_folding_factor)
    }

    pub const fn folding_factor(&self) -> FoldingFactor {
        match self.whir_first_folding_factor {
            Some(first) => FoldingFactor::ConstantFromSecondRound(first, self.whir_folding_factor),
            None => FoldingFactor::Constant(self.whir_folding_factor),
        }
    }

    pub fn rate_policy(&self, starting_log_inv_rate: usize) -> WhirRatePolicy {
        if self.pcs == PcsOption::Fri {
            return WhirRatePolicy::Native;
        }
        let bits = self.whir_first_round_domain_reduction.unwrap_or_else(|| {
            // Keep a positive first intermediate rate for smaller folding factors.
            let max = starting_log_inv_rate
                .checked_add(self.first_folding_factor())
                .and_then(|rate| rate.checked_sub(1))
                .expect("valid WHIR first-round geometry");
            2.min(max)
        });
        if bits == 1 {
            WhirRatePolicy::Native
        } else {
            WhirRatePolicy::FirstRoundReduction(bits)
        }
    }

    pub fn horner_packed_steps(&self, requested: Option<usize>) -> usize {
        requested.unwrap_or(match self.pcs {
            PcsOption::Fri => 4,
            // WHIR uses ordinary multiply-adds, so packed Horner columns would be unused.
            PcsOption::Whir => 1,
        })
    }

    pub fn security_level(&self, requested: Option<usize>) -> usize {
        // The reserve offsets query rounding under the faster rate schedule.
        // This is a per-error-term target; the PCS reports its composed bound separately.
        requested.unwrap_or(match self.pcs {
            PcsOption::Fri => 124,
            PcsOption::Whir => 66,
        })
    }

    pub const fn query_pow_bits(&self, requested: Option<usize>) -> usize {
        match requested {
            Some(bits) => bits,
            None => match self.pcs {
                PcsOption::Fri => 15,
                // Keep the extra queries below the recursive table padding boundary.
                PcsOption::Whir => 18,
            },
        }
    }

    pub fn assert_supported(&self, zk: bool, arity4: bool, disable_recompose_npo: bool) {
        if self.pcs == PcsOption::Whir {
            assert!(!zk, "--zk requires --pcs fri");
            assert!(!arity4, "--arity4 requires --pcs fri");
            assert!(
                !disable_recompose_npo,
                "--disable-recompose-npo requires --pcs fri"
            );
            assert!(
                self.whir_folding_factor > 0 && self.whir_folding_factor < usize::BITS as usize,
                "--whir-folding-factor must be positive and smaller than the machine word size"
            );
            assert!(
                self.first_folding_factor() > 0
                    && self.first_folding_factor() < usize::BITS as usize,
                "--whir-first-folding-factor must be positive and smaller than the machine word size"
            );
        }
    }

    pub fn min_trace_height(&self, fp: &FriParams, security_level: usize) -> usize {
        match self.pcs {
            PcsOption::Fri => 1 << (fp.log_final_poly_len + fp.log_blowup + 1),
            PcsOption::Whir => {
                assert!(fp.log_blowup > 0, "--log-blowup must be positive for WHIR");
                assert!(
                    fp.query_pow_bits < security_level,
                    "WHIR requires --query-pow-bits < --security-level"
                );
                // Even a one-column table must have enough folded leaves for unique queries.
                // Later rounds increase the inverse rate and therefore need fewer queries.
                let queries = SecurityAssumption::CapacityBound
                    .queries(security_level - fp.query_pow_bits, fp.log_blowup);
                (1usize << self.first_folding_factor())
                    .checked_mul(queries.next_power_of_two())
                    .expect("WHIR minimum trace height is too large")
            }
        }
    }
}

pub trait ExampleTablePacking {
    fn with_pcs_params(self, options: &PcsOptions, fp: &FriParams, security_level: usize) -> Self;
    fn with_whir_horner_packing(self, options: &PcsOptions, source: &TablePacking) -> Self;
}

impl ExampleTablePacking for TablePacking {
    fn with_pcs_params(self, options: &PcsOptions, fp: &FriParams, security_level: usize) -> Self {
        self.with_min_trace_height(options.min_trace_height(fp, security_level))
    }

    fn with_whir_horner_packing(self, options: &PcsOptions, source: &TablePacking) -> Self {
        match options.pcs {
            PcsOption::Fri => self,
            PcsOption::Whir => self.with_horner_pack_k(source.horner_packed_steps()),
        }
    }
}

/// Add a WHIR config to a field module that already defines its native field, extension,
/// permutation, MMCS and challenger via `define_field_module_types!`.
#[macro_export]
macro_rules! define_whir_module_types {
    (
        $default_perm:path, $perm_config:expr, $circuit_config:ty,
        $enable_fn:ident, $default_perm_circuit:expr, $gen_trace:ident
    ) => {
        type MyWhirPcs = p3_recursion::pcs::whir::uni::WhirUniPcs<
            Challenge,
            F,
            p3_dft::Radix2DFTSmallBatch<F>,
            MyMmcs,
            Challenger,
            p3_sumcheck::layout::PrefixProver<F, Challenge>,
        >;
        type MyWhirConfig = StarkConfig<MyWhirPcs, Challenge, Challenger>;

        #[derive(Clone)]
        struct ConfigWithWhirParams {
            config: Arc<MyWhirConfig>,
            verifier_params: p3_recursion::pcs::whir::uni::WhirUniVerifierParams<F>,
            mmcs: MyMmcs,
            disable_recompose_npo: bool,
        }

        impl StarkGenericConfig for ConfigWithWhirParams {
            type Pcs = MyWhirPcs;
            type Challenge = Challenge;
            type Challenger = Challenger;

            fn pcs(&self) -> &Self::Pcs {
                self.config.pcs()
            }

            fn initialise_challenger(&self) -> Self::Challenger {
                self.config.initialise_challenger()
            }
        }

        impl p3_recursion::backend::whir::WhirRecursionConfig for ConfigWithWhirParams {
            type Commitment = MerkleCapTargets<F, DIGEST_ELEMS>;
            type InputProof = ();
            type OpeningProof = p3_recursion::pcs::whir::uni::WhirUniProofTargets<
                F,
                Challenge,
                MyMmcs,
                DIGEST_ELEMS,
            >;
            type RawOpeningProof = p3_recursion::pcs::whir::uni::WhirUniProof<F, Challenge, MyMmcs>;

            fn with_whir_opening_proof<'a, A, R>(
                prev: &RecursionInput<'a, Self, A>,
                f: impl FnOnce(&Self::RawOpeningProof) -> R,
            ) -> R
            where
                A: RecursiveAir<F, Challenge, LogUpGadget>,
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
                circuit.$enable_fn::<$circuit_config, _>(
                    $gen_trace::<Challenge, $circuit_config>,
                    ($default_perm_circuit)(),
                );
                if self.disable_recompose_npo {
                    circuit.noop_enable_recompose::<F>(generate_recompose_trace::<F, Challenge>);
                } else {
                    circuit.enable_recompose::<F>(generate_recompose_trace::<F, Challenge>);
                }
                if ($perm_config).d() == 1
                    && <Challenge as ::p3_field::BasedVectorSpace<F>>::DIMENSION > 1
                {
                    circuit.set_recompose_coeff_ctl_for_decompose_links(true);
                }
                Ok(())
            }

            fn pcs_verifier_params(
                &self,
            ) -> &p3_recursion::pcs::whir::uni::WhirUniVerifierParams<F> {
                &self.verifier_params
            }

            fn set_whir_private_data(
                config: &Self,
                runner: &mut CircuitRunner<'_, Challenge>,
                op_ids: &[NonPrimitiveOpId],
                opening_proof: &Self::RawOpeningProof,
                transcript: OpeningTranscript<Self>,
            ) -> Result<(), &'static str> {
                use p3_recursion::pcs::whir::uni::{
                    restore_whir_recursion_paths_with_rate_policy, whir_round_paths_op_count,
                };
                let params = &config.verifier_params;
                let paths = restore_whir_recursion_paths_with_rate_policy::<
                    Self,
                    _,
                    _,
                    _,
                    _,
                    _,
                    DIGEST_ELEMS,
                >(
                    &config.mmcs,
                    transcript,
                    &config.initialise_challenger(),
                    opening_proof,
                    params.protocol_params(),
                    params.folding(),
                    params.variable_order(),
                    params.rate_policy(),
                )
                .map_err(|_| "Failed to restore WHIR Merkle paths")?;
                let mut offset = 0;
                for round_paths in &paths {
                    let count = whir_round_paths_op_count(round_paths);
                    let ids = op_ids
                        .get(offset..offset + count)
                        .ok_or("Not enough op_ids for restored WHIR Merkle paths")?;
                    p3_recursion::pcs::set_whir_mmcs_private_data::<F, Challenge, DIGEST_ELEMS>(
                        runner,
                        ids,
                        &round_paths.rounds,
                        &round_paths.final_paths,
                        $perm_config,
                    )?;
                    offset += count;
                }
                if offset != op_ids.len() {
                    return Err("WHIR op-id accounting mismatch");
                }
                Ok(())
            }
        }

        fn config_with_whir_params(
            fp: &FriParams,
            security_level: usize,
            disable_recompose_npo: bool,
            options: &PcsOptions,
        ) -> ConfigWithWhirParams {
            use p3_sumcheck::layout::Layout;
            use p3_whir::parameters::{ProtocolParameters, SecurityAssumption};

            let perm = $default_perm();
            let mmcs = MyMmcs::new(
                MyHash::new(perm.clone()),
                MyCompress::new(perm.clone()),
                fp.cap_height,
            );
            let challenger = Challenger::new(perm);
            let protocol = ProtocolParameters {
                security_level,
                pow_bits: fp.query_pow_bits,
                starting_log_inv_rate: fp.log_blowup,
                round_log_inv_rates: vec![],
                folding_factor: options.folding_factor(),
                soundness_type: SecurityAssumption::CapacityBound,
            };
            let pcs = MyWhirPcs::new(
                protocol.clone(),
                p3_dft::Radix2DFTSmallBatch::default(),
                mmcs.clone(),
                challenger.clone(),
                <F as p3_field::TwoAdicField>::TWO_ADICITY,
            )
            .with_rate_policy(options.rate_policy(fp.log_blowup))
            .expect("valid WHIR example rate policy");
            let verifier_params = p3_recursion::pcs::whir::uni::WhirUniVerifierParams::new(
                protocol,
                p3_sumcheck::layout::PrefixProver::<F, Challenge>::variable_order(),
                $perm_config,
            )
            .expect("valid WHIR example configuration")
            .with_rate_policy(options.rate_policy(fp.log_blowup))
            .expect("valid WHIR example rate policy");
            ConfigWithWhirParams {
                config: Arc::new(MyWhirConfig::new(pcs, challenger)),
                verifier_params,
                mmcs,
                disable_recompose_npo,
            }
        }
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rate_defaults_shrink_extension_codewords_and_keep_small_folds_valid() {
        let mut options = PcsOptions {
            pcs: PcsOption::Whir,
            whir_folding_factor: 4,
            whir_first_folding_factor: None,
            whir_first_round_domain_reduction: None,
        };
        assert_eq!(
            options.rate_policy(2),
            WhirRatePolicy::FirstRoundReduction(2)
        );
        assert_eq!(options.security_level(None), 66);
        assert_eq!(options.security_level(Some(64)), 64);
        assert_eq!(options.query_pow_bits(None), 18);
        assert_eq!(options.query_pow_bits(Some(15)), 15);
        options.whir_folding_factor = 2;
        assert_eq!(
            options.rate_policy(1),
            WhirRatePolicy::FirstRoundReduction(2)
        );
        options.whir_folding_factor = 1;
        assert_eq!(options.rate_policy(1), WhirRatePolicy::Native);
        options.whir_first_round_domain_reduction = Some(1);
        assert_eq!(options.rate_policy(2), WhirRatePolicy::Native);
    }

    #[test]
    fn horner_packing_defaults_and_overrides() {
        for (pcs, default) in [(PcsOption::Fri, 4), (PcsOption::Whir, 1)] {
            let options = PcsOptions {
                pcs,
                whir_folding_factor: 4,
                whir_first_folding_factor: None,
                whir_first_round_domain_reduction: None,
            };
            assert_eq!(options.horner_packed_steps(None), default);
            assert_eq!(
                options.query_pow_bits(None),
                if pcs == PcsOption::Fri { 15 } else { 18 }
            );
            for requested in [1, 2, 4] {
                assert_eq!(options.horner_packed_steps(Some(requested)), requested);
                let source = TablePacking::new(4, 3).with_horner_pack_k(requested);
                let fresh = TablePacking::new(1, 2).with_whir_horner_packing(&options, &source);
                assert_eq!(
                    fresh.horner_packed_steps(),
                    if pcs == PcsOption::Whir { requested } else { 2 }
                );
            }
        }
    }
}
