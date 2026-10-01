//! PCS selection and WHIR configuration shared by the recursive examples.

use p3_whir::parameters::SecurityAssumption;

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
}

impl PcsOptions {
    pub fn security_level(&self, requested: Option<usize>) -> usize {
        // Leave room for WHIR's claim-batching and sumcheck bounds in the D4/D2 fields.
        requested.unwrap_or(match self.pcs {
            PcsOption::Fri => 124,
            PcsOption::Whir => 64,
        })
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
                (1usize << self.whir_folding_factor)
                    .checked_mul(queries.next_power_of_two())
                    .expect("WHIR minimum trace height is too large")
            }
        }
    }
}

pub trait ExampleTablePacking {
    fn with_pcs_params(self, options: &PcsOptions, fp: &FriParams, security_level: usize) -> Self;
}

impl ExampleTablePacking for TablePacking {
    fn with_pcs_params(self, options: &PcsOptions, fp: &FriParams, security_level: usize) -> Self {
        self.with_min_trace_height(options.min_trace_height(fp, security_level))
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
                    restore_whir_recursion_paths, whir_round_paths_op_count,
                };
                let params = &config.verifier_params;
                let paths = restore_whir_recursion_paths::<Self, _, _, _, _, _, DIGEST_ELEMS>(
                    &config.mmcs,
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
            folding_factor: usize,
        ) -> ConfigWithWhirParams {
            use p3_sumcheck::layout::Layout;
            use p3_whir::parameters::{FoldingFactor, ProtocolParameters, SecurityAssumption};

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
                folding_factor: FoldingFactor::Constant(folding_factor),
                soundness_type: SecurityAssumption::CapacityBound,
            };
            let pcs = MyWhirPcs::new(
                protocol.clone(),
                p3_dft::Radix2DFTSmallBatch::default(),
                mmcs.clone(),
                challenger.clone(),
                <F as p3_field::TwoAdicField>::TWO_ADICITY,
            );
            let verifier_params = p3_recursion::pcs::whir::uni::WhirUniVerifierParams::new(
                protocol,
                p3_sumcheck::layout::PrefixProver::<F, Challenge>::variable_order(),
                $perm_config,
            )
            .expect("valid WHIR example configuration");
            ConfigWithWhirParams {
                config: Arc::new(MyWhirConfig::new(pcs, challenger)),
                verifier_params,
                mmcs,
                disable_recompose_npo,
            }
        }
    };
}
