use alloc::string::ToString;
use alloc::vec::Vec;

use p3_air::{SymbolicExpression, SymbolicExpressionExt};
use p3_circuit_prover::air::AluExtMulKind;
use p3_circuit_prover::batch_stark_prover::NUM_PRIMITIVE_TABLES;
use p3_circuit_prover::{AirVariant, BatchStarkProof, CircuitVerifier, RowCounts, TablePacking};
use p3_commit::Pcs;
use p3_field::{Algebra, ExtensionField, PrimeCharacteristicRing, PrimeField64};
use p3_lookup::logup::LogUpGadget;
use p3_uni_stark::{OpenedValues, Proof, StarkGenericConfig, Val};
use p3_util::log2_ceil_usize;

use crate::input_contract::stark_layout::{CommitmentRole, NativeStarkLayout};
use crate::input_contract::{GlobalPreprocessedShape, NonPrimitiveContract};
use crate::pcs::fri::CheckedFriCommitment;
use crate::prepared::input::NativeCommitment;
use crate::recursion::RecursionInput;
use crate::traits::RecursiveAir;
use crate::verifier::{InputResourceUsage, VerificationError, VerifierLimits};

fn add_opened_values<SC: StarkGenericConfig>(
    usage: &mut InputResourceUsage,
    limits: &VerifierLimits,
    values: &OpenedValues<SC::Challenge>,
) -> Result<(), VerificationError> {
    let OpenedValues {
        trace_local,
        trace_next,
        preprocessed_local,
        preprocessed_next,
        quotient_chunks,
        random,
    } = values;
    // Each quotient chunk owns a separately allocated row even when that row
    // contains no scalars, so charge the container axis before walking it.
    usage.add_metadata_entries(limits, quotient_chunks.len())?;
    for row in core::iter::once(trace_local)
        .chain(trace_next.iter())
        .chain(preprocessed_local.iter())
        .chain(preprocessed_next.iter())
        .chain(quotient_chunks.iter())
        .chain(random.iter())
    {
        usage.check_matrix_width(limits, row.len())?;
        usage.add_scalar_elements(limits, row.len())?;
    }
    Ok(())
}

fn add_cap<SC, Comm>(
    usage: &mut InputResourceUsage,
    limits: &VerifierLimits,
    cap: &<SC::Pcs as Pcs<SC::Challenge, SC::Challenger>>::Commitment,
) -> Result<(), VerificationError>
where
    SC: StarkGenericConfig,
    Comm: CheckedFriCommitment<
            SC::Challenge,
            Input = <SC::Pcs as Pcs<SC::Challenge, SC::Challenger>>::Commitment,
        >,
{
    usage.add_cap_roots(limits, Comm::checked_fri_cap_roots(cap)?)?;
    usage.add_scalar_elements(limits, Comm::checked_fri_public_values_len(cap)?)
}

const fn check_height(
    usage: &InputResourceUsage,
    limits: &VerifierLimits,
    height: usize,
) -> Result<(), VerificationError> {
    usage.check_log_degree(limits, log2_ceil_usize(height))
}

pub(crate) fn check_uni_stark_resources<SC, Comm>(
    limits: &VerifierLimits,
    proof: &Proof<SC>,
    public_inputs: &[Val<SC>],
    preprocessed_commit: Option<&NativeCommitment<SC>>,
    pcs_usage: InputResourceUsage,
) -> Result<InputResourceUsage, VerificationError>
where
    SC: StarkGenericConfig,
    Comm: CheckedFriCommitment<
            SC::Challenge,
            Input = <SC::Pcs as Pcs<SC::Challenge, SC::Challenger>>::Commitment,
        >,
{
    let mut usage = pcs_usage;
    usage.add_instances(limits, 1)?;
    usage.check_log_degree(limits, proof.degree_bits)?;
    usage.check_matrix_width(limits, public_inputs.len())?;
    usage.add_scalar_elements(limits, public_inputs.len())?;
    add_cap::<SC, Comm>(&mut usage, limits, &proof.commitments.trace)?;
    add_cap::<SC, Comm>(&mut usage, limits, &proof.commitments.quotient_chunks)?;
    if let Some(random) = &proof.commitments.random {
        add_cap::<SC, Comm>(&mut usage, limits, random)?;
    }
    if let Some(preprocessed) = preprocessed_commit {
        add_cap::<SC, Comm>(&mut usage, limits, preprocessed)?;
    }
    add_opened_values::<SC>(&mut usage, limits, &proof.opened_values)?;
    usage.check(limits)?;
    Ok(usage)
}

pub(crate) fn check_batch_stark_resources<SC, Comm>(
    limits: &VerifierLimits,
    proof: &BatchStarkProof<SC>,
    common_data: &p3_batch_stark::CommonData<SC>,
    table_public_inputs: &[Vec<Val<SC>>],
    pcs_usage: InputResourceUsage,
) -> Result<InputResourceUsage, VerificationError>
where
    SC: StarkGenericConfig,
    Comm: CheckedFriCommitment<
            SC::Challenge,
            Input = <SC::Pcs as Pcs<SC::Challenge, SC::Challenger>>::Commitment,
        >,
{
    let mut usage = pcs_usage;
    let mut instance_axis = proof
        .proof
        .opened_values
        .instances
        .len()
        .max(proof.proof.degree_bits.len())
        .max(proof.proof.lookup_terminals.len())
        .max(table_public_inputs.len())
        .max(common_data.lookups.len());
    if let Some(preprocessed) = &common_data.preprocessed {
        instance_axis = instance_axis.max(preprocessed.instances.len());
    }
    usage.add_instances(limits, instance_axis)?;

    // Metadata is cheap to inspect and can itself be attacker-controlled. Walk
    // it before proof rows/caps so oversized manifests and identifiers fail
    // before any substantially larger PCS payload is traversed.
    usage.add_metadata_entries(limits, proof.proof.degree_bits.len())?;
    usage.add_metadata_entries(limits, table_public_inputs.len())?;
    usage.add_metadata_entries(limits, proof.proof.lookup_terminals.len())?;
    usage.add_metadata_entries(limits, proof.non_primitives.len())?;
    usage.check_matrix_width(limits, proof.table_packing.public_lanes())?;
    usage.check_matrix_width(limits, proof.table_packing.alu_lanes())?;
    usage.check_matrix_width(limits, proof.table_packing.horner_packed_steps())?;
    check_height(&usage, limits, proof.table_packing.min_trace_height())?;
    for height in [
        proof.table_packing.alu_min_height(),
        proof.table_packing.public_min_height(),
        proof.table_packing.const_min_height(),
    ]
    .into_iter()
    .flatten()
    {
        check_height(&usage, limits, height)?;
    }
    usage.add_metadata_entries(limits, proof.rows.iter().len())?;
    for rows in proof.rows.iter() {
        check_height(&usage, limits, rows)?;
    }
    for entry in &proof.non_primitives {
        usage.add_metadata_string_bytes(limits, entry.op_type.as_str().len())?;
        usage.check_matrix_width(limits, entry.lanes)?;
        usage.check_matrix_width(limits, entry.public_values.len())?;
        check_height(&usage, limits, entry.rows)?;
    }
    for (op_type, lanes) in proof.table_packing.npo_lanes_iter() {
        usage.add_metadata_entries(limits, 1)?;
        usage.add_metadata_string_bytes(limits, op_type.as_str().len())?;
        usage.check_matrix_width(limits, lanes)?;
    }
    for (op_type, height) in proof.table_packing.npo_min_heights() {
        usage.add_metadata_entries(limits, 1)?;
        usage.add_metadata_string_bytes(limits, op_type.as_str().len())?;
        check_height(&usage, limits, height)?;
    }
    usage.add_metadata_entries(limits, common_data.lookups.len())?;
    for lookups in &common_data.lookups {
        usage.add_metadata_entries(limits, lookups.len())?;
    }
    if let Some(preprocessed) = &common_data.preprocessed {
        usage.add_metadata_entries(limits, preprocessed.instances.len())?;
        usage.add_metadata_entries(limits, preprocessed.matrix_to_instance.len())?;
        for metadata in preprocessed.instances.iter().flatten() {
            usage.check_matrix_width(limits, metadata.width)?;
            usage.check_log_degree(limits, metadata.degree_bits)?;
        }
    }

    for &degree in &proof.proof.degree_bits {
        usage.check_log_degree(limits, degree)?;
    }
    for values in table_public_inputs {
        usage.check_matrix_width(limits, values.len())?;
        usage.add_scalar_elements(limits, values.len())?;
    }
    for instance in &proof.proof.opened_values.instances {
        add_opened_values::<SC>(&mut usage, limits, &instance.base_opened_values)?;
        for row in [&instance.permutation_local, &instance.permutation_next] {
            usage.check_matrix_width(limits, row.len())?;
            usage.add_scalar_elements(limits, row.len())?;
        }
    }
    usage.add_scalar_elements(
        limits,
        proof.proof.lookup_terminals.iter().flatten().count(),
    )?;
    usage.add_scalar_elements(limits, usize::from(proof.w_binomial.is_some()))?;

    add_cap::<SC, Comm>(&mut usage, limits, &proof.proof.commitments.main)?;
    if let Some(permutation) = &proof.proof.commitments.permutation {
        add_cap::<SC, Comm>(&mut usage, limits, permutation)?;
    }
    add_cap::<SC, Comm>(&mut usage, limits, &proof.proof.commitments.quotient_chunks)?;
    if let Some(random) = &proof.proof.commitments.random {
        add_cap::<SC, Comm>(&mut usage, limits, random)?;
    }

    for entry in &proof.non_primitives {
        usage.add_scalar_elements(limits, entry.public_values.len())?;
    }
    if let Some(preprocessed) = &common_data.preprocessed {
        add_cap::<SC, Comm>(&mut usage, limits, &preprocessed.commitment)?;
    }
    usage.check(limits)?;
    Ok(usage)
}

pub(crate) fn check_trusted_batch_stark_resources<SC, Comm>(
    limits: &VerifierLimits,
    verifier: &CircuitVerifier<SC>,
    proof: &BatchStarkProof<SC>,
    pcs_usage: InputResourceUsage,
) -> Result<InputResourceUsage, VerificationError>
where
    SC: StarkGenericConfig + 'static,
    Comm: CheckedFriCommitment<
            SC::Challenge,
            Input = <SC::Pcs as Pcs<SC::Challenge, SC::Challenger>>::Commitment,
        >,
{
    // The retained descriptor supplies public values. Avoid materializing a replacement vector
    // until the complete witness/common/PCS resource walk has succeeded.
    let mut usage = check_batch_stark_resources::<SC, Comm>(
        limits,
        proof,
        verifier.common_data(),
        &[],
        pcs_usage,
    )?;
    usage.add_metadata_entries(
        limits,
        3usize
            .checked_add(verifier.relation().non_primitives().len())
            .ok_or(VerificationError::ResourceArithmeticOverflow {
                component: "metadata entries",
            })?,
    )?;
    for entry in verifier.relation().non_primitives() {
        usage.check_matrix_width(limits, entry.public_values().len())?;
        usage.add_scalar_elements(limits, entry.public_values().len())?;
    }
    usage.check(limits)?;
    Ok(usage)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct StarkLayoutPolicy {
    pub(crate) is_zk: usize,
    pub(crate) log_max_lde_height: usize,
}

impl StarkLayoutPolicy {
    pub(crate) fn from_config<SC: StarkGenericConfig>(config: &SC) -> Self {
        Self {
            is_zk: config.is_zk(),
            log_max_lde_height: config.pcs().log_max_lde_height(),
        }
    }

    pub(crate) fn validate_config<SC: StarkGenericConfig>(
        self,
        config: &SC,
    ) -> Result<(), VerificationError> {
        self.validate_actual(Self::from_config(config))
    }

    fn validate_actual(self, actual: Self) -> Result<(), VerificationError> {
        if self == actual {
            Ok(())
        } else {
            Err(VerificationError::PreparedInputMismatch {
                component: "input.stark_policy",
            })
        }
    }
}

#[cfg(test)]
mod policy_tests {
    use alloc::vec;

    use p3_baby_bear::BabyBear;
    use p3_field::extension::BinomialExtensionField;
    use p3_uni_stark::{OpenedValues, StarkConfig};

    use super::{StarkLayoutPolicy, add_opened_values};
    use crate::pcs::whir::uni::pcs::tests::{MyChallenger, MyPcs};
    use crate::verifier::{InputResourceUsage, VerificationError, VerifierLimits};

    type Challenge = BinomialExtensionField<BabyBear, 4>;
    type Config = StarkConfig<MyPcs, Challenge, MyChallenger>;

    #[test]
    fn retained_stark_policy_rejects_each_runtime_policy_mismatch() {
        let retained = StarkLayoutPolicy {
            is_zk: 1,
            log_max_lde_height: 31,
        };
        retained.validate_actual(retained).unwrap();

        for actual in [
            StarkLayoutPolicy {
                is_zk: 0,
                ..retained
            },
            StarkLayoutPolicy {
                log_max_lde_height: 30,
                ..retained
            },
        ] {
            assert!(matches!(
                retained.validate_actual(actual),
                Err(VerificationError::PreparedInputMismatch {
                    component: "input.stark_policy"
                })
            ));
        }
    }

    #[test]
    fn opened_values_charge_empty_quotient_chunk_containers() {
        let values = OpenedValues::<Challenge> {
            trace_local: vec![],
            trace_next: None,
            preprocessed_local: None,
            preprocessed_next: None,
            quotient_chunks: vec![vec![], vec![], vec![]],
            random: None,
        };
        let exact = VerifierLimits {
            max_metadata_entries: 3,
            ..VerifierLimits::default()
        };
        let mut usage = InputResourceUsage::default();

        add_opened_values::<Config>(&mut usage, &exact, &values)
            .expect("three empty quotient chunk rows fit exactly");
        assert_eq!(usage.metadata_entries, 3);

        assert!(matches!(
            add_opened_values::<Config>(
                &mut InputResourceUsage::default(),
                &VerifierLimits {
                    max_metadata_entries: 2,
                    ..exact
                },
                &values,
            ),
            Err(VerificationError::ResourceLimitExceeded {
                component: "metadata entries",
                actual: 3,
                limit: 2,
            })
        ));
    }
}

#[derive(Clone, PartialEq, Eq)]
#[allow(clippy::large_enum_variant)]
pub(crate) enum StarkPackingAuthority<F> {
    Uni {
        public_inputs: usize,
        preprocessed_present: bool,
    },
    Batch {
        public_inputs: Vec<usize>,
        table_packing: TablePacking,
        rows: RowCounts,
        alu_variant: AirVariant,
        ext_degree: usize,
        w_binomial: Option<F>,
        alu_quintic_trinomial: bool,
        non_primitives: Vec<NonPrimitiveContract<F>>,
        statement_instance: Option<usize>,
        preprocessed: Option<GlobalPreprocessedShape<()>>,
    },
}

pub(crate) fn capture_stark_authority<SC, A>(
    input: &RecursionInput<'_, SC, A>,
) -> StarkPackingAuthority<Val<SC>>
where
    SC: StarkGenericConfig,
    A: RecursiveAir<Val<SC>, SC::Challenge, LogUpGadget>,
{
    match input {
        RecursionInput::UniStark {
            public_inputs,
            preprocessed_commit,
            ..
        } => StarkPackingAuthority::Uni {
            public_inputs: public_inputs.len(),
            preprocessed_present: preprocessed_commit.is_some(),
        },
        RecursionInput::BatchStark {
            proof,
            common_data,
            table_public_inputs,
        } => StarkPackingAuthority::Batch {
            public_inputs: table_public_inputs.iter().map(Vec::len).collect(),
            table_packing: proof.table_packing.clone(),
            rows: proof.rows,
            alu_variant: proof.alu_variant,
            ext_degree: proof.ext_degree,
            w_binomial: proof.w_binomial,
            alu_quintic_trinomial: proof.alu_quintic_trinomial,
            non_primitives: proof
                .non_primitives
                .iter()
                .map(|entry| NonPrimitiveContract {
                    op_type: entry.op_type.clone(),
                    rows: entry.rows,
                    lanes: entry.lanes,
                    air_variant: entry.air_variant,
                    public_values: entry.public_values.clone(),
                })
                .collect(),
            statement_instance: None,
            preprocessed: common_data
                .preprocessed
                .as_ref()
                .map(|global| GlobalPreprocessedShape {
                    commitment: (),
                    instances: global
                        .instances
                        .iter()
                        .map(|entry| {
                            entry.as_ref().map(|meta| {
                                crate::input_contract::PreprocessedInstanceShape {
                                    matrix_index: meta.matrix_index,
                                    width: meta.width,
                                    degree_bits: meta.degree_bits,
                                }
                            })
                        })
                        .collect(),
                    matrix_to_instance: global.matrix_to_instance.clone(),
                }),
        },
    }
}

/// Capture batch packing authority from a retained verifier descriptor, never witness metadata.
pub(crate) fn capture_trusted_batch_authority<SC>(
    verifier: &CircuitVerifier<SC>,
    expected_statement: &[Val<SC>],
) -> Result<StarkPackingAuthority<Val<SC>>, VerificationError>
where
    SC: StarkGenericConfig + 'static,
    Val<SC>: p3_circuit_prover::config::StarkField,
    SymbolicExpressionExt<Val<SC>, SC::Challenge>:
        Algebra<SymbolicExpression<Val<SC>>> + Algebra<SC::Challenge>,
{
    let relation = verifier.relation();
    let public_values = verifier
        .table_public_values(expected_statement)
        .map_err(|error| VerificationError::InvalidProofShape(error.to_string()))?;
    let (w_binomial, alu_quintic_trinomial) = match relation.reduction() {
        AluExtMulKind::Base => (None, false),
        AluExtMulKind::Binomial { w } => (Some(w), false),
        AluExtMulKind::QuinticTrinomial => (None, true),
    };
    Ok(StarkPackingAuthority::Batch {
        public_inputs: public_values.iter().map(Vec::len).collect(),
        table_packing: relation.table_packing().clone(),
        rows: *relation.rows(),
        alu_variant: relation.alu_variant(),
        ext_degree: relation.ext_degree(),
        w_binomial,
        alu_quintic_trinomial,
        non_primitives: relation
            .non_primitives()
            .iter()
            .zip(public_values.iter().skip(NUM_PRIMITIVE_TABLES))
            .map(|(entry, values)| NonPrimitiveContract {
                op_type: entry.op_type().clone(),
                rows: entry.rows(),
                lanes: entry.lanes(),
                air_variant: entry.air_variant(),
                public_values: values.clone(),
            })
            .collect(),
        statement_instance: verifier.statement_layout().table_instance(),
        preprocessed: verifier.common_data().preprocessed.as_ref().map(|global| {
            GlobalPreprocessedShape {
                commitment: (),
                instances: global
                    .instances
                    .iter()
                    .map(|entry| {
                        entry.as_ref().map(|meta| {
                            crate::input_contract::PreprocessedInstanceShape {
                                matrix_index: meta.matrix_index,
                                width: meta.width,
                                degree_bits: meta.degree_bits,
                            }
                        })
                    })
                    .collect(),
                matrix_to_instance: global.matrix_to_instance.clone(),
            }
        }),
    })
}

pub(crate) fn input_caps<'a, SC, A>(
    input: &'a RecursionInput<'_, SC, A>,
    layout: &NativeStarkLayout<'_>,
) -> Result<Vec<&'a NativeCommitment<SC>>, VerificationError>
where
    SC: StarkGenericConfig,
    A: RecursiveAir<Val<SC>, SC::Challenge, LogUpGadget>,
{
    let mut caps = Vec::with_capacity(layout.commitment_count());
    for ordinal in 0..layout.commitment_count() {
        let cap = match (input, layout.commitment_role(ordinal)) {
            (RecursionInput::UniStark { proof, .. }, Some(CommitmentRole::Random)) => {
                proof.commitments.random.as_ref()
            }
            (RecursionInput::UniStark { proof, .. }, Some(CommitmentRole::Trace)) => {
                Some(&proof.commitments.trace)
            }
            (RecursionInput::UniStark { proof, .. }, Some(CommitmentRole::Quotient)) => {
                Some(&proof.commitments.quotient_chunks)
            }
            (
                RecursionInput::UniStark {
                    preprocessed_commit,
                    ..
                },
                Some(CommitmentRole::Preprocessed),
            ) => preprocessed_commit.as_ref(),
            (RecursionInput::BatchStark { proof, .. }, Some(CommitmentRole::Random)) => {
                proof.proof.commitments.random.as_ref()
            }
            (RecursionInput::BatchStark { proof, .. }, Some(CommitmentRole::Trace)) => {
                Some(&proof.proof.commitments.main)
            }
            (RecursionInput::BatchStark { proof, .. }, Some(CommitmentRole::Quotient)) => {
                Some(&proof.proof.commitments.quotient_chunks)
            }
            (
                RecursionInput::BatchStark { common_data, .. },
                Some(CommitmentRole::Preprocessed),
            ) => common_data
                .preprocessed
                .as_ref()
                .map(|global| &global.commitment),
            (RecursionInput::BatchStark { proof, .. }, Some(CommitmentRole::Permutation)) => {
                proof.proof.commitments.permutation.as_ref()
            }
            _ => None,
        }
        .ok_or_else(|| {
            VerificationError::InvalidProofShape(
                "STARK commitment presence disagrees with retained layout".into(),
            )
        })?;
        caps.push(cap);
    }
    Ok(caps)
}

pub(crate) fn validate_stark_replacement<SC, A>(
    authority: &StarkPackingAuthority<Val<SC>>,
    expected: &NativeStarkLayout<'_>,
    policy: StarkLayoutPolicy,
    input: &RecursionInput<'_, SC, A>,
) -> Result<(), VerificationError>
where
    SC: StarkGenericConfig,
    A: RecursiveAir<Val<SC>, SC::Challenge, LogUpGadget>,
    Val<SC>: PrimeField64,
    SC::Challenge: ExtensionField<Val<SC>> + PrimeCharacteristicRing,
{
    match (authority, input) {
        (
            StarkPackingAuthority::Uni {
                public_inputs,
                preprocessed_present,
            },
            RecursionInput::UniStark {
                proof,
                air,
                public_inputs: actual_public,
                preprocessed_commit,
            },
        ) if *public_inputs == actual_public.len()
            && *preprocessed_present == preprocessed_commit.is_some() =>
        {
            let actual = crate::verifier::plan_uni_native_layout_with_policy(
                policy.is_zk,
                policy.log_max_lde_height,
                *air,
                proof,
                actual_public.len(),
                preprocessed_commit.as_ref(),
            )?;
            if &actual != expected {
                return Err(VerificationError::PreparedInputMismatch {
                    component: "input.stark_layout",
                });
            }
        }
        (
            StarkPackingAuthority::Batch {
                public_inputs,
                table_packing,
                rows,
                alu_variant,
                ext_degree,
                w_binomial,
                alu_quintic_trinomial,
                non_primitives,
                statement_instance,
                preprocessed,
            },
            RecursionInput::BatchStark {
                proof,
                common_data,
                table_public_inputs,
            },
        ) => {
            let preprocessed_matches =
                match (preprocessed.as_ref(), common_data.preprocessed.as_ref()) {
                    (None, None) => true,
                    (Some(expected), Some(actual)) => {
                        expected.instances.len() == actual.instances.len()
                            && expected.instances.iter().zip(&actual.instances).all(
                                |(expected, actual)| {
                                    expected.as_ref().map(|shape| {
                                        (shape.matrix_index, shape.width, shape.degree_bits)
                                    }) == actual.as_ref().map(|shape| {
                                        (shape.matrix_index, shape.width, shape.degree_bits)
                                    })
                                },
                            )
                            && expected.matrix_to_instance == actual.matrix_to_instance
                    }
                    _ => false,
                };
            let metadata_matches = public_inputs.len() == table_public_inputs.len()
                && public_inputs
                    .iter()
                    .zip(table_public_inputs)
                    .all(|(expected, actual)| *expected == actual.len())
                && table_packing == &proof.table_packing
                && rows == &proof.rows
                && alu_variant == &proof.alu_variant
                && *ext_degree == proof.ext_degree
                && w_binomial == &proof.w_binomial
                && *alu_quintic_trinomial == proof.alu_quintic_trinomial
                && non_primitives.len() == proof.non_primitives.len()
                && non_primitives
                    .iter()
                    .zip(&proof.non_primitives)
                    .enumerate()
                    .all(|(index, (expected, actual))| {
                        expected.op_type == actual.op_type
                            && expected.rows == actual.rows
                            && expected.lanes == actual.lanes
                            && expected.air_variant == actual.air_variant
                            && if *statement_instance == Some(NUM_PRIMITIVE_TABLES + index) {
                                expected.public_values.len() == actual.public_values.len()
                            } else {
                                expected.public_values == actual.public_values
                            }
                    })
                && preprocessed_matches;
            if !metadata_matches {
                return Err(VerificationError::PreparedInputMismatch {
                    component: "input.metadata",
                });
            }
            validate_batch_against_layout(expected, input)?;
        }
        _ => {
            return Err(VerificationError::PreparedInputMismatch {
                component: "input.kind",
            });
        }
    }
    Ok(())
}

fn validate_batch_against_layout<SC, A>(
    expected: &NativeStarkLayout<'_>,
    input: &RecursionInput<'_, SC, A>,
) -> Result<(), VerificationError>
where
    SC: StarkGenericConfig,
    A: RecursiveAir<Val<SC>, SC::Challenge, LogUpGadget>,
{
    let RecursionInput::BatchStark {
        proof,
        common_data,
        table_public_inputs,
    } = input
    else {
        unreachable!()
    };
    let batch = &proof.proof;
    if batch.degree_bits.len() != expected.instances.len()
        || batch.opened_values.instances.len() != expected.instances.len()
        || table_public_inputs.len() != expected.instances.len()
        || batch.commitments.random.is_some() != expected.has_random
        || common_data.preprocessed.is_some() != expected.has_preprocessed
        || batch.commitments.permutation.is_some() != expected.has_permutation
    {
        return Err(VerificationError::PreparedInputMismatch {
            component: "input.stark_layout",
        });
    }
    for (index, (opened, layout)) in batch
        .opened_values
        .instances
        .iter()
        .zip(&expected.instances)
        .enumerate()
    {
        let base = &opened.base_opened_values;
        if batch.degree_bits[index] != layout.ext_log
            || base.trace_local.len() != layout.trace_width
            || base.trace_next.as_ref().map_or(0, Vec::len)
                != layout.trace_width * usize::from(layout.trace_next)
            || base.preprocessed_local.as_ref().map_or(0, Vec::len) != layout.pre_width
            || base.preprocessed_next.as_ref().map_or(0, Vec::len)
                != layout.pre_width * usize::from(layout.pre_next)
            || base.quotient_chunks.len() != layout.quotient_chunks
            || base
                .quotient_chunks
                .iter()
                .any(|chunk| chunk.len() != layout.challenge_width)
            || base
                .random
                .as_ref()
                .is_some_and(|values| values.len() != layout.challenge_width)
            || opened.permutation_local.len() != layout.permutation_width
            || opened.permutation_next.len() != layout.permutation_width
        {
            return Err(VerificationError::PreparedInputMismatch {
                component: "input.stark_layout",
            });
        }
    }
    Ok(())
}
