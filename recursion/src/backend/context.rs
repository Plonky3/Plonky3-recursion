use alloc::vec::Vec;

use p3_circuit_prover::{AirVariant, RowCounts, TablePacking};
use p3_field::{ExtensionField, PrimeCharacteristicRing, PrimeField64};
use p3_lookup::logup::LogUpGadget;
use p3_uni_stark::{StarkGenericConfig, Val};

use crate::input_contract::stark_layout::{CommitmentRole, NativeStarkLayout};
use crate::input_contract::{GlobalPreprocessedShape, NonPrimitiveContract};
use crate::prepared::input::NativeCommitment;
use crate::recursion::RecursionInput;
use crate::traits::RecursiveAir;
use crate::verifier::VerificationError;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct StarkLayoutPolicy {
    pub(crate) is_zk: usize,
    pub(crate) log_max_lde_height: usize,
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
                    .all(|(expected, actual)| {
                        expected.op_type == actual.op_type
                            && expected.rows == actual.rows
                            && expected.lanes == actual.lanes
                            && expected.air_variant == actual.air_variant
                            && expected.public_values == actual.public_values
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
