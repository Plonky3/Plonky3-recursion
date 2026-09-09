use alloc::boxed::Box;
use alloc::format;
use alloc::string::ToString;
use alloc::vec::Vec;

use p3_batch_stark::CommonData;
use p3_circuit_prover::BatchStarkProof;
use p3_circuit_prover::batch_stark_prover::TableProver;
use p3_circuit_prover::field_params::ExtractBinomialW;
use p3_commit::Pcs;
use p3_field::{ExtensionField, PrimeField64};
use p3_uni_stark::{Proof, StarkGenericConfig, Val};

use crate::input_contract::{
    BatchInputContract, CommitmentsShape, GlobalPreprocessedShape, InputContract,
    NonPrimitiveContract, OpenedValuesShape, OpenedValuesWithLookupsShape,
    PreprocessedInstanceShape, UniInputContract,
};
use crate::recursion::{BatchOnly, RecursionInput};
use crate::traits::{PreparedRecursive, Recursive, RecursiveAir};
use crate::verifier::{ReconstructedBatchTables, VerificationError, reconstruct_batch_tables};

/// Native PCS commitment type selected by a STARK configuration.
pub type NativeCommitment<SC> = <<SC as StarkGenericConfig>::Pcs as Pcs<
    <SC as StarkGenericConfig>::Challenge,
    <SC as StarkGenericConfig>::Challenger,
>>::Commitment;

/// Result of capturing a native input contract shape for one commitment/opening pair.
pub(crate) type CaptureShapeResult<SC, CommShape, OpeningShape> =
    Result<InputContract<Val<SC>, CommShape, OpeningShape>, VerificationError>;

/// Borrowed witness view accepted by a prepared verifier.
pub enum PreparedInput<'p, SC: StarkGenericConfig> {
    /// One uni-STARK proof and its dynamic public values.
    UniStark {
        proof: &'p Proof<SC>,
        public_inputs: &'p [Val<SC>],
        preprocessed_commit: Option<&'p NativeCommitment<SC>>,
    },
    /// One circuit batch-STARK proof and its explicit common/public data.
    BatchStark {
        proof: &'p BatchStarkProof<SC>,
        common_data: &'p CommonData<SC>,
        table_public_inputs: &'p [Vec<Val<SC>>],
    },
}

impl<'p, SC: StarkGenericConfig> Clone for PreparedInput<'p, SC> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<'p, SC: StarkGenericConfig> Copy for PreparedInput<'p, SC> {}

/// Borrowed trusted source used while constructing a prepared verifier.
pub enum PreparedSource<'air, 'p, SC: StarkGenericConfig, A> {
    /// A uni-STARK source retaining the original AIR separately from the proof lifetime.
    UniStark {
        air: &'air A,
        proof: &'p Proof<SC>,
        public_inputs: &'p [Val<SC>],
        preprocessed_commit: Option<&'p NativeCommitment<SC>>,
    },
    /// A batch-STARK source; reconstructed table AIRs provide its trusted interpretation.
    BatchStark {
        proof: &'p BatchStarkProof<SC>,
        common_data: &'p CommonData<SC>,
        table_public_inputs: &'p [Vec<Val<SC>>],
    },
}

impl<'air, 'p, SC: StarkGenericConfig, A> Clone for PreparedSource<'air, 'p, SC, A> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<'air, 'p, SC: StarkGenericConfig, A> Copy for PreparedSource<'air, 'p, SC, A> {}

impl<'p, SC: StarkGenericConfig> PreparedSource<'static, 'p, SC, BatchOnly> {
    /// Construct a batch-only source without a placeholder AIR value.
    pub const fn batch(
        proof: &'p BatchStarkProof<SC>,
        common_data: &'p CommonData<SC>,
        table_public_inputs: &'p [Vec<Val<SC>>],
    ) -> Self {
        Self::BatchStark {
            proof,
            common_data,
            table_public_inputs,
        }
    }
}

impl<'air, 'p, SC: StarkGenericConfig, A> PreparedSource<'air, 'p, SC, A> {
    pub(crate) const fn as_input(&self) -> PreparedInput<'_, SC> {
        match self {
            Self::UniStark {
                proof,
                public_inputs,
                preprocessed_commit,
                ..
            } => PreparedInput::UniStark {
                proof,
                public_inputs,
                preprocessed_commit: *preprocessed_commit,
            },
            Self::BatchStark {
                proof,
                common_data,
                table_public_inputs,
            } => PreparedInput::BatchStark {
                proof,
                common_data,
                table_public_inputs,
            },
        }
    }
}

pub(crate) fn legacy_input<'a, 'p: 'a, SC, A>(
    air: Option<&'a A>,
    input: &'a PreparedInput<'p, SC>,
) -> Result<RecursionInput<'a, SC, A>, VerificationError>
where
    SC: StarkGenericConfig,
    A: crate::traits::RecursiveAir<Val<SC>, SC::Challenge, p3_lookup::logup::LogUpGadget>,
{
    match (air, input) {
        (
            Some(air),
            PreparedInput::UniStark {
                proof,
                public_inputs,
                preprocessed_commit,
            },
        ) => Ok(RecursionInput::UniStark {
            proof,
            air,
            public_inputs: public_inputs.to_vec(),
            preprocessed_commit: preprocessed_commit.cloned(),
        }),
        (
            None,
            PreparedInput::BatchStark {
                proof,
                common_data,
                table_public_inputs,
            },
        ) => Ok(RecursionInput::BatchStark {
            proof,
            common_data,
            table_public_inputs: table_public_inputs.to_vec(),
        }),
        _ => Err(VerificationError::PreparedInputMismatch {
            component: "input.kind",
        }),
    }
}

fn opened_values_shape<EF>(values: &p3_uni_stark::OpenedValues<EF>) -> OpenedValuesShape {
    let p3_uni_stark::OpenedValues {
        trace_local,
        trace_next,
        preprocessed_local,
        preprocessed_next,
        quotient_chunks,
        random,
    } = values;
    OpenedValuesShape {
        trace_local: trace_local.len(),
        trace_next: trace_next.as_ref().map(Vec::len),
        preprocessed_local: preprocessed_local.as_ref().map(Vec::len),
        preprocessed_next: preprocessed_next.as_ref().map(Vec::len),
        quotient_chunks: quotient_chunks.iter().map(Vec::len).collect(),
        random: random.as_ref().map(Vec::len),
    }
}

/// Capture every native input property that affects target allocation or compiled verification.
pub(crate) fn capture_input_shape<SC, Comm, Opening>(
    input: &PreparedInput<'_, SC>,
) -> CaptureShapeResult<SC, Comm::Shape, Opening::Shape>
where
    SC: StarkGenericConfig,
    Comm: Recursive<SC::Challenge, Input = NativeCommitment<SC>> + PreparedRecursive<SC::Challenge>,
    Opening: Recursive<SC::Challenge, Input = <SC::Pcs as Pcs<SC::Challenge, SC::Challenger>>::Proof>
        + PreparedRecursive<SC::Challenge>,
{
    match input {
        PreparedInput::UniStark {
            proof,
            public_inputs,
            preprocessed_commit,
        } => {
            let Proof {
                commitments,
                opened_values,
                opening_proof,
                degree_bits,
            } = proof;
            let p3_uni_stark::Commitments {
                trace,
                quotient_chunks,
                random,
            } = commitments;
            Ok(InputContract::Uni(UniInputContract {
                degree_bits: *degree_bits,
                public_inputs: public_inputs.len(),
                commitments: CommitmentsShape {
                    main: Comm::input_shape(trace)?,
                    permutation: None,
                    quotient_chunks: Comm::input_shape(quotient_chunks)?,
                    random: random.as_ref().map(Comm::input_shape).transpose()?,
                },
                opened_values: opened_values_shape(opened_values),
                opening: Opening::input_shape(opening_proof)?,
                preprocessed_commit: preprocessed_commit
                    .map(|commitment| Comm::input_shape(commitment))
                    .transpose()?,
            }))
        }
        PreparedInput::BatchStark {
            proof,
            common_data,
            table_public_inputs,
        } => {
            proof
                .validate()
                .map_err(|error| VerificationError::InvalidProofShape(error.to_string()))?;
            let BatchStarkProof {
                proof: batch,
                table_packing,
                rows,
                alu_variant,
                ext_degree,
                w_binomial,
                alu_quintic_trinomial,
                non_primitives,
                // Explicit common_data is authoritative in prepared high-level paths. The
                // embedded copy is unused and intentionally excluded from this contract.
                stark_common: _,
            } = proof;
            let p3_batch_stark::BatchProof {
                commitments,
                opened_values,
                opening_proof,
                lookup_terminals,
                degree_bits,
            } = batch;
            let p3_batch_stark::BatchOpenedValues { instances } = opened_values;
            let instance_count = instances.len();
            if instance_count == 0
                || degree_bits.len() != instance_count
                || lookup_terminals.len() != instance_count
                || table_public_inputs.len() != instance_count
            {
                return Err(VerificationError::InvalidProofShape(format!(
                    "batch input vector cardinality mismatch: instances {instance_count}, degree bits {}, lookup terminals {}, public inputs {}",
                    degree_bits.len(),
                    lookup_terminals.len(),
                    table_public_inputs.len()
                )));
            }
            let p3_batch_stark::BatchCommitments {
                main,
                permutation,
                quotient_chunks,
                random,
            } = commitments;
            let commitments = CommitmentsShape {
                main: Comm::input_shape(main)?,
                permutation: permutation.as_ref().map(Comm::input_shape).transpose()?,
                quotient_chunks: Comm::input_shape(quotient_chunks)?,
                random: random.as_ref().map(Comm::input_shape).transpose()?,
            };
            let opened_values = instances
                .iter()
                .map(|instance| {
                    let p3_batch_stark::proof::OpenedValuesWithLookups {
                        base_opened_values,
                        permutation_local,
                        permutation_next,
                    } = instance;
                    OpenedValuesWithLookupsShape {
                        base: opened_values_shape(base_opened_values),
                        permutation_local: permutation_local.len(),
                        permutation_next: permutation_next.len(),
                    }
                })
                .collect();
            let non_primitives = non_primitives
                .iter()
                .map(|entry| {
                    let p3_circuit_prover::batch_stark_prover::NonPrimitiveTableEntry {
                        op_type,
                        rows,
                        lanes,
                        public_values,
                        air_variant,
                    } = entry;
                    NonPrimitiveContract {
                        op_type: op_type.clone(),
                        rows: *rows,
                        lanes: *lanes,
                        air_variant: *air_variant,
                        public_values: public_values.clone(),
                    }
                })
                .collect();
            let CommonData {
                preprocessed: common_preprocessed,
                // Lookup contexts are rebuilt from the trusted reconstructed table AIRs, so
                // supplied lookups do not select behavior in these built-in high-level paths.
                lookups: _,
            } = common_data;
            let preprocessed = common_preprocessed
                .as_ref()
                .map(|global| -> Result<_, VerificationError> {
                    let p3_batch_stark::common::GlobalPreprocessed {
                        commitment,
                        instances,
                        matrix_to_instance,
                    } = global;
                    Ok(GlobalPreprocessedShape {
                        commitment: Comm::input_shape(commitment)?,
                        instances: instances
                            .iter()
                            .map(|instance| {
                                instance.as_ref().map(|metadata| {
                                    let p3_batch_stark::common::PreprocessedInstanceMeta {
                                        matrix_index,
                                        width,
                                        degree_bits,
                                    } = metadata;
                                    PreprocessedInstanceShape {
                                        matrix_index: *matrix_index,
                                        width: *width,
                                        degree_bits: *degree_bits,
                                    }
                                })
                            })
                            .collect(),
                        matrix_to_instance: matrix_to_instance.clone(),
                    })
                })
                .transpose()?;
            Ok(InputContract::Batch(Box::new(BatchInputContract {
                degree_bits: degree_bits.clone(),
                public_inputs: table_public_inputs.iter().map(Vec::len).collect(),
                commitments,
                opened_values,
                lookup_terminals: lookup_terminals.iter().map(Option::is_some).collect(),
                opening: Opening::input_shape(opening_proof)?,
                table_packing: table_packing.clone(),
                rows: *rows,
                alu_variant: *alu_variant,
                ext_degree: *ext_degree,
                w_binomial: *w_binomial,
                alu_quintic_trinomial: *alu_quintic_trinomial,
                non_primitives,
                preprocessed,
            })))
        }
    }
}

/// Compare two well-formed native contracts in a stable, diagnostic field order.
pub(crate) fn compare_input_contract<F: PartialEq, C: PartialEq, O: PartialEq>(
    expected: &InputContract<F, C, O>,
    actual: &InputContract<F, C, O>,
) -> Result<(), VerificationError> {
    macro_rules! same {
        ($left:expr, $right:expr, $component:literal) => {
            if $left != $right {
                return Err(VerificationError::PreparedInputMismatch {
                    component: $component,
                });
            }
        };
    }
    match (expected, actual) {
        (InputContract::Uni(a), InputContract::Uni(b)) => {
            same!(a.degree_bits, b.degree_bits, "input.degree_bits");
            same!(a.public_inputs, b.public_inputs, "input.public_inputs");
            same!(a.commitments, b.commitments, "input.commitments");
            same!(a.opened_values, b.opened_values, "input.opened_values");
            same!(a.opening, b.opening, "input.opening_proof");
            same!(
                a.preprocessed_commit,
                b.preprocessed_commit,
                "input.preprocessed"
            );
        }
        (InputContract::Batch(a), InputContract::Batch(b)) => {
            same!(a.degree_bits, b.degree_bits, "input.degree_bits");
            same!(a.public_inputs, b.public_inputs, "input.public_inputs");
            same!(a.commitments, b.commitments, "input.commitments");
            same!(a.opened_values, b.opened_values, "input.opened_values");
            same!(
                a.lookup_terminals,
                b.lookup_terminals,
                "input.opened_values"
            );
            same!(a.opening, b.opening, "input.opening_proof");
            same!(a.table_packing, b.table_packing, "input.metadata");
            same!(a.rows, b.rows, "input.metadata");
            same!(a.alu_variant, b.alu_variant, "input.metadata");
            same!(a.ext_degree, b.ext_degree, "input.metadata");
            same!(a.w_binomial, b.w_binomial, "input.metadata");
            same!(
                a.alu_quintic_trinomial,
                b.alu_quintic_trinomial,
                "input.metadata"
            );
            same!(a.non_primitives, b.non_primitives, "input.metadata");
            same!(a.preprocessed, b.preprocessed, "input.preprocessed");
        }
        _ => {
            return Err(VerificationError::PreparedInputMismatch {
                component: "input.kind",
            });
        }
    }
    Ok(())
}

pub(crate) fn validate_manifest_public_inputs<SC: StarkGenericConfig>(
    proof: &BatchStarkProof<SC>,
    table_public_inputs: &[Vec<Val<SC>>],
) -> Result<(), VerificationError> {
    let expected_len = 3 + proof.non_primitives.len();
    if table_public_inputs.len() != expected_len
        || table_public_inputs[..table_public_inputs.len().min(3)]
            .iter()
            .any(|values| !values.is_empty())
        || proof
            .non_primitives
            .iter()
            .zip(table_public_inputs.iter().skip(3))
            .any(|(entry, values)| entry.public_values != *values)
    {
        return Err(VerificationError::InvalidProofShape(
            "batch table public inputs disagree with prepared manifest".into(),
        ));
    }
    Ok(())
}

fn validate_reconstructed_public_inputs<SC, const TRACE_D: usize>(
    reconstructed: &ReconstructedBatchTables<SC, TRACE_D>,
    table_public_inputs: &[Vec<Val<SC>>],
) -> Result<(), VerificationError>
where
    SC: StarkGenericConfig,
{
    if reconstructed.public_values.as_slice() != table_public_inputs
        || reconstructed
            .airs
            .iter()
            .zip(&reconstructed.public_values)
            .any(|(air, values)| p3_air::BaseAir::<Val<SC>>::num_public_values(air) != values.len())
    {
        return Err(VerificationError::InvalidProofShape(
            "batch table public inputs disagree with reconstructed AIR/transcript".into(),
        ));
    }
    Ok(())
}

fn reconstruct_and_validate_public_inputs<SC, const TRACE_D: usize>(
    config: &SC,
    proof: &BatchStarkProof<SC>,
    table_public_inputs: &[Vec<Val<SC>>],
    non_primitive_provers: &[Box<dyn TableProver<SC>>],
) -> Result<(), VerificationError>
where
    SC: StarkGenericConfig + 'static,
    Val<SC>: PrimeField64,
    SC::Challenge: ExtensionField<Val<SC>> + ExtractBinomialW<Val<SC>>,
{
    let reconstructed =
        reconstruct_batch_tables::<SC, TRACE_D>(config, proof, non_primitive_provers)?;
    validate_reconstructed_public_inputs(&reconstructed, table_public_inputs)
}

/// Shared built-in backend capture. Callers supply exactly the plugin list selected for the
/// input proof's own extension degree.
pub(crate) fn capture_builtin_input_contract<SC, A, Comm, Opening>(
    config: &SC,
    source: &RecursionInput<'_, SC, A>,
    whir_degree_four_only: bool,
    make_non_primitive_provers: impl FnOnce(usize) -> Vec<Box<dyn TableProver<SC>>>,
) -> CaptureShapeResult<SC, Comm::Shape, Opening::Shape>
where
    SC: StarkGenericConfig + 'static,
    A: RecursiveAir<Val<SC>, SC::Challenge, p3_lookup::logup::LogUpGadget>,
    Comm: Recursive<SC::Challenge, Input = NativeCommitment<SC>> + PreparedRecursive<SC::Challenge>,
    Opening: Recursive<SC::Challenge, Input = <SC::Pcs as Pcs<SC::Challenge, SC::Challenger>>::Proof>
        + PreparedRecursive<SC::Challenge>,
    Val<SC>: PrimeField64,
    SC::Challenge: ExtensionField<Val<SC>> + ExtractBinomialW<Val<SC>>,
{
    let input = match source {
        RecursionInput::UniStark {
            proof,
            public_inputs,
            preprocessed_commit,
            ..
        } => PreparedInput::UniStark {
            proof,
            public_inputs,
            preprocessed_commit: preprocessed_commit.as_ref(),
        },
        RecursionInput::BatchStark {
            proof,
            common_data,
            table_public_inputs,
        } => PreparedInput::BatchStark {
            proof,
            common_data,
            table_public_inputs,
        },
    };
    // Pure native shape capture and raw guards always precede trusted interpretation.
    let contract = capture_input_shape::<SC, Comm, Opening>(&input)?;

    match source {
        RecursionInput::UniStark {
            air, public_inputs, ..
        } => match air.expected_public_input_count() {
            Some(expected) if expected == public_inputs.len() => {}
            Some(expected) => {
                return Err(VerificationError::InvalidProofShape(format!(
                    "uni-STARK public input count mismatch: AIR expects {expected}, got {}",
                    public_inputs.len()
                )));
            }
            None => {
                return Err(VerificationError::InvalidProofShape(
                    "prepared uni-STARK AIR does not declare an exact public input count".into(),
                ));
            }
        },
        RecursionInput::BatchStark {
            proof,
            table_public_inputs,
            ..
        } => {
            if whir_degree_four_only && proof.ext_degree != 4 {
                return Err(VerificationError::InvalidProofShape(format!(
                    "WhirRecursionBackend supports batch proofs of ext_degree 4, got {}",
                    proof.ext_degree
                )));
            }
            if !matches!(proof.ext_degree, 1 | 2 | 4 | 5) {
                return Err(VerificationError::InvalidProofShape(format!(
                    "unsupported batch proof ext_degree {}",
                    proof.ext_degree
                )));
            }
            let non_primitive_provers = make_non_primitive_provers(proof.ext_degree);
            match proof.ext_degree {
                1 => reconstruct_and_validate_public_inputs::<SC, 1>(
                    config,
                    proof,
                    table_public_inputs,
                    &non_primitive_provers,
                )?,
                2 => reconstruct_and_validate_public_inputs::<SC, 2>(
                    config,
                    proof,
                    table_public_inputs,
                    &non_primitive_provers,
                )?,
                4 => reconstruct_and_validate_public_inputs::<SC, 4>(
                    config,
                    proof,
                    table_public_inputs,
                    &non_primitive_provers,
                )?,
                5 => reconstruct_and_validate_public_inputs::<SC, 5>(
                    config,
                    proof,
                    table_public_inputs,
                    &non_primitive_provers,
                )?,
                degree => {
                    return Err(VerificationError::InvalidProofShape(format!(
                        "unsupported batch proof ext_degree {degree}"
                    )));
                }
            }
        }
    }
    Ok(contract)
}

/// Shared built-in backend reuse check. Metadata equality is established before the manifest's
/// duplicated public source is inspected; neither reconstruction nor transcript replay occurs.
pub(crate) fn validate_builtin_prepared_input<SC, Comm, Opening>(
    contract: &InputContract<Val<SC>, Comm::Shape, Opening::Shape>,
    input: &PreparedInput<'_, SC>,
) -> Result<(), VerificationError>
where
    SC: StarkGenericConfig,
    Comm: Recursive<SC::Challenge, Input = NativeCommitment<SC>> + PreparedRecursive<SC::Challenge>,
    Opening: Recursive<SC::Challenge, Input = <SC::Pcs as Pcs<SC::Challenge, SC::Challenger>>::Proof>
        + PreparedRecursive<SC::Challenge>,
{
    let actual = capture_input_shape::<SC, Comm, Opening>(input)?;
    compare_input_contract(contract, &actual)?;
    if let PreparedInput::BatchStark {
        proof,
        table_public_inputs,
        ..
    } = input
    {
        validate_manifest_public_inputs(proof, table_public_inputs)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use alloc::boxed::Box;
    use alloc::vec;

    use p3_air::{Air, AirBuilder, AirLayout, BaseAir, BaseLeaf, SymbolicExpr, WindowAccess};
    use p3_circuit::ops::NpoTypeId;
    use p3_circuit::tables::Traces;
    use p3_circuit_prover::batch_stark_prover::{
        BatchAir, BatchTableInstance, DynamicAirEntry, NonPrimitiveTableEntry, TableProver,
    };
    use p3_circuit_prover::{AirVariant, RowCounts, TablePacking};
    use p3_field::extension::{BinomialExtensionField, QuinticTrinomialExtensionField};
    use p3_field::{Algebra, Field, PrimeCharacteristicRing};
    use p3_lookup::logup::LogUpGadget;
    use p3_uni_stark::{StarkGenericConfig, SymbolicExpression, SymbolicExpressionExt, Val};

    use super::{
        capture_builtin_input_contract, compare_input_contract,
        validate_reconstructed_public_inputs,
    };
    use crate::input_contract::{
        BatchInputContract, CommitmentsShape, GlobalPreprocessedShape, InputContract,
        NonPrimitiveContract, OpenedValuesShape, OpenedValuesWithLookupsShape,
        PreprocessedInstanceShape,
    };
    use crate::prepared::test_common as common;
    use crate::verifier::{CircuitTablesAir, ReconstructedBatchTables, VerificationError};

    fn contains_constant<F: Field + Copy>(
        expression: &SymbolicExpr<BaseLeaf<F>>,
        value: F,
    ) -> bool {
        match expression {
            SymbolicExpr::Leaf(BaseLeaf::Constant(constant)) => *constant == value,
            SymbolicExpr::Leaf(_) => false,
            SymbolicExpr::Add { x, y, .. }
            | SymbolicExpr::Sub { x, y, .. }
            | SymbolicExpr::Mul { x, y, .. } => {
                contains_constant(x, value) || contains_constant(y, value)
            }
            SymbolicExpr::Neg { x, .. } => contains_constant(x, value),
        }
    }

    fn opened(trace_local: usize, trace_next: Option<usize>) -> OpenedValuesShape {
        OpenedValuesShape {
            trace_local,
            trace_next,
            preprocessed_local: None,
            preprocessed_next: None,
            quotient_chunks: vec![1, 3],
            random: None,
        }
    }

    fn contract() -> InputContract<u32, usize, usize> {
        InputContract::Batch(Box::new(BatchInputContract {
            degree_bits: vec![8, 9],
            public_inputs: vec![1, 3],
            commitments: CommitmentsShape {
                main: 2,
                permutation: Some(2),
                quotient_chunks: 2,
                random: None,
            },
            opened_values: vec![OpenedValuesWithLookupsShape {
                base: opened(2, Some(3)),
                permutation_local: 1,
                permutation_next: 2,
            }],
            lookup_terminals: vec![true],
            opening: 7,
            table_packing: TablePacking::new(2, 4)
                .with_horner_pack_k(3)
                .with_min_trace_height(8)
                .with_alu_min_height(16)
                .with_public_min_height(16)
                .with_const_min_height(16)
                .with_npo_lanes(NpoTypeId::new("plugin"), 2)
                .with_npo_min_height(NpoTypeId::new("plugin"), 16)
                .with_strict_heights(),
            rows: RowCounts::new([8, 16, 32]),
            alu_variant: AirVariant::Optimized,
            ext_degree: 4,
            w_binomial: Some(11),
            alu_quintic_trinomial: false,
            non_primitives: vec![
                NonPrimitiveContract {
                    op_type: NpoTypeId::new("plugin"),
                    rows: 64,
                    lanes: 2,
                    air_variant: AirVariant::Baseline,
                    public_values: vec![5, 6],
                },
                NonPrimitiveContract {
                    op_type: NpoTypeId::new("plugin-2"),
                    rows: 32,
                    lanes: 1,
                    air_variant: AirVariant::Optimized,
                    public_values: vec![7],
                },
            ],
            preprocessed: Some(GlobalPreprocessedShape {
                commitment: 2,
                instances: vec![
                    Some(PreprocessedInstanceShape {
                        matrix_index: 0,
                        width: 4,
                        degree_bits: 8,
                    }),
                    None,
                ],
                matrix_to_instance: vec![0],
            }),
        }))
    }

    fn assert_component(
        expected: &InputContract<u32, usize, usize>,
        actual: &InputContract<u32, usize, usize>,
        component: &'static str,
    ) {
        assert!(matches!(
            compare_input_contract(expected, actual),
            Err(VerificationError::PreparedInputMismatch { component: got }) if got == component
        ));
    }

    #[test]
    fn equal_total_public_and_opening_partitions_do_not_collide() {
        let expected = contract();
        let mut actual = expected.clone();
        let InputContract::Batch(actual) = &mut actual else {
            unreachable!()
        };
        actual.public_inputs = vec![2, 2];
        assert_component(
            &expected,
            &InputContract::Batch(actual.clone()),
            "input.public_inputs",
        );

        let mut actual = expected.clone();
        let InputContract::Batch(actual) = &mut actual else {
            unreachable!()
        };
        actual.opened_values[0].base.trace_local = 3;
        actual.opened_values[0].base.trace_next = Some(2);
        actual.opened_values[0].base.quotient_chunks = vec![2, 2];
        assert_component(
            &expected,
            &InputContract::Batch(actual.clone()),
            "input.opened_values",
        );
    }

    #[test]
    fn optionality_degrees_and_terminals_are_bound() {
        let expected = contract();
        let mut actual = expected.clone();
        let InputContract::Batch(actual) = &mut actual else {
            unreachable!()
        };
        actual.degree_bits[0] += 1;
        assert_component(
            &expected,
            &InputContract::Batch(actual.clone()),
            "input.degree_bits",
        );

        let mut actual = expected.clone();
        let InputContract::Batch(actual) = &mut actual else {
            unreachable!()
        };
        actual.opened_values[0].base.preprocessed_local = Some(0);
        actual.opened_values[0].base.random = Some(0);
        assert_component(
            &expected,
            &InputContract::Batch(actual.clone()),
            "input.opened_values",
        );

        let mut actual = expected.clone();
        let InputContract::Batch(actual) = &mut actual else {
            unreachable!()
        };
        actual.lookup_terminals[0] = false;
        assert_component(
            &expected,
            &InputContract::Batch(actual.clone()),
            "input.opened_values",
        );
    }

    #[test]
    fn all_batch_compile_metadata_is_bound() {
        type Mutation = fn(&mut BatchInputContract<u32, usize, usize>);

        let expected = contract();
        let mutations: [Mutation; 16] = [
            |c| c.rows = RowCounts::new([16, 16, 32]),
            |c| c.table_packing = TablePacking::new(1, 4),
            |c| c.table_packing = c.table_packing.clone().with_min_trace_height(32),
            |c| c.table_packing = c.table_packing.clone().with_public_alu_lanes(3, 4),
            |c| c.table_packing = c.table_packing.clone().with_horner_pack_k(4),
            |c| c.alu_variant = AirVariant::Baseline,
            |c| c.ext_degree = 5,
            |c| c.w_binomial = Some(12),
            |c| c.alu_quintic_trinomial = true,
            |c| c.non_primitives[0].op_type = NpoTypeId::new("changed"),
            |c| c.non_primitives[0].rows += 1,
            |c| c.non_primitives[0].lanes += 1,
            |c| c.non_primitives[0].air_variant = AirVariant::Optimized,
            |c| c.non_primitives[0].public_values[0] += 1,
            |c| c.non_primitives.swap(0, 1),
            |c| {
                c.table_packing = TablePacking::new(2, 4)
                    .with_horner_pack_k(3)
                    .with_min_trace_height(8)
                    .with_alu_min_height(16)
                    .with_public_min_height(16)
                    .with_const_min_height(16)
                    .with_npo_lanes(NpoTypeId::new("plugin"), 2)
                    .with_npo_min_height(NpoTypeId::new("plugin"), 16);
            },
        ];
        for mutate in mutations {
            let mut actual = expected.clone();
            let InputContract::Batch(actual) = &mut actual else {
                unreachable!()
            };
            mutate(actual);
            assert_component(
                &expected,
                &InputContract::Batch(actual.clone()),
                "input.metadata",
            );
        }
    }

    #[test]
    fn exact_preprocessed_mapping_and_metadata_are_bound() {
        let expected = contract();
        let mutations: [fn(&mut GlobalPreprocessedShape<usize>); 4] = [
            |p| p.matrix_to_instance = vec![1],
            |p| p.instances[0].as_mut().unwrap().matrix_index = 1,
            |p| p.instances[0].as_mut().unwrap().width += 1,
            |p| p.instances[0].as_mut().unwrap().degree_bits += 1,
        ];
        for mutate in mutations {
            let mut actual = expected.clone();
            let InputContract::Batch(actual) = &mut actual else {
                unreachable!()
            };
            mutate(actual.preprocessed.as_mut().unwrap());
            assert_component(
                &expected,
                &InputContract::Batch(actual.clone()),
                "input.preprocessed",
            );
        }

        let mut actual = expected.clone();
        let InputContract::Batch(actual) = &mut actual else {
            unreachable!()
        };
        actual.preprocessed = None;
        assert_component(
            &expected,
            &InputContract::Batch(actual.clone()),
            "input.preprocessed",
        );
    }

    #[test]
    fn raw_batch_cardinality_guard_precedes_plugin_factory() {
        type Config = common::KoalaBearD4RecursionConfig;

        let mut fixture = common::build_koala_bear_d4_first_layer_input();
        fixture.base_proof.proof.degree_bits.pop();
        let source = fixture.recursion_input();
        let mut factory_calls = 0;
        let result = capture_builtin_input_contract::<
            Config,
            crate::recursion::BatchOnly,
            <Config as crate::backend::fri::FriRecursionConfig>::Commitment,
            <Config as crate::backend::fri::FriRecursionConfig>::OpeningProof,
        >(&fixture.layer_config, &source, false, |_| {
            factory_calls += 1;
            panic!("plugin factory must remain lazy until raw shape validation succeeds")
        });

        assert!(matches!(
            result,
            Err(VerificationError::InvalidProofShape(_))
        ));
        assert_eq!(factory_calls, 0);
    }

    #[derive(Clone)]
    struct ManifestConstantAir<F> {
        constant: F,
    }

    impl<F: Field + Copy> BaseAir<F> for ManifestConstantAir<F> {
        fn width(&self) -> usize {
            1
        }

        fn num_public_values(&self) -> usize {
            1
        }
    }

    impl<F, AB> Air<AB> for ManifestConstantAir<F>
    where
        F: Field + Copy,
        AB: AirBuilder<F = F>,
    {
        fn eval(&self, builder: &mut AB) {
            let main = builder.main();
            let local = main.current_slice();
            builder.assert_eq(local[0], self.constant);
        }
    }

    impl<SC> BatchAir<SC> for ManifestConstantAir<Val<SC>>
    where
        SC: StarkGenericConfig,
        Val<SC>: Field + Copy,
        SymbolicExpressionExt<Val<SC>, SC::Challenge>:
            Algebra<SymbolicExpression<Val<SC>>> + Algebra<SC::Challenge>,
    {
    }

    struct ManifestConstantPlugin;

    impl<SC> TableProver<SC> for ManifestConstantPlugin
    where
        SC: StarkGenericConfig + 'static,
        Val<SC>: Field + Copy,
        SymbolicExpressionExt<Val<SC>, SC::Challenge>:
            Algebra<SymbolicExpression<Val<SC>>> + Algebra<SC::Challenge>,
    {
        fn op_type(&self) -> NpoTypeId {
            NpoTypeId::new("manifest-constant")
        }

        fn batch_instance_d1(
            &self,
            _config: &SC,
            _packing: &TablePacking,
            _traces: &Traces<Val<SC>>,
        ) -> Option<BatchTableInstance<SC>> {
            panic!("manifest reconstruction test must not build proving instances")
        }

        fn batch_instance_d2(
            &self,
            _config: &SC,
            _packing: &TablePacking,
            _traces: &Traces<BinomialExtensionField<Val<SC>, 2>>,
        ) -> Option<BatchTableInstance<SC>> {
            panic!("manifest reconstruction test must not build proving instances")
        }

        fn batch_instance_d4(
            &self,
            _config: &SC,
            _packing: &TablePacking,
            _traces: &Traces<BinomialExtensionField<Val<SC>, 4>>,
        ) -> Option<BatchTableInstance<SC>> {
            panic!("manifest reconstruction test must not build proving instances")
        }

        fn batch_instance_d6(
            &self,
            _config: &SC,
            _packing: &TablePacking,
            _traces: &Traces<BinomialExtensionField<Val<SC>, 6>>,
        ) -> Option<BatchTableInstance<SC>> {
            panic!("manifest reconstruction test must not build proving instances")
        }

        fn batch_instance_d8(
            &self,
            _config: &SC,
            _packing: &TablePacking,
            _traces: &Traces<BinomialExtensionField<Val<SC>, 8>>,
        ) -> Option<BatchTableInstance<SC>> {
            panic!("manifest reconstruction test must not build proving instances")
        }

        fn batch_instance_d5(
            &self,
            _config: &SC,
            _packing: &TablePacking,
            _traces: &Traces<QuinticTrinomialExtensionField<Val<SC>>>,
        ) -> Option<BatchTableInstance<SC>> {
            panic!("manifest reconstruction test must not build proving instances")
        }

        fn batch_air_from_table_entry(
            &self,
            _config: &SC,
            _degree: usize,
            _circuit_extension_degree: u32,
            table_entry: &NonPrimitiveTableEntry<SC>,
        ) -> Result<DynamicAirEntry<SC>, alloc::string::String> {
            let [constant] = table_entry.public_values.as_slice() else {
                return Err("expected one manifest constant".into());
            };
            Ok(DynamicAirEntry::new(Box::new(ManifestConstantAir {
                constant: *constant,
            })))
        }
    }

    #[test]
    fn reconstructed_manifest_public_value_is_pinned_and_used_as_an_air_constant() {
        type Config = common::KoalaBearD4RecursionConfig;

        let fixture = common::build_koala_bear_d4_first_layer_input();
        let constant = Val::<Config>::from_u64(7);
        let entry = NonPrimitiveTableEntry::<Config> {
            op_type: NpoTypeId::new("manifest-constant"),
            rows: 8,
            lanes: 1,
            public_values: vec![constant],
            air_variant: AirVariant::Baseline,
        };
        let air = ManifestConstantPlugin
            .batch_air_from_table_entry(&fixture.layer_config, 4, 4, &entry)
            .unwrap();
        let changed_entry = NonPrimitiveTableEntry::<Config> {
            op_type: NpoTypeId::new("manifest-constant"),
            rows: 8,
            lanes: 1,
            public_values: vec![Val::<Config>::from_u64(8)],
            air_variant: AirVariant::Baseline,
        };
        let changed_air = ManifestConstantPlugin
            .batch_air_from_table_entry(&fixture.layer_config, 4, 4, &changed_entry)
            .unwrap();
        let (constraints, extension_constraints) =
            p3_batch_stark::symbolic::get_symbolic_constraints::<
                Val<Config>,
                <Config as StarkGenericConfig>::Challenge,
                _,
                LogUpGadget,
            >(&air, AirLayout::from_air(&air), &[], &LogUpGadget::new());
        let (changed_constraints, changed_extension_constraints) =
            p3_batch_stark::symbolic::get_symbolic_constraints::<
                Val<Config>,
                <Config as StarkGenericConfig>::Challenge,
                _,
                LogUpGadget,
            >(
                &changed_air,
                AirLayout::from_air(&changed_air),
                &[],
                &LogUpGadget::new(),
            );
        assert_eq!(constraints.len(), 1);
        assert!(extension_constraints.is_empty());
        assert!(changed_extension_constraints.is_empty());
        assert!(contains_constant(&constraints[0], constant));
        assert!(!contains_constant(
            &constraints[0],
            Val::<Config>::from_u64(8)
        ));
        assert!(contains_constant(
            &changed_constraints[0],
            Val::<Config>::from_u64(8)
        ));
        assert!(!contains_constant(&changed_constraints[0], constant));

        let reconstructed = ReconstructedBatchTables::<Config, 4> {
            airs: vec![CircuitTablesAir::Dynamic(air)],
            trace_lens: vec![entry.rows],
            public_values: vec![vec![constant]],
        };
        validate_reconstructed_public_inputs(&reconstructed, &[vec![constant]])
            .expect("the manifest value and AIR public arity agree");
        assert!(matches!(
            validate_reconstructed_public_inputs(
                &reconstructed,
                &[vec![Val::<Config>::from_u64(8)]],
            ),
            Err(VerificationError::InvalidProofShape(_))
        ));
    }
}
