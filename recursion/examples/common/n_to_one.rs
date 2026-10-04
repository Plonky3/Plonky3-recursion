//! Example-local N-to-1 aggregation over batch proofs.

use p3_batch_stark::BatchProof;
use p3_circuit_prover::PreparedCircuitProver;
use p3_circuit_prover::batch_stark_prover::ProvingMaybeSend;
use p3_field::BasedVectorSpace;
use p3_maybe_rayon::prelude::*;
use p3_recursion::{PreparedPcsRecursionBackend, VerifierCircuitResult};

use super::common::*;

struct PreparedGroup<InSC, OutSC, B, const D: usize>
where
    InSC: StarkGenericConfig,
    OutSC: StarkGenericConfig<Challenge = InSC::Challenge> + 'static,
    B: PreparedPcsRecursionBackend<InSC, BatchOnly, D>,
{
    circuit: Circuit<InSC::Challenge>,
    results: Vec<<B as PcsRecursionBackend<InSC, BatchOnly, D>>::VerifierResult>,
    contracts: Vec<B::InputContract>,
    prover: PreparedCircuitProver<OutSC>,
    profile: Option<RecursionLayerProfile>,
}

/// Prepare once per level, rebuilding only for groups with incompatible input shapes.
/// The first proof runs alone to warm the DFT caches before concurrent proving.
#[allow(clippy::too_many_arguments)]
pub(super) fn aggregate_level<InSC, OutSC, B, const D: usize>(
    proofs: &[RecursionOutput<InSC>],
    arity: usize,
    input_config: &InSC,
    output_config: &OutSC,
    backend: &B,
    params: &ProveNextLayerParams,
    concurrent: bool,
    profile_seed: Option<&RecursionLayerProfile>,
) -> Result<(Vec<RecursionOutput<OutSC>>, Option<RecursionLayerProfile>), VerificationError>
where
    InSC: StarkGenericConfig + Send + Sync + Clone + 'static,
    OutSC: StarkGenericConfig<Challenge = InSC::Challenge> + Send + Sync + Clone + 'static,
    B: PreparedPcsRecursionBackend<InSC, BatchOnly, D>
        + PcsRecursionBackend<OutSC, BatchOnly, D>
        + Sync,
    B::InputContract: Sync,
    <B as PcsRecursionBackend<InSC, BatchOnly, D>>::VerifierResult: Sync,
    Val<InSC>: PrimeField64 + StarkField,
    Val<OutSC>: PrimeField64 + StarkField,
    InSC::Challenge: BasedVectorSpace<Val<InSC>>
        + From<Val<InSC>>
        + ExtensionField<Val<InSC>>
        + ExtractBinomialW<Val<InSC>>
        + BasedVectorSpace<Val<OutSC>>
        + From<Val<OutSC>>
        + ExtensionField<Val<OutSC>>
        + ExtractBinomialW<Val<OutSC>>,
    SymbolicExpressionExt<Val<OutSC>, OutSC::Challenge>:
        Algebra<SymbolicExpression<Val<OutSC>>> + Algebra<OutSC::Challenge>,
    OutSC::Challenger: p3_challenger::GrindingChallenger<Witness = Val<OutSC>>,
    BatchProof<OutSC>: ProvingMaybeSend,
    p3_uni_stark::PcsProverError<OutSC>: Send,
    <OutSC::Pcs as Pcs<OutSC::Challenge, OutSC::Challenger>>::Domain: Send + Sync,
    OutSC::Pcs: Sync,
    <OutSC::Pcs as Pcs<OutSC::Challenge, OutSC::Challenger>>::ProverData: Send + Sync,
    <OutSC::Pcs as Pcs<OutSC::Challenge, OutSC::Challenger>>::Commitment: Send + Sync,
    RecursionOutput<InSC>: Sync,
    RecursionOutput<OutSC>: Send,
{
    assert!(arity >= 2 && !proofs.is_empty() && proofs.len().is_multiple_of(arity));

    let prepare_group = |group: &[RecursionOutput<InSC>]| {
        let inputs: Vec<_> = group
            .iter()
            .map(RecursionOutput::into_recursion_input::<BatchOnly>)
            .collect();
        let (circuit, results, contracts) = {
            let _span = tracing::info_span!("build_aggregation_layer_circuit").entered();
            for input in &inputs {
                <B as PcsRecursionBackend<InSC, BatchOnly, D>>::preflight_input(
                    backend,
                    input_config,
                    input,
                )?;
                backend.validate_input(input_config, input)?;
            }
            let contracts = inputs
                .iter()
                .map(|input| backend.capture_input_contract(input_config, input))
                .collect::<Result<Vec<_>, _>>()?;
            let mut builder = CircuitBuilder::new();
            backend.prepare_circuit(input_config, &mut builder)?;
            let results = inputs
                .iter()
                .map(|input| backend.build_verifier_circuit(input, input_config, &mut builder))
                .collect::<Result<Vec<_>, _>>()?;
            let circuit = builder.build().map_err(VerificationError::CircuitBuilder)?;
            (circuit, results, contracts)
        };

        let profile = profile_seed.cloned().map(|seed| {
            solve_fixed_point_for_circuit::<OutSC, BatchOnly, B, D>(seed, &circuit, backend, 8)
        });
        let packing = profile
            .as_ref()
            .map_or(&params.table_packing, |p| &p.table_packing);
        let constraint_profile = profile
            .as_ref()
            .map_or(params.constraint_profile, |p| p.constraint_profile);
        let prover = {
            let _span = tracing::info_span!("build_next_layer_prep").entered();
            let mut prover = BatchStarkProver::new(output_config.clone())
                .with_table_packing(packing.clone())
                .with_alu_variant(match constraint_profile {
                    ConstraintProfile::Standard => p3_circuit_prover::AirVariant::Baseline,
                    ConstraintProfile::RecursionOptimized => {
                        p3_circuit_prover::AirVariant::Optimized
                    }
                });
            for table in
                <B as PcsRecursionBackend<OutSC, BatchOnly, D>>::non_primitive_provers(backend, D)
            {
                prover.register_table_prover(table);
            }
            prover
                .prepare_circuit::<OutSC::Challenge, D>(
                    &circuit,
                    &<B as PcsRecursionBackend<OutSC, BatchOnly, D>>::non_primitive_preprocessors(
                        backend,
                    ),
                    &<B as PcsRecursionBackend<OutSC, BatchOnly, D>>::non_primitive_air_builders(
                        backend,
                    ),
                    constraint_profile,
                )
                .map_err(VerificationError::Prover)?
        };
        Ok::<_, VerificationError>(PreparedGroup {
            circuit,
            results,
            contracts,
            prover,
            profile,
        })
    };

    let check_group = |group: &[RecursionOutput<InSC>],
                       owner: &PreparedGroup<InSC, OutSC, B, D>| {
        let tables: Vec<_> = group.iter().map(batch_table_public_inputs).collect();
        let inputs: Vec<_> = group
            .iter()
            .zip(&tables)
            .map(|(proof, table)| batch_prepared_input(proof, table))
            .collect();
        for input in &inputs {
            <B as PreparedPcsRecursionBackend<InSC, BatchOnly, D>>::preflight_input(
                backend,
                input_config,
                input,
            )?;
        }
        for (input, contract) in inputs.iter().zip(&owner.contracts) {
            backend.validate_prepared_input(input_config, contract, input)?;
        }
        Ok::<_, VerificationError>(())
    };

    let prove_group = |group: &[RecursionOutput<InSC>],
                       owner: &PreparedGroup<InSC, OutSC, B, D>| {
        let output = {
            let _span = tracing::info_span!("prove_aggregation_layer").entered();
            let inputs: Vec<_> = group
                .iter()
                .map(RecursionOutput::into_recursion_input::<BatchOnly>)
                .collect();
            let mut public_inputs = Vec::new();
            let mut private_inputs = Vec::new();
            for (input, result) in inputs.iter().zip(&owner.results) {
                public_inputs.extend(result.pack_public_inputs(input)?);
                private_inputs.extend(result.pack_private_inputs(input)?);
            }
            let mut runner = owner.circuit.runner();
            runner
                .set_public_inputs(&public_inputs)
                .map_err(VerificationError::Circuit)?;
            runner
                .set_private_inputs(&private_inputs)
                .map_err(VerificationError::Circuit)?;
            for (input, result) in inputs.iter().zip(&owner.results) {
                backend
                    .set_private_data_for_result(input_config, &mut runner, result, input)
                    .map_err(|error| VerificationError::InvalidProofShape(error.into()))?;
            }
            let traces = runner.run().map_err(VerificationError::Circuit)?;
            let (proof, data) = owner
                .prover
                .prove_with_legacy_data(&traces)
                .map_err(VerificationError::Prover)?;
            RecursionOutput(proof, data)
        };
        report_proof_size(&output.0);
        owner
            .prover
            .verifier()
            .verify(&output.0, &[])
            .map_err(VerificationError::Prover)?;
        Ok::<_, VerificationError>(output)
    };

    let groups: Vec<_> = proofs.chunks_exact(arity).collect();
    let owner = prepare_group(groups[0])?;
    check_group(groups[0], &owner)?;
    let mut outputs = vec![prove_group(groups[0], &owner)?];
    let prove_remaining = |group: &&[RecursionOutput<InSC>]| match check_group(group, &owner) {
        Ok(()) => prove_group(group, &owner),
        Err(error) if is_prepared_input_mismatch(&error) => {
            let replacement = prepare_group(group)?;
            check_group(group, &replacement)?;
            prove_group(group, &replacement)
        }
        Err(error) => Err(error),
    };
    let rest = if concurrent {
        groups[1..]
            .par_iter()
            .map(prove_remaining)
            .collect::<Result<Vec<_>, _>>()?
    } else {
        groups[1..]
            .iter()
            .map(prove_remaining)
            .collect::<Result<Vec<_>, _>>()?
    };
    outputs.extend(rest);
    Ok((outputs, owner.profile))
}

#[cfg(test)]
mod tests {
    use p3_koala_bear::KoalaBear;
    use p3_recursion::VerifierLimits;
    use p3_recursion::builtin_config::{
        FriConfigV1, KoalaBearD4Poseidon2BinaryConfig, SuiteIdV1, koala_bear_d4_poseidon2_binary,
    };

    use super::*;

    fn leaves(
        count: u32,
    ) -> (
        KoalaBearD4Poseidon2BinaryConfig,
        Vec<RecursionOutput<KoalaBearD4Poseidon2BinaryConfig>>,
    ) {
        let descriptor = FriConfigV1::new(
            SuiteIdV1::KoalaBearD4Poseidon2BinaryFri,
            1,
            0,
            2,
            2,
            0,
            0,
            0,
            0,
            0,
            0,
        );
        let config =
            koala_bear_d4_poseidon2_binary(&descriptor, &VerifierLimits::default()).unwrap();
        let proofs = (1..=count)
            .map(|value| {
                let mut builder = CircuitBuilder::new();
                let constant = builder.alloc_const(KoalaBear::from_u32(value), "constant");
                let expected = builder.alloc_public_input("expected");
                builder.connect(constant, expected);
                let circuit = builder.build().unwrap();
                let prepared = BatchStarkProver::new(config.clone())
                    .with_table_packing(TablePacking::new(1, 1).with_min_trace_height(4))
                    .prepare_circuit::<KoalaBear, 1>(
                        &circuit,
                        &[],
                        &[],
                        ConstraintProfile::Standard,
                    )
                    .unwrap();
                let mut runner = circuit.runner();
                runner
                    .set_public_inputs(&[KoalaBear::from_u32(value)])
                    .unwrap();
                let traces = runner.run().unwrap();
                let (proof, data) = prepared.prove_with_legacy_data(&traces).unwrap();
                RecursionOutput(proof, data)
            })
            .collect();
        (config, proofs)
    }

    #[test]
    fn aggregates_three_distinct_children_per_circuit_with_shared_preparation() {
        let (config, proofs) = leaves(6);
        let backend = FriRecursionBackend::<16, 8>::new(Poseidon2Config::KOALA_BEAR_D4_W16)
            .for_extension_degree::<4>();
        let params = ProveNextLayerParams {
            table_packing: TablePacking::new(2, 2).with_min_trace_height(4),
            constraint_profile: ConstraintProfile::Standard,
        };
        let (outputs, _) = aggregate_level::<_, _, _, 4>(
            &proofs, 3, &config, &config, &backend, &params, true, None,
        )
        .unwrap();
        assert_eq!(outputs.len(), 2);
        assert!(Arc::ptr_eq(&outputs[0].1, &outputs[1].1));
    }

    #[test]
    fn rejects_a_malformed_third_child() {
        let (config, mut proofs) = leaves(3);
        proofs[2].0.proof.opened_values.instances[0]
            .base_opened_values
            .trace_local
            .pop();
        let backend = FriRecursionBackend::<16, 8>::new(Poseidon2Config::KOALA_BEAR_D4_W16)
            .for_extension_degree::<4>();
        let params = ProveNextLayerParams {
            table_packing: TablePacking::new(2, 2).with_min_trace_height(4),
            constraint_profile: ConstraintProfile::Standard,
        };
        assert!(
            aggregate_level::<_, _, _, 4>(
                &proofs, 3, &config, &config, &backend, &params, false, None,
            )
            .is_err()
        );
    }
}
