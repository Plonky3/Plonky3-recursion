use alloc::string::{String, ToString};
use alloc::vec::Vec;
use alloc::{format, vec};

use hashbrown::HashMap;
use p3_air::{
    Air as P3Air, AirBuilder, AirBuilderWithPublicValues, BaseAir as P3BaseAir,
    PermutationAirBuilder,
};
use p3_batch_stark::CommonData;
use p3_circuit::CircuitBuilder;
use p3_circuit::utils::ColumnsTargets;
use p3_circuit_prover::air::{AddAir, ConstAir, MulAir, PublicAir, WitnessAir};
use p3_circuit_prover::batch_stark_prover::{PrimitiveTable, RowCounts};
use p3_commit::{Pcs, PolynomialSpace};
use p3_field::{BasedVectorSpace, Field, PrimeCharacteristicRing, PrimeField};
use p3_lookup::lookup_traits::{Kind, Lookup, LookupData, LookupGadget};
use p3_uni_stark::{StarkGenericConfig, SymbolicExpression, Val};

use super::{ObservableCommitment, VerificationError, recompose_quotient_from_chunks_circuit};
use crate::challenger::CircuitChallenger;
use crate::traits::{
    LookupMetadata, Recursive, RecursiveAir, RecursiveChallenger, RecursiveLookupGadget,
    RecursivePcs,
};
use crate::types::{BatchProofTargets, CommonDataTargets, OpenedValuesTargets};
use crate::{BatchStarkVerifierInputsBuilder, Target};

/// Type alias for PCS verifier parameters.
pub type PcsVerifierParams<SC, InputProof, OpeningProof, Comm> =
    <<SC as StarkGenericConfig>::Pcs as RecursivePcs<
        SC,
        InputProof,
        OpeningProof,
        Comm,
        <<SC as StarkGenericConfig>::Pcs as Pcs<
            <SC as StarkGenericConfig>::Challenge,
            <SC as StarkGenericConfig>::Challenger,
        >>::Domain,
    >>::VerifierParams;

// TODO(Robin): Remove with dynamic dispatch
/// Wrapper enum for heterogeneous circuit table AIRs used by circuit-prover tables.
pub enum CircuitTablesAir<F: Field, const D: usize> {
    Witness(WitnessAir<F, D>),
    Const(ConstAir<F, D>),
    Public(PublicAir<F, D>),
    Add(AddAir<F, D>),
    Mul(MulAir<F, D>),
}

impl<F: Field, const D: usize> P3BaseAir<F> for CircuitTablesAir<F, D> {
    fn width(&self) -> usize {
        match self {
            Self::Witness(a) => P3BaseAir::width(a),
            Self::Const(a) => P3BaseAir::width(a),
            Self::Public(a) => P3BaseAir::width(a),
            Self::Add(a) => P3BaseAir::width(a),
            Self::Mul(a) => P3BaseAir::width(a),
        }
    }
}

impl<AB, const D: usize> P3Air<AB> for CircuitTablesAir<AB::F, D>
where
    AB: AirBuilder + PermutationAirBuilder + AirBuilderWithPublicValues,
    AB::F: Field,
{
    fn eval(&self, builder: &mut AB) {
        match self {
            Self::Witness(a) => P3Air::eval(a, builder),
            Self::Const(a) => P3Air::eval(a, builder),
            Self::Public(a) => P3Air::eval(a, builder),
            Self::Add(a) => P3Air::eval(a, builder),
            Self::Mul(a) => P3Air::eval(a, builder),
        }
    }

    fn add_lookup_columns(&mut self) -> Vec<usize> {
        match self {
            Self::Witness(a) => P3Air::<AB>::add_lookup_columns(a),
            Self::Const(a) => P3Air::<AB>::add_lookup_columns(a),
            Self::Public(a) => P3Air::<AB>::add_lookup_columns(a),
            Self::Add(a) => P3Air::<AB>::add_lookup_columns(a),
            Self::Mul(a) => P3Air::<AB>::add_lookup_columns(a),
        }
    }

    fn get_lookups(&mut self) -> Vec<p3_lookup::lookup_traits::Lookup<<AB>::F>> {
        match self {
            Self::Witness(a) => P3Air::<AB>::get_lookups(a),
            Self::Const(a) => P3Air::<AB>::get_lookups(a),
            Self::Public(a) => P3Air::<AB>::get_lookups(a),
            Self::Add(a) => P3Air::<AB>::get_lookups(a),
            Self::Mul(a) => P3Air::<AB>::get_lookups(a),
        }
    }
}

/// Build and attach a recursive verifier circuit for a circuit-prover [`BatchStarkProof`].
///
/// This reconstructs the circuit table AIRs from the proof metadata (rows + packing) so callers
/// don't need to pass `circuit_airs` explicitly. Returns the allocated input builder to pack
/// public inputs afterwards.
pub fn verify_p3_recursion_proof_circuit<
    SC: StarkGenericConfig,
    Comm: Recursive<
            SC::Challenge,
            Input = <SC::Pcs as Pcs<SC::Challenge, SC::Challenger>>::Commitment,
        > + Clone
        + ObservableCommitment,
    InputProof: Recursive<SC::Challenge>,
    OpeningProof: Recursive<SC::Challenge, Input = <SC::Pcs as Pcs<SC::Challenge, SC::Challenger>>::Proof>,
    LG: RecursiveLookupGadget<SC::Challenge>,
    const RATE: usize,
    const TRACE_D: usize,
>(
    config: &SC,
    circuit: &mut CircuitBuilder<SC::Challenge>,
    proof: &p3_circuit_prover::batch_stark_prover::BatchStarkProof<SC>,
    pcs_params: &PcsVerifierParams<SC, InputProof, OpeningProof, Comm>,
    common_data: &CommonData<SC>,
    lookup_gadget: &LG,
) -> Result<BatchStarkVerifierInputsBuilder<SC, Comm, OpeningProof>, VerificationError>
where
    <SC as StarkGenericConfig>::Pcs: RecursivePcs<
            SC,
            InputProof,
            OpeningProof,
            Comm,
            <SC::Pcs as Pcs<SC::Challenge, SC::Challenger>>::Domain,
        >,
    SC::Challenge: PrimeCharacteristicRing,
    Val<SC>: PrimeField,
    <<SC as StarkGenericConfig>::Pcs as Pcs<SC::Challenge, SC::Challenger>>::Domain: Clone,
    SymbolicExpression<SC::Challenge>: From<SymbolicExpression<Val<SC>>>,
{
    assert_eq!(proof.ext_degree, TRACE_D, "trace extension degree mismatch");
    let rows: RowCounts = proof.rows;
    let packing = proof.table_packing;
    let witness_lanes = packing.witness_lanes();
    let add_lanes = packing.add_lanes();
    let mul_lanes = packing.mul_lanes();

    let circuit_airs = vec![
        CircuitTablesAir::Witness(WitnessAir::<Val<SC>, TRACE_D>::new(
            rows[PrimitiveTable::Witness],
            witness_lanes,
        )),
        CircuitTablesAir::Const(ConstAir::<Val<SC>, TRACE_D>::new(
            rows[PrimitiveTable::Const],
        )),
        CircuitTablesAir::Public(PublicAir::<Val<SC>, TRACE_D>::new(
            rows[PrimitiveTable::Public],
        )),
        CircuitTablesAir::Add(AddAir::<Val<SC>, TRACE_D>::new(
            rows[PrimitiveTable::Add],
            add_lanes,
        )),
        CircuitTablesAir::Mul(MulAir::<Val<SC>, TRACE_D>::new(
            rows[PrimitiveTable::Mul],
            mul_lanes,
        )),
    ];

    // TODO: public values are empty for all circuit tables for now.
    let air_public_counts = vec![0usize; proof.proof.opened_values.instances.len()];
    let verifier_inputs = BatchStarkVerifierInputsBuilder::<SC, Comm, OpeningProof>::allocate(
        circuit,
        &proof.proof,
        common_data,
        &air_public_counts,
    );

    let common = &verifier_inputs.common_data;

    verify_batch_circuit::<
        CircuitTablesAir<Val<SC>, TRACE_D>,
        SC,
        Comm,
        InputProof,
        OpeningProof,
        LG,
        RATE,
    >(
        config,
        &circuit_airs,
        circuit,
        &verifier_inputs.proof_targets,
        &verifier_inputs.air_public_targets,
        pcs_params,
        common,
        lookup_gadget,
    )?;

    Ok(verifier_inputs)
}

/// Verify a batch-STARK proof inside a recursive circuit.
#[allow(clippy::too_many_arguments)]
pub fn verify_batch_circuit<
    A,
    SC: StarkGenericConfig,
    Comm: Recursive<
            SC::Challenge,
            Input = <SC::Pcs as Pcs<SC::Challenge, SC::Challenger>>::Commitment,
        > + Clone
        + ObservableCommitment,
    InputProof: Recursive<SC::Challenge>,
    OpeningProof: Recursive<SC::Challenge>,
    LG: RecursiveLookupGadget<SC::Challenge>,
    const RATE: usize,
>(
    config: &SC,
    airs: &[A],
    circuit: &mut CircuitBuilder<SC::Challenge>,
    proof_targets: &BatchProofTargets<SC, Comm, OpeningProof>,
    public_values: &[Vec<Target>],
    pcs_params: &PcsVerifierParams<SC, InputProof, OpeningProof, Comm>,
    common: &CommonDataTargets<SC, Comm>,
    lookup_gadget: &LG,
) -> Result<(), VerificationError>
where
    A: RecursiveAir<Val<SC>, SC::Challenge, LG>,
    <SC as StarkGenericConfig>::Pcs: RecursivePcs<
            SC,
            InputProof,
            OpeningProof,
            Comm,
            <SC::Pcs as Pcs<SC::Challenge, SC::Challenger>>::Domain,
        >,
    SC::Challenge: PrimeCharacteristicRing,
    <<SC as StarkGenericConfig>::Pcs as Pcs<SC::Challenge, SC::Challenger>>::Domain: Clone,
{
    let BatchProofTargets {
        commitments_targets,
        flattened_opened_values_targets: flattened,
        opened_values_targets,
        opening_proof,
        global_lookup_data,
        degree_bits,
    } = proof_targets;
    let instances = &opened_values_targets.instances;

    //TODO: Add support for ZK mode.
    debug_assert_eq!(config.is_zk(), 0, "batch recursion assumes non-ZK");
    if airs.is_empty() {
        return Err(VerificationError::InvalidProofShape(
            "batch-STARK verification requires at least one instance".to_string(),
        ));
    }

    if airs.len() != instances.len()
        || airs.len() != public_values.len()
        || airs.len() != proof_targets.degree_bits.len()
    {
        return Err(VerificationError::InvalidProofShape(
            "Mismatch between number of AIRs, instances, public values, or degree bits".to_string(),
        ));
    }

    let all_lookups = &common.lookups;

    let pcs = config.pcs();

    if commitments_targets.random_commit.is_some() {
        return Err(VerificationError::InvalidProofShape(
            "Batch-STARK verifier does not support random commitments".to_string(),
        ));
    }

    let n_instances = airs.len();

    // Pre-compute per-instance quotient degrees and preprocessed widths, and validate proof shape.
    let mut preprocessed_widths = Vec::with_capacity(airs.len());
    let mut log_quotient_degrees = Vec::with_capacity(n_instances);
    let mut quotient_degrees = Vec::with_capacity(n_instances);
    for (i, ((air, instance), public_vals)) in airs
        .iter()
        .zip(instances.iter())
        .zip(public_values)
        .enumerate()
    {
        let OpenedValuesTargets {
            trace_local_targets,
            trace_next_targets,
            preprocessed_local_targets,
            preprocessed_next_targets,
            quotient_chunks_targets,
            ..
        } = &instance.opened_values_no_lookups;

        let pre_w = common
            .preprocessed
            .as_ref()
            .and_then(|g| g.instances.instances[i].as_ref().map(|m| m.width))
            .unwrap_or(0);
        preprocessed_widths.push(pre_w);

        let local_prep_len = preprocessed_local_targets.as_ref().map_or(0, |v| v.len());
        let next_prep_len = preprocessed_next_targets.as_ref().map_or(0, |v| v.len());
        if local_prep_len != pre_w || next_prep_len != pre_w {
            return Err(VerificationError::InvalidProofShape(format!(
                "Instance has incorrect preprocessed width: expected {pre_w}, got {local_prep_len} / {next_prep_len}"
            )));
        }
        let air_width = A::width(air);
        if trace_local_targets.len() != air_width || trace_next_targets.len() != air_width {
            return Err(VerificationError::InvalidProofShape(format!(
                "Instance has incorrect trace width: expected {}, got {} / {}",
                air_width,
                trace_local_targets.len(),
                trace_next_targets.len()
            )));
        }

        let log_qd = A::get_log_num_quotient_chunks(
            air,
            pre_w,
            public_vals.len() + global_lookup_data[i].len(), // The expected cumulated values are also public inputs.
            &all_lookups[i],
            &lookup_data_to_pv_index(&global_lookup_data[i], public_vals.len()),
            config.is_zk(),
            lookup_gadget,
        );
        let quotient_degree = 1 << (log_qd + config.is_zk());

        if quotient_chunks_targets.len() != quotient_degree {
            return Err(VerificationError::InvalidProofShape(format!(
                "Instance quotient chunk count mismatch: expected {}, got {}",
                quotient_degree,
                quotient_chunks_targets.len()
            )));
        }

        if quotient_chunks_targets
            .iter()
            .any(|chunk| chunk.len() != SC::Challenge::DIMENSION)
        {
            return Err(VerificationError::InvalidProofShape(format!(
                "Invalid quotient chunk length: expected {}",
                SC::Challenge::DIMENSION
            )));
        }

        log_quotient_degrees.push(log_qd);
        quotient_degrees.push(quotient_degree);
    }

    // Challenger initialisation mirrors the native batch-STARK verifier transcript.
    let mut challenger = CircuitChallenger::<RATE>::new();
    let inst_count_target = circuit.alloc_const(
        SC::Challenge::from_usize(n_instances),
        "number of instances",
    );
    challenger.observe(circuit, inst_count_target);

    for ((&ext_db, quotient_degree), air) in degree_bits
        .iter()
        .zip(quotient_degrees.iter())
        .zip(airs.iter())
    {
        let base_db = ext_db.checked_sub(config.is_zk()).ok_or_else(|| {
            VerificationError::InvalidProofShape(
                "Extended degree bits smaller than ZK adjustment".to_string(),
            )
        })?;
        let base_db_target =
            circuit.alloc_const(SC::Challenge::from_usize(base_db), "base degree bits");
        let ext_db_target =
            circuit.alloc_const(SC::Challenge::from_usize(ext_db), "extended degree bits");
        let width_target =
            circuit.alloc_const(SC::Challenge::from_usize(A::width(air)), "air width");
        let quotient_chunks_target = circuit.alloc_const(
            SC::Challenge::from_usize(*quotient_degree),
            "quotient chunk count",
        );

        challenger.observe(circuit, ext_db_target);
        challenger.observe(circuit, base_db_target);
        challenger.observe(circuit, width_target);
        challenger.observe(circuit, quotient_chunks_target);
    }

    challenger.observe_slice(
        circuit,
        &commitments_targets.trace_targets.to_observation_targets(),
    );
    for pv in public_values {
        challenger.observe_slice(circuit, pv);
    }

    // Observe preprocessed widths for each instance. If a global
    // preprocessed commitment exists, observe it once.
    for &pre_w in preprocessed_widths.iter() {
        let pre_w_target =
            circuit.alloc_const(SC::Challenge::from_usize(pre_w), "preprocessed width");
        challenger.observe(circuit, pre_w_target);
    }
    if let Some(global) = &common.preprocessed {
        challenger.observe_slice(circuit, &global.commitment.to_observation_targets());
    }

    // Validate shape of the lookup commitment.
    let is_lookup = proof_targets
        .commitments_targets
        .permutation_targets
        .is_some();
    if is_lookup != all_lookups.iter().any(|c| !c.is_empty()) {
        return Err(VerificationError::InvalidProofShape(
            "Mismatch between lookup commitment and lookup data".to_string(),
        ));
    }

    // Fetch lookups and sample their challenges.
    let challenges_per_instance =
        get_perm_challenges::<SC, RATE, LG>(circuit, &mut challenger, all_lookups, lookup_gadget);

    // Then, observe the permutation tables, if any.
    if is_lookup {
        challenger.observe_slice(
            circuit,
            &commitments_targets
                .permutation_targets
                .clone()
                .expect("We checked that the commitment exists")
                .to_observation_targets(),
        );
    }

    let alpha = challenger.sample(circuit);

    challenger.observe_slice(
        circuit,
        &commitments_targets
            .quotient_chunks_targets
            .to_observation_targets(),
    );
    let zeta = challenger.sample(circuit);

    // Build per-instance domains.
    let mut trace_domains = Vec::with_capacity(n_instances);
    let mut ext_trace_domains = Vec::with_capacity(n_instances);
    for &ext_db in degree_bits {
        let base_db = ext_db - config.is_zk();
        trace_domains.push(pcs.natural_domain_for_degree(1 << base_db));
        ext_trace_domains.push(pcs.natural_domain_for_degree(1 << ext_db));
    }

    // Collect commitments with opening points for PCS verification.
    let mut coms_to_verify = vec![];

    let trace_round: Vec<_> = ext_trace_domains
        .iter()
        .zip(instances.iter())
        .map(|(ext_dom, inst)| {
            let first_point = pcs.first_point(ext_dom);
            let next_point = ext_dom.next_point(first_point).ok_or_else(|| {
                VerificationError::InvalidProofShape(
                    "Trace domain does not provide next point".to_string(),
                )
            })?;
            let generator = next_point * first_point.inverse();
            let generator_const = circuit.add_const(generator);
            let zeta_next = circuit.mul(zeta, generator_const);
            Ok((
                *ext_dom,
                vec![
                    (
                        zeta,
                        inst.opened_values_no_lookups.trace_local_targets.clone(),
                    ),
                    (
                        zeta_next,
                        inst.opened_values_no_lookups.trace_next_targets.clone(),
                    ),
                ],
            ))
        })
        .collect::<Result<_, VerificationError>>()?;
    coms_to_verify.push((commitments_targets.trace_targets.clone(), trace_round));

    let quotient_domains: Vec<Vec<_>> = degree_bits
        .iter()
        .zip(ext_trace_domains.iter())
        .zip(log_quotient_degrees.iter())
        .map(|((&ext_db, ext_dom), &log_qd)| {
            let base_db = ext_db - config.is_zk();
            let q_domain = ext_dom.create_disjoint_domain(1 << (base_db + log_qd + config.is_zk()));
            q_domain.split_domains(1 << (log_qd + config.is_zk()))
        })
        .collect();

    let mut quotient_round = Vec::new();
    for (domains, inst) in quotient_domains.iter().zip(instances.iter()) {
        if domains.len() != inst.opened_values_no_lookups.quotient_chunks_targets.len() {
            return Err(VerificationError::InvalidProofShape(
                "Quotient chunk count mismatch across domains".to_string(),
            ));
        }
        for (domain, values) in domains
            .iter()
            .zip(inst.opened_values_no_lookups.quotient_chunks_targets.iter())
        {
            quotient_round.push((*domain, vec![(zeta, values.clone())]));
        }
    }
    coms_to_verify.push((
        commitments_targets.quotient_chunks_targets.clone(),
        quotient_round,
    ));

    if let Some(global) = &common.preprocessed {
        let mut pre_round = Vec::with_capacity(global.matrix_to_instance.len());

        for (matrix_index, &inst_idx) in global.matrix_to_instance.iter().enumerate() {
            let pre_w = preprocessed_widths[inst_idx];
            if pre_w == 0 {
                return Err(VerificationError::InvalidProofShape(
                    "Instance has preprocessed columns with zero width".to_string(),
                ));
            }

            let inst = &instances[inst_idx];
            let local = inst
                .opened_values_no_lookups
                .preprocessed_local_targets
                .as_ref()
                .ok_or_else(|| {
                    VerificationError::InvalidProofShape(
                        "Missing preprocessed local columns".to_string(),
                    )
                })?;
            let next = inst
                .opened_values_no_lookups
                .preprocessed_next_targets
                .as_ref()
                .ok_or_else(|| {
                    VerificationError::InvalidProofShape(
                        "Missing preprocessed next columns".to_string(),
                    )
                })?;
            // Validate that the preprocessed data's base degree matches what we expect.
            let ext_db = degree_bits[inst_idx];
            let expected_base_db = ext_db - config.is_zk();

            let meta = global.instances.instances[inst_idx]
                .as_ref()
                .ok_or_else(|| {
                    VerificationError::InvalidProofShape(
                        "Missing preprocessed instance metadata".to_string(),
                    )
                })?;
            if meta.matrix_index != matrix_index || meta.degree_bits != expected_base_db {
                return Err(VerificationError::InvalidProofShape(
                    "Preprocessed instance metadata mismatch".to_string(),
                ));
            }

            let ext_dom = &ext_trace_domains[inst_idx];

            let first_point = pcs.first_point(ext_dom);
            let next_point = ext_dom.next_point(first_point).ok_or_else(|| {
                VerificationError::InvalidProofShape(
                    "Trace domain does not provide next point".to_string(),
                )
            })?;
            let generator = next_point * first_point.inverse();
            let generator_const = circuit.add_const(generator);
            let zeta_next = circuit.mul(zeta, generator_const);

            pre_round.push((
                *ext_dom,
                vec![(zeta, local.clone()), (zeta_next, next.clone())],
            ));
        }

        coms_to_verify.push((global.commitment.clone(), pre_round));
    }

    if is_lookup {
        let permutation_commit = commitments_targets
            .permutation_targets
            .clone()
            .expect("We checked that the commitment exists");

        let mut permutation_round = Vec::new();

        for (i, ext_dom) in ext_trace_domains.iter().enumerate() {
            let inst = &instances[i];
            let permutation_local = &inst.permutation_local_targets;
            let permutation_next = &inst.permutation_next_targets;

            if permutation_local.len() != permutation_next.len() {
                return Err(VerificationError::InvalidProofShape(
                    "Mismatch between the lengths of permutation local and next opened values"
                        .to_string(),
                ));
            }

            if !permutation_local.is_empty() {
                let first_point = pcs.first_point(ext_dom);
                let next_point = ext_dom.next_point(first_point).ok_or_else(|| {
                    VerificationError::InvalidProofShape(
                        "Trace domain does not provide next point".to_string(),
                    )
                })?;
                let generator = next_point * first_point.inverse();
                let generator_const = circuit.add_const(generator);
                let zeta_next = circuit.mul(zeta, generator_const);

                permutation_round.push((
                    *ext_dom,
                    vec![
                        (zeta, permutation_local.clone()),
                        (zeta_next, permutation_next.clone()),
                    ],
                ));
            }
        }

        coms_to_verify.push((permutation_commit, permutation_round));
    }

    let pcs_challenges = SC::Pcs::get_challenges_circuit::<RATE>(
        circuit,
        &mut challenger,
        &proof_targets.opening_proof,
        flattened,
        pcs_params,
    )?;

    pcs.verify_circuit(
        circuit,
        &pcs_challenges,
        &coms_to_verify,
        opening_proof,
        pcs_params,
    )?;

    // Verify AIR constraints per instance.
    for i in 0..n_instances {
        let air = &airs[i];
        let inst = &instances[i];
        let trace_domain = &trace_domains[i];
        let public_vals = &public_values[i];
        let domains = &quotient_domains[i];

        let quotient = recompose_quotient_from_chunks_circuit::<SC, _, _, _, _>(
            circuit,
            domains,
            &inst.opened_values_no_lookups.quotient_chunks_targets,
            zeta,
            pcs,
        );

        // Recompose permutation openings from base-flattened columns into extension field columns.
        // The permutation commitment is a base-flattened matrix with `width = aux_width * DIMENSION`.
        // For constraint evaluation, we need an extension field matrix with width `aux_width``.
        let aux_width = all_lookups[i]
            .iter()
            .flat_map(|ctx| ctx.columns.iter().cloned())
            .max()
            .map(|m| m + 1)
            .unwrap_or(0);

        let recompose = |circuit: &mut CircuitBuilder<SC::Challenge>,
                         flat: &[Target]|
         -> Vec<Target> {
            if aux_width == 0 {
                return vec![];
            }
            let ext_degree = SC::Challenge::DIMENSION;
            debug_assert!(
                flat.len() == aux_width * ext_degree,
                "flattened permutation opening length ({}) must equal aux_width ({}) * DIMENSION ({})",
                flat.len(),
                aux_width,
                ext_degree
            );
            // Chunk the flattened coefficients into groups of size `dim`.
            // Each chunk represents the coefficients of one extension field element.
            flat.chunks_exact(ext_degree)
                .map(|coeffs| {
                    let mut sum = circuit.add_const(SC::Challenge::ZERO);
                    // Dot product: sum(coeff_j * basis_j)
                    coeffs.iter().enumerate().for_each(|(j, &coeff)| {
                        let e_i = circuit.add_const(
                            SC::Challenge::ith_basis_element(j)
                                .expect("Basis element should exist"),
                        );
                        let m = circuit.mul(coeff, e_i);
                        sum = circuit.add(sum, m);
                    });
                    sum
                })
                .collect()
        };

        let local_permutation_values = recompose(circuit, &inst.permutation_local_targets);
        let next_permutation_values = recompose(circuit, &inst.permutation_next_targets);

        let local_prep_values = match inst
            .opened_values_no_lookups
            .preprocessed_local_targets
            .as_ref()
        {
            Some(v) => v.as_slice(),
            None => &[],
        };
        let next_prep_values = match inst
            .opened_values_no_lookups
            .preprocessed_next_targets
            .as_ref()
        {
            Some(v) => v.as_slice(),
            None => &[],
        };

        // Add the expected cumulated values to the public values, so that we can use them in the constraints.
        let mut public_vals_with_expected_cumulated = public_vals.clone();
        public_vals_with_expected_cumulated
            .extend(global_lookup_data[i].iter().map(|ld| ld.expected_cumulated));
        let sels = pcs.selectors_at_point_circuit(circuit, trace_domain, &zeta);
        let columns_targets = ColumnsTargets {
            challenges: &challenges_per_instance[i],
            public_values: &public_vals_with_expected_cumulated,
            permutation_local_values: &local_permutation_values,
            permutation_next_values: &next_permutation_values,
            local_prep_values,
            next_prep_values,
            local_values: &inst.opened_values_no_lookups.trace_local_targets,
            next_values: &inst.opened_values_no_lookups.trace_next_targets,
        };

        let lookup_metadata = LookupMetadata {
            contexts: &all_lookups[i],
            lookup_data: &lookup_data_to_pv_index(&global_lookup_data[i], public_vals.len()),
        };
        let folded_constraints = air.eval_folded_circuit(
            circuit,
            &sels,
            &alpha,
            &lookup_metadata,
            columns_targets,
            lookup_gadget,
        );

        let folded_mul = circuit.mul(folded_constraints, sels.inv_vanishing);
        circuit.connect(folded_mul, quotient);

        // Check that the global lookup cumulative values accumulate to the expected value.
        let mut global_cumulative = HashMap::<&String, Vec<_>>::new();
        for data in global_lookup_data.iter().flatten() {
            global_cumulative
                .entry(&data.name)
                .or_default()
                .push(data.expected_cumulated);
        }

        for all_expected_cumulative in global_cumulative.values() {
            lookup_gadget.verify_global_final_value_circuit(circuit, all_expected_cumulative);
        }
    }

    Ok(())
}

pub(crate) fn get_perm_challenges<SC: StarkGenericConfig, const RATE: usize, LG: LookupGadget>(
    circuit: &mut CircuitBuilder<SC::Challenge>,
    challenger: &mut CircuitChallenger<RATE>,
    all_lookups: &[Vec<Lookup<Val<SC>>>],
    lookup_gadget: &LG,
) -> Vec<Vec<Target>> {
    let num_challenges_per_lookup = lookup_gadget.num_challenges();
    let mut global_perm_challenges = HashMap::new();

    all_lookups
        .iter()
        .map(|contexts| {
            // Pre-allocate for the instance's challenges.
            let num_challenges = contexts.len() * num_challenges_per_lookup;
            let mut instance_challenges = Vec::with_capacity(num_challenges);

            for context in contexts {
                match &context.kind {
                    Kind::Global(name) => {
                        // Get or create the global challenges.
                        let challenges: &mut Vec<Target> =
                            global_perm_challenges.entry(name).or_insert_with(|| {
                                (0..num_challenges_per_lookup)
                                    .map(|_| challenger.sample(circuit))
                                    .collect()
                            });
                        instance_challenges.extend_from_slice(challenges);
                    }
                    Kind::Local => {
                        instance_challenges.extend(
                            (0..num_challenges_per_lookup).map(|_| challenger.sample(circuit)),
                        );
                    }
                }
            }
            instance_challenges
        })
        .collect()
}

fn lookup_data_to_pv_index(
    global_lookup_data: &[LookupData<Target>],
    public_values_len: usize,
) -> Vec<LookupData<usize>> {
    global_lookup_data
        .iter()
        .enumerate()
        .map(|(index, ld)| LookupData {
            name: ld.name.clone(),
            aux_idx: ld.aux_idx,
            expected_cumulated: public_values_len + index,
        })
        .collect::<Vec<_>>()
}
