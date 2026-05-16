mod common;

use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_baby_bear::default_babybear_poseidon2_16;
use p3_batch_stark::{
    BatchProof, CommonData, ProverData, StarkInstance, prove_batch, verify_batch,
};
use p3_circuit::CircuitBuilder;
use p3_circuit::ops::{generate_poseidon2_trace, generate_recompose_trace};
use p3_field::Field;
use p3_lookup::Lookups;
use p3_lookup::logup::LogUpGadget;
use p3_matrix::dense::RowMajorMatrix;
use p3_poseidon2_circuit_air::BabyBearD4Width16;
use p3_recursion::pcs::MerkleCapTargets;
use p3_recursion::{
    BatchStarkVerifierInputsBuilder, FriVerifierParams, Poseidon2Config, VerificationError,
    verify_batch_circuit,
};
use p3_test_utils::baby_bear_params::*;
use rand::distr::{Distribution, StandardUniform};

use crate::common::{InnerFriGeneric, MulAir};

type InnerFri = InnerFriGeneric<MyConfig, MyHash, MyCompress, DIGEST_ELEMS>;

/// Enum to hold different AIR types for batch verification
#[derive(Clone, Copy)]
enum MixedAir {
    Mul(MulAir),               // has preprocessed columns
    Add(AddAirNoPreprocessed), // doesn't have any preprocessed columns
    Sub(SubAirPartialPreprocessed),
}

impl<Val: Field> BaseAir<Val> for MixedAir
where
    StandardUniform: Distribution<Val>,
{
    fn width(&self) -> usize {
        match self {
            Self::Mul(air) => BaseAir::<Val>::width(air),
            Self::Add(air) => BaseAir::<Val>::width(air),
            Self::Sub(air) => BaseAir::<Val>::width(air),
        }
    }

    fn preprocessed_width(&self) -> usize {
        match self {
            Self::Mul(air) => BaseAir::<Val>::preprocessed_width(air),
            Self::Add(air) => BaseAir::<Val>::preprocessed_width(air),
            Self::Sub(air) => BaseAir::<Val>::preprocessed_width(air),
        }
    }

    fn preprocessed_trace(&self) -> Option<RowMajorMatrix<Val>> {
        match self {
            Self::Mul(air) => BaseAir::<Val>::preprocessed_trace(air),
            Self::Add(air) => BaseAir::<Val>::preprocessed_trace(air),
            Self::Sub(air) => BaseAir::<Val>::preprocessed_trace(air),
        }
    }
}

impl<AB: AirBuilder> Air<AB> for MixedAir
where
    AB::F: Field,
    StandardUniform: Distribution<AB::F>,
{
    fn eval(&self, builder: &mut AB) {
        match self {
            Self::Mul(air) => Air::<AB>::eval(air, builder),
            Self::Add(air) => Air::<AB>::eval(air, builder),
            Self::Sub(air) => Air::<AB>::eval(air, builder),
        }
    }
}

/// AIR that doesn't have preprocessed columns - simple addition of two values
#[derive(Clone, Copy)]
pub struct AddAirNoPreprocessed {
    rows: usize,
}

impl Default for AddAirNoPreprocessed {
    fn default() -> Self {
        Self { rows: 1 << 3 }
    }
}

impl AddAirNoPreprocessed {
    pub fn random_valid_trace<Val: Field>(&self, valid: bool) -> RowMajorMatrix<Val>
    where
        StandardUniform: Distribution<Val>,
    {
        let width = 3; // [a, b, c] columns
        let mut main_trace_values = Val::zero_vec(self.rows * width);

        for row in 0..self.rows {
            let base_idx = row * width;
            let a = Val::from_usize(row);
            let b = Val::from_usize(row + 1);
            main_trace_values[base_idx] = a;
            main_trace_values[base_idx + 1] = b;

            // c = a + b
            main_trace_values[base_idx + 2] = if valid {
                a + b
            } else {
                a + b + Val::ONE // Make invalid
            };
        }

        RowMajorMatrix::new(main_trace_values, width)
    }
}

impl<Val: Field> BaseAir<Val> for AddAirNoPreprocessed
where
    StandardUniform: Distribution<Val>,
{
    fn width(&self) -> usize {
        3 // [a, b, c]
    }

    fn preprocessed_trace(&self) -> Option<RowMajorMatrix<Val>> {
        None // No preprocessed columns
    }
}

impl<AB: AirBuilder> Air<AB> for AddAirNoPreprocessed
where
    AB::F: Field,
    StandardUniform: Distribution<AB::F>,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let main_local = main.current_slice();

        let a = main_local[0];
        let b = main_local[1];
        let c = main_local[2];

        // Constraint: a + b = c
        builder.assert_zero(a + b - c);
    }
}

/// AIR that has some preprocessed columns - subtraction with one preprocessed constant
#[derive(Clone, Copy)]
pub struct SubAirPartialPreprocessed {
    rows: usize,
}

impl Default for SubAirPartialPreprocessed {
    fn default() -> Self {
        Self { rows: 1 << 3 }
    }
}

impl SubAirPartialPreprocessed {
    pub fn random_valid_trace<Val: Field>(
        &self,
        valid: bool,
    ) -> (RowMajorMatrix<Val>, RowMajorMatrix<Val>)
    where
        StandardUniform: Distribution<Val>,
    {
        let main_width = 2; // [a, result] columns
        let prep_width = 1; // [constant] column

        let mut main_trace_values = Val::zero_vec(self.rows * main_width);
        let mut prep_trace_values = Val::zero_vec(self.rows * prep_width);

        for row in 0..self.rows {
            let main_base_idx = row * main_width;
            let prep_base_idx = row * prep_width;

            let a = Val::from_usize(row + 10);
            let constant = Val::from_usize(5); // Preprocessed constant

            main_trace_values[main_base_idx] = a;
            prep_trace_values[prep_base_idx] = constant;

            // result = a - constant
            main_trace_values[main_base_idx + 1] = if valid {
                a - constant
            } else {
                a - constant + Val::ONE // Make invalid
            };
        }

        (
            RowMajorMatrix::new(main_trace_values, main_width),
            RowMajorMatrix::new(prep_trace_values, prep_width),
        )
    }
}

impl<Val: Field> BaseAir<Val> for SubAirPartialPreprocessed
where
    StandardUniform: Distribution<Val>,
{
    fn width(&self) -> usize {
        2 // [a, result]
    }

    fn preprocessed_width(&self) -> usize {
        1 // [constant]
    }

    fn preprocessed_trace(&self) -> Option<RowMajorMatrix<Val>> {
        Some(self.random_valid_trace(true).1)
    }
}

impl<AB: AirBuilder> Air<AB> for SubAirPartialPreprocessed
where
    AB::F: Field,
    StandardUniform: Distribution<AB::F>,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let main_local = main.current_slice();

        let preprocessed = builder.preprocessed().clone();
        let preprocessed_local = preprocessed.current_slice();

        let a = main_local[0];
        let result = main_local[1];
        let constant = preprocessed_local[0];

        // Constraint: a - constant = result
        builder.assert_zero(a - constant - result);
    }
}

/// AIR with public values: constrains `pis[0] == row[0]` on the first row.
#[derive(Clone, Copy)]
struct PublicValueAir {
    rows: usize,
}

impl PublicValueAir {
    fn generate_trace<Val: Field>(&self) -> (RowMajorMatrix<Val>, Vec<Val>) {
        let width = 2;
        let mut values = Val::zero_vec(self.rows * width);
        for row in 0..self.rows {
            let idx = row * width;
            let a = Val::from_usize(row + 42);
            let b = Val::from_usize(row + 1);
            values[idx] = a;
            values[idx + 1] = b;
        }
        let pv = values[0];
        (RowMajorMatrix::new(values, width), vec![pv])
    }
}

impl<Val: Field> BaseAir<Val> for PublicValueAir {
    fn width(&self) -> usize {
        2
    }

    fn num_public_values(&self) -> usize {
        1
    }
}

impl<AB: AirBuilder> Air<AB> for PublicValueAir
where
    AB::F: Field,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local = main.current_slice();
        let pis = builder.public_values();
        let pi0 = pis[0];

        builder.when_first_row().assert_eq(local[0], pi0);
    }
}

#[test]
fn test_batch_verifier_with_mixed_preprocessed() -> Result<(), VerificationError> {
    let n = 1 << 3;

    let scalars = test_fri_scalars();
    let fri_verifier_params = FriVerifierParams::unsafe_arithmetic_only_for_tests(
        scalars.log_blowup,
        scalars.log_final_poly_len,
        scalars.commit_pow_bits,
        scalars.query_pow_bits,
    );
    let config = make_test_config();
    // Same default permutation make_test_config uses, for the recursive verifier circuit.
    let perm = default_babybear_poseidon2_16();

    // Create three different AIRs with different preprocessed column configurations
    let air1 = MulAir { degree: 2, rows: n }; // Has preprocessed columns
    let air2 = AddAirNoPreprocessed { rows: n }; // No preprocessed columns  
    let air3 = SubAirPartialPreprocessed { rows: n }; // Some preprocessed columns

    // Generate valid traces for each AIR
    let trace1 = air1.random_valid_trace(true).0;
    let trace2 = air2.random_valid_trace(true);
    let trace3 = air3.random_valid_trace(true).0;

    // Each AIR has empty public inputs for this test
    let pvs = [vec![], vec![], vec![]];

    // Create MixedAir instances for batch proving
    let mixed_air1: MixedAir = MixedAir::Mul(air1);
    let mixed_air2 = MixedAir::Add(air2);
    let mixed_air3 = MixedAir::Sub(air3);

    // Create StarkInstances for batch proving
    let instances = vec![
        StarkInstance {
            air: &mixed_air1,
            trace: &trace1,
            public_values: pvs[0].clone(),
        },
        StarkInstance {
            air: &mixed_air2,
            trace: &trace2,
            public_values: pvs[1].clone(),
        },
        StarkInstance {
            air: &mixed_air3,
            trace: &trace3,
            public_values: pvs[2].clone(),
        },
    ];

    // Generate prover data and batch proof
    let prover_data = ProverData::from_instances(&config, &instances);
    let lookup_gadget = LogUpGadget::new();
    let batch_proof = prove_batch(&config, &instances, &prover_data);
    let airs = [mixed_air1, mixed_air2, mixed_air3];
    let common_data = &prover_data.common;

    verify_batch(&config, &airs, &batch_proof, &pvs, common_data).unwrap();

    // Create AIRs vector for verification circuit
    let airs = vec![mixed_air1, mixed_air2, mixed_air3];

    // The first and last AIRs have preprocessed columns, the second does not
    assert!(BaseAir::<F>::preprocessed_trace(&airs[0]).is_some());
    assert!(BaseAir::<F>::preprocessed_trace(&airs[1]).is_none());
    assert!(BaseAir::<F>::preprocessed_trace(&airs[2]).is_some());

    let mut circuit_builder = CircuitBuilder::new();
    circuit_builder.enable_poseidon2_perm::<BabyBearD4Width16, _>(
        generate_poseidon2_trace::<Challenge, BabyBearD4Width16>,
        perm,
    );
    circuit_builder.enable_recompose::<F>(generate_recompose_trace::<F, Challenge>);

    // Allocate batch verifier inputs
    let air_public_counts = vec![0usize; batch_proof.opened_values.instances.len()];
    let verifier_inputs = BatchStarkVerifierInputsBuilder::<
        MyConfig,
        MerkleCapTargets<F, DIGEST_ELEMS>,
        InnerFri,
    >::allocate(
        &mut circuit_builder,
        &batch_proof,
        common_data,
        &air_public_counts,
    );

    // Create PCS verifier params from FRI verifier params
    let pcs_verifier_params = fri_verifier_params;

    // Add the batch verification circuit to the builder for the following AIRs:
    // 1. MulAir (has preprocessed columns)
    // 2. AddAirNoPreprocessed (no preprocessed columns)
    // 3. SubAirPartialPreprocessed (some preprocessed columns)
    verify_batch_circuit::<_, _, _, _, _, _, _, WIDTH, RATE>(
        &config,
        &airs,
        &mut circuit_builder,
        &verifier_inputs.proof_targets,
        &verifier_inputs.air_public_targets,
        &pcs_verifier_params,
        &verifier_inputs.common_data,
        &lookup_gadget,
        Poseidon2Config::BABY_BEAR_D4_W16,
    )?;

    // Build the circuit
    let circuit = circuit_builder.build()?;
    let mut runner = circuit.runner();

    // Pack values using the batch builder
    let (public_inputs, private_inputs) =
        verifier_inputs.pack_values(&pvs, &batch_proof, common_data);

    runner
        .set_public_inputs(&public_inputs)
        .map_err(VerificationError::Circuit)?;
    runner
        .set_private_inputs(&private_inputs)
        .map_err(VerificationError::Circuit)?;

    let _traces = runner.run().map_err(VerificationError::Circuit)?;

    Ok(())
}

/// Build the standard 3-AIR mixed-preprocessed batch proof, apply `tamper` to the
/// (otherwise valid) `CommonData` *after* proving but *before* allocating verifier
/// targets, then run `verify_batch_circuit` and return its shape-validation result.
///
/// The circuit is intentionally not built/run: these tests only exercise the
/// up-front `CommonData` length/bounds validation.
fn run_with_tampered_common(
    tamper: impl FnOnce(&mut CommonData<MyConfig>),
) -> Result<(), VerificationError> {
    let n = 1 << 3;

    let scalars = test_fri_scalars();
    let fri_verifier_params = FriVerifierParams::unsafe_arithmetic_only_for_tests(
        scalars.log_blowup,
        scalars.log_final_poly_len,
        scalars.commit_pow_bits,
        scalars.query_pow_bits,
    );
    let config = make_test_config();
    let perm = default_babybear_poseidon2_16();

    let air1 = MulAir { degree: 2, rows: n };
    let air2 = AddAirNoPreprocessed { rows: n };
    let air3 = SubAirPartialPreprocessed { rows: n };

    let trace1 = air1.random_valid_trace(true).0;
    let trace2 = air2.random_valid_trace(true);
    let trace3 = air3.random_valid_trace(true).0;

    let pvs = [vec![], vec![], vec![]];

    let mixed_air1 = MixedAir::Mul(air1);
    let mixed_air2 = MixedAir::Add(air2);
    let mixed_air3 = MixedAir::Sub(air3);

    let instances = vec![
        StarkInstance {
            air: &mixed_air1,
            trace: &trace1,
            public_values: pvs[0].clone(),
        },
        StarkInstance {
            air: &mixed_air2,
            trace: &trace2,
            public_values: pvs[1].clone(),
        },
        StarkInstance {
            air: &mixed_air3,
            trace: &trace3,
            public_values: pvs[2].clone(),
        },
    ];

    let mut prover_data = ProverData::from_instances(&config, &instances);
    let lookup_gadget = LogUpGadget::new();
    let batch_proof = prove_batch(&config, &instances, &prover_data);
    let airs = vec![mixed_air1, mixed_air2, mixed_air3];

    // Corrupt the common data the verifier will bind against.
    tamper(&mut prover_data.common);
    let common_data = &prover_data.common;

    let mut circuit_builder = CircuitBuilder::new();
    circuit_builder.enable_poseidon2_perm::<BabyBearD4Width16, _>(
        generate_poseidon2_trace::<Challenge, BabyBearD4Width16>,
        perm,
    );
    circuit_builder.enable_recompose::<F>(generate_recompose_trace::<F, Challenge>);

    let air_public_counts = vec![0usize; batch_proof.opened_values.instances.len()];
    let verifier_inputs = BatchStarkVerifierInputsBuilder::<
        MyConfig,
        MerkleCapTargets<F, DIGEST_ELEMS>,
        InnerFri,
    >::allocate(
        &mut circuit_builder,
        &batch_proof,
        common_data,
        &air_public_counts,
    );

    let pcs_verifier_params = fri_verifier_params;
    verify_batch_circuit::<_, _, _, _, _, _, _, WIDTH, RATE>(
        &config,
        &airs,
        &mut circuit_builder,
        &verifier_inputs.proof_targets,
        &verifier_inputs.air_public_targets,
        &pcs_verifier_params,
        &verifier_inputs.common_data,
        &lookup_gadget,
        Poseidon2Config::BABY_BEAR_D4_W16,
    )
    .map(|_| ())
}

#[test]
fn test_batch_verifier_accepts_untampered_common() {
    // Sanity: the untampered setup passes the shape validation.
    run_with_tampered_common(|_| {}).expect("untampered CommonData must pass shape validation");
}

#[test]
fn test_batch_verifier_rejects_short_lookup_vector() {
    let err = run_with_tampered_common(|common| {
        common.lookups.pop();
    })
    .expect_err("CommonData with too few lookup entries must be rejected");
    assert!(
        matches!(err, VerificationError::InvalidProofShape(_)),
        "expected InvalidProofShape, got {err:?}"
    );
}

#[test]
fn test_batch_verifier_rejects_long_lookup_vector() {
    let err = run_with_tampered_common(|common| {
        common.lookups.push(Lookups::default());
    })
    .expect_err("CommonData with too many lookup entries must be rejected");
    assert!(
        matches!(err, VerificationError::InvalidProofShape(_)),
        "expected InvalidProofShape, got {err:?}"
    );
}

#[test]
fn test_batch_verifier_rejects_short_preprocessed_metadata() {
    let err = run_with_tampered_common(|common| {
        common
            .preprocessed
            .as_mut()
            .expect("mixed setup has preprocessed data")
            .instances
            .pop();
    })
    .expect_err("CommonData with too-short preprocessed metadata must be rejected");
    assert!(
        matches!(err, VerificationError::InvalidProofShape(_)),
        "expected InvalidProofShape, got {err:?}"
    );
}

#[test]
fn test_batch_verifier_rejects_out_of_bounds_matrix_to_instance() {
    let err = run_with_tampered_common(|common| {
        let global = common
            .preprocessed
            .as_mut()
            .expect("mixed setup has preprocessed data");
        // 3 instances => valid indices are 0..=2; inject an out-of-bounds entry.
        global.matrix_to_instance.push(3);
    })
    .expect_err("CommonData with out-of-bounds matrix_to_instance must be rejected");
    assert!(
        matches!(err, VerificationError::InvalidProofShape(_)),
        "expected InvalidProofShape, got {err:?}"
    );
}

/// Same flow as [`run_with_tampered_common`], but the corruption is applied to the
/// `BatchProof` (the permutation openings are sized from it during target
/// allocation) so we can exercise the permutation-opening width check.
fn run_with_tampered_proof(
    tamper: impl FnOnce(&mut BatchProof<MyConfig>),
) -> Result<(), VerificationError> {
    let n = 1 << 3;

    let scalars = test_fri_scalars();
    let fri_verifier_params = FriVerifierParams::unsafe_arithmetic_only_for_tests(
        scalars.log_blowup,
        scalars.log_final_poly_len,
        scalars.commit_pow_bits,
        scalars.query_pow_bits,
    );
    let config = make_test_config();
    let perm = default_babybear_poseidon2_16();

    let air1 = MulAir { degree: 2, rows: n };
    let air2 = AddAirNoPreprocessed { rows: n };
    let air3 = SubAirPartialPreprocessed { rows: n };

    let trace1 = air1.random_valid_trace(true).0;
    let trace2 = air2.random_valid_trace(true);
    let trace3 = air3.random_valid_trace(true).0;

    let pvs = [vec![], vec![], vec![]];

    let mixed_air1 = MixedAir::Mul(air1);
    let mixed_air2 = MixedAir::Add(air2);
    let mixed_air3 = MixedAir::Sub(air3);

    let instances = vec![
        StarkInstance {
            air: &mixed_air1,
            trace: &trace1,
            public_values: pvs[0].clone(),
        },
        StarkInstance {
            air: &mixed_air2,
            trace: &trace2,
            public_values: pvs[1].clone(),
        },
        StarkInstance {
            air: &mixed_air3,
            trace: &trace3,
            public_values: pvs[2].clone(),
        },
    ];

    let prover_data = ProverData::from_instances(&config, &instances);
    let lookup_gadget = LogUpGadget::new();
    let mut batch_proof = prove_batch(&config, &instances, &prover_data);
    let airs = vec![mixed_air1, mixed_air2, mixed_air3];
    let common_data = &prover_data.common;

    // Corrupt the proof the verifier targets are allocated from.
    tamper(&mut batch_proof);

    let mut circuit_builder = CircuitBuilder::new();
    circuit_builder.enable_poseidon2_perm::<BabyBearD4Width16, _>(
        generate_poseidon2_trace::<Challenge, BabyBearD4Width16>,
        perm,
    );
    circuit_builder.enable_recompose::<F>(generate_recompose_trace::<F, Challenge>);

    let air_public_counts = vec![0usize; batch_proof.opened_values.instances.len()];
    let verifier_inputs = BatchStarkVerifierInputsBuilder::<
        MyConfig,
        MerkleCapTargets<F, DIGEST_ELEMS>,
        InnerFri,
    >::allocate(
        &mut circuit_builder,
        &batch_proof,
        common_data,
        &air_public_counts,
    );

    let pcs_verifier_params = fri_verifier_params;
    verify_batch_circuit::<_, _, _, _, _, _, _, WIDTH, RATE>(
        &config,
        &airs,
        &mut circuit_builder,
        &verifier_inputs.proof_targets,
        &verifier_inputs.air_public_targets,
        &pcs_verifier_params,
        &verifier_inputs.common_data,
        &lookup_gadget,
        Poseidon2Config::BABY_BEAR_D4_W16,
    )
    .map(|_| ())
}

#[test]
fn test_batch_verifier_rejects_extra_local_permutation_coefficients() {
    let err = run_with_tampered_proof(|proof| {
        // These AIRs have no lookups (aux_width == 0), so a valid permutation
        // opening is empty; any extra coefficient must be rejected.
        proof.opened_values.instances[0]
            .permutation_local
            .push(Challenge::ONE);
    })
    .expect_err("extra local permutation coefficients must be rejected");
    assert!(
        matches!(err, VerificationError::InvalidProofShape(_)),
        "expected InvalidProofShape, got {err:?}"
    );
}

#[test]
fn test_batch_verifier_rejects_extra_next_permutation_coefficients() {
    let err = run_with_tampered_proof(|proof| {
        proof.opened_values.instances[2]
            .permutation_next
            .push(Challenge::ONE);
    })
    .expect_err("extra next permutation coefficients must be rejected");
    assert!(
        matches!(err, VerificationError::InvalidProofShape(_)),
        "expected InvalidProofShape, got {err:?}"
    );
}

#[test]
fn test_batch_verifier_with_public_values() -> Result<(), VerificationError> {
    let n = 1 << 3;

    let scalars = test_fri_scalars();
    let fri_verifier_params = FriVerifierParams::unsafe_arithmetic_only_for_tests(
        scalars.log_blowup,
        scalars.log_final_poly_len,
        scalars.commit_pow_bits,
        scalars.query_pow_bits,
    );
    let config = make_test_config();
    // Same default permutation make_test_config uses, for the recursive verifier circuit.
    let perm = default_babybear_poseidon2_16();

    let pv_air = PublicValueAir { rows: n };
    let (pv_trace, pv_vals) = pv_air.generate_trace::<F>();

    let pvs = [pv_vals];

    let instances = vec![StarkInstance {
        air: &pv_air,
        trace: &pv_trace,
        public_values: pvs[0].clone(),
    }];

    let prover_data = ProverData::from_instances(&config, &instances);
    let common_data = &prover_data.common;
    let batch_proof = prove_batch(&config, &instances, &prover_data);

    verify_batch(&config, &[pv_air], &batch_proof, &pvs, common_data).unwrap();

    let lookup_gadget = LogUpGadget::new();

    let mut circuit_builder = CircuitBuilder::new();
    circuit_builder.enable_poseidon2_perm::<BabyBearD4Width16, _>(
        generate_poseidon2_trace::<Challenge, BabyBearD4Width16>,
        perm,
    );
    circuit_builder.enable_recompose::<F>(generate_recompose_trace::<F, Challenge>);

    let air_public_counts = vec![1usize];
    let verifier_inputs = BatchStarkVerifierInputsBuilder::<
        MyConfig,
        MerkleCapTargets<F, DIGEST_ELEMS>,
        InnerFri,
    >::allocate(
        &mut circuit_builder,
        &batch_proof,
        common_data,
        &air_public_counts,
    );

    verify_batch_circuit::<_, _, _, _, _, _, _, WIDTH, RATE>(
        &config,
        &[pv_air],
        &mut circuit_builder,
        &verifier_inputs.proof_targets,
        &verifier_inputs.air_public_targets,
        &fri_verifier_params,
        &verifier_inputs.common_data,
        &lookup_gadget,
        Poseidon2Config::BABY_BEAR_D4_W16,
    )?;

    let circuit = circuit_builder.build()?;
    let mut runner = circuit.runner();

    let (public_inputs, private_inputs) =
        verifier_inputs.pack_values(&pvs, &batch_proof, common_data);

    runner
        .set_public_inputs(&public_inputs)
        .map_err(VerificationError::Circuit)?;
    runner
        .set_private_inputs(&private_inputs)
        .map_err(VerificationError::Circuit)?;

    let _traces = runner.run().map_err(VerificationError::Circuit)?;

    Ok(())
}

#[test]
#[should_panic(expected = "WitnessConflict")]
fn test_batch_verifier_wrong_public_values() {
    let n = 1 << 3;

    let scalars = test_fri_scalars();
    let fri_verifier_params = FriVerifierParams::unsafe_arithmetic_only_for_tests(
        scalars.log_blowup,
        scalars.log_final_poly_len,
        scalars.commit_pow_bits,
        scalars.query_pow_bits,
    );
    let config = make_test_config();
    // Same default permutation make_test_config uses, for the recursive verifier circuit.
    let perm = default_babybear_poseidon2_16();

    let pv_air = PublicValueAir { rows: n };
    let (pv_trace, pv_vals) = pv_air.generate_trace::<F>();

    let pvs = [pv_vals.clone()];

    let instances = vec![StarkInstance {
        air: &pv_air,
        trace: &pv_trace,
        public_values: pvs[0].clone(),
    }];

    let prover_data = ProverData::from_instances(&config, &instances);
    let common_data = &prover_data.common;
    let batch_proof = prove_batch(&config, &instances, &prover_data);

    let lookup_gadget = LogUpGadget::new();

    let mut circuit_builder = CircuitBuilder::new();
    circuit_builder.enable_poseidon2_perm::<BabyBearD4Width16, _>(
        generate_poseidon2_trace::<Challenge, BabyBearD4Width16>,
        perm,
    );
    circuit_builder.enable_recompose::<F>(generate_recompose_trace::<F, Challenge>);

    let air_public_counts = vec![1usize];
    let verifier_inputs = BatchStarkVerifierInputsBuilder::<
        MyConfig,
        MerkleCapTargets<F, DIGEST_ELEMS>,
        InnerFri,
    >::allocate(
        &mut circuit_builder,
        &batch_proof,
        common_data,
        &air_public_counts,
    );

    verify_batch_circuit::<_, _, _, _, _, _, _, WIDTH, RATE>(
        &config,
        &[pv_air],
        &mut circuit_builder,
        &verifier_inputs.proof_targets,
        &verifier_inputs.air_public_targets,
        &fri_verifier_params,
        &verifier_inputs.common_data,
        &lookup_gadget,
        Poseidon2Config::BABY_BEAR_D4_W16,
    )
    .unwrap();

    let circuit = circuit_builder.build().unwrap();
    let mut runner = circuit.runner();

    // Tamper with the public value: provide a wrong value.
    let wrong_pvs: [Vec<F>; 1] = [vec![pv_vals[0] + F::ONE]];

    let (public_inputs, private_inputs) =
        verifier_inputs.pack_values(&wrong_pvs, &batch_proof, common_data);

    runner.set_public_inputs(&public_inputs).unwrap();
    runner.set_private_inputs(&private_inputs).unwrap();

    // Should panic with WitnessConflict because the public value doesn't match the trace.
    runner.run().unwrap();
}
