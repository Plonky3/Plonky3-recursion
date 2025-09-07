use crate::air::{AddAir, ConstAir, MulAir, PublicAir, SubAir, WitnessAir};
use crate::config::{build_standard_config, ProverConfig};
use p3_baby_bear::BabyBear as Val;
use p3_field::{BasedVectorSpace, Field, PrimeCharacteristicRing};
use p3_trace_generator::tables::Traces;
use p3_uni_stark::{prove, verify};

// Re-export the proof type from the config module
pub type StarkProof = p3_uni_stark::Proof<ProverConfig>;

/// Proof for all tables combined
pub struct MultiTableProof {
    pub witness_proof: StarkProof,
    pub const_proof: StarkProof,
    pub public_proof: StarkProof,
    pub add_proof: StarkProof,
    pub mul_proof: StarkProof,
    pub sub_proof: StarkProof,
}

/// Unified prover that creates proofs for all tables
pub struct MultiTableProver {
    config: ProverConfig,
}

impl MultiTableProver {
    pub fn new() -> Self {
        Self {
            config: build_standard_config(),
        }
    }

    /// Prove all tables from the given traces
    /// Supports both base field (D=1) and BabyBear D=4 extension field
    pub fn prove_all_tables<F>(&self, traces: &Traces<F>) -> Result<MultiTableProof, String>
    where
        F: Field + BasedVectorSpace<Val>,
    {
        let pis = vec![];

        // Determine extension degree from field type
        let extension_degree = F::DIMENSION;

        match extension_degree {
            1 => self.prove_base_field(traces, pis),
            4 => self.prove_extension_field_d4(traces, pis),
            _ => Err(format!(
                "Unsupported extension degree: {}",
                extension_degree
            )),
        }
    }

    /// Prove all tables for base field (D=1)
    fn prove_base_field<F>(
        &self,
        traces: &Traces<F>,
        pis: Vec<Val>,
    ) -> Result<MultiTableProof, String>
    where
        F: Field + BasedVectorSpace<Val>,
    {
        // Convert traces to base field coefficients for witness table
        let witness_values: Vec<Val> = traces
            .witness_trace
            .values
            .iter()
            .map(|v| {
                let coeffs = v.as_basis_coefficients_slice();
                assert_eq!(coeffs.len(), 1, "Expected base field");
                coeffs[0]
            })
            .collect();

        // Prove witness table
        let witness_matrix =
            WitnessAir::<Val, 1>::trace_to_matrix(&witness_values, &traces.witness_trace.index);
        let witness_air = WitnessAir::<Val, 1>::new(traces.witness_trace.values.len());
        let witness_proof = prove(&self.config, &witness_air, witness_matrix, &pis);

        // Prove const table
        let const_matrix = ConstAir::<Val, 1>::trace_to_matrix(&traces.const_trace);
        let const_air = ConstAir::<Val, 1>::new(traces.const_trace.values.len());
        let const_proof = prove(&self.config, &const_air, const_matrix, &pis);

        // Prove public table
        let public_matrix = PublicAir::<Val, 1>::trace_to_matrix(&traces.public_trace);
        let public_air = PublicAir::<Val, 1>::new(traces.public_trace.values.len());
        let public_proof = prove(&self.config, &public_air, public_matrix, &pis);

        // Prove add table
        let add_matrix = AddAir::<Val, 1>::trace_to_matrix(&traces.add_trace);
        let add_air = AddAir::<Val, 1>::new(traces.add_trace.lhs_values.len());
        let add_proof = prove(&self.config, &add_air, add_matrix, &pis);

        // Prove mul table (base field, no binomial needed)
        let mul_matrix = MulAir::<Val, 1>::trace_to_matrix(&traces.mul_trace);
        let mul_air = MulAir::<Val, 1>::new(traces.mul_trace.lhs_values.len());
        let mul_proof = prove(&self.config, &mul_air, mul_matrix, &pis);

        // Prove sub table
        let sub_matrix = SubAir::<Val, 1>::trace_to_matrix(&traces.sub_trace);
        let sub_air = SubAir::<Val, 1>::new(traces.sub_trace.lhs_values.len());
        let sub_proof = prove(&self.config, &sub_air, sub_matrix, &pis);

        Ok(MultiTableProof {
            witness_proof,
            const_proof,
            public_proof,
            add_proof: add_proof,
            mul_proof,
            sub_proof,
        })
    }

    /// Prove all tables for BabyBear D=4 extension field
    fn prove_extension_field_d4<F>(
        &self,
        traces: &Traces<F>,
        pis: Vec<Val>,
    ) -> Result<MultiTableProof, String>
    where
        F: Field + BasedVectorSpace<Val>,
    {
        // Convert traces to base field coefficients for witness table
        let mut witness_values: Vec<Val> = Vec::new();
        for value in &traces.witness_trace.values {
            let coeffs = value.as_basis_coefficients_slice();
            assert_eq!(coeffs.len(), 4, "Expected D=4 extension field");
            witness_values.extend_from_slice(coeffs);
        }

        // Prove witness table
        let witness_matrix =
            WitnessAir::<Val, 4>::trace_to_matrix(&witness_values, &traces.witness_trace.index);
        let witness_air = WitnessAir::<Val, 4>::new(traces.witness_trace.values.len());
        let witness_proof = prove(&self.config, &witness_air, witness_matrix, &pis);

        // Prove const table
        let const_matrix = ConstAir::<Val, 4>::trace_to_matrix(&traces.const_trace);
        let const_air = ConstAir::<Val, 4>::new(traces.const_trace.values.len());
        let const_proof = prove(&self.config, &const_air, const_matrix, &pis);

        // Prove public table
        let public_matrix = PublicAir::<Val, 4>::trace_to_matrix(&traces.public_trace);
        let public_air = PublicAir::<Val, 4>::new(traces.public_trace.values.len());
        let public_proof = prove(&self.config, &public_air, public_matrix, &pis);

        // Prove add table
        let add_matrix = AddAir::<Val, 4>::trace_to_matrix(&traces.add_trace);
        let add_air = AddAir::<Val, 4>::new(traces.add_trace.lhs_values.len());
        let add_proof = prove(&self.config, &add_air, add_matrix, &pis);

        // Prove mul table with BabyBear D=4 binomial W=11
        let mul_matrix = MulAir::<Val, 4>::trace_to_matrix(&traces.mul_trace);
        let mul_air =
            MulAir::<Val, 4>::new_binomial(traces.mul_trace.lhs_values.len(), Val::from_u64(11));
        let mul_proof = prove(&self.config, &mul_air, mul_matrix, &pis);

        // Prove sub table
        let sub_matrix = SubAir::<Val, 4>::trace_to_matrix(&traces.sub_trace);
        let sub_air = SubAir::<Val, 4>::new(traces.sub_trace.lhs_values.len());
        let sub_proof = prove(&self.config, &sub_air, sub_matrix, &pis);

        Ok(MultiTableProof {
            witness_proof,
            const_proof,
            public_proof,
            add_proof: add_proof,
            mul_proof,
            sub_proof,
        })
    }

    /// Verify all proofs in the MultiTableProof
    pub fn verify_all_tables<F>(
        &self,
        proof: &MultiTableProof,
        traces: &Traces<F>,
    ) -> Result<(), String>
    where
        F: Field + BasedVectorSpace<Val>,
    {
        let pis = vec![];
        let extension_degree = F::DIMENSION;

        match extension_degree {
            1 => self.verify_base_field(proof, traces, pis),
            4 => self.verify_extension_field_d4(proof, traces, pis),
            _ => Err(format!(
                "Unsupported extension degree: {}",
                extension_degree
            )),
        }
    }

    fn verify_base_field<F>(
        &self,
        proof: &MultiTableProof,
        traces: &Traces<F>,
        pis: Vec<Val>,
    ) -> Result<(), String>
    where
        F: Field + BasedVectorSpace<Val>,
    {
        // Verify witness table
        let witness_air = WitnessAir::<Val, 1>::new(traces.witness_trace.values.len());
        verify(&self.config, &witness_air, &proof.witness_proof, &pis)
            .map_err(|e| format!("Witness verification failed: {:?}", e))?;

        // Verify const table
        let const_air = ConstAir::<Val, 1>::new(traces.const_trace.values.len());
        verify(&self.config, &const_air, &proof.const_proof, &pis)
            .map_err(|e| format!("Const verification failed: {:?}", e))?;

        // Verify public table
        let public_air = PublicAir::<Val, 1>::new(traces.public_trace.values.len());
        verify(&self.config, &public_air, &proof.public_proof, &pis)
            .map_err(|e| format!("Public verification failed: {:?}", e))?;

        // Verify add table
        let add_air = AddAir::<Val, 1>::new(traces.add_trace.lhs_values.len());
        verify(&self.config, &add_air, &proof.add_proof, &pis)
            .map_err(|e| format!("Add verification failed: {:?}", e))?;

        // Verify mul table
        let mul_air = MulAir::<Val, 1>::new(traces.mul_trace.lhs_values.len());
        verify(&self.config, &mul_air, &proof.mul_proof, &pis)
            .map_err(|e| format!("Mul verification failed: {:?}", e))?;

        // Verify sub table
        let sub_air = SubAir::<Val, 1>::new(traces.sub_trace.lhs_values.len());
        verify(&self.config, &sub_air, &proof.sub_proof, &pis)
            .map_err(|e| format!("Sub verification failed: {:?}", e))?;

        Ok(())
    }

    fn verify_extension_field_d4<F>(
        &self,
        proof: &MultiTableProof,
        traces: &Traces<F>,
        pis: Vec<Val>,
    ) -> Result<(), String>
    where
        F: Field + BasedVectorSpace<Val>,
    {
        // Verify witness table
        let witness_air = WitnessAir::<Val, 4>::new(traces.witness_trace.values.len());
        verify(&self.config, &witness_air, &proof.witness_proof, &pis)
            .map_err(|e| format!("Witness verification failed: {:?}", e))?;

        // Verify const table
        let const_air = ConstAir::<Val, 4>::new(traces.const_trace.values.len());
        verify(&self.config, &const_air, &proof.const_proof, &pis)
            .map_err(|e| format!("Const verification failed: {:?}", e))?;

        // Verify public table
        let public_air = PublicAir::<Val, 4>::new(traces.public_trace.values.len());
        verify(&self.config, &public_air, &proof.public_proof, &pis)
            .map_err(|e| format!("Public verification failed: {:?}", e))?;

        // Verify add table
        let add_air = AddAir::<Val, 4>::new(traces.add_trace.lhs_values.len());
        verify(&self.config, &add_air, &proof.add_proof, &pis)
            .map_err(|e| format!("Add verification failed: {:?}", e))?;

        // Verify mul table
        let mul_air =
            MulAir::<Val, 4>::new_binomial(traces.mul_trace.lhs_values.len(), Val::from_u64(11));
        verify(&self.config, &mul_air, &proof.mul_proof, &pis)
            .map_err(|e| format!("Mul verification failed: {:?}", e))?;

        // Verify sub table
        let sub_air = SubAir::<Val, 4>::new(traces.sub_trace.lhs_values.len());
        verify(&self.config, &sub_air, &proof.sub_proof, &pis)
            .map_err(|e| format!("Sub verification failed: {:?}", e))?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use p3_baby_bear::BabyBear;
    use p3_field::{extension::BinomialExtensionField, PrimeCharacteristicRing};
    use p3_trace_generator::circuit::Circuit;

    #[test]
    fn test_multi_table_prover_base_field() {
        let mut circuit = Circuit::<BabyBear>::new();

        // Create a simple circuit: x + 5 * 2 - 3 = result
        let x = circuit.add_public_input();
        let c5 = circuit.add_const(BabyBear::from_u64(5));
        let c2 = circuit.add_const(BabyBear::from_u64(2));
        let c3 = circuit.add_const(BabyBear::from_u64(3));

        let mul_result = circuit.mul(c5, c2); // 5 * 2 = 10
        let add_result = circuit.add(x, mul_result); // x + 10
        let _final_result = circuit.sub(add_result, c3); // (x + 10) - 3

        let program = circuit.build();
        let mut prover_instance = program.instantiate_prover();

        // Set public input: x = 7, so final result = 7 + 10 - 3 = 14
        prover_instance
            .set_public_inputs(&[BabyBear::from_u64(7)])
            .unwrap();

        let traces = prover_instance.materialize_traces().unwrap();

        // Create unified prover and prove all tables
        let multi_prover = MultiTableProver::new();
        let proof = multi_prover.prove_all_tables(&traces).unwrap();

        // Verify all proofs
        multi_prover.verify_all_tables(&proof, &traces).unwrap();

        println!("✓ Base field multi-table proof verification successful");
    }

    #[test]
    fn test_multi_table_prover_extension_field() {
        type ExtField = BinomialExtensionField<BabyBear, 4>;
        let mut circuit = Circuit::<ExtField>::new();

        // Create a circuit with extension field operations: x * y + z
        let x = circuit.add_public_input();
        let y = circuit.add_public_input();
        let z = circuit.add_public_input();

        let xy = circuit.mul(x, y);
        let _result = circuit.add(xy, z);

        let program = circuit.build();
        let mut prover_instance = program.instantiate_prover();

        // Set public inputs to extension field values
        let x_val = ExtField::from(BabyBear::from_u64(2)); // [2, 0, 0, 0]
        let y_val = ExtField::from(BabyBear::from_u64(3)); // [3, 0, 0, 0]
        let z_val = ExtField::from(BabyBear::from_u64(1)); // [1, 0, 0, 0]

        prover_instance
            .set_public_inputs(&[x_val, y_val, z_val])
            .unwrap();

        let traces = prover_instance.materialize_traces().unwrap();

        // Create unified prover and prove all tables
        let multi_prover = MultiTableProver::new();
        let proof = multi_prover.prove_all_tables(&traces).unwrap();

        // Verify all proofs
        multi_prover.verify_all_tables(&proof, &traces).unwrap();

        println!("✓ Extension field multi-table proof verification successful");
    }

    #[test]
    fn test_multi_table_prover_complex_circuit() {
        let mut circuit = Circuit::<BabyBear>::new();

        // More complex circuit from DESIGN.txt: 37 * x - 111 = 0
        let x = circuit.add_public_input();
        let c37 = circuit.add_const(BabyBear::from_u64(37));
        let c111 = circuit.add_const(BabyBear::from_u64(111));

        let mul_result = circuit.mul(c37, x);
        let sub_result = circuit.sub(mul_result, c111);
        circuit.assert_zero(sub_result);

        let program = circuit.build();
        let mut prover_instance = program.instantiate_prover();

        // Set public input: x = 3 (should satisfy 37 * 3 - 111 = 0)
        prover_instance
            .set_public_inputs(&[BabyBear::from_u64(3)])
            .unwrap();

        let traces = prover_instance.materialize_traces().unwrap();

        // Verify we have the expected operations
        assert!(!traces.const_trace.values.is_empty()); // constants: 37, 111, 0
        assert_eq!(traces.public_trace.values.len(), 1); // one public input
        assert_eq!(traces.mul_trace.lhs_values.len(), 1); // one multiplication: 37 * x
        assert_eq!(traces.sub_trace.lhs_values.len(), 2); // two subtractions

        // Create unified prover and prove all tables
        let multi_prover = MultiTableProver::new();
        let proof = multi_prover.prove_all_tables(&traces).unwrap();

        // Verify all proofs
        multi_prover.verify_all_tables(&proof, &traces).unwrap();

        println!("✓ Complex circuit multi-table proof verification successful");
    }
}
