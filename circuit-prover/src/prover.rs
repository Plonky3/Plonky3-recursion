use alloc::string::String;
use alloc::vec::Vec;
use alloc::{format, vec};

use p3_baby_bear::BabyBear as Val;
use p3_circuit::Circuit;
use p3_circuit::tables::Traces;
use p3_field::{BasedVectorSpace, Field, PrimeCharacteristicRing};
use p3_uni_stark::{prove, verify};

use crate::air::{AddAir, ConstAir, FakeMerkleVerifyAir, MulAir, PublicAir, SubAir, WitnessAir};
use crate::config::{ProverConfig, build_standard_config};
use crate::transparent::{
    TransparentProvingKey as TransparentPK, TransparentVerifyingKey as TransparentVK,
};

// Re-export the proof type from the config module
pub type StarkProof = p3_uni_stark::Proof<ProverConfig>;

/// Proof and metadata for a single table
pub struct TableProof {
    pub proof: StarkProof,
    pub rows: usize,
}

/// Proof for all tables combined
pub struct MultiTableProof {
    pub witness: TableProof,
    pub const_table: TableProof,
    pub public: TableProof,
    pub add: TableProof,
    pub mul: TableProof,
    pub sub: TableProof,
    pub fake_merkle: TableProof,
    // Extension field degree used for proving (1 or 4 for now)
    pub ext_degree: usize,
}

/// Unified prover that creates proofs for all tables
pub struct MultiTableProver {
    config: ProverConfig,
    /// Optional binomial parameter for degree-4 extensions (x^4 = W).
    /// Defaults to BabyBear's commonly used W=11, but can be overridden.
    w_d4: Option<Val>,
}

impl MultiTableProver {
    /// Default constructor: uses standard config and `W=11` for D=4 binomial multiplications.
    pub fn new() -> Self {
        Self {
            config: build_standard_config(),
            w_d4: Some(Val::from_u64(11)),
        }
    }

    /// Run transparent setup for index columns once per circuit build.
    ///
    /// This produces a placeholder commitment and metadata for all index columns across tables.
    /// It does not alter proof generation in this POC.
    pub fn setup_transparent_for_circuit<F>(
        &self,
        circuit: &Circuit<F>,
    ) -> (TransparentPK<F>, TransparentVK)
    where
        F: p3_field::Field + Clone,
    {
        crate::transparent::setup_default_transparent_indices(circuit)
    }

    /// Configure a custom W for degree-4 binomial extensions.
    pub fn with_w_d4(mut self, w: Option<Val>) -> Self {
        self.w_d4 = w;
        self
    }

    /// Verifier-side stub for transparent setup.
    /// Accepts the transparent verifying key and performs no checks yet.
    pub fn verify_transparent_setup(&self, _vk: &TransparentVK) -> Result<(), String> {
        Ok(())
    }

    /// Prove all tables from the given traces.
    /// Supports both base field (D=1) and D=4 extension field (binomial with W if provided).
    pub fn prove_all_tables<F>(&self, traces: &Traces<F>) -> Result<MultiTableProof, String>
    where
        F: Field + BasedVectorSpace<Val>,
    {
        let pis: Vec<Val> = vec![];
        match F::DIMENSION {
            1 => self.prove_for_degree::<F, 1>(traces, pis, None),
            4 => self.prove_for_degree::<F, 4>(traces, pis, self.w_d4),
            d => Err(format!("Unsupported extension degree: {d}")),
        }
    }

    /// Verify all proofs in the MultiTableProof
    pub fn verify_all_tables(&self, proof: &MultiTableProof) -> Result<(), String> {
        let pis: Vec<Val> = vec![];
        match proof.ext_degree {
            1 => self.verify_for_degree::<1>(proof, pis, None),
            4 => self.verify_for_degree::<4>(proof, pis, self.w_d4),
            d => Err(format!("Unsupported extension degree in proof: {d}")),
        }
    }

    // --------------------------
    // Internal generic helpers
    // --------------------------

    /// Prove all tables for a fixed degree `D`.
    fn prove_for_degree<FEl, const D: usize>(
        &self,
        traces: &Traces<FEl>,
        pis: Vec<Val>,
        w_binomial: Option<Val>,
    ) -> Result<MultiTableProof, String>
    where
        FEl: Field + BasedVectorSpace<Val>,
    {
        // Witness
        let witness_matrix = WitnessAir::<Val, D>::trace_to_matrix(&traces.witness_trace);
        let witness_air = WitnessAir::<Val, D>::new(traces.witness_trace.values.len());
        let witness_proof = prove(&self.config, &witness_air, witness_matrix, &pis);

        // Const
        let const_matrix = ConstAir::<Val, D>::trace_to_matrix(&traces.const_trace);
        let const_air = ConstAir::<Val, D>::new(traces.const_trace.values.len());
        let const_proof = prove(&self.config, &const_air, const_matrix, &pis);

        // Public
        let public_matrix = PublicAir::<Val, D>::trace_to_matrix(&traces.public_trace);
        let public_air = PublicAir::<Val, D>::new(traces.public_trace.values.len());
        let public_proof = prove(&self.config, &public_air, public_matrix, &pis);

        // Add
        let add_matrix = AddAir::<Val, D>::trace_to_matrix(&traces.add_trace);
        let add_air = AddAir::<Val, D>::new(traces.add_trace.lhs_values.len());
        let add_proof = prove(&self.config, &add_air, add_matrix, &pis);

        // Mul
        let mul_matrix = MulAir::<Val, D>::trace_to_matrix(&traces.mul_trace);
        let mul_air: MulAir<Val, D> = if D == 1 {
            MulAir::<Val, D>::new(traces.mul_trace.lhs_values.len())
        } else {
            let w = w_binomial.ok_or_else(|| {
                format!("Missing binomial parameter W for D={D} extension field multiplication",)
            })?;
            MulAir::<Val, D>::new_binomial(traces.mul_trace.lhs_values.len(), w)
        };
        let mul_proof = prove(&self.config, &mul_air, mul_matrix, &pis);

        // Sub
        let sub_matrix = SubAir::<Val, D>::trace_to_matrix(&traces.sub_trace);
        let sub_air = SubAir::<Val, D>::new(traces.sub_trace.lhs_values.len());
        let sub_proof = prove(&self.config, &sub_air, sub_matrix, &pis);

        // FakeMerkle
        let fake_merkle_matrix = FakeMerkleVerifyAir::trace_to_matrix(&traces.fake_merkle_trace);
        let fake_merkle_air = FakeMerkleVerifyAir::new(traces.fake_merkle_trace.left_values.len());
        let fake_merkle_proof = prove(&self.config, &fake_merkle_air, fake_merkle_matrix, &pis);

        Ok(MultiTableProof {
            witness: TableProof {
                proof: witness_proof,
                rows: traces.witness_trace.values.len(),
            },
            const_table: TableProof {
                proof: const_proof,
                rows: traces.const_trace.values.len(),
            },
            public: TableProof {
                proof: public_proof,
                rows: traces.public_trace.values.len(),
            },
            add: TableProof {
                proof: add_proof,
                rows: traces.add_trace.lhs_values.len(),
            },
            mul: TableProof {
                proof: mul_proof,
                rows: traces.mul_trace.lhs_values.len(),
            },
            sub: TableProof {
                proof: sub_proof,
                rows: traces.sub_trace.lhs_values.len(),
            },
            fake_merkle: TableProof {
                proof: fake_merkle_proof,
                rows: traces.fake_merkle_trace.left_values.len(),
            },
            ext_degree: D,
        })
    }

    /// Verify all tables for a fixed degree `D`.
    fn verify_for_degree<const D: usize>(
        &self,
        proof: &MultiTableProof,
        pis: Vec<Val>,
        w_binomial: Option<Val>,
    ) -> Result<(), String> {
        // Witness
        let witness_air = WitnessAir::<Val, D>::new(proof.witness.rows);
        verify(&self.config, &witness_air, &proof.witness.proof, &pis)
            .map_err(|e| format!("Witness verification failed: {e:?}"))?;

        // Const
        let const_air = ConstAir::<Val, D>::new(proof.const_table.rows);
        verify(&self.config, &const_air, &proof.const_table.proof, &pis)
            .map_err(|e| format!("Const verification failed: {e:?}"))?;

        // Public
        let public_air = PublicAir::<Val, D>::new(proof.public.rows);
        verify(&self.config, &public_air, &proof.public.proof, &pis)
            .map_err(|e| format!("Public verification failed: {e:?}"))?;

        // Add
        let add_air = AddAir::<Val, D>::new(proof.add.rows);
        verify(&self.config, &add_air, &proof.add.proof, &pis)
            .map_err(|e| format!("Add verification failed: {e:?}"))?;

        // Mul
        let mul_air: MulAir<Val, D> = if D == 1 {
            MulAir::<Val, D>::new(proof.mul.rows)
        } else {
            let w = w_binomial.ok_or_else(|| {
                format!("Missing binomial parameter W for D={D} extension field multiplication",)
            })?;
            MulAir::<Val, D>::new_binomial(proof.mul.rows, w)
        };
        verify(&self.config, &mul_air, &proof.mul.proof, &pis)
            .map_err(|e| format!("Mul verification failed: {e:?}"))?;

        // Sub
        let sub_air = SubAir::<Val, D>::new(proof.sub.rows);
        verify(&self.config, &sub_air, &proof.sub.proof, &pis)
            .map_err(|e| format!("Sub verification failed: {e:?}"))?;

        // FakeMerkle
        let fake_merkle_air = FakeMerkleVerifyAir::new(proof.fake_merkle.rows);
        verify(
            &self.config,
            &fake_merkle_air,
            &proof.fake_merkle.proof,
            &pis,
        )
        .map_err(|e| format!("FakeMerkle verification failed: {e:?}"))?;

        Ok(())
    }
}

#[cfg(test)]
mod transparent_setup_tests {
    extern crate std;
    use p3_baby_bear::BabyBear;
    use p3_circuit::builder::CircuitBuilder;
    use p3_field::PrimeCharacteristicRing;

    use super::*;

    #[test]
    fn transparent_setup_in_prover() {
        // Build a small circuit.
        let mut b = CircuitBuilder::<BabyBear>::new();
        let x = b.add_public_input();
        let c1 = b.add_const(BabyBear::from_i64(7));
        let c2 = b.add_const(BabyBear::from_i64(5));
        let y = b.mul(c1, x);
        let z = b.sub(y, c2);
        b.assert_zero(z);

        let circuit = b.build();

        // Prover sets up transparent columns once.
        let prover = MultiTableProver::new();
        let (tpk, tvk) = prover.setup_transparent_for_circuit(&circuit);

        // Basic sanity checks on PK/VK.
        assert!(!tpk.traces.is_empty(), "no transparent traces produced");
        assert_eq!(
            tpk.traces.len(),
            tpk.infos.len(),
            "trace/infos length mismatch"
        );
        for (info, rows) in tpk.infos.iter().zip(tpk.traces.iter()) {
            assert_eq!(info.width, rows.width, "width mismatch for {}", info.name);
            assert_eq!(
                info.height, rows.height,
                "height mismatch for {}",
                info.name
            );
            if info.height > 0 {
                assert!(
                    info.height.is_power_of_two(),
                    "height not power of two for {}",
                    info.name
                );
            }
        }

        // Verifier stub accepts the VK.
        prover
            .verify_transparent_setup(&tvk)
            .expect("transparent VK verification stub failed");

        std::println!("transparent providers: {}", tpk.ordering.len());
        // Dump each provider with up to 8 rows for readability.
        let max_rows = 8usize;
        for (name, idx) in tpk.ordering.iter() {
            if let Some(rows) = tpk.traces.get(*idx) {
                std::println!(
                    "provider={} width={} height={}",
                    name,
                    rows.width,
                    rows.height
                );
                let limit = core::cmp::min(rows.height, max_rows);
                for r in 0..limit {
                    let start = r * rows.width;
                    let end = start + rows.width;
                    std::println!("row {:>3}: {:?}", r, &rows.values[start..end]);
                }
                if rows.height > limit {
                    std::println!("... ({} more rows)", rows.height - limit);
                }
            }
        }
    }
}

impl Default for MultiTableProver {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod prover_tests {
    use p3_baby_bear::BabyBear;
    use p3_circuit::builder::CircuitBuilder;
    use p3_field::extension::BinomialExtensionField;
    use p3_field::{BasedVectorSpace, PrimeCharacteristicRing};

    use super::*;

    #[test]
    fn test_multi_table_prover_base_field() {
        let mut builder = CircuitBuilder::<BabyBear>::new();

        // Create a simple circuit: x + 5 * 2 - 3 = result
        let x = builder.add_public_input();
        let c5 = builder.add_const(BabyBear::from_u64(5));
        let c2 = builder.add_const(BabyBear::from_u64(2));
        let c3 = builder.add_const(BabyBear::from_u64(3));

        let mul_result = builder.mul(c5, c2); // 5 * 2 = 10
        let add_result = builder.add(x, mul_result); // x + 10
        let _final_result = builder.sub(add_result, c3); // (x + 10) - 3

        let circuit = builder.build();
        let mut runner = circuit.runner();

        // Set public input: x = 7, so final result = 7 + 10 - 3 = 14
        runner.set_public_inputs(&[BabyBear::from_u64(7)]).unwrap();

        let traces = runner.run().unwrap();

        // Create unified prover and prove all tables
        let multi_prover = MultiTableProver::new();
        let proof = multi_prover.prove_all_tables(&traces).unwrap();

        // Verify all proofs
        multi_prover.verify_all_tables(&proof).unwrap();
    }

    #[test]
    fn test_multi_table_prover_extension_field() {
        type ExtField = BinomialExtensionField<BabyBear, 4>;
        let mut builder = CircuitBuilder::<ExtField>::new();

        // Create a circuit with extension field operations: x * y + z
        let x = builder.add_public_input();
        let y = builder.add_public_input();
        let z = builder.add_public_input();

        let xy = builder.mul(x, y);
        let _result = builder.add(xy, z);

        let circuit = builder.build();
        let mut runner = circuit.runner();

        // Set public inputs to genuine extension field values with ALL non-zero coefficients
        let x_val = ExtField::from_basis_coefficients_slice(&[
            BabyBear::from_u64(2), // a0
            BabyBear::from_u64(3), // a1
            BabyBear::from_u64(5), // a2
            BabyBear::from_u64(7), // a3
        ])
        .unwrap();
        let y_val = ExtField::from_basis_coefficients_slice(&[
            BabyBear::from_u64(11), // b0
            BabyBear::from_u64(13), // b1
            BabyBear::from_u64(17), // b2
            BabyBear::from_u64(19), // b3
        ])
        .unwrap();
        let z_val = ExtField::from_basis_coefficients_slice(&[
            BabyBear::from_u64(23), // c0
            BabyBear::from_u64(29), // c1
            BabyBear::from_u64(31), // c2
            BabyBear::from_u64(37), // c3
        ])
        .unwrap();

        runner.set_public_inputs(&[x_val, y_val, z_val]).unwrap();
        let traces = runner.run().unwrap();

        // Create unified prover and prove all tables
        let multi_prover = MultiTableProver::new(); // defaults to W=11 for D=4
        let proof = multi_prover.prove_all_tables(&traces).unwrap();

        // Verify all proofs
        multi_prover.verify_all_tables(&proof).unwrap();
    }
}
