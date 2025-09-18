//! Multi-table prover and verifier for STARK proofs.
//!
//! Generic roles and degrees:
//! - F: Prover/verifier base field (BabyBear/KoalaBear/Goldilocks). All PCS/FRI arithmetic runs over `F`.
//! - P: Cryptographic permutation over `F` used by the hash/compress functions and challenger.
//! - EF: Element field used in circuit traces. Either the base field `F` or a binomial extension `BinomialExtensionField<F, D>`.
//! - D: Element-field extension degree. Must equal `EF::DIMENSION` and is used by AIRs like `WitnessAir<F, D>` to expand EF values into D base limbs.
//! - CD: Challenge field degree for FRI (independent of `D`). The challenger/PCS use `BinomialExtensionField<F, CD>`.
//!
//! Supports base fields (D=1) and binomial extension fields (D>1), with automatic
//! detection of the binomial parameter `W` for extension-field multiplication.

use alloc::vec;
use alloc::vec::Vec;

use p3_circuit::tables::Traces;
use p3_circuit::{CircuitBuilderError, CircuitError};
use p3_field::{BasedVectorSpace, Field};
use p3_uni_stark::{prove, verify};

use crate::air::{AddAir, ConstAir, FakeMerkleVerifyAir, MulAir, PublicAir, WitnessAir};
use crate::config::{ProverConfig, StarkField, StarkPermutation};
use crate::field_params::ExtractBinomialW;

/// Configuration for packing multiple primitive operations into a single AIR row.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TablePacking {
    add_lanes: usize,
    mul_lanes: usize,
}

impl TablePacking {
    pub fn new(add_lanes: usize, mul_lanes: usize) -> Self {
        Self {
            add_lanes: add_lanes.max(1),
            mul_lanes: mul_lanes.max(1),
        }
    }

    pub fn from_counts(add_lanes: usize, mul_lanes: usize) -> Self {
        Self::new(add_lanes, mul_lanes)
    }

    pub const fn add_lanes(self) -> usize {
        self.add_lanes
    }

    pub const fn mul_lanes(self) -> usize {
        self.mul_lanes
    }
}

impl Default for TablePacking {
    fn default() -> Self {
        Self::new(1, 1)
    }
}

/// STARK proof type alias for convenience.
///
/// - `F`: Base field for values and commitments.
/// - `P`: Permutation over `F` used by hash/challenger.
/// - `CD`: Challenge field degree (binomial extension over `F`).
pub type StarkProof<F, P, const CD: usize> = p3_uni_stark::Proof<ProverConfig<F, P, CD>>;

/// Proof and metadata for a single table.
///
/// - `F`: Base field.
/// - `P`: Permutation over `F`.
/// - `CD`: Challenge field degree.
pub struct TableProof<F, P, const CD: usize>
where
    F: StarkField + p3_field::extension::BinomiallyExtendable<CD>,
    P: StarkPermutation<F>,
{
    pub proof: StarkProof<F, P, CD>,
    /// Number of logical rows (operations) prior to any per-row packing.
    pub rows: usize,
}

/// Complete proof bundle containing proofs for all circuit tables.
///
/// Includes metadata for verification, such as:
/// - `ext_degree`: circuit element extension degree used in traces (may differ from `CD`).
/// - `w_binomial`: binomial parameter `W` for element-field multiplication, when applicable.
pub struct MultiTableProof<F, P, const CD: usize>
where
    F: StarkField + p3_field::extension::BinomiallyExtendable<CD>,
    P: StarkPermutation<F>,
{
    pub witness: TableProof<F, P, CD>,
    pub constants: TableProof<F, P, CD>,
    pub public: TableProof<F, P, CD>,
    pub add: TableProof<F, P, CD>,
    pub mul: TableProof<F, P, CD>,
    pub fake_merkle: TableProof<F, P, CD>,
    /// Packing configuration used when generating the proofs.
    pub table_packing: TablePacking,
    /// Extension field degree: 1 for base field; otherwise the extension degree used.
    pub ext_degree: usize,
    /// Binomial parameter W for extension fields (e.g., x^D = W); None for base fields
    pub w_binomial: Option<F>,
}

/// Multi-table STARK prover for circuit execution traces.
///
/// - `F`: Base field for values/commitments.
/// - `P`: Permutation over `F` (hash/challenger).
/// - `CD`: Challenge field degree; traces may use element fields of different degree.
pub struct MultiTableProver<F, P, const CD: usize>
where
    F: StarkField + p3_field::extension::BinomiallyExtendable<CD>,
    P: StarkPermutation<F>,
{
    config: ProverConfig<F, P, CD>,
    table_packing: TablePacking,
}

/// Errors that can arise during proving or verification.
#[derive(Debug)]
pub enum ProverError {
    /// Unsupported extension degree encountered.
    UnsupportedDegree(usize),
    /// Missing binomial parameter W for extension-field multiplication.
    MissingWForExtension,
    /// Circuit execution error.
    Circuit(CircuitError),
    /// Circuit building/lowering error.
    Builder(CircuitBuilderError),
    /// Verification failed for a specific table/phase.
    VerificationFailed { phase: &'static str },
}

impl core::fmt::Display for ProverError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            ProverError::UnsupportedDegree(d) => {
                write!(
                    f,
                    "unsupported extension degree: {d} (supported: 1,2,4,6,8)"
                )
            }
            ProverError::MissingWForExtension => {
                write!(
                    f,
                    "missing binomial parameter W for extension-field multiplication"
                )
            }
            ProverError::Circuit(err) => {
                write!(f, "circuit error: {err}")
            }
            ProverError::Builder(err) => {
                write!(f, "circuit build error: {err}")
            }
            ProverError::VerificationFailed { phase } => {
                write!(f, "verification failed in {phase}")
            }
        }
    }
}

impl From<CircuitError> for ProverError {
    fn from(err: CircuitError) -> Self {
        ProverError::Circuit(err)
    }
}

impl From<CircuitBuilderError> for ProverError {
    fn from(err: CircuitBuilderError) -> Self {
        ProverError::Builder(err)
    }
}

impl<F, P, const CD: usize> MultiTableProver<F, P, CD>
where
    F: StarkField + p3_field::extension::BinomiallyExtendable<CD>,
    P: StarkPermutation<F>,
{
    pub fn new(config: ProverConfig<F, P, CD>) -> Self {
        Self {
            config,
            table_packing: TablePacking::default(),
        }
    }

    pub fn with_table_packing(mut self, table_packing: TablePacking) -> Self {
        self.table_packing = table_packing;
        self
    }

    pub fn set_table_packing(&mut self, table_packing: TablePacking) {
        self.table_packing = table_packing;
    }

    pub const fn table_packing(&self) -> TablePacking {
        self.table_packing
    }

    /// Generate proofs for all circuit tables.
    ///
    /// Automatically detects whether to use base field or binomial extension field
    /// proving based on the circuit element type `EF`. For extension fields,
    /// the binomial parameter W is automatically extracted.
    pub fn prove_all_tables<EF>(
        &self,
        traces: &Traces<EF>,
    ) -> Result<MultiTableProof<F, P, CD>, ProverError>
    where
        EF: Field + BasedVectorSpace<F> + ExtractBinomialW<F>,
    {
        let pis = vec![];
        let w_opt = EF::extract_w();
        match EF::DIMENSION {
            1 => self.prove_for_degree::<EF, 1>(traces, &pis, None),
            2 => self.prove_for_degree::<EF, 2>(traces, &pis, w_opt),
            4 => self.prove_for_degree::<EF, 4>(traces, &pis, w_opt),
            6 => self.prove_for_degree::<EF, 6>(traces, &pis, w_opt),
            8 => self.prove_for_degree::<EF, 8>(traces, &pis, w_opt),
            d => Err(ProverError::UnsupportedDegree(d)),
        }
    }

    /// Verify all proofs in the given proof bundle.
    /// Uses the recorded extension degree and binomial parameter recorded during proving.
    pub fn verify_all_tables(&self, proof: &MultiTableProof<F, P, CD>) -> Result<(), ProverError> {
        let pis = vec![];

        let w_opt = proof.w_binomial;
        match proof.ext_degree {
            1 => self.verify_for_degree::<1>(proof, &pis, None),
            2 => self.verify_for_degree::<2>(proof, &pis, w_opt),
            4 => self.verify_for_degree::<4>(proof, &pis, w_opt),
            6 => self.verify_for_degree::<6>(proof, &pis, w_opt),
            8 => self.verify_for_degree::<8>(proof, &pis, w_opt),
            d => Err(ProverError::UnsupportedDegree(d)),
        }
    }

    // Internal implementation methods

    /// Prove all tables for a fixed extension degree.
    fn prove_for_degree<EF, const D: usize>(
        &self,
        traces: &Traces<EF>,
        pis: &Vec<F>,
        w_binomial: Option<F>,
    ) -> Result<MultiTableProof<F, P, CD>, ProverError>
    where
        EF: Field + BasedVectorSpace<F>,
    {
        debug_assert_eq!(D, EF::DIMENSION, "D parameter must match EF::DIMENSION");
        let table_packing = self.table_packing;
        let add_lanes = table_packing.add_lanes();
        let mul_lanes = table_packing.mul_lanes();
        // Witness
        let witness_matrix = WitnessAir::<F, D>::trace_to_matrix(&traces.witness_trace);
        let witness_air = WitnessAir::<F, D>::new(traces.witness_trace.values.len());
        let witness_proof = prove(&self.config, &witness_air, witness_matrix, pis);

        // Const
        let const_matrix = ConstAir::<F, D>::trace_to_matrix(&traces.const_trace);
        let const_air = ConstAir::<F, D>::new(traces.const_trace.values.len());
        let const_proof = prove(&self.config, &const_air, const_matrix, pis);

        // Public
        let public_matrix = PublicAir::<F, D>::trace_to_matrix(&traces.public_trace);
        let public_air = PublicAir::<F, D>::new(traces.public_trace.values.len());
        let public_proof = prove(&self.config, &public_air, public_matrix, pis);

        // Add
        let add_matrix = AddAir::<F, D>::trace_to_matrix(&traces.add_trace, add_lanes);
        let add_air = AddAir::<F, D>::new(traces.add_trace.lhs_values.len(), add_lanes);
        let add_proof = prove(&self.config, &add_air, add_matrix, pis);

        // Multiplication (uses binomial arithmetic for extension fields)
        let mul_matrix = MulAir::<F, D>::trace_to_matrix(&traces.mul_trace, mul_lanes);
        let mul_air: MulAir<F, D> = if D == 1 {
            MulAir::<F, D>::new(traces.mul_trace.lhs_values.len(), mul_lanes)
        } else {
            let w = w_binomial.ok_or(ProverError::MissingWForExtension)?;
            MulAir::<F, D>::new_binomial(traces.mul_trace.lhs_values.len(), mul_lanes, w)
        };
        let mul_proof = prove(&self.config, &mul_air, mul_matrix, pis);

        // FakeMerkle (always uses base field regardless of traces D)
        let fake_merkle_matrix =
            FakeMerkleVerifyAir::<F>::trace_to_matrix(&traces.fake_merkle_trace);
        let fake_merkle_air =
            FakeMerkleVerifyAir::<F>::new(traces.fake_merkle_trace.left_values.len());
        let fake_merkle_proof = prove(&self.config, &fake_merkle_air, fake_merkle_matrix, pis);

        Ok(MultiTableProof {
            witness: TableProof {
                proof: witness_proof,
                rows: traces.witness_trace.values.len(),
            },
            constants: TableProof {
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
            fake_merkle: TableProof {
                proof: fake_merkle_proof,
                rows: traces.fake_merkle_trace.left_values.len(),
            },
            table_packing,
            ext_degree: D,
            w_binomial: if D > 1 { w_binomial } else { None },
        })
    }

    /// Verify all tables for a fixed extension degree.
    fn verify_for_degree<const D: usize>(
        &self,
        proof: &MultiTableProof<F, P, CD>,
        pis: &Vec<F>,
        w_binomial: Option<F>,
    ) -> Result<(), ProverError> {
        let table_packing = proof.table_packing;
        let add_lanes = table_packing.add_lanes();
        let mul_lanes = table_packing.mul_lanes();
        // Witness
        let witness_air = WitnessAir::<F, D>::new(proof.witness.rows);
        verify(&self.config, &witness_air, &proof.witness.proof, pis)
            .map_err(|_| ProverError::VerificationFailed { phase: "witness" })?;

        // Const
        let const_air = ConstAir::<F, D>::new(proof.constants.rows);
        verify(&self.config, &const_air, &proof.constants.proof, pis)
            .map_err(|_| ProverError::VerificationFailed { phase: "const" })?;

        // Public
        let public_air = PublicAir::<F, D>::new(proof.public.rows);
        verify(&self.config, &public_air, &proof.public.proof, pis)
            .map_err(|_| ProverError::VerificationFailed { phase: "public" })?;

        // Add
        let add_air = AddAir::<F, D>::new(proof.add.rows, add_lanes);
        verify(&self.config, &add_air, &proof.add.proof, pis)
            .map_err(|_| ProverError::VerificationFailed { phase: "add" })?;

        // Mul
        let mul_air: MulAir<F, D> = if D == 1 {
            MulAir::<F, D>::new(proof.mul.rows, mul_lanes)
        } else {
            let w = w_binomial.ok_or(ProverError::MissingWForExtension)?;
            MulAir::<F, D>::new_binomial(proof.mul.rows, mul_lanes, w)
        };
        verify(&self.config, &mul_air, &proof.mul.proof, pis)
            .map_err(|_| ProverError::VerificationFailed { phase: "mul" })?;

        // FakeMerkle
        let fake_merkle_air = FakeMerkleVerifyAir::<F>::new(proof.fake_merkle.rows);
        verify(
            &self.config,
            &fake_merkle_air,
            &proof.fake_merkle.proof,
            pis,
        )
        .map_err(|_| ProverError::VerificationFailed {
            phase: "fake_merkle",
        })?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use p3_baby_bear::BabyBear;
    use p3_circuit::builder::CircuitBuilder;
    use p3_field::extension::BinomialExtensionField;
    use p3_field::{BasedVectorSpace, PrimeCharacteristicRing};
    use p3_goldilocks::Goldilocks;
    use p3_koala_bear::KoalaBear;

    use super::*;
    use crate::config::babybear_config::build_standard_config_babybear;
    use crate::config::goldilocks_config::build_standard_config_goldilocks;
    use crate::config::koalabear_config::build_standard_config_koalabear;

    #[test]
    fn test_babybear_prover_base_field() -> Result<(), ProverError> {
        let mut builder = CircuitBuilder::<BabyBear>::new();

        // Create circuit: x + 5 * 2 - 3 + (-1) = expected_result, then assert result == expected
        let x = builder.add_public_input();
        let expected_result = builder.add_public_input(); // Add expected result as public input
        let c5 = builder.add_const(BabyBear::from_u64(5));
        let c2 = builder.add_const(BabyBear::from_u64(2));
        let c3 = builder.add_const(BabyBear::from_u64(3));
        let neg_one = builder.add_const(BabyBear::NEG_ONE); // Field boundary test

        let mul_result = builder.mul(c5, c2); // 5 * 2 = 10
        let add_result = builder.add(x, mul_result); // x + 10
        let sub_result = builder.sub(add_result, c3); // (x + 10) - 3
        let final_result = builder.add(sub_result, neg_one); // + (-1) for boundary

        // Constrain: final_result - expected_result == 0
        let diff = builder.sub(final_result, expected_result);
        builder.assert_zero(diff);

        let circuit = builder.build()?;
        let mut runner = circuit.runner();

        // Set public inputs: x = 7, expected = 7 + 10 - 3 + (-1) = 13
        let x_val = BabyBear::from_u64(7);
        let expected_val = BabyBear::from_u64(13); // 7 + 10 - 3 - 1 = 13
        runner.set_public_inputs(&[x_val, expected_val])?;
        let traces = runner.run()?;

        // Create BabyBear prover and prove all tables
        let config = build_standard_config_babybear();
        let multi_prover = MultiTableProver::new(config);
        let proof = multi_prover.prove_all_tables(&traces)?;

        // Verify all proofs
        multi_prover.verify_all_tables(&proof)?;
        Ok(())
    }

    #[test]
    fn test_babybear_prover_extension_field_d4() -> Result<(), ProverError> {
        type ExtField = BinomialExtensionField<BabyBear, 4>;
        let mut builder = CircuitBuilder::<ExtField>::new();

        // Create circuit: x * y + z - w = expected_result, then assert result == expected
        let x = builder.add_public_input();
        let y = builder.add_public_input();
        let z = builder.add_public_input();
        let expected_result = builder.add_public_input(); // Add expected result as public input
        let w = builder.add_const(
            ExtField::from_basis_coefficients_slice(&[
                BabyBear::NEG_ONE, // -1 boundary test
                BabyBear::ZERO,
                BabyBear::ONE,
                BabyBear::TWO,
            ])
            .unwrap(),
        );

        let xy = builder.mul(x, y); // Extension field multiplication
        let add_result = builder.add(xy, z);
        let sub_result = builder.sub(add_result, w);

        // Constrain: sub_result - expected_result == 0
        let diff = builder.sub(sub_result, expected_result);
        builder.assert_zero(diff);

        let circuit = builder.build()?;
        let mut runner = circuit.runner();

        // Set public inputs with all non-zero coefficients
        let x_val = ExtField::from_basis_coefficients_slice(&[
            BabyBear::from_u64(2),
            BabyBear::from_u64(3),
            BabyBear::from_u64(5),
            BabyBear::from_u64(7),
        ])
        .unwrap();
        let y_val = ExtField::from_basis_coefficients_slice(&[
            BabyBear::from_u64(11),
            BabyBear::from_u64(13),
            BabyBear::from_u64(17),
            BabyBear::from_u64(19),
        ])
        .unwrap();
        let z_val = ExtField::from_basis_coefficients_slice(&[
            BabyBear::from_u64(23),
            BabyBear::from_u64(29),
            BabyBear::from_u64(31),
            BabyBear::from_u64(37),
        ])
        .unwrap();
        let w_val = ExtField::from_basis_coefficients_slice(&[
            BabyBear::NEG_ONE,
            BabyBear::ZERO,
            BabyBear::ONE,
            BabyBear::TWO,
        ])
        .unwrap();

        // Compute expected result: x * y + z - w
        let xy_expected = x_val * y_val;
        let add_expected = xy_expected + z_val;
        let expected_val = add_expected - w_val;

        runner.set_public_inputs(&[x_val, y_val, z_val, expected_val])?;
        let traces = runner.run()?;

        // Create BabyBear prover for extension field (D=4)
        let config = build_standard_config_babybear();
        let multi_prover = MultiTableProver::new(config);
        let proof = multi_prover.prove_all_tables(&traces)?;

        // Verify proof has correct extension degree and W parameter
        assert_eq!(proof.ext_degree, 4);
        // Derive W via trait to avoid hardcoding constants
        let expected_w = <ExtField as ExtractBinomialW<BabyBear>>::extract_w().unwrap();
        assert_eq!(proof.w_binomial, Some(expected_w));

        multi_prover.verify_all_tables(&proof)?;
        Ok(())
    }

    #[test]
    fn test_koalabear_prover_base_field() -> Result<(), ProverError> {
        let mut builder = CircuitBuilder::<KoalaBear>::new();

        // Create circuit: a * b + c - d = expected_result, then assert result == expected
        let a = builder.add_public_input();
        let b = builder.add_public_input();
        let expected_result = builder.add_public_input(); // Add expected result as public input
        let c = builder.add_const(KoalaBear::from_u64(100));
        let d = builder.add_const(KoalaBear::NEG_ONE); // Boundary test

        let ab = builder.mul(a, b);
        let add_result = builder.add(ab, c);
        let final_result = builder.sub(add_result, d);

        // Constrain: final_result - expected_result == 0
        let diff = builder.sub(final_result, expected_result);
        builder.assert_zero(diff);

        let circuit = builder.build()?;
        let mut runner = circuit.runner();

        // Set public inputs: a=42, b=13, expected = 42*13 + 100 - (-1) = 546 + 100 + 1 = 647
        let a_val = KoalaBear::from_u64(42);
        let b_val = KoalaBear::from_u64(13);
        let expected_val = KoalaBear::from_u64(647); // 42*13 + 100 - (-1) = 647
        runner.set_public_inputs(&[a_val, b_val, expected_val])?;
        let traces = runner.run()?;

        // Create KoalaBear prover
        let config = build_standard_config_koalabear();
        let multi_prover = MultiTableProver::new(config);
        let proof = multi_prover.prove_all_tables(&traces)?;

        multi_prover.verify_all_tables(&proof)?;
        Ok(())
    }

    #[test]
    fn test_koalabear_prover_extension_field_d8() -> Result<(), ProverError> {
        type KBExtField = BinomialExtensionField<KoalaBear, 8>;
        let mut builder = CircuitBuilder::<KBExtField>::new();

        // Create circuit: x * y * z = expected_result, then assert result == expected
        let x = builder.add_public_input();
        let y = builder.add_public_input();
        let expected_result = builder.add_public_input(); // Add expected result as public input
        let z = builder.add_const(
            KBExtField::from_basis_coefficients_slice(&[
                KoalaBear::from_u64(1),
                KoalaBear::NEG_ONE, // Mix: 1 and -1
                KoalaBear::from_u64(2),
                KoalaBear::from_u64(3),
                KoalaBear::from_u64(4),
                KoalaBear::from_u64(5),
                KoalaBear::from_u64(6),
                KoalaBear::from_u64(7),
            ])
            .unwrap(),
        );

        let xy = builder.mul(x, y); // First extension multiplication
        let xyz = builder.mul(xy, z); // Second extension multiplication

        // Constrain: xyz - expected_result == 0
        let diff = builder.sub(xyz, expected_result);
        builder.assert_zero(diff);

        let circuit = builder.build()?;
        let mut runner = circuit.runner();

        // Set public inputs with diverse coefficients
        let x_val = KBExtField::from_basis_coefficients_slice(&[
            KoalaBear::from_u64(4),
            KoalaBear::from_u64(6),
            KoalaBear::from_u64(8),
            KoalaBear::from_u64(10),
            KoalaBear::from_u64(12),
            KoalaBear::from_u64(14),
            KoalaBear::from_u64(16),
            KoalaBear::from_u64(18),
        ])
        .unwrap();
        let y_val = KBExtField::from_basis_coefficients_slice(&[
            KoalaBear::from_u64(12),
            KoalaBear::from_u64(14),
            KoalaBear::from_u64(16),
            KoalaBear::from_u64(18),
            KoalaBear::from_u64(20),
            KoalaBear::from_u64(22),
            KoalaBear::from_u64(24),
            KoalaBear::from_u64(26),
        ])
        .unwrap();
        let z_val = KBExtField::from_basis_coefficients_slice(&[
            KoalaBear::from_u64(1),
            KoalaBear::NEG_ONE,
            KoalaBear::from_u64(2),
            KoalaBear::from_u64(3),
            KoalaBear::from_u64(4),
            KoalaBear::from_u64(5),
            KoalaBear::from_u64(6),
            KoalaBear::from_u64(7),
        ])
        .unwrap();

        // Compute expected result: x * y * z
        let xy_expected = x_val * y_val;
        let expected_val = xy_expected * z_val;

        runner.set_public_inputs(&[x_val, y_val, expected_val])?;
        let traces = runner.run()?;

        // Create KoalaBear prover for extension field (D=8)
        let config = build_standard_config_koalabear();
        let multi_prover = MultiTableProver::new(config);
        let proof = multi_prover.prove_all_tables(&traces)?;

        // Verify proof has correct extension degree and W parameter for KoalaBear (D=8)
        assert_eq!(proof.ext_degree, 8);
        let expected_w_kb = <KBExtField as ExtractBinomialW<KoalaBear>>::extract_w().unwrap();
        assert_eq!(proof.w_binomial, Some(expected_w_kb));

        multi_prover.verify_all_tables(&proof)?;
        Ok(())
    }

    #[test]
    fn test_goldilocks_prover_extension_field_d2() -> Result<(), ProverError> {
        type ExtField = BinomialExtensionField<Goldilocks, 2>;
        let mut builder = CircuitBuilder::<ExtField>::new();

        // Simple circuit over D=2: x * y + z = expected
        let x = builder.add_public_input();
        let y = builder.add_public_input();
        let z = builder.add_public_input();
        let expected_result = builder.add_public_input();

        let xy = builder.mul(x, y);
        let res = builder.add(xy, z);

        let diff = builder.sub(res, expected_result);
        builder.assert_zero(diff);

        let circuit = builder.build()?;
        let mut runner = circuit.runner();

        let x_val = ExtField::from_basis_coefficients_slice(&[
            Goldilocks::from_u64(3),
            Goldilocks::NEG_ONE,
        ])
        .unwrap();
        let y_val = ExtField::from_basis_coefficients_slice(&[
            Goldilocks::from_u64(7),
            Goldilocks::from_u64(11),
        ])
        .unwrap();
        let z_val = ExtField::from_basis_coefficients_slice(&[
            Goldilocks::from_u64(13),
            Goldilocks::from_u64(17),
        ])
        .unwrap();

        let expected_val = x_val * y_val + z_val;
        runner.set_public_inputs(&[x_val, y_val, z_val, expected_val])?;

        let traces = runner.run()?;

        // Build Goldilocks config with challenge degree 2 (Poseidon2)
        let config = build_standard_config_goldilocks();
        let multi_prover = MultiTableProver::new(config);

        let proof = multi_prover.prove_all_tables(&traces)?;

        // Check extension metadata and verify
        assert_eq!(proof.ext_degree, 2);
        let expected_w = <ExtField as ExtractBinomialW<Goldilocks>>::extract_w().unwrap();
        assert_eq!(proof.w_binomial, Some(expected_w));

        multi_prover.verify_all_tables(&proof)?;
        Ok(())
    }
}
