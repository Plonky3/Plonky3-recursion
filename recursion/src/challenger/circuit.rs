//! Circuit-based challenger implementation matching native DuplexChallenger exactly.
//!
//! This module provides [`CircuitChallenger`], which maintains state as coefficient-level
//! targets to ensure exact transcript compatibility with the native `DuplexChallenger`.
//!
//! # Implementation Status
//!
//! The challenger computes Poseidon2 permutations via a witness hint. This ensures correct
//! transcript values during circuit execution. Full soundness enforcement via CTLs
//! (Cross-Table Lookups) can be added later by connecting to the Poseidon2 table.

use alloc::vec;
use alloc::vec::Vec;

use p3_circuit::ops::Poseidon2Config;
use p3_circuit::{CircuitBuilder, CircuitBuilderError};
use p3_field::{ExtensionField, PrimeField64};

use crate::Target;
use crate::traits::RecursiveChallenger;

/// Circuit challenger with coefficient-level state management.
///
/// Maintains state as WIDTH base field coefficient targets to exactly match
/// the native `DuplexChallenger<F, P, WIDTH, RATE>` behavior.
///
/// # Type Parameters
/// - `WIDTH`: Sponge state width (16 for Poseidon2)
/// - `RATE`: Sponge rate (8 for typical configuration)
///
/// # Design
/// The state is represented as WIDTH targets, each representing a base field element
/// embedded in the extension field (i.e., higher coefficients are zero).
/// When duplexing:
/// 1. State[0..input_buffer.len()] is overwritten with inputs
/// 2. State is recomposed to WIDTH/D extension elements
/// 3. Poseidon2 permutation is applied (via witness hint, CTLs added later for soundness)
/// 4. Output extension elements are decomposed back to coefficients
/// 5. Output buffer is filled from state[0..RATE]
pub struct CircuitChallenger<const WIDTH: usize, const RATE: usize> {
    /// Poseidon2 configuration for the permutation.
    poseidon2_config: Poseidon2Config,

    /// Sponge state: WIDTH base field coefficient targets.
    /// Each target represents a base field element embedded in EF.
    state: Vec<Target>,

    /// Buffered inputs not yet absorbed into state.
    input_buffer: Vec<Target>,

    /// Buffered outputs from last duplexing.
    output_buffer: Vec<Target>,

    /// Whether the challenger has been initialized with zero state.
    initialized: bool,
}

impl<const WIDTH: usize, const RATE: usize> CircuitChallenger<WIDTH, RATE> {
    /// Create a new uninitialized circuit challenger.
    ///
    /// # Parameters
    /// - `poseidon2_config`: The Poseidon2 configuration to use for permutations
    ///
    /// Call `init()` to initialize the state with zeros before use.
    pub const fn new(poseidon2_config: Poseidon2Config) -> Self {
        Self {
            poseidon2_config,
            state: Vec::new(),
            input_buffer: Vec::new(),
            output_buffer: Vec::new(),
            initialized: false,
        }
    }

    /// Initialize the challenger state with zeros.
    ///
    /// This must be called before any observe/sample operations.
    pub fn init<BF, EF>(&mut self, circuit: &mut CircuitBuilder<EF>)
    where
        BF: PrimeField64,
        EF: ExtensionField<BF>,
    {
        if self.initialized {
            return;
        }
        let zero = circuit.add_const(EF::ZERO);
        self.state = vec![zero; WIDTH];
        self.initialized = true;
    }

    /// Perform duplexing: absorb inputs, permute, fill output buffer.
    ///
    /// Matches native `DuplexChallenger::duplexing()` exactly.
    fn duplexing<BF, EF>(&mut self, circuit: &mut CircuitBuilder<EF>)
    where
        BF: PrimeField64,
        EF: ExtensionField<BF>,
    {
        debug_assert!(self.initialized, "Challenger must be initialized");
        debug_assert!(self.input_buffer.len() <= RATE, "Input buffer exceeds RATE");

        // 1. Overwrite state[0..n] with inputs (NOT XOR, matches native)
        for (i, val) in self.input_buffer.drain(..).enumerate() {
            self.state[i] = val;
        }

        // 2. Recompose WIDTH coefficient targets → WIDTH/D extension element targets
        let num_ext_limbs = WIDTH / EF::DIMENSION;
        assert_eq!(num_ext_limbs, 4, "Expected 4 extension limbs for WIDTH/D");

        let ext_inputs: [Target; 4] = [
            circuit
                .recompose_base_coeffs_to_ext::<BF>(&self.state[0..EF::DIMENSION])
                .expect("recomposition should succeed"),
            circuit
                .recompose_base_coeffs_to_ext::<BF>(&self.state[EF::DIMENSION..2 * EF::DIMENSION])
                .expect("recomposition should succeed"),
            circuit
                .recompose_base_coeffs_to_ext::<BF>(
                    &self.state[2 * EF::DIMENSION..3 * EF::DIMENSION],
                )
                .expect("recomposition should succeed"),
            circuit
                .recompose_base_coeffs_to_ext::<BF>(
                    &self.state[3 * EF::DIMENSION..4 * EF::DIMENSION],
                )
                .expect("recomposition should succeed"),
        ];

        // 3. Apply Poseidon2 permutation via witness hint
        // (CTLs for soundness can be added later)
        let ext_outputs = circuit
            .add_poseidon2_perm_for_challenger(self.poseidon2_config, ext_inputs)
            .expect("poseidon2 permutation should succeed");

        // 4. Decompose 4 extension outputs → WIDTH coefficient targets
        for (limb, &ext_out) in ext_outputs.iter().enumerate() {
            let coeffs = circuit
                .decompose_ext_to_base_coeffs::<BF>(ext_out)
                .expect("decomposition should succeed");
            let start = limb * EF::DIMENSION;
            for (i, coeff) in coeffs.into_iter().enumerate() {
                self.state[start + i] = coeff;
            }
        }

        // 5. Fill output buffer from state[0..RATE]
        self.output_buffer.clear();
        self.output_buffer.extend_from_slice(&self.state[..RATE]);
    }
}

impl<const WIDTH: usize, const RATE: usize> CircuitChallenger<WIDTH, RATE> {
    /// Create a challenger with BabyBear D4 Width16 configuration (default).
    pub fn new_babybear() -> Self {
        Self::new(Poseidon2Config::BabyBearD4Width16)
    }

    /// Create a challenger with KoalaBear D4 Width16 configuration.
    pub fn new_koalabear() -> Self {
        Self::new(Poseidon2Config::KoalaBearD4Width16)
    }
}

impl<BF, EF, const WIDTH: usize, const RATE: usize> RecursiveChallenger<BF, EF>
    for CircuitChallenger<WIDTH, RATE>
where
    BF: PrimeField64,
    EF: ExtensionField<BF>,
{
    fn observe(&mut self, circuit: &mut CircuitBuilder<EF>, value: Target) {
        // Ensure initialized
        self.init::<BF, EF>(circuit);

        // Any buffered output is now invalid (matches native behavior)
        self.output_buffer.clear();

        self.input_buffer.push(value);

        if self.input_buffer.len() == RATE {
            self.duplexing::<BF, EF>(circuit);
        }
    }

    fn sample(&mut self, circuit: &mut CircuitBuilder<EF>) -> Target {
        // Ensure initialized
        self.init::<BF, EF>(circuit);

        // If we have buffered inputs or ran out of outputs, duplex
        // (matches native DuplexChallenger::sample behavior)
        if !self.input_buffer.is_empty() || self.output_buffer.is_empty() {
            self.duplexing::<BF, EF>(circuit);
        }

        self.output_buffer
            .pop()
            .expect("Output buffer should be non-empty after duplexing")
    }

    fn observe_ext(&mut self, circuit: &mut CircuitBuilder<EF>, value: Target) {
        // Decompose extension element to D base coefficients
        let coeffs = circuit
            .decompose_ext_to_base_coeffs::<BF>(value)
            .expect("decomposition should succeed");

        // Observe each coefficient (matches native observe_algebra_element)
        for coeff in coeffs {
            self.observe(circuit, coeff);
        }
    }

    fn sample_ext(&mut self, circuit: &mut CircuitBuilder<EF>) -> Target {
        // Sample D base elements (matches native sample_algebra_element)
        let coeffs: Vec<_> = (0..EF::DIMENSION).map(|_| self.sample(circuit)).collect();

        // Recompose into extension element
        circuit
            .recompose_base_coeffs_to_ext::<BF>(&coeffs)
            .expect("recomposition should succeed")
    }

    fn sample_bits(
        &mut self,
        circuit: &mut CircuitBuilder<EF>,
        num_bits: usize,
    ) -> Result<Vec<Target>, CircuitBuilderError> {
        let base_sample = self.sample(circuit);
        // Decompose base field element to bits
        // We decompose the full base field bit width to ensure correct reconstruction
        let bits = circuit.decompose_to_bits::<BF>(base_sample, BF::bits())?;
        Ok(bits[..num_bits].to_vec())
    }

    fn check_pow_witness(
        &mut self,
        circuit: &mut CircuitBuilder<EF>,
        witness_bits: usize,
        witness: Target,
    ) -> Result<(), CircuitBuilderError> {
        // Observe witness as base field element
        self.observe(circuit, witness);

        // Sample and check leading bits are zero
        let bits = self.sample_bits(circuit, witness_bits)?;
        for bit in bits {
            circuit.assert_zero(bit);
        }

        Ok(())
    }

    fn clear(&mut self, circuit: &mut CircuitBuilder<EF>) {
        let zero = circuit.add_const(EF::ZERO);
        self.state = vec![zero; WIDTH];
        self.input_buffer.clear();
        self.output_buffer.clear();
        self.initialized = true;
    }
}

#[cfg(test)]
mod tests {
    use p3_baby_bear::{BabyBear, default_babybear_poseidon2_16};
    use p3_circuit::ops::generate_poseidon2_trace;
    use p3_field::extension::BinomialExtensionField;
    use p3_field::{BasedVectorSpace, PrimeCharacteristicRing};
    use p3_poseidon2_circuit_air::BabyBearD4Width16;

    use super::*;

    type Ext4 = BinomialExtensionField<BabyBear, 4>;
    const WIDTH: usize = 16;
    const RATE: usize = 8;

    fn setup_circuit_with_poseidon2() -> CircuitBuilder<Ext4> {
        let mut circuit = CircuitBuilder::<Ext4>::new();
        let perm = default_babybear_poseidon2_16();
        circuit.enable_poseidon2_perm::<BabyBearD4Width16, _>(
            generate_poseidon2_trace::<Ext4, BabyBearD4Width16>,
            perm,
        );
        circuit
    }

    #[test]
    fn test_circuit_challenger_observe_sample() {
        let mut circuit = setup_circuit_with_poseidon2();
        let mut challenger = CircuitChallenger::<WIDTH, RATE>::new_babybear();

        let val1 = circuit.add_const(Ext4::from(BabyBear::ONE));
        let val2 = circuit.add_const(Ext4::from(BabyBear::TWO));
        RecursiveChallenger::<BabyBear, Ext4>::observe(&mut challenger, &mut circuit, val1);
        RecursiveChallenger::<BabyBear, Ext4>::observe(&mut challenger, &mut circuit, val2);

        let challenge =
            RecursiveChallenger::<BabyBear, Ext4>::sample(&mut challenger, &mut circuit);
        assert!(challenge.0 > 0);
    }

    #[test]
    fn test_circuit_challenger_sample_ext_vec() {
        let mut circuit = setup_circuit_with_poseidon2();
        let mut challenger = CircuitChallenger::<WIDTH, RATE>::new_babybear();

        let challenges =
            RecursiveChallenger::<BabyBear, Ext4>::sample_ext_vec(&mut challenger, &mut circuit, 3);
        assert_eq!(challenges.len(), 3);
    }

    #[test]
    fn test_circuit_challenger_observe_ext() {
        let mut circuit = setup_circuit_with_poseidon2();
        let mut challenger = CircuitChallenger::<WIDTH, RATE>::new_babybear();

        // Observe an extension element (should decompose to 4 base coefficients)
        let ext_val = Ext4::from_basis_coefficients_slice(&[
            BabyBear::from_u64(1),
            BabyBear::from_u64(2),
            BabyBear::from_u64(3),
            BabyBear::from_u64(4),
        ])
        .unwrap();
        let target = circuit.add_const(ext_val);
        RecursiveChallenger::<BabyBear, Ext4>::observe_ext(&mut challenger, &mut circuit, target);

        // Should have 4 elements in input buffer
        assert_eq!(challenger.input_buffer.len(), 4);
    }

    #[test]
    fn test_circuit_challenger_clear() {
        let mut circuit = setup_circuit_with_poseidon2();
        let mut challenger = CircuitChallenger::<WIDTH, RATE>::new_babybear();

        let val = circuit.add_const(Ext4::from(BabyBear::ONE));
        RecursiveChallenger::<BabyBear, Ext4>::observe(&mut challenger, &mut circuit, val);

        assert_eq!(challenger.input_buffer.len(), 1);

        RecursiveChallenger::<BabyBear, Ext4>::clear(&mut challenger, &mut circuit);

        assert!(challenger.input_buffer.is_empty());
        assert!(challenger.output_buffer.is_empty());
        assert_eq!(challenger.state.len(), WIDTH);
    }

    #[test]
    fn test_circuit_challenger_duplexing_on_rate_full() {
        let mut circuit = setup_circuit_with_poseidon2();
        let mut challenger = CircuitChallenger::<WIDTH, RATE>::new_babybear();

        // Observe RATE elements to trigger duplexing
        for i in 0..RATE {
            let val = circuit.add_const(Ext4::from(BabyBear::from_u64(i as u64)));
            RecursiveChallenger::<BabyBear, Ext4>::observe(&mut challenger, &mut circuit, val);
        }

        // After RATE observations, input buffer should be empty (duplexed)
        assert!(challenger.input_buffer.is_empty());
        // Output buffer should be filled
        assert_eq!(challenger.output_buffer.len(), RATE);
    }

    #[test]
    fn test_circuit_challenger_partial_absorb_then_sample() {
        let mut circuit = setup_circuit_with_poseidon2();
        let mut challenger = CircuitChallenger::<WIDTH, RATE>::new_babybear();

        // Observe 3 elements (partial, not reaching RATE)
        for i in 0..3 {
            let val = circuit.add_const(Ext4::from(BabyBear::from_u64(i as u64)));
            RecursiveChallenger::<BabyBear, Ext4>::observe(&mut challenger, &mut circuit, val);
        }

        assert_eq!(challenger.input_buffer.len(), 3);

        // Sample should trigger duplexing with partial input
        let _sample = RecursiveChallenger::<BabyBear, Ext4>::sample(&mut challenger, &mut circuit);

        // After sample, input buffer should be empty
        assert!(challenger.input_buffer.is_empty());
        // Output buffer should have RATE - 1 elements (one was popped)
        assert_eq!(challenger.output_buffer.len(), RATE - 1);
    }
}
