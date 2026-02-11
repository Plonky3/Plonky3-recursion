//! Circuit-based challenger implementation matching native DuplexChallenger exactly.
//!
//! This module provides [`CircuitChallenger`], which maintains state as coefficient-level
//! targets to ensure exact transcript compatibility with the native `DuplexChallenger`.
//!
//! # Soundness
//!
//! All Poseidon2 permutations in the challenger are CTL-verified against the Poseidon2 AIR
//! table. This ensures cryptographic soundness of the transcript computations.

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
/// 3. Poseidon2 permutation is applied (CTL-verified against Poseidon2 AIR table)
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

        // Validate config matches extension field dimension
        let config_d = self.poseidon2_config.d();
        assert_eq!(
            config_d,
            EF::DIMENSION,
            "Poseidon2 config dimension mismatch: config D={} but EF::DIMENSION={}",
            config_d,
            EF::DIMENSION
        );

        // 1. Overwrite state[0..n] with inputs (NOT XOR, matches native)
        for (i, val) in self.input_buffer.drain(..).enumerate() {
            self.state[i] = val;
        }

        // Branch based on extension degree
        if EF::DIMENSION == 1 {
            // D=1: Use base field permutation directly
            self.duplexing_base(circuit);
        } else {
            // D=4: Use extension field permutation with recomposition
            self.duplexing_ext::<BF, EF>(circuit);
        }

        // 5. Fill output buffer from state[0..RATE]
        self.output_buffer.clear();
        self.output_buffer.extend_from_slice(&self.state[..RATE]);
    }

    /// Duplexing for D=1 (base field): permutation operates directly on 16 elements.
    fn duplexing_base<EF>(&mut self, circuit: &mut CircuitBuilder<EF>)
    where
        EF: p3_field::Field,
    {
        // State is already 16 base field elements, use directly
        let inputs: [Target; 16] = self
            .state
            .clone()
            .try_into()
            .expect("state should have WIDTH=16 elements");

        // Apply Poseidon2 permutation via witness hint (base field version)
        let outputs = circuit
            .add_poseidon2_perm_for_challenger_base(self.poseidon2_config, inputs)
            .expect("poseidon2 base permutation should succeed");

        // Update state directly
        self.state = outputs.to_vec();
    }

    /// Duplexing for extension field (D=2 or D=4): pack/unpack around permutation.
    fn duplexing_ext<BF, EF>(&mut self, circuit: &mut CircuitBuilder<EF>)
    where
        BF: PrimeField64,
        EF: ExtensionField<BF>,
    {
        let num_ext_limbs = WIDTH / EF::DIMENSION;
        assert_eq!(
            num_ext_limbs, 4,
            "Expected 4 extension limbs for WIDTH/D (D=2 or D=4)"
        );

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

        // 3. Apply Poseidon2 permutation (CTL-verified against Poseidon2 AIR table)
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
    }
}

impl<const WIDTH: usize, const RATE: usize> CircuitChallenger<WIDTH, RATE> {
    /// Create a challenger with BabyBear D4 Width16 configuration (default).
    pub const fn new_babybear() -> Self {
        Self::new(Poseidon2Config::BabyBearD4Width16)
    }

    /// Create a challenger with BabyBear D1 Width16 configuration (base field challenges).
    pub const fn new_babybear_base() -> Self {
        Self::new(Poseidon2Config::BabyBearD1Width16)
    }

    /// Create a challenger with KoalaBear D4 Width16 configuration.
    pub const fn new_koalabear() -> Self {
        Self::new(Poseidon2Config::KoalaBearD4Width16)
    }

    /// Create a challenger with KoalaBear D1 Width16 configuration (base field challenges).
    pub const fn new_koalabear_base() -> Self {
        Self::new(Poseidon2Config::KoalaBearD1Width16)
    }

    /// Create a challenger with Goldilocks D2 Width8 configuration.
    pub const fn new_goldilocks() -> Self {
        Self::new(Poseidon2Config::GoldilocksD2Width8)
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
        // When no PoW is required, keep challenger state unchanged
        if witness_bits == 0 {
            return Ok(());
        }

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
