//! Circuit-based challenger implementation matching native DuplexChallenger exactly.
//!
//! This module provides [`CircuitChallenger`], which maintains state as coefficient-level
//! targets to ensure exact transcript compatibility with the native `DuplexChallenger`.
//!
//! # Soundness
//!
//! All Poseidon2 permutations in the challenger are CTL-verified against the Poseidon2 AIR table.
//! For BabyBear/KoalaBear width-16 sponges with `d()==1`, native Fiat–Shamir still uses the D=1
//! sponge. When the circuit field `EF` is an extension field (`EF::DIMENSION > 1`), in-circuit
//! duplexing uses `add_poseidon2_perm_for_challenger` with the packed config (e.g. D4 width 16) so
//! `WitnessChecks` CTL keys match the Poseidon2 circuit AIR (one extension limb per logical input).
//! When `EF::DIMENSION == 1`, `add_poseidon2_perm_for_challenger_base` is used instead.
//! Goldilocks width-8 uses extension-packed Poseidon (`d=2` from config) with the same grouping as `config.d()`.

use alloc::vec;
use alloc::vec::Vec;

use p3_circuit::ops::Poseidon2Config;
use p3_circuit::{CircuitBuilder, CircuitBuilderError};
use p3_field::{ExtensionField, PrimeField64};

use crate::Target;
use crate::challenger_perm::ChallengerPermConfig;
use crate::traits::RecursiveChallenger;

/// Circuit challenger with coefficient-level state management.
///
/// Maintains state as WIDTH base field coefficient targets to exactly match
/// the native `DuplexChallenger<F, P, WIDTH, RATE>` behavior.
///
/// # Type Parameters
/// - `WIDTH`: Sponge state width (16 for Poseidon2)
/// - `RATE`: Sponge rate (8 for typical configuration)
/// - `C`: Challenger permutation config (e.g. [`Poseidon2Config`])
pub struct CircuitChallenger<const WIDTH: usize, const RATE: usize, C: ChallengerPermConfig> {
    /// Permutation config for the challenger (e.g. Poseidon2).
    config: C,

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

impl<const WIDTH: usize, const RATE: usize, C: ChallengerPermConfig>
    CircuitChallenger<WIDTH, RATE, C>
{
    /// Create a new uninitialized circuit challenger.
    ///
    /// # Parameters
    /// - `config`: The permutation configuration (e.g. Poseidon2) for the challenger.
    ///
    /// Call `init()` to initialize the state with zeros before use.
    pub const fn new(config: C) -> Self {
        Self {
            config,
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
        let zero = circuit.define_const(EF::ZERO);
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

        let poseidon2_config = self
            .config
            .as_poseidon2()
            .expect("only Poseidon2 challenger permutation is supported");
        assert_eq!(
            poseidon2_config.width(),
            WIDTH,
            "Poseidon2 config width {} does not match CircuitChallenger WIDTH {}",
            poseidon2_config.width(),
            WIDTH
        );

        // 1. Overwrite state[0..n] with inputs (NOT XOR, matches native)
        for (i, val) in self.input_buffer.drain(..).enumerate() {
            self.state[i] = val;
        }

        let d_perm = poseidon2_config.d();
        if d_perm == 1 {
            assert_eq!(
                WIDTH, 16,
                "D=1 challenger sponge is only implemented for WIDTH=16 (base Poseidon2 NPO)"
            );
            if EF::DIMENSION == 1 {
                self.duplexing_base(circuit);
            } else {
                let packed = poseidon2_config.packed_for_ctl_when_sponge_d1(EF::DIMENSION);
                assert_eq!(
                    packed.d(),
                    EF::DIMENSION,
                    "CircuitChallenger: Poseidon2 sponge d()==1 with circuit EF dimension {} \
                     requires a packed Poseidon2 config with d()=={} (e.g. BabyBearD4Width16)",
                    EF::DIMENSION,
                    EF::DIMENSION,
                );
                self.duplexing_packed::<BF, EF>(circuit, packed);
            }
        } else {
            assert_eq!(
                WIDTH % d_perm,
                0,
                "Packed Poseidon2 config: WIDTH {} must be divisible by config d() {}",
                WIDTH,
                d_perm
            );
            self.duplexing_packed::<BF, EF>(circuit, *poseidon2_config);
        }

        // 5. Fill output buffer from state[0..RATE]
        self.output_buffer.clear();
        self.output_buffer.extend_from_slice(&self.state[..RATE]);
    }

    /// Duplexing for Poseidon2 configs with `d() == 1`: permutation on 16 base limbs (native `BF^16`).
    fn duplexing_base<EF>(&mut self, circuit: &mut CircuitBuilder<EF>)
    where
        EF: p3_field::Field,
    {
        let poseidon2_config = self
            .config
            .as_poseidon2()
            .expect("only Poseidon2 challenger permutation is supported");
        let inputs: [Target; 16] = self
            .state
            .clone()
            .try_into()
            .expect("state should have WIDTH=16 elements");

        let outputs = circuit
            .add_poseidon2_perm_for_challenger_base(*poseidon2_config, inputs)
            .expect("poseidon2 base permutation should succeed");

        self.state = outputs.to_vec();
    }

    /// Duplexing for packed Poseidon2 configs: group `perm_cfg.d()` embedded base coefficients per
    /// extension limb, matching the Poseidon2 NPO layout for that config.
    fn duplexing_packed<BF, EF>(
        &mut self,
        circuit: &mut CircuitBuilder<EF>,
        perm_cfg: Poseidon2Config,
    ) where
        BF: PrimeField64,
        EF: ExtensionField<BF>,
    {
        let d_pack = perm_cfg.d();
        assert_eq!(
            EF::DIMENSION,
            d_pack,
            "circuit extension degree must match Poseidon2 config d() for packed challenger duplexing"
        );
        let num_ext_limbs = WIDTH / d_pack;
        let mut ext_inputs = Vec::with_capacity(num_ext_limbs);
        for i in 0..num_ext_limbs {
            let start = i * d_pack;
            let end = start + d_pack;
            let ext = circuit
                .recompose_base_coeffs_to_ext::<BF>(&self.state[start..end])
                .expect("recomposition should succeed");
            ext_inputs.push(ext);
        }

        let ext_outputs = circuit
            .add_poseidon2_perm_for_challenger(perm_cfg, &ext_inputs)
            .expect("poseidon2 permutation should succeed");

        for (limb, &ext_out) in ext_outputs.iter().enumerate() {
            let coeffs = circuit
                .decompose_ext_to_base_coeffs::<BF>(ext_out)
                .expect("decomposition should succeed");
            let start = limb * d_pack;
            for (i, coeff) in coeffs.into_iter().enumerate() {
                self.state[start + i] = coeff;
            }
        }
    }
}

impl<const WIDTH: usize, const RATE: usize> CircuitChallenger<WIDTH, RATE, Poseidon2Config> {
    /// Create a challenger with BabyBear D1 Width16 (sponge matches native `DuplexChallenger` on `BabyBear^16`).
    pub const fn new_babybear() -> Self {
        Self::new(Poseidon2Config::BabyBearD1Width16)
    }

    /// Same as [`Self::new_babybear`] (alias).
    pub const fn new_babybear_base() -> Self {
        Self::new(Poseidon2Config::BabyBearD1Width16)
    }

    /// Create a challenger with KoalaBear D1 Width16 (sponge matches native `DuplexChallenger` on `KoalaBear^16`).
    pub const fn new_koalabear() -> Self {
        Self::new(Poseidon2Config::KoalaBearD1Width16)
    }

    /// Same as [`Self::new_koalabear`] (alias).
    pub const fn new_koalabear_base() -> Self {
        Self::new(Poseidon2Config::KoalaBearD1Width16)
    }
}

impl CircuitChallenger<8, 4, Poseidon2Config> {
    /// Create a challenger with Goldilocks D2 Width8 configuration.
    pub const fn new_goldilocks() -> Self {
        Self::new(Poseidon2Config::GoldilocksD2Width8)
    }
}

impl<BF, EF, const WIDTH: usize, const RATE: usize, C: ChallengerPermConfig>
    RecursiveChallenger<BF, EF> for CircuitChallenger<WIDTH, RATE, C>
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
        let zero = circuit.define_const(EF::ZERO);
        self.state = vec![zero; WIDTH];
        self.input_buffer.clear();
        self.output_buffer.clear();
        self.initialized = true;
    }
}
