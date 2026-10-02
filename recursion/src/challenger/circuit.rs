//! Circuit-based challenger implementation matching native DuplexChallenger exactly.
//!
//! This module provides [`CircuitChallenger`], which maintains state as coefficient-level
//! targets to ensure exact transcript compatibility with the native `DuplexChallenger`.
//!
//! # Soundness
//!
//! Every challenger permutation is a Poseidon2 (or Poseidon1) non-primitive op, so the AIR
//! constrains the permutation itself and the lookup argument ties the CTL-exposed limbs to the
//! witness bus. The two duplex paths differ in how the sponge state carries from one permutation
//! to the next:
//!
//! - `duplexing_base` (`D == 1`) leaves the capacity slots empty and threads `new_start`, so the
//!   compact D=1 AIR binds each row's capacity input to the previous row's capacity output.
//! - `duplexing_ext` (`D >= 2`) threads `new_start` as well and sends its permutation rows to
//!   the challenger's own table, so consecutive duplex steps are adjacent rows. It leaves every
//!   capacity slot empty: the AIR pins a chain start's capacity to zero plus the prefix-free
//!   length tag, and its sponge chain constraint binds each later row's capacity input to the
//!   previous row's capacity output plus the tag. An absorb packs the rate into extension limbs
//!   fed over CTL; a squeeze that continues the chain leaves the rate slots empty too, and the
//!   same chain constraint binds them to the previous row's rate output. The rate outputs stay
//!   packed until a sample reads them.
//!
//! Every packing and unpacking the challenger performs goes through the `recompose/coeff` table
//! (`recompose_base_coeffs_to_ext_with_coeff_lookups` /
//! `decompose_ext_to_base_coeffs_with_coeff_lookups`). That table publishes each coefficient on
//! the `WitnessChecks` bus as `[idx, v_i, 0, .., 0]` alongside the packed limb, so a state
//! coefficient is a base-field element tied to the limb it belongs to. The plain recompose
//! table publishes only the packed limb, which would leave every coefficient free; the ALU
//! `mul_add` chain publishes each coefficient as a bus-bound operand but constrains only
//! `sum(c_i · basis_i)`, which over an extension field still leaves each coefficient `D - 1`
//! free base dimensions — enough to move a squeezed challenge or a query index while every
//! permutation limb stays put. The builder refuses the `recompose/coeff` calls outright when
//! that table is not enabled, so neither weaker lowering can stand in for it silently;
//! [`CircuitChallenger::with_alu_state_packing`] selects the chain explicitly, and only the
//! sponge-chain regression tests do.

use alloc::vec;
use alloc::vec::Vec;

use p3_circuit::ops::{Poseidon1Config, Poseidon2Config};
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
/// - `WIDTH`: Sponge state width from the selected permutation configuration.
/// - `RATE`: Sponge rate (8 for typical configuration)
/// - `C`: Challenger permutation config ([`Poseidon1Config`] or [`Poseidon2Config`])
pub struct CircuitChallenger<const WIDTH: usize, const RATE: usize, C: ChallengerPermConfig> {
    /// Permutation config for the challenger (e.g. Poseidon2).
    config: C,

    /// Sponge state: WIDTH base field coefficient targets.
    /// Each target represents a base field element embedded in EF.
    ///
    /// The `D >= 2` path tracks only the rate slots here, and a rate slot whose limb is still in
    /// `packed_rate` is stale until a sample unpacks it.
    state: Vec<Target>,

    /// Buffered inputs not yet absorbed into state.
    input_buffer: Vec<Target>,

    /// Number of rate slots, `state[..output_len]`, that the last duplexing produced and no
    /// sample has read yet. Samples read them from the last one down, like the native output
    /// buffer.
    output_len: usize,

    /// Rate output limbs of the last `D >= 2` permutation that no sample has unpacked into
    /// `state` yet, by limb index. Always empty on the `D == 1` path.
    packed_rate: Vec<Option<Target>>,

    /// Whether the challenger has been initialized with zero state.
    initialized: bool,

    /// Whether a permutation has run at least once since the last init/clear.
    ///
    /// The first permutation of an instance starts a fresh sponge chain (`new_start=true`);
    /// every later one continues it, which is what turns the AIR's capacity chain constraint on.
    duplexed_once: bool,

    /// Whether the sponge state is packed through the ALU `mul_add` chain rather than the
    /// `recompose/coeff` table. See [`CircuitChallenger::with_alu_state_packing`].
    alu_state_packing: bool,
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
            output_len: 0,
            packed_rate: Vec::new(),
            initialized: false,
            duplexed_once: false,
            alu_state_packing: false,
        }
    }

    /// Packs and unpacks the sponge state through the ALU `mul_add` chain instead of the
    /// `recompose/coeff` table.
    ///
    /// **A transcript lowered this way does not bind its own coefficients.** The chain ties
    /// only `sum(c_i · basis_i)` per limb, which over an extension field leaves each
    /// coefficient `D - 1` free base dimensions — enough to move a squeezed challenge or a
    /// query index while every permutation limb stays put. It exists so the sponge-chain
    /// regression tests can exercise the AIR's capacity constraints under a second lowering.
    #[must_use]
    pub const fn with_alu_state_packing(mut self) -> Self {
        self.alu_state_packing = true;
        self
    }

    /// Packs `coeffs` into one extension limb under this challenger's chosen lowering.
    fn pack_limb<BF, EF>(&self, circuit: &mut CircuitBuilder<EF>, coeffs: &[Target]) -> Target
    where
        BF: PrimeField64,
        EF: ExtensionField<BF>,
    {
        if self.alu_state_packing {
            circuit.recompose_base_coeffs_to_ext_via_alu::<BF>(coeffs)
        } else {
            circuit.recompose_base_coeffs_to_ext_with_coeff_lookups::<BF>(coeffs)
        }
        .expect("the challenger's sponge packing needs `enable_recompose`")
    }

    /// Unpacks one extension limb into base coefficients under the same lowering.
    fn unpack_limb<BF, EF>(&self, circuit: &mut CircuitBuilder<EF>, limb: Target) -> Vec<Target>
    where
        BF: PrimeField64,
        EF: ExtensionField<BF>,
    {
        if self.alu_state_packing {
            circuit.decompose_ext_to_base_coeffs_via_alu::<BF>(limb)
        } else {
            circuit.decompose_ext_to_base_coeffs_with_coeff_lookups::<BF>(limb)
        }
        .expect("the challenger's sponge unpacking needs `enable_recompose`")
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
        let num_absorbed = self.input_buffer.len();
        debug_assert!(num_absorbed <= RATE, "Input buffer exceeds RATE");

        let p2_config = self.config.as_poseidon2().copied();
        let p1_config = self.config.as_poseidon1().copied();

        // 1. Overwrite state[0..n] with inputs (NOT XOR, matches native)
        for (i, val) in self.input_buffer.drain(..).enumerate() {
            self.state[i] = val;
        }

        // 2. Prefix-free padding (matches native `DuplexChallenger` 0.6): on an absorb
        // (`num_absorbed > 0`) zero the rate slots the inputs did not overwrite, which together
        // replace every rate limb the previous permutation left packed. The permutation row
        // binds the absorbed length into the first capacity element (`absorb_len`). An empty
        // buffer is a squeeze: the state is permuted untouched.
        if num_absorbed > 0 {
            let zero = circuit.define_const(EF::ZERO);
            for slot in self.state.iter_mut().take(RATE).skip(num_absorbed) {
                *slot = zero;
            }
            self.packed_rate.clear();
        }

        // Branch by NPO packing (`config.d()`), not `EF::DIMENSION`, so a quintic
        // (or other) challenge field can still use a base width-16 permutation.
        if let Some(cfg) = p2_config {
            if cfg.d() == 1 {
                self.duplexing_base(circuit, cfg, num_absorbed);
            } else {
                self.duplexing_ext::<BF, EF>(circuit, cfg, num_absorbed);
            }
        } else if let Some(cfg) = p1_config {
            if cfg.d() == 1 {
                self.duplexing_base_p1(circuit, cfg, num_absorbed);
            } else {
                self.duplexing_ext_p1::<BF, EF>(circuit, cfg, num_absorbed);
            }
        } else {
            panic!("unsupported challenger permutation");
        }

        // 5. Every rate slot is a fresh output.
        self.output_len = RATE;
    }

    /// Duplexing for D=1 (base field): permutation operates directly on 16 elements.
    ///
    /// The first call uses `new_start=true`: rate slots are CTL-verified; capacity slots use
    /// `None` (initial state is zero and the compact D=1 AIR asserts zero capacity on sponge
    /// chain starts). Subsequent calls use `new_start=false` with `None` for capacity so the
    /// AIR enforces continuity via the chain constraint.
    fn duplexing_base<EF>(
        &mut self,
        circuit: &mut CircuitBuilder<EF>,
        poseidon2_config: Poseidon2Config,
        absorb_len: usize,
    ) where
        EF: p3_field::Field,
    {
        let (new_start, inputs) = if !self.duplexed_once {
            // First permutation: CTL-verify rate only; capacity is zero without witness CTL.
            let inputs: [Option<Target>; 16] =
                core::array::from_fn(|i| if i < RATE { Some(self.state[i]) } else { None });
            (true, inputs)
        } else {
            // Subsequent permutations: CTL-verify rate inputs only; capacity via chain.
            let inputs: [Option<Target>; 16] =
                core::array::from_fn(|i| if i < RATE { Some(self.state[i]) } else { None });
            (false, inputs)
        };
        self.duplexed_once = true;

        let outputs = circuit
            .add_poseidon2_perm_for_challenger_base(poseidon2_config, new_start, inputs, absorb_len)
            .expect("poseidon2 base permutation should succeed");

        self.state = outputs.to_vec();
    }

    /// Duplexing for D>=2: the state is packed into `WIDTH / D` extension limbs.
    ///
    /// No capacity limb is fed over CTL. `new_start` is `true` only for the first permutation
    /// of this instance, and the challenger table's AIR pins that row's capacity to zero plus
    /// `absorb_len`; on every later row its sponge chain constraint binds the capacity to the
    /// previous row's capacity output plus `absorb_len`. See [`Self::ext_perm_inputs`] for the
    /// rate. The rate outputs stay packed in `packed_rate` until a sample reads them.
    fn duplexing_ext<BF, EF>(
        &mut self,
        circuit: &mut CircuitBuilder<EF>,
        poseidon2_config: Poseidon2Config,
        absorb_len: usize,
    ) where
        BF: PrimeField64,
        EF: ExtensionField<BF>,
    {
        let new_start = !self.duplexed_once;
        self.duplexed_once = true;

        let ext_inputs = self.ext_perm_inputs::<BF, EF>(circuit, new_start, absorb_len);
        let ext_outputs = circuit
            .add_poseidon2_perm_for_challenger(poseidon2_config, new_start, &ext_inputs, absorb_len)
            .expect("poseidon2 permutation should succeed");

        self.packed_rate = ext_outputs[..RATE / EF::DIMENSION]
            .iter()
            .copied()
            .map(Some)
            .collect();
    }

    /// Input slots of a `D >= 2` duplex step.
    ///
    /// Every capacity slot is empty (see [`Self::duplexing_ext`]). A squeeze that continues the
    /// chain leaves its rate slots empty as well: the sponge chain constraint binds an empty rate
    /// limb to the previous row's rate output, which is exactly the state a squeeze permutes.
    /// Otherwise each rate limb is packed from `state` and fed over CTL, since no chain
    /// constraint binds the rate of an absorb (the observed values and their zero padding) or of
    /// a chain start.
    fn ext_perm_inputs<BF, EF>(
        &self,
        circuit: &mut CircuitBuilder<EF>,
        new_start: bool,
        absorb_len: usize,
    ) -> Vec<Option<Target>>
    where
        BF: PrimeField64,
        EF: ExtensionField<BF>,
    {
        let d = EF::DIMENSION;
        let chained_squeeze = absorb_len == 0 && !new_start;
        debug_assert!(
            chained_squeeze || self.packed_rate.is_empty(),
            "a rate limb fed over CTL must be packed from unpacked coefficients"
        );
        (0..WIDTH / d)
            .map(|limb| {
                (limb < RATE / d && !chained_squeeze).then(|| {
                    self.pack_limb::<BF, EF>(circuit, &self.state[limb * d..(limb + 1) * d])
                })
            })
            .collect()
    }

    /// Base coefficient in rate slot `i`, unpacking its limb from `packed_rate` the first time a
    /// sample reads it.
    fn rate_slot<BF, EF>(&mut self, circuit: &mut CircuitBuilder<EF>, i: usize) -> Target
    where
        BF: PrimeField64,
        EF: ExtensionField<BF>,
    {
        let d = EF::DIMENSION;
        let limb = i / d;
        if let Some(packed) = self.packed_rate.get_mut(limb).and_then(Option::take) {
            let coeffs = self.unpack_limb::<BF, EF>(circuit, packed);
            self.state[limb * d..(limb + 1) * d].copy_from_slice(&coeffs);
        }
        self.state[i]
    }

    /// Poseidon1 D=1 duplexing.
    fn duplexing_base_p1<EF>(
        &mut self,
        circuit: &mut CircuitBuilder<EF>,
        poseidon1_config: Poseidon1Config,
        absorb_len: usize,
    ) where
        EF: p3_field::Field,
    {
        let new_start = !self.duplexed_once;
        let inputs: [Option<Target>; 16] =
            core::array::from_fn(|i| if i < RATE { Some(self.state[i]) } else { None });
        self.duplexed_once = true;

        let outputs = circuit
            .add_poseidon1_perm_for_challenger_base(poseidon1_config, new_start, inputs, absorb_len)
            .expect("poseidon1 base permutation should succeed");

        self.state = outputs.to_vec();
    }

    /// Poseidon1 D>=2 duplexing. See [`Self::duplexing_ext`].
    fn duplexing_ext_p1<BF, EF>(
        &mut self,
        circuit: &mut CircuitBuilder<EF>,
        poseidon1_config: Poseidon1Config,
        absorb_len: usize,
    ) where
        BF: PrimeField64,
        EF: ExtensionField<BF>,
    {
        let new_start = !self.duplexed_once;
        self.duplexed_once = true;

        let ext_inputs = self.ext_perm_inputs::<BF, EF>(circuit, new_start, absorb_len);
        let ext_outputs = circuit
            .add_poseidon1_perm_for_challenger(poseidon1_config, new_start, &ext_inputs, absorb_len)
            .expect("poseidon1 permutation should succeed");

        self.packed_rate = ext_outputs[..RATE / EF::DIMENSION]
            .iter()
            .copied()
            .map(Some)
            .collect();
    }
}

impl<const WIDTH: usize, const RATE: usize> CircuitChallenger<WIDTH, RATE, Poseidon2Config> {
    /// Create a challenger with BabyBear D4 Width16 configuration (default).
    pub const fn new_babybear() -> Self {
        Self::new(Poseidon2Config::BABY_BEAR_D4_W16)
    }

    /// Create a challenger with BabyBear D1 Width16 configuration (base field challenges).
    pub const fn new_babybear_base() -> Self {
        Self::new(Poseidon2Config::BABY_BEAR_D1_W16)
    }

    /// Create a challenger with KoalaBear D4 Width16 configuration.
    pub const fn new_koalabear() -> Self {
        Self::new(Poseidon2Config::KOALA_BEAR_D4_W16)
    }

    /// Create a challenger with KoalaBear D1 Width16 configuration (base field challenges).
    pub const fn new_koalabear_base() -> Self {
        Self::new(Poseidon2Config::KOALA_BEAR_D1_W16)
    }
}

impl CircuitChallenger<8, 4, Poseidon2Config> {
    /// Create a challenger with Goldilocks D2 Width8 configuration.
    pub const fn new_goldilocks() -> Self {
        Self::new(Poseidon2Config::GOLDILOCKS_D2_W8)
    }
}

impl<const WIDTH: usize, const RATE: usize> CircuitChallenger<WIDTH, RATE, Poseidon1Config> {
    /// Create a Poseidon1 challenger with BabyBear D1 Width16 (base field challenges).
    pub const fn new_babybear_poseidon1_base() -> Self {
        Self::new(Poseidon1Config::BABY_BEAR_D1_W16)
    }

    /// Create a Poseidon1 challenger with KoalaBear D1 Width16 (base field challenges).
    pub const fn new_koalabear_poseidon1_base() -> Self {
        Self::new(Poseidon1Config::KOALA_BEAR_D1_W16)
    }
}

impl CircuitChallenger<8, 4, Poseidon1Config> {
    /// Create a Poseidon1 challenger with Goldilocks D2 Width8 configuration.
    pub const fn new_goldilocks_poseidon1() -> Self {
        Self::new(Poseidon1Config::GOLDILOCKS_D2_W8)
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
        self.output_len = 0;

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
        if !self.input_buffer.is_empty() || self.output_len == 0 {
            self.duplexing::<BF, EF>(circuit);
        }

        self.output_len = self
            .output_len
            .checked_sub(1)
            .expect("Output buffer should be non-empty after duplexing");
        self.rate_slot::<BF, EF>(circuit, self.output_len)
    }

    fn observe_ext(&mut self, circuit: &mut CircuitBuilder<EF>, value: Target) {
        // Decompose extension element to D base coefficients
        let coeffs = self.unpack_limb::<BF, EF>(circuit, value);

        // Observe each coefficient (matches native observe_algebra_element)
        for coeff in coeffs {
            self.observe(circuit, coeff);
        }
    }

    fn sample_ext(&mut self, circuit: &mut CircuitBuilder<EF>) -> Target {
        // Sample D base elements (matches native sample_algebra_element)
        let coeffs: Vec<_> = (0..EF::DIMENSION).map(|_| self.sample(circuit)).collect();

        // Recompose into extension element
        self.pack_limb::<BF, EF>(circuit, &coeffs)
    }

    fn sample_bits(
        &mut self,
        circuit: &mut CircuitBuilder<EF>,
        num_bits: usize,
    ) -> Result<Vec<Target>, CircuitBuilderError> {
        // A verifier parameter with `num_bits > BF::bits()` would panic on the
        // `bits[..num_bits]` slice below, so we check and abort early if needed.
        let bf_bits = BF::bits();
        if num_bits > bf_bits {
            return Err(CircuitBuilderError::BinaryDecompositionTooManyBits {
                expected: bf_bits,
                n_bits: num_bits,
            });
        }
        let base_sample = self.sample(circuit);
        // Decompose base field element to bits
        // We decompose the full base field bit width to ensure correct reconstruction
        let bits = circuit.decompose_to_bits::<BF>(base_sample, bf_bits)?;
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
        self.output_len = 0;
        self.packed_rate.clear();
        self.initialized = true;
        self.duplexed_once = false;
    }
}
