//! Circuit-based challenger implementation.

use alloc::vec::Vec;
use core::array::from_fn;

use p3_circuit::ops::Poseidon2PermCall;
use p3_circuit::{CircuitBuilder, CircuitBuilderError, Poseidon2PermOps};
use p3_circuit_prover::Poseidon2Config;
// TODO: Replace with Poseidon2 perm once integrated.
use p3_field::Field;

use crate::Target;
use crate::traits::RecursiveChallenger;

/// Concrete challenger implementation for Fiat-Shamir operations in circuits.
pub struct CircuitChallenger<const RATE: usize> {
    /// Buffer of field elements waiting to be absorbed
    absorb_buffer: Vec<Target>,
    /// Buffer of field elements waiting to be squeezed
    squeeze_buffer: Vec<Target>,
    /// Whether the challenger has been reset before the next sampling
    reset: bool,
    /// Hash config to use for this challenger
    config: Poseidon2Config,
}

impl<const RATE: usize> CircuitChallenger<RATE> {
    /// Create a new circuit challenger with empty state.
    pub const fn new(config: Poseidon2Config) -> Self {
        Self {
            absorb_buffer: Vec::new(),
            squeeze_buffer: Vec::new(),
            reset: true,
            config,
        }
    }

    /// Flush the absorb buffer, filling the squeeze buffer.
    fn flush_absorb<F: Field>(
        &mut self,
        circuit: &mut CircuitBuilder<F>,
    ) -> Result<(), CircuitBuilderError> {
        // Consume all inputs (if any).
        let hash_inputs = self.absorb_buffer.chunks(RATE);
        let nb_chunks = hash_inputs.len();

        let zero = circuit.add_const(F::ZERO);

        // TODO: Ugly, avoid double loop.
        // If there are no inputs, do an empty hash.
        if nb_chunks == 0 {
            let (_, out_targets) = circuit.add_poseidon2_perm(Poseidon2PermCall {
                config: self.config,
                new_start: self.reset,
                merkle_path: false,
                mmcs_bit: None,
                inputs: if self.reset {
                    [Some(zero); 4]
                } else {
                    [None; 4]
                },
                out_ctl: [true, true],
                mmcs_index_sum: None,
            })?;

            self.reset = false;

            for out_target in out_targets {
                if let Some(target) = out_target {
                    self.squeeze_buffer.push(target);
                }
            }
        } else {
            for (i, chunk) in hash_inputs.enumerate() {
                let (_, out_targets) = circuit.add_poseidon2_perm(Poseidon2PermCall {
                    config: self.config,
                    new_start: self.reset,
                    merkle_path: false,
                    mmcs_bit: None,
                    inputs: from_fn(|i| {
                        if i < chunk.len() {
                            Some(chunk[i])
                        } else {
                            if self.reset { Some(zero) } else { None }
                        }
                    }),
                    out_ctl: if i == nb_chunks - 1 {
                        [true, true]
                    } else {
                        [false, false]
                    },
                    mmcs_index_sum: None,
                })?;

                self.reset = false;

                for out_target in out_targets {
                    if let Some(target) = out_target {
                        self.squeeze_buffer.push(target);
                    }
                }
            }
        }
        self.absorb_buffer.clear();

        Ok(())
    }
}

impl<F: Field, const RATE: usize> RecursiveChallenger<F> for CircuitChallenger<RATE> {
    fn observe(&mut self, _circuit: &mut CircuitBuilder<F>, value: Target) {
        self.absorb_buffer.push(value);
    }

    fn sample(&mut self, circuit: &mut CircuitBuilder<F>) -> Result<Target, CircuitBuilderError> {
        // If there are unabsorbed elements, or if the squeeze buffer is empty, flush.
        // If the squeeze buffer is not empty, just pop.
        if !self.absorb_buffer.is_empty() || self.squeeze_buffer.is_empty() {
            self.flush_absorb(circuit)?;
        }

        // Return the first squeeze buffer element.
        Ok(self.squeeze_buffer.remove(0))
    }

    fn clear(&mut self) {
        self.absorb_buffer.clear();
        self.squeeze_buffer.clear();
        self.reset = true;
    }
}

#[cfg(test)]
mod tests {
    use p3_baby_bear::{BabyBear, default_babybear_poseidon2_16};
    use p3_circuit::ops::generate_poseidon2_trace;
    use p3_field::PrimeCharacteristicRing;
    use p3_field::extension::BinomialExtensionField;
    use p3_poseidon2_circuit_air::BabyBearD4Width16;

    use super::*;

    const DEFAULT_CHALLENGER_RATE: usize = 2;
    const CONFIG: Poseidon2Config = Poseidon2Config::BabyBearD4Width16;
    type Base = BabyBear;
    type Ext4 = BinomialExtensionField<Base, 4>;
    type Params = BabyBearD4Width16;

    #[test]
    fn test_circuit_challenger_observe_sample() {
        let mut circuit = CircuitBuilder::<Ext4>::new();
        circuit.enable_poseidon2_perm::<Params, _>(
            generate_poseidon2_trace::<Ext4, Params>,
            default_babybear_poseidon2_16(),
        );
        let mut challenger = CircuitChallenger::<DEFAULT_CHALLENGER_RATE>::new(CONFIG);

        let val1 = circuit.add_const(Ext4::ONE);
        let val2 = circuit.add_const(Ext4::TWO);
        challenger.observe(&mut circuit, val1);
        challenger.observe(&mut circuit, val2);

        let challenge = challenger.sample(&mut circuit).expect("Sampling failed");
        assert!(challenge.0 > 0);
    }

    #[test]
    fn test_circuit_challenger_sample_vec() {
        let mut circuit = CircuitBuilder::<Ext4>::new();
        circuit.enable_poseidon2_perm::<Params, _>(
            generate_poseidon2_trace::<Ext4, Params>,
            default_babybear_poseidon2_16(),
        );
        let mut challenger = CircuitChallenger::<DEFAULT_CHALLENGER_RATE>::new(CONFIG);

        let challenges = challenger
            .sample_vec(&mut circuit, 3)
            .expect("Sampling failed");
        assert_eq!(challenges.len(), 3);
    }

    #[test]
    fn test_circuit_challenger_clear() {
        let mut circuit = CircuitBuilder::<Ext4>::new();
        circuit.enable_poseidon2_perm::<Params, _>(
            generate_poseidon2_trace::<Ext4, Params>,
            default_babybear_poseidon2_16(),
        );
        let mut challenger = CircuitChallenger::<DEFAULT_CHALLENGER_RATE>::new(CONFIG);

        let val = circuit.add_const(Ext4::ONE);
        challenger.observe(&mut circuit, val);
        challenger.sample(&mut circuit).expect("Sampling failed");
        assert_eq!(challenger.squeeze_buffer.len(), 1);

        challenger.observe(&mut circuit, val);
        assert_eq!(challenger.absorb_buffer.len(), 1);

        RecursiveChallenger::<Ext4>::clear(&mut challenger);

        assert!(challenger.reset);
        assert!(challenger.absorb_buffer.is_empty());
        assert!(challenger.squeeze_buffer.is_empty());
    }
}
