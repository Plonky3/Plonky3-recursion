use alloc::vec::Vec;

/// Poseidon2 operation table
pub struct Poseidon2CircuitRow<F> {
    /// Poseidon2 operation type
    pub is_sponge: bool,
    /// Reset flag
    pub reset: bool,
    /// Absorb flags
    pub absorb_flags: Vec<bool>,
    /// Inputs to the Poseidon2 permutation
    pub input_values: Vec<F>,
    /// Input indices
    pub input_indices: Vec<u32>,
    /// Output indices
    pub output_indices: Vec<u32>,
}
pub type Poseidon2CircuitTrace<F> = Vec<Poseidon2CircuitRow<F>>;
