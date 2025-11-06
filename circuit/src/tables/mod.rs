//! Execution trace tables for zkVM circuit operations.

mod add;
mod constant;
mod mmcs;
mod mul;
mod poseidon2;
mod public;
mod runner;
mod witness;

pub use add::AddTrace;
pub use constant::ConstTrace;
pub use mmcs::{MmcsPathTrace, MmcsPrivateData, MmcsTrace};
pub use mul::MulTrace;
pub use poseidon2::{Poseidon2CircuitRow, Poseidon2CircuitTrace};
pub use public::PublicTrace;
pub use runner::CircuitRunner;
pub use witness::WitnessTrace;

/// Execution traces for all tables.
///
/// This structure holds the complete execution trace of a circuit,
/// containing all the data needed to generate proofs.
#[derive(Debug, Clone)]
pub struct Traces<F> {
    /// Central witness table (bus) storing all intermediate values.
    pub witness_trace: WitnessTrace<F>,
    /// Constant table for compile-time known values.
    pub const_trace: ConstTrace<F>,
    /// Public input table for externally provided values.
    pub public_trace: PublicTrace<F>,
    /// Addition operation table.
    pub add_trace: AddTrace<F>,
    /// Multiplication operation table.
    pub mul_trace: MulTrace<F>,
    /// MMCS (Merkle tree) verification table.
    pub mmcs_trace: MmcsTrace<F>,
}
