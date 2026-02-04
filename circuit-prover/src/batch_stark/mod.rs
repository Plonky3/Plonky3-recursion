//! Batch STARK prover and verifier that unifies all circuit tables
//! into a single batched STARK proof using `p3-batch-stark`.

mod circuit_table_air;
mod dynamic_air;
mod packing;
mod poseidon2_prover;
mod proof;
mod prover;
mod table_prover;

// Re-export public API
pub use dynamic_air::{BatchAir, CloneableBatchAir, DynamicAirEntry, NonPrimitiveTableEntry};
pub use packing::TablePacking;
pub use poseidon2_prover::Poseidon2Prover;
pub use proof::{
    BatchStarkProof, BatchStarkProverError, NUM_PRIMITIVE_TABLES, PrimitiveTable, RowCounts,
};
pub use prover::BatchStarkProver;
pub use table_prover::{BatchTableInstance, TableProver, transmute_traces};

#[cfg(test)]
mod tests;
