//! Blake3 membership proof non-primitive operation.
//!
//! This module contains all Blake3 membership proof related code:
//! - Builder API ([`Blake3Call`])
//! - Executor ([`executor::Blake3Executor`])
//! - Execution state ([`state::Blake3ExecutionState`])
//! - Private data ([`Blake3PrivateData`])
//! - Trace generation types ([`Blake3CircuitRow`], [`Blake3Trace`])
//!
//! The Blake3 table carries out Merkle membership proofs using Blake3
//! compression. Each compression spans 8 Ops (7 mixing rounds + 1
//! finalization row).
//!
//! - **Chaining**: Can start a new proof (`new_start`) or continue from
//!   the previous compression's output.
//! - **Round structure**: `is_new_blake` marks the first round of a
//!   compression; the executor tracks the round counter internally.
//! - **Hash outputs**: When `is_hash_output` is set on the last round,
//!   cv_out is exposed on the WitnessChecks bus via a CTL Receive
//!   interaction.
//! - **Private data**: Each round Op receives 8 bytes of `uint8_data`
//!   via [`Blake3PrivateData`], matching the per-Op private data model
//!   used by Poseidon2.
//! - **Merkle roots**: Verified at the circuit level against constant
//!   public values (not stored in this table).

pub mod builder;
pub mod call;
pub(crate) mod config;
pub(crate) mod executor;
pub mod plugin;
pub mod state;
pub mod trace;

pub use call::Blake3Call;
pub use plugin::Blake3CircuitPlugin;
pub use state::Blake3PrivateData;
pub use trace::{Blake3CircuitRow, Blake3Trace, generate_blake3_trace};
