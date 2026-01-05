pub mod poseidon2_perm;

// Crate-internal only
pub(crate) use poseidon2_perm::Poseidon2PermExecutor;
pub use poseidon2_perm::{
    // Prover/AIR (trace access)
    Poseidon2CircuitRow,
    Poseidon2Params,
    // Builder API
    Poseidon2PermCall,
    // Configuration
    Poseidon2PermConfig,
    Poseidon2PermExec,
    Poseidon2PermOps,
    Poseidon2PermPrivateData,
    Poseidon2Trace,
    generate_poseidon2_trace,
};
