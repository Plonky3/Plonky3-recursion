pub mod poseidon_perm;

// Crate-internal only
pub(crate) use poseidon_perm::PoseidonPermExecutor;
pub use poseidon_perm::{
    // Prover/AIR (trace access)
    Poseidon2CircuitRow,
    Poseidon2Params,
    Poseidon2Trace,
    // Builder API
    PoseidonPermCall,
    // Configuration
    PoseidonPermConfig,
    PoseidonPermExec,
    PoseidonPermOps,
    PoseidonPermPrivateData,
    generate_poseidon2_trace,
};
