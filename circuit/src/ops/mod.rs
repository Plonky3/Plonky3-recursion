pub mod hash;
pub mod mmcs;
pub mod poseidon2_perm;

pub(crate) use poseidon2_perm::Poseidon2PermExecutor;
pub use poseidon2_perm::{
    // D=1 configuration for base field challenges
    BabyBearD1Width16,
    // Prover/AIR (trace access)
    Poseidon2CircuitRow,
    Poseidon2Config,
    Poseidon2Params,
    // Builder API
    Poseidon2PermCall,
    // Configuration
    Poseidon2PermExec,
    Poseidon2PermOps,
    Poseidon2PermPrivateData,
    Poseidon2Trace,
    generate_poseidon2_trace,
};
