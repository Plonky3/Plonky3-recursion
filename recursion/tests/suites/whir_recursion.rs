// Share fixture types so their generic proof code is compiled once per suite.
#[path = "../common/mod.rs"]
mod common;

#[path = "../trusted_state_transition_whir.rs"]
mod trusted_state_transition_whir;
#[path = "../whir_actual_type_guard.rs"]
mod whir_actual_type_guard;
#[path = "../whir_batch_stark_native.rs"]
mod whir_batch_stark_native;
#[path = "../whir_goldilocks_d2.rs"]
mod whir_goldilocks_d2;
#[path = "../whir_poseidon1_backend.rs"]
mod whir_poseidon1_backend;
#[path = "../whir_poseidon1_recursion.rs"]
mod whir_poseidon1_recursion;
#[path = "../whir_recursion_backend.rs"]
mod whir_recursion_backend;
#[path = "../whir_recursive_pcs.rs"]
mod whir_recursive_pcs;
#[path = "../whir_saturated_recursion.rs"]
mod whir_saturated_recursion;
#[path = "../whir_suffix_recursion.rs"]
mod whir_suffix_recursion;
#[path = "../whir_uni_stark.rs"]
mod whir_uni_stark;
#[path = "../whir_varying_folding.rs"]
mod whir_varying_folding;
#[path = "../whir_verifier.rs"]
mod whir_verifier;
