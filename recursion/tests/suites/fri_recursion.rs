// Share fixture types so their generic proof code is compiled once per suite.
#[path = "../common/mod.rs"]
mod common;

#[path = "../aggregation_different_shapes.rs"]
mod aggregation_different_shapes;
#[path = "../arity4_leaf_hash_binding.rs"]
mod arity4_leaf_hash_binding;
#[path = "../arity4_mmcs_bus_balance.rs"]
mod arity4_mmcs_bus_balance;
#[path = "../fibonacci.rs"]
mod fibonacci;
#[path = "../fibonacci_batch_stark_prover.rs"]
mod fibonacci_batch_stark_prover;
#[path = "../fibonacci_batch_stark_prover_quintic.rs"]
mod fibonacci_batch_stark_prover_quintic;
#[path = "../fibonacci_batch_stark_prover_zk.rs"]
mod fibonacci_batch_stark_prover_zk;
#[path = "../fri.rs"]
mod fri;
#[path = "../fri_conditional_dispatch.rs"]
mod fri_conditional_dispatch;
#[path = "../fri_recursion_backend.rs"]
mod fri_recursion_backend;
#[path = "../goldilocks.rs"]
mod goldilocks;
#[path = "../hash_table_recursion.rs"]
mod hash_table_recursion;
#[path = "../mmcs_coeff_binding.rs"]
mod mmcs_coeff_binding;
#[path = "../mmcs_leaf_hash_binding.rs"]
mod mmcs_leaf_hash_binding;
#[path = "../mul_air.rs"]
mod mul_air;
#[path = "../per_table_min_height.rs"]
mod per_table_min_height;
#[path = "../poseidon2_shared_compat.rs"]
mod poseidon2_shared_compat;
#[path = "../preprocessing.rs"]
mod preprocessing;
#[path = "../recursive_arity4_mmcs.rs"]
mod recursive_arity4_mmcs;
#[path = "../test_lookups.rs"]
mod test_lookups;
#[path = "../zk_aggregation.rs"]
mod zk_aggregation;
#[path = "../zk_hiding_mmcs.rs"]
mod zk_hiding_mmcs;
