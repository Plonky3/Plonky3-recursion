#[path = "../common/test_config.rs"]
mod test_config;
use test_config::proof_config;

// Share fixture types so their generic proof code is compiled once per suite.
#[path = "../common/mod.rs"]
mod common;

#[path = "../binary_auxiliary_air.rs"]
mod binary_auxiliary_air;
#[path = "../binary_bus_auxiliary.rs"]
mod binary_bus_auxiliary;
#[path = "../binary_challenger.rs"]
mod binary_challenger;
#[path = "../binary_challenger_recursion.rs"]
mod binary_challenger_recursion;
#[path = "../binary_fraction_gkr.rs"]
mod binary_fraction_gkr;
#[path = "../binary_generic_sumcheck.rs"]
mod binary_generic_sumcheck;
#[path = "../binary_generic_sumcheck_transcript.rs"]
mod binary_generic_sumcheck_transcript;
#[path = "../binary_grouped_oracle.rs"]
mod binary_grouped_oracle;
#[path = "../binary_grouped_pcs.rs"]
mod binary_grouped_pcs;
#[path = "../binary_hash_artifacts.rs"]
mod binary_hash_artifacts;
#[path = "../binary_logup_star.rs"]
mod binary_logup_star;
#[path = "../binary_nonzero_challenges.rs"]
mod binary_nonzero_challenges;
#[path = "../binary_nonzero_tail.rs"]
mod binary_nonzero_tail;
#[path = "../binary_pcs.rs"]
mod binary_pcs;
#[path = "../binary_pcs_arithmetic.rs"]
mod binary_pcs_arithmetic;
#[path = "../binary_pcs_input.rs"]
mod binary_pcs_input;
#[path = "../binary_product_gkr.rs"]
mod binary_product_gkr;
#[path = "../binary_queries.rs"]
mod binary_queries;
#[path = "../binary_ring_switch.rs"]
mod binary_ring_switch;
#[path = "../binary_ring_tensor.rs"]
mod binary_ring_tensor;
#[path = "../binary_tower128.rs"]
mod binary_tower128;
#[path = "../binary_whir.rs"]
mod binary_whir;
#[path = "../binary_whir_arithmetic.rs"]
mod binary_whir_arithmetic;
#[path = "../binary_whir_bounds.rs"]
mod binary_whir_bounds;
#[path = "../binary_whir_queries.rs"]
mod binary_whir_queries;
