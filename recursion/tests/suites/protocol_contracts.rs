// Share fixture types so their generic proof code is compiled once per suite.
#[path = "../common/mod.rs"]
mod common;

#[path = "../assurance_backend.rs"]
mod assurance_backend;
#[path = "../assurance_transcript.rs"]
mod assurance_transcript;
#[path = "../builtin_config_kat.rs"]
mod builtin_config_kat;
#[path = "../builtin_config_native.rs"]
mod builtin_config_native;
#[path = "../builtin_config_proofs.rs"]
mod builtin_config_proofs;
#[path = "../builtin_config_registry.rs"]
mod builtin_config_registry;
#[path = "../builtin_fri_recursion_binary.rs"]
mod builtin_fri_recursion_binary;
#[path = "../builtin_fri_recursion_hiding.rs"]
mod builtin_fri_recursion_hiding;
#[path = "../builtin_fri_recursion_quaternary.rs"]
mod builtin_fri_recursion_quaternary;
#[path = "../builtin_whir_recursion.rs"]
mod builtin_whir_recursion;
#[path = "../challenger_base_sponge_binding.rs"]
mod challenger_base_sponge_binding;
#[path = "../challenger_sponge_binding.rs"]
mod challenger_sponge_binding;
#[path = "../challenger_transcript.rs"]
mod challenger_transcript;
