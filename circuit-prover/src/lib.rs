//! Plonky3 circuit prover (PoC): generic over base field and permutation.
//!
//! - Build a field-specific config via `config::{babybear_config, koalabear_config}`.
//! - Create a `MultiTableProver` from that config.
//! - Generate traces from a `p3_circuit::Circuit` runner and prove/verify.
//!
//! Example (BabyBear):
//!
//! ```ignore
//! use p3_baby_bear::BabyBear;
//! use p3_circuit::builder::CircuitBuilder;
//! use p3_circuit_prover::config::babybear_config::build_standard_config_babybear;
//! use p3_circuit_prover::MultiTableProver;
//!
//! let mut builder = CircuitBuilder::<BabyBear>::new();
//! let x = builder.add_public_input();
//! let y = builder.add_public_input();
//! let z = builder.add(x, y);
//! builder.assert_zero(builder.sub(z, builder.add_const(BabyBear::from_u64(3))));
//! let circuit = builder.build();
//! let mut runner = circuit.runner();
//! runner.set_public_inputs(&[BabyBear::from_u64(1), BabyBear::from_u64(2)]).unwrap();
//! let traces = runner.run().unwrap();
//! let cfg = build_standard_config_babybear();
//! let prover = MultiTableProver::new(cfg);
//! let proof = prover.prove_all_tables(&traces).unwrap();
//! prover.verify_all_tables(&proof).unwrap();
//! ```
#![no_std]

extern crate alloc;

pub mod air;
pub mod config;
pub mod field_params;
pub mod prover;

// Re-export main API
pub use prover::{MultiTableProof, MultiTableProver};
