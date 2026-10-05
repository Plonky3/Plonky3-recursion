//! Plonky3 circuit prover (PoC): generic over base field and permutation.
//!
//! Generics glossary used across this crate:
//! - `F`: Prover/verifier base field (BabyBear/KoalaBear/Goldilocks). PCS and FFTs operate over `F`.
//! - `P`: Cryptographic permutation over `F` used by hash/compress and the challenger.
//! - `EF`: Element field in circuit traces. Either `F` (base) or `BinomialExtensionField<F, D>`.
//! - `D`: Element-field extension degree. Must equal `EF::DIMENSION`. AIRs are parameterized as `<F, D>`.
//! - `CD`: FRI challenge field degree, independent of `D`.
//!
//! - Build a field-specific config via [`config::baby_bear`], [`config::koala_bear`], or [`config::goldilocks`].
//! - Prepare a circuit once with [`BatchStarkProver::prepare_circuit`].
//! - Prove runner traces with [`PreparedCircuitProver::prove`] and verify against an
//!   independently retained [`CircuitVerifier`] and expected statement.
//!
//! Example (BabyBear):
//!
//! ```rust
//! use p3_baby_bear::BabyBear;
//! use p3_circuit::{CircuitBuilder, StatementExport};
//! use p3_circuit_prover::batch_stark_prover::{StatementAirBuilder, StatementPreprocessor, StatementProver};
//! use p3_circuit_prover::common::{NpoAirBuilder, NpoPreprocessor};
//! use p3_circuit_prover::{config, BatchStarkProver, ConstraintProfile};
//!
//! let mut builder = CircuitBuilder::<BabyBear>::new();
//! let x = builder.public_input();
//! let schema = builder.set_statement_exports::<BabyBear>(&[StatementExport::Base(x)]).unwrap();
//! let circuit = builder.build().unwrap();
//! let preprocessors: Vec<Box<dyn NpoPreprocessor<BabyBear>>> =
//!     vec![Box::new(StatementPreprocessor::new(schema.clone()))];
//! let air_builders: Vec<Box<dyn NpoAirBuilder<config::BabyBearConfig, 1>>> =
//!     vec![Box::new(StatementAirBuilder::<1>::new(schema.clone()))];
//! let mut prover = BatchStarkProver::new(config::baby_bear());
//! prover.register_table_prover(Box::new(StatementProver::<1>::new(schema)));
//! let prepared = prover.prepare_circuit::<BabyBear, 1>(
//!     &circuit, &preprocessors, &air_builders, ConstraintProfile::Standard,
//! ).unwrap();
//! let verifier = prepared.verifier(); // Retain this independently of each proof.
//! let expected = BabyBear::new(3);
//! let mut runner = circuit.runner();
//! runner.set_public_inputs(&[expected]).unwrap();
//! let traces = runner.run().unwrap();
//! let proof = prepared.prove(&traces).unwrap();
//! verifier.verify(&proof, &[expected]).unwrap();
//! ```
#![no_std]

extern crate alloc;

pub mod air;
pub mod batch_stark_prover;
pub mod common;
pub mod config;
pub mod constraint_profile;
pub mod direct;
pub mod field_params;
pub mod manifest;
mod primitive_plan;
pub mod tuning;

// Re-export main API
pub use batch_stark_prover::*;
pub use common::{
    BuiltinArtifactAir, BuiltinArtifactNpo, CircuitRelation, NpoRelation, StatementLayout,
    TrustedBuiltinArtifactRelation,
};
pub use constraint_profile::ConstraintProfile;
pub use p3_circuit::AggregationStatementLayout;
