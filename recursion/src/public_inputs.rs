//! This module provides type-safe builders and helper functions
//! for constructing public inputs for recursive verification circuits.

use alloc::vec;
use alloc::vec::Vec;

use p3_batch_stark::BatchProof;
use p3_circuit::CircuitBuilder;
use p3_commit::Pcs;
use p3_field::{BasedVectorSpace, Field, PrimeField64};
use p3_uni_stark::{Proof, StarkGenericConfig, Val};

use crate::ProofTargets;
use crate::pcs::MAX_QUERY_INDEX_BITS;
use crate::traits::Recursive;
use crate::verifier::BatchProofTargets;

/// Builder for constructing public inputs.
///
/// The builder ensures public inputs are constructed in the same order as the circuit
/// allocates them.
///
/// # Example
/// ```ignore
/// let inputs = PublicInputBuilder::new()
///     .add_proof_values(proof_values)
///     .add_challenge(alpha)
///     .add_challenges(betas)
///     .build();
/// ```
#[derive(Default)]
pub struct PublicInputBuilder<F: Field> {
    inputs: Vec<F>,
}

impl<F: Field> PublicInputBuilder<F> {
    /// Create a new empty builder.
    pub const fn new() -> Self {
        Self { inputs: Vec::new() }
    }

    /// Add proof values extracted via `Recursive::get_values`.
    pub fn add_proof_values(&mut self, values: impl IntoIterator<Item = F>) -> &mut Self {
        self.inputs.extend(values);
        self
    }

    /// Add a single challenge value.
    pub fn add_challenge(&mut self, challenge: F) -> &mut Self {
        self.inputs.push(challenge);
        self
    }

    /// Add multiple challenge values.
    pub fn add_challenges(&mut self, challenges: impl IntoIterator<Item = F>) -> &mut Self {
        self.inputs.extend(challenges);
        self
    }

    /// Add a query index with automatic bit decomposition.
    pub fn add_query_index(&mut self, index: F) -> &mut Self
    where
        F: PrimeField64,
    {
        let index_usize = index.as_canonical_u64() as usize;

        // Add bit decomposition (MAX_QUERY_INDEX_BITS public inputs)
        for k in 0..MAX_QUERY_INDEX_BITS {
            let bit = if (index_usize >> k) & 1 == 1 {
                F::ONE
            } else {
                F::ZERO
            };
            self.inputs.push(bit);
        }

        self
    }

    /// Add pre-decomposed query index bits.
    pub fn add_query_index_bits(&mut self, bits: impl IntoIterator<Item = F>) -> &mut Self {
        self.inputs.extend(bits);
        self
    }

    /// Get the current number of inputs.
    pub const fn len(&self) -> usize {
        self.inputs.len()
    }

    /// Check if the builder is empty.
    pub const fn is_empty(&self) -> bool {
        self.inputs.is_empty()
    }

    /// Build and return the final input vector.
    pub fn build(self) -> Vec<F> {
        self.inputs
    }
}

/// Structure for organizing commitment opening data.
#[derive(Clone, Debug)]
pub struct CommitmentOpening<F: Field> {
    /// The commitment value (placeholder in arithmetic-only verification).
    pub commitment: F,
    /// Opened points: (evaluation point, values at that point).
    pub opened_points: Vec<(F, Vec<F>)>,
}

/// Helper for constructing public inputs for FRI-only verification circuits.
pub struct FriVerifierInputs<F: Field> {
    /// Values from FRI proof (commitments, opened values, final poly, etc.)
    pub fri_proof_values: Vec<F>,
    /// Alpha challenge for batch combination
    pub alpha: F,
    /// Beta challenges for FRI folding rounds
    pub betas: Vec<F>,
    /// Query index bits (pre-decomposed, little-endian)
    pub query_index_bits: Vec<Vec<F>>,
    /// Commitment openings (batch commitments and their opened values)
    pub commitment_openings: Vec<CommitmentOpening<F>>,
}

impl<F: Field> FriVerifierInputs<F> {
    /// Build the public input vector in the correct order.
    ///
    /// Order:
    /// 1. FRI proof values
    /// 2. Alpha challenge
    /// 3. Beta challenges
    /// 4. Query index bits (for each query)
    /// 5. Commitment openings (commitment, then (z, f(z)) pairs)
    pub fn build(self) -> Vec<F> {
        let mut builder = PublicInputBuilder::new();

        builder.add_proof_values(self.fri_proof_values);
        builder.add_challenge(self.alpha);
        builder.add_challenges(self.betas);

        for bits in self.query_index_bits {
            builder.add_query_index_bits(bits);
        }

        for opening in self.commitment_openings {
            builder.add_challenge(opening.commitment);
            for (z, values) in opening.opened_points {
                builder.add_challenge(z);
                builder.add_proof_values(values);
            }
        }

        builder.build()
    }
}

/// Helper for constructing public inputs for full STARK verification circuits.
///
/// This includes AIR public values, proof values, and challenges.
pub struct StarkVerifierInputs<F, EF>
where
    F: Field + PrimeField64,
    EF: Field + BasedVectorSpace<F> + From<F>,
{
    /// Public input values for the AIR being verified
    pub air_public_values: Vec<F>,
    /// Values extracted from the proof via `Recursive::get_values`
    pub proof_values: Vec<EF>,
    /// Values extracted from the preprocessed commitment (if any)
    pub preprocessed: Vec<EF>,
    /// All challenges (including query indices at the end)
    pub challenges: Vec<EF>,
    /// Number of FRI query proofs
    pub num_queries: usize,
}

impl<F, EF> StarkVerifierInputs<F, EF>
where
    F: Field + PrimeField64,
    EF: Field + BasedVectorSpace<F> + From<F>,
{
    /// Build the public input vector in the correct order.
    ///
    /// Order:
    /// 1. AIR public values
    /// 2. Proof values
    /// 3. All challenges (alpha, zeta, zeta_next, betas, query indices)
    pub fn build(self) -> Vec<EF> {
        let mut builder = PublicInputBuilder::new();

        builder.add_proof_values(self.air_public_values.iter().map(|&v| v.into()));
        builder.add_proof_values(self.proof_values);
        builder.add_proof_values(self.preprocessed);
        builder.add_challenges(self.challenges.iter().copied());

        builder.build()
    }
}

/// Constructs the public input values for a STARK verification circuit.
///
/// # Parameters
/// - `public_values`: The AIR public input values
/// - `proof_values`: Values extracted from the proof targets
/// - `challenges`: All challenge values
/// - `num_queries`: Number of FRI query proofs
///
/// # Returns
/// A vector of field elements ready to be passed to `CircuitRunner::set_public_inputs`
pub fn construct_stark_verifier_inputs<F, EF>(
    air_public_values: &[F],
    proof_values: &[EF],
    preprocessed: &[EF],
    challenges: &[EF],
    num_queries: usize,
) -> Vec<EF>
where
    F: Field + PrimeField64,
    EF: Field + BasedVectorSpace<F> + From<F>,
{
    StarkVerifierInputs {
        air_public_values: air_public_values.to_vec(),
        proof_values: proof_values.to_vec(),
        preprocessed: preprocessed.to_vec(),
        challenges: challenges.to_vec(),
        num_queries,
    }
    .build()
}

/// Constructs the public input values for a multi-instance STARK verification circuit.
pub fn construct_batch_stark_verifier_inputs<F, EF>(
    air_public_values: &[Vec<F>],
    proof_values: &[EF],
    challenges: &[EF],
) -> Vec<EF>
where
    F: Field + PrimeField64,
    EF: Field + BasedVectorSpace<F> + From<F>,
{
    let mut builder = PublicInputBuilder::new();

    for instance_pv in air_public_values {
        builder.add_proof_values(instance_pv.iter().map(|&v| v.into()));
    }

    builder.add_proof_values(proof_values.iter().copied());
    builder.add_challenges(challenges.iter().copied());

    builder.build()
}

/// Builder that handles both target allocation during circuit creation and value packing during execution.
///
/// # Example
/// ```ignore
/// // Phase 1: Circuit building
/// let mut circuit = CircuitBuilder::new();
/// let verifier = StarkVerifierInputsBuilder::allocate(&mut circuit, &proof, pis.len());
/// verify_circuit(config, air, &mut circuit, &verifier.proof_targets, &verifier.air_public_targets, ...)?;
/// let built_circuit = circuit.build()?;
///
/// // Phase 2: Execution
/// let challenges = generate_challenges(...);
/// let public_inputs = verifier.pack_values(&pis, &proof, &challenges, num_queries);
/// runner.set_public_inputs(&public_inputs)?;
/// ```
pub struct StarkVerifierInputsBuilder<SC, Comm, OpeningProof>
where
    SC: StarkGenericConfig,
    Comm: Recursive<
            SC::Challenge,
            Input = <SC::Pcs as Pcs<SC::Challenge, SC::Challenger>>::Commitment,
        >,
    OpeningProof:
        Recursive<SC::Challenge, Input = <SC::Pcs as Pcs<SC::Challenge, SC::Challenger>>::Proof>,
{
    /// AIR public input targets
    pub air_public_targets: Vec<crate::Target>,
    /// Allocated proof structure targets
    pub proof_targets: ProofTargets<SC, Comm, OpeningProof>,
    /// Allocated preprocessed commitment targets (if any)
    pub preprocessed_commit: Option<Comm>,
}

type Com<SC> = <<SC as StarkGenericConfig>::Pcs as Pcs<
    <SC as StarkGenericConfig>::Challenge,
    <SC as StarkGenericConfig>::Challenger,
>>::Commitment;

impl<SC, Comm, OpeningProof> StarkVerifierInputsBuilder<SC, Comm, OpeningProof>
where
    SC: StarkGenericConfig,
    Comm: Recursive<
            SC::Challenge,
            Input = <SC::Pcs as Pcs<SC::Challenge, SC::Challenger>>::Commitment,
        >,
    OpeningProof:
        Recursive<SC::Challenge, Input = <SC::Pcs as Pcs<SC::Challenge, SC::Challenger>>::Proof>,
{
    /// Allocate all targets during circuit building.
    ///
    /// # Parameters
    /// - `circuit`: Circuit builder to allocate targets in
    /// - `proof`: The proof (used to determine structure, not values)
    /// - `num_air_public_inputs`: Number of public inputs from the AIR
    ///
    /// # Returns
    /// A builder with allocated targets that can later pack values
    pub fn allocate(
        circuit: &mut CircuitBuilder<SC::Challenge>,
        proof: &Proof<SC>,
        preprocessed_commit: Option<Com<SC>>,
        num_air_public_inputs: usize,
    ) -> Self {
        // Allocate air public inputs
        let air_public_targets: Vec<crate::Target> = (0..num_air_public_inputs)
            .map(|_| circuit.add_public_input())
            .collect();

        // Allocate proof targets
        let proof_targets = ProofTargets::new(circuit, proof);

        // Allocate preprocessed commitment targets (if any)
        let preprocessed_commit = preprocessed_commit
            .as_ref()
            .map(|prep_comm| Comm::new(circuit, prep_comm));

        Self {
            air_public_targets,
            proof_targets,
            preprocessed_commit,
        }
    }

    /// Pack actual values in the same order as allocated targets.
    ///
    /// # Parameters
    /// - `air_public_values`: The AIR public input values
    /// - `proof`: The actual proof to extract values from
    /// - `challenges`: All challenge values (including query indices)
    /// - `num_queries`: Number of FRI query proofs
    ///
    /// # Returns
    /// Public inputs ready to be set
    pub fn pack_values(
        &self,
        air_public_values: &[Val<SC>],
        proof: &Proof<SC>,
        preprocessed_commit: &Option<Com<SC>>,
        challenges: &[SC::Challenge],
        num_queries: usize,
    ) -> Vec<SC::Challenge>
    where
        Val<SC>: PrimeField64,
        SC::Challenge: BasedVectorSpace<Val<SC>> + From<Val<SC>>,
    {
        let proof_values = ProofTargets::<SC, Comm, OpeningProof>::get_values(proof);

        let preprocessed = if let Some(prep_comm) = preprocessed_commit {
            Comm::get_values(prep_comm)
        } else {
            vec![]
        };

        construct_stark_verifier_inputs(
            air_public_values,
            &proof_values,
            &preprocessed,
            challenges,
            num_queries,
        )
    }
}

/// Builder for multi-instance STARK verification circuits.
pub struct BatchStarkVerifierInputsBuilder<SC, Comm, OpeningProof>
where
    SC: StarkGenericConfig,
    Comm: Recursive<
            SC::Challenge,
            Input = <SC::Pcs as Pcs<SC::Challenge, SC::Challenger>>::Commitment,
        >,
    OpeningProof:
        Recursive<SC::Challenge, Input = <SC::Pcs as Pcs<SC::Challenge, SC::Challenger>>::Proof>,
{
    /// AIR public input targets per instance.
    pub air_public_targets: Vec<Vec<crate::Target>>,
    /// Allocated proof structure targets.
    pub proof_targets: BatchProofTargets<SC, Comm, OpeningProof>,
}

impl<SC, Comm, OpeningProof> BatchStarkVerifierInputsBuilder<SC, Comm, OpeningProof>
where
    SC: StarkGenericConfig,
    Comm: Recursive<
            SC::Challenge,
            Input = <SC::Pcs as Pcs<SC::Challenge, SC::Challenger>>::Commitment,
        >,
    OpeningProof:
        Recursive<SC::Challenge, Input = <SC::Pcs as Pcs<SC::Challenge, SC::Challenger>>::Proof>,
{
    /// Allocate all targets during circuit building.
    pub fn allocate(
        circuit: &mut CircuitBuilder<SC::Challenge>,
        proof: &BatchProof<SC>,
        air_public_counts: &[usize],
    ) -> Self {
        assert_eq!(
            air_public_counts.len(),
            proof.opened_values.instances.len(),
            "public input count must match number of instances"
        );

        let air_public_targets = air_public_counts
            .iter()
            .map(|&count| (0..count).map(|_| circuit.add_public_input()).collect())
            .collect();

        let proof_targets = BatchProofTargets::new(circuit, proof);

        Self {
            air_public_targets,
            proof_targets,
        }
    }

    /// Pack actual values in the same order as allocated targets.
    pub fn pack_values(
        &self,
        air_public_values: &[Vec<Val<SC>>],
        proof: &BatchProof<SC>,
        challenges: &[SC::Challenge],
    ) -> Vec<SC::Challenge>
    where
        Val<SC>: PrimeField64,
        SC::Challenge: BasedVectorSpace<Val<SC>> + From<Val<SC>>,
    {
        let proof_values = BatchProofTargets::<SC, Comm, OpeningProof>::get_values(proof);

        construct_batch_stark_verifier_inputs(air_public_values, &proof_values, challenges)
    }
}

#[cfg(test)]
mod tests {
    use p3_baby_bear::BabyBear;
    use p3_field::PrimeCharacteristicRing;

    use super::*;

    #[test]
    fn test_public_input_builder() {
        let mut builder = PublicInputBuilder::<BabyBear>::new();

        assert_eq!(builder.len(), 0);
        assert!(builder.is_empty());

        builder
            .add_proof_values([BabyBear::from_u32(1), BabyBear::from_u32(2)])
            .add_challenge(BabyBear::from_u32(3))
            .add_challenges([BabyBear::from_u32(4), BabyBear::from_u32(5)]);

        assert_eq!(builder.len(), 5);
        assert!(!builder.is_empty());

        let inputs = builder.build();
        assert_eq!(inputs.len(), 5);
        assert_eq!(inputs[0], BabyBear::from_u32(1));
        assert_eq!(inputs[4], BabyBear::from_u32(5));
    }

    #[test]
    fn test_query_index_bit_decomposition() {
        let mut builder = PublicInputBuilder::<BabyBear>::new();

        // Index 5 = 0b101 in binary
        builder.add_query_index(BabyBear::from_u32(5));

        let inputs = builder.build();

        // Should have MAX_QUERY_INDEX_BITS bits
        assert_eq!(inputs.len(), MAX_QUERY_INDEX_BITS);

        // Check first few bits: 101 (little-endian)
        assert_eq!(inputs[0], BabyBear::ONE); // bit 0
        assert_eq!(inputs[1], BabyBear::ZERO); // bit 1
        assert_eq!(inputs[2], BabyBear::ONE); // bit 2

        // Rest should be zeros
        for &bit in &inputs[3..] {
            assert_eq!(bit, BabyBear::ZERO);
        }
    }

    #[cfg(test)]
    mod proptests {
        use proptest::prelude::*;

        use super::*;

        // Strategy for generating field elements
        fn field_element() -> impl Strategy<Value = BabyBear> {
            any::<u32>().prop_map(BabyBear::from_u32)
        }

        proptest! {
            #[test]
            fn build_preserves_order(vals in prop::collection::vec(field_element(), 1..20)) {
                let mut builder = PublicInputBuilder::<BabyBear>::new();
                builder.add_proof_values(vals.clone());

                let result = builder.build();

                // Check order
                prop_assert_eq!(result.len(), vals.len());
                for (i, &val) in vals.iter().enumerate() {
                    prop_assert_eq!(result[i], val);
                }
            }

            #[test]
            fn chaining_preserves_order(vals1 in prop::collection::vec(field_element(), 1..10),
                challenge in field_element(),
                vals2 in prop::collection::vec(field_element(), 1..10)
            ) {
                let mut builder = PublicInputBuilder::<BabyBear>::new();

                builder
                    .add_proof_values(vals1.clone())
                    .add_challenge(challenge)
                    .add_challenges(vals2.clone());

                let result = builder.build();

                let expected_len = vals1.len() + 1 + vals2.len();
                prop_assert_eq!(result.len(), expected_len);

                // Check order
                for (i, &val) in vals1.iter().enumerate() {
                    prop_assert_eq!(result[i], val, "vals1 order");
                }
                prop_assert_eq!(result[vals1.len()], challenge, "challenge position");
                for (i, &val) in vals2.iter().enumerate() {
                    prop_assert_eq!(result[vals1.len() + 1 + i], val, "vals2 order");
                }
            }
        }
    }
}
