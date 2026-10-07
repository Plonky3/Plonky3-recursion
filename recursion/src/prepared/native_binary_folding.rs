//! Prepared folding verifier circuits for tower children, proved over Tower128.

use alloc::sync::Arc;
use alloc::vec::Vec;

use p3_binary_dft::EncodableLevel;
use p3_binary_field::{BinaryField128, TowerLevel};
use p3_binary_pcs::transcript::BinaryPcsShape;
use p3_binary_pcs::{BinaryPcsConfig, BinaryPcsParams, ChallengeField, FoldAlphabet};
use p3_circuit::ops::binary_encoding::{BinaryCircuitEncoding, NativeBinaryEncoding};
use p3_circuit::ops::binary_host::BinaryCircuitHost;
use p3_circuit::ops::{ByteHash, NativeTower128Target};
use p3_circuit::{Circuit, CircuitBuilder, CircuitConstructionLimits};
use p3_circuit_prover::direct::DirectCircuitLimits;
use p3_circuit_prover::native_bus::{NativeBusCircuit, NativeBusCircuitAir};
use p3_field::{ExtensionField, PackedValue};
use p3_matrix::dense::RowMajorMatrix;
use p3_multi_stark::MultiStarkProof;
use p3_multi_stark::folder::VerifierAir;

use super::native_binary::codeword_cells;
use crate::artifact::{
    ArtifactLimits, BinaryNativeAuthority, BinaryNativeConfig, BinaryNativeGroupedAuthority,
    BinaryNativeGroupedConfig, BinaryNativeGroupedPcsParameters, BinaryNativeGroupedProver,
    BinaryNativePcsParameters, BinaryNativeProver, BinaryNativeVerifierSpec,
    VerifiedBinaryNativeGroupedProof, VerifiedBinaryNativeProof,
};
use crate::pcs::binary::{BinaryCodewordGrouping, RecursiveBinaryTowerField};
use crate::verifier::{
    BinaryGroupedMultiStarkInputShape, BinaryMultiStarkInputShape, BinaryMultiStarkProofTargets,
    VerificationError,
};
use crate::{BinaryQueryContinuation, BinaryTower128Challenger};

type F = BinaryField128;
type H = NativeBinaryEncoding;
type OutputAir = NativeBusCircuitAir<F>;
/// A complete native folding recursive proof; no prime-field output layer is involved.
pub type NativeBinaryFoldingRecursiveProof = MultiStarkProof<BinaryNativeConfig<F, F>>;
/// A complete native folding recursive proof whose Merkle leaves are whole
/// fold cosets; no prime-field output layer is involved.
pub type NativeBinaryGroupedFoldingRecursiveProof =
    MultiStarkProof<BinaryNativeGroupedConfig<F, F>>;

/// Caller-selected folding output protocol and transcript. Security and
/// grinding settings are validated by the checked output authority. Each
/// output PCS draws its derived query count plus `query_draw_slack` candidates
/// in circuit. These proofs do not hide the witness.
pub struct NativeBinaryFoldingRecursionOptions {
    pub main: BinaryPcsParams,
    pub preprocessed: BinaryPcsParams,
    /// Must not exceed the output circuit's main and preprocessed variable counts.
    pub log_folding_factor: usize,
    /// Must not exceed the depth of the smallest committed BaseFold tree;
    /// `cap_height <= log_inv_rate + 1` is always valid. Grouped layers,
    /// whose smallest tree has `2^log_inv_rate` coset leaves, require
    /// `cap_height <= log_inv_rate`.
    pub cap_height: usize,
    pub query_draw_slack: usize,
    pub initial_bytes: Vec<u8>,
    pub sumcheck_pow_bits: usize,
    pub max_tau_draws: usize,
    pub security_bits: usize,
    /// Bounds the combined initial main and preprocessing codewords before
    /// key generation. Merkle trees, graph and proving workspaces add memory.
    pub max_pcs_codeword_cells: usize,
    /// Independent policy for the output authority's larger recursive geometry.
    pub artifact_limits: ArtifactLimits,
}

/// Native child authorities whose proofs a folding layer closes in circuit.
/// The trait is private to this module, so no other child relation can be
/// prepared.
trait FoldingChild<Base> {
    type Shape;

    fn identity(&self) -> Arc<[u8]>;
    fn transcript(&self) -> (ByteHash, &[u8]);
    fn check_support(&self) -> Result<(), VerificationError>;
    fn shape(&self) -> Self::Shape;
    fn public_counts(shape: &Self::Shape) -> Vec<usize>;
    fn allocate(
        shape: &Self::Shape,
        builder: &mut CircuitBuilder<F>,
    ) -> Result<BinaryMultiStarkProofTargets<NativeTower128Target>, VerificationError>;
    fn verify(
        &self,
        builder: &mut CircuitBuilder<F>,
        challenger: BinaryTower128Challenger,
        public: &[Vec<NativeTower128Target>],
        proof: &BinaryMultiStarkProofTargets<NativeTower128Target>,
    ) -> Result<BinaryQueryContinuation, VerificationError>;
}

impl<Base, A> FoldingChild<Base> for BinaryNativeAuthority<Base, F, A>
where
    Base: RecursiveBinaryTowerField + EncodableLevel + FoldAlphabet<F> + PackedValue<Value = Base>,
    F: ExtensionField<Base> + ChallengeField<Base>,
    A: VerifierAir<Base, F>,
{
    type Shape = BinaryMultiStarkInputShape<Base, F>;

    fn identity(&self) -> Arc<[u8]> {
        self.shared_identity()
    }
    fn transcript(&self) -> (ByteHash, &[u8]) {
        (self.transcript_hash(), self.initial_bytes())
    }
    fn check_support(&self) -> Result<(), VerificationError> {
        self.recursive_verifier().check_native_circuit_support()
    }
    fn shape(&self) -> Self::Shape {
        self.recursive_verifier().input_shape()
    }
    fn public_counts(shape: &Self::Shape) -> Vec<usize> {
        shape.public_value_counts().collect()
    }
    fn allocate(
        shape: &Self::Shape,
        builder: &mut CircuitBuilder<F>,
    ) -> Result<BinaryMultiStarkProofTargets<NativeTower128Target>, VerificationError> {
        shape.allocate_native_targets(builder)
    }
    fn verify(
        &self,
        builder: &mut CircuitBuilder<F>,
        challenger: BinaryTower128Challenger,
        public: &[Vec<NativeTower128Target>],
        proof: &BinaryMultiStarkProofTargets<NativeTower128Target>,
    ) -> Result<BinaryQueryContinuation, VerificationError> {
        self.recursive_verifier()
            .verify_native(builder, challenger, public, proof)
    }
}

impl<Base, A> FoldingChild<Base> for BinaryNativeGroupedAuthority<Base, F, A>
where
    Base: RecursiveBinaryTowerField + EncodableLevel + FoldAlphabet<F> + PackedValue<Value = Base>,
    F: ExtensionField<Base> + ChallengeField<Base>,
    A: VerifierAir<Base, F>,
{
    type Shape = BinaryGroupedMultiStarkInputShape<Base, F>;

    fn identity(&self) -> Arc<[u8]> {
        self.shared_identity()
    }
    fn transcript(&self) -> (ByteHash, &[u8]) {
        (self.transcript_hash(), self.initial_bytes())
    }
    fn check_support(&self) -> Result<(), VerificationError> {
        self.recursive_verifier().check_native_circuit_support()
    }
    fn shape(&self) -> Self::Shape {
        self.recursive_verifier().input_shape()
    }
    fn public_counts(shape: &Self::Shape) -> Vec<usize> {
        shape.public_value_counts().collect()
    }
    fn allocate(
        shape: &Self::Shape,
        builder: &mut CircuitBuilder<F>,
    ) -> Result<BinaryMultiStarkProofTargets<NativeTower128Target>, VerificationError> {
        shape.allocate_native_targets(builder)
    }
    fn verify(
        &self,
        builder: &mut CircuitBuilder<F>,
        challenger: BinaryTower128Challenger,
        public: &[Vec<NativeTower128Target>],
        proof: &BinaryMultiStarkProofTargets<NativeTower128Target>,
    ) -> Result<BinaryQueryContinuation, VerificationError> {
        self.recursive_verifier()
            .verify_native(builder, challenger, public, proof)
    }
}

/// Output public values in output AIR order, and the output traces.
type OutputWitness = (Vec<Vec<F>>, Vec<RowMajorMatrix<F>>);

/// Child identity, native verifier graph and product-bus relation shared by
/// the ordinary and grouped folding layers.
struct FoldingCore<S> {
    input_identity: Arc<[u8]>,
    input_shape: S,
    public_counts: Vec<usize>,
    circuit: Circuit<F>,
    bus: NativeBusCircuit<F>,
    initial_codeword_cells: usize,
}

impl<S> FoldingCore<S> {
    /// Builds the child verifier graph and the output verifier spec, whose
    /// PCS parameters `output_pcs` wraps for the output authority's family.
    fn prepare<Base, C, P>(
        child: &C,
        options: NativeBinaryFoldingRecursionOptions,
        circuit_limits: &DirectCircuitLimits,
        construction_limits: Option<CircuitConstructionLimits>,
        output_pcs: impl Fn(BinaryNativePcsParameters) -> P,
    ) -> Result<(Self, BinaryNativeVerifierSpec<P>, ArtifactLimits), VerificationError>
    where
        C: FoldingChild<Base, Shape = S>,
    {
        let (transcript_hash, initial_bytes) = child.transcript();
        <H as BinaryCircuitHost<F>>::check_hash(transcript_hash)?;
        child.check_support()?;
        let input_shape = child.shape();
        let public_counts = C::public_counts(&input_shape);
        let mut builder = match construction_limits {
            Some(limits) => CircuitBuilder::<F>::with_construction_limits(limits)?,
            None => CircuitBuilder::<F>::new(),
        };
        builder.enable_native_keccak_f1600()?;
        let public: Vec<Vec<_>> = public_counts
            .iter()
            .map(|&count| {
                (0..count)
                    .map(|_| {
                        let value = builder.public_input();
                        builder.check_construction_limits()?;
                        Ok(builder.native_tower128_from_expr(value))
                    })
                    .collect::<Result<_, VerificationError>>()
            })
            .collect::<Result<_, VerificationError>>()?;
        let proof = C::allocate(&input_shape, &mut builder)?;
        let initial: Vec<_> = initial_bytes
            .iter()
            .map(|&byte| {
                let value = builder.define_const(H::encode_u16(u16::from(byte))?);
                builder.check_construction_limits()?;
                Ok::<_, VerificationError>(value)
            })
            .collect::<Result<_, _>>()?;
        let challenger = BinaryTower128Challenger::with_initial_bytes_with_host::<H, F>(
            &mut builder,
            transcript_hash,
            &initial,
        )?;
        child.verify(&mut builder, challenger, &public, &proof)?;
        builder.check_construction_limits()?;
        let circuit = builder.build()?;
        let bus = NativeBusCircuit::with_limits(&circuit, "recursion", *circuit_limits)?;
        let required_draws = bus.log_heights().iter().copied().max().unwrap_or(0);
        if options.max_tau_draws < required_draws {
            return Err(VerificationError::InvalidProofShape(alloc::format!(
                "native folding nonzero draw budget {} is below the required {}",
                options.max_tau_draws,
                required_draws,
            )));
        }
        let main_cells = codeword_cells(bus.main_variables(), options.main.log_inv_rate)?;
        let pp_cells = bus
            .preprocessed_variables()
            .map(|variables| codeword_cells(variables, options.preprocessed.log_inv_rate))
            .transpose()?
            .unwrap_or(0);
        let initial_codeword_cells = main_cells.checked_add(pp_cells).ok_or(
            VerificationError::ResourceArithmeticOverflow {
                component: "native folding PCS codeword cells",
            },
        )?;
        if initial_codeword_cells > options.max_pcs_codeword_cells {
            return Err(VerificationError::ResourceLimitExceeded {
                component: "native folding PCS codeword cells",
                actual: initial_codeword_cells,
                limit: options.max_pcs_codeword_cells,
            });
        }
        let pcs = |variables: usize,
                   params: BinaryPcsParams|
         -> Result<BinaryNativePcsParameters, VerificationError> {
            let config = BinaryPcsConfig::try_new_with_folding::<F, F>(
                variables,
                params,
                options.log_folding_factor,
            )
            .map_err(|error| {
                VerificationError::InvalidProofShape(alloc::format!(
                    "native folding output PCS configuration: {error:?}"
                ))
            })?;
            let max_query_draws = BinaryPcsShape::new(&config)
                .num_pairs
                .checked_add(options.query_draw_slack)
                .ok_or(VerificationError::ResourceArithmeticOverflow {
                    component: "native folding query draws",
                })?;
            Ok(BinaryNativePcsParameters {
                config,
                hash: ByteHash::Keccak256,
                cap_height: options.cap_height,
                max_query_draws,
            })
        };
        let main = pcs(bus.main_variables(), options.main)?;
        let preprocessed = bus
            .preprocessed_variables()
            .map(|variables| pcs(variables, options.preprocessed))
            .transpose()?;
        let spec = BinaryNativeVerifierSpec {
            main: output_pcs(main),
            preprocessed: preprocessed.map(&output_pcs),
            transcript_hash: ByteHash::Keccak256,
            initial_bytes: options.initial_bytes,
            sumcheck_pow_bits: options.sumcheck_pow_bits,
            max_tau_draws: options.max_tau_draws,
            security_bits: options.security_bits,
        };
        let core = Self {
            input_identity: child.identity(),
            input_shape,
            public_counts,
            circuit,
            bus,
            initial_codeword_cells,
        };
        Ok((core, spec, options.artifact_limits))
    }

    fn output_public_values<Base: RecursiveBinaryTowerField>(
        &self,
        expected: &[Vec<Base>],
    ) -> Result<Vec<Vec<F>>, VerificationError> {
        Ok(self.bus.public_values(&self.flatten_statement(expected)?)?)
    }

    fn flatten_statement<Base: RecursiveBinaryTowerField>(
        &self,
        public: &[Vec<Base>],
    ) -> Result<Vec<F>, VerificationError> {
        if public.len() != self.public_counts.len()
            || public
                .iter()
                .zip(&self.public_counts)
                .any(|(values, &count)| values.len() != count)
        {
            return Err(VerificationError::InvalidProofShape(
                "native folding child public value shape mismatch".into(),
            ));
        }
        Ok(public
            .iter()
            .flatten()
            .map(|value| F::from_repr(value.raw_coordinates()))
            .collect())
    }

    /// Checks the token's identity before `pack` or runner allocation, then
    /// returns the output statement and traces of the verifier circuit.
    fn witness<Base: RecursiveBinaryTowerField>(
        &self,
        identity: &[u8],
        statement: &[Vec<Base>],
        pack: impl FnOnce(&S) -> Result<Vec<F>, VerificationError>,
    ) -> Result<OutputWitness, VerificationError> {
        if identity != self.input_identity.as_ref() {
            return Err(VerificationError::PreparedInputMismatch {
                component: "native binary child authority",
            });
        }
        let public = self.flatten_statement(statement)?;
        let private = pack(&self.input_shape)?;
        let mut runner = self.circuit.runner();
        runner.set_public_inputs(&public)?;
        runner.set_private_inputs(&private)?;
        let trace = runner.run()?.witness_trace;
        let output_public = self.bus.public_values(&public)?;
        Ok((output_public, self.bus.traces(&trace)?))
    }
}

/// Retains the child authority's identity, native verifier graph, product-bus
/// relation, and matched folding proving/verification keys for repeatable proving.
pub struct PreparedNativeBinaryLayer<Base = F>
where
    Base: RecursiveBinaryTowerField,
{
    core: FoldingCore<BinaryMultiStarkInputShape<Base, F>>,
    prover: BinaryNativeProver<F, F, OutputAir>,
    authority: BinaryNativeAuthority<F, F, OutputAir>,
}

impl<Base: RecursiveBinaryTowerField> PreparedNativeBinaryLayer<Base>
where
    F: ExtensionField<Base>,
{
    /// Builds a full folding verifier and its native output authority. All
    /// child plans and preprocessing come from `authority`, independently of
    /// any proof. Native Keccak is required; BLAKE3, grouped and indexed child
    /// relations are rejected before graph allocation. Limits cover the graph
    /// and trace preparation; native PCS codewords and proving workspaces
    /// require additional memory.
    pub fn from_native_authority<A>(
        authority: &BinaryNativeAuthority<Base, F, A>,
        options: NativeBinaryFoldingRecursionOptions,
        circuit_limits: &DirectCircuitLimits,
    ) -> Result<Self, VerificationError>
    where
        Base: EncodableLevel + FoldAlphabet<F> + PackedValue<Value = Base>,
        F: ChallengeField<Base>,
        A: VerifierAir<Base, F>,
    {
        Self::prepare(authority, options, circuit_limits, None)
    }

    /// Stops verifier construction at periodic entry-count checkpoints before
    /// lowering. A checkpoint can overshoot by its local unit of work; these
    /// counts are separate from final circuit limits and memory in bytes.
    pub fn from_native_authority_with_construction_limits<A>(
        authority: &BinaryNativeAuthority<Base, F, A>,
        options: NativeBinaryFoldingRecursionOptions,
        circuit_limits: &DirectCircuitLimits,
        construction_limits: &CircuitConstructionLimits,
    ) -> Result<Self, VerificationError>
    where
        Base: EncodableLevel + FoldAlphabet<F> + PackedValue<Value = Base>,
        F: ChallengeField<Base>,
        A: VerifierAir<Base, F>,
    {
        Self::prepare(
            authority,
            options,
            circuit_limits,
            Some(*construction_limits),
        )
    }

    fn prepare<A>(
        authority: &BinaryNativeAuthority<Base, F, A>,
        options: NativeBinaryFoldingRecursionOptions,
        circuit_limits: &DirectCircuitLimits,
        construction_limits: Option<CircuitConstructionLimits>,
    ) -> Result<Self, VerificationError>
    where
        Base: EncodableLevel + FoldAlphabet<F> + PackedValue<Value = Base>,
        F: ChallengeField<Base>,
        A: VerifierAir<Base, F>,
    {
        let (core, spec, limits) = FoldingCore::prepare(
            authority,
            options,
            circuit_limits,
            construction_limits,
            |pcs| pcs,
        )?;
        let (prover, authority) =
            BinaryNativeAuthority::<F, F, OutputAir>::setup_with_artifact_limits(
                core.bus.airs().to_vec(),
                core.bus.log_heights().to_vec(),
                spec,
                limits,
            )?;
        Ok(Self {
            core,
            prover,
            authority,
        })
    }

    pub const fn circuit(&self) -> &Circuit<F> {
        &self.core.circuit
    }
    /// Output authority, suitable as the independently trusted child of another
    /// `PreparedNativeBinaryLayer`. Its statement uses output AIR order.
    pub const fn authority(&self) -> &BinaryNativeAuthority<F, F, OutputAir> {
        &self.authority
    }
    /// Releases the circuit and proving key while preserving the output
    /// verification authority for construction of the next layer.
    pub fn into_authority(self) -> BinaryNativeAuthority<F, F, OutputAir> {
        self.authority
    }
    pub fn child_public_value_counts(&self) -> &[usize] {
        &self.core.public_counts
    }
    pub const fn initial_codeword_cells(&self) -> usize {
        self.core.initial_codeword_cells
    }

    /// Maps an independently expected child statement to output AIR order.
    pub fn output_public_values(
        &self,
        expected: &[Vec<Base>],
    ) -> Result<Vec<Vec<F>>, VerificationError> {
        self.core.output_public_values(expected)
    }

    /// Accepts only a token checked under the retained child authority. Identity
    /// is checked before witness packing or runner allocation. The child public
    /// statement is exported as native scalars by the output product-bus AIR.
    pub fn prove_verified(
        &self,
        checked: &VerifiedBinaryNativeProof<Base, F>,
    ) -> Result<NativeBinaryFoldingRecursiveProof, VerificationError> {
        let (public, traces) =
            self.core
                .witness(&checked.identity, checked.public_values(), |shape| {
                    checked.native_input().private_native_values(shape)
                })?;
        self.prover.prove(&public, traces)
    }

    /// Verifies against the caller's original child statement. Expected values
    /// are never obtained from the recursive proof itself.
    pub fn verify(
        &self,
        proof: &NativeBinaryFoldingRecursiveProof,
        expected: &[Vec<Base>],
    ) -> Result<VerifiedBinaryNativeProof<F, F>, VerificationError> {
        self.authority
            .verify_native(proof, &self.output_public_values(expected)?)
    }
}

/// A folding layer whose child and output commit one fold coset per Merkle
/// leaf (`BinaryCodewordGrouping::Folding` for base and rounds, main and
/// preprocessed). Retains the child authority's identity, native verifier
/// graph, product-bus relation, and matched proving/verification keys.
pub struct PreparedNativeBinaryGroupedLayer<Base = F>
where
    Base: RecursiveBinaryTowerField,
{
    core: FoldingCore<BinaryGroupedMultiStarkInputShape<Base, F>>,
    prover: BinaryNativeGroupedProver<F, F, OutputAir>,
    authority: BinaryNativeGroupedAuthority<F, F, OutputAir>,
}

impl<Base: RecursiveBinaryTowerField> PreparedNativeBinaryGroupedLayer<Base>
where
    F: ExtensionField<Base>,
{
    /// Builds a full grouped folding verifier and its grouped native output
    /// authority. All child plans and preprocessing come from `authority`,
    /// independently of any proof. Native Keccak is required; BLAKE3,
    /// indexed child relations and child groupings whose leaves are not
    /// exactly one fold coset are rejected before graph allocation, as is a
    /// `cap_height` above either output `log_inv_rate`. Limits cover the graph
    /// and trace preparation; native PCS codewords and proving workspaces
    /// require additional memory.
    pub fn from_native_authority<A>(
        authority: &BinaryNativeGroupedAuthority<Base, F, A>,
        options: NativeBinaryFoldingRecursionOptions,
        circuit_limits: &DirectCircuitLimits,
    ) -> Result<Self, VerificationError>
    where
        Base: EncodableLevel + FoldAlphabet<F> + PackedValue<Value = Base>,
        F: ChallengeField<Base>,
        A: VerifierAir<Base, F>,
    {
        Self::prepare(authority, options, circuit_limits, None)
    }

    /// Stops verifier construction at periodic entry-count checkpoints before
    /// lowering. A checkpoint can overshoot by its local unit of work; these
    /// counts are separate from final circuit limits and memory in bytes.
    pub fn from_native_authority_with_construction_limits<A>(
        authority: &BinaryNativeGroupedAuthority<Base, F, A>,
        options: NativeBinaryFoldingRecursionOptions,
        circuit_limits: &DirectCircuitLimits,
        construction_limits: &CircuitConstructionLimits,
    ) -> Result<Self, VerificationError>
    where
        Base: EncodableLevel + FoldAlphabet<F> + PackedValue<Value = Base>,
        F: ChallengeField<Base>,
        A: VerifierAir<Base, F>,
    {
        Self::prepare(
            authority,
            options,
            circuit_limits,
            Some(*construction_limits),
        )
    }

    fn prepare<A>(
        authority: &BinaryNativeGroupedAuthority<Base, F, A>,
        options: NativeBinaryFoldingRecursionOptions,
        circuit_limits: &DirectCircuitLimits,
        construction_limits: Option<CircuitConstructionLimits>,
    ) -> Result<Self, VerificationError>
    where
        Base: EncodableLevel + FoldAlphabet<F> + PackedValue<Value = Base>,
        F: ChallengeField<Base>,
        A: VerifierAir<Base, F>,
    {
        let log_inv_rate = options
            .main
            .log_inv_rate
            .min(options.preprocessed.log_inv_rate);
        if options.cap_height > log_inv_rate {
            return Err(VerificationError::InvalidProofShape(alloc::format!(
                "grouped native folding cap height {} exceeds the output log inverse rate {}",
                options.cap_height,
                log_inv_rate,
            )));
        }
        let (core, spec, limits) = FoldingCore::prepare(
            authority,
            options,
            circuit_limits,
            construction_limits,
            |pcs| BinaryNativeGroupedPcsParameters {
                pcs,
                base_grouping: BinaryCodewordGrouping::Folding,
                round_grouping: BinaryCodewordGrouping::Folding,
            },
        )?;
        let (prover, authority) =
            BinaryNativeGroupedAuthority::<F, F, OutputAir>::setup_with_artifact_limits(
                core.bus.airs().to_vec(),
                core.bus.log_heights().to_vec(),
                spec,
                limits,
            )?;
        Ok(Self {
            core,
            prover,
            authority,
        })
    }

    pub const fn circuit(&self) -> &Circuit<F> {
        &self.core.circuit
    }
    /// Output authority, suitable as the independently trusted child of another
    /// `PreparedNativeBinaryGroupedLayer`. Its statement uses output AIR order.
    pub const fn authority(&self) -> &BinaryNativeGroupedAuthority<F, F, OutputAir> {
        &self.authority
    }
    /// Releases the circuit and proving key while preserving the output
    /// verification authority for construction of the next layer.
    pub fn into_authority(self) -> BinaryNativeGroupedAuthority<F, F, OutputAir> {
        self.authority
    }
    pub fn child_public_value_counts(&self) -> &[usize] {
        &self.core.public_counts
    }
    pub const fn initial_codeword_cells(&self) -> usize {
        self.core.initial_codeword_cells
    }

    /// Maps an independently expected child statement to output AIR order.
    pub fn output_public_values(
        &self,
        expected: &[Vec<Base>],
    ) -> Result<Vec<Vec<F>>, VerificationError> {
        self.core.output_public_values(expected)
    }

    /// Accepts only a token checked under the retained child authority. Identity
    /// is checked before witness packing or runner allocation. The child public
    /// statement is exported as native scalars by the output product-bus AIR.
    pub fn prove_verified(
        &self,
        checked: &VerifiedBinaryNativeGroupedProof<Base, F>,
    ) -> Result<NativeBinaryGroupedFoldingRecursiveProof, VerificationError> {
        let (public, traces) =
            self.core
                .witness(&checked.identity, checked.public_values(), |shape| {
                    checked.native_input().private_native_values(shape)
                })?;
        self.prover.prove(&public, traces)
    }

    /// Verifies against the caller's original child statement. Expected values
    /// are never obtained from the recursive proof itself.
    pub fn verify(
        &self,
        proof: &NativeBinaryGroupedFoldingRecursiveProof,
        expected: &[Vec<Base>],
    ) -> Result<VerifiedBinaryNativeGroupedProof<F, F>, VerificationError> {
        self.authority
            .verify_native(proof, &self.output_public_values(expected)?)
    }
}
