//! Prepared Poly64 verifier circuits with the released Poly192 challenge extension.

use alloc::sync::Arc;
use alloc::vec::Vec;

use p3_binary_field::{Poly64, Poly192};
use p3_circuit::ops::binary_encoding::{BinaryCircuitEncoding, NativeBinaryEncoding};
use p3_circuit::ops::binary_host::BinaryCircuitHost;
use p3_circuit::ops::{ByteHash, NativePoly192Target};
use p3_circuit::{Circuit, CircuitBuilder, CircuitConstructionLimits, ExprId};
use p3_circuit_prover::direct::DirectCircuitLimits;
use p3_circuit_prover::native_bus::{KeccakCommitment, NativeBusCircuit, NativeBusCircuitAir};
use p3_multi_stark::MultiStarkProof;
use p3_multi_stark::folder::VerifierAir;

use super::native_binary::{NativeBinaryRecursionOptions, codeword_cells, first_fold};
use crate::BinaryTower128Challenger;
use crate::artifact::{
    BinaryNativePolyMixedWhirAuthority, BinaryNativePolyWhirAuthority, BinaryNativePolyWhirConfig,
    BinaryNativePolyWhirLayout, BinaryNativePolyWhirPcsParameters, BinaryNativePolyWhirProver,
    BinaryNativeVerifierSpec, VerifiedBinaryNativePolyWhirProof,
};
use crate::verifier::{
    BinaryPolyMixedWhirMultiStarkInputShape, BinaryPolyMixedWhirMultiStarkProofTargets,
    BinaryPolyWhirMultiStarkInputShape, BinaryPolyWhirMultiStarkProofTargets, VerificationError,
};

type F = Poly64;
type H = NativeBinaryEncoding;
type OutputAir = NativeBusCircuitAir<F>;
/// A complete recursive proof over Poly64, using Poly192 verifier challenges.
pub type NativeBinaryPolyRecursiveProof = MultiStarkProof<BinaryNativePolyWhirConfig>;

/// Retains the child authority's identity, native verifier graph, product-bus
/// relation, and matched native proving/verification keys for repeatable proving.
pub struct PreparedNativeBinaryPolyWhirLayer {
    input_identity: Arc<[u8]>,
    input_shape: BinaryPolyWhirMultiStarkInputShape,
    public_counts: Vec<usize>,
    circuit: Circuit<F>,
    bus: NativeBusCircuit<F>,
    prover: BinaryNativePolyWhirProver<OutputAir>,
    authority: BinaryNativePolyWhirAuthority<OutputAir>,
    initial_codeword_cells: usize,
}

impl PreparedNativeBinaryPolyWhirLayer {
    /// Builds a full binary verifier and its native output authority. All child
    /// plans and preprocessing come from `authority`, independently of any proof.
    /// Native Keccak is required; indexed child relations are rejected before
    /// graph allocation. Limits cover the graph and trace preparation; native
    /// PCS codewords and proving workspaces require additional memory.
    pub fn from_native_authority<A, L>(
        authority: &BinaryNativePolyWhirAuthority<A, L>,
        options: NativeBinaryRecursionOptions,
        circuit_limits: &DirectCircuitLimits,
    ) -> Result<Self, VerificationError>
    where
        A: VerifierAir<Poly64, Poly192>,
        L: BinaryNativePolyWhirLayout,
    {
        Self::prepare(authority, options, circuit_limits, None)
    }

    /// Stops verifier construction at periodic entry-count checkpoints before
    /// lowering. A checkpoint can overshoot by its local unit of work; these
    /// counts are separate from final circuit limits and memory in bytes.
    pub fn from_native_authority_with_construction_limits<A, L>(
        authority: &BinaryNativePolyWhirAuthority<A, L>,
        options: NativeBinaryRecursionOptions,
        circuit_limits: &DirectCircuitLimits,
        construction_limits: &CircuitConstructionLimits,
    ) -> Result<Self, VerificationError>
    where
        A: VerifierAir<Poly64, Poly192>,
        L: BinaryNativePolyWhirLayout,
    {
        Self::prepare(
            authority,
            options,
            circuit_limits,
            Some(*construction_limits),
        )
    }

    /// Builds the child verifier circuit and its product-bus relation as
    /// preparation does, under the same limits and nonzero draw budget, and
    /// stops before the output codeword budget and key generation.
    /// `None` places no construction checkpoints, as in
    /// [`Self::from_native_authority`].
    pub fn verifier_circuit<A, L>(
        authority: &BinaryNativePolyWhirAuthority<A, L>,
        options: &NativeBinaryRecursionOptions,
        circuit_limits: &DirectCircuitLimits,
        construction_limits: Option<&CircuitConstructionLimits>,
    ) -> Result<(Circuit<F>, NativeBusCircuit<F>), VerificationError>
    where
        A: VerifierAir<Poly64, Poly192>,
        L: BinaryNativePolyWhirLayout,
    {
        native_poly_verifier_circuit(
            authority,
            options,
            circuit_limits,
            construction_limits,
            KeccakCommitment::Dense,
        )
    }

    fn prepare<A, L>(
        authority: &BinaryNativePolyWhirAuthority<A, L>,
        options: NativeBinaryRecursionOptions,
        circuit_limits: &DirectCircuitLimits,
        construction_limits: Option<CircuitConstructionLimits>,
    ) -> Result<Self, VerificationError>
    where
        A: VerifierAir<Poly64, Poly192>,
        L: BinaryNativePolyWhirLayout,
    {
        let (circuit, bus) = Self::verifier_circuit(
            authority,
            &options,
            circuit_limits,
            construction_limits.as_ref(),
        )?;
        let input_shape = authority.recursive_verifier().input_shape();
        let public_counts: Vec<_> = input_shape.public_value_counts().collect();
        let main_cells = codeword_cells(bus.main_variables(), options.main.starting_log_inv_rate)?;
        let pp_cells = bus
            .preprocessed_variables()
            .map(|variables| codeword_cells(variables, options.preprocessed.starting_log_inv_rate))
            .transpose()?
            .unwrap_or(0);
        let initial_codeword_cells = main_cells.checked_add(pp_cells).ok_or(
            VerificationError::ResourceArithmeticOverflow {
                component: "native recursive PCS codeword cells",
            },
        )?;
        if initial_codeword_cells > options.max_pcs_codeword_cells {
            return Err(VerificationError::ResourceLimitExceeded {
                component: "native recursive PCS codeword cells",
                actual: initial_codeword_cells,
                limit: options.max_pcs_codeword_cells,
            });
        }
        let limits = &options.artifact_limits;
        let main = BinaryNativePolyWhirPcsParameters::with_limits(
            bus.main_variables(),
            options.main,
            ByteHash::Keccak256,
            options.arity,
            options.cap_height,
            &limits.verifier,
        )?;
        let preprocessed = bus
            .preprocessed_variables()
            .map(|variables| {
                BinaryNativePolyWhirPcsParameters::with_limits(
                    variables,
                    options.preprocessed,
                    ByteHash::Keccak256,
                    options.arity,
                    options.cap_height,
                    &limits.verifier,
                )
            })
            .transpose()?;
        let spec = BinaryNativeVerifierSpec {
            main,
            preprocessed,
            transcript_hash: ByteHash::Keccak256,
            initial_bytes: options.initial_bytes,
            sumcheck_pow_bits: options.sumcheck_pow_bits,
            max_tau_draws: options.max_tau_draws,
            security_bits: options.security_bits,
        };
        let (prover, output_authority) =
            BinaryNativePolyWhirAuthority::<OutputAir>::setup_with_artifact_limits(
                bus.airs().to_vec(),
                bus.log_heights().to_vec(),
                spec,
                *limits,
            )?;
        Ok(Self {
            input_identity: authority.shared_identity(),
            input_shape,
            public_counts,
            circuit,
            bus,
            prover,
            authority: output_authority,
            initial_codeword_cells,
        })
    }

    pub const fn circuit(&self) -> &Circuit<F> {
        &self.circuit
    }
    /// Output authority, suitable as the independently trusted child of another
    /// `PreparedNativeBinaryPolyWhirLayer`. Its statement uses output AIR order.
    pub const fn authority(&self) -> &BinaryNativePolyWhirAuthority<OutputAir> {
        &self.authority
    }
    /// Releases the circuit and proving key while preserving the output
    /// verification authority for construction of the next layer.
    pub fn into_authority(self) -> BinaryNativePolyWhirAuthority<OutputAir> {
        self.authority
    }
    pub fn child_public_value_counts(&self) -> &[usize] {
        &self.public_counts
    }
    pub const fn initial_codeword_cells(&self) -> usize {
        self.initial_codeword_cells
    }

    /// Maps an independently expected child statement to output AIR order.
    pub fn output_public_values(
        &self,
        expected: &[Vec<F>],
    ) -> Result<Vec<Vec<F>>, VerificationError> {
        Ok(self.bus.public_values(&self.flatten_statement(expected)?)?)
    }

    fn flatten_statement(&self, public: &[Vec<F>]) -> Result<Vec<F>, VerificationError> {
        if public.len() != self.public_counts.len()
            || public
                .iter()
                .zip(&self.public_counts)
                .any(|(values, &count)| values.len() != count)
        {
            return Err(VerificationError::InvalidProofShape(
                "native recursive child public value shape mismatch".into(),
            ));
        }
        Ok(public.iter().flatten().copied().collect())
    }

    /// Accepts only a token checked under the retained child authority. Identity
    /// is checked before witness packing or runner allocation. The child public
    /// statement is exported as native scalars by the output product-bus AIR.
    pub fn prove_verified(
        &self,
        checked: &VerifiedBinaryNativePolyWhirProof,
    ) -> Result<NativeBinaryPolyRecursiveProof, VerificationError> {
        if checked.identity.as_ref() != self.input_identity.as_ref() {
            return Err(VerificationError::PreparedInputMismatch {
                component: "native binary child authority",
            });
        }
        let public = self.flatten_statement(checked.public_values())?;
        let private = checked
            .native_input()
            .private_native_values(&self.input_shape)?;
        let mut runner = self.circuit.runner();
        runner.set_public_inputs(&public)?;
        runner.set_private_inputs(&private)?;
        let trace = runner.run()?.witness_trace;
        let output_public = self.bus.public_values(&public)?;
        self.prover.prove(&output_public, self.bus.traces(&trace)?)
    }

    /// Verifies against the caller's original child statement. Expected values
    /// are never obtained from the recursive proof itself.
    pub fn verify(
        &self,
        proof: &NativeBinaryPolyRecursiveProof,
        expected: &[Vec<F>],
    ) -> Result<VerifiedBinaryNativePolyWhirProof, VerificationError> {
        self.authority
            .verify_native(proof, &self.output_public_values(expected)?)
    }
}

/// Native Poly64 WHIR child authorities whose complete verifier a native layer runs in circuit.
pub(super) trait NativePolyWhirChild {
    type Shape;
    type Targets;

    fn identity(&self) -> Arc<[u8]>;
    fn transcript(&self) -> (ByteHash, &[u8]);
    /// Refuses a child the native carrier cannot verify, before graph allocation.
    fn check_support(&self) -> Result<(), VerificationError>;
    fn shape(&self) -> Self::Shape;
    fn public_counts(shape: &Self::Shape) -> Vec<usize>;
    fn allocate(
        shape: &Self::Shape,
        builder: &mut CircuitBuilder<F>,
    ) -> Result<Self::Targets, VerificationError>;
    fn verify(
        &self,
        builder: &mut CircuitBuilder<F>,
        challenger: BinaryTower128Challenger,
        public: &[Vec<ExprId>],
        proof: &Self::Targets,
    ) -> Result<BinaryTower128Challenger, VerificationError>;
}

impl<A, L> NativePolyWhirChild for BinaryNativePolyWhirAuthority<A, L>
where
    A: VerifierAir<Poly64, Poly192>,
    L: BinaryNativePolyWhirLayout,
{
    type Shape = BinaryPolyWhirMultiStarkInputShape;
    type Targets = BinaryPolyWhirMultiStarkProofTargets<NativePoly192Target, ExprId>;

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
    ) -> Result<Self::Targets, VerificationError> {
        shape.allocate_native_targets(builder)
    }
    fn verify(
        &self,
        builder: &mut CircuitBuilder<F>,
        challenger: BinaryTower128Challenger,
        public: &[Vec<ExprId>],
        proof: &Self::Targets,
    ) -> Result<BinaryTower128Challenger, VerificationError> {
        self.recursive_verifier()
            .verify_native(builder, challenger, public, proof)
    }
}

impl<A: VerifierAir<Poly64, Poly192>> NativePolyWhirChild
    for BinaryNativePolyMixedWhirAuthority<A>
{
    type Shape = BinaryPolyMixedWhirMultiStarkInputShape;
    type Targets = BinaryPolyMixedWhirMultiStarkProofTargets;

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
    ) -> Result<Self::Targets, VerificationError> {
        shape.allocate_native_targets(builder)
    }
    fn verify(
        &self,
        builder: &mut CircuitBuilder<F>,
        challenger: BinaryTower128Challenger,
        public: &[Vec<ExprId>],
        proof: &Self::Targets,
    ) -> Result<BinaryTower128Challenger, VerificationError> {
        self.recursive_verifier()
            .verify_native(builder, challenger, public, proof)
    }
}

/// Builds the child's complete native verifier circuit and its product-bus relation, with the
/// output Keccak table committed as `keccak`, under `circuit_limits` and the options' nonzero
/// draw budget. `None` places no construction checkpoints.
pub(super) fn native_poly_verifier_circuit<C: NativePolyWhirChild>(
    child: &C,
    options: &NativeBinaryRecursionOptions,
    circuit_limits: &DirectCircuitLimits,
    construction_limits: Option<&CircuitConstructionLimits>,
    keccak: KeccakCommitment,
) -> Result<(Circuit<F>, NativeBusCircuit<F>), VerificationError> {
    let minimum_log_height = first_fold(&options.main)?;
    if first_fold(&options.preprocessed)? != minimum_log_height {
        return Err(VerificationError::InvalidProofShape(
            "native recursive main and preprocessing initial folds differ".into(),
        ));
    }
    let (transcript_hash, initial_bytes) = child.transcript();
    <H as BinaryCircuitHost<F>>::check_hash(transcript_hash)?;
    child.check_support()?;
    let input_shape = child.shape();
    let public_counts = C::public_counts(&input_shape);
    let mut builder = match construction_limits {
        Some(limits) => CircuitBuilder::<F>::with_construction_limits(*limits)?,
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
                    Ok(value)
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
    let bus = NativeBusCircuit::with_options(
        &circuit,
        "recursion",
        minimum_log_height,
        *circuit_limits,
        keccak,
    )?;
    let required_draws = bus.log_heights().iter().copied().max().unwrap_or(0);
    if options.max_tau_draws < required_draws {
        return Err(VerificationError::InvalidProofShape(alloc::format!(
            "native recursive nonzero draw budget {} is below the required {}",
            options.max_tau_draws,
            required_draws,
        )));
    }
    Ok((circuit, bus))
}
