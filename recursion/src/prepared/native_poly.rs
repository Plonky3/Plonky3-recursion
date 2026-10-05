//! Prepared Poly64 verifier circuits with the released Poly192 challenge extension.

use alloc::sync::Arc;
use alloc::vec::Vec;

use p3_binary_field::{Poly64, Poly192};
use p3_circuit::ops::ByteHash;
use p3_circuit::ops::binary_encoding::{BinaryCircuitEncoding, NativeBinaryEncoding};
use p3_circuit::ops::binary_host::BinaryCircuitHost;
use p3_circuit::{Circuit, CircuitBuilder, CircuitConstructionLimits};
use p3_circuit_prover::direct::DirectCircuitLimits;
use p3_circuit_prover::native_bus::{NativeBusCircuit, NativeBusCircuitAir};
use p3_multi_stark::MultiStarkProof;
use p3_multi_stark::folder::VerifierAir;

use super::native_binary::{NativeBinaryRecursionOptions, codeword_cells, first_fold};
use crate::BinaryTower128Challenger;
use crate::artifact::{
    BinaryNativePolyWhirAuthority, BinaryNativePolyWhirConfig, BinaryNativePolyWhirLayout,
    BinaryNativePolyWhirPcsParameters, BinaryNativePolyWhirProver, BinaryNativeVerifierSpec,
    VerifiedBinaryNativePolyWhirProof,
};
use crate::verifier::{BinaryPolyWhirMultiStarkInputShape, VerificationError};

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
        let minimum_log_height = first_fold(&options.main)?;
        if first_fold(&options.preprocessed)? != minimum_log_height {
            return Err(VerificationError::InvalidProofShape(
                "native recursive main and preprocessing initial folds differ".into(),
            ));
        }
        let verifier = authority.recursive_verifier();
        <H as BinaryCircuitHost<F>>::check_hash(authority.transcript_hash())?;
        verifier.check_native_circuit_support()?;
        let input_shape = verifier.input_shape();
        let public_counts: Vec<_> = input_shape.public_value_counts().collect();
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
                        Ok(value)
                    })
                    .collect::<Result<_, VerificationError>>()
            })
            .collect::<Result<_, VerificationError>>()?;
        let proof = input_shape.allocate_native_targets(&mut builder)?;
        let initial: Vec<_> = authority
            .initial_bytes()
            .iter()
            .map(|&byte| {
                let value = builder.define_const(H::encode_u16(u16::from(byte))?);
                builder.check_construction_limits()?;
                Ok::<_, VerificationError>(value)
            })
            .collect::<Result<_, _>>()?;
        let challenger = BinaryTower128Challenger::with_initial_bytes_with_host::<H, F>(
            &mut builder,
            authority.transcript_hash(),
            &initial,
        )?;
        verifier.verify_native(&mut builder, challenger, &public, &proof)?;
        builder.check_construction_limits()?;
        let circuit = builder.build()?;
        let bus = NativeBusCircuit::with_min_log_height_and_limits(
            &circuit,
            "recursion",
            minimum_log_height,
            *circuit_limits,
        )?;
        let required_draws = bus.log_heights().iter().copied().max().unwrap_or(0);
        if options.max_tau_draws < required_draws {
            return Err(VerificationError::InvalidProofShape(alloc::format!(
                "native recursive nonzero draw budget {} is below the required {}",
                options.max_tau_draws,
                required_draws,
            )));
        }
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

    pub fn circuit(&self) -> &Circuit<F> {
        &self.circuit
    }
    /// Output authority, suitable as the independently trusted child of another
    /// `PreparedNativeBinaryPolyWhirLayer`. Its statement uses output AIR order.
    pub fn authority(&self) -> &BinaryNativePolyWhirAuthority<OutputAir> {
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
    pub fn initial_codeword_cells(&self) -> usize {
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
