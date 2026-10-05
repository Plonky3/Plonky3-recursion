//! Prepared Tower32/Tower128 verifier circuits proved over Tower128.

use alloc::{sync::Arc, vec::Vec};

use p3_binary_dft::EncodableLevel;
use p3_binary_field::{BinaryField128, TowerLevel};
use p3_binary_pcs::{ChallengeField, FoldAlphabet, whir::BinaryWhirDomain};
use p3_circuit::{
    Circuit, CircuitBuilder,
    ops::{
        ByteHash,
        binary_encoding::{BinaryCircuitEncoding, NativeBinaryEncoding},
        binary_host::BinaryCircuitHost,
    },
};
use p3_circuit_prover::{
    direct::DirectCircuitLimits,
    native_bus::{NativeBusCircuit, NativeBusCircuitAir},
};
use p3_field::{ExtensionField, PackedValue};
use p3_multi_stark::{MultiStarkProof, folder::VerifierAir};
use p3_whir::{FoldingFactor, ProtocolParameters, WhirDomain};

use crate::{
    BinaryTower128Challenger,
    artifact::{
        ArtifactLimits, BinaryNativeVerifierSpec, BinaryNativeWhirAuthority,
        BinaryNativeWhirConfig, BinaryNativeWhirLayout, BinaryNativeWhirPcsParameters,
        BinaryNativeWhirProver, VerifiedBinaryNativeWhirProof,
    },
    pcs::binary::RecursiveBinaryWhirTowerField,
    verifier::{BinaryWhirMultiStarkInputShape, VerificationError},
};

type F = BinaryField128;
type H = NativeBinaryEncoding;
type OutputAir = NativeBusCircuitAir<F>;
/// A complete native recursive proof; no prime-field output layer is involved.
pub type NativeBinaryRecursiveProof = MultiStarkProof<BinaryNativeWhirConfig<F>>;

/// Caller-selected native output protocol and transcript. Security and grinding
/// settings are validated by the same checked authority used for ordinary proofs.
/// These proofs do not hide the witness.
pub struct NativeBinaryRecursionOptions {
    pub main: ProtocolParameters,
    pub preprocessed: ProtocolParameters,
    pub cap_height: usize,
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

/// Retains the child authority's identity, native verifier graph, product-bus
/// relation, and matched native proving/verification keys for repeatable proving.
pub struct PreparedNativeBinaryWhirLayer<Base = F>
where
    Base: RecursiveBinaryWhirTowerField,
{
    input_identity: Arc<[u8]>,
    input_shape: BinaryWhirMultiStarkInputShape<Base>,
    public_counts: Vec<usize>,
    circuit: Circuit<F>,
    bus: NativeBusCircuit<F>,
    prover: BinaryNativeWhirProver<F, OutputAir>,
    authority: BinaryNativeWhirAuthority<F, OutputAir>,
    initial_codeword_cells: usize,
}

impl<Base: RecursiveBinaryWhirTowerField> PreparedNativeBinaryWhirLayer<Base>
where
    F: ExtensionField<Base>,
{
    /// Builds a full binary verifier and its native output authority. All child
    /// plans and preprocessing come from `authority`, independently of any proof.
    /// Native Keccak is required; indexed child relations are rejected before
    /// graph allocation. Limits cover the graph and trace preparation; native
    /// PCS codewords and proving workspaces require additional memory.
    pub fn from_native_authority<A, L>(
        authority: &BinaryNativeWhirAuthority<Base, A, L>,
        options: NativeBinaryRecursionOptions,
        circuit_limits: &DirectCircuitLimits,
    ) -> Result<Self, VerificationError>
    where
        Base: EncodableLevel + FoldAlphabet<F> + PackedValue<Value = Base> + Ord,
        F: ChallengeField<Base>,
        BinaryWhirDomain<Base>: WhirDomain<Base, F>,
        A: VerifierAir<Base, F>,
        L: BinaryNativeWhirLayout<Base>,
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
        let mut builder = CircuitBuilder::<F>::new();
        builder.enable_native_keccak_f1600()?;
        let public: Vec<Vec<_>> = public_counts
            .iter()
            .map(|&count| {
                (0..count)
                    .map(|_| {
                        let value = builder.public_input();
                        builder.native_tower128_from_expr(value)
                    })
                    .collect()
            })
            .collect();
        let proof = input_shape.allocate_native_targets(&mut builder)?;
        let initial: Vec<_> = authority
            .initial_bytes()
            .iter()
            .map(|&byte| {
                H::encode_u16(u16::from(byte)).map(|constant| builder.define_const(constant))
            })
            .collect::<Result<_, _>>()?;
        let challenger = BinaryTower128Challenger::with_initial_bytes_with_host::<H, F>(
            &mut builder,
            authority.transcript_hash(),
            &initial,
        )?;
        verifier.verify_native(&mut builder, challenger, &public, &proof)?;
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
        let main = BinaryNativeWhirPcsParameters::<F>::with_limits(
            bus.main_variables(),
            options.main,
            ByteHash::Keccak256,
            options.cap_height,
            &limits.verifier,
        )?;
        let preprocessed = bus
            .preprocessed_variables()
            .map(|variables| {
                BinaryNativeWhirPcsParameters::<F>::with_limits(
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
            BinaryNativeWhirAuthority::<F, OutputAir>::setup_with_artifact_limits(
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
    /// `PreparedNativeBinaryWhirLayer`. Its statement uses output AIR order.
    pub fn authority(&self) -> &BinaryNativeWhirAuthority<F, OutputAir> {
        &self.authority
    }
    /// Releases the circuit and proving key while preserving the output
    /// verification authority for construction of the next layer.
    pub fn into_authority(self) -> BinaryNativeWhirAuthority<F, OutputAir> {
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
        expected: &[Vec<Base>],
    ) -> Result<Vec<Vec<F>>, VerificationError> {
        Ok(self.bus.public_values(&self.flatten_statement(expected)?)?)
    }

    fn flatten_statement(&self, public: &[Vec<Base>]) -> Result<Vec<F>, VerificationError> {
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
        Ok(public
            .iter()
            .flatten()
            .map(|value| F::from_repr(value.raw_coordinates()))
            .collect())
    }

    /// Accepts only a token checked under the retained child authority. Identity
    /// is checked before witness packing or runner allocation. The child public
    /// statement is exported as native scalars by the output product-bus AIR.
    pub fn prove_verified(
        &self,
        checked: &VerifiedBinaryNativeWhirProof<Base>,
    ) -> Result<NativeBinaryRecursiveProof, VerificationError> {
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
        proof: &NativeBinaryRecursiveProof,
        expected: &[Vec<Base>],
    ) -> Result<VerifiedBinaryNativeWhirProof<F>, VerificationError> {
        self.authority
            .verify_native(proof, &self.output_public_values(expected)?)
    }
}

fn first_fold(parameters: &ProtocolParameters) -> Result<usize, VerificationError> {
    let value = match &parameters.folding_factor {
        FoldingFactor::Constant(value) | FoldingFactor::ConstantFromSecondRound(value, _) => *value,
        FoldingFactor::PerRound(values) => values.first().copied().unwrap_or(0),
    };
    if value == 0 || value >= usize::BITS as usize {
        return Err(VerificationError::InvalidProofShape(
            "native recursive initial fold must be nonzero and fit a table height".into(),
        ));
    }
    Ok(value)
}

fn codeword_cells(variables: usize, log_inv_rate: usize) -> Result<usize, VerificationError> {
    let exponent = variables
        .checked_add(log_inv_rate)
        .and_then(|sum| u32::try_from(sum).ok());
    exponent.and_then(|bits| 1usize.checked_shl(bits)).ok_or(
        VerificationError::ResourceArithmeticOverflow {
            component: "native recursive PCS codeword cells",
        },
    )
}
