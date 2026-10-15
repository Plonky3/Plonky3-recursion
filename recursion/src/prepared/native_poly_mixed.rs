//! Prepared Poly64 verifier circuits proved over Poly64, with the output proof's hash table
//! committed as packed bits.

use alloc::sync::Arc;
use alloc::vec::Vec;

use p3_binary_field::{Poly64, Poly192};
use p3_circuit::{Circuit, CircuitConstructionLimits};
use p3_circuit_prover::direct::DirectCircuitLimits;
use p3_circuit_prover::native_bus::{KeccakCommitment, NativeBusCircuit, NativeBusCircuitAir};
use p3_multi_stark::MultiStarkProof;
use p3_multi_stark::folder::VerifierAir;

use super::native_binary::codeword_cells;
use super::native_binary_mixed::NativeBinaryMixedRecursionOptions;
use super::native_poly::{NativePolyWhirChild, native_poly_verifier_circuit};
use crate::artifact::{
    BinaryNativePolyMixedWhirAuthority, BinaryNativePolyMixedWhirConfig,
    BinaryNativePolyMixedWhirPcsParameters, BinaryNativePolyMixedWhirProver,
    BinaryNativePolyWhirAuthority, BinaryNativePolyWhirLayout, BinaryNativePolyWhirPcsParameters,
    BinaryNativeVerifierSpec, VerifiedBinaryNativePolyMixedWhirProof,
    VerifiedBinaryNativePolyWhirProof,
};
use crate::verifier::{
    BinaryPolyMixedWhirMultiStarkInputShape, BinaryPolyWhirMultiStarkInputShape, VerificationError,
};

type F = Poly64;
type OutputAir = NativeBusCircuitAir<F>;
/// A complete native Poly64 recursive proof whose hash table is committed as packed bits.
pub type NativeBinaryPolyMixedRecursiveProof = MultiStarkProof<BinaryNativePolyMixedWhirConfig>;

/// Row variables one field element of the packed commitment absorbs.
const ABSORBED_VARIABLES: usize = BinaryNativePolyMixedWhirPcsParameters::ABSORBED_VARIABLES;

/// Retains the child authority's identity, native verifier graph, product-bus relation, and
/// matched mixed proving/verification keys for repeatable proving. `S` is the child verifier's
/// input shape: dense for a dense child authority, mixed for a mixed child authority.
pub struct PreparedNativeBinaryPolyMixedWhirLayer<S = BinaryPolyWhirMultiStarkInputShape> {
    input_identity: Arc<[u8]>,
    input_shape: S,
    public_counts: Vec<usize>,
    circuit: Circuit<F>,
    bus: NativeBusCircuit<F>,
    prover: BinaryNativePolyMixedWhirProver<OutputAir>,
    authority: BinaryNativePolyMixedWhirAuthority<OutputAir>,
    initial_codeword_cells: usize,
}

impl PreparedNativeBinaryPolyMixedWhirLayer {
    /// Builds the child's full native verifier and an output authority that commits the
    /// output hash table as packed bits. All child plans and preprocessing come from
    /// `authority`, independently of any proof. The child's transcript hash, Keccak-256 or
    /// BLAKE3, must also be its commitments' hash, and is the output's.
    pub fn from_native_authority<A, L>(
        authority: &BinaryNativePolyWhirAuthority<A, L>,
        options: NativeBinaryMixedRecursionOptions,
        circuit_limits: &DirectCircuitLimits,
    ) -> Result<Self, VerificationError>
    where
        A: VerifierAir<Poly64, Poly192>,
        L: BinaryNativePolyWhirLayout,
    {
        Self::prepare(authority, options, circuit_limits, None)
    }

    /// As [`Self::from_native_authority`], stopping verifier construction at periodic
    /// entry-count checkpoints before lowering.
    pub fn from_native_authority_with_construction_limits<A, L>(
        authority: &BinaryNativePolyWhirAuthority<A, L>,
        options: NativeBinaryMixedRecursionOptions,
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

    /// Accepts only a token checked under the retained child authority. Identity is checked
    /// before witness packing or runner allocation.
    pub fn prove_verified(
        &self,
        checked: &VerifiedBinaryNativePolyWhirProof,
    ) -> Result<NativeBinaryPolyMixedRecursiveProof, VerificationError> {
        self.prove_checked(&checked.identity, checked.public_values(), |shape| {
            checked.native_input().private_native_values(shape)
        })
    }
}

impl PreparedNativeBinaryPolyMixedWhirLayer<BinaryPolyMixedWhirMultiStarkInputShape> {
    /// Builds the full native verifier of a child with one table committed as packed bits,
    /// such as another mixed layer's output, and an output authority that commits the output
    /// hash table as packed bits. All child plans and preprocessing come from `authority`,
    /// independently of any proof. The child's transcript hash must also be its commitments'
    /// hash, and is the output's.
    pub fn from_mixed_authority<A: VerifierAir<Poly64, Poly192>>(
        authority: &BinaryNativePolyMixedWhirAuthority<A>,
        options: NativeBinaryMixedRecursionOptions,
        circuit_limits: &DirectCircuitLimits,
    ) -> Result<Self, VerificationError> {
        Self::prepare(authority, options, circuit_limits, None)
    }

    /// As [`Self::from_mixed_authority`], stopping verifier construction at periodic
    /// entry-count checkpoints before lowering.
    pub fn from_mixed_authority_with_construction_limits<A: VerifierAir<Poly64, Poly192>>(
        authority: &BinaryNativePolyMixedWhirAuthority<A>,
        options: NativeBinaryMixedRecursionOptions,
        circuit_limits: &DirectCircuitLimits,
        construction_limits: &CircuitConstructionLimits,
    ) -> Result<Self, VerificationError> {
        Self::prepare(
            authority,
            options,
            circuit_limits,
            Some(*construction_limits),
        )
    }

    /// Accepts only a token checked under the retained child authority. Identity is checked
    /// before witness packing or runner allocation.
    pub fn prove_verified(
        &self,
        checked: &VerifiedBinaryNativePolyMixedWhirProof,
    ) -> Result<NativeBinaryPolyMixedRecursiveProof, VerificationError> {
        self.prove_checked(&checked.identity, checked.public_values(), |shape| {
            checked.native_input().private_native_values(shape)
        })
    }
}

impl<S> PreparedNativeBinaryPolyMixedWhirLayer<S> {
    fn prepare<C: NativePolyWhirChild<Shape = S>>(
        child: &C,
        options: NativeBinaryMixedRecursionOptions,
        circuit_limits: &DirectCircuitLimits,
        construction_limits: Option<CircuitConstructionLimits>,
    ) -> Result<Self, VerificationError> {
        let NativeBinaryMixedRecursionOptions {
            base: options,
            packed,
        } = options;
        let (circuit, bus) = native_poly_verifier_circuit(
            child,
            &options,
            circuit_limits,
            construction_limits.as_ref(),
            KeccakCommitment::Bits,
        )?;
        let input_shape = child.shape();
        let public_counts = C::public_counts(&input_shape);
        let (packed_table, bit_variables) = bus
            .packed_table_index()
            .zip(bus.packed_bit_variables())
            .ok_or_else(|| {
                VerificationError::InvalidProofShape(
                    "native recursive output has no packed hash table".into(),
                )
            })?;
        let packed_variables = bit_variables
            .checked_sub(ABSORBED_VARIABLES)
            .ok_or_else(|| {
                VerificationError::InvalidProofShape(
                    "native recursive packed hash table is smaller than one field element".into(),
                )
            })?;
        let main_cells = codeword_cells(bus.main_variables(), options.main.starting_log_inv_rate)?;
        let packed_cells = codeword_cells(packed_variables, packed.starting_log_inv_rate)?;
        let pp_cells = bus
            .preprocessed_variables()
            .map(|variables| codeword_cells(variables, options.preprocessed.starting_log_inv_rate))
            .transpose()?
            .unwrap_or(0);
        let initial_codeword_cells = main_cells
            .checked_add(packed_cells)
            .and_then(|cells| cells.checked_add(pp_cells))
            .ok_or(VerificationError::ResourceArithmeticOverflow {
                component: "native recursive PCS codeword cells",
            })?;
        if initial_codeword_cells > options.max_pcs_codeword_cells {
            return Err(VerificationError::ResourceLimitExceeded {
                component: "native recursive PCS codeword cells",
                actual: initial_codeword_cells,
                limit: options.max_pcs_codeword_cells,
            });
        }
        let limits = &options.artifact_limits;
        let hash = child.transcript().0;
        let whir = |variables, protocol| {
            BinaryNativePolyWhirPcsParameters::with_limits(
                variables,
                protocol,
                hash,
                options.arity,
                options.cap_height,
                &limits.verifier,
            )
        };
        let main = BinaryNativePolyMixedWhirPcsParameters::with_packed_table(
            whir(bus.main_variables(), options.main)?,
            whir(packed_variables, packed)?,
            packed_table,
            bit_variables,
        )?;
        let preprocessed = bus
            .preprocessed_variables()
            .map(|variables| {
                whir(variables, options.preprocessed)
                    .map(BinaryNativePolyMixedWhirPcsParameters::dense)
            })
            .transpose()?;
        let spec = BinaryNativeVerifierSpec {
            main,
            preprocessed,
            transcript_hash: hash,
            initial_bytes: options.initial_bytes,
            sumcheck_pow_bits: options.sumcheck_pow_bits,
            max_tau_draws: options.max_tau_draws,
            security_bits: options.security_bits,
        };
        let (prover, output_authority) =
            BinaryNativePolyMixedWhirAuthority::<OutputAir>::setup_with_artifact_limits(
                bus.airs().to_vec(),
                bus.log_heights().to_vec(),
                spec,
                *limits,
            )?;
        Ok(Self {
            input_identity: child.identity(),
            input_shape,
            public_counts,
            circuit,
            bus,
            prover,
            authority: output_authority,
            initial_codeword_cells,
        })
    }

    /// Reuses this layer's graph and keys after checking a new composed security
    /// target. Retained clones of the output authority must be dropped first.
    pub fn with_security_bits(mut self, bits: usize) -> Result<Self, VerificationError> {
        (self.prover, self.authority) = self.prover.with_security_bits(self.authority, bits)?;
        Ok(self)
    }

    pub const fn circuit(&self) -> &Circuit<F> {
        &self.circuit
    }
    /// Output authority over the mixed commitment, suitable as the independently trusted
    /// child of [`PreparedNativeBinaryPolyMixedWhirLayer::from_mixed_authority`]. Its
    /// statement uses output AIR order.
    pub const fn authority(&self) -> &BinaryNativePolyMixedWhirAuthority<OutputAir> {
        &self.authority
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

    /// Checks the token's identity before `pack` or runner allocation, then runs the verifier
    /// circuit on the token's statement and the child proof's values from `pack` and proves
    /// its tables.
    fn prove_checked(
        &self,
        identity: &[u8],
        statement: &[Vec<F>],
        pack: impl FnOnce(&S) -> Result<Vec<F>, VerificationError>,
    ) -> Result<NativeBinaryPolyMixedRecursiveProof, VerificationError> {
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
        drop(private);
        let trace = runner.run_witness()?;
        let output_public = self.bus.public_values(&public)?;
        let tables = self.bus.column_major_tables(&trace)?;
        drop(trace);
        self.prover.prove_tables(&output_public, tables)
    }

    /// Verifies against the caller's original child statement. Expected values are never
    /// obtained from the recursive proof itself.
    pub fn verify(
        &self,
        proof: &NativeBinaryPolyMixedRecursiveProof,
        expected: &[Vec<F>],
    ) -> Result<VerifiedBinaryNativePolyMixedWhirProof, VerificationError> {
        self.authority
            .verify_native(proof, &self.output_public_values(expected)?)
    }
}
