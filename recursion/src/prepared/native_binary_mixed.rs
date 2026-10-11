//! Prepared Tower32/Tower128 verifier circuits proved over Tower128, with the output proof's
//! Keccak table committed as packed bits.

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::marker::PhantomData;

use p3_binary_dft::EncodableLevel;
use p3_binary_field::{BinaryField128, TowerLevel};
use p3_binary_pcs::whir::BinaryWhirDomain;
use p3_binary_pcs::{ChallengeField, FoldAlphabet};
use p3_circuit::ops::{ByteHash, NativeTower128Target};
use p3_circuit::{Circuit, CircuitBuilder, CircuitConstructionLimits};
use p3_circuit_prover::direct::DirectCircuitLimits;
use p3_circuit_prover::native_bus::{
    KeccakCommitment, NativeBusCircuit, NativeBusCircuitAir, NativeBusTrace,
};
use p3_field::{ExtensionField, PackedValue};
use p3_multi_stark::MultiStarkProof;
use p3_multi_stark::folder::VerifierAir;
use p3_sumcheck::layout::Table;
use p3_whir::{ProtocolParameters, WhirDomain};

use super::native_binary::{
    NativeBinaryRecursionOptions, NativeWhirChild, codeword_cells, native_verifier_circuit,
};
use crate::BinaryTower128Challenger;
use crate::artifact::{
    BinaryNativeMixedWhirAuthority, BinaryNativeMixedWhirConfig,
    BinaryNativeMixedWhirPcsParameters, BinaryNativeMixedWhirProver, BinaryNativeVerifierSpec,
    BinaryNativeWhirAuthority, BinaryNativeWhirLayout, BinaryNativeWhirPcsParameters,
    VerifiedBinaryNativeMixedWhirProof, VerifiedBinaryNativeWhirProof,
};
use crate::pcs::binary::{NativeBooleanWhirTraceProofTargets, RecursiveBinaryWhirTowerField};
use crate::verifier::{
    BinaryMixedWhirMultiStarkInputShape, BinaryMixedWhirMultiStarkProofTargets,
    BinaryWhirMultiStarkInputShape, VerificationError,
};

type F = BinaryField128;
type OutputAir = NativeBusCircuitAir<F>;
/// A complete native recursive proof whose Keccak table is committed as packed bits.
pub type NativeBinaryMixedRecursiveProof = MultiStarkProof<BinaryNativeMixedWhirConfig>;

/// Row variables one field element of the packed commitment absorbs.
const ABSORBED_VARIABLES: usize = 7;

/// The ordinary native output options plus the packed commitment's protocol. The packed
/// commitment uses the base options' hash and cap height.
pub struct NativeBinaryMixedRecursionOptions {
    pub base: NativeBinaryRecursionOptions,
    /// Protocol of the Keccak table's packed-bit commitment.
    pub packed: ProtocolParameters,
}

/// Retains the child authority's identity, native verifier graph, product-bus relation, and
/// matched mixed proving/verification keys for repeatable proving. `S` is the child verifier's
/// input shape: dense for a dense child authority, mixed for a mixed child authority.
pub struct PreparedNativeBinaryMixedWhirLayer<Base = F, S = BinaryWhirMultiStarkInputShape<Base>>
where
    Base: RecursiveBinaryWhirTowerField,
{
    input_identity: Arc<[u8]>,
    input_shape: S,
    /// The child statement's field.
    statement: PhantomData<Base>,
    public_counts: Vec<usize>,
    circuit: Circuit<F>,
    bus: NativeBusCircuit<F>,
    prover: BinaryNativeMixedWhirProver<OutputAir>,
    authority: BinaryNativeMixedWhirAuthority<OutputAir>,
    initial_codeword_cells: usize,
}

impl<Base: RecursiveBinaryWhirTowerField> PreparedNativeBinaryMixedWhirLayer<Base>
where
    F: ExtensionField<Base>,
{
    /// Builds the child's full native verifier and an output authority that commits the
    /// output Keccak table as packed bits. All child plans and preprocessing come from
    /// `authority`, independently of any proof. Native Keccak is required.
    pub fn from_native_authority<A, L>(
        authority: &BinaryNativeWhirAuthority<Base, A, L>,
        options: NativeBinaryMixedRecursionOptions,
        circuit_limits: &DirectCircuitLimits,
    ) -> Result<Self, VerificationError>
    where
        Base: EncodableLevel + FoldAlphabet<F> + PackedValue<Value = Base> + Ord,
        F: ChallengeField<Base>,
        BinaryWhirDomain<Base>: WhirDomain<Base, F>,
        A: VerifierAir<Base, F>,
        L: BinaryNativeWhirLayout<Base>,
    {
        Self::prepare(authority, options, circuit_limits, None)
    }

    /// As [`Self::from_native_authority`], stopping verifier construction at periodic
    /// entry-count checkpoints before lowering.
    pub fn from_native_authority_with_construction_limits<A, L>(
        authority: &BinaryNativeWhirAuthority<Base, A, L>,
        options: NativeBinaryMixedRecursionOptions,
        circuit_limits: &DirectCircuitLimits,
        construction_limits: &CircuitConstructionLimits,
    ) -> Result<Self, VerificationError>
    where
        Base: EncodableLevel + FoldAlphabet<F> + PackedValue<Value = Base> + Ord,
        F: ChallengeField<Base>,
        BinaryWhirDomain<Base>: WhirDomain<Base, F>,
        A: VerifierAir<Base, F>,
        L: BinaryNativeWhirLayout<Base>,
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
        checked: &VerifiedBinaryNativeWhirProof<Base>,
    ) -> Result<NativeBinaryMixedRecursiveProof, VerificationError> {
        self.prove_checked(&checked.identity, checked.public_values(), |shape| {
            checked.native_input().private_native_values(shape)
        })
    }
}

impl PreparedNativeBinaryMixedWhirLayer<F, BinaryMixedWhirMultiStarkInputShape> {
    /// Builds the full native verifier of a child with one table committed as packed bits,
    /// such as another mixed layer's output, whose Keccak table is, and an output authority
    /// that commits the output Keccak table as packed bits. All child plans and preprocessing
    /// come from `authority`, independently of any proof. Native Keccak is required.
    pub fn from_mixed_authority<A: VerifierAir<F, F>>(
        authority: &BinaryNativeMixedWhirAuthority<A>,
        options: NativeBinaryMixedRecursionOptions,
        circuit_limits: &DirectCircuitLimits,
    ) -> Result<Self, VerificationError> {
        Self::prepare(authority, options, circuit_limits, None)
    }

    /// As [`Self::from_mixed_authority`], stopping verifier construction at periodic
    /// entry-count checkpoints before lowering.
    pub fn from_mixed_authority_with_construction_limits<A: VerifierAir<F, F>>(
        authority: &BinaryNativeMixedWhirAuthority<A>,
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
        checked: &VerifiedBinaryNativeMixedWhirProof,
    ) -> Result<NativeBinaryMixedRecursiveProof, VerificationError> {
        self.prove_checked(&checked.identity, checked.public_values(), |shape| {
            checked.native_input().private_native_values(shape)
        })
    }
}

impl<A: VerifierAir<F, F>> NativeWhirChild for BinaryNativeMixedWhirAuthority<A> {
    type Shape = BinaryMixedWhirMultiStarkInputShape;
    type Targets = BinaryMixedWhirMultiStarkProofTargets<
        NativeTower128Target,
        NativeBooleanWhirTraceProofTargets,
    >;

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
        public: &[Vec<NativeTower128Target>],
        proof: &Self::Targets,
    ) -> Result<BinaryTower128Challenger, VerificationError> {
        self.recursive_verifier()
            .verify_native(builder, challenger, public, proof)
    }
}

impl<Base: RecursiveBinaryWhirTowerField, S> PreparedNativeBinaryMixedWhirLayer<Base, S>
where
    F: ExtensionField<Base>,
{
    fn prepare<C: NativeWhirChild<Shape = S>>(
        child: &C,
        options: NativeBinaryMixedRecursionOptions,
        circuit_limits: &DirectCircuitLimits,
        construction_limits: Option<CircuitConstructionLimits>,
    ) -> Result<Self, VerificationError> {
        let NativeBinaryMixedRecursionOptions {
            base: options,
            packed,
        } = options;
        let (circuit, bus) = native_verifier_circuit(
            child,
            &options,
            circuit_limits,
            construction_limits.as_ref(),
            KeccakCommitment::Bits,
        )?;
        let input_shape = child.shape();
        let public_counts = C::public_counts(&input_shape);
        let (keccak_table, bit_variables) = bus
            .keccak_table_index()
            .zip(bus.packed_bit_variables())
            .ok_or_else(|| {
                VerificationError::InvalidProofShape(
                    "native recursive output has no packed Keccak table".into(),
                )
            })?;
        let packed_variables = bit_variables
            .checked_sub(ABSORBED_VARIABLES)
            .ok_or_else(|| {
                VerificationError::InvalidProofShape(
                    "native recursive packed Keccak table is smaller than one field element".into(),
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
        let whir = |variables, protocol| {
            BinaryNativeWhirPcsParameters::<F>::with_limits(
                variables,
                protocol,
                ByteHash::Keccak256,
                options.arity,
                options.cap_height,
                &limits.verifier,
            )
        };
        let main = BinaryNativeMixedWhirPcsParameters::with_packed_table(
            whir(bus.main_variables(), options.main)?,
            whir(packed_variables, packed)?,
            keccak_table,
            bit_variables,
        )?;
        let preprocessed = bus
            .preprocessed_variables()
            .map(|variables| {
                whir(variables, options.preprocessed).map(BinaryNativeMixedWhirPcsParameters::dense)
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
            BinaryNativeMixedWhirAuthority::<OutputAir>::setup_with_artifact_limits(
                bus.airs().to_vec(),
                bus.log_heights().to_vec(),
                spec,
                *limits,
            )?;
        Ok(Self {
            input_identity: child.identity(),
            input_shape,
            statement: PhantomData,
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
    /// Output authority over the mixed commitment, suitable as the independently trusted
    /// child of [`PreparedNativeBinaryMixedWhirLayer::from_mixed_authority`]. Its statement
    /// uses output AIR order.
    pub const fn authority(&self) -> &BinaryNativeMixedWhirAuthority<OutputAir> {
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

    /// Checks the token's identity before `pack` or runner allocation, then runs the verifier
    /// circuit on the token's statement and the child proof's values from `pack` and proves
    /// its tables.
    fn prove_checked(
        &self,
        identity: &[u8],
        statement: &[Vec<Base>],
        pack: impl FnOnce(&S) -> Result<Vec<F>, VerificationError>,
    ) -> Result<NativeBinaryMixedRecursiveProof, VerificationError> {
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
        let tables = self
            .bus
            .trace_tables(&trace)?
            .into_iter()
            .map(|trace| match trace {
                NativeBusTrace::Dense(matrix) => Table::new(matrix.transpose()),
                NativeBusTrace::PackedBits { words, log_height } => {
                    Table::from_packed_bits(words, log_height)
                }
            })
            .collect();
        self.prover.prove_tables(&output_public, tables)
    }

    /// Verifies against the caller's original child statement. Expected values are never
    /// obtained from the recursive proof itself.
    pub fn verify(
        &self,
        proof: &NativeBinaryMixedRecursiveProof,
        expected: &[Vec<Base>],
    ) -> Result<VerifiedBinaryNativeMixedWhirProof, VerificationError> {
        self.authority
            .verify_native(proof, &self.output_public_values(expected)?)
    }
}
