//! Prepared Tower32/Tower128 verifier circuits proved over Tower128, with the output proof's
//! Keccak table committed as packed bits.

use alloc::sync::Arc;
use alloc::vec::Vec;

use p3_binary_dft::EncodableLevel;
use p3_binary_field::{BinaryField128, TowerLevel};
use p3_binary_pcs::whir::BinaryWhirDomain;
use p3_binary_pcs::{ChallengeField, FoldAlphabet};
use p3_circuit::ops::ByteHash;
use p3_circuit::ops::binary_encoding::{BinaryCircuitEncoding, NativeBinaryEncoding};
use p3_circuit::ops::binary_host::BinaryCircuitHost;
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

use super::native_binary::{NativeBinaryRecursionOptions, codeword_cells, first_fold};
use crate::BinaryTower128Challenger;
use crate::artifact::{
    BinaryNativeMixedWhirAuthority, BinaryNativeMixedWhirConfig,
    BinaryNativeMixedWhirPcsParameters, BinaryNativeMixedWhirProver, BinaryNativeVerifierSpec,
    BinaryNativeWhirAuthority, BinaryNativeWhirLayout, BinaryNativeWhirPcsParameters,
    VerifiedBinaryNativeMixedWhirProof, VerifiedBinaryNativeWhirProof,
};
use crate::pcs::binary::RecursiveBinaryWhirTowerField;
use crate::verifier::{BinaryWhirMultiStarkInputShape, VerificationError};

type F = BinaryField128;
type H = NativeBinaryEncoding;
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
/// matched mixed proving/verification keys for repeatable proving.
pub struct PreparedNativeBinaryMixedWhirLayer<Base = F>
where
    Base: RecursiveBinaryWhirTowerField,
{
    input_identity: Arc<[u8]>,
    input_shape: BinaryWhirMultiStarkInputShape<Base>,
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

    fn prepare<A, L>(
        authority: &BinaryNativeWhirAuthority<Base, A, L>,
        options: NativeBinaryMixedRecursionOptions,
        circuit_limits: &DirectCircuitLimits,
        construction_limits: Option<CircuitConstructionLimits>,
    ) -> Result<Self, VerificationError>
    where
        Base: EncodableLevel + FoldAlphabet<F> + PackedValue<Value = Base> + Ord,
        F: ChallengeField<Base>,
        BinaryWhirDomain<Base>: WhirDomain<Base, F>,
        A: VerifierAir<Base, F>,
        L: BinaryNativeWhirLayout<Base>,
    {
        let NativeBinaryMixedRecursionOptions {
            base: options,
            packed,
        } = options;
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
                        Ok(builder.native_tower128_from_expr(value))
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
        let bus = NativeBusCircuit::with_options(
            &circuit,
            "recursion",
            minimum_log_height,
            *circuit_limits,
            KeccakCommitment::Bits,
        )?;
        let required_draws = bus.log_heights().iter().copied().max().unwrap_or(0);
        if options.max_tau_draws < required_draws {
            return Err(VerificationError::InvalidProofShape(alloc::format!(
                "native recursive nonzero draw budget {} is below the required {}",
                options.max_tau_draws,
                required_draws,
            )));
        }
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
    /// Output authority over the mixed commitment. Its statement uses output AIR order.
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

    /// Accepts only a token checked under the retained child authority. Identity is checked
    /// before witness packing or runner allocation.
    pub fn prove_verified(
        &self,
        checked: &VerifiedBinaryNativeWhirProof<Base>,
    ) -> Result<NativeBinaryMixedRecursiveProof, VerificationError> {
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
