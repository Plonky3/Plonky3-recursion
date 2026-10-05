//! Shared prepared prover lifecycle for complete private binary relations.

use core::hash::Hash;

use p3_circuit::ops::BinaryTower128Target;

use super::statement::ClosedStatement;
use super::*;
use crate::verifier::{
    BinaryGroupedMultiStarkInputShape, BinaryGroupedMultiStarkProofTargets,
    BinaryGroupedMultiStarkVerifier, BinaryMultiStarkProofTargets,
    NativeBinaryGroupedMultiStarkInput,
};

/// Only complete built-in relations can populate this shared prepared lifecycle.
pub(super) trait ClosedBinaryCircuit<F, E> {
    type Statement: ClosedStatement<F>;
    type Shape;
    type Targets;
    type Input;
    fn usage(&self) -> InputResourceUsage;
    fn shape(&self) -> Self::Shape;
    fn public_counts(shape: &Self::Shape) -> Vec<usize>;
    fn allocate_targets<BF, EF>(
        shape: &Self::Shape,
        b: &mut CircuitBuilder<EF>,
    ) -> Result<Self::Targets, VerificationError>
    where
        BF: PrimeField64,
        EF: ExtensionField<BF> + Eq + Hash;
    fn verify_circuit<BF, EF>(
        &self,
        b: &mut CircuitBuilder<EF>,
        ch: BinaryTower128Challenger,
        public: &[Vec<<Self::Statement as ClosedStatement<F>>::Target>],
        targets: &Self::Targets,
    ) -> Result<(), VerificationError>
    where
        BF: PrimeField64,
        EF: ExtensionField<BF> + Eq + Hash;
    fn private_values<EF: p3_field::Field>(
        input: &Self::Input,
        shape: &Self::Shape,
    ) -> Result<Vec<EF>, VerificationError>;
}

macro_rules! circuit_relation {
    ($verifier:ident, $shape:ident, $targets:ident, $input:ident) => {
        impl<F, E> ClosedBinaryCircuit<F, E> for $verifier<F, E>
        where
            F: RecursiveBinaryTowerField,
            E: RecursiveBinaryChallengeField + ExtensionField<F>,
        {
            type Statement = BinaryStatementLayout<F>;
            type Shape = $shape<F, E>;
            type Targets = $targets;
            type Input = $input<F, E>;
            fn usage(&self) -> InputResourceUsage {
                self.input_resource_usage()
            }
            fn shape(&self) -> Self::Shape {
                self.input_shape()
            }
            fn public_counts(shape: &Self::Shape) -> Vec<usize> {
                shape.public_value_counts().collect()
            }
            fn allocate_targets<BF, EF>(
                shape: &Self::Shape,
                b: &mut CircuitBuilder<EF>,
            ) -> Result<Self::Targets, VerificationError>
            where
                BF: PrimeField64,
                EF: ExtensionField<BF> + Eq + Hash,
            {
                shape.allocate_targets::<BF, EF>(b)
            }
            fn verify_circuit<BF, EF>(
                &self,
                b: &mut CircuitBuilder<EF>,
                ch: BinaryTower128Challenger,
                public: &[Vec<BinaryTower128Target>],
                targets: &Self::Targets,
            ) -> Result<(), VerificationError>
            where
                BF: PrimeField64,
                EF: ExtensionField<BF> + Eq + Hash,
            {
                self.verify::<BF, EF>(b, ch, public, targets).map(|_| ())
            }
            fn private_values<EF: p3_field::Field>(
                input: &Self::Input,
                shape: &Self::Shape,
            ) -> Result<Vec<EF>, VerificationError> {
                input.private_values::<EF>(shape)
            }
        }
    };
}
circuit_relation!(
    BinaryMultiStarkVerifier,
    BinaryMultiStarkInputShape,
    BinaryMultiStarkProofTargets,
    NativeBinaryMultiStarkInput
);
circuit_relation!(
    BinaryGroupedMultiStarkVerifier,
    BinaryGroupedMultiStarkInputShape,
    BinaryGroupedMultiStarkProofTargets,
    NativeBinaryGroupedMultiStarkInput
);

pub(super) struct BinaryPreparedCore<
    F,
    E,
    SC: StarkGenericConfig + 'static,
    const D: usize,
    R,
    S,
    SL = BinaryStatementLayout<F>,
> {
    pub(super) binary: R,
    shape: S,
    field: PhantomData<(F, E)>,
    pub(super) layout: SL,
    circuit: Circuit<SC::Challenge>,
    pub(super) prepared: PreparedProver<SC>,
    pub(super) params: ProveNextLayerParams,
    pub(super) native_identity: Option<Arc<[u8]>>,
}

impl<F, E, SC, const D: usize, R, S, SL> BinaryPreparedCore<F, E, SC, D, R, S, SL>
where
    R: ClosedBinaryCircuit<F, E, Shape = S, Statement = SL>,
    SL: ClosedStatement<F>,
    SC: StarkGenericConfig + Send + Sync + Clone + 'static,
    Val<SC>: PrimeField64 + StarkField,
    SC::Challenge: BasedVectorSpace<Val<SC>>
        + From<Val<SC>>
        + ExtensionField<Val<SC>>
        + ExtractBinomialW<Val<SC>>,
    SymbolicExpressionExt<Val<SC>, SC::Challenge>:
        Algebra<SymbolicExpression<Val<SC>>> + Algebra<SC::Challenge>,
    SC::Challenger: p3_challenger::GrindingChallenger<Witness = Val<SC>>,
    p3_uni_stark::PcsProverError<SC>: Send,
    <SC::Pcs as Pcs<SC::Challenge, SC::Challenger>>::Domain: Send + Sync,
    SC::Pcs: Sync,
    <SC::Pcs as Pcs<SC::Challenge, SC::Challenger>>::ProverData: Sync,
    <SC::Pcs as Pcs<SC::Challenge, SC::Challenger>>::Commitment: Sync,
    StatementPreprocessor: NpoPreprocessor<Val<SC>>,
    KeccakF1600Preprocessor: NpoPreprocessor<Val<SC>>,
    Blake3CompressPreprocessor: NpoPreprocessor<Val<SC>>,
{
    #[expect(
        clippy::needless_pass_by_value,
        reason = "Keep the owned configuration used by prepared-layer constructors."
    )]
    pub(super) fn with_limits(
        binary: R,
        hash: ByteHash,
        initial_bytes: &[u8],
        output_config: SC,
        params: ProveNextLayerParams,
        limits: &VerifierLimits,
    ) -> Result<Self, VerificationError> {
        if D != <SC::Challenge as BasedVectorSpace<Val<SC>>>::DIMENSION {
            return Err(invalid("binary prepared circuit extension degree mismatch"));
        }
        let mut usage = binary.usage();
        usage.check(limits)?;
        usage.add_metadata_entries(limits, initial_bytes.len())?;
        let shape = binary.shape();
        let counts: Vec<_> = R::public_counts(&shape);
        let layout = SL::with_limits(&counts, limits)?;
        usage.add_metadata_entries(limits, layout.schema().base_len())?;
        let mut b = CircuitBuilder::<SC::Challenge>::new();
        // Main PCS, preprocessing PCS and transcript hashes are independently
        // configured. Register both closed byte-hash implementations.
        b.enable_keccak_f1600::<Val<SC>>();
        b.enable_blake3_compress::<Val<SC>>();
        let (public, original_limbs) = layout.allocate_public::<Val<SC>, SC::Challenge>(&mut b)?;
        let targets = R::allocate_targets::<Val<SC>, SC::Challenge>(&shape, &mut b)?;
        let initial = initial_bytes
            .iter()
            .map(|&byte| b.define_const(SC::Challenge::from_u8(byte)))
            .collect::<Vec<_>>();
        let ch = BinaryTower128Challenger::with_initial_bytes::<Val<SC>, SC::Challenge>(
            &mut b, hash, &initial,
        )?;
        binary.verify_circuit::<Val<SC>, SC::Challenge>(&mut b, ch, &public, &targets)?;
        // SAFETY: These are the exact original limb IDs used above to build
        // each AIR public value consumed by the complete binary verifier.
        // The layout fixes their instance/value/limb order and Base encoding.
        unsafe {
            VerifiedStatementTargets::new_unchecked(&b, layout.schema().clone(), original_limbs)
        }?
        .install::<Val<SC>>(&mut b)?;
        let circuit = b.build()?;
        let mut preprocessors: Vec<Box<dyn NpoPreprocessor<Val<SC>>>> = vec![
            Box::new(KeccakF1600Preprocessor),
            Box::new(Blake3CompressPreprocessor),
        ];
        let mut builders: Vec<Box<dyn NpoAirBuilder<SC, D>>> = vec![
            Box::new(KeccakF1600AirBuilder::<D>),
            Box::new(Blake3CompressAirBuilder::<D>),
        ];
        let mut provers: Vec<Box<dyn TableProver<SC>>> = vec![
            Box::new(KeccakF1600Prover::<D>),
            Box::new(Blake3CompressProver::<D>),
        ];
        if layout.schema().base_len() != 0 {
            preprocessors.push(Box::new(StatementPreprocessor::new(
                layout.schema().clone(),
            )));
            builders.push(Box::new(StatementAirBuilder::<D>::new(
                layout.schema().clone(),
            )));
            provers.push(Box::new(StatementProver::<D>::new(layout.schema().clone())));
        }
        let prepared = prepare_prover_from_parts::<SC, D>(
            &circuit,
            &output_config,
            &params,
            &preprocessors,
            &builders,
            provers,
        )?;
        Ok(Self {
            binary,
            shape,
            layout,
            circuit,
            prepared,
            params,
            native_identity: None,
            field: PhantomData,
        })
    }

    pub(super) fn prove(
        &self,
        input: &R::Input,
        public: &[Vec<F>],
    ) -> Result<RecursionOutput<SC>, VerificationError>
    where
        p3_batch_stark::BatchProof<SC>: ProvingMaybeSend,
    {
        let public: Vec<_> = self
            .layout
            .pack::<Val<SC>>(public)?
            .into_iter()
            .map(SC::Challenge::from)
            .collect();
        let private = R::private_values::<SC::Challenge>(input, &self.shape)?;
        let mut runner = self.circuit.runner();
        runner.set_public_inputs(&public)?;
        runner.set_private_inputs(&private)?;
        let traces = runner.run()?;
        self.prepared.prove(&traces)
    }
}
