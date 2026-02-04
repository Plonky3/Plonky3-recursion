//! BatchStarkProver implementation.

use alloc::boxed::Box;
use alloc::vec::Vec;
use alloc::{format, vec};

use p3_air::Air;
use p3_batch_stark::{CommonData, StarkGenericConfig, StarkInstance, Val};
use p3_circuit::op::Poseidon2Config;
use p3_circuit::tables::Traces;
use p3_field::extension::{BinomialExtensionField, BinomiallyExtendable};
use p3_field::{BasedVectorSpace, Field};
use p3_matrix::dense::RowMajorMatrix;
use p3_uni_stark::{SymbolicAirBuilder, SymbolicExpression};
use tracing::instrument;

use super::dynamic_air::NonPrimitiveTableEntry;
use super::packing::TablePacking;
use super::poseidon2_prover::Poseidon2Prover;
use super::proof::{
    BatchStarkProof, BatchStarkProverError, NUM_PRIMITIVE_TABLES, PrimitiveTable, RowCounts,
};
use super::table_prover::{BatchTableInstance, TableProver, transmute_traces};
use crate::air::{AddAir, ConstAir, MulAir, PublicAir, WitnessAir};
use crate::common::CircuitTableAir;
use crate::config::StarkField;
use crate::field_params::ExtractBinomialW;

/// Produces a single batch STARK proof covering all circuit tables.
pub struct BatchStarkProver<SC>
where
    SC: StarkGenericConfig + 'static,
{
    config: SC,
    table_packing: TablePacking,
    /// Registered dynamic non-primitive table provers.
    non_primitive_provers: Vec<Box<dyn TableProver<SC>>>,
}

impl<SC> BatchStarkProver<SC>
where
    SC: StarkGenericConfig + 'static,
    Val<SC>: StarkField,
    SymbolicExpression<SC::Challenge>: From<SymbolicExpression<Val<SC>>>,
{
    pub fn new(config: SC) -> Self {
        Self {
            config,
            table_packing: TablePacking::default(),
            non_primitive_provers: Vec::new(),
        }
    }

    #[must_use]
    pub const fn with_table_packing(mut self, table_packing: TablePacking) -> Self {
        self.table_packing = table_packing;
        self
    }

    /// Register a dynamic non-primitive table prover.
    pub fn register_table_prover(&mut self, prover: Box<dyn TableProver<SC>>) {
        self.non_primitive_provers.push(prover);
    }

    /// Builder-style registration for a dynamic non-primitive table prover.
    #[must_use]
    pub fn with_table_prover(mut self, prover: Box<dyn TableProver<SC>>) -> Self {
        self.register_table_prover(prover);
        self
    }

    /// Register the non-primitive Poseidon2 prover plugin with the given configuration.
    pub fn register_poseidon2_table(&mut self, config: Poseidon2Config)
    where
        SC: Send + Sync,
        Val<SC>: BinomiallyExtendable<4>,
    {
        self.register_table_prover(Box::new(Poseidon2Prover::new(config)));
    }

    #[inline]
    pub const fn table_packing(&self) -> TablePacking {
        self.table_packing
    }

    /// Generate a unified batch STARK proof for all circuit tables.
    #[instrument(skip_all)]
    pub fn prove_all_tables<EF>(
        &self,
        traces: &Traces<EF>,
        common: &CommonData<SC>,
        witness_multiplicities: Vec<Val<SC>>,
    ) -> Result<BatchStarkProof<SC>, BatchStarkProverError>
    where
        EF: Field + BasedVectorSpace<Val<SC>> + ExtractBinomialW<Val<SC>>,
        SymbolicExpression<SC::Challenge>: From<SymbolicExpression<Val<SC>>>,
    {
        let w_opt = EF::extract_w();
        match EF::DIMENSION {
            1 => self.prove::<EF, 1>(traces, None, common, witness_multiplicities),
            2 => self.prove::<EF, 2>(traces, w_opt, common, witness_multiplicities),
            4 => self.prove::<EF, 4>(traces, w_opt, common, witness_multiplicities),
            6 => self.prove::<EF, 6>(traces, w_opt, common, witness_multiplicities),
            8 => self.prove::<EF, 8>(traces, w_opt, common, witness_multiplicities),
            d => Err(BatchStarkProverError::UnsupportedDegree(d)),
        }
    }

    /// Verify the unified batch STARK proof against all tables.
    pub fn verify_all_tables(
        &self,
        proof: &BatchStarkProof<SC>,
        common: &CommonData<SC>,
    ) -> Result<(), BatchStarkProverError> {
        match proof.ext_degree {
            1 => self.verify::<1>(proof, None, common),
            2 => self.verify::<2>(proof, proof.w_binomial, common),
            4 => self.verify::<4>(proof, proof.w_binomial, common),
            6 => self.verify::<6>(proof, proof.w_binomial, common),
            8 => self.verify::<8>(proof, proof.w_binomial, common),
            d => Err(BatchStarkProverError::UnsupportedDegree(d)),
        }
    }

    /// Generate a batch STARK proof for a specific extension field degree.
    ///
    /// This is the core proving logic that handles all circuit tables for a given
    /// extension field dimension. It constructs AIRs, converts traces to matrices,
    /// and generates the unified proof.
    fn prove<EF, const D: usize>(
        &self,
        traces: &Traces<EF>,
        w_binomial: Option<Val<SC>>,
        common: &CommonData<SC>,
        witness_multiplicities: Vec<Val<SC>>,
    ) -> Result<BatchStarkProof<SC>, BatchStarkProverError>
    where
        EF: Field + BasedVectorSpace<Val<SC>>,
    {
        // Build matrices and AIRs per table.
        let packing = self.table_packing;
        let witness_lanes = packing.witness_lanes();
        let add_lanes = packing.add_lanes();
        let mul_lanes = packing.mul_lanes();

        // Witness
        let witness_rows = traces.witness_trace.num_rows();
        let witness_air = WitnessAir::<Val<SC>, D>::new_with_preprocessed(
            witness_rows,
            witness_lanes,
            witness_multiplicities,
        );
        let witness_matrix: RowMajorMatrix<Val<SC>> =
            WitnessAir::<Val<SC>, D>::trace_to_matrix(&traces.witness_trace, witness_lanes);

        // Const
        let const_rows = traces.const_trace.values.len();
        let const_prep = ConstAir::<Val<SC>, D>::trace_to_preprocessed(&traces.const_trace);
        let const_air = ConstAir::<Val<SC>, D>::new_with_preprocessed(const_rows, const_prep);
        let const_matrix: RowMajorMatrix<Val<SC>> =
            ConstAir::<Val<SC>, D>::trace_to_matrix(&traces.const_trace);

        // Public
        let public_rows = traces.public_trace.values.len();
        let public_prep = PublicAir::<Val<SC>, D>::trace_to_preprocessed(&traces.public_trace);
        let public_air = PublicAir::<Val<SC>, D>::new_with_preprocessed(public_rows, public_prep);
        let public_matrix: RowMajorMatrix<Val<SC>> =
            PublicAir::<Val<SC>, D>::trace_to_matrix(&traces.public_trace);

        // Add
        let add_rows = traces.add_trace.lhs_values.len();
        let add_prep = AddAir::<Val<SC>, D>::trace_to_preprocessed(&traces.add_trace);
        let add_air = AddAir::<Val<SC>, D>::new_with_preprocessed(add_rows, add_lanes, add_prep);
        let add_matrix: RowMajorMatrix<Val<SC>> =
            AddAir::<Val<SC>, D>::trace_to_matrix(&traces.add_trace, add_lanes);

        // Mul
        let mul_rows = traces.mul_trace.lhs_values.len();
        let mul_prep = MulAir::<Val<SC>, D>::trace_to_preprocessed(&traces.mul_trace);
        let mul_air: MulAir<Val<SC>, D> = if D == 1 {
            MulAir::<Val<SC>, D>::new_with_preprocessed(mul_rows, mul_lanes, mul_prep)
        } else {
            let w = w_binomial.ok_or(BatchStarkProverError::MissingWForExtension)?;
            MulAir::<Val<SC>, D>::new_binomial_with_preprocessed(mul_rows, mul_lanes, w, mul_prep)
        };
        let mul_matrix: RowMajorMatrix<Val<SC>> =
            MulAir::<Val<SC>, D>::trace_to_matrix(&traces.mul_trace, mul_lanes);

        tracing::warn!(
            "Witness length: {}",
            traces.witness_trace.num_rows() / witness_lanes
        );
        tracing::warn!("Const length: {}", traces.const_trace.values.len());
        tracing::warn!("Public length: {}", traces.public_trace.values.len());
        tracing::warn!(
            "Add length: {}",
            traces.add_trace.lhs_values.len() / add_lanes
        );
        tracing::warn!(
            "Mul length: {}",
            traces.mul_trace.lhs_values.len() / mul_lanes
        );

        // We first handle all non-primitive tables dynamically, which will then be batched alongside primitive ones.
        // Each trace must have a corresponding registered prover for it to be provable.
        for (&op_type, trace) in &traces.non_primitive_traces {
            if trace.rows() == 0 {
                continue;
            }
            if !self
                .non_primitive_provers
                .iter()
                .any(|p| p.op_type() == op_type)
            {
                return Err(BatchStarkProverError::MissingTableProver(op_type));
            }
        }

        let mut dynamic_instances: Vec<BatchTableInstance<SC>> = Vec::new();
        if D == 1 {
            let t: &Traces<Val<SC>> = unsafe { transmute_traces(traces) };
            for p in &self.non_primitive_provers {
                if let Some(instance) = p.batch_instance_d1(&self.config, packing, t) {
                    dynamic_instances.push(instance);
                }
            }
        } else if D == 2 {
            type EF2<F> = BinomialExtensionField<F, 2>;
            let t: &Traces<EF2<Val<SC>>> = unsafe { transmute_traces(traces) };
            for p in &self.non_primitive_provers {
                if let Some(instance) = p.batch_instance_d2(&self.config, packing, t) {
                    dynamic_instances.push(instance);
                }
            }
        } else if D == 4 {
            type EF4<F> = BinomialExtensionField<F, 4>;
            let t: &Traces<EF4<Val<SC>>> = unsafe { transmute_traces(traces) };
            for p in &self.non_primitive_provers {
                if let Some(instance) = p.batch_instance_d4(&self.config, packing, t) {
                    dynamic_instances.push(instance);
                }
            }
        } else if D == 6 {
            type EF6<F> = BinomialExtensionField<F, 6>;
            let t: &Traces<EF6<Val<SC>>> = unsafe { transmute_traces(traces) };
            for p in &self.non_primitive_provers {
                if let Some(instance) = p.batch_instance_d6(&self.config, packing, t) {
                    dynamic_instances.push(instance);
                }
            }
        } else if D == 8 {
            type EF8<F> = BinomialExtensionField<F, 8>;
            let t: &Traces<EF8<Val<SC>>> = unsafe { transmute_traces(traces) };
            for p in &self.non_primitive_provers {
                if let Some(instance) = p.batch_instance_d8(&self.config, packing, t) {
                    dynamic_instances.push(instance);
                }
            }
        }

        // Wrap AIRs in enum for heterogeneous batching and build instances in fixed order.
        let mut air_storage: Vec<CircuitTableAir<SC, D>> =
            Vec::with_capacity(NUM_PRIMITIVE_TABLES + dynamic_instances.len());
        let mut trace_storage: Vec<RowMajorMatrix<Val<SC>>> =
            Vec::with_capacity(NUM_PRIMITIVE_TABLES + dynamic_instances.len());
        let mut public_storage: Vec<Vec<Val<SC>>> =
            Vec::with_capacity(NUM_PRIMITIVE_TABLES + dynamic_instances.len());
        let mut non_primitives: Vec<NonPrimitiveTableEntry<SC>> =
            Vec::with_capacity(dynamic_instances.len());

        air_storage.push(CircuitTableAir::Witness(witness_air));
        trace_storage.push(witness_matrix);
        public_storage.push(Vec::new());

        air_storage.push(CircuitTableAir::Const(const_air));
        trace_storage.push(const_matrix);
        public_storage.push(Vec::new());

        air_storage.push(CircuitTableAir::Public(public_air));
        trace_storage.push(public_matrix);
        public_storage.push(Vec::new());

        air_storage.push(CircuitTableAir::Add(add_air));
        trace_storage.push(add_matrix);
        public_storage.push(Vec::new());

        air_storage.push(CircuitTableAir::Mul(mul_air));
        trace_storage.push(mul_matrix);
        public_storage.push(Vec::new());

        for instance in dynamic_instances {
            let BatchTableInstance {
                op_type,
                air,
                trace,
                public_values,
                rows,
            } = instance;
            air_storage.push(CircuitTableAir::Dynamic(air));
            trace_storage.push(trace);
            public_storage.push(public_values.clone());
            non_primitives.push(NonPrimitiveTableEntry {
                op_type,
                rows,
                public_values,
            });
        }

        let instances: Vec<StarkInstance<'_, SC, CircuitTableAir<SC, D>>> = air_storage
            .iter_mut()
            .zip(trace_storage)
            .zip(public_storage)
            .map(|((air, trace), public_values)| {
                let lookups = Air::<SymbolicAirBuilder<Val<SC>, SC::Challenge>>::get_lookups(air);

                StarkInstance {
                    air,
                    trace,
                    public_values,
                    lookups,
                }
            })
            .collect();

        let proof = p3_batch_stark::prove_batch(&self.config, &instances, common);

        // Ensure all primitive table row counts are at least 1
        // RowCounts::new requires non-zero counts, so pad zeros to 1
        let witness_rows_padded = witness_rows.max(1);
        let const_rows_padded = const_rows.max(1);
        let public_rows_padded = public_rows.max(1);
        let add_rows_padded = add_rows.max(1);
        let mul_rows_padded = mul_rows.max(1);

        Ok(BatchStarkProof {
            proof,
            table_packing: packing,
            rows: RowCounts::new([
                witness_rows_padded,
                const_rows_padded,
                public_rows_padded,
                add_rows_padded,
                mul_rows_padded,
            ]),
            ext_degree: D,
            w_binomial: if D > 1 { w_binomial } else { None },
            non_primitives,
        })
    }

    /// Verify a batch STARK proof for a specific extension field degree.
    ///
    /// This reconstructs the AIRs from the proof metadata and verifies the proof
    /// against all circuit tables. The AIRs are reconstructed using the same
    /// configuration that was used during proof generation.
    fn verify<const D: usize>(
        &self,
        proof: &BatchStarkProof<SC>,
        w_binomial: Option<Val<SC>>,
        common: &CommonData<SC>,
    ) -> Result<(), BatchStarkProverError> {
        // Rebuild AIRs in the same order as prove.
        let packing = proof.table_packing;
        let witness_lanes = packing.witness_lanes();
        let add_lanes = packing.add_lanes();
        let mul_lanes = packing.mul_lanes();

        let witness_air = CircuitTableAir::Witness(WitnessAir::<Val<SC>, D>::new(
            proof.rows[PrimitiveTable::Witness],
            witness_lanes,
        ));
        let const_air = CircuitTableAir::Const(ConstAir::<Val<SC>, D>::new(
            proof.rows[PrimitiveTable::Const],
        ));
        let public_air = CircuitTableAir::Public(PublicAir::<Val<SC>, D>::new(
            proof.rows[PrimitiveTable::Public],
        ));
        let add_air = CircuitTableAir::Add(AddAir::<Val<SC>, D>::new(
            proof.rows[PrimitiveTable::Add],
            add_lanes,
        ));
        let mul_air: CircuitTableAir<SC, D> = if D == 1 {
            CircuitTableAir::Mul(MulAir::<Val<SC>, D>::new(
                proof.rows[PrimitiveTable::Mul],
                mul_lanes,
            ))
        } else {
            let w = w_binomial.ok_or(BatchStarkProverError::MissingWForExtension)?;
            CircuitTableAir::Mul(MulAir::<Val<SC>, D>::new_binomial(
                proof.rows[PrimitiveTable::Mul],
                mul_lanes,
                w,
            ))
        };
        let mut airs = vec![witness_air, const_air, public_air, add_air, mul_air];
        let mut pvs: Vec<Vec<Val<SC>>> = vec![Vec::new(); NUM_PRIMITIVE_TABLES];

        for entry in &proof.non_primitives {
            let plugin = self
                .non_primitive_provers
                .iter()
                .find(|p| {
                    let tp = p.as_ref();
                    TableProver::op_type(tp) == entry.op_type
                })
                .ok_or_else(|| {
                    BatchStarkProverError::Verify(format!(
                        "unknown non-primitive op: {:?}",
                        entry.op_type
                    ))
                })?;
            let air = plugin
                .batch_air_from_table_entry(&self.config, D, entry)
                .map_err(BatchStarkProverError::Verify)?;
            airs.push(CircuitTableAir::Dynamic(air));
            pvs.push(entry.public_values.clone());
        }

        p3_batch_stark::verify_batch(&self.config, &airs, &proof.proof, &pvs, common)
            .map_err(|e| BatchStarkProverError::Verify(format!("{e:?}")))
    }
}
