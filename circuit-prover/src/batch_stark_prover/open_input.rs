use alloc::boxed::Box;
use alloc::format;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;

use p3_air::SymbolicExpression;
use p3_batch_stark::{StarkGenericConfig, Val};
use p3_circuit::op::NonPrimitiveOpType;
use p3_circuit::ops::open_input::{OpenInputRow, OpenInputTrace};
use p3_circuit::tables::Traces;
use p3_field::extension::{BinomialExtensionField, BinomiallyExtendable};
use p3_field::{BasedVectorSpace, Field, PrimeCharacteristicRing};
use p3_fri_air::OpenInputAir;

use super::dynamic_air::{BatchTableInstance, DynamicAirEntry, TableProver};
use crate::batch_stark_prover::{BatchAir, NonPrimitiveTableEntry, TablePacking};
use crate::config::StarkField;

impl<SC, const D: usize> BatchAir<SC> for OpenInputAir<Val<SC>, D>
where
    SC: StarkGenericConfig + Send + Sync,
    Val<SC>: StarkField,
    SymbolicExpression<SC::Challenge>: From<SymbolicExpression<Val<SC>>>,
{
}

/// Prover plugin for the `OpenInput` non-primitive table.
///
/// Unlike Poseidon2, OpenInput does not need field-specific variants: the AIR
/// always stores `D` base-field columns per extension element, where `D` is
/// the extension degree used for the proof.  Only D=1 and D=4 are supported.
#[derive(Clone)]
pub struct OpenInputProver;

unsafe impl Send for OpenInputProver {}
unsafe impl Sync for OpenInputProver {}

impl OpenInputProver {
    pub const fn new() -> Self {
        Self
    }

    /// Produce a `BatchTableInstance` for any extension degree known at compile time.
    ///
    /// The trace is always stored in base-field form (`OpenInputTrace<Val<SC>>`), with each
    /// `Vec` field holding `D` base-field coefficients.  For D > 1 the rows are
    /// converted to `OpenInputRow<BinomialExtensionField<Val<SC>, D>>` (one EF element
    /// per Vec) before being passed to `trace_to_matrix`, matching its expected layout.
    fn batch_instance_impl<SC, const D: usize>(
        _config: &SC,
        packing: TablePacking,
        traces: &Traces<Val<SC>>,
        w_binomial: Val<SC>,
    ) -> Option<BatchTableInstance<SC>>
    where
        SC: StarkGenericConfig + 'static + Send + Sync,
        Val<SC>: StarkField + BinomiallyExtendable<D>,
        BinomialExtensionField<Val<SC>, D>:
            Field + BasedVectorSpace<Val<SC>> + p3_field::ExtensionField<Val<SC>>,
        SymbolicExpression<SC::Challenge>: From<SymbolicExpression<Val<SC>>>,
    {
        let trace =
            traces.non_primitive_trace::<OpenInputTrace<Val<SC>>>(NonPrimitiveOpType::OpenInput)?;

        let rows = trace.rows.len();
        if rows == 0 {
            return None;
        }

        let min_height = packing.min_trace_height();
        let preprocessed = OpenInputAir::<Val<SC>, D>::trace_to_preprocessed(trace);
        let generator = Val::<SC>::GENERATOR;
        let air = OpenInputAir::<Val<SC>, D>::new_with_preprocessed(w_binomial, preprocessed)
            .with_generator(generator)
            .with_min_height(min_height);

        // Convert base-field rows (D coefficients each) to extension-field rows (1 EF element
        // each), which is the layout expected by `trace_to_matrix`.
        let ef_rows: Vec<OpenInputRow<BinomialExtensionField<Val<SC>, D>>> = trace
            .rows
            .iter()
            .map(|row| OpenInputRow {
                alpha: vec![BinomialExtensionField::<Val<SC>, D>::from_basis_coefficients_slice(
                    &row.alpha,
                )
                .expect("alpha must have exactly D coefficients")],
                pow_at_x: vec![
                    BinomialExtensionField::<Val<SC>, D>::from_basis_coefficients_slice(
                        &row.pow_at_x,
                    )
                    .expect("pow_at_x must have exactly D coefficients"),
                ],
                pow_at_z: vec![
                    BinomialExtensionField::<Val<SC>, D>::from_basis_coefficients_slice(
                        &row.pow_at_z,
                    )
                    .expect("pow_at_z must have exactly D coefficients"),
                ],
                alpha_index: row.alpha_index,
                pow_at_x_index: row.pow_at_x_index,
                pow_at_z_index: row.pow_at_z_index,
                ro_index: row.ro_index,
                is_last: row.is_last,
                is_real: row.is_real,
                is_eval: row.is_eval,
                g_power: BinomialExtensionField::<Val<SC>, D>::from(row.g_power),
            })
            .collect();

        let matrix = air.trace_to_matrix::<BinomialExtensionField<Val<SC>, D>>(&ef_rows);
        let padded_rows = rows.next_power_of_two();

        Some(BatchTableInstance {
            op_type: NonPrimitiveOpType::OpenInput,
            air: DynamicAirEntry::new(Box::new(air)),
            trace: matrix,
            public_values: Vec::new(),
            rows: padded_rows,
        })
    }
}

impl<SC> TableProver<SC> for OpenInputProver
where
    SC: StarkGenericConfig + 'static + Send + Sync,
    Val<SC>: StarkField + BinomiallyExtendable<4>,
    SymbolicExpression<SC::Challenge>: From<SymbolicExpression<Val<SC>>>,
{
    fn op_type(&self) -> NonPrimitiveOpType {
        NonPrimitiveOpType::OpenInput
    }

    fn batch_instance_d1(
        &self,
        _config: &SC,
        packing: TablePacking,
        traces: &Traces<Val<SC>>,
    ) -> Option<BatchTableInstance<SC>> {
        let trace =
            traces.non_primitive_trace::<OpenInputTrace<Val<SC>>>(NonPrimitiveOpType::OpenInput)?;

        let rows = trace.rows.len();
        if rows == 0 {
            return None;
        }

        let min_height = packing.min_trace_height();
        let preprocessed = OpenInputAir::<Val<SC>, 1>::trace_to_preprocessed(trace);
        let generator = Val::<SC>::GENERATOR;
        // w_binomial is unused for D=1 (no extension multiplication).
        let air = OpenInputAir::<Val<SC>, 1>::new_with_preprocessed(Val::<SC>::ZERO, preprocessed)
            .with_generator(generator)
            .with_min_height(min_height);
        let matrix = air.trace_to_matrix::<Val<SC>>(&trace.rows);
        let padded_rows = rows.next_power_of_two();

        Some(BatchTableInstance {
            op_type: NonPrimitiveOpType::OpenInput,
            air: DynamicAirEntry::new(Box::new(air)),
            trace: matrix,
            public_values: Vec::new(),
            rows: padded_rows,
        })
    }

    fn batch_instance_d2(
        &self,
        _config: &SC,
        _packing: TablePacking,
        _traces: &Traces<BinomialExtensionField<Val<SC>, 2>>,
    ) -> Option<BatchTableInstance<SC>> {
        None
    }

    fn batch_instance_d4(
        &self,
        _config: &SC,
        packing: TablePacking,
        traces: &Traces<BinomialExtensionField<Val<SC>, 4>>,
    ) -> Option<BatchTableInstance<SC>> {
        // OpenInput traces are always stored in base-field form regardless of extension degree.
        // We transmute the traces view to base-field so the downcast finds the right TypeId.
        use crate::batch_stark_prover::dynamic_air::transmute_traces;
        let base_traces: &Traces<Val<SC>> = unsafe { transmute_traces(traces) };
        let w = <Val<SC> as BinomiallyExtendable<4>>::W;
        Self::batch_instance_impl::<SC, 4>(_config, packing, base_traces, w)
    }

    fn batch_instance_d6(
        &self,
        _config: &SC,
        _packing: TablePacking,
        _traces: &Traces<BinomialExtensionField<Val<SC>, 6>>,
    ) -> Option<BatchTableInstance<SC>> {
        None
    }

    fn batch_instance_d8(
        &self,
        _config: &SC,
        _packing: TablePacking,
        _traces: &Traces<BinomialExtensionField<Val<SC>, 8>>,
    ) -> Option<BatchTableInstance<SC>> {
        None
    }

    fn batch_air_from_table_entry(
        &self,
        _config: &SC,
        degree: usize,
        _table_entry: &NonPrimitiveTableEntry<SC>,
    ) -> Result<DynamicAirEntry<SC>, String> {
        let generator = Val::<SC>::GENERATOR;
        match degree {
            1 => Ok(DynamicAirEntry::new(Box::new(
                OpenInputAir::<Val<SC>, 1>::new(Val::<SC>::ZERO).with_generator(generator),
            ))),
            4 => {
                let w = <Val<SC> as BinomiallyExtendable<4>>::W;
                Ok(DynamicAirEntry::new(Box::new(
                    OpenInputAir::<Val<SC>, 4>::new(w).with_generator(generator),
                )))
            }
            d => Err(format!("OpenInputProver: unsupported extension degree {d}")),
        }
    }

    fn air_with_committed_preprocessed(
        &self,
        committed_prep: Vec<Val<SC>>,
        min_height: usize,
    ) -> Option<DynamicAirEntry<SC>> {
        // The committed preprocessed data from `get_airs_and_degrees_with_prep` uses
        // D-scaled witness indices, while `trace_to_preprocessed` uses raw WitnessId
        // indices. We must override with the committed data so lookup tuples match
        // the D-scaled indices used by all other tables (Const, Public, ALU, Poseidon2).
        let w = <Val<SC> as BinomiallyExtendable<4>>::W;
        let generator = Val::<SC>::GENERATOR;
        let air = OpenInputAir::<Val<SC>, 4>::new_with_preprocessed(w, committed_prep)
            .with_generator(generator)
            .with_min_height(min_height);
        Some(DynamicAirEntry::new(Box::new(air)))
    }
}
