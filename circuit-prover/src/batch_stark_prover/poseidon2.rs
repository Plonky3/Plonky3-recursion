use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;
use core::borrow::Borrow;
use core::mem::transmute;

use p3_air::{Air, AirBuilder, BaseAir};
use p3_baby_bear::{BabyBear, GenericPoseidon2LinearLayersBabyBear};
#[cfg(debug_assertions)]
use p3_batch_stark::DebugConstraintBuilderWithLookups;
use p3_batch_stark::{StarkGenericConfig, Val};
use p3_circuit::op::{NonPrimitiveOpType, Poseidon2Config};
use p3_circuit::ops::{Poseidon2CircuitRow, Poseidon2Params, Poseidon2Trace};
use p3_circuit::tables::Traces;
use p3_field::extension::{BinomialExtensionField, BinomiallyExtendable};
use p3_field::{ExtensionField, Field, PrimeCharacteristicRing, PrimeField};
use p3_koala_bear::{GenericPoseidon2LinearLayersKoalaBear, KoalaBear};
use p3_lookup::folder::{ProverConstraintFolderWithLookups, VerifierConstraintFolderWithLookups};
use p3_lookup::lookup_traits::Lookup;
use p3_matrix::Matrix;
use p3_matrix::dense::RowMajorMatrix;
use p3_poseidon2_air::RoundConstants;
use p3_poseidon2_circuit_air::{
    BabyBearD4Width16, BabyBearD4Width24, KoalaBearD4Width16, KoalaBearD4Width24,
    Poseidon2CircuitAirBabyBearD4Width16, Poseidon2CircuitAirBabyBearD4Width24,
    Poseidon2CircuitAirKoalaBearD4Width16, Poseidon2CircuitAirKoalaBearD4Width24, eval_unchecked,
    extract_preprocessed_from_operations,
};
use p3_uni_stark::{
    ProverConstraintFolder, SymbolicAirBuilder, SymbolicExpression, VerifierConstraintFolder,
};

use super::dynamic_air::{BatchAir, BatchTableInstance, DynamicAirEntry, TableProver};
use crate::batch_stark_prover::{
    BABY_BEAR_MODULUS, KOALA_BEAR_MODULUS, NonPrimitiveTableEntry, TablePacking,
};
use crate::config::StarkField;

/// Wrapper for Poseidon2CircuitAir that implements BatchAir<SC>
/// We need this because `BatchAir` requires `BaseAir<Val<SC>>`.
/// but `Poseidon2CircuitAir` works over a specific field.
pub(crate) enum Poseidon2AirWrapperInner {
    BabyBearD4Width16(Box<Poseidon2CircuitAirBabyBearD4Width16>),
    BabyBearD4Width24(Box<Poseidon2CircuitAirBabyBearD4Width24>),
    KoalaBearD4Width16(Box<Poseidon2CircuitAirKoalaBearD4Width16>),
    KoalaBearD4Width24(Box<Poseidon2CircuitAirKoalaBearD4Width24>),
}

impl Poseidon2AirWrapperInner {
    fn width(&self) -> usize {
        match self {
            Self::BabyBearD4Width16(air) => air.width(),
            Self::BabyBearD4Width24(air) => air.width(),
            Self::KoalaBearD4Width16(air) => air.width(),
            Self::KoalaBearD4Width24(air) => air.width(),
        }
    }
}

impl Clone for Poseidon2AirWrapperInner {
    fn clone(&self) -> Self {
        match self {
            Self::BabyBearD4Width16(air) => Self::BabyBearD4Width16(air.clone()),
            Self::BabyBearD4Width24(air) => Self::BabyBearD4Width24(air.clone()),
            Self::KoalaBearD4Width16(air) => Self::KoalaBearD4Width16(air.clone()),
            Self::KoalaBearD4Width24(air) => Self::KoalaBearD4Width24(air.clone()),
        }
    }
}

pub(crate) struct Poseidon2AirWrapper<SC: StarkGenericConfig> {
    pub(crate) inner: Poseidon2AirWrapperInner,
    pub(crate) width: usize,
    _phantom: core::marker::PhantomData<SC>,
}

impl<SC> BatchAir<SC> for Poseidon2AirWrapper<SC>
where
    SC: StarkGenericConfig + Send + Sync,
    Val<SC>: StarkField,
    SymbolicExpression<SC::Challenge>: From<SymbolicExpression<Val<SC>>>,
{
}

impl<SC: StarkGenericConfig> Clone for Poseidon2AirWrapper<SC> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            width: self.width,
            _phantom: core::marker::PhantomData,
        }
    }
}

impl<SC> BaseAir<Val<SC>> for Poseidon2AirWrapper<SC>
where
    SC: StarkGenericConfig + Send + Sync,
    Val<SC>: StarkField,
{
    fn width(&self) -> usize {
        self.width
    }

    fn preprocessed_trace(&self) -> Option<RowMajorMatrix<Val<SC>>> {
        match &self.inner {
            Poseidon2AirWrapperInner::BabyBearD4Width16(air) => {
                assert_eq!(Val::<SC>::from_u64(BABY_BEAR_MODULUS), Val::<SC>::ZERO,);
                let preprocessed = BaseAir::<BabyBear>::preprocessed_trace(air.as_ref())?;
                Some(unsafe {
                    transmute::<RowMajorMatrix<BabyBear>, RowMajorMatrix<Val<SC>>>(preprocessed)
                })
            }
            Poseidon2AirWrapperInner::BabyBearD4Width24(air) => {
                assert_eq!(Val::<SC>::from_u64(BABY_BEAR_MODULUS), Val::<SC>::ZERO,);
                let preprocessed = BaseAir::<BabyBear>::preprocessed_trace(air.as_ref())?;
                Some(unsafe {
                    transmute::<RowMajorMatrix<BabyBear>, RowMajorMatrix<Val<SC>>>(preprocessed)
                })
            }
            Poseidon2AirWrapperInner::KoalaBearD4Width16(air) => {
                assert_eq!(Val::<SC>::from_u64(KOALA_BEAR_MODULUS), Val::<SC>::ZERO,);
                let preprocessed = BaseAir::<KoalaBear>::preprocessed_trace(air.as_ref())?;
                Some(unsafe {
                    transmute::<RowMajorMatrix<KoalaBear>, RowMajorMatrix<Val<SC>>>(preprocessed)
                })
            }
            Poseidon2AirWrapperInner::KoalaBearD4Width24(air) => {
                assert_eq!(Val::<SC>::from_u64(KOALA_BEAR_MODULUS), Val::<SC>::ZERO,);
                let preprocessed = BaseAir::<KoalaBear>::preprocessed_trace(air.as_ref())?;
                Some(unsafe {
                    transmute::<RowMajorMatrix<KoalaBear>, RowMajorMatrix<Val<SC>>>(preprocessed)
                })
            }
        }
    }
}

impl<SC> Air<SymbolicAirBuilder<Val<SC>, SC::Challenge>> for Poseidon2AirWrapper<SC>
where
    SC: StarkGenericConfig + Send + Sync,
    Val<SC>: StarkField,
{
    fn eval(&self, builder: &mut SymbolicAirBuilder<Val<SC>, SC::Challenge>) {
        match &self.inner {
            Poseidon2AirWrapperInner::BabyBearD4Width16(air) => {
                assert_eq!(Val::<SC>::from_u64(BABY_BEAR_MODULUS), Val::<SC>::ZERO,);
                unsafe {
                    let builder_bb: &mut SymbolicAirBuilder<BabyBear> =
                        core::mem::transmute(builder);
                    Air::eval(air.as_ref(), builder_bb);
                }
            }
            Poseidon2AirWrapperInner::BabyBearD4Width24(air) => {
                assert_eq!(Val::<SC>::from_u64(BABY_BEAR_MODULUS), Val::<SC>::ZERO,);
                unsafe {
                    let builder_bb: &mut SymbolicAirBuilder<BabyBear> =
                        core::mem::transmute(builder);
                    Air::eval(air.as_ref(), builder_bb);
                }
            }
            Poseidon2AirWrapperInner::KoalaBearD4Width16(air) => {
                assert_eq!(Val::<SC>::from_u64(KOALA_BEAR_MODULUS), Val::<SC>::ZERO,);
                unsafe {
                    let builder_kb: &mut SymbolicAirBuilder<KoalaBear> =
                        core::mem::transmute(builder);
                    Air::eval(air.as_ref(), builder_kb);
                }
            }
            Poseidon2AirWrapperInner::KoalaBearD4Width24(air) => {
                assert_eq!(Val::<SC>::from_u64(KOALA_BEAR_MODULUS), Val::<SC>::ZERO,);
                unsafe {
                    let builder_kb: &mut SymbolicAirBuilder<KoalaBear> =
                        core::mem::transmute(builder);
                    Air::eval(air.as_ref(), builder_kb);
                }
            }
        }
    }

    fn add_lookup_columns(&mut self) -> Vec<usize> {
        match &mut self.inner {
            Poseidon2AirWrapperInner::BabyBearD4Width16(air) => {
                let air_bb: &mut Poseidon2CircuitAirBabyBearD4Width16 = air.as_mut();
                <Poseidon2CircuitAirBabyBearD4Width16 as Air<
                    SymbolicAirBuilder<BabyBear, BinomialExtensionField<BabyBear, 4>>,
                >>::add_lookup_columns(air_bb)
            }
            Poseidon2AirWrapperInner::BabyBearD4Width24(air) => {
                let air_bb: &mut Poseidon2CircuitAirBabyBearD4Width24 = air.as_mut();
                <Poseidon2CircuitAirBabyBearD4Width24 as Air<
                    SymbolicAirBuilder<BabyBear, BinomialExtensionField<BabyBear, 4>>,
                >>::add_lookup_columns(air_bb)
            }
            Poseidon2AirWrapperInner::KoalaBearD4Width16(air) => {
                let air_kb: &mut Poseidon2CircuitAirKoalaBearD4Width16 = air.as_mut();
                <Poseidon2CircuitAirKoalaBearD4Width16 as Air<
                    SymbolicAirBuilder<KoalaBear, BinomialExtensionField<KoalaBear, 4>>,
                >>::add_lookup_columns(air_kb)
            }
            Poseidon2AirWrapperInner::KoalaBearD4Width24(air) => {
                let air_kb: &mut Poseidon2CircuitAirKoalaBearD4Width24 = air.as_mut();
                <Poseidon2CircuitAirKoalaBearD4Width24 as Air<
                    SymbolicAirBuilder<KoalaBear, BinomialExtensionField<KoalaBear, 4>>,
                >>::add_lookup_columns(air_kb)
            }
        }
    }

    #[allow(clippy::missing_transmute_annotations)]
    fn get_lookups(
        &mut self,
    ) -> Vec<Lookup<<SymbolicAirBuilder<Val<SC>, SC::Challenge> as AirBuilder>::F>> {
        match &mut self.inner {
            Poseidon2AirWrapperInner::BabyBearD4Width16(air) => unsafe {
                assert_eq!(Val::<SC>::from_u64(BABY_BEAR_MODULUS), Val::<SC>::ZERO,);
                let air_bb: &mut Poseidon2CircuitAirBabyBearD4Width16 = air.as_mut();
                let lookups_bb = <Poseidon2CircuitAirBabyBearD4Width16 as Air<
                    SymbolicAirBuilder<BabyBear, BinomialExtensionField<BabyBear, 4>>,
                >>::get_lookups(air_bb);
                core::mem::transmute(lookups_bb)
            },
            Poseidon2AirWrapperInner::BabyBearD4Width24(air) => unsafe {
                assert_eq!(Val::<SC>::from_u64(BABY_BEAR_MODULUS), Val::<SC>::ZERO,);
                let air_bb: &mut Poseidon2CircuitAirBabyBearD4Width24 = air.as_mut();
                let lookups_bb = <Poseidon2CircuitAirBabyBearD4Width24 as Air<
                    SymbolicAirBuilder<BabyBear, BinomialExtensionField<BabyBear, 4>>,
                >>::get_lookups(air_bb);
                core::mem::transmute(lookups_bb)
            },
            Poseidon2AirWrapperInner::KoalaBearD4Width16(air) => unsafe {
                assert_eq!(Val::<SC>::from_u64(KOALA_BEAR_MODULUS), Val::<SC>::ZERO,);
                let air_kb: &mut Poseidon2CircuitAirKoalaBearD4Width16 = air.as_mut();
                let lookups_kb = <Poseidon2CircuitAirKoalaBearD4Width16 as Air<
                    SymbolicAirBuilder<KoalaBear, BinomialExtensionField<KoalaBear, 4>>,
                >>::get_lookups(air_kb);
                core::mem::transmute(lookups_kb)
            },
            Poseidon2AirWrapperInner::KoalaBearD4Width24(air) => unsafe {
                assert_eq!(Val::<SC>::from_u64(KOALA_BEAR_MODULUS), Val::<SC>::ZERO,);
                let air_kb: &mut Poseidon2CircuitAirKoalaBearD4Width24 = air.as_mut();
                let lookups_kb = <Poseidon2CircuitAirKoalaBearD4Width24 as Air<
                    SymbolicAirBuilder<KoalaBear, BinomialExtensionField<KoalaBear, 4>>,
                >>::get_lookups(air_kb);
                core::mem::transmute(lookups_kb)
            },
        }
    }
}

/// Helper function to evaluate a Poseidon2 variant with a given builder.
/// This encapsulates the common pattern of transmuting slices and calling eval_unchecked.
pub(crate) unsafe fn eval_poseidon2_variant<
    SC,
    F: PrimeField,
    AB: AirBuilder,
    LinearLayers,
    const D: usize,
    const WIDTH: usize,
    const WIDTH_EXT: usize,
    const RATE_EXT: usize,
    const CAPACITY_EXT: usize,
    const SBOX_DEGREE: u64,
    const SBOX_REGISTERS: usize,
    const HALF_FULL_ROUNDS: usize,
    const PARTIAL_ROUNDS: usize,
>(
    air: &p3_poseidon2_circuit_air::Poseidon2CircuitAir<
        F,
        LinearLayers,
        D,
        WIDTH,
        WIDTH_EXT,
        RATE_EXT,
        CAPACITY_EXT,
        SBOX_DEGREE,
        SBOX_REGISTERS,
        HALF_FULL_ROUNDS,
        PARTIAL_ROUNDS,
    >,
    builder: &mut AB,
    local_slice: &[<AB as AirBuilder>::Var],
    next_slice: &[<AB as AirBuilder>::Var],
    next_preprocessed_slice: &[<AB as AirBuilder>::Var],
) where
    SC: StarkGenericConfig,
    Val<SC>: StarkField + PrimeField,
    AB::F: PrimeField,
    LinearLayers: p3_poseidon2::GenericPoseidon2LinearLayers<WIDTH>,
{
    unsafe {
        let local_slice_ptr = local_slice.as_ptr() as *const <F as p3_field::Field>::Packing;
        let local_slice_f = core::slice::from_raw_parts(local_slice_ptr, local_slice.len());
        let local_f: &p3_poseidon2_circuit_air::Poseidon2CircuitCols<
            <F as p3_field::Field>::Packing,
            p3_poseidon2_air::Poseidon2Cols<
                <F as p3_field::Field>::Packing,
                WIDTH,
                SBOX_DEGREE,
                SBOX_REGISTERS,
                HALF_FULL_ROUNDS,
                PARTIAL_ROUNDS,
            >,
        > = (*local_slice_f).borrow();

        let next_slice_ptr = next_slice.as_ptr() as *const <F as p3_field::Field>::Packing;
        let next_slice_f = core::slice::from_raw_parts(next_slice_ptr, next_slice.len());
        let next_f: &p3_poseidon2_circuit_air::Poseidon2CircuitCols<
            <F as p3_field::Field>::Packing,
            p3_poseidon2_air::Poseidon2Cols<
                <F as p3_field::Field>::Packing,
                WIDTH,
                SBOX_DEGREE,
                SBOX_REGISTERS,
                HALF_FULL_ROUNDS,
                PARTIAL_ROUNDS,
            >,
        > = (*next_slice_f).borrow();

        let next_preprocessed_ptr =
            next_preprocessed_slice.as_ptr() as *const <F as p3_field::Field>::Packing;
        let next_preprocessed_f =
            core::slice::from_raw_parts(next_preprocessed_ptr, next_preprocessed_slice.len());

        let local_var: &p3_poseidon2_circuit_air::Poseidon2CircuitCols<
            AB::Var,
            p3_poseidon2_air::Poseidon2Cols<
                AB::Var,
                WIDTH,
                SBOX_DEGREE,
                SBOX_REGISTERS,
                HALF_FULL_ROUNDS,
                PARTIAL_ROUNDS,
            >,
        > = core::mem::transmute(local_f);

        let next_var: &p3_poseidon2_circuit_air::Poseidon2CircuitCols<
            AB::Var,
            p3_poseidon2_air::Poseidon2Cols<
                AB::Var,
                WIDTH,
                SBOX_DEGREE,
                SBOX_REGISTERS,
                HALF_FULL_ROUNDS,
                PARTIAL_ROUNDS,
            >,
        > = core::mem::transmute(next_f);

        let next_preprocessed_var: &[AB::Var] = core::mem::transmute(next_preprocessed_f);

        eval_unchecked::<
            F,
            AB,
            LinearLayers,
            D,
            WIDTH,
            WIDTH_EXT,
            RATE_EXT,
            CAPACITY_EXT,
            SBOX_DEGREE,
            SBOX_REGISTERS,
            HALF_FULL_ROUNDS,
            PARTIAL_ROUNDS,
        >(air, builder, local_var, next_var, next_preprocessed_var);
    }
}

impl<'a, SC> Air<ProverConstraintFolder<'a, SC>> for Poseidon2AirWrapper<SC>
where
    SC: StarkGenericConfig + Send + Sync,
    Val<SC>: StarkField + PrimeField,
{
    fn eval(&self, builder: &mut ProverConstraintFolder<'a, SC>) {
        let main = builder.main();
        let local_slice = main.row_slice(0).expect("The matrix is empty?");
        let next_slice = main.row_slice(1).expect("The matrix has only one row?");
        let preprocessed = builder
            .preprocessed()
            .expect("Expected preprocessed columns");
        let next_preprocessed_slice = preprocessed
            .row_slice(1)
            .expect("The preprocessed matrix has only one row?");

        match &self.inner {
            Poseidon2AirWrapperInner::BabyBearD4Width16(air) => unsafe {
                eval_poseidon2_variant::<
                    SC,
                    BabyBear,
                    ProverConstraintFolder<'a, SC>,
                    p3_baby_bear::GenericPoseidon2LinearLayersBabyBear,
                    { BabyBearD4Width16::D },
                    { BabyBearD4Width16::WIDTH },
                    { BabyBearD4Width16::WIDTH_EXT },
                    { BabyBearD4Width16::RATE_EXT },
                    { BabyBearD4Width16::CAPACITY_EXT },
                    { BabyBearD4Width16::SBOX_DEGREE },
                    { BabyBearD4Width16::SBOX_REGISTERS },
                    { BabyBearD4Width16::HALF_FULL_ROUNDS },
                    { BabyBearD4Width16::PARTIAL_ROUNDS },
                >(
                    air.as_ref(),
                    builder,
                    &local_slice,
                    &next_slice,
                    &next_preprocessed_slice,
                );
            },
            Poseidon2AirWrapperInner::BabyBearD4Width24(air) => unsafe {
                eval_poseidon2_variant::<
                    SC,
                    BabyBear,
                    ProverConstraintFolder<'a, SC>,
                    p3_baby_bear::GenericPoseidon2LinearLayersBabyBear,
                    { BabyBearD4Width24::D },
                    { BabyBearD4Width24::WIDTH },
                    { BabyBearD4Width24::WIDTH_EXT },
                    { BabyBearD4Width24::RATE_EXT },
                    { BabyBearD4Width24::CAPACITY_EXT },
                    { BabyBearD4Width24::SBOX_DEGREE },
                    { BabyBearD4Width24::SBOX_REGISTERS },
                    { BabyBearD4Width24::HALF_FULL_ROUNDS },
                    { BabyBearD4Width24::PARTIAL_ROUNDS },
                >(
                    air.as_ref(),
                    builder,
                    &local_slice,
                    &next_slice,
                    &next_preprocessed_slice,
                );
            },
            Poseidon2AirWrapperInner::KoalaBearD4Width16(air) => unsafe {
                eval_poseidon2_variant::<
                    SC,
                    KoalaBear,
                    ProverConstraintFolder<'a, SC>,
                    p3_koala_bear::GenericPoseidon2LinearLayersKoalaBear,
                    { KoalaBearD4Width16::D },
                    { KoalaBearD4Width16::WIDTH },
                    { KoalaBearD4Width16::WIDTH_EXT },
                    { KoalaBearD4Width16::RATE_EXT },
                    { KoalaBearD4Width16::CAPACITY_EXT },
                    { KoalaBearD4Width16::SBOX_DEGREE },
                    { KoalaBearD4Width16::SBOX_REGISTERS },
                    { KoalaBearD4Width16::HALF_FULL_ROUNDS },
                    { KoalaBearD4Width16::PARTIAL_ROUNDS },
                >(
                    air.as_ref(),
                    builder,
                    &local_slice,
                    &next_slice,
                    &next_preprocessed_slice,
                );
            },
            Poseidon2AirWrapperInner::KoalaBearD4Width24(air) => unsafe {
                eval_poseidon2_variant::<
                    SC,
                    KoalaBear,
                    ProverConstraintFolder<'a, SC>,
                    p3_koala_bear::GenericPoseidon2LinearLayersKoalaBear,
                    { KoalaBearD4Width24::D },
                    { KoalaBearD4Width24::WIDTH },
                    { KoalaBearD4Width24::WIDTH_EXT },
                    { KoalaBearD4Width24::RATE_EXT },
                    { KoalaBearD4Width24::CAPACITY_EXT },
                    { KoalaBearD4Width24::SBOX_DEGREE },
                    { KoalaBearD4Width24::SBOX_REGISTERS },
                    { KoalaBearD4Width24::HALF_FULL_ROUNDS },
                    { KoalaBearD4Width24::PARTIAL_ROUNDS },
                >(
                    air.as_ref(),
                    builder,
                    &local_slice,
                    &next_slice,
                    &next_preprocessed_slice,
                );
            },
        }
    }

    fn add_lookup_columns(&mut self) -> Vec<usize> {
        match &mut self.inner {
            Poseidon2AirWrapperInner::BabyBearD4Width16(air) => {
                let air_bb: &mut Poseidon2CircuitAirBabyBearD4Width16 = air.as_mut();
                <Poseidon2CircuitAirBabyBearD4Width16 as Air<
                    SymbolicAirBuilder<BabyBear, BinomialExtensionField<BabyBear, 4>>,
                >>::add_lookup_columns(air_bb)
            }
            Poseidon2AirWrapperInner::BabyBearD4Width24(air) => {
                let air_bb: &mut Poseidon2CircuitAirBabyBearD4Width24 = air.as_mut();
                <Poseidon2CircuitAirBabyBearD4Width24 as Air<
                    SymbolicAirBuilder<BabyBear, BinomialExtensionField<BabyBear, 4>>,
                >>::add_lookup_columns(air_bb)
            }
            Poseidon2AirWrapperInner::KoalaBearD4Width16(air) => {
                let air_kb: &mut Poseidon2CircuitAirKoalaBearD4Width16 = air.as_mut();
                <Poseidon2CircuitAirKoalaBearD4Width16 as Air<
                    SymbolicAirBuilder<KoalaBear, BinomialExtensionField<KoalaBear, 4>>,
                >>::add_lookup_columns(air_kb)
            }
            Poseidon2AirWrapperInner::KoalaBearD4Width24(air) => {
                let air_kb: &mut Poseidon2CircuitAirKoalaBearD4Width24 = air.as_mut();
                <Poseidon2CircuitAirKoalaBearD4Width24 as Air<
                    SymbolicAirBuilder<KoalaBear, BinomialExtensionField<KoalaBear, 4>>,
                >>::add_lookup_columns(air_kb)
            }
        }
    }

    #[allow(clippy::missing_transmute_annotations)]
    fn get_lookups(&mut self) -> Vec<Lookup<<ProverConstraintFolder<'a, SC> as AirBuilder>::F>> {
        match &mut self.inner {
            Poseidon2AirWrapperInner::BabyBearD4Width16(air) => unsafe {
                assert_eq!(Val::<SC>::from_u64(BABY_BEAR_MODULUS), Val::<SC>::ZERO,);
                let air_bb: &mut Poseidon2CircuitAirBabyBearD4Width16 = air.as_mut();
                let lookups_bb = <Poseidon2CircuitAirBabyBearD4Width16 as Air<
                    SymbolicAirBuilder<BabyBear, BinomialExtensionField<BabyBear, 4>>,
                >>::get_lookups(air_bb);
                core::mem::transmute(lookups_bb)
            },
            Poseidon2AirWrapperInner::BabyBearD4Width24(air) => unsafe {
                assert_eq!(Val::<SC>::from_u64(BABY_BEAR_MODULUS), Val::<SC>::ZERO,);
                let air_bb: &mut Poseidon2CircuitAirBabyBearD4Width24 = air.as_mut();
                let lookups_bb = <Poseidon2CircuitAirBabyBearD4Width24 as Air<
                    SymbolicAirBuilder<BabyBear, BinomialExtensionField<BabyBear, 4>>,
                >>::get_lookups(air_bb);
                core::mem::transmute(lookups_bb)
            },
            Poseidon2AirWrapperInner::KoalaBearD4Width16(air) => unsafe {
                assert_eq!(Val::<SC>::from_u64(KOALA_BEAR_MODULUS), Val::<SC>::ZERO,);
                let air_kb: &mut Poseidon2CircuitAirKoalaBearD4Width16 = air.as_mut();
                let lookups_kb = <Poseidon2CircuitAirKoalaBearD4Width16 as Air<
                    SymbolicAirBuilder<KoalaBear, BinomialExtensionField<KoalaBear, 4>>,
                >>::get_lookups(air_kb);
                core::mem::transmute(lookups_kb)
            },
            Poseidon2AirWrapperInner::KoalaBearD4Width24(air) => unsafe {
                assert_eq!(Val::<SC>::from_u64(KOALA_BEAR_MODULUS), Val::<SC>::ZERO,);
                let air_kb: &mut Poseidon2CircuitAirKoalaBearD4Width24 = air.as_mut();
                let lookups_kb = <Poseidon2CircuitAirKoalaBearD4Width24 as Air<
                    SymbolicAirBuilder<KoalaBear, BinomialExtensionField<KoalaBear, 4>>,
                >>::get_lookups(air_kb);
                core::mem::transmute(lookups_kb)
            },
        }
    }
}

impl<'a, SC> Air<ProverConstraintFolderWithLookups<'a, SC>> for Poseidon2AirWrapper<SC>
where
    SC: StarkGenericConfig + Send + Sync,
    Val<SC>: StarkField + PrimeField,
{
    fn eval(&self, builder: &mut ProverConstraintFolderWithLookups<'a, SC>) {
        let main = builder.main();
        let local_slice = main.row_slice(0).expect("The matrix is empty?");
        let next_slice = main.row_slice(1).expect("The matrix has only one row?");
        let preprocessed = builder
            .preprocessed()
            .expect("Expected preprocessed columns");
        let next_preprocessed_slice = preprocessed
            .row_slice(1)
            .expect("The preprocessed matrix has only one row?");

        match &self.inner {
            Poseidon2AirWrapperInner::BabyBearD4Width16(air) => unsafe {
                eval_poseidon2_variant::<
                    SC,
                    BabyBear,
                    ProverConstraintFolderWithLookups<'a, SC>,
                    p3_baby_bear::GenericPoseidon2LinearLayersBabyBear,
                    { BabyBearD4Width16::D },
                    { BabyBearD4Width16::WIDTH },
                    { BabyBearD4Width16::WIDTH_EXT },
                    { BabyBearD4Width16::RATE_EXT },
                    { BabyBearD4Width16::CAPACITY_EXT },
                    { BabyBearD4Width16::SBOX_DEGREE },
                    { BabyBearD4Width16::SBOX_REGISTERS },
                    { BabyBearD4Width16::HALF_FULL_ROUNDS },
                    { BabyBearD4Width16::PARTIAL_ROUNDS },
                >(
                    air.as_ref(),
                    builder,
                    &local_slice,
                    &next_slice,
                    &next_preprocessed_slice,
                );
            },
            Poseidon2AirWrapperInner::BabyBearD4Width24(air) => unsafe {
                eval_poseidon2_variant::<
                    SC,
                    BabyBear,
                    ProverConstraintFolderWithLookups<'a, SC>,
                    p3_baby_bear::GenericPoseidon2LinearLayersBabyBear,
                    { BabyBearD4Width24::D },
                    { BabyBearD4Width24::WIDTH },
                    { BabyBearD4Width24::WIDTH_EXT },
                    { BabyBearD4Width24::RATE_EXT },
                    { BabyBearD4Width24::CAPACITY_EXT },
                    { BabyBearD4Width24::SBOX_DEGREE },
                    { BabyBearD4Width24::SBOX_REGISTERS },
                    { BabyBearD4Width24::HALF_FULL_ROUNDS },
                    { BabyBearD4Width24::PARTIAL_ROUNDS },
                >(
                    air.as_ref(),
                    builder,
                    &local_slice,
                    &next_slice,
                    &next_preprocessed_slice,
                );
            },
            Poseidon2AirWrapperInner::KoalaBearD4Width16(air) => unsafe {
                eval_poseidon2_variant::<
                    SC,
                    KoalaBear,
                    ProverConstraintFolderWithLookups<'a, SC>,
                    p3_koala_bear::GenericPoseidon2LinearLayersKoalaBear,
                    { KoalaBearD4Width16::D },
                    { KoalaBearD4Width16::WIDTH },
                    { KoalaBearD4Width16::WIDTH_EXT },
                    { KoalaBearD4Width16::RATE_EXT },
                    { KoalaBearD4Width16::CAPACITY_EXT },
                    { KoalaBearD4Width16::SBOX_DEGREE },
                    { KoalaBearD4Width16::SBOX_REGISTERS },
                    { KoalaBearD4Width16::HALF_FULL_ROUNDS },
                    { KoalaBearD4Width16::PARTIAL_ROUNDS },
                >(
                    air.as_ref(),
                    builder,
                    &local_slice,
                    &next_slice,
                    &next_preprocessed_slice,
                );
            },
            Poseidon2AirWrapperInner::KoalaBearD4Width24(air) => unsafe {
                eval_poseidon2_variant::<
                    SC,
                    KoalaBear,
                    ProverConstraintFolderWithLookups<'a, SC>,
                    p3_koala_bear::GenericPoseidon2LinearLayersKoalaBear,
                    { KoalaBearD4Width24::D },
                    { KoalaBearD4Width24::WIDTH },
                    { KoalaBearD4Width24::WIDTH_EXT },
                    { KoalaBearD4Width24::RATE_EXT },
                    { KoalaBearD4Width24::CAPACITY_EXT },
                    { KoalaBearD4Width24::SBOX_DEGREE },
                    { KoalaBearD4Width24::SBOX_REGISTERS },
                    { KoalaBearD4Width24::HALF_FULL_ROUNDS },
                    { KoalaBearD4Width24::PARTIAL_ROUNDS },
                >(
                    air.as_ref(),
                    builder,
                    &local_slice,
                    &next_slice,
                    &next_preprocessed_slice,
                );
            },
        }
    }

    fn add_lookup_columns(&mut self) -> Vec<usize> {
        match &mut self.inner {
            Poseidon2AirWrapperInner::BabyBearD4Width16(air) => {
                let air_bb: &mut Poseidon2CircuitAirBabyBearD4Width16 = air.as_mut();
                <Poseidon2CircuitAirBabyBearD4Width16 as Air<
                    SymbolicAirBuilder<BabyBear, BinomialExtensionField<BabyBear, 4>>,
                >>::add_lookup_columns(air_bb)
            }
            Poseidon2AirWrapperInner::BabyBearD4Width24(air) => {
                let air_bb: &mut Poseidon2CircuitAirBabyBearD4Width24 = air.as_mut();
                <Poseidon2CircuitAirBabyBearD4Width24 as Air<
                    SymbolicAirBuilder<BabyBear, BinomialExtensionField<BabyBear, 4>>,
                >>::add_lookup_columns(air_bb)
            }
            Poseidon2AirWrapperInner::KoalaBearD4Width16(air) => {
                let air_kb: &mut Poseidon2CircuitAirKoalaBearD4Width16 = air.as_mut();
                <Poseidon2CircuitAirKoalaBearD4Width16 as Air<
                    SymbolicAirBuilder<KoalaBear, BinomialExtensionField<KoalaBear, 4>>,
                >>::add_lookup_columns(air_kb)
            }
            Poseidon2AirWrapperInner::KoalaBearD4Width24(air) => {
                let air_kb: &mut Poseidon2CircuitAirKoalaBearD4Width24 = air.as_mut();
                <Poseidon2CircuitAirKoalaBearD4Width24 as Air<
                    SymbolicAirBuilder<KoalaBear, BinomialExtensionField<KoalaBear, 4>>,
                >>::add_lookup_columns(air_kb)
            }
        }
    }

    #[allow(clippy::missing_transmute_annotations)]
    fn get_lookups(
        &mut self,
    ) -> Vec<Lookup<<ProverConstraintFolderWithLookups<'a, SC> as AirBuilder>::F>> {
        match &mut self.inner {
            Poseidon2AirWrapperInner::BabyBearD4Width16(air) => unsafe {
                assert_eq!(Val::<SC>::from_u64(BABY_BEAR_MODULUS), Val::<SC>::ZERO,);
                let air_bb: &mut Poseidon2CircuitAirBabyBearD4Width16 = air.as_mut();
                let lookups_bb = <Poseidon2CircuitAirBabyBearD4Width16 as Air<
                    SymbolicAirBuilder<BabyBear, BinomialExtensionField<BabyBear, 4>>,
                >>::get_lookups(air_bb);
                core::mem::transmute(lookups_bb)
            },
            Poseidon2AirWrapperInner::BabyBearD4Width24(air) => unsafe {
                assert_eq!(Val::<SC>::from_u64(BABY_BEAR_MODULUS), Val::<SC>::ZERO,);
                let air_bb: &mut Poseidon2CircuitAirBabyBearD4Width24 = air.as_mut();
                let lookups_bb = <Poseidon2CircuitAirBabyBearD4Width24 as Air<
                    SymbolicAirBuilder<BabyBear, BinomialExtensionField<BabyBear, 4>>,
                >>::get_lookups(air_bb);
                core::mem::transmute(lookups_bb)
            },
            Poseidon2AirWrapperInner::KoalaBearD4Width16(air) => unsafe {
                assert_eq!(Val::<SC>::from_u64(KOALA_BEAR_MODULUS), Val::<SC>::ZERO,);
                let air_kb: &mut Poseidon2CircuitAirKoalaBearD4Width16 = air.as_mut();
                let lookups_kb = <Poseidon2CircuitAirKoalaBearD4Width16 as Air<
                    SymbolicAirBuilder<KoalaBear, BinomialExtensionField<KoalaBear, 4>>,
                >>::get_lookups(air_kb);
                core::mem::transmute(lookups_kb)
            },
            Poseidon2AirWrapperInner::KoalaBearD4Width24(air) => unsafe {
                assert_eq!(Val::<SC>::from_u64(KOALA_BEAR_MODULUS), Val::<SC>::ZERO,);
                let air_kb: &mut Poseidon2CircuitAirKoalaBearD4Width24 = air.as_mut();
                let lookups_kb = <Poseidon2CircuitAirKoalaBearD4Width24 as Air<
                    SymbolicAirBuilder<KoalaBear, BinomialExtensionField<KoalaBear, 4>>,
                >>::get_lookups(air_kb);
                core::mem::transmute(lookups_kb)
            },
        }
    }
}

impl<'a, SC> Air<VerifierConstraintFolder<'a, SC>> for Poseidon2AirWrapper<SC>
where
    SC: StarkGenericConfig + Send + Sync,
    Val<SC>: StarkField + PrimeField,
{
    fn eval(&self, builder: &mut VerifierConstraintFolder<'a, SC>) {
        let main = builder.main();
        let local_slice = main.row_slice(0).expect("The matrix is empty?");
        let next_slice = main.row_slice(1).expect("The matrix has only one row?");
        let preprocessed = builder
            .preprocessed()
            .expect("Expected preprocessed columns");
        let next_preprocessed_slice = preprocessed
            .row_slice(1)
            .expect("The preprocessed matrix has only one row?");

        match &self.inner {
            Poseidon2AirWrapperInner::BabyBearD4Width16(air) => unsafe {
                eval_poseidon2_variant::<
                    SC,
                    BabyBear,
                    VerifierConstraintFolder<'a, SC>,
                    GenericPoseidon2LinearLayersBabyBear,
                    { BabyBearD4Width16::D },
                    { BabyBearD4Width16::WIDTH },
                    { BabyBearD4Width16::WIDTH_EXT },
                    { BabyBearD4Width16::RATE_EXT },
                    { BabyBearD4Width16::CAPACITY_EXT },
                    { BabyBearD4Width16::SBOX_DEGREE },
                    { BabyBearD4Width16::SBOX_REGISTERS },
                    { BabyBearD4Width16::HALF_FULL_ROUNDS },
                    { BabyBearD4Width16::PARTIAL_ROUNDS },
                >(
                    air.as_ref(),
                    builder,
                    &local_slice,
                    &next_slice,
                    &next_preprocessed_slice,
                );
            },
            Poseidon2AirWrapperInner::BabyBearD4Width24(air) => unsafe {
                eval_poseidon2_variant::<
                    SC,
                    BabyBear,
                    VerifierConstraintFolder<'a, SC>,
                    GenericPoseidon2LinearLayersBabyBear,
                    { BabyBearD4Width24::D },
                    { BabyBearD4Width24::WIDTH },
                    { BabyBearD4Width24::WIDTH_EXT },
                    { BabyBearD4Width24::RATE_EXT },
                    { BabyBearD4Width24::CAPACITY_EXT },
                    { BabyBearD4Width24::SBOX_DEGREE },
                    { BabyBearD4Width24::SBOX_REGISTERS },
                    { BabyBearD4Width24::HALF_FULL_ROUNDS },
                    { BabyBearD4Width24::PARTIAL_ROUNDS },
                >(
                    air.as_ref(),
                    builder,
                    &local_slice,
                    &next_slice,
                    &next_preprocessed_slice,
                );
            },
            Poseidon2AirWrapperInner::KoalaBearD4Width16(air) => unsafe {
                eval_poseidon2_variant::<
                    SC,
                    KoalaBear,
                    VerifierConstraintFolder<'a, SC>,
                    GenericPoseidon2LinearLayersKoalaBear,
                    { KoalaBearD4Width16::D },
                    { KoalaBearD4Width16::WIDTH },
                    { KoalaBearD4Width16::WIDTH_EXT },
                    { KoalaBearD4Width16::RATE_EXT },
                    { KoalaBearD4Width16::CAPACITY_EXT },
                    { KoalaBearD4Width16::SBOX_DEGREE },
                    { KoalaBearD4Width16::SBOX_REGISTERS },
                    { KoalaBearD4Width16::HALF_FULL_ROUNDS },
                    { KoalaBearD4Width16::PARTIAL_ROUNDS },
                >(
                    air.as_ref(),
                    builder,
                    &local_slice,
                    &next_slice,
                    &next_preprocessed_slice,
                );
            },
            Poseidon2AirWrapperInner::KoalaBearD4Width24(air) => unsafe {
                eval_poseidon2_variant::<
                    SC,
                    KoalaBear,
                    VerifierConstraintFolder<'a, SC>,
                    GenericPoseidon2LinearLayersKoalaBear,
                    { KoalaBearD4Width24::D },
                    { KoalaBearD4Width24::WIDTH },
                    { KoalaBearD4Width24::WIDTH_EXT },
                    { KoalaBearD4Width24::RATE_EXT },
                    { KoalaBearD4Width24::CAPACITY_EXT },
                    { KoalaBearD4Width24::SBOX_DEGREE },
                    { KoalaBearD4Width24::SBOX_REGISTERS },
                    { KoalaBearD4Width24::HALF_FULL_ROUNDS },
                    { KoalaBearD4Width24::PARTIAL_ROUNDS },
                >(
                    air.as_ref(),
                    builder,
                    &local_slice,
                    &next_slice,
                    &next_preprocessed_slice,
                );
            },
        }
    }
}

impl<'a, SC> Air<VerifierConstraintFolderWithLookups<'a, SC>> for Poseidon2AirWrapper<SC>
where
    SC: StarkGenericConfig + Send + Sync,
    Val<SC>: StarkField + PrimeField,
{
    fn eval(&self, builder: &mut VerifierConstraintFolderWithLookups<'a, SC>) {
        let main = builder.main();
        let local_slice = main.row_slice(0).expect("The matrix is empty?");
        let next_slice = main.row_slice(1).expect("The matrix has only one row?");
        let preprocessed = builder
            .preprocessed()
            .expect("Expected preprocessed columns");
        let next_preprocessed_slice = preprocessed
            .row_slice(1)
            .expect("The preprocessed matrix has only one row?");

        match &self.inner {
            Poseidon2AirWrapperInner::BabyBearD4Width16(air) => unsafe {
                eval_poseidon2_variant::<
                    SC,
                    BabyBear,
                    VerifierConstraintFolderWithLookups<'a, SC>,
                    p3_baby_bear::GenericPoseidon2LinearLayersBabyBear,
                    { BabyBearD4Width16::D },
                    { BabyBearD4Width16::WIDTH },
                    { BabyBearD4Width16::WIDTH_EXT },
                    { BabyBearD4Width16::RATE_EXT },
                    { BabyBearD4Width16::CAPACITY_EXT },
                    { BabyBearD4Width16::SBOX_DEGREE },
                    { BabyBearD4Width16::SBOX_REGISTERS },
                    { BabyBearD4Width16::HALF_FULL_ROUNDS },
                    { BabyBearD4Width16::PARTIAL_ROUNDS },
                >(
                    air.as_ref(),
                    builder,
                    &local_slice,
                    &next_slice,
                    &next_preprocessed_slice,
                );
            },
            Poseidon2AirWrapperInner::BabyBearD4Width24(air) => unsafe {
                eval_poseidon2_variant::<
                    SC,
                    BabyBear,
                    VerifierConstraintFolderWithLookups<'a, SC>,
                    p3_baby_bear::GenericPoseidon2LinearLayersBabyBear,
                    { BabyBearD4Width24::D },
                    { BabyBearD4Width24::WIDTH },
                    { BabyBearD4Width24::WIDTH_EXT },
                    { BabyBearD4Width24::RATE_EXT },
                    { BabyBearD4Width24::CAPACITY_EXT },
                    { BabyBearD4Width24::SBOX_DEGREE },
                    { BabyBearD4Width24::SBOX_REGISTERS },
                    { BabyBearD4Width24::HALF_FULL_ROUNDS },
                    { BabyBearD4Width24::PARTIAL_ROUNDS },
                >(
                    air.as_ref(),
                    builder,
                    &local_slice,
                    &next_slice,
                    &next_preprocessed_slice,
                );
            },
            Poseidon2AirWrapperInner::KoalaBearD4Width16(air) => unsafe {
                eval_poseidon2_variant::<
                    SC,
                    KoalaBear,
                    VerifierConstraintFolderWithLookups<'a, SC>,
                    p3_koala_bear::GenericPoseidon2LinearLayersKoalaBear,
                    { KoalaBearD4Width16::D },
                    { KoalaBearD4Width16::WIDTH },
                    { KoalaBearD4Width16::WIDTH_EXT },
                    { KoalaBearD4Width16::RATE_EXT },
                    { KoalaBearD4Width16::CAPACITY_EXT },
                    { KoalaBearD4Width16::SBOX_DEGREE },
                    { KoalaBearD4Width16::SBOX_REGISTERS },
                    { KoalaBearD4Width16::HALF_FULL_ROUNDS },
                    { KoalaBearD4Width16::PARTIAL_ROUNDS },
                >(
                    air.as_ref(),
                    builder,
                    &local_slice,
                    &next_slice,
                    &next_preprocessed_slice,
                );
            },
            Poseidon2AirWrapperInner::KoalaBearD4Width24(air) => unsafe {
                eval_poseidon2_variant::<
                    SC,
                    KoalaBear,
                    VerifierConstraintFolderWithLookups<'a, SC>,
                    p3_koala_bear::GenericPoseidon2LinearLayersKoalaBear,
                    { KoalaBearD4Width24::D },
                    { KoalaBearD4Width24::WIDTH },
                    { KoalaBearD4Width24::WIDTH_EXT },
                    { KoalaBearD4Width24::RATE_EXT },
                    { KoalaBearD4Width24::CAPACITY_EXT },
                    { KoalaBearD4Width24::SBOX_DEGREE },
                    { KoalaBearD4Width24::SBOX_REGISTERS },
                    { KoalaBearD4Width24::HALF_FULL_ROUNDS },
                    { KoalaBearD4Width24::PARTIAL_ROUNDS },
                >(
                    air.as_ref(),
                    builder,
                    &local_slice,
                    &next_slice,
                    &next_preprocessed_slice,
                );
            },
        }
    }

    fn add_lookup_columns(&mut self) -> Vec<usize> {
        match &mut self.inner {
            Poseidon2AirWrapperInner::BabyBearD4Width16(air) => {
                let air_bb: &mut Poseidon2CircuitAirBabyBearD4Width16 = air.as_mut();
                <Poseidon2CircuitAirBabyBearD4Width16 as Air<
                    SymbolicAirBuilder<BabyBear, BinomialExtensionField<BabyBear, 4>>,
                >>::add_lookup_columns(air_bb)
            }
            Poseidon2AirWrapperInner::BabyBearD4Width24(air) => {
                let air_bb: &mut Poseidon2CircuitAirBabyBearD4Width24 = air.as_mut();
                <Poseidon2CircuitAirBabyBearD4Width24 as Air<
                    SymbolicAirBuilder<BabyBear, BinomialExtensionField<BabyBear, 4>>,
                >>::add_lookup_columns(air_bb)
            }
            Poseidon2AirWrapperInner::KoalaBearD4Width16(air) => {
                let air_kb: &mut Poseidon2CircuitAirKoalaBearD4Width16 = air.as_mut();
                <Poseidon2CircuitAirKoalaBearD4Width16 as Air<
                    SymbolicAirBuilder<KoalaBear, BinomialExtensionField<KoalaBear, 4>>,
                >>::add_lookup_columns(air_kb)
            }
            Poseidon2AirWrapperInner::KoalaBearD4Width24(air) => {
                let air_kb: &mut Poseidon2CircuitAirKoalaBearD4Width24 = air.as_mut();
                <Poseidon2CircuitAirKoalaBearD4Width24 as Air<
                    SymbolicAirBuilder<KoalaBear, BinomialExtensionField<KoalaBear, 4>>,
                >>::add_lookup_columns(air_kb)
            }
        }
    }

    #[allow(clippy::missing_transmute_annotations)]
    fn get_lookups(
        &mut self,
    ) -> Vec<Lookup<<VerifierConstraintFolderWithLookups<'a, SC> as AirBuilder>::F>> {
        match &mut self.inner {
            Poseidon2AirWrapperInner::BabyBearD4Width16(air) => unsafe {
                assert_eq!(Val::<SC>::from_u64(BABY_BEAR_MODULUS), Val::<SC>::ZERO,);
                let air_bb: &mut Poseidon2CircuitAirBabyBearD4Width16 = air.as_mut();
                let lookups_bb = <Poseidon2CircuitAirBabyBearD4Width16 as Air<
                    SymbolicAirBuilder<BabyBear, BinomialExtensionField<BabyBear, 4>>,
                >>::get_lookups(air_bb);
                core::mem::transmute(lookups_bb)
            },
            Poseidon2AirWrapperInner::BabyBearD4Width24(air) => unsafe {
                assert_eq!(Val::<SC>::from_u64(BABY_BEAR_MODULUS), Val::<SC>::ZERO,);
                let air_bb: &mut Poseidon2CircuitAirBabyBearD4Width24 = air.as_mut();
                let lookups_bb = <Poseidon2CircuitAirBabyBearD4Width24 as Air<
                    SymbolicAirBuilder<BabyBear, BinomialExtensionField<BabyBear, 4>>,
                >>::get_lookups(air_bb);
                core::mem::transmute(lookups_bb)
            },
            Poseidon2AirWrapperInner::KoalaBearD4Width16(air) => unsafe {
                assert_eq!(Val::<SC>::from_u64(KOALA_BEAR_MODULUS), Val::<SC>::ZERO,);
                let air_kb: &mut Poseidon2CircuitAirKoalaBearD4Width16 = air.as_mut();
                let lookups_kb = <Poseidon2CircuitAirKoalaBearD4Width16 as Air<
                    SymbolicAirBuilder<KoalaBear, BinomialExtensionField<KoalaBear, 4>>,
                >>::get_lookups(air_kb);
                core::mem::transmute(lookups_kb)
            },
            Poseidon2AirWrapperInner::KoalaBearD4Width24(air) => unsafe {
                assert_eq!(Val::<SC>::from_u64(KOALA_BEAR_MODULUS), Val::<SC>::ZERO,);
                let air_kb: &mut Poseidon2CircuitAirKoalaBearD4Width24 = air.as_mut();
                let lookups_kb = <Poseidon2CircuitAirKoalaBearD4Width24 as Air<
                    SymbolicAirBuilder<KoalaBear, BinomialExtensionField<KoalaBear, 4>>,
                >>::get_lookups(air_kb);
                core::mem::transmute(lookups_kb)
            },
        }
    }
}

#[cfg(debug_assertions)]
impl<'a, SC> Air<DebugConstraintBuilderWithLookups<'a, Val<SC>, SC::Challenge>>
    for Poseidon2AirWrapper<SC>
where
    SC: StarkGenericConfig + Send + Sync,
    Val<SC>: StarkField + PrimeField,
{
    fn eval(&self, builder: &mut DebugConstraintBuilderWithLookups<'a, Val<SC>, SC::Challenge>) {
        let main = builder.main();
        let local_slice = main.row_slice(0).expect("The matrix is empty?");
        let next_slice = main.row_slice(1).expect("The matrix has only one row?");
        let preprocessed = builder
            .preprocessed()
            .expect("Expected preprocessed columns");
        let next_preprocessed_slice = preprocessed
            .row_slice(1)
            .expect("The preprocessed matrix has only one row?");

        match &self.inner {
            Poseidon2AirWrapperInner::BabyBearD4Width16(air) => unsafe {
                eval_poseidon2_variant::<
                    SC,
                    BabyBear,
                    DebugConstraintBuilderWithLookups<'a, Val<SC>, SC::Challenge>,
                    GenericPoseidon2LinearLayersBabyBear,
                    { BabyBearD4Width16::D },
                    { BabyBearD4Width16::WIDTH },
                    { BabyBearD4Width16::WIDTH_EXT },
                    { BabyBearD4Width16::RATE_EXT },
                    { BabyBearD4Width16::CAPACITY_EXT },
                    { BabyBearD4Width16::SBOX_DEGREE },
                    { BabyBearD4Width16::SBOX_REGISTERS },
                    { BabyBearD4Width16::HALF_FULL_ROUNDS },
                    { BabyBearD4Width16::PARTIAL_ROUNDS },
                >(
                    air.as_ref(),
                    builder,
                    &local_slice,
                    &next_slice,
                    &next_preprocessed_slice,
                );
            },
            Poseidon2AirWrapperInner::BabyBearD4Width24(air) => unsafe {
                eval_poseidon2_variant::<
                    SC,
                    BabyBear,
                    DebugConstraintBuilderWithLookups<'a, Val<SC>, SC::Challenge>,
                    GenericPoseidon2LinearLayersBabyBear,
                    { BabyBearD4Width24::D },
                    { BabyBearD4Width24::WIDTH },
                    { BabyBearD4Width24::WIDTH_EXT },
                    { BabyBearD4Width24::RATE_EXT },
                    { BabyBearD4Width24::CAPACITY_EXT },
                    { BabyBearD4Width24::SBOX_DEGREE },
                    { BabyBearD4Width24::SBOX_REGISTERS },
                    { BabyBearD4Width24::HALF_FULL_ROUNDS },
                    { BabyBearD4Width24::PARTIAL_ROUNDS },
                >(
                    air.as_ref(),
                    builder,
                    &local_slice,
                    &next_slice,
                    &next_preprocessed_slice,
                );
            },
            Poseidon2AirWrapperInner::KoalaBearD4Width16(air) => unsafe {
                eval_poseidon2_variant::<
                    SC,
                    KoalaBear,
                    DebugConstraintBuilderWithLookups<'a, Val<SC>, SC::Challenge>,
                    GenericPoseidon2LinearLayersKoalaBear,
                    { KoalaBearD4Width16::D },
                    { KoalaBearD4Width16::WIDTH },
                    { KoalaBearD4Width16::WIDTH_EXT },
                    { KoalaBearD4Width16::RATE_EXT },
                    { KoalaBearD4Width16::CAPACITY_EXT },
                    { KoalaBearD4Width16::SBOX_DEGREE },
                    { KoalaBearD4Width16::SBOX_REGISTERS },
                    { KoalaBearD4Width16::HALF_FULL_ROUNDS },
                    { KoalaBearD4Width16::PARTIAL_ROUNDS },
                >(
                    air.as_ref(),
                    builder,
                    &local_slice,
                    &next_slice,
                    &next_preprocessed_slice,
                );
            },
            Poseidon2AirWrapperInner::KoalaBearD4Width24(air) => unsafe {
                eval_poseidon2_variant::<
                    SC,
                    KoalaBear,
                    DebugConstraintBuilderWithLookups<'a, Val<SC>, SC::Challenge>,
                    GenericPoseidon2LinearLayersKoalaBear,
                    { KoalaBearD4Width24::D },
                    { KoalaBearD4Width24::WIDTH },
                    { KoalaBearD4Width24::WIDTH_EXT },
                    { KoalaBearD4Width24::RATE_EXT },
                    { KoalaBearD4Width24::CAPACITY_EXT },
                    { KoalaBearD4Width24::SBOX_DEGREE },
                    { KoalaBearD4Width24::SBOX_REGISTERS },
                    { KoalaBearD4Width24::HALF_FULL_ROUNDS },
                    { KoalaBearD4Width24::PARTIAL_ROUNDS },
                >(
                    air.as_ref(),
                    builder,
                    &local_slice,
                    &next_slice,
                    &next_preprocessed_slice,
                );
            },
        }
    }

    fn add_lookup_columns(&mut self) -> Vec<usize> {
        match &mut self.inner {
            Poseidon2AirWrapperInner::BabyBearD4Width16(air) => {
                let air_bb: &mut Poseidon2CircuitAirBabyBearD4Width16 = air.as_mut();
                <Poseidon2CircuitAirBabyBearD4Width16 as Air<
                    DebugConstraintBuilderWithLookups<
                        'a,
                        BabyBear,
                        BinomialExtensionField<BabyBear, 4>,
                    >,
                >>::add_lookup_columns(air_bb)
            }
            Poseidon2AirWrapperInner::BabyBearD4Width24(air) => {
                let air_bb: &mut Poseidon2CircuitAirBabyBearD4Width24 = air.as_mut();
                <Poseidon2CircuitAirBabyBearD4Width24 as Air<
                    DebugConstraintBuilderWithLookups<
                        'a,
                        BabyBear,
                        BinomialExtensionField<BabyBear, 4>,
                    >,
                >>::add_lookup_columns(air_bb)
            }
            Poseidon2AirWrapperInner::KoalaBearD4Width16(air) => {
                let air_kb: &mut Poseidon2CircuitAirKoalaBearD4Width16 = air.as_mut();
                <Poseidon2CircuitAirKoalaBearD4Width16 as Air<
                    DebugConstraintBuilderWithLookups<
                        'a,
                        KoalaBear,
                        BinomialExtensionField<KoalaBear, 4>,
                    >,
                >>::add_lookup_columns(air_kb)
            }
            Poseidon2AirWrapperInner::KoalaBearD4Width24(air) => {
                let air_kb: &mut Poseidon2CircuitAirKoalaBearD4Width24 = air.as_mut();
                <Poseidon2CircuitAirKoalaBearD4Width24 as Air<
                    DebugConstraintBuilderWithLookups<
                        'a,
                        KoalaBear,
                        BinomialExtensionField<KoalaBear, 4>,
                    >,
                >>::add_lookup_columns(air_kb)
            }
        }
    }

    #[allow(clippy::missing_transmute_annotations)] // this gets overly verbose otherwise
    fn get_lookups(
        &mut self,
    ) -> Vec<Lookup<<DebugConstraintBuilderWithLookups<'a, Val<SC>, SC::Challenge> as AirBuilder>::F>>
    {
        match &mut self.inner {
            Poseidon2AirWrapperInner::BabyBearD4Width16(air) => unsafe {
                // Runtime check: verify Val<SC> == BabyBear before transmute
                assert_eq!(Val::<SC>::from_u64(BABY_BEAR_MODULUS), Val::<SC>::ZERO,);
                let air_bb: &mut Poseidon2CircuitAirBabyBearD4Width16 = air.as_mut();
                let lookups_bb = <Poseidon2CircuitAirBabyBearD4Width16 as Air<
                    SymbolicAirBuilder<BabyBear, BinomialExtensionField<BabyBear, 4>>,
                >>::get_lookups(air_bb);
                core::mem::transmute(lookups_bb)
            },
            Poseidon2AirWrapperInner::BabyBearD4Width24(air) => unsafe {
                // Runtime check: verify Val<SC> == BabyBear before transmute
                assert_eq!(Val::<SC>::from_u64(BABY_BEAR_MODULUS), Val::<SC>::ZERO,);
                let air_bb: &mut Poseidon2CircuitAirBabyBearD4Width24 = air.as_mut();
                let lookups_bb = <Poseidon2CircuitAirBabyBearD4Width24 as Air<
                    SymbolicAirBuilder<BabyBear, BinomialExtensionField<BabyBear, 4>>,
                >>::get_lookups(air_bb);
                core::mem::transmute(lookups_bb)
            },
            Poseidon2AirWrapperInner::KoalaBearD4Width16(air) => unsafe {
                // Runtime check: verify Val<SC> == KoalaBear before transmute
                assert_eq!(Val::<SC>::from_u64(KOALA_BEAR_MODULUS), Val::<SC>::ZERO,);
                let air_kb: &mut Poseidon2CircuitAirKoalaBearD4Width16 = air.as_mut();
                let lookups_kb = <Poseidon2CircuitAirKoalaBearD4Width16 as Air<
                    SymbolicAirBuilder<KoalaBear, BinomialExtensionField<KoalaBear, 4>>,
                >>::get_lookups(air_kb);
                core::mem::transmute(lookups_kb)
            },
            Poseidon2AirWrapperInner::KoalaBearD4Width24(air) => unsafe {
                // Runtime check: verify Val<SC> == KoalaBear before transmute
                assert_eq!(Val::<SC>::from_u64(KOALA_BEAR_MODULUS), Val::<SC>::ZERO,);
                let air_kb: &mut Poseidon2CircuitAirKoalaBearD4Width24 = air.as_mut();
                let lookups_kb = <Poseidon2CircuitAirKoalaBearD4Width24 as Air<
                    SymbolicAirBuilder<KoalaBear, BinomialExtensionField<KoalaBear, 4>>,
                >>::get_lookups(air_kb);
                core::mem::transmute(lookups_kb)
            },
        }
    }
}

/// Poseidon2 prover plugin that supports runtime configuration.
#[derive(Clone)]
pub struct Poseidon2Prover {
    /// The configuration that provides permutation and constants.
    config: Poseidon2Config,
}

unsafe impl Send for Poseidon2Prover {}
unsafe impl Sync for Poseidon2Prover {}

impl Poseidon2Prover {
    pub const fn new(config: Poseidon2Config) -> Self {
        Self { config }
    }

    const fn baby_bear_constants_16() -> RoundConstants<BabyBear, 16, 4, 13> {
        let beginning_full: [[BabyBear; 16]; 4] = p3_baby_bear::BABYBEAR_RC16_EXTERNAL_INITIAL;
        let partial: [BabyBear; 13] = p3_baby_bear::BABYBEAR_RC16_INTERNAL;
        let ending_full: [[BabyBear; 16]; 4] = p3_baby_bear::BABYBEAR_RC16_EXTERNAL_FINAL;
        RoundConstants::new(beginning_full, partial, ending_full)
    }

    const fn baby_bear_constants_24() -> RoundConstants<BabyBear, 24, 4, 21> {
        let beginning_full: [[BabyBear; 24]; 4] = p3_baby_bear::BABYBEAR_RC24_EXTERNAL_INITIAL;
        let partial: [BabyBear; 21] = p3_baby_bear::BABYBEAR_RC24_INTERNAL;
        let ending_full: [[BabyBear; 24]; 4] = p3_baby_bear::BABYBEAR_RC24_EXTERNAL_FINAL;
        RoundConstants::new(beginning_full, partial, ending_full)
    }

    const fn koala_bear_constants_16() -> RoundConstants<KoalaBear, 16, 4, 20> {
        let beginning_full: [[KoalaBear; 16]; 4] = p3_koala_bear::KOALABEAR_RC16_EXTERNAL_INITIAL;
        let partial: [KoalaBear; 20] = p3_koala_bear::KOALABEAR_RC16_INTERNAL;
        let ending_full: [[KoalaBear; 16]; 4] = p3_koala_bear::KOALABEAR_RC16_EXTERNAL_FINAL;
        RoundConstants::new(beginning_full, partial, ending_full)
    }

    const fn koala_bear_constants_24() -> RoundConstants<KoalaBear, 24, 4, 23> {
        let beginning_full: [[KoalaBear; 24]; 4] = p3_koala_bear::KOALABEAR_RC24_EXTERNAL_INITIAL;
        let partial: [KoalaBear; 23] = p3_koala_bear::KOALABEAR_RC24_INTERNAL;
        let ending_full: [[KoalaBear; 24]; 4] = p3_koala_bear::KOALABEAR_RC24_EXTERNAL_FINAL;
        RoundConstants::new(beginning_full, partial, ending_full)
    }

    fn air_wrapper_for_config(config: Poseidon2Config) -> Poseidon2AirWrapperInner {
        match config {
            Poseidon2Config::BabyBearD1Width16 | Poseidon2Config::BabyBearD4Width16 => {
                Poseidon2AirWrapperInner::BabyBearD4Width16(Box::new(
                    Poseidon2CircuitAirBabyBearD4Width16::new(Self::baby_bear_constants_16()),
                ))
            }
            Poseidon2Config::BabyBearD4Width24 => {
                Poseidon2AirWrapperInner::BabyBearD4Width24(Box::new(
                    Poseidon2CircuitAirBabyBearD4Width24::new(Self::baby_bear_constants_24()),
                ))
            }
            Poseidon2Config::KoalaBearD1Width16 | Poseidon2Config::KoalaBearD4Width16 => {
                Poseidon2AirWrapperInner::KoalaBearD4Width16(Box::new(
                    Poseidon2CircuitAirKoalaBearD4Width16::new(Self::koala_bear_constants_16()),
                ))
            }
            Poseidon2Config::KoalaBearD4Width24 => {
                Poseidon2AirWrapperInner::KoalaBearD4Width24(Box::new(
                    Poseidon2CircuitAirKoalaBearD4Width24::new(Self::koala_bear_constants_24()),
                ))
            }
        }
    }

    fn air_wrapper_for_config_with_preprocessed<F: Field>(
        config: Poseidon2Config,
        preprocessed: Vec<F>,
        min_height: usize,
    ) -> Poseidon2AirWrapperInner {
        match config {
            Poseidon2Config::BabyBearD1Width16 | Poseidon2Config::BabyBearD4Width16 => {
                assert!(F::from_u64(BABY_BEAR_MODULUS) == F::ZERO,);
                Poseidon2AirWrapperInner::BabyBearD4Width16(Box::new(
                    Poseidon2CircuitAirBabyBearD4Width16::new_with_preprocessed(
                        Self::baby_bear_constants_16(),
                        unsafe { transmute::<Vec<F>, Vec<BabyBear>>(preprocessed) },
                    )
                    .with_min_height(min_height),
                ))
            }
            Poseidon2Config::BabyBearD4Width24 => {
                assert!(F::from_u64(BABY_BEAR_MODULUS) == F::ZERO,);
                Poseidon2AirWrapperInner::BabyBearD4Width24(Box::new(
                    Poseidon2CircuitAirBabyBearD4Width24::new_with_preprocessed(
                        Self::baby_bear_constants_24(),
                        unsafe { transmute::<Vec<F>, Vec<BabyBear>>(preprocessed) },
                    )
                    .with_min_height(min_height),
                ))
            }
            Poseidon2Config::KoalaBearD1Width16 | Poseidon2Config::KoalaBearD4Width16 => {
                assert!(F::from_u64(KOALA_BEAR_MODULUS) == F::ZERO,);
                Poseidon2AirWrapperInner::KoalaBearD4Width16(Box::new(
                    Poseidon2CircuitAirKoalaBearD4Width16::new_with_preprocessed(
                        Self::koala_bear_constants_16(),
                        unsafe { transmute::<Vec<F>, Vec<KoalaBear>>(preprocessed) },
                    )
                    .with_min_height(min_height),
                ))
            }
            Poseidon2Config::KoalaBearD4Width24 => {
                assert!(F::from_u64(KOALA_BEAR_MODULUS) == F::ZERO,);
                Poseidon2AirWrapperInner::KoalaBearD4Width24(Box::new(
                    Poseidon2CircuitAirKoalaBearD4Width24::new_with_preprocessed(
                        Self::koala_bear_constants_24(),
                        unsafe { transmute::<Vec<F>, Vec<KoalaBear>>(preprocessed) },
                    )
                    .with_min_height(min_height),
                ))
            }
        }
    }

    pub fn wrapper_from_config_with_preprocessed<SC>(
        &self,
        preprocessed: Vec<Val<SC>>,
        min_height: usize,
    ) -> DynamicAirEntry<SC>
    where
        SC: StarkGenericConfig + 'static + Send + Sync,
        Val<SC>: StarkField,
        SymbolicExpression<SC::Challenge>: From<SymbolicExpression<Val<SC>>>,
    {
        DynamicAirEntry::new(Box::new(Poseidon2AirWrapper {
            inner: Self::air_wrapper_for_config_with_preprocessed::<Val<SC>>(
                self.config,
                preprocessed,
                min_height,
            ),
            width: self.width_from_config(),
            _phantom: core::marker::PhantomData::<SC>,
        }))
    }

    pub fn width_from_config(&self) -> usize {
        match self.config {
            Poseidon2Config::BabyBearD1Width16 | Poseidon2Config::BabyBearD4Width16 => {
                Poseidon2CircuitAirBabyBearD4Width16::new(Self::baby_bear_constants_16()).width()
            }
            Poseidon2Config::BabyBearD4Width24 => {
                Poseidon2CircuitAirBabyBearD4Width24::new(Self::baby_bear_constants_24()).width()
            }
            Poseidon2Config::KoalaBearD1Width16 | Poseidon2Config::KoalaBearD4Width16 => {
                Poseidon2CircuitAirKoalaBearD4Width16::new(Self::koala_bear_constants_16()).width()
            }
            Poseidon2Config::KoalaBearD4Width24 => {
                Poseidon2CircuitAirKoalaBearD4Width24::new(Self::koala_bear_constants_24()).width()
            }
        }
    }

    pub const fn preprocessed_width_from_config(&self) -> usize {
        match self.config {
            Poseidon2Config::BabyBearD1Width16 | Poseidon2Config::BabyBearD4Width16 => {
                Poseidon2CircuitAirBabyBearD4Width16::preprocessed_width()
            }
            Poseidon2Config::BabyBearD4Width24 => {
                Poseidon2CircuitAirBabyBearD4Width24::preprocessed_width()
            }
            Poseidon2Config::KoalaBearD1Width16 | Poseidon2Config::KoalaBearD4Width16 => {
                Poseidon2CircuitAirKoalaBearD4Width16::preprocessed_width()
            }
            Poseidon2Config::KoalaBearD4Width24 => {
                Poseidon2CircuitAirKoalaBearD4Width24::preprocessed_width()
            }
        }
    }

    fn batch_instance_from_traces<SC, CF>(
        &self,
        _config: &SC,
        packing: TablePacking,
        traces: &Traces<CF>,
    ) -> Option<BatchTableInstance<SC>>
    where
        SC: StarkGenericConfig + 'static + Send + Sync,
        Val<SC>: StarkField,
        CF: Field + ExtensionField<Val<SC>>,
        SymbolicExpression<SC::Challenge>: From<SymbolicExpression<Val<SC>>>,
    {
        let t = traces.non_primitive_trace::<Poseidon2Trace<Val<SC>>>(
            NonPrimitiveOpType::Poseidon2Perm(self.config),
        )?;

        let rows = t.total_rows();
        if rows == 0 {
            return None;
        }

        let min_height = packing.min_trace_height();
        match self.config {
            Poseidon2Config::BabyBearD1Width16 | Poseidon2Config::BabyBearD4Width16 => {
                self.batch_instance_base_impl::<SC, 16, 4, 13, 2>(t, min_height)
            }
            Poseidon2Config::BabyBearD4Width24 => {
                self.batch_instance_base_impl::<SC, 24, 4, 21, 4>(t, min_height)
            }
            Poseidon2Config::KoalaBearD1Width16 | Poseidon2Config::KoalaBearD4Width16 => {
                self.batch_instance_base_impl::<SC, 16, 4, 20, 2>(t, min_height)
            }
            Poseidon2Config::KoalaBearD4Width24 => {
                self.batch_instance_base_impl::<SC, 24, 4, 23, 4>(t, min_height)
            }
        }
    }

    fn batch_instance_base_impl<
        SC,
        const WIDTH: usize,
        const HALF_FULL_ROUNDS: usize,
        const PARTIAL_ROUNDS: usize,
        const RATE_EXT: usize,
    >(
        &self,
        t: &Poseidon2Trace<Val<SC>>,
        min_height: usize,
    ) -> Option<BatchTableInstance<SC>>
    where
        SC: StarkGenericConfig + 'static + Send + Sync,
        Val<SC>: StarkField,
        SymbolicExpression<SC::Challenge>: From<SymbolicExpression<Val<SC>>>,
    {
        let rows = t.total_rows();

        let padded_rows = rows.next_power_of_two();
        let mut padded_ops = t.operations.clone();
        while padded_ops.len() < padded_rows {
            padded_ops.push(
                padded_ops
                    .last()
                    .cloned()
                    .unwrap_or_else(|| Poseidon2CircuitRow {
                        new_start: true,
                        merkle_path: false,
                        mmcs_bit: false,
                        mmcs_index_sum: Val::<SC>::ZERO,
                        input_values: vec![Val::<SC>::ZERO; WIDTH],
                        in_ctl: [false; 4],
                        input_indices: [0; 4],
                        out_ctl: [false; 2],
                        output_indices: [0; 2],
                        mmcs_index_sum_idx: 0,
                        mmcs_ctl_enabled: false,
                    }),
            );
        }

        let (air, matrix) = match self.config {
            Poseidon2Config::BabyBearD1Width16 | Poseidon2Config::BabyBearD4Width16 => {
                let constants = Self::baby_bear_constants_16();
                let preprocessed = extract_preprocessed_from_operations::<BabyBear, Val<SC>>(
                    &t.operations,
                    self.config.d() as u32,
                );
                let air = Poseidon2CircuitAirBabyBearD4Width16::new_with_preprocessed(
                    constants.clone(),
                    preprocessed.clone(),
                )
                .with_min_height(min_height);
                let ops_babybear: Vec<Poseidon2CircuitRow<BabyBear>> =
                    unsafe { transmute(padded_ops.clone()) };
                let matrix_f = air.generate_trace_rows(&ops_babybear, &constants, 0);
                let matrix: RowMajorMatrix<Val<SC>> = unsafe { transmute(matrix_f) };
                (
                    Poseidon2AirWrapper {
                        inner: Self::air_wrapper_for_config_with_preprocessed::<BabyBear>(
                            self.config,
                            preprocessed,
                            min_height,
                        ),
                        width: air.width(),
                        _phantom: core::marker::PhantomData::<SC>,
                    },
                    matrix,
                )
            }
            Poseidon2Config::BabyBearD4Width24 => {
                let constants = Self::baby_bear_constants_24();
                let preprocessed = extract_preprocessed_from_operations::<BabyBear, Val<SC>>(
                    &t.operations,
                    self.config.d() as u32,
                );
                let air = Poseidon2CircuitAirBabyBearD4Width24::new_with_preprocessed(
                    constants.clone(),
                    preprocessed.clone(),
                )
                .with_min_height(min_height);
                let ops_babybear: Vec<Poseidon2CircuitRow<BabyBear>> =
                    unsafe { transmute(padded_ops.clone()) };
                let matrix_f = air.generate_trace_rows(&ops_babybear, &constants, 0);
                let matrix: RowMajorMatrix<Val<SC>> = unsafe { transmute(matrix_f) };
                (
                    Poseidon2AirWrapper {
                        inner: Self::air_wrapper_for_config_with_preprocessed(
                            self.config,
                            preprocessed,
                            min_height,
                        ),
                        width: air.width(),
                        _phantom: core::marker::PhantomData::<SC>,
                    },
                    matrix,
                )
            }
            Poseidon2Config::KoalaBearD1Width16 | Poseidon2Config::KoalaBearD4Width16 => {
                let constants = Self::koala_bear_constants_16();
                let preprocessed = extract_preprocessed_from_operations::<KoalaBear, Val<SC>>(
                    &t.operations,
                    self.config.d() as u32,
                );
                let air = Poseidon2CircuitAirKoalaBearD4Width16::new_with_preprocessed(
                    constants.clone(),
                    preprocessed.clone(),
                )
                .with_min_height(min_height);
                let ops_koalabear: Vec<Poseidon2CircuitRow<KoalaBear>> =
                    unsafe { transmute(padded_ops.clone()) };
                let matrix_f = air.generate_trace_rows(&ops_koalabear, &constants, 0);
                let matrix: RowMajorMatrix<Val<SC>> = unsafe { transmute(matrix_f) };
                (
                    Poseidon2AirWrapper {
                        inner: Self::air_wrapper_for_config_with_preprocessed(
                            self.config,
                            preprocessed,
                            min_height,
                        ),
                        width: air.width(),
                        _phantom: core::marker::PhantomData::<SC>,
                    },
                    matrix,
                )
            }
            Poseidon2Config::KoalaBearD4Width24 => {
                let constants = Self::koala_bear_constants_24();
                let preprocessed = extract_preprocessed_from_operations::<KoalaBear, Val<SC>>(
                    &t.operations,
                    self.config.d() as u32,
                );
                let air = Poseidon2CircuitAirKoalaBearD4Width24::new_with_preprocessed(
                    constants.clone(),
                    preprocessed.clone(),
                )
                .with_min_height(min_height);
                let ops_koalabear: Vec<Poseidon2CircuitRow<KoalaBear>> =
                    unsafe { transmute(padded_ops.clone()) };
                let matrix_f = air.generate_trace_rows(&ops_koalabear, &constants, 0);
                let matrix: RowMajorMatrix<Val<SC>> = unsafe { transmute(matrix_f) };
                (
                    Poseidon2AirWrapper {
                        inner: Self::air_wrapper_for_config_with_preprocessed(
                            self.config,
                            preprocessed,
                            min_height,
                        ),
                        width: air.width(),
                        _phantom: core::marker::PhantomData::<SC>,
                    },
                    matrix,
                )
            }
        };

        Some(BatchTableInstance {
            op_type: NonPrimitiveOpType::Poseidon2Perm(self.config),
            air: DynamicAirEntry::new(Box::new(air)),
            trace: matrix,
            public_values: Vec::new(),
            rows: padded_rows,
        })
    }
}

impl<SC> TableProver<SC> for Poseidon2Prover
where
    SC: StarkGenericConfig + 'static + Send + Sync,
    Val<SC>: StarkField + BinomiallyExtendable<4>,
    SymbolicExpression<SC::Challenge>: From<SymbolicExpression<Val<SC>>>,
{
    fn op_type(&self) -> NonPrimitiveOpType {
        NonPrimitiveOpType::Poseidon2Perm(self.config)
    }

    fn batch_instance_d1(
        &self,
        config: &SC,
        packing: TablePacking,
        traces: &Traces<Val<SC>>,
    ) -> Option<BatchTableInstance<SC>> {
        self.batch_instance_from_traces::<SC, Val<SC>>(config, packing, traces)
    }

    fn batch_instance_d2(
        &self,
        config: &SC,
        packing: TablePacking,
        traces: &Traces<BinomialExtensionField<Val<SC>, 2>>,
    ) -> Option<BatchTableInstance<SC>> {
        let _ = (config, packing, traces);
        None
    }

    fn batch_instance_d4(
        &self,
        config: &SC,
        packing: TablePacking,
        traces: &Traces<BinomialExtensionField<Val<SC>, 4>>,
    ) -> Option<BatchTableInstance<SC>> {
        self.batch_instance_from_traces::<SC, BinomialExtensionField<Val<SC>, 4>>(
            config, packing, traces,
        )
    }

    fn batch_instance_d6(
        &self,
        config: &SC,
        packing: TablePacking,
        traces: &Traces<BinomialExtensionField<Val<SC>, 6>>,
    ) -> Option<BatchTableInstance<SC>> {
        let _ = (config, packing, traces);
        None
    }

    fn batch_instance_d8(
        &self,
        config: &SC,
        packing: TablePacking,
        traces: &Traces<BinomialExtensionField<Val<SC>, 8>>,
    ) -> Option<BatchTableInstance<SC>> {
        let _ = (config, packing, traces);
        None
    }

    fn batch_air_from_table_entry(
        &self,
        _config: &SC,
        _degree: usize,
        _table_entry: &NonPrimitiveTableEntry<SC>,
    ) -> Result<DynamicAirEntry<SC>, String> {
        let inner = Self::air_wrapper_for_config(self.config);
        let width = inner.width();
        let wrapper = Poseidon2AirWrapper {
            inner,
            width,
            _phantom: core::marker::PhantomData::<SC>,
        };
        Ok(DynamicAirEntry::new(Box::new(wrapper)))
    }

    fn air_with_committed_preprocessed(
        &self,
        committed_prep: Vec<Val<SC>>,
        min_height: usize,
    ) -> Option<DynamicAirEntry<SC>> {
        Some(self.wrapper_from_config_with_preprocessed(committed_prep, min_height))
    }
}
