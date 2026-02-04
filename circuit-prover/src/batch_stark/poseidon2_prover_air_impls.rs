impl<'a, SC> Air<ProverConstraintFolder<'a, SC>> for Poseidon2AirWrapper<SC>
where
    SC: StarkGenericConfig + Send + Sync,
    Val<SC>: StarkField + PrimeField,
{
    fn eval(&self, builder: &mut ProverConstraintFolder<'a, SC>) {
        // Extract row data (same pattern as Poseidon2CircuitAir::eval)
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
                    ProverConstraintFolder<'a, SC>,
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
                    ProverConstraintFolder<'a, SC>,
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
                    ProverConstraintFolder<'a, SC>,
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
                    ProverConstraintFolderWithLookups<'a, SC>,
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
                    ProverConstraintFolderWithLookups<'a, SC>,
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
                    ProverConstraintFolderWithLookups<'a, SC>,
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
                    VerifierConstraintFolderWithLookups<'a, SC>,
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
                    VerifierConstraintFolderWithLookups<'a, SC>,
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
                    VerifierConstraintFolderWithLookups<'a, SC>,
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
