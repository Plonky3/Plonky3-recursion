use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec::Vec;
use alloc::{format, vec};
use core::any::Any;
use core::mem::transmute;

#[cfg(debug_assertions)]
use p3_air::DebugConstraintBuilder;
use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_baby_bear::{BabyBear, GenericPoseidon2LinearLayersBabyBear};
use p3_batch_stark::{StarkGenericConfig, Val};
use p3_circuit::ops::{
    GoldilocksD2Width8, NonPrimitivePreprocessedMap, NpoTypeId, Poseidon2CircuitRow,
    Poseidon2Config, Poseidon2Params, Poseidon2Trace,
};
use p3_circuit::tables::Traces;
use p3_circuit::{CircuitError, PreprocessedColumns};
use p3_field::extension::{
    BinomialExtensionField, BinomiallyExtendable, QuinticTrinomialExtensionField,
};
use p3_field::{
    Algebra, BasedVectorSpace, ExtensionField, Field, PrimeCharacteristicRing, PrimeField,
    PrimeField64,
};
use p3_goldilocks::{GenericPoseidon2LinearLayersGoldilocks, Goldilocks};
use p3_koala_bear::{GenericPoseidon2LinearLayersKoalaBear, KoalaBear};
use p3_lookup::folder::{ProverConstraintFolderWithLookups, VerifierConstraintFolderWithLookups};
use p3_lookup::symbolic::InteractionSymbolicBuilder;
use p3_matrix::dense::RowMajorMatrix;
use p3_poseidon_circuit_cols::{
    poseidon_preprocessed_row_width_for_air, poseidon_shared_challenger_role_offset,
};
use p3_poseidon2_circuit_air::*;
use p3_uni_stark::{
    ProverConstraintFolder, SymbolicExpression, SymbolicExpressionExt, VerifierConstraintFolder,
};
use p3_util::log2_ceil_usize;

use super::dynamic_air::{BatchAir, BatchTableInstance, DynamicAirEntry, TableProver};
use crate::batch_stark_prover::{
    BABY_BEAR_MODULUS, KOALA_BEAR_MODULUS, NonPrimitiveTableEntry, TablePacking,
    poseidon_d1_witness_bus_dim, poseidon_preprocess_for_prover,
};
use crate::common::{CircuitTableAir, NpoAirBuilder, NpoPreprocessor};
use crate::config::{BabyBearConfig, GoldilocksConfig, KoalaBearConfig, StarkField};
use crate::constraint_profile::ConstraintProfile;

pub enum Poseidon2AirWrapperInner {
    BabyBearD1Width16Bus1(Box<Poseidon2CircuitAirBabyBearD1Width16>),
    BabyBearD1Width16Bus5(Box<Poseidon2CircuitAirBabyBearD1Width16WitnessBus5>),
    BabyBearD4Width16(Box<Poseidon2CircuitAirBabyBearD4Width16>),
    BabyBearD4Width24(Box<Poseidon2CircuitAirBabyBearD4Width24>),
    BabyBearD4Width32(Box<Poseidon2CircuitAirBabyBearD4Width32>),
    KoalaBearD1Width16Bus1(Box<Poseidon2CircuitAirKoalaBearD1Width16>),
    KoalaBearD1Width16Bus5(Box<Poseidon2CircuitAirKoalaBearD1Width16WitnessBus5>),
    KoalaBearD4Width16(Box<Poseidon2CircuitAirKoalaBearD4Width16>),
    KoalaBearD4Width24(Box<Poseidon2CircuitAirKoalaBearD4Width24>),
    KoalaBearD1Width32Bus1(Box<Poseidon2CircuitAirKoalaBearD1Width32>),
    KoalaBearD1Width32Bus5(Box<Poseidon2CircuitAirKoalaBearD1Width32WitnessBus5>),
    KoalaBearD4Width32(Box<Poseidon2CircuitAirKoalaBearD4Width32>),
    GoldilocksD2Width8(Box<Poseidon2CircuitAirGoldilocksD2Width8>),
    GoldilocksD2Width16(Box<Poseidon2CircuitAirGoldilocksD2Width16>),
}

#[cfg(test)]
mod width_tests {
    use super::*;

    #[test]
    fn poseidon_width_lookup_matches_every_constructed_air() {
        let configs = [
            Poseidon2Config::BABY_BEAR_D1_W16,
            Poseidon2Config::BABY_BEAR_D4_W16,
            Poseidon2Config::BABY_BEAR_D4_W24,
            Poseidon2Config::BABY_BEAR_D4_W32,
            Poseidon2Config::KOALA_BEAR_D1_W16,
            Poseidon2Config::KOALA_BEAR_D4_W16,
            Poseidon2Config::KOALA_BEAR_D4_W24,
            Poseidon2Config::KOALA_BEAR_D1_W32,
            Poseidon2Config::KOALA_BEAR_D4_W32,
            Poseidon2Config::GOLDILOCKS_D2_W8,
            Poseidon2Config::GOLDILOCKS_D2_W16,
            Poseidon2Config::BABY_BEAR_D4_W16.for_challenger(),
            Poseidon2Config::BABY_BEAR_D4_W24.for_challenger(),
            Poseidon2Config::KOALA_BEAR_D4_W16.for_challenger(),
            Poseidon2Config::KOALA_BEAR_D4_W24.for_challenger(),
            Poseidon2Config::GOLDILOCKS_D2_W8.for_challenger(),
        ];
        for config in configs {
            let prover = Poseidon2Prover::new(config, ConstraintProfile::Standard);
            let air = Poseidon2Prover::air_wrapper_for_config(config);
            assert_eq!(prover.main_width_from_config(), air.width());
            assert_eq!(
                prover.preprocessed_width_from_config(),
                air.preprocessed_width()
            );
        }

        for (config, modulus_is_baby_bear) in [
            (Poseidon2Config::BABY_BEAR_D1_W16, true),
            (Poseidon2Config::KOALA_BEAR_D1_W16, false),
            (Poseidon2Config::KOALA_BEAR_D1_W32, false),
        ] {
            let expected =
                Poseidon2Prover::new(config, ConstraintProfile::Standard).main_width_from_config();
            for witness_bus in [1, 5] {
                let width = if modulus_is_baby_bear {
                    Poseidon2Prover::air_wrapper_for_config_with_preprocessed::<BabyBear>(
                        config,
                        Vec::new(),
                        1,
                        witness_bus,
                    )
                    .unwrap()
                    .width()
                } else {
                    Poseidon2Prover::air_wrapper_for_config_with_preprocessed::<KoalaBear>(
                        config,
                        Vec::new(),
                        1,
                        witness_bus,
                    )
                    .unwrap()
                    .width()
                };
                assert_eq!(expected, width);
            }
        }
    }

    #[test]
    fn shared_shapes_preserve_widths_and_reject_unsupported_geometry() {
        let shared = [
            Poseidon2Config::BABY_BEAR_D4_W16,
            Poseidon2Config::BABY_BEAR_D4_W24,
            Poseidon2Config::KOALA_BEAR_D4_W16,
            Poseidon2Config::KOALA_BEAR_D4_W24,
            Poseidon2Config::GOLDILOCKS_D2_W8,
        ];
        for ordinary in shared {
            let combined = ordinary.for_shared_challenger_table();
            let ordinary_prover = Poseidon2Prover::new(ordinary, ConstraintProfile::Standard);
            let combined_prover = Poseidon2Prover::new(combined, ConstraintProfile::Standard);
            assert_eq!(
                combined_prover.main_width_from_config(),
                ordinary_prover.main_width_from_config()
            );
            assert_eq!(
                combined_prover.preprocessed_width_from_config(),
                ordinary_prover.preprocessed_width_from_config()
            );
        }
    }

    #[test]
    #[should_panic(expected = "shared challenger tables require extension limbs")]
    fn shared_rejects_d1_geometry() {
        Poseidon2Config::BABY_BEAR_D1_W16.for_shared_challenger_table();
    }

    #[test]
    #[should_panic(expected = "arity-4 tables cannot share challenger rows")]
    fn shared_rejects_arity4_geometry() {
        Poseidon2Config::KOALA_BEAR_D4_W32.for_shared_challenger_table();
    }
}

#[cfg(test)]
mod shared_materialization_tests {
    use p3_circuit::tables::{
        AluTrace, ConstTrace, NonPrimitiveTrace, PublicTrace, Traces, WitnessTrace,
    };
    use p3_field::extension::BinomialExtensionField;
    use p3_matrix::Matrix;

    use super::*;

    fn row(value: BabyBear) -> Poseidon2CircuitRow<BabyBear> {
        let config = Poseidon2Config::BABY_BEAR_D4_W16;
        Poseidon2CircuitRow {
            challenger: false,
            new_start: true,
            merkle_path: false,
            mmcs_bit: false,
            mmcs_bit2: false,
            mmcs_index_sum: BabyBear::ZERO,
            input_values: {
                let mut values = BabyBear::zero_vec(config.width());
                values[0] = value;
                values.into()
            },
            in_ctl: vec![false; config.width_ext()].into(),
            input_indices: vec![0; config.width_ext()].into(),
            out_ctl: vec![false; config.rate_ext()].into(),
            output_indices: vec![0; config.rate_ext()].into(),
            mmcs_index_sum_idx: 0,
            mmcs_ctl_enabled: false,
            absorb_len: 0,
        }
    }

    fn traces(
        config: Poseidon2Config,
        include_challenger: bool,
        include_ordinary: bool,
    ) -> Traces<BinomialExtensionField<BabyBear, 4>> {
        let sources = config.source_configs();
        let mut non_primitive_traces = hashbrown::HashMap::new();
        if include_challenger {
            non_primitive_traces.insert(
                NpoTypeId::poseidon2_perm(sources[0]),
                Box::new(Poseidon2Trace {
                    op_type: NpoTypeId::poseidon2_perm(sources[0]),
                    operations: vec![row(BabyBear::from_u64(11))],
                })
                    as Box<dyn NonPrimitiveTrace<BinomialExtensionField<BabyBear, 4>>>,
            );
        }
        if include_ordinary {
            non_primitive_traces.insert(
                NpoTypeId::poseidon2_perm(sources[1]),
                Box::new(Poseidon2Trace {
                    op_type: NpoTypeId::poseidon2_perm(sources[1]),
                    operations: vec![row(BabyBear::from_u64(22))],
                })
                    as Box<dyn NonPrimitiveTrace<BinomialExtensionField<BabyBear, 4>>>,
            );
        }
        Traces {
            witness_trace: WitnessTrace::new(Vec::new()),
            const_trace: ConstTrace {
                index: Vec::new(),
                values: Vec::new(),
            },
            public_trace: PublicTrace {
                index: Vec::new(),
                values: Vec::new(),
            },
            alu_trace: AluTrace {
                op_kind: Vec::new(),
                values: Vec::new(),
                indices: Vec::new(),
            },
            non_primitive_traces,
            tag_to_witness: hashbrown::HashMap::new(),
        }
    }

    #[test]
    fn shared_materialization_has_stable_source_order_and_physical_identity() {
        let config = Poseidon2Config::BABY_BEAR_D4_W16.for_shared_challenger_table();
        let prover = Poseidon2Prover::new(config, ConstraintProfile::Standard);
        let packing = TablePacking::new(1, 1);
        let stark_config = crate::config::baby_bear();

        for (challenger, ordinary, expected_rows) in [
            (false, false, None),
            (true, false, Some(1)),
            (false, true, Some(1)),
            (true, true, Some(2)),
        ] {
            let traces = traces(config, challenger, ordinary);
            let instance = prover.batch_instance_d4(&stark_config, &packing, &traces);
            match expected_rows {
                None => assert!(instance.is_none()),
                Some(rows) => {
                    let instance = instance.expect("nonempty source materializes");
                    assert_eq!(instance.op_type, NpoTypeId::poseidon2_perm(config));
                    assert_eq!(instance.rows, rows);
                    assert_eq!(instance.trace.height(), rows.next_power_of_two());
                    if challenger && ordinary {
                        assert_eq!(instance.trace.values[0], BabyBear::from_u64(11));
                        let row_width = instance.trace.width();
                        assert_eq!(instance.trace.values[row_width], BabyBear::from_u64(22));
                    }
                }
            }
        }
    }

    #[test]
    fn shared_materialization_preserves_logical_rows_under_power_of_two_padding() {
        let config = Poseidon2Config::BABY_BEAR_D4_W16.for_shared_challenger_table();
        let prover = Poseidon2Prover::new(config, ConstraintProfile::Standard);
        let packing =
            TablePacking::new(1, 1).with_npo_min_height(NpoTypeId::poseidon2_perm(config), 4);
        let traces = traces(config, true, true);
        let instance = prover
            .batch_instance_d4(&crate::config::baby_bear(), &packing, &traces)
            .expect("combined sources materialize");

        assert_eq!(instance.rows, 4);
        assert_eq!(instance.trace.height(), 4);
        assert_eq!(instance.trace.values[0], BabyBear::from_u64(11));
        assert_eq!(
            instance.trace.values[instance.trace.width()],
            BabyBear::from_u64(22)
        );
    }
}

impl Poseidon2AirWrapperInner {
    /// Declare whether the wrapped table holds nothing but challenger duplex-sponge rows.
    ///
    /// The AIR emits the sponge chain-start capacity constraint only when it does.
    fn with_challenger_role(self, challenger: bool) -> Self {
        match self {
            Self::BabyBearD1Width16Bus1(air) => {
                Self::BabyBearD1Width16Bus1(Box::new((*air).with_challenger_role(challenger)))
            }
            Self::BabyBearD1Width16Bus5(air) => {
                Self::BabyBearD1Width16Bus5(Box::new((*air).with_challenger_role(challenger)))
            }
            Self::BabyBearD4Width16(air) => {
                Self::BabyBearD4Width16(Box::new((*air).with_challenger_role(challenger)))
            }
            Self::BabyBearD4Width24(air) => {
                Self::BabyBearD4Width24(Box::new((*air).with_challenger_role(challenger)))
            }
            Self::BabyBearD4Width32(air) => {
                Self::BabyBearD4Width32(Box::new((*air).with_challenger_role(challenger)))
            }
            Self::KoalaBearD1Width16Bus1(air) => {
                Self::KoalaBearD1Width16Bus1(Box::new((*air).with_challenger_role(challenger)))
            }
            Self::KoalaBearD1Width16Bus5(air) => {
                Self::KoalaBearD1Width16Bus5(Box::new((*air).with_challenger_role(challenger)))
            }
            Self::KoalaBearD4Width16(air) => {
                Self::KoalaBearD4Width16(Box::new((*air).with_challenger_role(challenger)))
            }
            Self::KoalaBearD4Width24(air) => {
                Self::KoalaBearD4Width24(Box::new((*air).with_challenger_role(challenger)))
            }
            Self::KoalaBearD1Width32Bus1(air) => {
                Self::KoalaBearD1Width32Bus1(Box::new((*air).with_challenger_role(challenger)))
            }
            Self::KoalaBearD1Width32Bus5(air) => {
                Self::KoalaBearD1Width32Bus5(Box::new((*air).with_challenger_role(challenger)))
            }
            Self::KoalaBearD4Width32(air) => {
                Self::KoalaBearD4Width32(Box::new((*air).with_challenger_role(challenger)))
            }
            Self::GoldilocksD2Width8(air) => {
                Self::GoldilocksD2Width8(Box::new((*air).with_challenger_role(challenger)))
            }
            Self::GoldilocksD2Width16(air) => {
                Self::GoldilocksD2Width16(Box::new((*air).with_challenger_role(challenger)))
            }
        }
    }

    fn with_shared_role(self, shared: bool) -> Self {
        match self {
            Self::BabyBearD1Width16Bus1(air) => {
                Self::BabyBearD1Width16Bus1(Box::new(air.with_shared_role(shared)))
            }
            Self::BabyBearD1Width16Bus5(air) => {
                Self::BabyBearD1Width16Bus5(Box::new(air.with_shared_role(shared)))
            }
            Self::BabyBearD4Width16(air) => {
                Self::BabyBearD4Width16(Box::new(air.with_shared_role(shared)))
            }
            Self::BabyBearD4Width24(air) => {
                Self::BabyBearD4Width24(Box::new(air.with_shared_role(shared)))
            }
            Self::BabyBearD4Width32(air) => {
                Self::BabyBearD4Width32(Box::new(air.with_shared_role(shared)))
            }
            Self::KoalaBearD1Width16Bus1(air) => {
                Self::KoalaBearD1Width16Bus1(Box::new(air.with_shared_role(shared)))
            }
            Self::KoalaBearD1Width16Bus5(air) => {
                Self::KoalaBearD1Width16Bus5(Box::new(air.with_shared_role(shared)))
            }
            Self::KoalaBearD4Width16(air) => {
                Self::KoalaBearD4Width16(Box::new(air.with_shared_role(shared)))
            }
            Self::KoalaBearD4Width24(air) => {
                Self::KoalaBearD4Width24(Box::new(air.with_shared_role(shared)))
            }
            Self::KoalaBearD1Width32Bus1(air) => {
                Self::KoalaBearD1Width32Bus1(Box::new(air.with_shared_role(shared)))
            }
            Self::KoalaBearD1Width32Bus5(air) => {
                Self::KoalaBearD1Width32Bus5(Box::new(air.with_shared_role(shared)))
            }
            Self::KoalaBearD4Width32(air) => {
                Self::KoalaBearD4Width32(Box::new(air.with_shared_role(shared)))
            }
            Self::GoldilocksD2Width8(air) => {
                Self::GoldilocksD2Width8(Box::new(air.with_shared_role(shared)))
            }
            Self::GoldilocksD2Width16(air) => {
                Self::GoldilocksD2Width16(Box::new(air.with_shared_role(shared)))
            }
        }
    }

    pub fn width(&self) -> usize {
        match self {
            Self::BabyBearD1Width16Bus1(air) => air.width(),
            Self::BabyBearD1Width16Bus5(air) => air.width(),
            Self::BabyBearD4Width16(air) => air.width(),
            Self::BabyBearD4Width24(air) => air.width(),
            Self::BabyBearD4Width32(air) => air.width(),
            Self::KoalaBearD1Width16Bus1(air) => air.width(),
            Self::KoalaBearD1Width16Bus5(air) => air.width(),
            Self::KoalaBearD4Width16(air) => air.width(),
            Self::KoalaBearD4Width24(air) => air.width(),
            Self::KoalaBearD1Width32Bus1(air) => air.width(),
            Self::KoalaBearD1Width32Bus5(air) => air.width(),
            Self::KoalaBearD4Width32(air) => air.width(),
            Self::GoldilocksD2Width8(air) => air.width(),
            Self::GoldilocksD2Width16(air) => air.width(),
        }
    }

    pub fn preprocessed_width(&self) -> usize {
        match self {
            Self::BabyBearD1Width16Bus1(air) => {
                BaseAir::<BabyBear>::preprocessed_width(air.as_ref())
            }
            Self::BabyBearD1Width16Bus5(air) => {
                BaseAir::<BabyBear>::preprocessed_width(air.as_ref())
            }
            Self::BabyBearD4Width16(air) => BaseAir::<BabyBear>::preprocessed_width(air.as_ref()),
            Self::BabyBearD4Width24(air) => BaseAir::<BabyBear>::preprocessed_width(air.as_ref()),
            Self::BabyBearD4Width32(air) => BaseAir::<BabyBear>::preprocessed_width(air.as_ref()),
            Self::KoalaBearD1Width16Bus1(air) => {
                BaseAir::<KoalaBear>::preprocessed_width(air.as_ref())
            }
            Self::KoalaBearD1Width16Bus5(air) => {
                BaseAir::<KoalaBear>::preprocessed_width(air.as_ref())
            }
            Self::KoalaBearD4Width16(air) => BaseAir::<KoalaBear>::preprocessed_width(air.as_ref()),
            Self::KoalaBearD4Width24(air) => BaseAir::<KoalaBear>::preprocessed_width(air.as_ref()),
            Self::KoalaBearD1Width32Bus1(air) => {
                BaseAir::<KoalaBear>::preprocessed_width(air.as_ref())
            }
            Self::KoalaBearD1Width32Bus5(air) => {
                BaseAir::<KoalaBear>::preprocessed_width(air.as_ref())
            }
            Self::KoalaBearD4Width32(air) => BaseAir::<KoalaBear>::preprocessed_width(air.as_ref()),
            Self::GoldilocksD2Width8(air) => {
                BaseAir::<Goldilocks>::preprocessed_width(air.as_ref())
            }
            Self::GoldilocksD2Width16(air) => {
                BaseAir::<Goldilocks>::preprocessed_width(air.as_ref())
            }
        }
    }
}

impl Clone for Poseidon2AirWrapperInner {
    fn clone(&self) -> Self {
        match self {
            Self::BabyBearD1Width16Bus1(air) => Self::BabyBearD1Width16Bus1(air.clone()),
            Self::BabyBearD1Width16Bus5(air) => Self::BabyBearD1Width16Bus5(air.clone()),
            Self::BabyBearD4Width16(air) => Self::BabyBearD4Width16(air.clone()),
            Self::BabyBearD4Width24(air) => Self::BabyBearD4Width24(air.clone()),
            Self::BabyBearD4Width32(air) => Self::BabyBearD4Width32(air.clone()),
            Self::KoalaBearD1Width16Bus1(air) => Self::KoalaBearD1Width16Bus1(air.clone()),
            Self::KoalaBearD1Width16Bus5(air) => Self::KoalaBearD1Width16Bus5(air.clone()),
            Self::KoalaBearD4Width16(air) => Self::KoalaBearD4Width16(air.clone()),
            Self::KoalaBearD4Width24(air) => Self::KoalaBearD4Width24(air.clone()),
            Self::KoalaBearD1Width32Bus1(air) => Self::KoalaBearD1Width32Bus1(air.clone()),
            Self::KoalaBearD1Width32Bus5(air) => Self::KoalaBearD1Width32Bus5(air.clone()),
            Self::KoalaBearD4Width32(air) => Self::KoalaBearD4Width32(air.clone()),
            Self::GoldilocksD2Width8(air) => Self::GoldilocksD2Width8(air.clone()),
            Self::GoldilocksD2Width16(air) => Self::GoldilocksD2Width16(air.clone()),
        }
    }
}

pub(crate) struct Poseidon2AirWrapper<SC: StarkGenericConfig> {
    pub(crate) inner: Poseidon2AirWrapperInner,
    _phantom: core::marker::PhantomData<SC>,
}

impl<SC> BatchAir<SC> for Poseidon2AirWrapper<SC>
where
    SC: StarkGenericConfig + Send + Sync,
    Val<SC>: StarkField,
    SymbolicExpressionExt<Val<SC>, SC::Challenge>:
        Algebra<SymbolicExpression<Val<SC>>> + Algebra<SC::Challenge>,
{
}

impl<SC: StarkGenericConfig> Clone for Poseidon2AirWrapper<SC> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            _phantom: core::marker::PhantomData,
        }
    }
}

macro_rules! call_eval_variant {
    ($Params:ty, $Config:ty, $F:ty, $LL:ty, $AB:ty, $WITNESS_EXT:expr;
     $air:expr, $b:expr, $l:expr, $n:expr, $p:expr) => {
        eval_poseidon2_variant::<
            $Config,
            $F,
            $AB,
            $LL,
            { <$Params as Poseidon2Params>::D },
            { <$Params as Poseidon2Params>::WIDTH },
            { <$Params as Poseidon2Params>::WIDTH_EXT },
            { <$Params as Poseidon2Params>::RATE_EXT },
            { <$Params as Poseidon2Params>::CAPACITY_EXT },
            { <$Params as Poseidon2Params>::SBOX_DEGREE },
            { <$Params as Poseidon2Params>::SBOX_REGISTERS },
            { <$Params as Poseidon2Params>::HALF_FULL_ROUNDS },
            { <$Params as Poseidon2Params>::PARTIAL_ROUNDS },
            $WITNESS_EXT,
        >($air, $b, $l, $n, $p)
    };
}

macro_rules! eval_folder_inner {
    ($inner:expr, $builder:expr, $local:expr, $next:expr, $prep:expr;
     bb=$bb_ty:ty, kb=$kb_ty:ty, gl=$gl_ty:ty) => {
        match $inner {
            Poseidon2AirWrapperInner::BabyBearD1Width16Bus1(air) => unsafe {
                let b: &mut $bb_ty = transmute::<_, &mut $bb_ty>($builder);
                let l: &[<$bb_ty as AirBuilder>::Var] = transmute($local);
                let n: &[<$bb_ty as AirBuilder>::Var] = transmute($next);
                let p: &[<$bb_ty as AirBuilder>::Var] = transmute($prep);
                call_eval_variant!(BabyBearD1Width16, BabyBearConfig, BabyBear,
                    GenericPoseidon2LinearLayersBabyBear, $bb_ty, 1;
                    air.as_ref(), b, l, n, p);
            },
            Poseidon2AirWrapperInner::BabyBearD1Width16Bus5(air) => unsafe {
                let b: &mut $bb_ty = transmute::<_, &mut $bb_ty>($builder);
                let l: &[<$bb_ty as AirBuilder>::Var] = transmute($local);
                let n: &[<$bb_ty as AirBuilder>::Var] = transmute($next);
                let p: &[<$bb_ty as AirBuilder>::Var] = transmute($prep);
                call_eval_variant!(BabyBearD1Width16, BabyBearConfig, BabyBear,
                    GenericPoseidon2LinearLayersBabyBear, $bb_ty, 5;
                    air.as_ref(), b, l, n, p);
            },
            Poseidon2AirWrapperInner::BabyBearD4Width16(air) => unsafe {
                let b: &mut $bb_ty = transmute::<_, &mut $bb_ty>($builder);
                let l: &[<$bb_ty as AirBuilder>::Var] = transmute($local);
                let n: &[<$bb_ty as AirBuilder>::Var] = transmute($next);
                let p: &[<$bb_ty as AirBuilder>::Var] = transmute($prep);
                call_eval_variant!(BabyBearD4Width16, BabyBearConfig, BabyBear,
                    GenericPoseidon2LinearLayersBabyBear, $bb_ty,
                    { <BabyBearD4Width16 as Poseidon2Params>::D };
                    air.as_ref(), b, l, n, p);
            },
            Poseidon2AirWrapperInner::BabyBearD4Width24(air) => unsafe {
                let b: &mut $bb_ty = transmute::<_, &mut $bb_ty>($builder);
                let l: &[<$bb_ty as AirBuilder>::Var] = transmute($local);
                let n: &[<$bb_ty as AirBuilder>::Var] = transmute($next);
                let p: &[<$bb_ty as AirBuilder>::Var] = transmute($prep);
                call_eval_variant!(BabyBearD4Width24, BabyBearConfig, BabyBear,
                    GenericPoseidon2LinearLayersBabyBear, $bb_ty,
                    { <BabyBearD4Width24 as Poseidon2Params>::D };
                    air.as_ref(), b, l, n, p);
            },
            Poseidon2AirWrapperInner::BabyBearD4Width32(air) => unsafe {
                let b: &mut $bb_ty = transmute::<_, &mut $bb_ty>($builder);
                let l: &[<$bb_ty as AirBuilder>::Var] = transmute($local);
                let n: &[<$bb_ty as AirBuilder>::Var] = transmute($next);
                let p: &[<$bb_ty as AirBuilder>::Var] = transmute($prep);
                call_eval_variant!(BabyBearD4Width32, BabyBearConfig, BabyBear,
                    GenericPoseidon2LinearLayersBabyBear, $bb_ty,
                    { <BabyBearD4Width32 as Poseidon2Params>::D };
                    air.as_ref(), b, l, n, p);
            },
            Poseidon2AirWrapperInner::KoalaBearD1Width16Bus1(air) => unsafe {
                let b: &mut $kb_ty = transmute::<_, &mut $kb_ty>($builder);
                let l: &[<$kb_ty as AirBuilder>::Var] = transmute($local);
                let n: &[<$kb_ty as AirBuilder>::Var] = transmute($next);
                let p: &[<$kb_ty as AirBuilder>::Var] = transmute($prep);
                call_eval_variant!(KoalaBearD1Width16, KoalaBearConfig, KoalaBear,
                    GenericPoseidon2LinearLayersKoalaBear, $kb_ty, 1;
                    air.as_ref(), b, l, n, p);
            },
            Poseidon2AirWrapperInner::KoalaBearD1Width16Bus5(air) => unsafe {
                let b: &mut $kb_ty = transmute::<_, &mut $kb_ty>($builder);
                let l: &[<$kb_ty as AirBuilder>::Var] = transmute($local);
                let n: &[<$kb_ty as AirBuilder>::Var] = transmute($next);
                let p: &[<$kb_ty as AirBuilder>::Var] = transmute($prep);
                call_eval_variant!(KoalaBearD1Width16, KoalaBearConfig, KoalaBear,
                    GenericPoseidon2LinearLayersKoalaBear, $kb_ty, 5;
                    air.as_ref(), b, l, n, p);
            },
            Poseidon2AirWrapperInner::KoalaBearD4Width16(air) => unsafe {
                let b: &mut $kb_ty = transmute::<_, &mut $kb_ty>($builder);
                let l: &[<$kb_ty as AirBuilder>::Var] = transmute($local);
                let n: &[<$kb_ty as AirBuilder>::Var] = transmute($next);
                let p: &[<$kb_ty as AirBuilder>::Var] = transmute($prep);
                call_eval_variant!(KoalaBearD4Width16, KoalaBearConfig, KoalaBear,
                    GenericPoseidon2LinearLayersKoalaBear, $kb_ty,
                    { <KoalaBearD4Width16 as Poseidon2Params>::D };
                    air.as_ref(), b, l, n, p);
            },
            Poseidon2AirWrapperInner::KoalaBearD4Width24(air) => unsafe {
                let b: &mut $kb_ty = transmute::<_, &mut $kb_ty>($builder);
                let l: &[<$kb_ty as AirBuilder>::Var] = transmute($local);
                let n: &[<$kb_ty as AirBuilder>::Var] = transmute($next);
                let p: &[<$kb_ty as AirBuilder>::Var] = transmute($prep);
                call_eval_variant!(KoalaBearD4Width24, KoalaBearConfig, KoalaBear,
                    GenericPoseidon2LinearLayersKoalaBear, $kb_ty,
                    { <KoalaBearD4Width24 as Poseidon2Params>::D };
                    air.as_ref(), b, l, n, p);
            },
            Poseidon2AirWrapperInner::KoalaBearD1Width32Bus1(air) => unsafe {
                let b: &mut $kb_ty = transmute::<_, &mut $kb_ty>($builder);
                let l: &[<$kb_ty as AirBuilder>::Var] = transmute($local);
                let n: &[<$kb_ty as AirBuilder>::Var] = transmute($next);
                let p: &[<$kb_ty as AirBuilder>::Var] = transmute($prep);
                call_eval_variant!(KoalaBearD1Width32, KoalaBearConfig, KoalaBear,
                    GenericPoseidon2LinearLayersKoalaBear, $kb_ty, 1;
                    air.as_ref(), b, l, n, p);
            },
            Poseidon2AirWrapperInner::KoalaBearD1Width32Bus5(air) => unsafe {
                let b: &mut $kb_ty = transmute::<_, &mut $kb_ty>($builder);
                let l: &[<$kb_ty as AirBuilder>::Var] = transmute($local);
                let n: &[<$kb_ty as AirBuilder>::Var] = transmute($next);
                let p: &[<$kb_ty as AirBuilder>::Var] = transmute($prep);
                call_eval_variant!(KoalaBearD1Width32, KoalaBearConfig, KoalaBear,
                    GenericPoseidon2LinearLayersKoalaBear, $kb_ty, 5;
                    air.as_ref(), b, l, n, p);
            },
            Poseidon2AirWrapperInner::KoalaBearD4Width32(air) => unsafe {
                let b: &mut $kb_ty = transmute::<_, &mut $kb_ty>($builder);
                let l: &[<$kb_ty as AirBuilder>::Var] = transmute($local);
                let n: &[<$kb_ty as AirBuilder>::Var] = transmute($next);
                let p: &[<$kb_ty as AirBuilder>::Var] = transmute($prep);
                call_eval_variant!(KoalaBearD4Width32, KoalaBearConfig, KoalaBear,
                    GenericPoseidon2LinearLayersKoalaBear, $kb_ty,
                    { <KoalaBearD4Width32 as Poseidon2Params>::D };
                    air.as_ref(), b, l, n, p);
            },
            Poseidon2AirWrapperInner::GoldilocksD2Width8(air) => unsafe {
                let b: &mut $gl_ty = transmute::<_, &mut $gl_ty>($builder);
                let l: &[<$gl_ty as AirBuilder>::Var] = transmute($local);
                let n: &[<$gl_ty as AirBuilder>::Var] = transmute($next);
                let p: &[<$gl_ty as AirBuilder>::Var] = transmute($prep);
                call_eval_variant!(GoldilocksD2Width8, GoldilocksConfig, Goldilocks,
                    GenericPoseidon2LinearLayersGoldilocks, $gl_ty,
                    { <GoldilocksD2Width8 as Poseidon2Params>::D };
                    air.as_ref(), b, l, n, p);
            },
            Poseidon2AirWrapperInner::GoldilocksD2Width16(air) => unsafe {
                let b: &mut $gl_ty = transmute::<_, &mut $gl_ty>($builder);
                let l: &[<$gl_ty as AirBuilder>::Var] = transmute($local);
                let n: &[<$gl_ty as AirBuilder>::Var] = transmute($next);
                let p: &[<$gl_ty as AirBuilder>::Var] = transmute($prep);
                call_eval_variant!(GoldilocksD2Width16, GoldilocksConfig, Goldilocks,
                    GenericPoseidon2LinearLayersGoldilocks, $gl_ty,
                    { <GoldilocksD2Width16 as Poseidon2Params>::D };
                    air.as_ref(), b, l, n, p);
            },
        }
    };
}

macro_rules! eval_symbolic_inner {
    ($inner:expr, $builder:expr, $F:ty) => {
        match $inner {
            Poseidon2AirWrapperInner::BabyBearD1Width16Bus1(air) => {
                assert_eq!(<$F>::from_u64(BABY_BEAR_MODULUS), <$F>::ZERO);
                unsafe {
                    let b: &mut InteractionSymbolicBuilder<BabyBear> =
                        core::mem::transmute($builder);
                    Air::eval(air.as_ref(), b);
                }
            }
            Poseidon2AirWrapperInner::BabyBearD1Width16Bus5(air) => {
                assert_eq!(<$F>::from_u64(BABY_BEAR_MODULUS), <$F>::ZERO);
                unsafe {
                    let b: &mut InteractionSymbolicBuilder<BabyBear> =
                        core::mem::transmute($builder);
                    Air::eval(air.as_ref(), b);
                }
            }
            Poseidon2AirWrapperInner::BabyBearD4Width16(air) => {
                assert_eq!(<$F>::from_u64(BABY_BEAR_MODULUS), <$F>::ZERO);
                unsafe {
                    let b: &mut InteractionSymbolicBuilder<BabyBear> =
                        core::mem::transmute($builder);
                    Air::eval(air.as_ref(), b);
                }
            }
            Poseidon2AirWrapperInner::BabyBearD4Width24(air) => {
                assert_eq!(<$F>::from_u64(BABY_BEAR_MODULUS), <$F>::ZERO);
                unsafe {
                    let b: &mut InteractionSymbolicBuilder<BabyBear> =
                        core::mem::transmute($builder);
                    Air::eval(air.as_ref(), b);
                }
            }
            Poseidon2AirWrapperInner::BabyBearD4Width32(air) => {
                assert_eq!(<$F>::from_u64(BABY_BEAR_MODULUS), <$F>::ZERO);
                unsafe {
                    let b: &mut InteractionSymbolicBuilder<BabyBear> =
                        core::mem::transmute($builder);
                    Air::eval(air.as_ref(), b);
                }
            }
            Poseidon2AirWrapperInner::KoalaBearD1Width16Bus1(air) => {
                assert_eq!(<$F>::from_u64(KOALA_BEAR_MODULUS), <$F>::ZERO);
                unsafe {
                    let b: &mut InteractionSymbolicBuilder<KoalaBear> =
                        core::mem::transmute($builder);
                    Air::eval(air.as_ref(), b);
                }
            }
            Poseidon2AirWrapperInner::KoalaBearD1Width16Bus5(air) => {
                assert_eq!(<$F>::from_u64(KOALA_BEAR_MODULUS), <$F>::ZERO);
                unsafe {
                    let b: &mut InteractionSymbolicBuilder<KoalaBear> =
                        core::mem::transmute($builder);
                    Air::eval(air.as_ref(), b);
                }
            }
            Poseidon2AirWrapperInner::KoalaBearD4Width16(air) => {
                assert_eq!(<$F>::from_u64(KOALA_BEAR_MODULUS), <$F>::ZERO);
                unsafe {
                    let b: &mut InteractionSymbolicBuilder<KoalaBear> =
                        core::mem::transmute($builder);
                    Air::eval(air.as_ref(), b);
                }
            }
            Poseidon2AirWrapperInner::KoalaBearD4Width24(air) => {
                assert_eq!(<$F>::from_u64(KOALA_BEAR_MODULUS), <$F>::ZERO);
                unsafe {
                    let b: &mut InteractionSymbolicBuilder<KoalaBear> =
                        core::mem::transmute($builder);
                    Air::eval(air.as_ref(), b);
                }
            }
            Poseidon2AirWrapperInner::KoalaBearD1Width32Bus1(air) => {
                assert_eq!(<$F>::from_u64(KOALA_BEAR_MODULUS), <$F>::ZERO);
                unsafe {
                    let b: &mut InteractionSymbolicBuilder<KoalaBear> =
                        core::mem::transmute($builder);
                    Air::eval(air.as_ref(), b);
                }
            }
            Poseidon2AirWrapperInner::KoalaBearD1Width32Bus5(air) => {
                assert_eq!(<$F>::from_u64(KOALA_BEAR_MODULUS), <$F>::ZERO);
                unsafe {
                    let b: &mut InteractionSymbolicBuilder<KoalaBear> =
                        core::mem::transmute($builder);
                    Air::eval(air.as_ref(), b);
                }
            }
            Poseidon2AirWrapperInner::KoalaBearD4Width32(air) => {
                assert_eq!(<$F>::from_u64(KOALA_BEAR_MODULUS), <$F>::ZERO);
                unsafe {
                    let b: &mut InteractionSymbolicBuilder<KoalaBear> =
                        core::mem::transmute($builder);
                    Air::eval(air.as_ref(), b);
                }
            }
            Poseidon2AirWrapperInner::GoldilocksD2Width8(air) => unsafe {
                let b: &mut InteractionSymbolicBuilder<
                    Goldilocks,
                    BinomialExtensionField<Goldilocks, 2>,
                > = core::mem::transmute($builder);
                Air::eval(air.as_ref(), b);
            },
            Poseidon2AirWrapperInner::GoldilocksD2Width16(air) => unsafe {
                let b: &mut InteractionSymbolicBuilder<
                    Goldilocks,
                    BinomialExtensionField<Goldilocks, 2>,
                > = core::mem::transmute($builder);
                Air::eval(air.as_ref(), b);
            },
        }
    };
}

macro_rules! eval_verifier_inner {
    ($inner:expr, $builder:expr, $local:expr, $next:expr, $prep:expr; ab=$ab:ty) => {
        match $inner {
            Poseidon2AirWrapperInner::BabyBearD1Width16Bus1(air) => unsafe {
                call_eval_variant!(BabyBearD1Width16, BabyBearConfig, BabyBear,
                    GenericPoseidon2LinearLayersBabyBear, $ab, 1;
                    air.as_ref(), $builder, $local, $next, $prep);
            },
            Poseidon2AirWrapperInner::BabyBearD1Width16Bus5(air) => unsafe {
                call_eval_variant!(BabyBearD1Width16, BabyBearConfig, BabyBear,
                    GenericPoseidon2LinearLayersBabyBear, $ab, 5;
                    air.as_ref(), $builder, $local, $next, $prep);
            },
            Poseidon2AirWrapperInner::BabyBearD4Width16(air) => unsafe {
                call_eval_variant!(BabyBearD4Width16, BabyBearConfig, BabyBear,
                    GenericPoseidon2LinearLayersBabyBear, $ab,
                    { <BabyBearD4Width16 as Poseidon2Params>::D };
                    air.as_ref(), $builder, $local, $next, $prep);
            },
            Poseidon2AirWrapperInner::BabyBearD4Width24(air) => unsafe {
                call_eval_variant!(BabyBearD4Width24, BabyBearConfig, BabyBear,
                    GenericPoseidon2LinearLayersBabyBear, $ab,
                    { <BabyBearD4Width24 as Poseidon2Params>::D };
                    air.as_ref(), $builder, $local, $next, $prep);
            },
            Poseidon2AirWrapperInner::BabyBearD4Width32(air) => unsafe {
                call_eval_variant!(BabyBearD4Width32, BabyBearConfig, BabyBear,
                    GenericPoseidon2LinearLayersBabyBear, $ab,
                    { <BabyBearD4Width32 as Poseidon2Params>::D };
                    air.as_ref(), $builder, $local, $next, $prep);
            },
            Poseidon2AirWrapperInner::KoalaBearD1Width16Bus1(air) => unsafe {
                call_eval_variant!(KoalaBearD1Width16, KoalaBearConfig, KoalaBear,
                    GenericPoseidon2LinearLayersKoalaBear, $ab, 1;
                    air.as_ref(), $builder, $local, $next, $prep);
            },
            Poseidon2AirWrapperInner::KoalaBearD1Width16Bus5(air) => unsafe {
                call_eval_variant!(KoalaBearD1Width16, KoalaBearConfig, KoalaBear,
                    GenericPoseidon2LinearLayersKoalaBear, $ab, 5;
                    air.as_ref(), $builder, $local, $next, $prep);
            },
            Poseidon2AirWrapperInner::KoalaBearD4Width16(air) => unsafe {
                call_eval_variant!(KoalaBearD4Width16, KoalaBearConfig, KoalaBear,
                    GenericPoseidon2LinearLayersKoalaBear, $ab,
                    { <KoalaBearD4Width16 as Poseidon2Params>::D };
                    air.as_ref(), $builder, $local, $next, $prep);
            },
            Poseidon2AirWrapperInner::KoalaBearD4Width24(air) => unsafe {
                call_eval_variant!(KoalaBearD4Width24, KoalaBearConfig, KoalaBear,
                    GenericPoseidon2LinearLayersKoalaBear, $ab,
                    { <KoalaBearD4Width24 as Poseidon2Params>::D };
                    air.as_ref(), $builder, $local, $next, $prep);
            },
            Poseidon2AirWrapperInner::KoalaBearD1Width32Bus1(air) => unsafe {
                call_eval_variant!(KoalaBearD1Width32, KoalaBearConfig, KoalaBear,
                    GenericPoseidon2LinearLayersKoalaBear, $ab, 1;
                    air.as_ref(), $builder, $local, $next, $prep);
            },
            Poseidon2AirWrapperInner::KoalaBearD1Width32Bus5(air) => unsafe {
                call_eval_variant!(KoalaBearD1Width32, KoalaBearConfig, KoalaBear,
                    GenericPoseidon2LinearLayersKoalaBear, $ab, 5;
                    air.as_ref(), $builder, $local, $next, $prep);
            },
            Poseidon2AirWrapperInner::KoalaBearD4Width32(air) => unsafe {
                call_eval_variant!(KoalaBearD4Width32, KoalaBearConfig, KoalaBear,
                    GenericPoseidon2LinearLayersKoalaBear, $ab,
                    { <KoalaBearD4Width32 as Poseidon2Params>::D };
                    air.as_ref(), $builder, $local, $next, $prep);
            },
            Poseidon2AirWrapperInner::GoldilocksD2Width8(air) => unsafe {
                call_eval_variant!(GoldilocksD2Width8, GoldilocksConfig, Goldilocks,
                    GenericPoseidon2LinearLayersGoldilocks, $ab,
                    { <GoldilocksD2Width8 as Poseidon2Params>::D };
                    air.as_ref(), $builder, $local, $next, $prep);
            },
            Poseidon2AirWrapperInner::GoldilocksD2Width16(air) => unsafe {
                call_eval_variant!(GoldilocksD2Width16, GoldilocksConfig, Goldilocks,
                    GenericPoseidon2LinearLayersGoldilocks, $ab,
                    { <GoldilocksD2Width16 as Poseidon2Params>::D };
                    air.as_ref(), $builder, $local, $next, $prep);
            },
        }
    };
}

macro_rules! preprocessed_trace_inner {
    ($inner:expr, $SC:ty) => {
        match $inner {
            Poseidon2AirWrapperInner::BabyBearD1Width16Bus1(air) => {
                assert_eq!(Val::<$SC>::from_u64(BABY_BEAR_MODULUS), Val::<$SC>::ZERO);
                let p = BaseAir::<BabyBear>::preprocessed_trace(air.as_ref())?;
                Some(unsafe { transmute::<RowMajorMatrix<BabyBear>, RowMajorMatrix<Val<$SC>>>(p) })
            }
            Poseidon2AirWrapperInner::BabyBearD1Width16Bus5(air) => {
                assert_eq!(Val::<$SC>::from_u64(BABY_BEAR_MODULUS), Val::<$SC>::ZERO);
                let p = BaseAir::<BabyBear>::preprocessed_trace(air.as_ref())?;
                Some(unsafe { transmute::<RowMajorMatrix<BabyBear>, RowMajorMatrix<Val<$SC>>>(p) })
            }
            Poseidon2AirWrapperInner::BabyBearD4Width16(air) => {
                assert_eq!(Val::<$SC>::from_u64(BABY_BEAR_MODULUS), Val::<$SC>::ZERO);
                let p = BaseAir::<BabyBear>::preprocessed_trace(air.as_ref())?;
                Some(unsafe { transmute::<RowMajorMatrix<BabyBear>, RowMajorMatrix<Val<$SC>>>(p) })
            }
            Poseidon2AirWrapperInner::BabyBearD4Width24(air) => {
                assert_eq!(Val::<$SC>::from_u64(BABY_BEAR_MODULUS), Val::<$SC>::ZERO);
                let p = BaseAir::<BabyBear>::preprocessed_trace(air.as_ref())?;
                Some(unsafe { transmute::<RowMajorMatrix<BabyBear>, RowMajorMatrix<Val<$SC>>>(p) })
            }
            Poseidon2AirWrapperInner::BabyBearD4Width32(air) => {
                assert_eq!(Val::<$SC>::from_u64(BABY_BEAR_MODULUS), Val::<$SC>::ZERO);
                let p = BaseAir::<BabyBear>::preprocessed_trace(air.as_ref())?;
                Some(unsafe { transmute::<RowMajorMatrix<BabyBear>, RowMajorMatrix<Val<$SC>>>(p) })
            }
            Poseidon2AirWrapperInner::KoalaBearD1Width16Bus1(air) => {
                assert_eq!(Val::<$SC>::from_u64(KOALA_BEAR_MODULUS), Val::<$SC>::ZERO);
                let p = BaseAir::<KoalaBear>::preprocessed_trace(air.as_ref())?;
                Some(unsafe { transmute::<RowMajorMatrix<KoalaBear>, RowMajorMatrix<Val<$SC>>>(p) })
            }
            Poseidon2AirWrapperInner::KoalaBearD1Width16Bus5(air) => {
                assert_eq!(Val::<$SC>::from_u64(KOALA_BEAR_MODULUS), Val::<$SC>::ZERO);
                let p = BaseAir::<KoalaBear>::preprocessed_trace(air.as_ref())?;
                Some(unsafe { transmute::<RowMajorMatrix<KoalaBear>, RowMajorMatrix<Val<$SC>>>(p) })
            }
            Poseidon2AirWrapperInner::KoalaBearD4Width16(air) => {
                assert_eq!(Val::<$SC>::from_u64(KOALA_BEAR_MODULUS), Val::<$SC>::ZERO);
                let p = BaseAir::<KoalaBear>::preprocessed_trace(air.as_ref())?;
                Some(unsafe { transmute::<RowMajorMatrix<KoalaBear>, RowMajorMatrix<Val<$SC>>>(p) })
            }
            Poseidon2AirWrapperInner::KoalaBearD4Width24(air) => {
                assert_eq!(Val::<$SC>::from_u64(KOALA_BEAR_MODULUS), Val::<$SC>::ZERO);
                let p = BaseAir::<KoalaBear>::preprocessed_trace(air.as_ref())?;
                Some(unsafe { transmute::<RowMajorMatrix<KoalaBear>, RowMajorMatrix<Val<$SC>>>(p) })
            }
            Poseidon2AirWrapperInner::KoalaBearD1Width32Bus1(air) => {
                assert_eq!(Val::<$SC>::from_u64(KOALA_BEAR_MODULUS), Val::<$SC>::ZERO);
                let p = BaseAir::<KoalaBear>::preprocessed_trace(air.as_ref())?;
                Some(unsafe { transmute::<RowMajorMatrix<KoalaBear>, RowMajorMatrix<Val<$SC>>>(p) })
            }
            Poseidon2AirWrapperInner::KoalaBearD1Width32Bus5(air) => {
                assert_eq!(Val::<$SC>::from_u64(KOALA_BEAR_MODULUS), Val::<$SC>::ZERO);
                let p = BaseAir::<KoalaBear>::preprocessed_trace(air.as_ref())?;
                Some(unsafe { transmute::<RowMajorMatrix<KoalaBear>, RowMajorMatrix<Val<$SC>>>(p) })
            }
            Poseidon2AirWrapperInner::KoalaBearD4Width32(air) => {
                assert_eq!(Val::<$SC>::from_u64(KOALA_BEAR_MODULUS), Val::<$SC>::ZERO);
                let p = BaseAir::<KoalaBear>::preprocessed_trace(air.as_ref())?;
                Some(unsafe { transmute::<RowMajorMatrix<KoalaBear>, RowMajorMatrix<Val<$SC>>>(p) })
            }
            Poseidon2AirWrapperInner::GoldilocksD2Width8(air) => {
                let p = BaseAir::<Goldilocks>::preprocessed_trace(air.as_ref())?;
                Some(unsafe {
                    transmute::<RowMajorMatrix<Goldilocks>, RowMajorMatrix<Val<$SC>>>(p)
                })
            }
            Poseidon2AirWrapperInner::GoldilocksD2Width16(air) => {
                let p = BaseAir::<Goldilocks>::preprocessed_trace(air.as_ref())?;
                Some(unsafe {
                    transmute::<RowMajorMatrix<Goldilocks>, RowMajorMatrix<Val<$SC>>>(p)
                })
            }
        }
    };
}

impl<SC> BaseAir<Val<SC>> for Poseidon2AirWrapper<SC>
where
    SC: StarkGenericConfig + Send + Sync,
    Val<SC>: StarkField,
{
    fn width(&self) -> usize {
        self.inner.width()
    }

    fn preprocessed_width(&self) -> usize {
        self.inner.preprocessed_width()
    }

    fn preprocessed_trace(&self) -> Option<RowMajorMatrix<Val<SC>>> {
        preprocessed_trace_inner!(&self.inner, SC)
    }
}

impl<SC> Air<InteractionSymbolicBuilder<Val<SC>, SC::Challenge>> for Poseidon2AirWrapper<SC>
where
    SC: StarkGenericConfig + Send + Sync,
    Val<SC>: StarkField,
{
    fn eval(&self, builder: &mut InteractionSymbolicBuilder<Val<SC>, SC::Challenge>) {
        eval_symbolic_inner!(&self.inner, builder, Val<SC>);
    }
}

impl<F: Field> BaseAir<F> for Poseidon2AirWrapperInner {
    fn width(&self) -> usize {
        Self::width(self)
    }

    fn preprocessed_width(&self) -> usize {
        Self::preprocessed_width(self)
    }
}

impl<F, EF> Air<InteractionSymbolicBuilder<F, EF>> for Poseidon2AirWrapperInner
where
    F: Field + PrimeField64,
    EF: ExtensionField<F>,
    SymbolicExpressionExt<F, EF>: Algebra<SymbolicExpression<F>>,
{
    fn eval(&self, builder: &mut InteractionSymbolicBuilder<F, EF>) {
        eval_symbolic_inner!(self, builder, F);
    }
}

pub fn poseidon2_verifier_air_from_config(config: Poseidon2Config) -> Poseidon2AirWrapperInner {
    Poseidon2Prover::air_wrapper_for_config(config)
}

pub(crate) fn poseidon2_artifact_air<SC>(
    config: Poseidon2Config,
    min_height: usize,
    circuit_extension_degree: u32,
) -> Option<DynamicAirEntry<SC>>
where
    SC: StarkGenericConfig + 'static + Send + Sync,
    Val<SC>: StarkField,
    SymbolicExpressionExt<Val<SC>, SC::Challenge>:
        Algebra<SymbolicExpression<Val<SC>>> + Algebra<SC::Challenge>,
{
    Poseidon2Prover::new(config, Default::default()).wrapper_from_config_with_preprocessed(
        Vec::new(),
        min_height,
        circuit_extension_degree,
    )
}

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
    const WITNESS_EXT_D: usize,
>(
    air: &Poseidon2CircuitAir<
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
        WITNESS_EXT_D,
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
            WITNESS_EXT_D,
        >(
            air,
            builder,
            local_slice,
            next_slice,
            next_preprocessed_slice,
        );
    }
}

impl<'a, SC> Air<ProverConstraintFolder<'a, SC>> for Poseidon2AirWrapper<SC>
where
    SC: StarkGenericConfig + Send + Sync,
    Val<SC>: StarkField + PrimeField,
    SymbolicExpressionExt<Val<SC>, SC::Challenge>: Algebra<SymbolicExpression<Val<SC>>>,
{
    fn eval(&self, builder: &mut ProverConstraintFolder<'a, SC>) {
        let main = builder.main();
        let local_slice = main.current_slice();
        let next_slice = main.next_slice();
        let preprocessed = *builder.preprocessed();
        let next_preprocessed_slice = preprocessed.next_slice();

        eval_folder_inner!(
            &self.inner, builder, local_slice, next_slice, next_preprocessed_slice;
            bb=ProverConstraintFolder<'a, BabyBearConfig>,
            kb=ProverConstraintFolder<'a, KoalaBearConfig>,
            gl=ProverConstraintFolder<'a, GoldilocksConfig>
        );
    }
}

impl<'a, SC> Air<ProverConstraintFolderWithLookups<'a, SC>> for Poseidon2AirWrapper<SC>
where
    SC: StarkGenericConfig + Send + Sync,
    Val<SC>: StarkField + PrimeField,
{
    fn eval(&self, builder: &mut ProverConstraintFolderWithLookups<'a, SC>) {
        let main = builder.main();
        let local_slice = main.current_slice();
        let next_slice = main.next_slice();
        let preprocessed = *builder.preprocessed();
        let next_preprocessed_slice = preprocessed.next_slice();

        eval_folder_inner!(
            &self.inner, builder, local_slice, next_slice, next_preprocessed_slice;
            bb=ProverConstraintFolderWithLookups<'a, BabyBearConfig>,
            kb=ProverConstraintFolderWithLookups<'a, KoalaBearConfig>,
            gl=ProverConstraintFolderWithLookups<'a, GoldilocksConfig>
        );
    }
}

impl<'a, SC> Air<VerifierConstraintFolder<'a, SC>> for Poseidon2AirWrapper<SC>
where
    SC: StarkGenericConfig + Send + Sync,
    Val<SC>: StarkField + PrimeField,
{
    fn eval(&self, builder: &mut VerifierConstraintFolder<'a, SC>) {
        let main = builder.main();
        let local_slice = main.current_slice();
        let next_slice = main.next_slice();
        let preprocessed = *builder.preprocessed();
        let next_preprocessed_slice = preprocessed.next_slice();

        eval_verifier_inner!(
            &self.inner, builder, &local_slice, &next_slice, &next_preprocessed_slice;
            ab=VerifierConstraintFolder<'a, SC>
        );
    }
}

impl<'a, SC> Air<VerifierConstraintFolderWithLookups<'a, SC>> for Poseidon2AirWrapper<SC>
where
    SC: StarkGenericConfig + Send + Sync,
    Val<SC>: StarkField + PrimeField,
{
    fn eval(&self, builder: &mut VerifierConstraintFolderWithLookups<'a, SC>) {
        let main = builder.main();
        let local_slice = main.current_slice();
        let next_slice = main.next_slice();
        let preprocessed = *builder.preprocessed();
        let next_preprocessed_slice = preprocessed.next_slice();

        eval_verifier_inner!(
            &self.inner, builder, &local_slice, &next_slice, &next_preprocessed_slice;
            ab=VerifierConstraintFolderWithLookups<'a, SC>
        );
    }
}

#[cfg(debug_assertions)]
impl<'a, SC> Air<DebugConstraintBuilder<'a, Val<SC>, SC::Challenge>> for Poseidon2AirWrapper<SC>
where
    SC: StarkGenericConfig + Send + Sync,
    Val<SC>: StarkField + PrimeField,
{
    fn eval(&self, builder: &mut DebugConstraintBuilder<'a, Val<SC>, SC::Challenge>) {
        let main = builder.main();
        let local_slice = main.current_slice();
        let next_slice = main.next_slice();
        let preprocessed = *builder.preprocessed();
        let next_preprocessed_slice = preprocessed.next_slice();

        eval_verifier_inner!(
            &self.inner, builder, &local_slice, &next_slice, &next_preprocessed_slice;
            ab=DebugConstraintBuilder<'a, Val<SC>, SC::Challenge>
        );
    }
}

#[derive(Clone)]
pub struct Poseidon2Prover {
    config: Poseidon2Config,
}

impl Poseidon2Prover {
    pub(crate) fn poseidon2_op_type(&self) -> NpoTypeId {
        NpoTypeId::poseidon2_perm(self.config)
    }

    pub const fn new(
        config: Poseidon2Config,
        _profile: crate::constraint_profile::ConstraintProfile,
    ) -> Self {
        Self { config }
    }

    pub(crate) fn air_wrapper_for_config(config: Poseidon2Config) -> Poseidon2AirWrapperInner {
        let inner = match config.without_challenger_role() {
            Poseidon2Config::BABY_BEAR_D1_W16 => Poseidon2AirWrapperInner::BabyBearD1Width16Bus1(
                Box::new(BabyBearD1Width16::default_air()),
            ),
            Poseidon2Config::BABY_BEAR_D4_W16 => Poseidon2AirWrapperInner::BabyBearD4Width16(
                Box::new(BabyBearD4Width16::default_air()),
            ),
            Poseidon2Config::BABY_BEAR_D4_W24 => Poseidon2AirWrapperInner::BabyBearD4Width24(
                Box::new(BabyBearD4Width24::default_air()),
            ),
            Poseidon2Config::BABY_BEAR_D4_W32 => Poseidon2AirWrapperInner::BabyBearD4Width32(
                Box::new(BabyBearD4Width32::default_air()),
            ),
            Poseidon2Config::KOALA_BEAR_D1_W16 => Poseidon2AirWrapperInner::KoalaBearD1Width16Bus1(
                Box::new(KoalaBearD1Width16::default_air()),
            ),
            Poseidon2Config::KOALA_BEAR_D4_W16 => Poseidon2AirWrapperInner::KoalaBearD4Width16(
                Box::new(KoalaBearD4Width16::default_air()),
            ),
            Poseidon2Config::KOALA_BEAR_D4_W24 => Poseidon2AirWrapperInner::KoalaBearD4Width24(
                Box::new(KoalaBearD4Width24::default_air()),
            ),
            Poseidon2Config::KOALA_BEAR_D1_W32 => Poseidon2AirWrapperInner::KoalaBearD1Width32Bus1(
                Box::new(KoalaBearD1Width32::default_air()),
            ),
            Poseidon2Config::KOALA_BEAR_D4_W32 => Poseidon2AirWrapperInner::KoalaBearD4Width32(
                Box::new(KoalaBearD4Width32::default_air()),
            ),
            Poseidon2Config::GOLDILOCKS_D2_W8 => Poseidon2AirWrapperInner::GoldilocksD2Width8(
                Box::new(goldilocks_d2_width8_default_air()),
            ),
            Poseidon2Config::GOLDILOCKS_D2_W16 => Poseidon2AirWrapperInner::GoldilocksD2Width16(
                Box::new(GoldilocksD2Width16::default_air()),
            ),
            // `Poseidon2Config` fields are private; only the seven public assoc
            // consts above can be constructed, so this is unreachable.
            _ => unreachable!("unsupported Poseidon2Config"),
        };
        inner
            .with_challenger_role(config.is_challenger())
            .with_shared_role(config.is_shared())
    }

    fn air_wrapper_for_config_with_preprocessed<F: Field>(
        config: Poseidon2Config,
        preprocessed: Vec<F>,
        min_height: usize,
        circuit_extension_degree: u32,
    ) -> Option<Poseidon2AirWrapperInner> {
        let inner = match config.without_challenger_role() {
            Poseidon2Config::BABY_BEAR_D1_W16 => {
                assert!(F::from_u64(BABY_BEAR_MODULUS) == F::ZERO);
                let prep = unsafe { transmute::<Vec<F>, Vec<BabyBear>>(preprocessed) };
                match poseidon_d1_witness_bus_dim(circuit_extension_degree)? {
                    1 => Poseidon2AirWrapperInner::BabyBearD1Width16Bus1(Box::new(
                        BabyBearD1Width16::default_air_with_preprocessed(prep, min_height),
                    )),
                    5 => Poseidon2AirWrapperInner::BabyBearD1Width16Bus5(Box::new(
                        BabyBearD1Width16::default_air_with_preprocessed_witness_bus5(
                            prep, min_height,
                        ),
                    )),
                    _ => unreachable!(),
                }
            }
            Poseidon2Config::BABY_BEAR_D4_W16 => {
                assert!(F::from_u64(BABY_BEAR_MODULUS) == F::ZERO);
                Poseidon2AirWrapperInner::BabyBearD4Width16(Box::new(
                    BabyBearD4Width16::default_air_with_preprocessed(
                        unsafe { transmute::<Vec<F>, Vec<BabyBear>>(preprocessed) },
                        min_height,
                    ),
                ))
            }
            Poseidon2Config::BABY_BEAR_D4_W24 => {
                assert!(F::from_u64(BABY_BEAR_MODULUS) == F::ZERO);
                Poseidon2AirWrapperInner::BabyBearD4Width24(Box::new(
                    BabyBearD4Width24::default_air_with_preprocessed(
                        unsafe { transmute::<Vec<F>, Vec<BabyBear>>(preprocessed) },
                        min_height,
                    ),
                ))
            }
            Poseidon2Config::BABY_BEAR_D4_W32 => {
                assert!(F::from_u64(BABY_BEAR_MODULUS) == F::ZERO);
                Poseidon2AirWrapperInner::BabyBearD4Width32(Box::new(
                    BabyBearD4Width32::default_air_with_preprocessed(
                        unsafe { transmute::<Vec<F>, Vec<BabyBear>>(preprocessed) },
                        min_height,
                    ),
                ))
            }
            Poseidon2Config::KOALA_BEAR_D1_W16 => {
                assert!(F::from_u64(KOALA_BEAR_MODULUS) == F::ZERO);
                let prep = unsafe { transmute::<Vec<F>, Vec<KoalaBear>>(preprocessed) };
                match poseidon_d1_witness_bus_dim(circuit_extension_degree)? {
                    1 => Poseidon2AirWrapperInner::KoalaBearD1Width16Bus1(Box::new(
                        KoalaBearD1Width16::default_air_with_preprocessed(prep, min_height),
                    )),
                    5 => Poseidon2AirWrapperInner::KoalaBearD1Width16Bus5(Box::new(
                        KoalaBearD1Width16::default_air_with_preprocessed_witness_bus5(
                            prep, min_height,
                        ),
                    )),
                    _ => unreachable!(),
                }
            }
            Poseidon2Config::KOALA_BEAR_D4_W16 => {
                assert!(F::from_u64(KOALA_BEAR_MODULUS) == F::ZERO);
                Poseidon2AirWrapperInner::KoalaBearD4Width16(Box::new(
                    KoalaBearD4Width16::default_air_with_preprocessed(
                        unsafe { transmute::<Vec<F>, Vec<KoalaBear>>(preprocessed) },
                        min_height,
                    ),
                ))
            }
            Poseidon2Config::KOALA_BEAR_D4_W24 => {
                assert!(F::from_u64(KOALA_BEAR_MODULUS) == F::ZERO);
                Poseidon2AirWrapperInner::KoalaBearD4Width24(Box::new(
                    KoalaBearD4Width24::default_air_with_preprocessed(
                        unsafe { transmute::<Vec<F>, Vec<KoalaBear>>(preprocessed) },
                        min_height,
                    ),
                ))
            }
            Poseidon2Config::KOALA_BEAR_D1_W32 => {
                assert!(F::from_u64(KOALA_BEAR_MODULUS) == F::ZERO);
                let prep = unsafe { transmute::<Vec<F>, Vec<KoalaBear>>(preprocessed) };
                match poseidon_d1_witness_bus_dim(circuit_extension_degree)? {
                    1 => Poseidon2AirWrapperInner::KoalaBearD1Width32Bus1(Box::new(
                        KoalaBearD1Width32::default_air_with_preprocessed(prep, min_height),
                    )),
                    5 => Poseidon2AirWrapperInner::KoalaBearD1Width32Bus5(Box::new(
                        KoalaBearD1Width32::default_air_with_preprocessed_witness_bus5(
                            prep, min_height,
                        ),
                    )),
                    _ => unreachable!(),
                }
            }
            Poseidon2Config::KOALA_BEAR_D4_W32 => {
                assert!(F::from_u64(KOALA_BEAR_MODULUS) == F::ZERO);
                Poseidon2AirWrapperInner::KoalaBearD4Width32(Box::new(
                    KoalaBearD4Width32::default_air_with_preprocessed(
                        unsafe { transmute::<Vec<F>, Vec<KoalaBear>>(preprocessed) },
                        min_height,
                    ),
                ))
            }
            Poseidon2Config::GOLDILOCKS_D2_W8 => Poseidon2AirWrapperInner::GoldilocksD2Width8(
                Box::new(goldilocks_d2_width8_default_air_with_preprocessed(
                    unsafe { transmute::<Vec<F>, Vec<Goldilocks>>(preprocessed) },
                    min_height,
                )),
            ),
            Poseidon2Config::GOLDILOCKS_D2_W16 => Poseidon2AirWrapperInner::GoldilocksD2Width16(
                Box::new(GoldilocksD2Width16::default_air_with_preprocessed(
                    unsafe { transmute::<Vec<F>, Vec<Goldilocks>>(preprocessed) },
                    min_height,
                )),
            ),
            _ => unreachable!("unsupported Poseidon2Config"),
        };
        Some(
            inner
                .with_challenger_role(config.is_challenger())
                .with_shared_role(config.is_shared()),
        )
    }

    pub fn wrapper_from_config_with_preprocessed<SC>(
        &self,
        preprocessed: Vec<Val<SC>>,
        min_height: usize,
        circuit_extension_degree: u32,
    ) -> Option<DynamicAirEntry<SC>>
    where
        SC: StarkGenericConfig + 'static + Send + Sync,
        Val<SC>: StarkField,
        SymbolicExpressionExt<Val<SC>, SC::Challenge>:
            Algebra<SymbolicExpression<Val<SC>>> + Algebra<SC::Challenge>,
    {
        let inner = Self::air_wrapper_for_config_with_preprocessed::<Val<SC>>(
            self.config,
            preprocessed,
            min_height,
            circuit_extension_degree,
        )?;
        Some(DynamicAirEntry::new(Box::new(Poseidon2AirWrapper {
            inner,
            _phantom: core::marker::PhantomData::<SC>,
        })))
    }

    pub const fn preprocessed_width_from_config(&self) -> usize {
        match self.config.without_challenger_role() {
            Poseidon2Config::BABY_BEAR_D1_W16 => {
                Poseidon2CircuitAirBabyBearD1Width16::preprocessed_width()
            }
            Poseidon2Config::BABY_BEAR_D4_W16 => {
                Poseidon2CircuitAirBabyBearD4Width16::preprocessed_width()
            }
            Poseidon2Config::BABY_BEAR_D4_W24 => {
                Poseidon2CircuitAirBabyBearD4Width24::preprocessed_width()
            }
            Poseidon2Config::BABY_BEAR_D4_W32 => {
                Poseidon2CircuitAirBabyBearD4Width32::preprocessed_width()
            }
            Poseidon2Config::KOALA_BEAR_D1_W16 => {
                Poseidon2CircuitAirKoalaBearD1Width16::preprocessed_width()
            }
            Poseidon2Config::KOALA_BEAR_D4_W16 => {
                Poseidon2CircuitAirKoalaBearD4Width16::preprocessed_width()
            }
            Poseidon2Config::KOALA_BEAR_D4_W24 => {
                Poseidon2CircuitAirKoalaBearD4Width24::preprocessed_width()
            }
            Poseidon2Config::KOALA_BEAR_D1_W32 => {
                Poseidon2CircuitAirKoalaBearD1Width32::preprocessed_width()
            }
            Poseidon2Config::KOALA_BEAR_D4_W32 => {
                Poseidon2CircuitAirKoalaBearD4Width32::preprocessed_width()
            }
            Poseidon2Config::GOLDILOCKS_D2_W8 => {
                Poseidon2CircuitAirGoldilocksD2Width8::preprocessed_width()
            }
            Poseidon2Config::GOLDILOCKS_D2_W16 => {
                Poseidon2CircuitAirGoldilocksD2Width16::preprocessed_width()
            }
            _ => panic!("unsupported Poseidon2Config"),
        }
    }

    pub const fn main_width_from_config(&self) -> usize {
        match self.config.without_challenger_role() {
            Poseidon2Config::BABY_BEAR_D1_W16 => Poseidon2CircuitAirBabyBearD1Width16::main_width(),
            Poseidon2Config::BABY_BEAR_D4_W16 => Poseidon2CircuitAirBabyBearD4Width16::main_width(),
            Poseidon2Config::BABY_BEAR_D4_W24 => Poseidon2CircuitAirBabyBearD4Width24::main_width(),
            Poseidon2Config::BABY_BEAR_D4_W32 => Poseidon2CircuitAirBabyBearD4Width32::main_width(),
            Poseidon2Config::KOALA_BEAR_D1_W16 => {
                Poseidon2CircuitAirKoalaBearD1Width16::main_width()
            }
            Poseidon2Config::KOALA_BEAR_D4_W16 => {
                Poseidon2CircuitAirKoalaBearD4Width16::main_width()
            }
            Poseidon2Config::KOALA_BEAR_D4_W24 => {
                Poseidon2CircuitAirKoalaBearD4Width24::main_width()
            }
            Poseidon2Config::KOALA_BEAR_D1_W32 => {
                Poseidon2CircuitAirKoalaBearD1Width32::main_width()
            }
            Poseidon2Config::KOALA_BEAR_D4_W32 => {
                Poseidon2CircuitAirKoalaBearD4Width32::main_width()
            }
            Poseidon2Config::GOLDILOCKS_D2_W8 => {
                Poseidon2CircuitAirGoldilocksD2Width8::main_width()
            }
            Poseidon2Config::GOLDILOCKS_D2_W16 => {
                Poseidon2CircuitAirGoldilocksD2Width16::main_width()
            }
            _ => panic!("unsupported Poseidon2Config"),
        }
    }

    fn batch_instance_from_traces<SC, CF>(
        &self,
        _config: &SC,
        packing: &TablePacking,
        traces: &Traces<CF>,
    ) -> Option<BatchTableInstance<SC>>
    where
        SC: StarkGenericConfig + 'static + Send + Sync,
        Val<SC>: StarkField,
        CF: Field + ExtensionField<Val<SC>> + BasedVectorSpace<Val<SC>>,
        SymbolicExpressionExt<Val<SC>, SC::Challenge>:
            Algebra<SymbolicExpression<Val<SC>>> + Algebra<SC::Challenge>,
    {
        let op_type = NpoTypeId::poseidon2_perm(self.config);
        let operations = if self.config.is_shared() {
            let mut operations = Vec::new();
            for source in self.config.source_configs() {
                let source_id = NpoTypeId::poseidon2_perm(source);
                let Some(source_trace) =
                    traces.non_primitive_trace::<Poseidon2Trace<Val<SC>>>(&source_id)
                else {
                    continue;
                };
                if source_trace.operations.is_empty() {
                    continue;
                }
                // Each independently generated stream must begin a chain. This is also the
                // condition that keeps MMCS terminal multiplicities unchanged at the merge seam.
                debug_assert!(source_trace.operations[0].new_start);
                let challenger = source.is_challenger();
                operations.extend(source_trace.operations.iter().cloned().map(|mut row| {
                    row.challenger = challenger;
                    row
                }));
            }
            operations
        } else {
            traces
                .non_primitive_trace::<Poseidon2Trace<Val<SC>>>(&op_type)?
                .operations
                .clone()
        };
        if operations.is_empty() {
            return None;
        }

        let min_height = packing
            .npo_min_height(&op_type)
            .unwrap_or_else(|| packing.min_trace_height());
        let witness_ctl_scale = <CF as BasedVectorSpace<Val<SC>>>::DIMENSION as u32;
        self.batch_instance_base_impl::<SC>(operations, min_height, witness_ctl_scale)
    }

    fn batch_instance_base_impl<SC>(
        &self,
        operations: Vec<Poseidon2CircuitRow<Val<SC>>>,
        min_height: usize,
        witness_ctl_scale: u32,
    ) -> Option<BatchTableInstance<SC>>
    where
        SC: StarkGenericConfig + 'static + Send + Sync,
        Val<SC>: StarkField,
        SymbolicExpressionExt<Val<SC>, SC::Challenge>:
            Algebra<SymbolicExpression<Val<SC>>> + Algebra<SC::Challenge>,
    {
        let cfg = self.config;
        let rows = operations.len();

        // Pad logical ops to the larger of (next power-of-two of row count) and `min_height`.
        let padded_rows = rows.next_power_of_two().max(min_height.next_power_of_two());
        let width = cfg.width();
        let width_ext = cfg.width_ext();
        let rate_ext = cfg.rate_ext();
        // Must match `Poseidon2CircuitAir::preprocessed_trace`: first padded row is a sponge
        // chain boundary (`new_start` in preprocessed) with zero state. Duplicating the last real
        // row would leave non-zero capacity inputs and break compact D=1 constraints that assert
        // zero capacity on sponge `new_start` transitions.
        let pad_filler = Poseidon2CircuitRow {
            challenger: false,
            new_start: true,
            merkle_path: false,
            mmcs_bit: false,
            mmcs_bit2: false,
            mmcs_index_sum: Val::<SC>::ZERO,
            input_values: Val::<SC>::zero_vec(width).into(),
            in_ctl: vec![false; width_ext].into(),
            input_indices: vec![0; width_ext].into(),
            out_ctl: vec![false; rate_ext].into(),
            output_indices: vec![0; rate_ext].into(),
            mmcs_index_sum_idx: 0,
            mmcs_ctl_enabled: false,
            absorb_len: 0,
        };
        let mut padded_ops = operations;
        padded_ops.resize(padded_rows, pad_filler);

        let (air, matrix) = match cfg.without_challenger_role() {
            Poseidon2Config::BABY_BEAR_D1_W16 => {
                let constants = BabyBearD1Width16::round_constants();
                let wbus = poseidon_d1_witness_bus_dim(witness_ctl_scale)?;
                let preprocessed =
                    extract_preprocessed_from_operations_with_role::<16, 8, BabyBear, Val<SC>>(
                        &padded_ops[..rows],
                        witness_ctl_scale,
                        1,
                        cfg.is_challenger(),
                        cfg.is_shared(),
                    );
                let (inner, matrix_f) = match wbus {
                    1 => {
                        let air = BabyBearD1Width16::default_air_with_preprocessed(
                            preprocessed,
                            min_height,
                        );
                        let ops: Vec<Poseidon2CircuitRow<BabyBear>> =
                            unsafe { transmute(padded_ops) };
                        let matrix_f = air.generate_trace_rows(&ops, &constants, 0);
                        (
                            Poseidon2AirWrapperInner::BabyBearD1Width16Bus1(Box::new(air)),
                            matrix_f,
                        )
                    }
                    5 => {
                        let air = BabyBearD1Width16::default_air_with_preprocessed_witness_bus5(
                            preprocessed,
                            min_height,
                        );
                        let ops: Vec<Poseidon2CircuitRow<BabyBear>> =
                            unsafe { transmute(padded_ops) };
                        let matrix_f = air.generate_trace_rows(&ops, &constants, 0);
                        (
                            Poseidon2AirWrapperInner::BabyBearD1Width16Bus5(Box::new(air)),
                            matrix_f,
                        )
                    }
                    _ => unreachable!(),
                };
                let matrix: RowMajorMatrix<Val<SC>> = unsafe { transmute(matrix_f) };
                (
                    Poseidon2AirWrapper {
                        inner,
                        _phantom: core::marker::PhantomData::<SC>,
                    },
                    matrix,
                )
            }
            Poseidon2Config::BABY_BEAR_D4_W16 => {
                let constants = BabyBearD4Width16::round_constants();
                let preprocessed =
                    extract_preprocessed_from_operations_with_role::<4, 2, BabyBear, Val<SC>>(
                        &padded_ops[..rows],
                        witness_ctl_scale,
                        cfg.d(),
                        cfg.is_challenger(),
                        cfg.is_shared(),
                    );
                let air =
                    BabyBearD4Width16::default_air_with_preprocessed(preprocessed, min_height);
                let ops: Vec<Poseidon2CircuitRow<BabyBear>> = unsafe { transmute(padded_ops) };
                let matrix_f = air.generate_trace_rows(&ops, &constants, 0);
                let matrix: RowMajorMatrix<Val<SC>> = unsafe { transmute(matrix_f) };
                (
                    Poseidon2AirWrapper {
                        inner: Poseidon2AirWrapperInner::BabyBearD4Width16(Box::new(air)),
                        _phantom: core::marker::PhantomData::<SC>,
                    },
                    matrix,
                )
            }
            Poseidon2Config::BABY_BEAR_D4_W24 => {
                let constants = BabyBearD4Width24::round_constants();
                let preprocessed =
                    extract_preprocessed_from_operations_with_role::<6, 4, BabyBear, Val<SC>>(
                        &padded_ops[..rows],
                        witness_ctl_scale,
                        cfg.d(),
                        cfg.is_challenger(),
                        cfg.is_shared(),
                    );
                let air =
                    BabyBearD4Width24::default_air_with_preprocessed(preprocessed, min_height);
                let ops: Vec<Poseidon2CircuitRow<BabyBear>> = unsafe { transmute(padded_ops) };
                let matrix_f = air.generate_trace_rows(&ops, &constants, 0);
                let matrix: RowMajorMatrix<Val<SC>> = unsafe { transmute(matrix_f) };
                (
                    Poseidon2AirWrapper {
                        inner: Poseidon2AirWrapperInner::BabyBearD4Width24(Box::new(air)),
                        _phantom: core::marker::PhantomData::<SC>,
                    },
                    matrix,
                )
            }
            Poseidon2Config::BABY_BEAR_D4_W32 => {
                let constants = BabyBearD4Width32::round_constants();
                let preprocessed =
                    extract_preprocessed_from_operations_with_role::<8, 6, BabyBear, Val<SC>>(
                        &padded_ops[..rows],
                        witness_ctl_scale,
                        cfg.d(),
                        cfg.is_challenger(),
                        cfg.is_shared(),
                    );
                let air =
                    BabyBearD4Width32::default_air_with_preprocessed(preprocessed, min_height);
                let ops: Vec<Poseidon2CircuitRow<BabyBear>> = unsafe { transmute(padded_ops) };
                let matrix_f = air.generate_trace_rows(&ops, &constants, 0);
                let matrix: RowMajorMatrix<Val<SC>> = unsafe { transmute(matrix_f) };
                (
                    Poseidon2AirWrapper {
                        inner: Poseidon2AirWrapperInner::BabyBearD4Width32(Box::new(air)),
                        _phantom: core::marker::PhantomData::<SC>,
                    },
                    matrix,
                )
            }
            Poseidon2Config::KOALA_BEAR_D1_W16 => {
                let constants = KoalaBearD1Width16::round_constants();
                let wbus = poseidon_d1_witness_bus_dim(witness_ctl_scale)?;
                let preprocessed =
                    extract_preprocessed_from_operations_with_role::<16, 8, KoalaBear, Val<SC>>(
                        &padded_ops[..rows],
                        witness_ctl_scale,
                        1,
                        cfg.is_challenger(),
                        cfg.is_shared(),
                    );
                let (inner, matrix_f) = match wbus {
                    1 => {
                        let air = KoalaBearD1Width16::default_air_with_preprocessed(
                            preprocessed,
                            min_height,
                        );
                        let ops: Vec<Poseidon2CircuitRow<KoalaBear>> =
                            unsafe { transmute(padded_ops) };
                        let matrix_f = air.generate_trace_rows(&ops, &constants, 0);
                        (
                            Poseidon2AirWrapperInner::KoalaBearD1Width16Bus1(Box::new(air)),
                            matrix_f,
                        )
                    }
                    5 => {
                        let air = KoalaBearD1Width16::default_air_with_preprocessed_witness_bus5(
                            preprocessed,
                            min_height,
                        );
                        let ops: Vec<Poseidon2CircuitRow<KoalaBear>> =
                            unsafe { transmute(padded_ops) };
                        let matrix_f = air.generate_trace_rows(&ops, &constants, 0);
                        (
                            Poseidon2AirWrapperInner::KoalaBearD1Width16Bus5(Box::new(air)),
                            matrix_f,
                        )
                    }
                    _ => unreachable!(),
                };
                let matrix: RowMajorMatrix<Val<SC>> = unsafe { transmute(matrix_f) };
                (
                    Poseidon2AirWrapper {
                        inner,
                        _phantom: core::marker::PhantomData::<SC>,
                    },
                    matrix,
                )
            }
            Poseidon2Config::KOALA_BEAR_D4_W16 => {
                let constants = KoalaBearD4Width16::round_constants();
                let preprocessed =
                    extract_preprocessed_from_operations_with_role::<4, 2, KoalaBear, Val<SC>>(
                        &padded_ops[..rows],
                        witness_ctl_scale,
                        cfg.d(),
                        cfg.is_challenger(),
                        cfg.is_shared(),
                    );
                let air =
                    KoalaBearD4Width16::default_air_with_preprocessed(preprocessed, min_height);
                let ops: Vec<Poseidon2CircuitRow<KoalaBear>> = unsafe { transmute(padded_ops) };
                let matrix_f = air.generate_trace_rows(&ops, &constants, 0);
                let matrix: RowMajorMatrix<Val<SC>> = unsafe { transmute(matrix_f) };
                (
                    Poseidon2AirWrapper {
                        inner: Poseidon2AirWrapperInner::KoalaBearD4Width16(Box::new(air)),
                        _phantom: core::marker::PhantomData::<SC>,
                    },
                    matrix,
                )
            }
            Poseidon2Config::KOALA_BEAR_D4_W24 => {
                let constants = KoalaBearD4Width24::round_constants();
                let preprocessed =
                    extract_preprocessed_from_operations_with_role::<6, 4, KoalaBear, Val<SC>>(
                        &padded_ops[..rows],
                        witness_ctl_scale,
                        cfg.d(),
                        cfg.is_challenger(),
                        cfg.is_shared(),
                    );
                let air =
                    KoalaBearD4Width24::default_air_with_preprocessed(preprocessed, min_height);
                let ops: Vec<Poseidon2CircuitRow<KoalaBear>> = unsafe { transmute(padded_ops) };
                let matrix_f = air.generate_trace_rows(&ops, &constants, 0);
                let matrix: RowMajorMatrix<Val<SC>> = unsafe { transmute(matrix_f) };
                (
                    Poseidon2AirWrapper {
                        inner: Poseidon2AirWrapperInner::KoalaBearD4Width24(Box::new(air)),
                        _phantom: core::marker::PhantomData::<SC>,
                    },
                    matrix,
                )
            }
            Poseidon2Config::KOALA_BEAR_D1_W32 => {
                let constants = KoalaBearD1Width32::round_constants();
                let wbus = poseidon_d1_witness_bus_dim(witness_ctl_scale)?;
                let preprocessed =
                    extract_preprocessed_from_operations_with_role::<32, 24, KoalaBear, Val<SC>>(
                        &padded_ops[..rows],
                        witness_ctl_scale,
                        1,
                        cfg.is_challenger(),
                        cfg.is_shared(),
                    );
                let (inner, matrix_f) = match wbus {
                    1 => {
                        let air = KoalaBearD1Width32::default_air_with_preprocessed(
                            preprocessed,
                            min_height,
                        );
                        let ops: Vec<Poseidon2CircuitRow<KoalaBear>> =
                            unsafe { transmute(padded_ops) };
                        let matrix_f = air.generate_trace_rows(&ops, &constants, 0);
                        (
                            Poseidon2AirWrapperInner::KoalaBearD1Width32Bus1(Box::new(air)),
                            matrix_f,
                        )
                    }
                    5 => {
                        let air = KoalaBearD1Width32::default_air_with_preprocessed_witness_bus5(
                            preprocessed,
                            min_height,
                        );
                        let ops: Vec<Poseidon2CircuitRow<KoalaBear>> =
                            unsafe { transmute(padded_ops) };
                        let matrix_f = air.generate_trace_rows(&ops, &constants, 0);
                        (
                            Poseidon2AirWrapperInner::KoalaBearD1Width32Bus5(Box::new(air)),
                            matrix_f,
                        )
                    }
                    _ => unreachable!(),
                };
                let matrix: RowMajorMatrix<Val<SC>> = unsafe { transmute(matrix_f) };
                (
                    Poseidon2AirWrapper {
                        inner,
                        _phantom: core::marker::PhantomData::<SC>,
                    },
                    matrix,
                )
            }
            Poseidon2Config::KOALA_BEAR_D4_W32 => {
                let constants = KoalaBearD4Width32::round_constants();
                let preprocessed =
                    extract_preprocessed_from_operations_with_role::<8, 6, KoalaBear, Val<SC>>(
                        &padded_ops[..rows],
                        witness_ctl_scale,
                        cfg.d(),
                        cfg.is_challenger(),
                        cfg.is_shared(),
                    );
                let air =
                    KoalaBearD4Width32::default_air_with_preprocessed(preprocessed, min_height);
                let ops: Vec<Poseidon2CircuitRow<KoalaBear>> = unsafe { transmute(padded_ops) };
                let matrix_f = air.generate_trace_rows(&ops, &constants, 0);
                let matrix: RowMajorMatrix<Val<SC>> = unsafe { transmute(matrix_f) };
                (
                    Poseidon2AirWrapper {
                        inner: Poseidon2AirWrapperInner::KoalaBearD4Width32(Box::new(air)),
                        _phantom: core::marker::PhantomData::<SC>,
                    },
                    matrix,
                )
            }
            Poseidon2Config::GOLDILOCKS_D2_W8 => {
                let constants = goldilocks_d2_width8_round_constants();
                let preprocessed =
                    extract_preprocessed_from_operations_with_role::<4, 2, Goldilocks, Val<SC>>(
                        &padded_ops[..rows],
                        witness_ctl_scale,
                        cfg.d(),
                        cfg.is_challenger(),
                        cfg.is_shared(),
                    );
                let air =
                    goldilocks_d2_width8_default_air_with_preprocessed(preprocessed, min_height);
                let ops: Vec<Poseidon2CircuitRow<Goldilocks>> = unsafe { transmute(padded_ops) };
                let matrix_f = air.generate_trace_rows(&ops, &constants, 0);
                let matrix: RowMajorMatrix<Val<SC>> = unsafe { transmute(matrix_f) };
                (
                    Poseidon2AirWrapper {
                        inner: Poseidon2AirWrapperInner::GoldilocksD2Width8(Box::new(air)),
                        _phantom: core::marker::PhantomData::<SC>,
                    },
                    matrix,
                )
            }
            Poseidon2Config::GOLDILOCKS_D2_W16 => {
                let constants = goldilocks_d2_width16_round_constants();
                let preprocessed =
                    extract_preprocessed_from_operations_with_role::<8, 6, Goldilocks, Val<SC>>(
                        &padded_ops[..rows],
                        witness_ctl_scale,
                        cfg.d(),
                        cfg.is_challenger(),
                        cfg.is_shared(),
                    );
                let air =
                    GoldilocksD2Width16::default_air_with_preprocessed(preprocessed, min_height);
                let ops: Vec<Poseidon2CircuitRow<Goldilocks>> = unsafe { transmute(padded_ops) };
                let matrix_f = air.generate_trace_rows(&ops, &constants, 0);
                let matrix: RowMajorMatrix<Val<SC>> = unsafe { transmute(matrix_f) };
                (
                    Poseidon2AirWrapper {
                        inner: Poseidon2AirWrapperInner::GoldilocksD2Width16(Box::new(air)),
                        _phantom: core::marker::PhantomData::<SC>,
                    },
                    matrix,
                )
            }
            _ => unreachable!("unsupported Poseidon2Config"),
        };

        Some(BatchTableInstance {
            op_type: NpoTypeId::poseidon2_perm(self.config),
            air: DynamicAirEntry::new(Box::new(air)),
            trace: matrix,
            public_values: Vec::new(),
            rows: padded_rows,
            lanes: 1,
        })
    }
}

impl<SC> TableProver<SC> for Poseidon2Prover
where
    SC: StarkGenericConfig + 'static + Send + Sync,
    Val<SC>: StarkField + BinomiallyExtendable<4>,
    SymbolicExpressionExt<Val<SC>, SC::Challenge>:
        Algebra<SymbolicExpression<Val<SC>>> + Algebra<SC::Challenge>,
{
    fn op_type(&self) -> NpoTypeId {
        self.poseidon2_op_type()
    }

    fn source_op_types(&self) -> Vec<NpoTypeId> {
        if self.config.is_shared() {
            self.config
                .source_configs()
                .into_iter()
                .map(NpoTypeId::poseidon2_perm)
                .collect()
        } else {
            vec![self.poseidon2_op_type()]
        }
    }

    fn batch_instance_d1(
        &self,
        config: &SC,
        packing: &TablePacking,
        traces: &Traces<Val<SC>>,
    ) -> Option<BatchTableInstance<SC>> {
        self.batch_instance_from_traces::<SC, Val<SC>>(config, packing, traces)
    }

    fn batch_instance_d2(
        &self,
        _config: &SC,
        _packing: &TablePacking,
        _traces: &Traces<BinomialExtensionField<Val<SC>, 2>>,
    ) -> Option<BatchTableInstance<SC>> {
        None
    }

    fn batch_instance_d4(
        &self,
        config: &SC,
        packing: &TablePacking,
        traces: &Traces<BinomialExtensionField<Val<SC>, 4>>,
    ) -> Option<BatchTableInstance<SC>> {
        self.batch_instance_from_traces::<SC, BinomialExtensionField<Val<SC>, 4>>(
            config, packing, traces,
        )
    }

    fn batch_instance_d5(
        &self,
        _config: &SC,
        packing: &TablePacking,
        traces: &Traces<QuinticTrinomialExtensionField<Val<SC>>>,
    ) -> Option<BatchTableInstance<SC>> {
        let op_type = NpoTypeId::poseidon2_perm(self.config);
        let t = traces.non_primitive_trace::<Poseidon2Trace<Val<SC>>>(&op_type)?;
        let rows = t.total_rows();
        if rows == 0 {
            return None;
        }
        let min_height = packing
            .npo_min_height(&op_type)
            .unwrap_or_else(|| packing.min_trace_height());
        self.batch_instance_base_impl::<SC>(t.operations.clone(), min_height, 5)
    }

    fn batch_instance_d6(
        &self,
        config: &SC,
        packing: &TablePacking,
        traces: &Traces<BinomialExtensionField<Val<SC>, 6>>,
    ) -> Option<BatchTableInstance<SC>> {
        let _ = (config, packing, traces);
        None
    }

    fn batch_instance_d8(
        &self,
        config: &SC,
        packing: &TablePacking,
        traces: &Traces<BinomialExtensionField<Val<SC>, 8>>,
    ) -> Option<BatchTableInstance<SC>> {
        let _ = (config, packing, traces);
        None
    }

    fn batch_air_from_table_entry(
        &self,
        _config: &SC,
        _degree: usize,
        circuit_extension_degree: u32,
        _table_entry: &NonPrimitiveTableEntry<SC>,
    ) -> Result<DynamicAirEntry<SC>, String> {
        self.wrapper_from_config_with_preprocessed(Vec::new(), 1, circuit_extension_degree)
            .ok_or_else(|| {
                format!(
                    "unsupported witness bus dimension {} for Poseidon2 config {:?}",
                    circuit_extension_degree, self.config
                )
            })
    }

    fn air_with_committed_preprocessed(
        &self,
        committed_prep: Vec<Val<SC>>,
        min_height: usize,
        _lanes: usize,
        circuit_extension_degree: u32,
    ) -> Option<DynamicAirEntry<SC>> {
        self.wrapper_from_config_with_preprocessed(
            committed_prep,
            min_height,
            circuit_extension_degree,
        )
    }
}
pub struct Poseidon2ProverD2(pub(crate) Poseidon2Prover);

impl Poseidon2ProverD2 {
    pub const fn new(
        config: Poseidon2Config,
        profile: crate::constraint_profile::ConstraintProfile,
    ) -> Self {
        Self(Poseidon2Prover::new(config, profile))
    }
}

impl<SC> TableProver<SC> for Poseidon2ProverD2
where
    SC: StarkGenericConfig + 'static + Send + Sync,
    Val<SC>: StarkField + BinomiallyExtendable<2>,
    SymbolicExpressionExt<Val<SC>, SC::Challenge>:
        Algebra<SymbolicExpression<Val<SC>>> + Algebra<SC::Challenge>,
{
    fn op_type(&self) -> NpoTypeId {
        self.0.poseidon2_op_type()
    }

    fn source_op_types(&self) -> Vec<NpoTypeId> {
        if self.0.config.is_shared() {
            self.0
                .config
                .source_configs()
                .into_iter()
                .map(NpoTypeId::poseidon2_perm)
                .collect()
        } else {
            vec![self.0.poseidon2_op_type()]
        }
    }

    fn batch_instance_d1(
        &self,
        _config: &SC,
        _packing: &TablePacking,
        _traces: &Traces<Val<SC>>,
    ) -> Option<BatchTableInstance<SC>> {
        None
    }

    fn batch_instance_d2(
        &self,
        config: &SC,
        packing: &TablePacking,
        traces: &Traces<BinomialExtensionField<Val<SC>, 2>>,
    ) -> Option<BatchTableInstance<SC>> {
        self.0
            .batch_instance_from_traces::<SC, BinomialExtensionField<Val<SC>, 2>>(
                config, packing, traces,
            )
    }

    fn batch_instance_d4(
        &self,
        _config: &SC,
        _packing: &TablePacking,
        _traces: &Traces<BinomialExtensionField<Val<SC>, 4>>,
    ) -> Option<BatchTableInstance<SC>> {
        None
    }

    fn batch_instance_d6(
        &self,
        _config: &SC,
        _packing: &TablePacking,
        _traces: &Traces<BinomialExtensionField<Val<SC>, 6>>,
    ) -> Option<BatchTableInstance<SC>> {
        None
    }

    fn batch_instance_d8(
        &self,
        _config: &SC,
        _packing: &TablePacking,
        _traces: &Traces<BinomialExtensionField<Val<SC>, 8>>,
    ) -> Option<BatchTableInstance<SC>> {
        None
    }

    fn batch_air_from_table_entry(
        &self,
        _config: &SC,
        _degree: usize,
        circuit_extension_degree: u32,
        _table_entry: &NonPrimitiveTableEntry<SC>,
    ) -> Result<DynamicAirEntry<SC>, String> {
        self.0
            .wrapper_from_config_with_preprocessed(Vec::new(), 1, circuit_extension_degree)
            .ok_or_else(|| {
                format!(
                    "unsupported witness bus dimension {} for Poseidon2 config {:?}",
                    circuit_extension_degree, self.0.config
                )
            })
    }

    fn air_with_committed_preprocessed(
        &self,
        committed_prep: Vec<Val<SC>>,
        min_height: usize,
        _lanes: usize,
        circuit_extension_degree: u32,
    ) -> Option<DynamicAirEntry<SC>> {
        self.0.wrapper_from_config_with_preprocessed(
            committed_prep,
            min_height,
            circuit_extension_degree,
        )
    }
}

/// Shared helper implementing Poseidon2-specific preprocessing on generic preprocessed columns.
fn poseidon2_preprocess_for_prover<F, ExtF, const D: usize>(
    preprocessed: &mut PreprocessedColumns<ExtF, D>,
) -> Result<NonPrimitivePreprocessedMap<F>, CircuitError>
where
    F: StarkField + PrimeField64,
    ExtF: ExtensionField<F>,
{
    poseidon_preprocess_for_prover(preprocessed, "poseidon2_perm/", |name| {
        Poseidon2Config::from_variant_name(name)
            .map(|cfg| (cfg.d(), cfg.width_ext(), cfg.rate_ext()))
    })
}

/// Stateless plugin used for Poseidon2 preprocessing.
#[derive(Clone, Default)]
pub struct Poseidon2Preprocessor;

/// Configured preprocessor for physical shared challenger/MMCS tables. It deliberately runs the
/// generic Poseidon2 pass first so ext-read and duplicate-output bookkeeping remains keyed by
/// the original logical source identities before rows are concatenated.
#[derive(Clone, Debug)]
pub struct Poseidon2SharedPreprocessor {
    configs: Vec<Poseidon2Config>,
}

impl Poseidon2SharedPreprocessor {
    pub const fn new(configs: Vec<Poseidon2Config>) -> Self {
        Self { configs }
    }
}

fn merge_shared_preprocessed<F: StarkField + PrimeField64>(
    map: &mut NonPrimitivePreprocessedMap<F>,
    config: Poseidon2Config,
) -> Result<(), CircuitError> {
    let sources = config.source_configs();
    let width_ext = config.width_ext();
    let rate_ext = config.rate_ext();
    let row_width = poseidon_preprocessed_row_width_for_air(config.d(), width_ext, rate_ext);
    let role_offset = poseidon_shared_challenger_role_offset(rate_ext);
    let new_start_offset = row_width - 2;
    let mut merged = Vec::new();
    let mut found = false;
    for source in sources {
        let source_id = NpoTypeId::poseidon2_perm(source);
        let Some(mut values) = map.remove(&source_id) else {
            continue;
        };
        found = true;
        if !values.len().is_multiple_of(row_width) {
            return Err(CircuitError::InvalidPreprocessedValues);
        }
        if values.get(new_start_offset).copied() != Some(F::ONE) {
            return Err(CircuitError::InvalidPreprocessedValues);
        }
        for row in values.chunks_exact_mut(row_width) {
            if source.is_challenger() {
                row[role_offset] = if row[new_start_offset] == F::ONE {
                    F::ONE
                } else {
                    F::ZERO
                };
            } else {
                // The second capacity slot is reserved for the shared role gate; in particular,
                // clear the redundant Merkle selector on every ordinary continuation row.
                row[role_offset] = F::ZERO;
            }
        }
        merged.extend(values);
    }
    if found {
        map.insert(NpoTypeId::poseidon2_perm(config), merged);
    }
    Ok(())
}

fn shared_preprocess<F, const D: usize>(
    circuit: &dyn Any,
    preprocessed: &mut dyn Any,
    configs: &[Poseidon2Config],
) -> Result<NonPrimitivePreprocessedMap<F>, CircuitError>
where
    F: StarkField + PrimeField64,
    Poseidon2Preprocessor: NpoPreprocessor<F>,
{
    let mut map = Poseidon2Preprocessor.preprocess(circuit, preprocessed)?;
    for &config in configs {
        merge_shared_preprocessed(&mut map, config)?;
    }
    Ok(map)
}

impl NpoPreprocessor<BabyBear> for Poseidon2Preprocessor {
    fn preprocess(
        &self,
        _circuit: &dyn Any,
        preprocessed: &mut dyn Any,
    ) -> Result<NonPrimitivePreprocessedMap<BabyBear>, CircuitError> {
        if let Some(prep) = preprocessed.downcast_mut::<PreprocessedColumns<BabyBear, 1>>() {
            return poseidon2_preprocess_for_prover::<BabyBear, BabyBear, 1>(prep);
        }
        if let Some(prep) = preprocessed
            .downcast_mut::<PreprocessedColumns<BinomialExtensionField<BabyBear, 4>, 4>>()
        {
            return poseidon2_preprocess_for_prover::<
                BabyBear,
                BinomialExtensionField<BabyBear, 4>,
                4,
            >(prep);
        }
        Ok(NonPrimitivePreprocessedMap::new())
    }
}

impl NpoPreprocessor<KoalaBear> for Poseidon2Preprocessor {
    fn preprocess(
        &self,
        _circuit: &dyn Any,
        preprocessed: &mut dyn Any,
    ) -> Result<NonPrimitivePreprocessedMap<KoalaBear>, CircuitError> {
        if let Some(prep) = preprocessed.downcast_mut::<PreprocessedColumns<KoalaBear, 1>>() {
            return poseidon2_preprocess_for_prover::<KoalaBear, KoalaBear, 1>(prep);
        }
        if let Some(prep) = preprocessed
            .downcast_mut::<PreprocessedColumns<BinomialExtensionField<KoalaBear, 4>, 4>>()
        {
            return poseidon2_preprocess_for_prover::<
                KoalaBear,
                BinomialExtensionField<KoalaBear, 4>,
                4,
            >(prep);
        }
        if let Some(prep) = preprocessed
            .downcast_mut::<PreprocessedColumns<QuinticTrinomialExtensionField<KoalaBear>, 5>>()
        {
            return poseidon2_preprocess_for_prover::<
                KoalaBear,
                QuinticTrinomialExtensionField<KoalaBear>,
                5,
            >(prep);
        }
        Ok(NonPrimitivePreprocessedMap::new())
    }
}

impl NpoPreprocessor<Goldilocks> for Poseidon2Preprocessor {
    fn preprocess(
        &self,
        _circuit: &dyn Any,
        preprocessed: &mut dyn Any,
    ) -> Result<NonPrimitivePreprocessedMap<Goldilocks>, CircuitError> {
        if let Some(prep) = preprocessed.downcast_mut::<PreprocessedColumns<Goldilocks, 1>>() {
            return poseidon2_preprocess_for_prover::<Goldilocks, Goldilocks, 1>(prep);
        }
        if let Some(prep) = preprocessed
            .downcast_mut::<PreprocessedColumns<BinomialExtensionField<Goldilocks, 2>, 2>>()
        {
            return poseidon2_preprocess_for_prover::<
                Goldilocks,
                BinomialExtensionField<Goldilocks, 2>,
                2,
            >(prep);
        }
        Ok(NonPrimitivePreprocessedMap::new())
    }
}

impl NpoPreprocessor<BabyBear> for Poseidon2SharedPreprocessor {
    fn preprocess(
        &self,
        circuit: &dyn Any,
        preprocessed: &mut dyn Any,
    ) -> Result<NonPrimitivePreprocessedMap<BabyBear>, CircuitError> {
        if preprocessed.is::<PreprocessedColumns<BabyBear, 1>>() {
            return shared_preprocess::<BabyBear, 1>(circuit, preprocessed, &self.configs);
        }
        if preprocessed.is::<PreprocessedColumns<BinomialExtensionField<BabyBear, 4>, 4>>() {
            return shared_preprocess::<BabyBear, 4>(circuit, preprocessed, &self.configs);
        }
        Ok(NonPrimitivePreprocessedMap::new())
    }
}

impl NpoPreprocessor<KoalaBear> for Poseidon2SharedPreprocessor {
    fn preprocess(
        &self,
        circuit: &dyn Any,
        preprocessed: &mut dyn Any,
    ) -> Result<NonPrimitivePreprocessedMap<KoalaBear>, CircuitError> {
        if preprocessed.is::<PreprocessedColumns<KoalaBear, 1>>() {
            return shared_preprocess::<KoalaBear, 1>(circuit, preprocessed, &self.configs);
        }
        if preprocessed.is::<PreprocessedColumns<BinomialExtensionField<KoalaBear, 4>, 4>>() {
            return shared_preprocess::<KoalaBear, 4>(circuit, preprocessed, &self.configs);
        }
        if preprocessed.is::<PreprocessedColumns<QuinticTrinomialExtensionField<KoalaBear>, 5>>() {
            return shared_preprocess::<KoalaBear, 5>(circuit, preprocessed, &self.configs);
        }
        Ok(NonPrimitivePreprocessedMap::new())
    }
}

impl NpoPreprocessor<Goldilocks> for Poseidon2SharedPreprocessor {
    fn preprocess(
        &self,
        circuit: &dyn Any,
        preprocessed: &mut dyn Any,
    ) -> Result<NonPrimitivePreprocessedMap<Goldilocks>, CircuitError> {
        if preprocessed.is::<PreprocessedColumns<Goldilocks, 1>>() {
            return shared_preprocess::<Goldilocks, 1>(circuit, preprocessed, &self.configs);
        }
        if preprocessed.is::<PreprocessedColumns<BinomialExtensionField<Goldilocks, 2>, 2>>() {
            return shared_preprocess::<Goldilocks, 2>(circuit, preprocessed, &self.configs);
        }
        Ok(NonPrimitivePreprocessedMap::new())
    }
}

/// Returns `Some(config)` when this Poseidon2 variant is supported for batch AIR building at
/// extension degree `D` (2 = Goldilocks, 4 = BabyBear / KoalaBear, 5 = KoalaBear quintic).
///
/// For `D = 5` only D=1 (base-field) configs are valid: the quintic challenger always operates
/// in the base field.
pub(crate) fn poseidon2_config_for_air_builder<const D: usize>(
    config: Poseidon2Config,
) -> Option<Poseidon2Config> {
    let shape = config.without_challenger_role();
    match D {
        2 => match shape {
            Poseidon2Config::GOLDILOCKS_D2_W8 | Poseidon2Config::GOLDILOCKS_D2_W16 => Some(config),
            _ => None,
        },
        4 => match shape {
            Poseidon2Config::BABY_BEAR_D1_W16
            | Poseidon2Config::BABY_BEAR_D4_W16
            | Poseidon2Config::BABY_BEAR_D4_W24
            | Poseidon2Config::BABY_BEAR_D4_W32
            | Poseidon2Config::KOALA_BEAR_D1_W16
            | Poseidon2Config::KOALA_BEAR_D4_W16
            | Poseidon2Config::KOALA_BEAR_D4_W24
            | Poseidon2Config::KOALA_BEAR_D4_W32 => Some(config),
            _ => None,
        },
        5 => match shape {
            Poseidon2Config::BABY_BEAR_D1_W16
            | Poseidon2Config::KOALA_BEAR_D1_W16
            | Poseidon2Config::KOALA_BEAR_D1_W32 => Some(config),
            _ => None,
        },
        _ => None,
    }
}

pub(crate) fn poseidon2_air_try_build<SC, const D: usize>(
    op_type: &NpoTypeId,
    prep_base: &[Val<SC>],
    min_height: usize,
    constraint_profile: ConstraintProfile,
) -> Option<(CircuitTableAir<SC, D>, usize)>
where
    SC: StarkGenericConfig + 'static + Send + Sync,
    Val<SC>: StarkField + BinomiallyExtendable<D>,
    SymbolicExpressionExt<Val<SC>, SC::Challenge>:
        Algebra<SymbolicExpression<Val<SC>>> + Algebra<SC::Challenge>,
{
    let suffix = op_type.as_str().strip_prefix("poseidon2_perm/")?;
    let config = Poseidon2Config::from_variant_name(suffix)?;
    let config = poseidon2_config_for_air_builder::<D>(config)?;
    let prover = Poseidon2Prover::new(config, constraint_profile);
    let wrapper =
        prover.wrapper_from_config_with_preprocessed(prep_base.to_vec(), min_height, D as u32)?;
    let width = prover.preprocessed_width_from_config();
    let num_rows = prep_base.len().div_ceil(width);
    let degree = log2_ceil_usize(
        num_rows
            .next_power_of_two()
            .max(min_height.next_power_of_two()),
    );
    Some((CircuitTableAir::Dynamic(wrapper), degree))
}

/// Poseidon2 NPO AIR builder parameterized by extension degree `D`.
#[derive(Clone, Default)]
pub struct Poseidon2AirBuilder<const D: usize>;

impl<SC> NpoAirBuilder<SC, 2> for Poseidon2AirBuilder<2>
where
    SC: StarkGenericConfig + 'static + Send + Sync,
    Val<SC>: StarkField + BinomiallyExtendable<2>,
    SymbolicExpressionExt<Val<SC>, SC::Challenge>:
        Algebra<SymbolicExpression<Val<SC>>> + Algebra<SC::Challenge>,
{
    fn trusted_rows_are_padded_height(&self) -> bool {
        true
    }

    fn try_build(
        &self,
        op_type: &NpoTypeId,
        prep_base: &[Val<SC>],
        min_height: usize,
        _lanes: usize,
        constraint_profile: ConstraintProfile,
    ) -> Option<(CircuitTableAir<SC, 2>, usize)> {
        poseidon2_air_try_build::<SC, 2>(op_type, prep_base, min_height, constraint_profile)
    }
}

impl<SC> NpoAirBuilder<SC, 4> for Poseidon2AirBuilder<4>
where
    SC: StarkGenericConfig + 'static + Send + Sync,
    Val<SC>: StarkField + BinomiallyExtendable<4>,
    SymbolicExpressionExt<Val<SC>, SC::Challenge>:
        Algebra<SymbolicExpression<Val<SC>>> + Algebra<SC::Challenge>,
{
    fn trusted_rows_are_padded_height(&self) -> bool {
        true
    }

    fn try_build(
        &self,
        op_type: &NpoTypeId,
        prep_base: &[Val<SC>],
        min_height: usize,
        _lanes: usize,
        constraint_profile: ConstraintProfile,
    ) -> Option<(CircuitTableAir<SC, 4>, usize)> {
        poseidon2_air_try_build::<SC, 4>(op_type, prep_base, min_height, constraint_profile)
    }
}

impl<SC> NpoAirBuilder<SC, 5> for Poseidon2AirBuilder<5>
where
    SC: StarkGenericConfig + 'static + Send + Sync,
    Val<SC>: StarkField,
    SymbolicExpressionExt<Val<SC>, SC::Challenge>:
        Algebra<SymbolicExpression<Val<SC>>> + Algebra<SC::Challenge>,
{
    fn trusted_rows_are_padded_height(&self) -> bool {
        true
    }

    fn try_build(
        &self,
        op_type: &NpoTypeId,
        prep_base: &[Val<SC>],
        min_height: usize,
        _lanes: usize,
        constraint_profile: ConstraintProfile,
    ) -> Option<(CircuitTableAir<SC, 5>, usize)> {
        let suffix = op_type.as_str().strip_prefix("poseidon2_perm/")?;
        let config = Poseidon2Config::from_variant_name(suffix)?;
        // For D=5 circuits the Poseidon2 permutation always operates in the base field
        // (the quintic challenger uses D=1 configs).
        let config = match config.without_challenger_role() {
            Poseidon2Config::BABY_BEAR_D1_W16
            | Poseidon2Config::KOALA_BEAR_D1_W16
            | Poseidon2Config::KOALA_BEAR_D1_W32 => config,
            _ => return None,
        };
        let prover = Poseidon2Prover::new(config, constraint_profile);
        let wrapper =
            prover.wrapper_from_config_with_preprocessed(prep_base.to_vec(), min_height, 5)?;
        let width = prover.preprocessed_width_from_config();
        let num_rows = prep_base.len().div_ceil(width);
        let degree = log2_ceil_usize(
            num_rows
                .next_power_of_two()
                .max(min_height.next_power_of_two()),
        );
        Some((CircuitTableAir::Dynamic(wrapper), degree))
    }
}

/// Poseidon2 NPO AIR builder restricted to one concrete Poseidon2 config.
///
/// Mixed circuits can contain more than one Poseidon2 table (for example W16 challenger rows plus
/// W32 MMCS rows). One builder per config keeps the prover-data table order aligned with the
/// registered table provers.
#[derive(Clone, Copy)]
pub struct Poseidon2AirBuilderForConfig<const D: usize> {
    config: Poseidon2Config,
}

impl<const D: usize> Poseidon2AirBuilderForConfig<D> {
    /// Build a config-restricted Poseidon2 AIR builder.
    pub const fn new(config: Poseidon2Config) -> Self {
        Self { config }
    }

    fn matches_op_type(&self, op_type: &NpoTypeId) -> bool {
        let Some(suffix) = op_type.as_str().strip_prefix("poseidon2_perm/") else {
            return false;
        };
        Poseidon2Config::from_variant_name(suffix) == Some(self.config)
    }
}

impl<SC> NpoAirBuilder<SC, 2> for Poseidon2AirBuilderForConfig<2>
where
    SC: StarkGenericConfig + 'static + Send + Sync,
    Val<SC>: StarkField + BinomiallyExtendable<2>,
    SymbolicExpressionExt<Val<SC>, SC::Challenge>:
        Algebra<SymbolicExpression<Val<SC>>> + Algebra<SC::Challenge>,
{
    fn trusted_rows_are_padded_height(&self) -> bool {
        true
    }

    fn try_build(
        &self,
        op_type: &NpoTypeId,
        prep_base: &[Val<SC>],
        min_height: usize,
        _lanes: usize,
        constraint_profile: ConstraintProfile,
    ) -> Option<(CircuitTableAir<SC, 2>, usize)> {
        self.matches_op_type(op_type).then_some(())?;
        poseidon2_air_try_build::<SC, 2>(op_type, prep_base, min_height, constraint_profile)
    }
}

impl<SC> NpoAirBuilder<SC, 4> for Poseidon2AirBuilderForConfig<4>
where
    SC: StarkGenericConfig + 'static + Send + Sync,
    Val<SC>: StarkField + BinomiallyExtendable<4>,
    SymbolicExpressionExt<Val<SC>, SC::Challenge>:
        Algebra<SymbolicExpression<Val<SC>>> + Algebra<SC::Challenge>,
{
    fn trusted_rows_are_padded_height(&self) -> bool {
        true
    }

    fn try_build(
        &self,
        op_type: &NpoTypeId,
        prep_base: &[Val<SC>],
        min_height: usize,
        _lanes: usize,
        constraint_profile: ConstraintProfile,
    ) -> Option<(CircuitTableAir<SC, 4>, usize)> {
        self.matches_op_type(op_type).then_some(())?;
        poseidon2_air_try_build::<SC, 4>(op_type, prep_base, min_height, constraint_profile)
    }
}

impl<SC> NpoAirBuilder<SC, 5> for Poseidon2AirBuilderForConfig<5>
where
    SC: StarkGenericConfig + 'static + Send + Sync,
    Val<SC>: StarkField,
    SymbolicExpressionExt<Val<SC>, SC::Challenge>:
        Algebra<SymbolicExpression<Val<SC>>> + Algebra<SC::Challenge>,
{
    fn trusted_rows_are_padded_height(&self) -> bool {
        true
    }

    fn try_build(
        &self,
        op_type: &NpoTypeId,
        prep_base: &[Val<SC>],
        min_height: usize,
        _lanes: usize,
        constraint_profile: ConstraintProfile,
    ) -> Option<(CircuitTableAir<SC, 5>, usize)> {
        self.matches_op_type(op_type).then_some(())?;
        // For D=5 circuits the Poseidon2 permutation always operates in the base field
        // (the quintic challenger uses D=1 configs).
        let config = match self.config.without_challenger_role() {
            Poseidon2Config::BABY_BEAR_D1_W16
            | Poseidon2Config::KOALA_BEAR_D1_W16
            | Poseidon2Config::KOALA_BEAR_D1_W32 => self.config,
            _ => return None,
        };
        let prover = Poseidon2Prover::new(config, constraint_profile);
        let wrapper =
            prover.wrapper_from_config_with_preprocessed(prep_base.to_vec(), min_height, 5)?;
        let width = prover.preprocessed_width_from_config();
        let num_rows = prep_base.len().div_ceil(width);
        let degree = log2_ceil_usize(
            num_rows
                .next_power_of_two()
                .max(min_height.next_power_of_two()),
        );
        Some((CircuitTableAir::Dynamic(wrapper), degree))
    }
}

/// Returns a type-erased Poseidon2 preprocessor for use when `Val<SC>` is BabyBear, Goldilocks, or KoalaBear.
pub fn poseidon2_preprocessor<F>() -> Box<dyn NpoPreprocessor<F>>
where
    F: StarkField + PrimeField64,
    Poseidon2Preprocessor: NpoPreprocessor<F>,
{
    Box::new(Poseidon2Preprocessor)
}

#[cfg(test)]
mod shared_preprocessing_tests {
    use super::*;

    #[test]
    fn shared_preprocessing_requires_each_source_to_start_a_chain() {
        let config = Poseidon2Config::KOALA_BEAR_D4_W16.for_shared_challenger_table();
        let width = poseidon_preprocessed_row_width_for_air(
            config.d(),
            config.width_ext(),
            config.rate_ext(),
        );
        let challenger = config.source_configs()[0];
        let mut malformed = vec![BabyBear::ZERO; width];
        malformed[width - 2] = BabyBear::ZERO;
        let mut map = NonPrimitivePreprocessedMap::new();
        map.insert(NpoTypeId::poseidon2_perm(challenger), malformed);

        assert!(matches!(
            merge_shared_preprocessed(&mut map, config),
            Err(CircuitError::InvalidPreprocessedValues)
        ));
    }

    #[test]
    fn shared_preprocessing_orders_sources_and_sets_only_challenger_gate() {
        let config = Poseidon2Config::KOALA_BEAR_D4_W16.for_shared_challenger_table();
        let width = poseidon_preprocessed_row_width_for_air(
            config.d(),
            config.width_ext(),
            config.rate_ext(),
        );
        let role_offset = poseidon_shared_challenger_role_offset(config.rate_ext());
        let challenger = config.source_configs()[0];
        let ordinary = config.source_configs()[1];
        let mut challenger_row = vec![BabyBear::ZERO; width];
        challenger_row[width - 2] = BabyBear::ONE;
        let mut ordinary_row = vec![BabyBear::ZERO; width];
        ordinary_row[width - 2] = BabyBear::ONE;
        let mut map = NonPrimitivePreprocessedMap::new();
        map.insert(NpoTypeId::poseidon2_perm(ordinary), ordinary_row);
        map.insert(NpoTypeId::poseidon2_perm(challenger), challenger_row);

        merge_shared_preprocessed(&mut map, config).unwrap();
        let merged = map
            .get(&NpoTypeId::poseidon2_perm(config))
            .expect("shared physical source");
        assert_eq!(merged.len(), 2 * width);
        assert_eq!(merged[role_offset], BabyBear::ONE);
        assert_eq!(merged[width + role_offset], BabyBear::ZERO);
    }

    #[test]
    fn shared_preprocessing_concatenates_rows_and_preserves_signed_outputs() {
        let config = Poseidon2Config::BABY_BEAR_D4_W16.for_shared_challenger_table();
        let width = poseidon_preprocessed_row_width_for_air(
            config.d(),
            config.width_ext(),
            config.rate_ext(),
        );
        let challenger = config.source_configs()[0];
        let ordinary = config.source_configs()[1];
        let mut challenger_rows = vec![BabyBear::ZERO; width * 2];
        challenger_rows[width - 2] = BabyBear::ONE;
        challenger_rows[width] = BabyBear::from_u64(7);
        challenger_rows[width + width - 2] = BabyBear::ONE;
        let mut ordinary_rows = vec![BabyBear::ZERO; width];
        ordinary_rows[0] = BabyBear::NEG_ONE;
        ordinary_rows[width - 2] = BabyBear::ONE;
        let mut map = NonPrimitivePreprocessedMap::new();
        map.insert(NpoTypeId::poseidon2_perm(ordinary), ordinary_rows);
        map.insert(NpoTypeId::poseidon2_perm(challenger), challenger_rows);

        merge_shared_preprocessed(&mut map, config).unwrap();
        let merged = map
            .get(&NpoTypeId::poseidon2_perm(config))
            .expect("shared physical source");
        assert_eq!(merged.len(), width * 3);
        assert_eq!(merged[width], BabyBear::from_u64(7));
        assert_eq!(merged[width * 2], BabyBear::NEG_ONE);
    }

    #[test]
    fn shared_preprocessing_counts_boundary_wrap_and_padding_reads_per_source() {
        type Ext = BinomialExtensionField<BabyBear, 4>;
        let config = Poseidon2Config::BABY_BEAR_D4_W16.for_shared_challenger_table();
        let challenger = config.source_configs()[0];
        let ordinary = config.source_configs()[1];
        let row_width = poseidon_preprocessed_row_width_for_air(
            config.d(),
            config.width_ext(),
            config.rate_ext(),
        );
        let tail = row_width - 4;
        let source_rows = |new_starts: &[bool]| {
            let mut rows = vec![Ext::ZERO; row_width * new_starts.len()];
            for (row_idx, new_start) in new_starts.iter().copied().enumerate() {
                let row = &mut rows[row_idx * row_width..(row_idx + 1) * row_width];
                row[tail] = Ext::ZERO;
                row[tail + 1] = Ext::ONE;
                row[tail + 2] = Ext::from(BabyBear::from_bool(new_start));
                row[config.width_ext() * 4 + 1] = Ext::ONE;
            }
            rows
        };
        let mut columns = PreprocessedColumns::<Ext, 4>::new();
        columns.non_primitive.insert(
            NpoTypeId::poseidon2_perm(challenger),
            // The first two starts exercise an in-table chain boundary; the final row's
            // terminal read is against the first padded row.
            source_rows(&[true, true, false]),
        );
        columns.non_primitive.insert(
            NpoTypeId::poseidon2_perm(ordinary),
            // A power-of-two source has no padding, so its final terminal read wraps to
            // the first row's chain start.
            source_rows(&[true, true, false, false]),
        );
        columns
            .dup_npo_outputs
            .insert(NpoTypeId::poseidon2_perm(ordinary), vec![true]);

        let preprocessor = Poseidon2SharedPreprocessor::new(vec![config]);
        let map: NonPrimitivePreprocessedMap<BabyBear> =
            preprocessor.preprocess(&(), &mut columns).unwrap();

        assert_eq!(columns.ext_reads, vec![4]);
        let merged = map
            .get(&NpoTypeId::poseidon2_perm(config))
            .expect("shared physical source");
        let output_ctl = config.width_ext() * 4 + 1;
        assert_eq!(merged[output_ctl], BabyBear::from_u32(4));
        assert_eq!(merged[row_width + output_ctl], BabyBear::from_u32(4));
        assert_eq!(merged[row_width * 2 + output_ctl], BabyBear::from_u32(4));
        assert_eq!(merged[row_width * 3 + output_ctl], BabyBear::NEG_ONE);
        assert_eq!(merged[row_width * 4 + output_ctl], BabyBear::NEG_ONE);
        assert_eq!(merged[row_width * 6 + output_ctl], BabyBear::NEG_ONE);
        assert_eq!(
            merged[poseidon_shared_challenger_role_offset(config.rate_ext())],
            BabyBear::ONE
        );
    }
}
