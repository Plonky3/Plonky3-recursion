use alloc::vec::Vec;

use crate::builtin_config::{
    BuiltinConfigDescriptorV1, FriConfigV1, SuiteIdV1, WhirConfigV1, WhirRateModeV1,
};
use p3_batch_stark::common::{GlobalPreprocessed, PreprocessedInstanceMeta};
use p3_batch_stark::{CommonData, StarkGenericConfig};
use p3_circuit::ops::{NpoTypeId, Poseidon1Config, Poseidon2Config};
use p3_circuit::{StatementField, StatementSchema};
use p3_circuit_prover::air::AluExtMulKind;
use p3_circuit_prover::{
    AirVariant, CircuitRelation, ConstraintProfile, NpoRelation, RowCounts, TablePacking,
};
use p3_field::PrimeField64;

use crate::VerifierLimits;

use super::ArtifactError;
use super::wire::{Reader, Writer};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum BuiltinNpoV1 {
    Statement,
    Recompose,
    RecomposeWithCoefficientLookups,
    Poseidon1(Poseidon1Config),
    Poseidon2(Poseidon2Config),
}

const POSEIDON1_CONFIGS: [Poseidon1Config; 12] = [
    Poseidon1Config::BABY_BEAR_D1_W16,
    Poseidon1Config::BABY_BEAR_D4_W16,
    Poseidon1Config::BABY_BEAR_D4_W24,
    Poseidon1Config::KOALA_BEAR_D1_W16,
    Poseidon1Config::KOALA_BEAR_D4_W16,
    Poseidon1Config::KOALA_BEAR_D4_W24,
    Poseidon1Config::GOLDILOCKS_D2_W8,
    Poseidon1Config::BABY_BEAR_D4_W16.for_challenger(),
    Poseidon1Config::BABY_BEAR_D4_W24.for_challenger(),
    Poseidon1Config::KOALA_BEAR_D4_W16.for_challenger(),
    Poseidon1Config::KOALA_BEAR_D4_W24.for_challenger(),
    Poseidon1Config::GOLDILOCKS_D2_W8.for_challenger(),
];

const POSEIDON2_CONFIGS: [Poseidon2Config; 16] = [
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

impl BuiltinNpoV1 {
    fn from_native(op_type: &NpoTypeId) -> Result<Self, ArtifactError> {
        if op_type == &NpoTypeId::statement() {
            return Ok(Self::Statement);
        }
        if op_type == &NpoTypeId::recompose() {
            return Ok(Self::Recompose);
        }
        if op_type == &NpoTypeId::recompose_with_coeff_lookups() {
            return Ok(Self::RecomposeWithCoefficientLookups);
        }
        for config in POSEIDON1_CONFIGS {
            if op_type == &NpoTypeId::poseidon1_perm(config) {
                return Ok(Self::Poseidon1(config));
            }
        }
        for config in POSEIDON2_CONFIGS {
            if op_type == &NpoTypeId::poseidon2_perm(config) {
                return Ok(Self::Poseidon2(config));
            }
        }
        Err(ArtifactError::UnsupportedBuiltinAir(u16::MAX))
    }

    fn from_wire(tag: u16) -> Result<Self, ArtifactError> {
        match tag {
            1 => Ok(Self::Statement),
            2 => Ok(Self::Recompose),
            3 => Ok(Self::RecomposeWithCoefficientLookups),
            0x0100..=0x010b => Ok(Self::Poseidon1(
                POSEIDON1_CONFIGS[usize::from(tag - 0x0100)],
            )),
            0x0200..=0x020f => Ok(Self::Poseidon2(
                POSEIDON2_CONFIGS[usize::from(tag - 0x0200)],
            )),
            _ => Err(ArtifactError::UnsupportedBuiltinAir(tag)),
        }
    }

    fn wire_tag(self) -> u16 {
        match self {
            Self::Statement => 1,
            Self::Recompose => 2,
            Self::RecomposeWithCoefficientLookups => 3,
            Self::Poseidon1(config) => {
                0x0100
                    + POSEIDON1_CONFIGS
                        .iter()
                        .position(|candidate| *candidate == config)
                        .expect("only registry-selected Poseidon1 configs reach encoding")
                        as u16
            }
            Self::Poseidon2(config) => {
                0x0200
                    + POSEIDON2_CONFIGS
                        .iter()
                        .position(|candidate| *candidate == config)
                        .expect("only registry-selected Poseidon2 configs reach encoding")
                        as u16
            }
        }
    }

    fn op_type(self) -> NpoTypeId {
        match self {
            Self::Statement => NpoTypeId::statement(),
            Self::Recompose => NpoTypeId::recompose(),
            Self::RecomposeWithCoefficientLookups => NpoTypeId::recompose_with_coeff_lookups(),
            Self::Poseidon1(config) => NpoTypeId::poseidon1_perm(config),
            Self::Poseidon2(config) => NpoTypeId::poseidon2_perm(config),
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct NpoDescriptorV1<F: Copy> {
    pub kind: BuiltinNpoV1,
    pub rows: usize,
    pub lanes: usize,
    pub air_variant: AirVariant,
    pub public_values: NpoPublicValuesV1<F>,
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) enum NpoPublicValuesV1<F: Copy> {
    Static(Vec<F>),
    Statement { width: usize },
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct RelationDescriptorV1<F: Copy> {
    pub table_packing: TablePacking,
    pub rows: RowCounts,
    pub ext_degree: usize,
    pub reduction: AluExtMulKind<F>,
    pub alu_variant: AirVariant,
    pub constraint_profile: ConstraintProfile,
    pub non_primitives: Vec<NpoDescriptorV1<F>>,
    pub statement_schema: StatementSchema,
    pub statement_table_instance: Option<usize>,
    pub aggregation_statement_layout: Option<p3_circuit::AggregationStatementLayout>,
    pub trace_degree_bits: Vec<usize>,
}

impl<F: Copy> RelationDescriptorV1<F> {
    pub(crate) fn from_native(relation: &CircuitRelation<F>) -> Result<Self, ArtifactError> {
        let statement_npo = relation
            .statement_layout()
            .table_instance()
            .and_then(|instance| instance.checked_sub(p3_circuit_prover::NUM_PRIMITIVE_TABLES));
        let statement_width = relation.statement_layout().schema().base_len();
        let non_primitives = relation
            .non_primitives()
            .iter()
            .enumerate()
            .map(|(index, relation)| {
                npo_from_native(
                    relation,
                    (statement_npo == Some(index)).then_some(statement_width),
                )
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self {
            table_packing: relation.table_packing().clone(),
            rows: *relation.rows(),
            ext_degree: relation.ext_degree(),
            reduction: relation.reduction(),
            alu_variant: relation.alu_variant(),
            constraint_profile: relation.constraint_profile(),
            non_primitives,
            statement_schema: relation.statement_layout().schema().clone(),
            statement_table_instance: relation.statement_layout().table_instance(),
            aggregation_statement_layout: relation.aggregation_statement_layout().cloned(),
            trace_degree_bits: relation.trace_degree_bits().to_vec(),
        })
    }

    pub(crate) fn into_trusted(
        self,
    ) -> Result<p3_circuit_prover::TrustedBuiltinArtifactRelation<F>, ArtifactError> {
        let non_primitives = self
            .non_primitives
            .into_iter()
            .map(|npo| match npo.public_values {
                NpoPublicValuesV1::Statement { width } => {
                    Ok(p3_circuit_prover::BuiltinArtifactNpo::statement(width))
                }
                NpoPublicValuesV1::Static(public_values) => {
                    let air = match npo.kind {
                        BuiltinNpoV1::Statement => return Err(ArtifactError::NonCanonicalMetadata),
                        BuiltinNpoV1::Recompose => p3_circuit_prover::BuiltinArtifactAir::Recompose,
                        BuiltinNpoV1::RecomposeWithCoefficientLookups => {
                            p3_circuit_prover::BuiltinArtifactAir::RecomposeWithCoefficientLookups
                        }
                        BuiltinNpoV1::Poseidon1(config) => {
                            p3_circuit_prover::BuiltinArtifactAir::Poseidon1(config)
                        }
                        BuiltinNpoV1::Poseidon2(config) => {
                            p3_circuit_prover::BuiltinArtifactAir::Poseidon2(config)
                        }
                    };
                    Ok(p3_circuit_prover::BuiltinArtifactNpo::static_values(
                        air,
                        npo.rows,
                        npo.lanes,
                        npo.air_variant,
                        public_values,
                    ))
                }
            })
            .collect::<Result<Vec<_>, ArtifactError>>()?;
        p3_circuit_prover::TrustedBuiltinArtifactRelation::try_new(
            self.table_packing,
            self.rows,
            self.ext_degree,
            self.reduction,
            self.alu_variant,
            self.constraint_profile,
            non_primitives,
            self.statement_schema,
            self.statement_table_instance,
            self.aggregation_statement_layout,
            self.trace_degree_bits,
        )
        .map_err(|_| ArtifactError::NonCanonicalMetadata)
    }
}

fn npo_from_native<F: Copy>(
    relation: &NpoRelation<F>,
    statement_width: Option<usize>,
) -> Result<NpoDescriptorV1<F>, ArtifactError> {
    let kind = BuiltinNpoV1::from_native(relation.op_type())?;
    if statement_width.is_some()
        && (kind != BuiltinNpoV1::Statement
            || relation.rows() != 1
            || relation.lanes() != 1
            || relation.air_variant() != AirVariant::Baseline)
    {
        return Err(ArtifactError::NonCanonicalMetadata);
    }
    if statement_width.is_none() && kind == BuiltinNpoV1::Statement {
        return Err(ArtifactError::NonCanonicalMetadata);
    }
    Ok(NpoDescriptorV1 {
        kind,
        rows: relation.rows(),
        lanes: relation.lanes(),
        air_variant: relation.air_variant(),
        public_values: statement_width.map_or_else(
            || NpoPublicValuesV1::Static(relation.public_values().to_vec()),
            |width| NpoPublicValuesV1::Statement { width },
        ),
    })
}

fn write_option_u32(writer: &mut Writer, value: Option<usize>) -> Result<(), ArtifactError> {
    match value {
        None => writer.write_u8(0),
        Some(value) => {
            writer.write_u8(1)?;
            writer.write_count("optional index", value)
        }
    }
}

fn read_option_u32(
    reader: &mut Reader<'_>,
    component: &'static str,
) -> Result<Option<usize>, ArtifactError> {
    match reader.read_u8()? {
        0 => Ok(None),
        1 => Ok(Some(
            usize::try_from(reader.read_u32()?).map_err(|_| ArtifactError::LengthOverflow)?,
        )),
        tag => Err(ArtifactError::InvalidTag { component, tag }),
    }
}

fn write_air_variant(writer: &mut Writer, variant: AirVariant) -> Result<(), ArtifactError> {
    writer.write_u8(match variant {
        AirVariant::Baseline => 0,
        AirVariant::Optimized => 1,
    })
}

fn read_air_variant(reader: &mut Reader<'_>) -> Result<AirVariant, ArtifactError> {
    match reader.read_u8()? {
        0 => Ok(AirVariant::Baseline),
        1 => Ok(AirVariant::Optimized),
        tag => Err(ArtifactError::InvalidTag {
            component: "AIR variant",
            tag,
        }),
    }
}

fn write_packing(writer: &mut Writer, packing: &TablePacking) -> Result<(), ArtifactError> {
    writer.write_count("public lanes", packing.public_lanes())?;
    writer.write_count("ALU lanes", packing.alu_lanes())?;
    let npo_lanes = packing.npo_lanes_iter().collect::<Vec<_>>();
    writer.write_vec(
        "NPO lane overrides",
        &npo_lanes,
        |writer, (op_type, lanes)| {
            writer.write_u16(BuiltinNpoV1::from_native(op_type)?.wire_tag())?;
            writer.write_count("NPO lanes", *lanes)
        },
    )?;
    write_option_u32(writer, packing.alu_min_height())?;
    write_option_u32(writer, packing.public_min_height())?;
    write_option_u32(writer, packing.const_min_height())?;
    let npo_heights = packing.npo_min_heights().collect::<Vec<_>>();
    writer.write_vec(
        "NPO minimum-height overrides",
        &npo_heights,
        |writer, (op_type, height)| {
            writer.write_u16(BuiltinNpoV1::from_native(op_type)?.wire_tag())?;
            writer.write_count("NPO minimum height", *height)
        },
    )?;
    writer.write_count("minimum trace height", packing.min_trace_height())?;
    writer.write_count("Horner packed steps", packing.horner_packed_steps())?;
    writer.write_bool(packing.is_strict())
}

fn read_count_value(reader: &mut Reader<'_>) -> Result<usize, ArtifactError> {
    usize::try_from(reader.read_u32()?).map_err(|_| ArtifactError::LengthOverflow)
}

fn read_packing(reader: &mut Reader<'_>) -> Result<TablePacking, ArtifactError> {
    let public_lanes = read_count_value(reader)?;
    let alu_lanes = read_count_value(reader)?;
    if public_lanes == 0 || alu_lanes == 0 {
        return Err(ArtifactError::NonCanonicalMetadata);
    }
    let npo_lanes = reader.read_vec("NPO lane overrides", 6, |reader| {
        let kind = BuiltinNpoV1::from_wire(reader.read_u16()?)?;
        let lanes = read_count_value(reader)?;
        if lanes == 0 {
            return Err(ArtifactError::NonCanonicalMetadata);
        }
        Ok((kind, lanes))
    })?;
    reject_duplicate_npo_keys(&npo_lanes)?;
    let alu_min_height = read_option_u32(reader, "ALU minimum height")?;
    let public_min_height = read_option_u32(reader, "public minimum height")?;
    let const_min_height = read_option_u32(reader, "constant minimum height")?;
    let npo_heights = reader.read_vec("NPO minimum-height overrides", 6, |reader| {
        Ok((
            BuiltinNpoV1::from_wire(reader.read_u16()?)?,
            read_count_value(reader)?,
        ))
    })?;
    reject_duplicate_npo_keys(&npo_heights)?;
    let min_trace_height = read_count_value(reader)?;
    let horner_packed_steps = read_count_value(reader)?;
    let strict = reader.read_bool("strict table heights")?;
    if min_trace_height == 0
        || !min_trace_height.is_power_of_two()
        || horner_packed_steps < 2
        || [alu_min_height, public_min_height, const_min_height]
            .into_iter()
            .flatten()
            .any(|height| height == 0 || !height.is_power_of_two())
        || npo_heights
            .iter()
            .any(|(_, height)| *height == 0 || !height.is_power_of_two())
    {
        return Err(ArtifactError::NonCanonicalMetadata);
    }
    let mut packing = TablePacking::new(public_lanes, alu_lanes)
        .with_min_trace_height(min_trace_height)
        .with_horner_pack_k(horner_packed_steps);
    for (kind, lanes) in npo_lanes {
        packing = packing.with_npo_lanes(kind.op_type(), lanes);
    }
    if let Some(height) = alu_min_height {
        packing = packing.with_alu_min_height(height);
    }
    if let Some(height) = public_min_height {
        packing = packing.with_public_min_height(height);
    }
    if let Some(height) = const_min_height {
        packing = packing.with_const_min_height(height);
    }
    for (kind, height) in npo_heights {
        packing = packing.with_npo_min_height(kind.op_type(), height);
    }
    if strict {
        packing = packing.with_strict_heights();
    }
    packing
        .validate()
        .map_err(|_| ArtifactError::NonCanonicalMetadata)?;
    Ok(packing)
}

fn reject_duplicate_npo_keys<T>(values: &[(BuiltinNpoV1, T)]) -> Result<(), ArtifactError> {
    for (index, (kind, _)) in values.iter().enumerate() {
        if values[..index].iter().any(|(previous, _)| previous == kind) {
            return Err(ArtifactError::NonCanonicalMetadata);
        }
    }
    Ok(())
}

fn write_schema(writer: &mut Writer, schema: &StatementSchema) -> Result<(), ArtifactError> {
    writer.write_vec(
        "statement fields",
        schema.fields(),
        |writer, field| match field {
            StatementField::Base => writer.write_u8(0),
            StatementField::Extension { degree } => {
                writer.write_u8(1)?;
                writer.write_count("statement extension degree", *degree)
            }
        },
    )?;
    writer.write_count("statement flattened width", schema.base_len())
}

fn read_schema(reader: &mut Reader<'_>) -> Result<StatementSchema, ArtifactError> {
    let fields = reader.read_vec("statement fields", 1, |reader| match reader.read_u8()? {
        0 => Ok(StatementField::Base),
        1 => Ok(StatementField::Extension {
            degree: read_count_value(reader)?,
        }),
        tag => Err(ArtifactError::InvalidTag {
            component: "statement field",
            tag,
        }),
    })?;
    let encoded_base_len = read_count_value(reader)?;
    let schema =
        StatementSchema::try_new(fields).map_err(|_| ArtifactError::NonCanonicalMetadata)?;
    if schema.base_len() != encoded_base_len {
        return Err(ArtifactError::NonCanonicalMetadata);
    }
    Ok(schema)
}

fn write_aggregation_layout(
    writer: &mut Writer,
    layout: Option<&p3_circuit::AggregationStatementLayout>,
) -> Result<(), ArtifactError> {
    match layout {
        None => writer.write_u8(0),
        Some(layout) => {
            writer.write_u8(1)?;
            write_schema(writer, layout.left())?;
            write_schema(writer, layout.right())?;
            writer.write_count("aggregation statement split", layout.split_at())?;
            write_schema(writer, layout.output())
        }
    }
}

fn read_aggregation_layout(
    reader: &mut Reader<'_>,
) -> Result<Option<p3_circuit::AggregationStatementLayout>, ArtifactError> {
    match reader.read_u8()? {
        0 => Ok(None),
        1 => {
            let left = read_schema(reader)?;
            let right = read_schema(reader)?;
            let split_at = read_count_value(reader)?;
            let output = read_schema(reader)?;
            p3_circuit::AggregationStatementLayout::try_new(left, right, split_at, output)
                .map(Some)
                .map_err(|_| ArtifactError::NonCanonicalMetadata)
        }
        tag => Err(ArtifactError::InvalidTag {
            component: "aggregation statement layout",
            tag,
        }),
    }
}

pub(crate) fn write_relation<F: PrimeField64>(
    writer: &mut Writer,
    relation: &RelationDescriptorV1<F>,
    field: super::wire::FieldEncoding<F>,
) -> Result<(), ArtifactError> {
    write_packing(writer, &relation.table_packing)?;
    for row in relation.rows.iter() {
        writer.write_count("primitive rows", row)?;
    }
    writer.write_count("extension degree", relation.ext_degree)?;
    match relation.reduction {
        AluExtMulKind::Base => writer.write_u8(0)?,
        AluExtMulKind::Binomial { w } => {
            writer.write_u8(1)?;
            writer.write_field(field, w)?;
        }
        AluExtMulKind::QuinticTrinomial => writer.write_u8(2)?,
    }
    write_air_variant(writer, relation.alu_variant)?;
    writer.write_u8(match relation.constraint_profile {
        ConstraintProfile::Standard => 0,
        ConstraintProfile::RecursionOptimized => 1,
    })?;
    writer.write_vec("NPO relations", &relation.non_primitives, |writer, npo| {
        writer.write_u16(npo.kind.wire_tag())?;
        writer.write_count("NPO rows", npo.rows)?;
        writer.write_count("NPO lanes", npo.lanes)?;
        write_air_variant(writer, npo.air_variant)?;
        match &npo.public_values {
            NpoPublicValuesV1::Statement { width } => {
                writer.write_bool(true)?;
                writer.write_count("statement public width", *width)
            }
            NpoPublicValuesV1::Static(values) => {
                writer.write_bool(false)?;
                writer.write_vec("NPO public values", values, |writer, value| {
                    writer.write_field(field, *value)
                })
            }
        }
    })?;
    write_schema(writer, &relation.statement_schema)?;
    write_option_u32(writer, relation.statement_table_instance)?;
    write_aggregation_layout(writer, relation.aggregation_statement_layout.as_ref())?;
    writer.write_vec(
        "trace degree bits",
        &relation.trace_degree_bits,
        |writer, degree| writer.write_count("trace degree bits", *degree),
    )
}

pub(crate) fn read_relation<F: PrimeField64>(
    reader: &mut Reader<'_>,
    field: super::wire::FieldEncoding<F>,
) -> Result<RelationDescriptorV1<F>, ArtifactError> {
    let table_packing = read_packing(reader)?;
    let mut row_values = [0usize; p3_circuit_prover::NUM_PRIMITIVE_TABLES];
    for row in &mut row_values {
        *row = read_count_value(reader)?;
        if *row == 0 {
            return Err(ArtifactError::NonCanonicalMetadata);
        }
    }
    let rows = RowCounts::new(row_values);
    let ext_degree = read_count_value(reader)?;
    let reduction = match reader.read_u8()? {
        0 => AluExtMulKind::Base,
        1 => AluExtMulKind::Binomial {
            w: reader.read_field(field)?,
        },
        2 => AluExtMulKind::QuinticTrinomial,
        tag => {
            return Err(ArtifactError::InvalidTag {
                component: "extension reduction",
                tag,
            });
        }
    };
    let alu_variant = read_air_variant(reader)?;
    let constraint_profile = match reader.read_u8()? {
        0 => ConstraintProfile::Standard,
        1 => ConstraintProfile::RecursionOptimized,
        tag => {
            return Err(ArtifactError::InvalidTag {
                component: "constraint profile",
                tag,
            });
        }
    };
    let max_instances = reader.limits().verifier.max_instances;
    let non_primitives = reader.read_vec_limited("NPO relations", max_instances, 13, |reader| {
        let kind = BuiltinNpoV1::from_wire(reader.read_u16()?)?;
        let rows = read_count_value(reader)?;
        let lanes = read_count_value(reader)?;
        let air_variant = read_air_variant(reader)?;
        let public_values = if reader.read_bool("dynamic statement policy")? {
            let width = read_count_value(reader)?;
            if width > reader.limits().verifier.max_matrix_width {
                return Err(ArtifactError::DecodeLimitExceeded {
                    component: "statement public width",
                    actual: width,
                    limit: reader.limits().verifier.max_matrix_width,
                });
            }
            if kind != BuiltinNpoV1::Statement {
                return Err(ArtifactError::NonCanonicalMetadata);
            }
            NpoPublicValuesV1::Statement { width }
        } else {
            if kind == BuiltinNpoV1::Statement {
                return Err(ArtifactError::NonCanonicalMetadata);
            }
            NpoPublicValuesV1::Static(reader.read_vec_limited(
                "NPO public values",
                reader.limits().verifier.max_matrix_width,
                field.encoded_bytes(),
                |reader| reader.read_field(field),
            )?)
        };
        Ok(NpoDescriptorV1 {
            kind,
            rows,
            lanes,
            air_variant,
            public_values,
        })
    })?;
    let statement_schema = read_schema(reader)?;
    let statement_table_instance = read_option_u32(reader, "statement table instance")?;
    let aggregation_statement_layout = read_aggregation_layout(reader)?;
    let trace_degree_bits =
        reader.read_vec_limited("trace degree bits", max_instances, 4, read_count_value)?;
    let relation = RelationDescriptorV1 {
        table_packing,
        rows,
        ext_degree,
        reduction,
        alu_variant,
        constraint_profile,
        non_primitives,
        statement_schema,
        statement_table_instance,
        aggregation_statement_layout,
        trace_degree_bits,
    };
    validate_relation_descriptor(&relation)?;
    validate_relation_geometry(&relation, &reader.limits().verifier)?;
    Ok(relation)
}

const fn check_geometry_limit(
    component: &'static str,
    actual: usize,
    limit: usize,
) -> Result<(), ArtifactError> {
    if actual > limit {
        return Err(ArtifactError::DecodeLimitExceeded {
            component,
            actual,
            limit,
        });
    }
    Ok(())
}

fn checked_geometry_product(left: usize, right: usize) -> Result<usize, ArtifactError> {
    left.checked_mul(right).ok_or(ArtifactError::LengthOverflow)
}

const fn check_matrix_width(
    component: &'static str,
    width: usize,
    limits: &VerifierLimits,
) -> Result<(), ArtifactError> {
    check_geometry_limit(component, width, limits.max_matrix_width)
}

fn trace_height(degree: usize, limits: &VerifierLimits) -> Result<usize, ArtifactError> {
    check_geometry_limit("trace degree bits", degree, limits.max_log_domain_or_degree)?;
    let shift = u32::try_from(degree).map_err(|_| ArtifactError::LengthOverflow)?;
    1usize
        .checked_shl(shift)
        .ok_or(ArtifactError::LengthOverflow)
}

fn validate_table_height(
    rows: usize,
    lanes: usize,
    minimum_height: usize,
    degree: usize,
    limits: &VerifierLimits,
) -> Result<(), ArtifactError> {
    let height = trace_height(degree, limits)?;
    let natural_height = rows.div_ceil(lanes);
    if natural_height > height || minimum_height > height {
        return Err(ArtifactError::NonCanonicalMetadata);
    }
    Ok(())
}

fn validate_relation_geometry<F: Copy>(
    relation: &RelationDescriptorV1<F>,
    limits: &VerifierLimits,
) -> Result<(), ArtifactError> {
    let packing = &relation.table_packing;
    let ext_degree = relation.ext_degree;

    check_geometry_limit(
        "primitive rows",
        relation.rows.iter().max().unwrap_or(0),
        limits.max_total_scalar_elements,
    )?;
    check_matrix_width(
        "constant matrix width",
        ext_degree
            .checked_add(2)
            .ok_or(ArtifactError::LengthOverflow)?,
        limits,
    )?;
    check_matrix_width(
        "public matrix width",
        checked_geometry_product(packing.public_lanes(), ext_degree.max(2))?,
        limits,
    )?;

    let horner_steps = packing.horner_packed_steps();
    let horner_minus_one = horner_steps
        .checked_sub(1)
        .ok_or(ArtifactError::LengthOverflow)?;
    let alu_main_lane_width = ext_degree
        .checked_mul(4)
        .ok_or(ArtifactError::LengthOverflow)?;
    let alu_main_lanes_width = checked_geometry_product(packing.alu_lanes(), alu_main_lane_width)?;
    let alu_prep_lanes_width = checked_geometry_product(packing.alu_lanes(), 13)?;
    let main_extra_units = (horner_minus_one / 2)
        .checked_add(
            horner_minus_one
                .checked_mul(2)
                .ok_or(ArtifactError::LengthOverflow)?,
        )
        .and_then(|value| value.checked_add(1))
        .ok_or(ArtifactError::LengthOverflow)?;
    let main_extra = main_extra_units
        .checked_mul(ext_degree)
        .ok_or(ArtifactError::LengthOverflow)?;
    let prep_extra = horner_minus_one
        .checked_mul(7)
        .ok_or(ArtifactError::LengthOverflow)?;
    let alu_main_width = alu_main_lanes_width
        .checked_add(main_extra)
        .ok_or(ArtifactError::LengthOverflow)?;
    let alu_prep_width = alu_prep_lanes_width
        .checked_add(prep_extra)
        .ok_or(ArtifactError::LengthOverflow)?;
    let alu_width = alu_main_width.max(alu_prep_width);
    check_matrix_width("ALU matrix width", alu_width, limits)?;

    let primitive = [
        (
            relation.rows[p3_circuit_prover::PrimitiveTable::Const],
            1,
            packing
                .const_min_height()
                .unwrap_or_else(|| packing.min_trace_height()),
        ),
        (
            relation.rows[p3_circuit_prover::PrimitiveTable::Public],
            packing.public_lanes(),
            packing
                .public_min_height()
                .unwrap_or_else(|| packing.min_trace_height()),
        ),
        (
            relation.rows[p3_circuit_prover::PrimitiveTable::Alu],
            packing.alu_lanes(),
            packing
                .alu_min_height()
                .unwrap_or_else(|| packing.min_trace_height()),
        ),
    ];
    for ((rows, lanes, minimum), degree) in primitive
        .into_iter()
        .zip(relation.trace_degree_bits.iter().copied())
    {
        validate_table_height(rows, lanes, minimum, degree, limits)?;
    }

    for (index, npo) in relation.non_primitives.iter().enumerate() {
        check_geometry_limit("NPO rows", npo.rows, limits.max_total_scalar_elements)?;
        let per_lane_width = match npo.kind {
            BuiltinNpoV1::Statement => match npo.public_values {
                NpoPublicValuesV1::Statement { width } => {
                    width.checked_add(1).ok_or(ArtifactError::LengthOverflow)?
                }
                NpoPublicValuesV1::Static(_) => return Err(ArtifactError::NonCanonicalMetadata),
            },
            BuiltinNpoV1::Recompose => ext_degree.max(2),
            BuiltinNpoV1::RecomposeWithCoefficientLookups => ext_degree
                .checked_mul(2)
                .and_then(|width| width.checked_add(2))
                .ok_or(ArtifactError::LengthOverflow)?,
            BuiltinNpoV1::Poseidon1(config) => {
                if npo.lanes != 1 {
                    return Err(ArtifactError::NonCanonicalMetadata);
                }
                config.width()
            }
            BuiltinNpoV1::Poseidon2(config) => {
                if npo.lanes != 1 {
                    return Err(ArtifactError::NonCanonicalMetadata);
                }
                config.width()
            }
        };
        let matrix_width = checked_geometry_product(npo.lanes, per_lane_width)?;
        check_matrix_width("NPO matrix width", matrix_width, limits)?;
        let degree = relation.trace_degree_bits[p3_circuit_prover::NUM_PRIMITIVE_TABLES + index];
        let minimum = packing
            .npo_min_height(&npo.kind.op_type())
            .unwrap_or_else(|| packing.min_trace_height());
        validate_table_height(npo.rows, npo.lanes, minimum, degree, limits)?;
    }
    Ok(())
}

fn validate_relation_descriptor<F: Copy>(
    relation: &RelationDescriptorV1<F>,
) -> Result<(), ArtifactError> {
    let expected_instances = p3_circuit_prover::NUM_PRIMITIVE_TABLES
        .checked_add(relation.non_primitives.len())
        .ok_or(ArtifactError::LengthOverflow)?;
    if relation.trace_degree_bits.len() != expected_instances {
        return Err(ArtifactError::NonCanonicalMetadata);
    }
    let statement_index = relation
        .statement_table_instance
        .and_then(|instance| instance.checked_sub(p3_circuit_prover::NUM_PRIMITIVE_TABLES));
    if relation.statement_schema.base_len() == 0 {
        if relation.statement_table_instance.is_some()
            || relation
                .non_primitives
                .iter()
                .any(|npo| matches!(npo.public_values, NpoPublicValuesV1::Statement { .. }))
        {
            return Err(ArtifactError::NonCanonicalMetadata);
        }
    } else {
        let Some(index) = statement_index else {
            return Err(ArtifactError::NonCanonicalMetadata);
        };
        let Some(npo) = relation.non_primitives.get(index) else {
            return Err(ArtifactError::NonCanonicalMetadata);
        };
        if !matches!(npo.public_values, NpoPublicValuesV1::Statement { .. })
            || npo.kind != BuiltinNpoV1::Statement
            || npo.rows != 1
            || npo.lanes != 1
            || npo.air_variant != AirVariant::Baseline
            || !matches!(
                npo.public_values,
                NpoPublicValuesV1::Statement { width }
                    if width == relation.statement_schema.base_len()
            )
            || relation
                .non_primitives
                .iter()
                .enumerate()
                .any(|(other, npo)| {
                    other != index
                        && matches!(npo.public_values, NpoPublicValuesV1::Statement { .. })
                })
        {
            return Err(ArtifactError::NonCanonicalMetadata);
        }
    }
    if relation
        .aggregation_statement_layout
        .as_ref()
        .is_some_and(|layout| layout.output() != &relation.statement_schema)
    {
        return Err(ArtifactError::NonCanonicalMetadata);
    }
    match relation.reduction {
        AluExtMulKind::Base if relation.ext_degree == 1 => {}
        AluExtMulKind::Binomial { .. } if relation.ext_degree > 1 => {}
        AluExtMulKind::QuinticTrinomial if relation.ext_degree == 5 => {}
        _ => return Err(ArtifactError::NonCanonicalMetadata),
    }
    Ok(())
}

pub(crate) fn write_config(
    writer: &mut Writer,
    descriptor: &BuiltinConfigDescriptorV1,
) -> Result<(), ArtifactError> {
    match descriptor {
        BuiltinConfigDescriptorV1::Fri(config) => {
            writer.write_u8(0)?;
            writer.write_u16(config.suite().as_u16())?;
            writer.write_u32(config.log_blowup())?;
            writer.write_u32(config.log_final_poly_len())?;
            writer.write_u32(config.max_log_arity())?;
            writer.write_u32(config.num_queries())?;
            writer.write_u32(config.commit_pow_bits())?;
            writer.write_u32(config.query_pow_bits())?;
            writer.write_u32(config.input_cap_height())?;
            writer.write_u32(config.commit_cap_height())?;
            writer.write_u32(config.num_random_codewords())?;
            writer.write_u32(config.salt_elements())
        }
        BuiltinConfigDescriptorV1::Whir(config) => {
            writer.write_u8(1)?;
            writer.write_u16(config.suite().as_u16())?;
            writer.write_u32(config.starting_log_inv_rate())?;
            match config.round_log_inv_rates() {
                WhirRateModeV1::Auto => writer.write_u8(0)?,
                WhirRateModeV1::Explicit(rates) => {
                    writer.write_u8(1)?;
                    writer.write_vec("WHIR round rates", rates, |writer, rate| {
                        writer.write_u32(*rate)
                    })?;
                }
            }
            writer.write_u32(config.folding_factor())?;
            writer.write_u16(config.security_assumption_id())?;
            writer.write_u32(config.security_level())?;
            writer.write_u32(config.pow_bits())?;
            writer.write_u32(config.log_max_lde_height())?;
            writer.write_u32(config.cap_height())
        }
    }
}

pub(crate) fn read_config(
    reader: &mut Reader<'_>,
    expected_suite: SuiteIdV1,
) -> Result<BuiltinConfigDescriptorV1, ArtifactError> {
    let tag = reader.read_u8()?;
    let raw_suite = reader.read_u16()?;
    if raw_suite != expected_suite.as_u16() {
        return Err(ArtifactError::NonCanonicalMetadata);
    }
    let descriptor = match tag {
        0 => BuiltinConfigDescriptorV1::Fri(FriConfigV1::new(
            expected_suite,
            reader.read_u32()?,
            reader.read_u32()?,
            reader.read_u32()?,
            reader.read_u32()?,
            reader.read_u32()?,
            reader.read_u32()?,
            reader.read_u32()?,
            reader.read_u32()?,
            reader.read_u32()?,
            reader.read_u32()?,
        )),
        1 => {
            let starting_log_inv_rate = reader.read_u32()?;
            let round_log_inv_rates = match reader.read_u8()? {
                0 => WhirRateModeV1::Auto,
                1 => WhirRateModeV1::Explicit(reader.read_vec_limited(
                    "WHIR round rates",
                    reader.limits().verifier.max_rounds,
                    4,
                    Reader::read_u32,
                )?),
                tag => {
                    return Err(ArtifactError::InvalidTag {
                        component: "WHIR rate mode",
                        tag,
                    });
                }
            };
            BuiltinConfigDescriptorV1::Whir(WhirConfigV1::new(
                expected_suite,
                starting_log_inv_rate,
                round_log_inv_rates,
                reader.read_u32()?,
                reader.read_u16()?,
                reader.read_u32()?,
                reader.read_u32()?,
                reader.read_u32()?,
                reader.read_u32()?,
            ))
        }
        tag => {
            return Err(ArtifactError::InvalidTag {
                component: "configuration family",
                tag,
            });
        }
    };
    descriptor.validate(&reader.limits().verifier)?;
    Ok(descriptor)
}

pub(crate) fn write_common<SC: StarkGenericConfig>(
    writer: &mut Writer,
    common: &CommonData<SC>,
    mut write_commitment: impl FnMut(
        &mut Writer,
        &p3_batch_stark::Commitment<SC>,
    ) -> Result<(), ArtifactError>,
) -> Result<(), ArtifactError> {
    match &common.preprocessed {
        None => writer.write_u8(0),
        Some(preprocessed) => {
            writer.write_u8(1)?;
            write_commitment(writer, &preprocessed.commitment)?;
            writer.write_vec(
                "preprocessed instances",
                &preprocessed.instances,
                |writer, metadata| match metadata {
                    None => writer.write_u8(0),
                    Some(metadata) => {
                        writer.write_u8(1)?;
                        writer.write_count("preprocessed matrix index", metadata.matrix_index)?;
                        writer.write_count("preprocessed matrix width", metadata.width)?;
                        writer.write_count("preprocessed matrix degree", metadata.degree_bits)
                    }
                },
            )?;
            writer.write_vec(
                "preprocessed matrix routing",
                &preprocessed.matrix_to_instance,
                |writer, instance| writer.write_count("preprocessed routed instance", *instance),
            )
        }
    }
}

pub(crate) fn read_common<SC: StarkGenericConfig>(
    reader: &mut Reader<'_>,
    mut read_commitment: impl FnMut(
        &mut Reader<'_>,
    ) -> Result<p3_batch_stark::Commitment<SC>, ArtifactError>,
) -> Result<CommonData<SC>, ArtifactError> {
    let preprocessed = match reader.read_u8()? {
        0 => None,
        1 => {
            let commitment = read_commitment(reader)?;
            let max_instances = reader.limits().verifier.max_instances;
            let max_width = reader.limits().verifier.max_matrix_width;
            let max_degree = reader.limits().verifier.max_log_domain_or_degree;
            let instances =
                reader.read_vec_limited("preprocessed instances", max_instances, 1, |reader| {
                    match reader.read_u8()? {
                        0 => Ok(None),
                        1 => {
                            let matrix_index = read_count_value(reader)?;
                            let width = read_count_value(reader)?;
                            let degree_bits = read_count_value(reader)?;
                            if width == 0 || width > max_width {
                                return Err(ArtifactError::DecodeLimitExceeded {
                                    component: "preprocessed matrix width",
                                    actual: width,
                                    limit: max_width,
                                });
                            }
                            if degree_bits > max_degree {
                                return Err(ArtifactError::DecodeLimitExceeded {
                                    component: "preprocessed matrix degree",
                                    actual: degree_bits,
                                    limit: max_degree,
                                });
                            }
                            Ok(Some(PreprocessedInstanceMeta {
                                matrix_index,
                                width,
                                degree_bits,
                            }))
                        }
                        tag => Err(ArtifactError::InvalidTag {
                            component: "preprocessed instance",
                            tag,
                        }),
                    }
                })?;
            let matrix_to_instance = reader.read_vec_limited(
                "preprocessed matrix routing",
                max_instances,
                4,
                read_count_value,
            )?;
            if matrix_to_instance
                .iter()
                .any(|&instance| instance >= instances.len())
            {
                return Err(ArtifactError::NonCanonicalMetadata);
            }
            let mut next_matrix = 0;
            for (instance, metadata) in instances.iter().enumerate() {
                if let Some(metadata) = metadata {
                    if metadata.matrix_index != next_matrix
                        || matrix_to_instance.get(next_matrix) != Some(&instance)
                    {
                        return Err(ArtifactError::NonCanonicalMetadata);
                    }
                    next_matrix += 1;
                }
            }
            if next_matrix != matrix_to_instance.len() {
                return Err(ArtifactError::NonCanonicalMetadata);
            }
            Some(GlobalPreprocessed {
                commitment,
                instances,
                matrix_to_instance,
            })
        }
        tag => {
            return Err(ArtifactError::InvalidTag {
                component: "preprocessed common data",
                tag,
            });
        }
    };
    Ok(CommonData::new(preprocessed, Vec::new()))
}

#[cfg(test)]
mod tests {
    use alloc::vec;

    use p3_baby_bear::BabyBear;
    use p3_circuit::ops::NpoTypeId;
    use p3_circuit::{StatementField, StatementSchema};
    use p3_circuit_prover::air::AluExtMulKind;
    use p3_circuit_prover::{AirVariant, ConstraintProfile, RowCounts, TablePacking};
    use p3_field::PrimeCharacteristicRing;

    use crate::artifact::wire::{Reader, Writer};
    use crate::artifact::{ArtifactError, ArtifactLimits};
    use crate::builtin_config::{
        BuiltinConfigDescriptorV1, FriConfigV1, SuiteIdV1, WhirConfigV1, WhirRateModeV1,
        WhirSecurityAssumptionV1,
    };

    use super::{
        BuiltinNpoV1, NpoDescriptorV1, NpoPublicValuesV1, RelationDescriptorV1, read_config,
        read_relation, validate_relation_descriptor, write_config, write_relation,
    };

    fn ordinary() -> BuiltinConfigDescriptorV1 {
        BuiltinConfigDescriptorV1::Fri(FriConfigV1::new(
            SuiteIdV1::BabyBearD4Poseidon2BinaryFri,
            1,
            3,
            4,
            16,
            7,
            5,
            3,
            3,
            0,
            0,
        ))
    }

    fn whir() -> BuiltinConfigDescriptorV1 {
        BuiltinConfigDescriptorV1::Whir(WhirConfigV1::new(
            SuiteIdV1::KoalaBearD4Poseidon2Whir,
            1,
            WhirRateModeV1::Explicit(vec![2, 3]),
            4,
            WhirSecurityAssumptionV1::UniqueDecoding.as_u16(),
            80,
            8,
            20,
            3,
        ))
    }

    #[test]
    fn config_codec_roundtrips_exact_runtime_parameters() {
        for descriptor in [ordinary(), whir()] {
            let limits = ArtifactLimits::default();
            let mut writer = Writer::new(1024);
            write_config(&mut writer, &descriptor).unwrap();
            let bytes = writer.finish().unwrap();
            let mut reader = Reader::new(&bytes, &limits);
            let decoded = read_config(&mut reader, descriptor.suite()).unwrap();
            reader.finish().unwrap();
            assert_eq!(decoded, descriptor);
        }
    }

    #[test]
    fn config_codec_rejects_header_body_suite_substitution() {
        let limits = ArtifactLimits::default();
        let mut writer = Writer::new(1024);
        write_config(&mut writer, &ordinary()).unwrap();
        let bytes = writer.finish().unwrap();
        let mut reader = Reader::new(&bytes, &limits);
        assert_eq!(
            read_config(&mut reader, SuiteIdV1::KoalaBearD4Poseidon2BinaryFri),
            Err(ArtifactError::NonCanonicalMetadata)
        );
    }

    fn relation() -> RelationDescriptorV1<BabyBear> {
        RelationDescriptorV1 {
            table_packing: TablePacking::new(2, 4)
                .with_npo_lanes(NpoTypeId::recompose(), 8)
                .with_npo_min_height(NpoTypeId::statement(), 8)
                .with_min_trace_height(4)
                .with_horner_pack_k(3)
                .with_strict_heights(),
            rows: RowCounts::new([3, 5, 8]),
            ext_degree: 4,
            reduction: AluExtMulKind::Binomial {
                w: BabyBear::from_u32(11),
            },
            alu_variant: AirVariant::Optimized,
            constraint_profile: ConstraintProfile::RecursionOptimized,
            non_primitives: vec![
                NpoDescriptorV1 {
                    kind: BuiltinNpoV1::Recompose,
                    rows: 2,
                    lanes: 8,
                    air_variant: AirVariant::Baseline,
                    public_values: NpoPublicValuesV1::Static(vec![BabyBear::from_u32(17)]),
                },
                NpoDescriptorV1 {
                    kind: BuiltinNpoV1::Statement,
                    rows: 1,
                    lanes: 1,
                    air_variant: AirVariant::Baseline,
                    public_values: NpoPublicValuesV1::Statement { width: 5 },
                },
            ],
            statement_schema: StatementSchema::try_new(vec![
                StatementField::Base,
                StatementField::Extension { degree: 4 },
            ])
            .unwrap(),
            statement_table_instance: Some(p3_circuit_prover::NUM_PRIMITIVE_TABLES + 1),
            aggregation_statement_layout: Some(
                p3_circuit::AggregationStatementLayout::try_new(
                    StatementSchema::try_new(vec![StatementField::Base]).unwrap(),
                    StatementSchema::try_new(vec![StatementField::Extension { degree: 4 }])
                        .unwrap(),
                    1,
                    StatementSchema::try_new(vec![
                        StatementField::Base,
                        StatementField::Extension { degree: 4 },
                    ])
                    .unwrap(),
                )
                .unwrap(),
            ),
            trace_degree_bits: vec![2, 3, 4, 2, 3],
        }
    }

    #[test]
    fn relation_codec_roundtrips_order_and_dynamic_statement_width() {
        let expected = relation();
        let limits = ArtifactLimits::default();
        let field = crate::artifact::wire::FieldEncoding::<BabyBear>::u32();
        let mut writer = Writer::new(4096);
        write_relation(&mut writer, &expected, field).unwrap();
        let bytes = writer.finish().unwrap();

        let mut reader = Reader::new(&bytes, &limits);
        let decoded = read_relation(&mut reader, field).unwrap();
        reader.finish().unwrap();
        assert_eq!(decoded, expected);

        let mut canonical = Writer::new(4096);
        write_relation(&mut canonical, &decoded, field).unwrap();
        assert_eq!(canonical.finish().unwrap(), bytes);
    }

    #[test]
    fn relation_validation_rejects_statement_at_the_wrong_table_instance() {
        let mut descriptor = relation();
        descriptor.statement_table_instance = Some(p3_circuit_prover::NUM_PRIMITIVE_TABLES);
        assert_eq!(
            validate_relation_descriptor(&descriptor),
            Err(ArtifactError::NonCanonicalMetadata)
        );
    }

    #[test]
    fn relation_validation_rejects_a_second_dynamic_statement_policy() {
        let mut descriptor = relation();
        descriptor.non_primitives[0].public_values = NpoPublicValuesV1::Statement { width: 1 };
        assert_eq!(
            validate_relation_descriptor(&descriptor),
            Err(ArtifactError::NonCanonicalMetadata)
        );
    }

    #[test]
    fn built_in_air_registry_rejects_unknown_numeric_tags() {
        assert_eq!(
            BuiltinNpoV1::from_wire(0xffff),
            Err(ArtifactError::UnsupportedBuiltinAir(0xffff))
        );
    }
}
