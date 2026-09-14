use alloc::vec::Vec;

use p3_batch_stark::proof::OpenedValuesWithLookups;
use p3_batch_stark::{BatchCommitments, BatchOpenedValues, BatchProof, StarkGenericConfig};
use p3_field::{BasedVectorSpace, PrimeField64};
use p3_lookup::LookupTerminal;
use p3_uni_stark::OpenedValues;

use crate::artifact::ArtifactError;
use crate::artifact::wire::{FieldEncoding, Reader, Writer};

fn write_option<T>(
    writer: &mut Writer,
    value: Option<&T>,
    mut write_value: impl FnMut(&mut Writer, &T) -> Result<(), ArtifactError>,
) -> Result<(), ArtifactError> {
    match value {
        None => writer.write_u8(0),
        Some(value) => {
            writer.write_u8(1)?;
            write_value(writer, value)
        }
    }
}

fn read_option<T>(
    reader: &mut Reader<'_>,
    component: &'static str,
    mut read_value: impl FnMut(&mut Reader<'_>) -> Result<T, ArtifactError>,
) -> Result<Option<T>, ArtifactError> {
    match reader.read_u8()? {
        0 => Ok(None),
        1 => read_value(reader).map(Some),
        tag => Err(ArtifactError::InvalidTag { component, tag }),
    }
}

fn write_extension_vec<F, EF>(
    writer: &mut Writer,
    component: &'static str,
    values: &[EF],
    field: FieldEncoding<F>,
) -> Result<(), ArtifactError>
where
    F: PrimeField64,
    EF: BasedVectorSpace<F>,
{
    writer.write_vec(component, values, |writer, value| {
        writer.write_extension(field, value)
    })
}

fn read_extension_vec<F, EF>(
    reader: &mut Reader<'_>,
    component: &'static str,
    max: usize,
    field: FieldEncoding<F>,
) -> Result<Vec<EF>, ArtifactError>
where
    F: PrimeField64,
    EF: BasedVectorSpace<F>,
{
    let min_bytes = field
        .encoded_bytes()
        .checked_mul(EF::DIMENSION)
        .ok_or(ArtifactError::LengthOverflow)?;
    reader.read_vec_limited(component, max, min_bytes, |reader| {
        reader.read_extension(field)
    })
}

fn write_opened_values<F, EF>(
    writer: &mut Writer,
    values: &OpenedValues<EF>,
    field: FieldEncoding<F>,
) -> Result<(), ArtifactError>
where
    F: PrimeField64,
    EF: BasedVectorSpace<F>,
{
    write_extension_vec(writer, "trace local openings", &values.trace_local, field)?;
    write_option(writer, values.trace_next.as_ref(), |writer, values| {
        write_extension_vec(writer, "trace next openings", values, field)
    })?;
    write_option(
        writer,
        values.preprocessed_local.as_ref(),
        |writer, values| write_extension_vec(writer, "preprocessed local openings", values, field),
    )?;
    write_option(
        writer,
        values.preprocessed_next.as_ref(),
        |writer, values| write_extension_vec(writer, "preprocessed next openings", values, field),
    )?;
    writer.write_vec(
        "quotient chunk opening vectors",
        &values.quotient_chunks,
        |writer, chunk| write_extension_vec(writer, "quotient chunk openings", chunk, field),
    )?;
    write_option(writer, values.random.as_ref(), |writer, values| {
        write_extension_vec(writer, "random openings", values, field)
    })
}

fn read_opened_values<F, EF>(
    reader: &mut Reader<'_>,
    field: FieldEncoding<F>,
) -> Result<OpenedValues<EF>, ArtifactError>
where
    F: PrimeField64,
    EF: BasedVectorSpace<F>,
{
    let max_width = reader.limits().verifier.max_matrix_width;
    let max_rounds = reader.limits().verifier.max_rounds;
    Ok(OpenedValues {
        trace_local: read_extension_vec(reader, "trace local openings", max_width, field)?,
        trace_next: read_option(reader, "trace next openings", |reader| {
            read_extension_vec(reader, "trace next openings", max_width, field)
        })?,
        preprocessed_local: read_option(reader, "preprocessed local openings", |reader| {
            read_extension_vec(reader, "preprocessed local openings", max_width, field)
        })?,
        preprocessed_next: read_option(reader, "preprocessed next openings", |reader| {
            read_extension_vec(reader, "preprocessed next openings", max_width, field)
        })?,
        quotient_chunks: reader.read_vec_limited(
            "quotient chunk opening vectors",
            max_rounds,
            4,
            |reader| read_extension_vec(reader, "quotient chunk openings", max_width, field),
        )?,
        random: read_option(reader, "random openings", |reader| {
            read_extension_vec(reader, "random openings", max_width, field)
        })?,
    })
}

pub(crate) fn write_batch_proof<SC, F>(
    writer: &mut Writer,
    proof: &BatchProof<SC>,
    field: FieldEncoding<F>,
    mut write_commitment: impl FnMut(
        &mut Writer,
        &p3_batch_stark::Commitment<SC>,
    ) -> Result<(), ArtifactError>,
    mut write_opening_proof: impl FnMut(
        &mut Writer,
        &p3_batch_stark::PcsProof<SC>,
    ) -> Result<(), ArtifactError>,
) -> Result<(), ArtifactError>
where
    SC: StarkGenericConfig,
    F: PrimeField64,
    SC::Challenge: BasedVectorSpace<F>,
{
    write_commitment(writer, &proof.commitments.main)?;
    write_option(
        writer,
        proof.commitments.permutation.as_ref(),
        |writer, value| write_commitment(writer, value),
    )?;
    write_commitment(writer, &proof.commitments.quotient_chunks)?;
    write_option(
        writer,
        proof.commitments.random.as_ref(),
        |writer, value| write_commitment(writer, value),
    )?;
    writer.write_vec(
        "batch opened-value instances",
        &proof.opened_values.instances,
        |writer, instance| {
            write_opened_values(writer, &instance.base_opened_values, field)?;
            write_extension_vec(
                writer,
                "permutation local openings",
                &instance.permutation_local,
                field,
            )?;
            write_extension_vec(
                writer,
                "permutation next openings",
                &instance.permutation_next,
                field,
            )
        },
    )?;
    write_opening_proof(writer, &proof.opening_proof)?;
    writer.write_vec(
        "lookup terminals",
        &proof.lookup_terminals,
        |writer, terminal| {
            write_option(writer, terminal.as_ref(), |writer, terminal| {
                writer.write_extension(field, &terminal.0)
            })
        },
    )?;
    writer.write_vec("batch degree bits", &proof.degree_bits, |writer, degree| {
        writer.write_count("batch degree bits", *degree)
    })
}

pub(crate) fn read_batch_proof<SC, F>(
    reader: &mut Reader<'_>,
    field: FieldEncoding<F>,
    mut read_commitment: impl FnMut(
        &mut Reader<'_>,
    ) -> Result<p3_batch_stark::Commitment<SC>, ArtifactError>,
    mut read_opening_proof: impl FnMut(
        &mut Reader<'_>,
    ) -> Result<p3_batch_stark::PcsProof<SC>, ArtifactError>,
) -> Result<BatchProof<SC>, ArtifactError>
where
    SC: StarkGenericConfig,
    F: PrimeField64,
    SC::Challenge: BasedVectorSpace<F>,
{
    let main = read_commitment(reader)?;
    let permutation = read_option(reader, "permutation commitment", |reader| {
        read_commitment(reader)
    })?;
    let quotient_chunks = read_commitment(reader)?;
    let random = read_option(reader, "random commitment", |reader| {
        read_commitment(reader)
    })?;
    let max_instances = reader.limits().verifier.max_instances;
    let max_width = reader.limits().verifier.max_matrix_width;
    let instances =
        reader.read_vec_limited("batch opened-value instances", max_instances, 4, |reader| {
            Ok(OpenedValuesWithLookups {
                base_opened_values: read_opened_values(reader, field)?,
                permutation_local: read_extension_vec(
                    reader,
                    "permutation local openings",
                    max_width,
                    field,
                )?,
                permutation_next: read_extension_vec(
                    reader,
                    "permutation next openings",
                    max_width,
                    field,
                )?,
            })
        })?;
    let opening_proof = read_opening_proof(reader)?;
    let lookup_terminals =
        reader.read_vec_limited("lookup terminals", max_instances, 1, |reader| {
            read_option(reader, "lookup terminal", |reader| {
                reader.read_extension(field).map(LookupTerminal)
            })
        })?;
    let degree_bits = reader.read_vec_limited("batch degree bits", max_instances, 4, |reader| {
        let degree =
            usize::try_from(reader.read_u32()?).map_err(|_| ArtifactError::LengthOverflow)?;
        if degree > reader.limits().verifier.max_log_domain_or_degree {
            return Err(ArtifactError::DecodeLimitExceeded {
                component: "batch degree bits",
                actual: degree,
                limit: reader.limits().verifier.max_log_domain_or_degree,
            });
        }
        Ok(degree)
    })?;
    if instances.len() != lookup_terminals.len() || instances.len() != degree_bits.len() {
        return Err(ArtifactError::NonCanonicalMetadata);
    }
    Ok(BatchProof {
        commitments: BatchCommitments {
            main,
            permutation,
            quotient_chunks,
            random,
        },
        opened_values: BatchOpenedValues { instances },
        opening_proof,
        lookup_terminals,
        degree_bits,
    })
}
