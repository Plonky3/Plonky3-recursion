use p3_commit::Mmcs;
use p3_field::{ExtensionField, PrimeField64};
use p3_multilinear_util::poly::Poly;
use p3_sumcheck::{OpeningBatch, SumcheckData};
use p3_whir::{PcsProof, QueryOpenings, SharedProofOpening, WhirProof, WhirRoundProof};

use crate::artifact::ArtifactError;
use crate::artifact::wire::{FieldEncoding, Reader, Writer};
use crate::pcs::whir::uni::WhirUniProof;

use super::mmcs::MmcsCodec;

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

pub(crate) fn read_option<T>(
    reader: &mut Reader<'_>,
    component: &'static str,
    read_value: impl FnOnce(&mut Reader<'_>) -> Result<T, ArtifactError>,
) -> Result<Option<T>, ArtifactError> {
    match reader.read_u8()? {
        0 => Ok(None),
        1 => read_value(reader).map(Some),
        tag => Err(ArtifactError::InvalidTag { component, tag }),
    }
}

fn write_sumcheck<F, EF>(
    writer: &mut Writer,
    sumcheck: &SumcheckData<F, EF>,
    field: FieldEncoding<F>,
) -> Result<(), ArtifactError>
where
    F: PrimeField64,
    EF: ExtensionField<F>,
{
    writer.write_vec(
        "WHIR sumcheck evaluations",
        &sumcheck.polynomial_evaluations,
        |writer, evaluations| {
            writer.write_extension(field, &evaluations[0])?;
            writer.write_extension(field, &evaluations[1])
        },
    )?;
    writer.write_vec(
        "WHIR sumcheck PoW witnesses",
        &sumcheck.pow_witnesses,
        |writer, witness| writer.write_field(field, *witness),
    )
}

fn read_sumcheck<F, EF>(
    reader: &mut Reader<'_>,
    field: FieldEncoding<F>,
) -> Result<SumcheckData<F, EF>, ArtifactError>
where
    F: PrimeField64,
    EF: ExtensionField<F>,
{
    let max_rounds = reader.limits().verifier.max_rounds;
    let extension_bytes = field
        .encoded_bytes()
        .checked_mul(EF::DIMENSION)
        .ok_or(ArtifactError::LengthOverflow)?;
    let polynomial_evaluations = reader.read_vec_limited(
        "WHIR sumcheck evaluations",
        max_rounds,
        extension_bytes
            .checked_mul(2)
            .ok_or(ArtifactError::LengthOverflow)?,
        |reader| Ok([reader.read_extension(field)?, reader.read_extension(field)?]),
    )?;
    let pow_witnesses = reader.read_vec_limited(
        "WHIR sumcheck PoW witnesses",
        max_rounds,
        field.encoded_bytes(),
        |reader| reader.read_field(field),
    )?;
    Ok(SumcheckData {
        polynomial_evaluations,
        pow_witnesses,
    })
}

fn write_shared_opening<F, T, M, Codec>(
    writer: &mut Writer,
    opening: &SharedProofOpening<T, <M as Mmcs<F>>::MultiProof>,
    field: FieldEncoding<F>,
    codec: &Codec,
    mut write_value: impl FnMut(&mut Writer, &T, FieldEncoding<F>) -> Result<(), ArtifactError>,
) -> Result<(), ArtifactError>
where
    F: PrimeField64,
    T: Send + Sync + Clone,
    M: Mmcs<F>,
    Codec: MmcsCodec<F, M>,
{
    writer.write_vec("WHIR query rows", &opening.rows, |writer, row| {
        writer.write_vec("WHIR query row", row, |writer, value| {
            write_value(writer, value, field)
        })
    })?;
    codec.write_multi_proof(writer, &opening.proof)
}

fn read_shared_opening<F, T, M, Codec>(
    reader: &mut Reader<'_>,
    field: FieldEncoding<F>,
    codec: &Codec,
    minimum_value_bytes: usize,
    mut read_value: impl FnMut(&mut Reader<'_>, FieldEncoding<F>) -> Result<T, ArtifactError>,
) -> Result<SharedProofOpening<T, <M as Mmcs<F>>::MultiProof>, ArtifactError>
where
    F: PrimeField64,
    T: Send + Sync + Clone,
    M: Mmcs<F>,
    Codec: MmcsCodec<F, M>,
{
    let max_queries = reader.limits().verifier.max_queries_per_round;
    let max_width = reader.limits().verifier.max_matrix_width;
    let rows = reader.read_vec_limited("WHIR query rows", max_queries, 4, |reader| {
        reader.read_vec_limited("WHIR query row", max_width, minimum_value_bytes, |reader| {
            read_value(reader, field)
        })
    })?;
    let proof = codec.read_multi_proof(reader)?;
    Ok(SharedProofOpening { rows, proof })
}

fn write_query_openings<F, EF, M, Codec>(
    writer: &mut Writer,
    openings: &QueryOpenings<F, EF, <M as Mmcs<F>>::MultiProof>,
    field: FieldEncoding<F>,
    codec: &Codec,
) -> Result<(), ArtifactError>
where
    F: PrimeField64,
    EF: ExtensionField<F>,
    M: Mmcs<F>,
    Codec: MmcsCodec<F, M>,
{
    match openings {
        QueryOpenings::Base(opening) => {
            writer.write_u8(0)?;
            write_shared_opening::<F, F, M, Codec>(
                writer,
                opening,
                field,
                codec,
                |writer, value, field| writer.write_field(field, *value),
            )
        }
        QueryOpenings::Extension(opening) => {
            writer.write_u8(1)?;
            write_shared_opening::<F, EF, M, Codec>(
                writer,
                opening,
                field,
                codec,
                |writer, value, field| writer.write_extension(field, value),
            )
        }
    }
}

pub(super) fn read_query_openings<F, EF, M, Codec>(
    reader: &mut Reader<'_>,
    field: FieldEncoding<F>,
    codec: &Codec,
) -> Result<QueryOpenings<F, EF, <M as Mmcs<F>>::MultiProof>, ArtifactError>
where
    F: PrimeField64,
    EF: ExtensionField<F>,
    M: Mmcs<F>,
    Codec: MmcsCodec<F, M>,
{
    match reader.read_u8()? {
        0 => read_shared_opening::<F, F, M, Codec>(
            reader,
            field,
            codec,
            field.encoded_bytes(),
            |reader, field| reader.read_field(field),
        )
        .map(QueryOpenings::Base),
        1 => {
            let extension_bytes = field
                .encoded_bytes()
                .checked_mul(EF::DIMENSION)
                .ok_or(ArtifactError::LengthOverflow)?;
            read_shared_opening::<F, EF, M, Codec>(
                reader,
                field,
                codec,
                extension_bytes,
                |reader, field| reader.read_extension(field),
            )
            .map(QueryOpenings::Extension)
        }
        tag => Err(ArtifactError::InvalidTag {
            component: "WHIR query field",
            tag,
        }),
    }
}

fn write_optional_poly<F, EF>(
    writer: &mut Writer,
    polynomial: Option<&Poly<EF>>,
    field: FieldEncoding<F>,
) -> Result<(), ArtifactError>
where
    F: PrimeField64,
    EF: ExtensionField<F>,
{
    write_option(writer, polynomial, |writer, polynomial| {
        if polynomial.as_slice().is_empty() || !polynomial.as_slice().len().is_power_of_two() {
            return Err(ArtifactError::MalformedProof {
                component: "WHIR final polynomial",
            });
        }
        writer.write_vec(
            "WHIR final polynomial",
            polynomial.as_slice(),
            |writer, value| writer.write_extension(field, value),
        )
    })
}

pub(crate) fn read_optional_poly<F, EF>(
    reader: &mut Reader<'_>,
    field: FieldEncoding<F>,
) -> Result<Option<Poly<EF>>, ArtifactError>
where
    F: PrimeField64,
    EF: ExtensionField<F>,
{
    read_option(reader, "WHIR final polynomial", |reader| {
        let max_final_poly = reader.limits().verifier.max_final_poly_evaluations;
        let extension_bytes = field
            .encoded_bytes()
            .checked_mul(EF::DIMENSION)
            .ok_or(ArtifactError::LengthOverflow)?;
        let evaluations = reader.read_vec_limited(
            "WHIR final polynomial",
            max_final_poly,
            extension_bytes,
            |reader| reader.read_extension(field),
        )?;
        if evaluations.is_empty() || !evaluations.len().is_power_of_two() {
            return Err(ArtifactError::MalformedProof {
                component: "WHIR final polynomial",
            });
        }
        Ok(Poly::new(evaluations))
    })
}

fn write_whir_pcs_proof<F, EF, M, Codec>(
    writer: &mut Writer,
    proof: &PcsProof<F, EF, M>,
    field: FieldEncoding<F>,
    codec: &Codec,
) -> Result<(), ArtifactError>
where
    F: PrimeField64,
    EF: ExtensionField<F>,
    M: Mmcs<F>,
    Codec: MmcsCodec<F, M>,
{
    let whir = &proof.whir;
    writer.write_vec(
        "WHIR initial OOD answers",
        &whir.initial_ood_answers,
        |writer, value| writer.write_extension(field, value),
    )?;
    write_sumcheck(writer, &whir.initial_sumcheck, field)?;
    writer.write_vec("WHIR rounds", &whir.rounds, |writer, round| {
        write_option(writer, round.commitment.as_ref(), |writer, commitment| {
            <Codec as MmcsCodec<F, M>>::write_commitment(codec, writer, commitment)
        })?;
        writer.write_vec(
            "WHIR round OOD answers",
            &round.ood_answers,
            |writer, value| writer.write_extension(field, value),
        )?;
        writer.write_field(field, round.pow_witness)?;
        write_query_openings::<F, EF, M, Codec>(writer, &round.openings, field, codec)?;
        write_sumcheck(writer, &round.sumcheck, field)
    })?;
    write_optional_poly(writer, whir.final_poly.as_ref(), field)?;
    writer.write_field(field, whir.final_pow_witness)?;
    write_query_openings::<F, EF, M, Codec>(writer, &whir.final_openings, field, codec)?;
    write_option(writer, whir.final_sumcheck.as_ref(), |writer, sumcheck| {
        write_sumcheck(writer, sumcheck, field)
    })?;
    writer.write_vec("WHIR opening batches", &proof.evals, |writer, batch| {
        writer.write_vec(
            "WHIR current evaluations",
            batch.current(),
            |writer, value| writer.write_extension(field, value),
        )?;
        writer.write_vec("WHIR next evaluations", batch.next(), |writer, value| {
            writer.write_extension(field, value)
        })
    })
}

pub(super) fn read_whir_pcs_proof<F, EF, M, Codec>(
    reader: &mut Reader<'_>,
    field: FieldEncoding<F>,
    codec: &Codec,
) -> Result<PcsProof<F, EF, M>, ArtifactError>
where
    F: PrimeField64,
    EF: ExtensionField<F>,
    M: Mmcs<F>,
    Codec: MmcsCodec<F, M>,
{
    let max_rounds = reader.limits().verifier.max_rounds;
    let max_instances = reader.limits().verifier.max_instances;
    let max_width = reader.limits().verifier.max_matrix_width;
    let extension_bytes = field
        .encoded_bytes()
        .checked_mul(EF::DIMENSION)
        .ok_or(ArtifactError::LengthOverflow)?;
    let initial_ood_answers = reader.read_vec_limited(
        "WHIR initial OOD answers",
        max_width,
        extension_bytes,
        |reader| reader.read_extension(field),
    )?;
    let initial_sumcheck = read_sumcheck(reader, field)?;
    let rounds = reader.read_vec_limited("WHIR rounds", max_rounds, 14, |reader| {
        let commitment = read_option(reader, "WHIR commitment", |reader| {
            <Codec as MmcsCodec<F, M>>::read_commitment(codec, reader)
        })?;
        let ood_answers = reader.read_vec_limited(
            "WHIR round OOD answers",
            max_width,
            extension_bytes,
            |reader| reader.read_extension(field),
        )?;
        let pow_witness = reader.read_field(field)?;
        let openings = read_query_openings::<F, EF, M, Codec>(reader, field, codec)?;
        let sumcheck = read_sumcheck(reader, field)?;
        Ok(WhirRoundProof {
            commitment,
            ood_answers,
            pow_witness,
            openings,
            sumcheck,
        })
    })?;
    let final_poly = read_optional_poly(reader, field)?;
    let final_pow_witness = reader.read_field(field)?;
    let final_openings = read_query_openings::<F, EF, M, Codec>(reader, field, codec)?;
    let final_sumcheck = read_option(reader, "WHIR final sumcheck", |reader| {
        read_sumcheck(reader, field)
    })?;
    let evals = reader.read_vec_limited("WHIR opening batches", max_instances, 8, |reader| {
        let current = reader.read_vec_limited(
            "WHIR current evaluations",
            max_width,
            extension_bytes,
            |reader| reader.read_extension(field),
        )?;
        let next = reader.read_vec_limited(
            "WHIR next evaluations",
            max_width,
            extension_bytes,
            |reader| reader.read_extension(field),
        )?;
        if current.is_empty() && next.is_empty() {
            return Err(ArtifactError::MalformedProof {
                component: "WHIR opening batch",
            });
        }
        Ok(OpeningBatch::new(current, next))
    })?;
    Ok(PcsProof {
        whir: WhirProof {
            initial_ood_answers,
            initial_sumcheck,
            rounds,
            final_poly,
            final_pow_witness,
            final_openings,
            final_sumcheck,
        },
        evals,
    })
}

pub(crate) fn write_whir_uni_proof<F, EF, M, Codec>(
    writer: &mut Writer,
    proof: &WhirUniProof<F, EF, M>,
    field: FieldEncoding<F>,
    codec: &Codec,
) -> Result<(), ArtifactError>
where
    F: PrimeField64,
    EF: ExtensionField<F>,
    M: Mmcs<F>,
    Codec: MmcsCodec<F, M>,
{
    writer.write_vec("WHIR PCS rounds", &proof.rounds, |writer, proof| {
        write_whir_pcs_proof(writer, proof, field, codec)
    })
}

pub(crate) fn read_whir_uni_proof<F, EF, M, Codec>(
    reader: &mut Reader<'_>,
    field: FieldEncoding<F>,
    codec: &Codec,
) -> Result<WhirUniProof<F, EF, M>, ArtifactError>
where
    F: PrimeField64,
    EF: ExtensionField<F>,
    M: Mmcs<F>,
    Codec: MmcsCodec<F, M>,
{
    let max_instances = reader.limits().verifier.max_instances;
    let rounds = reader.read_vec_limited("WHIR PCS rounds", max_instances, 4, |reader| {
        read_whir_pcs_proof(reader, field, codec)
    })?;
    Ok(WhirUniProof { rounds })
}
