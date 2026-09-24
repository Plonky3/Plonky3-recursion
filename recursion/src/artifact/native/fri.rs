use alloc::vec::Vec;

use p3_commit::{Mmcs, OpenedValues};
use p3_field::{ExtensionField, PrimeField64};
use p3_fri::{BatchMultiOpening, CommitPhaseMultiStep, FriProof};

use super::mmcs::MmcsCodec;
use crate::artifact::ArtifactError;
use crate::artifact::wire::{FieldEncoding, Reader, Writer};

type NativeFriProof<F, EF, InputMmcs, FriMmcs> =
    FriProof<EF, FriMmcs, F, Vec<BatchMultiOpening<F, InputMmcs>>>;
type HidingFriProof<F, EF, InputMmcs, FriMmcs> =
    (OpenedValues<EF>, NativeFriProof<F, EF, InputMmcs, FriMmcs>);

pub(crate) fn write_fri_proof<F, EF, InputMmcs, FriMmcs, InputCodec, FriCodec>(
    writer: &mut Writer,
    proof: &NativeFriProof<F, EF, InputMmcs, FriMmcs>,
    field: FieldEncoding<F>,
    input_codec: &InputCodec,
    fri_codec: &FriCodec,
) -> Result<(), ArtifactError>
where
    F: PrimeField64,
    EF: ExtensionField<F>,
    InputMmcs: Mmcs<F>,
    FriMmcs: Mmcs<EF>,
    InputCodec: MmcsCodec<F, InputMmcs>,
    FriCodec: MmcsCodec<EF, FriMmcs>,
{
    writer.write_field(field, proof.batch_pow_witness)?;
    writer.write_vec(
        "FRI commit-phase commitments",
        &proof.commit_phase_commits,
        |writer, commitment| fri_codec.write_commitment(writer, commitment),
    )?;
    writer.write_vec(
        "FRI commit PoW witnesses",
        &proof.commit_pow_witnesses,
        |writer, witness| writer.write_field(field, *witness),
    )?;
    writer.write_vec(
        "FRI input openings",
        &proof.input_openings,
        |writer, opening| {
            writer.write_vec(
                "FRI input query rows",
                &opening.opened_values,
                |writer, matrices| {
                    writer.write_vec("FRI input matrices", matrices, |writer, row| {
                        writer.write_vec("FRI input row", row, |writer, value| {
                            writer.write_field(field, *value)
                        })
                    })
                },
            )?;
            input_codec.write_multi_proof(writer, &opening.opening_proof)
        },
    )?;
    writer.write_vec(
        "FRI commit-phase openings",
        &proof.commit_phase_openings,
        |writer, step| {
            writer.write_vec("FRI sibling rows", &step.sibling_values, |writer, row| {
                writer.write_vec("FRI sibling values", row, |writer, value| {
                    writer.write_extension(field, value)
                })
            })?;
            fri_codec.write_multi_proof(writer, &step.opening_proof)
        },
    )?;
    if proof.final_poly.is_empty() || !proof.final_poly.len().is_power_of_two() {
        return Err(ArtifactError::MalformedProof {
            component: "FRI final polynomial",
        });
    }
    writer.write_vec(
        "FRI final polynomial",
        &proof.final_poly,
        |writer, value| writer.write_extension(field, value),
    )?;
    writer.write_field(field, proof.query_pow_witness)
}

pub(crate) fn read_fri_proof<F, EF, InputMmcs, FriMmcs, InputCodec, FriCodec>(
    reader: &mut Reader<'_>,
    field: FieldEncoding<F>,
    input_codec: &InputCodec,
    fri_codec: &FriCodec,
) -> Result<NativeFriProof<F, EF, InputMmcs, FriMmcs>, ArtifactError>
where
    F: PrimeField64,
    EF: ExtensionField<F>,
    InputMmcs: Mmcs<F>,
    FriMmcs: Mmcs<EF>,
    InputCodec: MmcsCodec<F, InputMmcs>,
    FriCodec: MmcsCodec<EF, FriMmcs>,
{
    let max_rounds = reader.limits().verifier.max_rounds;
    let max_queries = reader.limits().verifier.max_queries_per_round;
    let max_instances = reader.limits().verifier.max_instances;
    let max_width = reader.limits().verifier.max_matrix_width;
    let max_final_poly = reader.limits().verifier.max_final_poly_evaluations;
    let extension_bytes = field
        .encoded_bytes()
        .checked_mul(EF::DIMENSION)
        .ok_or(ArtifactError::LengthOverflow)?;

    let batch_pow_witness = reader.read_field(field)?;
    let commit_phase_commits =
        reader.read_vec_limited("FRI commit-phase commitments", max_rounds, 4, |reader| {
            fri_codec.read_commitment(reader)
        })?;
    let commit_pow_witnesses = reader.read_vec_limited(
        "FRI commit PoW witnesses",
        max_rounds,
        field.encoded_bytes(),
        |reader| reader.read_field(field),
    )?;
    let input_openings =
        reader.read_vec_limited("FRI input openings", max_instances, 8, |reader| {
            let opened_values =
                reader.read_vec_limited("FRI input query rows", max_queries, 4, |reader| {
                    reader.read_vec_limited("FRI input matrices", max_instances, 4, |reader| {
                        reader.read_vec_limited(
                            "FRI input row",
                            max_width,
                            field.encoded_bytes(),
                            |reader| reader.read_field(field),
                        )
                    })
                })?;
            let opening_proof = input_codec.read_multi_proof(reader)?;
            Ok(BatchMultiOpening {
                opened_values,
                opening_proof,
            })
        })?;
    let commit_phase_openings =
        reader.read_vec_limited("FRI commit-phase openings", max_rounds, 9, |reader| {
            let sibling_values =
                reader.read_vec_limited("FRI sibling rows", max_queries, 4, |reader| {
                    reader.read_vec_limited(
                        "FRI sibling values",
                        max_width,
                        extension_bytes,
                        |reader| reader.read_extension(field),
                    )
                })?;
            let opening_proof = fri_codec.read_multi_proof(reader)?;
            Ok(CommitPhaseMultiStep {
                sibling_values,
                opening_proof,
            })
        })?;
    let final_poly = reader.read_vec_limited(
        "FRI final polynomial",
        max_final_poly,
        extension_bytes,
        |reader| reader.read_extension(field),
    )?;
    if final_poly.is_empty() || !final_poly.len().is_power_of_two() {
        return Err(ArtifactError::MalformedProof {
            component: "FRI final polynomial",
        });
    }
    let query_pow_witness = reader.read_field(field)?;
    Ok(FriProof {
        batch_pow_witness,
        commit_phase_commits,
        commit_pow_witnesses,
        input_openings,
        commit_phase_openings,
        final_poly,
        query_pow_witness,
    })
}

fn write_opened_values<F, EF>(
    writer: &mut Writer,
    values: &OpenedValues<EF>,
    field: FieldEncoding<F>,
) -> Result<(), ArtifactError>
where
    F: PrimeField64,
    EF: ExtensionField<F>,
{
    writer.write_vec("hiding rounds", values, |writer, matrices| {
        writer.write_vec("hiding matrices", matrices, |writer, points| {
            writer.write_vec("hiding points", points, |writer, values| {
                writer.write_vec("hiding opened values", values, |writer, value| {
                    writer.write_extension(field, value)
                })
            })
        })
    })
}

fn read_opened_values<F, EF>(
    reader: &mut Reader<'_>,
    field: FieldEncoding<F>,
) -> Result<OpenedValues<EF>, ArtifactError>
where
    F: PrimeField64,
    EF: ExtensionField<F>,
{
    let max_rounds = reader.limits().verifier.max_rounds;
    let max_instances = reader.limits().verifier.max_instances;
    let max_points = reader.limits().verifier.max_queries_per_round;
    let max_width = reader.limits().verifier.max_matrix_width;
    let extension_bytes = field
        .encoded_bytes()
        .checked_mul(EF::DIMENSION)
        .ok_or(ArtifactError::LengthOverflow)?;
    reader.read_vec_limited("hiding rounds", max_rounds, 4, |reader| {
        reader.read_vec_limited("hiding matrices", max_instances, 4, |reader| {
            reader.read_vec_limited("hiding points", max_points, 4, |reader| {
                reader.read_vec_limited(
                    "hiding opened values",
                    max_width,
                    extension_bytes,
                    |reader| reader.read_extension(field),
                )
            })
        })
    })
}

pub(crate) fn write_hiding_fri_proof<F, EF, InputMmcs, FriMmcs, InputCodec, FriCodec>(
    writer: &mut Writer,
    proof: &HidingFriProof<F, EF, InputMmcs, FriMmcs>,
    field: FieldEncoding<F>,
    input_codec: &InputCodec,
    fri_codec: &FriCodec,
) -> Result<(), ArtifactError>
where
    F: PrimeField64,
    EF: ExtensionField<F>,
    InputMmcs: Mmcs<F>,
    FriMmcs: Mmcs<EF>,
    InputCodec: MmcsCodec<F, InputMmcs>,
    FriCodec: MmcsCodec<EF, FriMmcs>,
{
    write_opened_values(writer, &proof.0, field)?;
    write_fri_proof(writer, &proof.1, field, input_codec, fri_codec)
}

pub(crate) fn read_hiding_fri_proof<F, EF, InputMmcs, FriMmcs, InputCodec, FriCodec>(
    reader: &mut Reader<'_>,
    field: FieldEncoding<F>,
    input_codec: &InputCodec,
    fri_codec: &FriCodec,
) -> Result<HidingFriProof<F, EF, InputMmcs, FriMmcs>, ArtifactError>
where
    F: PrimeField64,
    EF: ExtensionField<F>,
    InputMmcs: Mmcs<F>,
    FriMmcs: Mmcs<EF>,
    InputCodec: MmcsCodec<F, InputMmcs>,
    FriCodec: MmcsCodec<EF, FriMmcs>,
{
    let opened_values = read_opened_values(reader, field)?;
    let proof = read_fri_proof(reader, field, input_codec, fri_codec)?;
    Ok((opened_values, proof))
}
