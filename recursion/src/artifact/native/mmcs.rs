use alloc::vec::Vec;

use p3_commit::Mmcs;
use p3_field::PrimeField64;
use p3_merkle_tree::PrunedMerklePaths;
use p3_symmetric::MerkleCap;

use crate::artifact::ArtifactError;
use crate::artifact::wire::{FieldEncoding, Reader, Writer};

type SaltedMultiProof<F, const DIGEST_ELEMS: usize> =
    (Vec<Vec<Vec<F>>>, PrunedMerklePaths<F, DIGEST_ELEMS>);

pub(crate) trait MmcsCodec<T, M: Mmcs<T>>
where
    T: Send + Sync + Clone,
{
    fn write_commitment(
        &self,
        writer: &mut Writer,
        commitment: &M::Commitment,
    ) -> Result<(), ArtifactError>;

    fn read_commitment(&self, reader: &mut Reader<'_>) -> Result<M::Commitment, ArtifactError>;

    fn write_multi_proof(
        &self,
        writer: &mut Writer,
        proof: &M::MultiProof,
    ) -> Result<(), ArtifactError>;

    fn read_multi_proof(&self, reader: &mut Reader<'_>) -> Result<M::MultiProof, ArtifactError>;
}

#[derive(Clone, Copy)]
pub(crate) struct MerkleMmcsCodec<F, const DIGEST_ELEMS: usize> {
    field: FieldEncoding<F>,
}

impl<F: PrimeField64, const DIGEST_ELEMS: usize> MerkleMmcsCodec<F, DIGEST_ELEMS> {
    pub(crate) const fn new(field: FieldEncoding<F>) -> Self {
        Self { field }
    }
}

#[derive(Clone, Copy)]
pub(crate) struct SaltedMerkleMmcsCodec<F, const DIGEST_ELEMS: usize, const SALT_ELEMS: usize> {
    field: FieldEncoding<F>,
}

impl<F: PrimeField64, const DIGEST_ELEMS: usize, const SALT_ELEMS: usize>
    SaltedMerkleMmcsCodec<F, DIGEST_ELEMS, SALT_ELEMS>
{
    pub(crate) const fn new(field: FieldEncoding<F>) -> Self {
        Self { field }
    }
}

fn write_digest<F: PrimeField64, const DIGEST_ELEMS: usize>(
    writer: &mut Writer,
    digest: &[F; DIGEST_ELEMS],
    field: FieldEncoding<F>,
) -> Result<(), ArtifactError> {
    for &element in digest {
        writer.write_field(field, element)?;
    }
    Ok(())
}

fn read_digest<F: PrimeField64, const DIGEST_ELEMS: usize>(
    reader: &mut Reader<'_>,
    field: FieldEncoding<F>,
) -> Result<[F; DIGEST_ELEMS], ArtifactError> {
    let mut digest = [F::ZERO; DIGEST_ELEMS];
    for element in &mut digest {
        *element = reader.read_field(field)?;
    }
    Ok(digest)
}

pub(crate) fn write_merkle_cap<F: PrimeField64, const DIGEST_ELEMS: usize>(
    writer: &mut Writer,
    cap: &MerkleCap<F, [F; DIGEST_ELEMS]>,
    field: FieldEncoding<F>,
) -> Result<(), ArtifactError> {
    writer.write_vec("Merkle cap roots", cap.roots(), |writer, root| {
        write_digest(writer, root, field)
    })
}

pub(crate) fn read_merkle_cap<F: PrimeField64, const DIGEST_ELEMS: usize>(
    reader: &mut Reader<'_>,
    field: FieldEncoding<F>,
) -> Result<MerkleCap<F, [F; DIGEST_ELEMS]>, ArtifactError> {
    let max_roots = reader.limits().verifier.max_cap_roots;
    let min_root_bytes = field
        .encoded_bytes()
        .checked_mul(DIGEST_ELEMS)
        .ok_or(ArtifactError::LengthOverflow)?;
    let roots =
        reader.read_vec_limited("Merkle cap roots", max_roots, min_root_bytes, |reader| {
            read_digest(reader, field)
        })?;
    if roots.is_empty() || !roots.len().is_power_of_two() {
        return Err(ArtifactError::MalformedProof {
            component: "Merkle cap",
        });
    }
    Ok(MerkleCap::new(roots))
}

fn write_pruned_paths<F: PrimeField64, const DIGEST_ELEMS: usize>(
    writer: &mut Writer,
    paths: &PrunedMerklePaths<F, DIGEST_ELEMS>,
    field: FieldEncoding<F>,
) -> Result<(), ArtifactError> {
    writer.write_vec(
        "compressed frontier hashes",
        &paths.sibling_hashes,
        |writer, hash| write_digest(writer, hash, field),
    )
}

fn read_pruned_paths<F: PrimeField64, const DIGEST_ELEMS: usize>(
    reader: &mut Reader<'_>,
    field: FieldEncoding<F>,
) -> Result<PrunedMerklePaths<F, DIGEST_ELEMS>, ArtifactError> {
    let max_hashes = reader.limits().verifier.max_compressed_frontier_hashes;
    let min_hash_bytes = field
        .encoded_bytes()
        .checked_mul(DIGEST_ELEMS)
        .ok_or(ArtifactError::LengthOverflow)?;
    let sibling_hashes = reader.read_vec_limited(
        "compressed frontier hashes",
        max_hashes,
        min_hash_bytes,
        |reader| read_digest(reader, field),
    )?;
    Ok(PrunedMerklePaths { sibling_hashes })
}

pub(crate) fn write_salted_multi_proof<
    F: PrimeField64,
    const DIGEST_ELEMS: usize,
    const SALT_ELEMS: usize,
>(
    writer: &mut Writer,
    proof: &(Vec<Vec<Vec<F>>>, PrunedMerklePaths<F, DIGEST_ELEMS>),
    field: FieldEncoding<F>,
) -> Result<(), ArtifactError> {
    writer.write_vec("salt query rows", &proof.0, |writer, matrices| {
        writer.write_vec("salt matrices", matrices, |writer, salt| {
            if salt.len() != SALT_ELEMS {
                return Err(ArtifactError::MalformedProof {
                    component: "MMCS salt",
                });
            }
            writer.write_vec("MMCS salt", salt, |writer, value| {
                writer.write_field(field, *value)
            })
        })
    })?;
    write_pruned_paths(writer, &proof.1, field)
}

pub(crate) fn read_salted_multi_proof<
    F: PrimeField64,
    const DIGEST_ELEMS: usize,
    const SALT_ELEMS: usize,
>(
    reader: &mut Reader<'_>,
    field: FieldEncoding<F>,
) -> Result<SaltedMultiProof<F, DIGEST_ELEMS>, ArtifactError> {
    let max_queries = reader.limits().verifier.max_queries_per_round;
    let max_matrices = reader.limits().verifier.max_instances;
    let salts = reader.read_vec_limited("salt query rows", max_queries, 4, |reader| {
        reader.read_vec_limited("salt matrices", max_matrices, 4, |reader| {
            reader.read_vec_exact("MMCS salt", SALT_ELEMS, field.encoded_bytes(), |reader| {
                reader.read_field(field)
            })
        })
    })?;
    let paths = read_pruned_paths(reader, field)?;
    Ok((salts, paths))
}

impl<T, M, F, const DIGEST_ELEMS: usize> MmcsCodec<T, M> for MerkleMmcsCodec<F, DIGEST_ELEMS>
where
    T: Send + Sync + Clone,
    F: PrimeField64,
    M: Mmcs<
            T,
            Commitment = MerkleCap<F, [F; DIGEST_ELEMS]>,
            MultiProof = PrunedMerklePaths<F, DIGEST_ELEMS>,
        >,
{
    fn write_commitment(
        &self,
        writer: &mut Writer,
        commitment: &M::Commitment,
    ) -> Result<(), ArtifactError> {
        write_merkle_cap(writer, commitment, self.field)
    }

    fn read_commitment(&self, reader: &mut Reader<'_>) -> Result<M::Commitment, ArtifactError> {
        read_merkle_cap(reader, self.field)
    }

    fn write_multi_proof(
        &self,
        writer: &mut Writer,
        proof: &M::MultiProof,
    ) -> Result<(), ArtifactError> {
        write_pruned_paths(writer, proof, self.field)
    }

    fn read_multi_proof(&self, reader: &mut Reader<'_>) -> Result<M::MultiProof, ArtifactError> {
        read_pruned_paths(reader, self.field)
    }
}

impl<T, M, F, const DIGEST_ELEMS: usize, const SALT_ELEMS: usize> MmcsCodec<T, M>
    for SaltedMerkleMmcsCodec<F, DIGEST_ELEMS, SALT_ELEMS>
where
    T: Send + Sync + Clone,
    F: PrimeField64,
    M: Mmcs<
            T,
            Commitment = MerkleCap<F, [F; DIGEST_ELEMS]>,
            MultiProof = (Vec<Vec<Vec<F>>>, PrunedMerklePaths<F, DIGEST_ELEMS>),
        >,
{
    fn write_commitment(
        &self,
        writer: &mut Writer,
        commitment: &M::Commitment,
    ) -> Result<(), ArtifactError> {
        write_merkle_cap(writer, commitment, self.field)
    }

    fn read_commitment(&self, reader: &mut Reader<'_>) -> Result<M::Commitment, ArtifactError> {
        read_merkle_cap(reader, self.field)
    }

    fn write_multi_proof(
        &self,
        writer: &mut Writer,
        proof: &M::MultiProof,
    ) -> Result<(), ArtifactError> {
        write_salted_multi_proof::<F, DIGEST_ELEMS, SALT_ELEMS>(writer, proof, self.field)
    }

    fn read_multi_proof(&self, reader: &mut Reader<'_>) -> Result<M::MultiProof, ArtifactError> {
        read_salted_multi_proof::<F, DIGEST_ELEMS, SALT_ELEMS>(reader, self.field)
    }
}
