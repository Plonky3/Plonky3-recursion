use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec::Vec;

use p3_baby_bear::BabyBear;
use p3_circuit::ops::NpoTypeId;
use p3_circuit::{StatementError, StatementSchema};
use p3_circuit_prover::{BatchStarkProof, CircuitVerifier, NonPrimitiveTableEntry, TablePacking};
use p3_field::extension::{BinomialExtensionField, QuinticTrinomialExtensionField};
use p3_field::{Algebra, BasedVectorSpace, PrimeField64};
use p3_goldilocks::Goldilocks;
use p3_koala_bear::KoalaBear;
use p3_uni_stark::{StarkGenericConfig, SymbolicExpression, SymbolicExpressionExt};
use rand::rngs::StdRng;
use rand::{CryptoRng, SeedableRng};

use super::descriptor::{
    RelationDescriptorV1, read_common, read_config, read_relation, write_common, write_config,
    write_relation,
};
use super::native::{
    MerkleMmcsCodec, SaltedMerkleMmcsCodec, read_batch_proof, read_fri_proof,
    read_hiding_fri_proof, read_merkle_cap, read_whir_uni_proof, write_batch_proof,
    write_fri_proof, write_hiding_fri_proof, write_merkle_cap, write_whir_uni_proof,
};
use super::wire::{FieldEncoding, Reader, Writer, decode_framed, encode_framed};
use super::{
    ArtifactError, ArtifactKind, ArtifactLimits, CanonicalStatement, PortableVerifier,
    PortableVerifierInner,
};
use crate::builtin_config::*;

mod private {
    pub trait Sealed {}
}

pub(crate) trait BuiltinArtifactConfig:
    private::Sealed + StarkGenericConfig + Sized + Send + Sync + 'static
where
    p3_batch_stark::Val<Self>: PrimeField64,
    Self::Challenge: BasedVectorSpace<p3_batch_stark::Val<Self>>,
{
    fn artifact_descriptor(&self) -> BuiltinConfigDescriptorV1;
    fn field_encoding() -> FieldEncoding<p3_batch_stark::Val<Self>>;
    fn reconstruct(
        descriptor: &BuiltinConfigDescriptorV1,
        limits: &ArtifactLimits,
    ) -> Result<Self, ArtifactError>;
    fn write_commitment(
        writer: &mut Writer,
        commitment: &p3_batch_stark::Commitment<Self>,
    ) -> Result<(), ArtifactError>;
    fn read_commitment(
        reader: &mut Reader<'_>,
    ) -> Result<p3_batch_stark::Commitment<Self>, ArtifactError>;
    fn write_opening_proof(
        writer: &mut Writer,
        proof: &p3_batch_stark::PcsProof<Self>,
    ) -> Result<(), ArtifactError>;
    fn read_opening_proof(
        reader: &mut Reader<'_>,
    ) -> Result<p3_batch_stark::PcsProof<Self>, ArtifactError>;
}

macro_rules! ordinary_impl {
    ($config:ty, $field:ty, $challenge:ty, $digest:expr, $encoding:expr, $factory:path) => {
        impl private::Sealed for $config {}
        impl BuiltinArtifactConfig for $config {
            fn artifact_descriptor(&self) -> BuiltinConfigDescriptorV1 {
                BuiltinConfigDescriptorV1::Fri(*self.descriptor())
            }

            fn field_encoding() -> FieldEncoding<p3_batch_stark::Val<Self>> {
                $encoding
            }

            fn reconstruct(
                descriptor: &BuiltinConfigDescriptorV1,
                limits: &ArtifactLimits,
            ) -> Result<Self, ArtifactError> {
                let BuiltinConfigDescriptorV1::Fri(descriptor) = descriptor else {
                    return Err(ArtifactError::NonCanonicalMetadata);
                };
                Ok($factory(descriptor, &limits.verifier)?)
            }

            fn write_commitment(
                writer: &mut Writer,
                commitment: &p3_batch_stark::Commitment<Self>,
            ) -> Result<(), ArtifactError> {
                write_merkle_cap::<$field, $digest>(writer, commitment, Self::field_encoding())
            }

            fn read_commitment(
                reader: &mut Reader<'_>,
            ) -> Result<p3_batch_stark::Commitment<Self>, ArtifactError> {
                read_merkle_cap::<$field, $digest>(reader, Self::field_encoding())
            }

            fn write_opening_proof(
                writer: &mut Writer,
                proof: &p3_batch_stark::PcsProof<Self>,
            ) -> Result<(), ArtifactError> {
                let codec = MerkleMmcsCodec::<$field, $digest>::new(Self::field_encoding());
                write_fri_proof::<$field, $challenge, _, _, _, _>(
                    writer,
                    proof,
                    Self::field_encoding(),
                    &codec,
                    &codec,
                )
            }

            fn read_opening_proof(
                reader: &mut Reader<'_>,
            ) -> Result<p3_batch_stark::PcsProof<Self>, ArtifactError> {
                let codec = MerkleMmcsCodec::<$field, $digest>::new(Self::field_encoding());
                read_fri_proof::<$field, $challenge, _, _, _, _>(
                    reader,
                    Self::field_encoding(),
                    &codec,
                    &codec,
                )
            }
        }
    };
}

ordinary_impl!(BabyBearD4Poseidon2BinaryConfig, BabyBear, BinomialExtensionField<BabyBear, 4>, 8, FieldEncoding::u32(), baby_bear_d4_poseidon2_binary);
ordinary_impl!(BabyBearD4Poseidon1BinaryConfig, BabyBear, BinomialExtensionField<BabyBear, 4>, 8, FieldEncoding::u32(), baby_bear_d4_poseidon1_binary);
ordinary_impl!(KoalaBearD4Poseidon2BinaryConfig, KoalaBear, BinomialExtensionField<KoalaBear, 4>, 8, FieldEncoding::u32(), koala_bear_d4_poseidon2_binary);
ordinary_impl!(KoalaBearD4Poseidon1BinaryConfig, KoalaBear, BinomialExtensionField<KoalaBear, 4>, 8, FieldEncoding::u32(), koala_bear_d4_poseidon1_binary);
ordinary_impl!(GoldilocksD2Poseidon2BinaryConfig, Goldilocks, BinomialExtensionField<Goldilocks, 2>, 4, FieldEncoding::u64(), goldilocks_d2_poseidon2_binary);
ordinary_impl!(GoldilocksD2Poseidon1BinaryConfig, Goldilocks, BinomialExtensionField<Goldilocks, 2>, 4, FieldEncoding::u64(), goldilocks_d2_poseidon1_binary);
ordinary_impl!(
    KoalaBearD5Poseidon2BinaryConfig,
    KoalaBear,
    QuinticTrinomialExtensionField<KoalaBear>,
    8,
    FieldEncoding::u32(),
    koala_bear_d5_poseidon2_binary
);
ordinary_impl!(
    KoalaBearD5Poseidon1BinaryConfig,
    KoalaBear,
    QuinticTrinomialExtensionField<KoalaBear>,
    8,
    FieldEncoding::u32(),
    koala_bear_d5_poseidon1_binary
);
ordinary_impl!(BabyBearD4Poseidon2QuaternaryConfig, BabyBear, BinomialExtensionField<BabyBear, 4>, 8, FieldEncoding::u32(), baby_bear_d4_poseidon2_quaternary);
ordinary_impl!(KoalaBearD4Poseidon2QuaternaryConfig, KoalaBear, BinomialExtensionField<KoalaBear, 4>, 8, FieldEncoding::u32(), koala_bear_d4_poseidon2_quaternary);
ordinary_impl!(GoldilocksD2Poseidon2QuaternaryConfig, Goldilocks, BinomialExtensionField<Goldilocks, 2>, 4, FieldEncoding::u64(), goldilocks_d2_poseidon2_quaternary);
ordinary_impl!(
    KoalaBearD5Poseidon2QuaternaryConfig,
    KoalaBear,
    QuinticTrinomialExtensionField<KoalaBear>,
    8,
    FieldEncoding::u32(),
    koala_bear_d5_poseidon2_quaternary
);

macro_rules! random_codeword_impl {
    ($config:ident, $field:ty, $challenge:ty, $digest:expr, $encoding:expr, $factory:path) => {
        impl<R> private::Sealed for $config<R> where
            R: CryptoRng + SeedableRng + Send + Sync + 'static
        {
        }
        impl<R> BuiltinArtifactConfig for $config<R>
        where
            R: CryptoRng + SeedableRng + Send + Sync + 'static,
        {
            fn artifact_descriptor(&self) -> BuiltinConfigDescriptorV1 {
                BuiltinConfigDescriptorV1::Fri(*self.descriptor())
            }
            fn field_encoding() -> FieldEncoding<p3_batch_stark::Val<Self>> {
                $encoding
            }
            fn reconstruct(
                descriptor: &BuiltinConfigDescriptorV1,
                limits: &ArtifactLimits,
            ) -> Result<Self, ArtifactError> {
                let BuiltinConfigDescriptorV1::Fri(descriptor) = descriptor else {
                    return Err(ArtifactError::NonCanonicalMetadata);
                };
                Ok($factory(
                    descriptor,
                    &limits.verifier,
                    R::seed_from_u64(0x5033_4152_5449_4631),
                )?)
            }
            fn write_commitment(
                writer: &mut Writer,
                commitment: &p3_batch_stark::Commitment<Self>,
            ) -> Result<(), ArtifactError> {
                write_merkle_cap::<$field, $digest>(writer, commitment, Self::field_encoding())
            }
            fn read_commitment(
                reader: &mut Reader<'_>,
            ) -> Result<p3_batch_stark::Commitment<Self>, ArtifactError> {
                read_merkle_cap::<$field, $digest>(reader, Self::field_encoding())
            }
            fn write_opening_proof(
                writer: &mut Writer,
                proof: &p3_batch_stark::PcsProof<Self>,
            ) -> Result<(), ArtifactError> {
                let codec = MerkleMmcsCodec::<$field, $digest>::new(Self::field_encoding());
                write_hiding_fri_proof::<$field, $challenge, _, _, _, _>(
                    writer,
                    proof,
                    Self::field_encoding(),
                    &codec,
                    &codec,
                )
            }
            fn read_opening_proof(
                reader: &mut Reader<'_>,
            ) -> Result<p3_batch_stark::PcsProof<Self>, ArtifactError> {
                let codec = MerkleMmcsCodec::<$field, $digest>::new(Self::field_encoding());
                read_hiding_fri_proof::<$field, $challenge, _, _, _, _>(
                    reader,
                    Self::field_encoding(),
                    &codec,
                    &codec,
                )
            }
        }
    };
}

random_codeword_impl!(BabyBearD4Poseidon2RandomCodewordConfig, BabyBear, BinomialExtensionField<BabyBear, 4>, 8, FieldEncoding::u32(), baby_bear_d4_poseidon2_random_codeword);
random_codeword_impl!(BabyBearD4Poseidon1RandomCodewordConfig, BabyBear, BinomialExtensionField<BabyBear, 4>, 8, FieldEncoding::u32(), baby_bear_d4_poseidon1_random_codeword);
random_codeword_impl!(KoalaBearD4Poseidon2RandomCodewordConfig, KoalaBear, BinomialExtensionField<KoalaBear, 4>, 8, FieldEncoding::u32(), koala_bear_d4_poseidon2_random_codeword);
random_codeword_impl!(KoalaBearD4Poseidon1RandomCodewordConfig, KoalaBear, BinomialExtensionField<KoalaBear, 4>, 8, FieldEncoding::u32(), koala_bear_d4_poseidon1_random_codeword);
random_codeword_impl!(GoldilocksD2Poseidon2RandomCodewordConfig, Goldilocks, BinomialExtensionField<Goldilocks, 2>, 4, FieldEncoding::u64(), goldilocks_d2_poseidon2_random_codeword);
random_codeword_impl!(GoldilocksD2Poseidon1RandomCodewordConfig, Goldilocks, BinomialExtensionField<Goldilocks, 2>, 4, FieldEncoding::u64(), goldilocks_d2_poseidon1_random_codeword);

impl<R> private::Sealed for KoalaBearD4Poseidon2SaltedConfig<R> where
    R: CryptoRng + SeedableRng + Send + Sync + 'static
{
}
impl<R> BuiltinArtifactConfig for KoalaBearD4Poseidon2SaltedConfig<R>
where
    R: CryptoRng + SeedableRng + Send + Sync + 'static,
{
    fn artifact_descriptor(&self) -> BuiltinConfigDescriptorV1 {
        BuiltinConfigDescriptorV1::Fri(*self.descriptor())
    }
    fn field_encoding() -> FieldEncoding<p3_batch_stark::Val<Self>> {
        FieldEncoding::u32()
    }
    fn reconstruct(
        descriptor: &BuiltinConfigDescriptorV1,
        limits: &ArtifactLimits,
    ) -> Result<Self, ArtifactError> {
        let BuiltinConfigDescriptorV1::Fri(descriptor) = descriptor else {
            return Err(ArtifactError::NonCanonicalMetadata);
        };
        Ok(koala_bear_d4_poseidon2_salted(
            descriptor,
            &limits.verifier,
            R::seed_from_u64(1),
            R::seed_from_u64(2),
            R::seed_from_u64(3),
        )?)
    }
    fn write_commitment(
        writer: &mut Writer,
        commitment: &p3_batch_stark::Commitment<Self>,
    ) -> Result<(), ArtifactError> {
        write_merkle_cap::<KoalaBear, 8>(writer, commitment, Self::field_encoding())
    }
    fn read_commitment(
        reader: &mut Reader<'_>,
    ) -> Result<p3_batch_stark::Commitment<Self>, ArtifactError> {
        read_merkle_cap::<KoalaBear, 8>(reader, Self::field_encoding())
    }
    fn write_opening_proof(
        writer: &mut Writer,
        proof: &p3_batch_stark::PcsProof<Self>,
    ) -> Result<(), ArtifactError> {
        let codec = SaltedMerkleMmcsCodec::<KoalaBear, 8, 4>::new(Self::field_encoding());
        write_hiding_fri_proof::<KoalaBear, BinomialExtensionField<KoalaBear, 4>, _, _, _, _>(
            writer,
            proof,
            Self::field_encoding(),
            &codec,
            &codec,
        )
    }
    fn read_opening_proof(
        reader: &mut Reader<'_>,
    ) -> Result<p3_batch_stark::PcsProof<Self>, ArtifactError> {
        let codec = SaltedMerkleMmcsCodec::<KoalaBear, 8, 4>::new(Self::field_encoding());
        read_hiding_fri_proof::<KoalaBear, BinomialExtensionField<KoalaBear, 4>, _, _, _, _>(
            reader,
            Self::field_encoding(),
            &codec,
            &codec,
        )
    }
}

macro_rules! whir_impl {
    ($config:ty, $field:ty, $challenge:ty, $encoding:expr, $factory:path) => {
        impl private::Sealed for $config {}
        impl BuiltinArtifactConfig for $config {
            fn artifact_descriptor(&self) -> BuiltinConfigDescriptorV1 {
                BuiltinConfigDescriptorV1::Whir(self.descriptor().clone())
            }
            fn field_encoding() -> FieldEncoding<p3_batch_stark::Val<Self>> {
                $encoding
            }
            fn reconstruct(
                descriptor: &BuiltinConfigDescriptorV1,
                limits: &ArtifactLimits,
            ) -> Result<Self, ArtifactError> {
                let BuiltinConfigDescriptorV1::Whir(descriptor) = descriptor else {
                    return Err(ArtifactError::NonCanonicalMetadata);
                };
                Ok($factory(descriptor, &limits.verifier)?)
            }
            fn write_commitment(
                writer: &mut Writer,
                commitment: &p3_batch_stark::Commitment<Self>,
            ) -> Result<(), ArtifactError> {
                write_merkle_cap::<$field, 8>(writer, commitment, Self::field_encoding())
            }
            fn read_commitment(
                reader: &mut Reader<'_>,
            ) -> Result<p3_batch_stark::Commitment<Self>, ArtifactError> {
                read_merkle_cap::<$field, 8>(reader, Self::field_encoding())
            }
            fn write_opening_proof(
                writer: &mut Writer,
                proof: &p3_batch_stark::PcsProof<Self>,
            ) -> Result<(), ArtifactError> {
                let codec = MerkleMmcsCodec::<$field, 8>::new(Self::field_encoding());
                write_whir_uni_proof::<$field, $challenge, _, _>(
                    writer,
                    proof,
                    Self::field_encoding(),
                    &codec,
                )
            }
            fn read_opening_proof(
                reader: &mut Reader<'_>,
            ) -> Result<p3_batch_stark::PcsProof<Self>, ArtifactError> {
                let codec = MerkleMmcsCodec::<$field, 8>::new(Self::field_encoding());
                read_whir_uni_proof::<$field, $challenge, _, _>(
                    reader,
                    Self::field_encoding(),
                    &codec,
                )
            }
        }
    };
}

whir_impl!(BabyBearD4Poseidon2WhirConfig, BabyBear, BinomialExtensionField<BabyBear, 4>, FieldEncoding::u32(), baby_bear_d4_poseidon2_whir);
whir_impl!(KoalaBearD4Poseidon2WhirConfig, KoalaBear, BinomialExtensionField<KoalaBear, 4>, FieldEncoding::u32(), koala_bear_d4_poseidon2_whir);

pub(crate) fn encode_verifier<SC>(
    verifier: &CircuitVerifier<SC>,
    limits: ArtifactLimits,
) -> Result<Vec<u8>, ArtifactError>
where
    SC: BuiltinArtifactConfig,
    p3_batch_stark::Val<SC>: p3_circuit_prover::config::StarkField + PrimeField64,
    SC::Challenge: BasedVectorSpace<p3_batch_stark::Val<SC>>,
    SymbolicExpressionExt<p3_batch_stark::Val<SC>, SC::Challenge>:
        Algebra<SymbolicExpression<p3_batch_stark::Val<SC>>> + Algebra<SC::Challenge>,
{
    let descriptor = verifier.config().artifact_descriptor();
    let suite = descriptor.suite();
    let relation = RelationDescriptorV1::from_native(verifier.relation())?;
    encode_framed(
        super::ArtifactKind::Verifier,
        suite.as_u16(),
        limits.max_verifier_bytes,
        |writer| {
            writer.write_u16(suite.spec().protocol_revision)?;
            write_config(writer, &descriptor)?;
            write_relation(writer, &relation, SC::field_encoding())?;
            write_common(writer, verifier.common_data(), SC::write_commitment)
        },
    )
}

pub(crate) fn encode_proof<SC>(
    verifier: &CircuitVerifier<SC>,
    proof: &BatchStarkProof<SC>,
    limits: ArtifactLimits,
) -> Result<Vec<u8>, ArtifactError>
where
    SC: BuiltinArtifactConfig,
    p3_batch_stark::Val<SC>: p3_circuit_prover::config::StarkField + PrimeField64,
    SC::Challenge: BasedVectorSpace<p3_batch_stark::Val<SC>>,
    SymbolicExpressionExt<p3_batch_stark::Val<SC>, SC::Challenge>:
        Algebra<SymbolicExpression<p3_batch_stark::Val<SC>>> + Algebra<SC::Challenge>,
{
    let statement = match verifier.statement_layout().table_instance() {
        Some(instance) => proof
            .non_primitives
            .get(instance - p3_circuit_prover::NUM_PRIMITIVE_TABLES)
            .ok_or(ArtifactError::NonCanonicalMetadata)?
            .public_values
            .as_slice(),
        None => &[],
    };
    verifier
        .verify(proof, statement)
        .map_err(|_| ArtifactError::VerificationRejected)?;
    let suite = verifier.config().artifact_descriptor().suite();
    encode_framed(
        ArtifactKind::Proof,
        suite.as_u16(),
        limits.max_proof_bytes,
        |writer| {
            writer.write_u16(suite.spec().protocol_revision)?;
            writer.write_vec("attached statement", statement, |writer, value| {
                writer.write_field(SC::field_encoding(), *value)
            })?;
            write_batch_proof::<SC, p3_batch_stark::Val<SC>>(
                writer,
                &proof.proof,
                SC::field_encoding(),
                SC::write_commitment,
                SC::write_opening_proof,
            )
        },
    )
}

impl<SC> super::PortableArtifactExport for CircuitVerifier<SC>
where
    SC: BuiltinArtifactConfig,
    p3_batch_stark::Val<SC>: p3_circuit_prover::config::StarkField + PrimeField64,
    SC::Challenge: BasedVectorSpace<p3_batch_stark::Val<SC>>,
    SymbolicExpressionExt<p3_batch_stark::Val<SC>, SC::Challenge>:
        Algebra<SymbolicExpression<p3_batch_stark::Val<SC>>> + Algebra<SC::Challenge>,
{
    type Config = SC;

    fn encode_verifier_artifact(&self, limits: ArtifactLimits) -> Result<Vec<u8>, ArtifactError> {
        encode_verifier(self, limits)
    }

    fn encode_proof_artifact(
        &self,
        proof: &BatchStarkProof<Self::Config>,
        limits: ArtifactLimits,
    ) -> Result<Vec<u8>, ArtifactError> {
        encode_proof(self, proof, limits)
    }
}

pub(crate) struct TypedPortableVerifier<SC>
where
    SC: BuiltinArtifactConfig,
    p3_batch_stark::Val<SC>: p3_circuit_prover::config::StarkField + PrimeField64,
    SC::Challenge: BasedVectorSpace<p3_batch_stark::Val<SC>>,
{
    verifier: CircuitVerifier<SC>,
    suite: SuiteIdV1,
    limits: ArtifactLimits,
}

fn try_copy_slice<T: Copy>(
    reader: &mut Reader<'_>,
    values: &[T],
    component: &'static str,
) -> Result<Vec<T>, ArtifactError> {
    reader.charge_conversion_vec::<T>(values.len())?;
    let mut copied = Vec::new();
    copied
        .try_reserve_exact(values.len())
        .map_err(|_| ArtifactError::AllocationFailed { component })?;
    copied.extend_from_slice(values);
    Ok(copied)
}

fn try_copy_npo_id(reader: &mut Reader<'_>, id: &NpoTypeId) -> Result<NpoTypeId, ArtifactError> {
    reader.charge_conversion_vec::<u8>(id.as_str().len())?;
    let mut owned = String::new();
    owned
        .try_reserve_exact(id.as_str().len())
        .map_err(|_| ArtifactError::AllocationFailed {
            component: "NPO identifier copy",
        })?;
    owned.push_str(id.as_str());
    Ok(NpoTypeId::new(owned))
}

fn charge_table_packing_copy(
    reader: &mut Reader<'_>,
    packing: &TablePacking,
) -> Result<(), ArtifactError> {
    let lane_count = packing.npo_lanes_iter().count();
    reader.charge_conversion_vec::<(NpoTypeId, usize)>(lane_count)?;
    for (id, _) in packing.npo_lanes_iter() {
        reader.charge_conversion_vec::<u8>(id.as_str().len())?;
    }
    let height_count = packing.npo_min_heights().count();
    reader.charge_conversion_vec::<(NpoTypeId, usize)>(height_count)?;
    for (id, _) in packing.npo_min_heights() {
        reader.charge_conversion_vec::<u8>(id.as_str().len())?;
    }
    Ok(())
}

impl<SC> PortableVerifierInner for TypedPortableVerifier<SC>
where
    SC: BuiltinArtifactConfig,
    p3_batch_stark::Val<SC>: p3_circuit_prover::config::StarkField + PrimeField64,
    SC::Challenge: BasedVectorSpace<p3_batch_stark::Val<SC>>,
    SymbolicExpressionExt<p3_batch_stark::Val<SC>, SC::Challenge>:
        Algebra<SymbolicExpression<p3_batch_stark::Val<SC>>> + Algebra<SC::Challenge>,
{
    fn schema(&self) -> &StatementSchema {
        self.verifier.statement_layout().schema()
    }

    fn verify_encoded(
        &self,
        bytes: &[u8],
        expected: CanonicalStatement<'_>,
    ) -> Result<(), ArtifactError> {
        let (native, expected_statement) = decode_framed(
            bytes,
            ArtifactKind::Proof,
            &self.limits,
            |raw| raw == self.suite.as_u16(),
            |raw, reader| {
                if raw != self.suite.as_u16()
                    || reader.read_u16()? != self.suite.spec().protocol_revision
                {
                    return Err(ArtifactError::NonCanonicalMetadata);
                }
                let expected_statement = decode_canonical_statement::<p3_batch_stark::Val<SC>>(
                    expected,
                    self.schema(),
                    SC::field_encoding(),
                    reader,
                )?;
                let attached = reader.read_vec_exact(
                    "attached statement",
                    self.schema().base_len(),
                    SC::field_encoding().encoded_bytes(),
                    |reader| reader.read_field(SC::field_encoding()),
                )?;
                let proof = read_batch_proof::<SC, p3_batch_stark::Val<SC>>(
                    reader,
                    SC::field_encoding(),
                    SC::read_commitment,
                    SC::read_opening_proof,
                )?;
                let relation = self.verifier.relation();
                reader.charge_conversion_vec::<NonPrimitiveTableEntry<SC>>(
                    relation.non_primitives().len(),
                )?;
                let mut non_primitives = Vec::new();
                non_primitives
                    .try_reserve_exact(relation.non_primitives().len())
                    .map_err(|_| ArtifactError::AllocationFailed {
                        component: "proof NPO conversion",
                    })?;
                let statement_index = self
                    .verifier
                    .statement_layout()
                    .table_instance()
                    .and_then(|index| index.checked_sub(p3_circuit_prover::NUM_PRIMITIVE_TABLES));
                let mut attached = Some(attached);
                for (index, npo) in relation.non_primitives().iter().enumerate() {
                    let public_values = if statement_index == Some(index) {
                        attached.take().ok_or(ArtifactError::NonCanonicalMetadata)?
                    } else {
                        try_copy_slice(reader, npo.public_values(), "NPO public values copy")?
                    };
                    non_primitives.push(NonPrimitiveTableEntry {
                        op_type: try_copy_npo_id(reader, npo.op_type())?,
                        rows: npo.rows(),
                        lanes: npo.lanes(),
                        public_values,
                        air_variant: npo.air_variant(),
                    });
                }
                charge_table_packing_copy(reader, relation.table_packing())?;
                let table_packing =
                    relation
                        .table_packing()
                        .try_clone_for_artifact()
                        .map_err(|_| ArtifactError::AllocationFailed {
                            component: "table packing copy",
                        })?;
                reader.charge_conversion_vec::<()>(0)?;
                let (w_binomial, alu_quintic_trinomial) = match relation.reduction() {
                    p3_circuit_prover::air::AluExtMulKind::Base => (None, false),
                    p3_circuit_prover::air::AluExtMulKind::Binomial { w } => (Some(w), false),
                    p3_circuit_prover::air::AluExtMulKind::QuinticTrinomial => (None, true),
                };
                let native = BatchStarkProof {
                    proof,
                    table_packing,
                    rows: *relation.rows(),
                    alu_variant: relation.alu_variant(),
                    ext_degree: relation.ext_degree(),
                    w_binomial,
                    alu_quintic_trinomial,
                    non_primitives,
                    stark_common: p3_batch_stark::CommonData::new(None, Vec::new()),
                };
                Ok((native, expected_statement))
            },
        )?;
        self.verifier
            .verify(&native, &expected_statement)
            .map_err(|_| ArtifactError::VerificationRejected)
    }
}

fn decode_canonical_statement<F: PrimeField64>(
    expected: CanonicalStatement<'_>,
    schema: &StatementSchema,
    field: FieldEncoding<F>,
    reader: &mut Reader<'_>,
) -> Result<Vec<F>, ArtifactError> {
    if expected.element_count != schema.base_len() {
        return Err(ArtifactError::Statement(
            StatementError::ValueLengthMismatch {
                expected: schema.base_len(),
                got: expected.element_count,
            },
        ));
    }
    reader.read_alternate_slice(expected.canonical_bytes, |reader| {
        reader.read_exact_items(
            "expected statement",
            expected.element_count,
            field.encoded_bytes(),
            |reader| reader.read_field(field),
        )
    })
}

pub(crate) fn decode_portable_verifier(
    candidate: &[u8],
    limits: ArtifactLimits,
) -> Result<PortableVerifier, ArtifactError> {
    let raw_suite = u16::from_le_bytes(candidate[11..13].try_into().unwrap());
    let suite = SuiteIdV1::from_u16(raw_suite)?;
    macro_rules! decode {
        ($config:ty) => {
            decode_typed::<$config>(candidate, suite, limits)
        };
    }
    match suite {
        SuiteIdV1::BabyBearD4Poseidon2BinaryFri => decode!(BabyBearD4Poseidon2BinaryConfig),
        SuiteIdV1::BabyBearD4Poseidon1BinaryFri => decode!(BabyBearD4Poseidon1BinaryConfig),
        SuiteIdV1::KoalaBearD4Poseidon2BinaryFri => decode!(KoalaBearD4Poseidon2BinaryConfig),
        SuiteIdV1::KoalaBearD4Poseidon1BinaryFri => decode!(KoalaBearD4Poseidon1BinaryConfig),
        SuiteIdV1::GoldilocksD2Poseidon2BinaryFri => decode!(GoldilocksD2Poseidon2BinaryConfig),
        SuiteIdV1::GoldilocksD2Poseidon1BinaryFri => decode!(GoldilocksD2Poseidon1BinaryConfig),
        SuiteIdV1::KoalaBearD5Poseidon2BinaryFri => decode!(KoalaBearD5Poseidon2BinaryConfig),
        SuiteIdV1::KoalaBearD5Poseidon1BinaryFri => decode!(KoalaBearD5Poseidon1BinaryConfig),
        SuiteIdV1::BabyBearD4Poseidon2QuaternaryFri => decode!(BabyBearD4Poseidon2QuaternaryConfig),
        SuiteIdV1::KoalaBearD4Poseidon2QuaternaryFri => {
            decode!(KoalaBearD4Poseidon2QuaternaryConfig)
        }
        SuiteIdV1::GoldilocksD2Poseidon2QuaternaryFri => {
            decode!(GoldilocksD2Poseidon2QuaternaryConfig)
        }
        SuiteIdV1::KoalaBearD5Poseidon2QuaternaryFri => {
            decode!(KoalaBearD5Poseidon2QuaternaryConfig)
        }
        SuiteIdV1::BabyBearD4Poseidon2RandomCodewordFri => {
            decode!(BabyBearD4Poseidon2RandomCodewordConfig<StdRng>)
        }
        SuiteIdV1::BabyBearD4Poseidon1RandomCodewordFri => {
            decode!(BabyBearD4Poseidon1RandomCodewordConfig<StdRng>)
        }
        SuiteIdV1::KoalaBearD4Poseidon2RandomCodewordFri => {
            decode!(KoalaBearD4Poseidon2RandomCodewordConfig<StdRng>)
        }
        SuiteIdV1::KoalaBearD4Poseidon1RandomCodewordFri => {
            decode!(KoalaBearD4Poseidon1RandomCodewordConfig<StdRng>)
        }
        SuiteIdV1::GoldilocksD2Poseidon2RandomCodewordFri => {
            decode!(GoldilocksD2Poseidon2RandomCodewordConfig<StdRng>)
        }
        SuiteIdV1::GoldilocksD2Poseidon1RandomCodewordFri => {
            decode!(GoldilocksD2Poseidon1RandomCodewordConfig<StdRng>)
        }
        SuiteIdV1::KoalaBearD4Poseidon2SaltedFri => {
            decode!(KoalaBearD4Poseidon2SaltedConfig<StdRng>)
        }
        SuiteIdV1::BabyBearD4Poseidon2Whir => decode!(BabyBearD4Poseidon2WhirConfig),
        SuiteIdV1::KoalaBearD4Poseidon2Whir => decode!(KoalaBearD4Poseidon2WhirConfig),
    }
}

fn decode_typed<SC>(
    candidate: &[u8],
    suite: SuiteIdV1,
    limits: ArtifactLimits,
) -> Result<PortableVerifier, ArtifactError>
where
    SC: BuiltinArtifactConfig,
    p3_batch_stark::Val<SC>: p3_circuit_prover::config::StarkField + PrimeField64,
    SC::Challenge: BasedVectorSpace<p3_batch_stark::Val<SC>>,
    SymbolicExpressionExt<p3_batch_stark::Val<SC>, SC::Challenge>:
        Algebra<SymbolicExpression<p3_batch_stark::Val<SC>>> + Algebra<SC::Challenge>,
{
    let (descriptor, relation, common) = decode_framed(
        candidate,
        ArtifactKind::Verifier,
        &limits,
        |raw| raw == suite.as_u16(),
        |raw, reader| {
            if raw != suite.as_u16() || reader.read_u16()? != suite.spec().protocol_revision {
                return Err(ArtifactError::NonCanonicalMetadata);
            }
            let descriptor = read_config(reader, suite)?;
            let relation = read_relation(reader, SC::field_encoding())?;
            let common = read_common::<SC>(reader, SC::read_commitment)?;
            Ok((descriptor, relation, common))
        },
    )?;
    let config = SC::reconstruct(&descriptor, &limits)?;
    let verifier = CircuitVerifier::from_independently_trusted_builtin_artifact(
        config,
        relation.into_trusted()?,
        common,
    )
    .map_err(|_| ArtifactError::NonCanonicalMetadata)?;
    let canonical = encode_verifier(&verifier, limits)?;
    if canonical != candidate {
        return Err(ArtifactError::NonCanonicalMetadata);
    }
    Ok(PortableVerifier::from_parts(
        Box::new(TypedPortableVerifier {
            verifier,
            suite,
            limits,
        }),
        canonical,
    ))
}

#[cfg(test)]
mod tests {
    use alloc::vec::Vec;
    use core::convert::Infallible;
    use core::mem::size_of;
    use core::sync::atomic::{AtomicUsize, Ordering};

    use p3_baby_bear::BabyBear;
    use p3_circuit::CircuitBuilder;
    use p3_circuit::ops::NpoTypeId;
    use p3_circuit_prover::{
        BatchStarkProof, BatchStarkProver, BuiltinArtifactNpo, CircuitVerifier, ConstraintProfile,
        NonPrimitiveTableEntry, Poseidon1Prover, Poseidon2Prover, TablePacking,
    };
    use p3_field::PrimeCharacteristicRing;
    use p3_field::extension::BinomialExtensionField;
    use p3_koala_bear::KoalaBear;
    use rand::rngs::StdRng;
    use rand::{SeedableRng, TryCryptoRng, TryRng};

    use super::super::descriptor::{
        BuiltinNpoV1, NpoDescriptorV1, NpoPublicValuesV1, RelationDescriptorV1, read_common,
        read_config, read_relation, read_relation_without_trusted_conversion_charge, write_common,
        write_config, write_relation,
    };
    use super::super::native::{read_merkle_cap, write_merkle_cap};
    use super::super::wire::{FieldEncoding, Reader, Writer, decode_framed, encode_framed};
    use crate::artifact::{
        ArtifactError, ArtifactKind, ArtifactLimits, CanonicalStatement, ExpectedVerifierArtifact,
        PortableArtifactExport, PortableVerifier,
    };
    use crate::builtin_config::{
        BabyBearD4Poseidon2RandomCodewordConfig, BuiltinConfigDescriptorV1, FriConfigV1,
        KoalaBearD4Poseidon2BinaryConfig, SuiteIdV1, baby_bear_d4_poseidon2_binary,
        baby_bear_d4_poseidon2_random_codeword, koala_bear_d4_poseidon2_binary,
    };
    use crate::prepared::test_common;
    use crate::{
        BatchOnly, FriRecursionConfig, ProveNextLayerParams, TrustedPreparedAggregation,
        TrustedPreparedInput, TrustedPreparedSource,
    };

    static VERIFICATION_RNG_DRAWS: AtomicUsize = AtomicUsize::new(0);

    const fn accounted_vec_allocation<T>(entries: usize) -> usize {
        size_of::<Vec<T>>() + entries * size_of::<T>()
    }

    #[derive(Debug)]
    struct AuditedRng(StdRng);

    impl TryRng for AuditedRng {
        type Error = Infallible;

        fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
            VERIFICATION_RNG_DRAWS.fetch_add(1, Ordering::Relaxed);
            self.0.try_next_u32()
        }

        fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
            VERIFICATION_RNG_DRAWS.fetch_add(1, Ordering::Relaxed);
            self.0.try_next_u64()
        }

        fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Self::Error> {
            VERIFICATION_RNG_DRAWS.fetch_add(1, Ordering::Relaxed);
            self.0.try_fill_bytes(dst)
        }
    }

    impl TryCryptoRng for AuditedRng {}

    impl SeedableRng for AuditedRng {
        type Seed = <StdRng as SeedableRng>::Seed;

        fn from_seed(seed: Self::Seed) -> Self {
            Self(StdRng::from_seed(seed))
        }
    }

    fn exported_double_circuit(multiplier: u32, input_value: u32) -> (Vec<u8>, Vec<u8>) {
        let limits = ArtifactLimits::default();
        let suite = SuiteIdV1::BabyBearD4Poseidon2BinaryFri;
        let descriptor = FriConfigV1::new(suite, 1, 0, 2, 2, 0, 0, 0, 0, 0, 0);
        let config = baby_bear_d4_poseidon2_binary(&descriptor, &limits.verifier).unwrap();

        let mut builder = CircuitBuilder::<BabyBear>::new();
        let input = builder.public_input();
        let multiplier_target = builder.define_const(BabyBear::from_u32(multiplier));
        let output = builder.public_input();
        let product = builder.mul(input, multiplier_target);
        builder.connect(product, output);
        let circuit = builder.build().unwrap();
        let mut runner = circuit.runner();
        runner
            .set_public_inputs(&[
                BabyBear::from_u32(input_value),
                BabyBear::from_u32(input_value * multiplier),
            ])
            .unwrap();
        let traces = runner.run().unwrap();

        let prepared = BatchStarkProver::new(config)
            .with_table_packing(TablePacking::new(4, 4).with_min_trace_height(32))
            .prepare_circuit::<BabyBear, 1>(&circuit, &[], &[], ConstraintProfile::Standard)
            .unwrap();
        let native_verifier = prepared.verifier();
        let native_proof = prepared.prove(&traces).unwrap();
        let verifier_bytes = native_verifier.encode_verifier_artifact(limits).unwrap();
        let proof_bytes = native_verifier
            .encode_proof_artifact(&native_proof, limits)
            .unwrap();

        drop(native_proof);
        drop(native_verifier);
        drop(prepared);
        drop(traces);
        drop(circuit);

        (verifier_bytes, proof_bytes)
    }

    fn rewrite_baby_bear_verifier_relation(
        bytes: &[u8],
        limits: ArtifactLimits,
        mutate: impl FnOnce(&mut RelationDescriptorV1<BabyBear>),
    ) -> Vec<u8> {
        type Config = crate::builtin_config::BabyBearD4Poseidon2BinaryConfig;

        let suite = SuiteIdV1::BabyBearD4Poseidon2BinaryFri;
        let (descriptor, mut relation, common) = decode_framed(
            bytes,
            ArtifactKind::Verifier,
            &limits,
            |raw| raw == suite.as_u16(),
            |_, reader| {
                assert_eq!(reader.read_u16().unwrap(), suite.spec().protocol_revision);
                let descriptor = read_config(reader, suite).unwrap();
                let relation = read_relation(reader, FieldEncoding::u32()).unwrap();
                let common = read_common::<Config>(
                    reader,
                    <Config as super::BuiltinArtifactConfig>::read_commitment,
                )
                .unwrap();
                Ok((descriptor, relation, common))
            },
        )
        .unwrap();
        mutate(&mut relation);
        encode_framed(
            ArtifactKind::Verifier,
            suite.as_u16(),
            limits.max_verifier_bytes,
            |writer| {
                writer.write_u16(suite.spec().protocol_revision)?;
                write_config(writer, &descriptor)?;
                write_relation(writer, &relation, FieldEncoding::u32())?;
                write_common(
                    writer,
                    &common,
                    <Config as super::BuiltinArtifactConfig>::write_commitment,
                )
            },
        )
        .unwrap()
    }

    #[test]
    fn generated_proof_survives_dropping_all_native_owners() {
        let (verifier_bytes, proof_bytes) = exported_double_circuit(2, 4);
        let limits = ArtifactLimits {
            max_verifier_bytes: verifier_bytes.len(),
            max_proof_bytes: proof_bytes.len(),
            ..ArtifactLimits::default()
        };

        let imported = PortableVerifier::decode(
            &verifier_bytes,
            ExpectedVerifierArtifact::from_trusted_bytes(&verifier_bytes),
            limits,
        )
        .unwrap();
        imported
            .verify_encoded(&proof_bytes, CanonicalStatement::new(&[], 0))
            .unwrap();

        let verifier_below = ArtifactLimits {
            max_verifier_bytes: verifier_bytes.len() - 1,
            ..limits
        };
        assert_eq!(
            PortableVerifier::decode(
                &verifier_bytes,
                ExpectedVerifierArtifact::from_trusted_bytes(&verifier_bytes),
                verifier_below,
            )
            .err()
            .unwrap(),
            ArtifactError::DecodeLimitExceeded {
                component: "artifact bytes",
                actual: verifier_bytes.len(),
                limit: verifier_bytes.len() - 1,
            }
        );

        let proof_below = ArtifactLimits {
            max_proof_bytes: proof_bytes.len() - 1,
            ..limits
        };
        let imported = PortableVerifier::decode(
            &verifier_bytes,
            ExpectedVerifierArtifact::from_trusted_bytes(&verifier_bytes),
            proof_below,
        )
        .unwrap();
        assert_eq!(
            imported
                .verify_encoded(&proof_bytes, CanonicalStatement::new(&[], 0))
                .unwrap_err(),
            ArtifactError::DecodeLimitExceeded {
                component: "artifact bytes",
                actual: proof_bytes.len(),
                limit: proof_bytes.len() - 1,
            }
        );
    }

    #[test]
    fn public_import_rejects_truncated_trailing_and_non_artifact_proofs() {
        let limits = ArtifactLimits::default();
        let (verifier_bytes, proof_bytes) = exported_double_circuit(2, 4);
        let imported = PortableVerifier::decode(
            &verifier_bytes,
            ExpectedVerifierArtifact::from_trusted_bytes(&verifier_bytes),
            limits,
        )
        .unwrap();

        assert!(matches!(
            imported.verify_encoded(
                &proof_bytes[..proof_bytes.len() - 1],
                CanonicalStatement::new(&[], 0),
            ),
            Err(ArtifactError::Truncated)
        ));
        let mut trailing = proof_bytes;
        trailing.push(0);
        assert!(matches!(
            imported.verify_encoded(&trailing, CanonicalStatement::new(&[], 0)),
            Err(ArtifactError::TrailingBytes)
        ));
        assert_eq!(
            imported
                .verify_encoded(&[0; 32], CanonicalStatement::new(&[], 0))
                .unwrap_err(),
            ArtifactError::BadMagic
        );
    }

    #[test]
    fn pinned_verifier_and_proof_substitution_are_rejected() {
        let limits = ArtifactLimits::default();
        let (verifier_a, proof_a) = exported_double_circuit(2, 4);
        let (verifier_b, proof_b) = exported_double_circuit(3, 4);
        assert_ne!(verifier_a, verifier_b);

        assert!(
            PortableVerifier::decode(
                &verifier_b,
                ExpectedVerifierArtifact::from_trusted_bytes(&verifier_a),
                limits,
            )
            .is_err()
        );

        let imported_a = PortableVerifier::decode(
            &verifier_a,
            ExpectedVerifierArtifact::from_trusted_bytes(&verifier_a),
            limits,
        )
        .unwrap();
        imported_a
            .verify_encoded(&proof_a, CanonicalStatement::new(&[], 0))
            .unwrap();
        assert!(
            imported_a
                .verify_encoded(&proof_b, CanonicalStatement::new(&[], 0))
                .is_err()
        );
    }

    #[test]
    fn public_import_enforces_exact_allocation_and_container_boundaries() {
        let (verifier_bytes, _) = exported_double_circuit(2, 4);
        let expected = ExpectedVerifierArtifact::from_trusted_bytes(&verifier_bytes);
        let default = ArtifactLimits::default();

        let minimum_passing = |maximum: usize, set_limit: fn(&mut ArtifactLimits, usize)| {
            let mut lower = 0;
            let mut upper = maximum;
            while lower < upper {
                let candidate = lower + (upper - lower) / 2;
                let mut limits = default;
                set_limit(&mut limits, candidate);
                if PortableVerifier::decode(&verifier_bytes, expected, limits).is_ok() {
                    upper = candidate;
                } else {
                    lower = candidate + 1;
                }
            }
            lower
        };
        let minimum_allocation = minimum_passing(default.max_decoded_bytes, |limits, value| {
            limits.max_decoded_bytes = value;
        });
        assert!(minimum_allocation > 0);
        let mut exact = default;
        exact.max_decoded_bytes = minimum_allocation;
        PortableVerifier::decode(&verifier_bytes, expected, exact).unwrap();
        exact.max_decoded_bytes -= 1;
        assert!(matches!(
            PortableVerifier::decode(&verifier_bytes, expected, exact),
            Err(ArtifactError::DecodeLimitExceeded { .. })
        ));

        let minimum_containers = minimum_passing(default.max_container_entries, |limits, value| {
            limits.max_container_entries = value;
        });
        assert!(minimum_containers > 0);
        let mut exact = default;
        exact.max_container_entries = minimum_containers;
        PortableVerifier::decode(&verifier_bytes, expected, exact).unwrap();
        exact.max_container_entries -= 1;
        assert!(matches!(
            PortableVerifier::decode(&verifier_bytes, expected, exact),
            Err(ArtifactError::DecodeLimitExceeded { .. })
        ));
    }

    #[test]
    fn nonempty_adapter_copy_charges_before_reserving() {
        let values = [BabyBear::from_u32(1), BabyBear::from_u32(2)];
        let exact_allocation = accounted_vec_allocation::<BabyBear>(values.len());
        let exact_limits = ArtifactLimits {
            max_decoded_bytes: exact_allocation,
            ..ArtifactLimits::default()
        };
        let mut exact_reader = Reader::new(&[], &exact_limits);
        assert_eq!(
            super::try_copy_slice(&mut exact_reader, &values, "test adapter copy").unwrap(),
            values
        );
        assert_eq!(exact_reader.requested_allocation_bytes(), exact_allocation);

        let mut below_limits = exact_limits;
        below_limits.max_decoded_bytes -= 1;
        let mut below_reader = Reader::new(&[], &below_limits);
        assert!(matches!(
            super::try_copy_slice(&mut below_reader, &values, "test adapter copy"),
            Err(ArtifactError::DecodeLimitExceeded {
                component: "decoded allocation bytes",
                actual,
                limit,
            }) if actual == exact_allocation && limit + 1 == exact_allocation
        ));
    }

    #[test]
    fn trusted_candidate_rejects_unsafe_relation_geometry_before_air_construction() {
        let limits = ArtifactLimits::default();
        let (verifier_bytes, _) = exported_double_circuit(2, 4);

        let zero_lanes = rewrite_baby_bear_verifier_relation(&verifier_bytes, limits, |relation| {
            relation.non_primitives.push(NpoDescriptorV1 {
                kind: BuiltinNpoV1::Recompose,
                rows: 1,
                lanes: 0,
                air_variant: p3_circuit_prover::AirVariant::Baseline,
                public_values: NpoPublicValuesV1::Static(Vec::new()),
            });
            relation.trace_degree_bits.push(5);
        });
        assert!(matches!(
            PortableVerifier::decode(
                &zero_lanes,
                ExpectedVerifierArtifact::from_trusted_bytes(&zero_lanes),
                limits,
            ),
            Err(ArtifactError::NonCanonicalMetadata)
        ));

        let zero_rows = rewrite_baby_bear_verifier_relation(&verifier_bytes, limits, |relation| {
            relation.non_primitives.push(NpoDescriptorV1 {
                kind: BuiltinNpoV1::Recompose,
                rows: 0,
                lanes: u32::MAX as usize,
                air_variant: p3_circuit_prover::AirVariant::Baseline,
                public_values: NpoPublicValuesV1::Static(Vec::new()),
            });
            relation.trace_degree_bits.push(5);
        });
        assert!(matches!(
            PortableVerifier::decode(
                &zero_rows,
                ExpectedVerifierArtifact::from_trusted_bytes(&zero_rows),
                limits,
            ),
            Err(ArtifactError::NonCanonicalMetadata)
        ));

        let bad_lanes = rewrite_baby_bear_verifier_relation(&verifier_bytes, limits, |relation| {
            relation.non_primitives.push(NpoDescriptorV1 {
                kind: BuiltinNpoV1::Recompose,
                rows: 1,
                lanes: 33,
                air_variant: p3_circuit_prover::AirVariant::Baseline,
                public_values: NpoPublicValuesV1::Static(Vec::new()),
            });
            relation.trace_degree_bits.push(5);
        });
        let mut narrow = limits;
        narrow.verifier.max_matrix_width = 64;
        assert!(matches!(
            PortableVerifier::decode(
                &bad_lanes,
                ExpectedVerifierArtifact::from_trusted_bytes(&bad_lanes),
                narrow,
            ),
            Err(ArtifactError::DecodeLimitExceeded {
                component: "NPO matrix width",
                ..
            })
        ));

        let bad_degree = rewrite_baby_bear_verifier_relation(&verifier_bytes, limits, |relation| {
            relation.trace_degree_bits[0] = 33;
        });
        assert!(matches!(
            PortableVerifier::decode(
                &bad_degree,
                ExpectedVerifierArtifact::from_trusted_bytes(&bad_degree),
                limits,
            ),
            Err(ArtifactError::DecodeLimitExceeded {
                component: "trace degree bits",
                ..
            })
        ));

        let inconsistent_rows =
            rewrite_baby_bear_verifier_relation(&verifier_bytes, limits, |relation| {
                let height = 1usize << relation.trace_degree_bits[0];
                relation.rows = p3_circuit_prover::RowCounts::new([height + 1, 1, 1]);
            });
        assert!(matches!(
            PortableVerifier::decode(
                &inconsistent_rows,
                ExpectedVerifierArtifact::from_trusted_bytes(&inconsistent_rows),
                limits,
            ),
            Err(ArtifactError::NonCanonicalMetadata)
        ));

        let max_u32_rows =
            rewrite_baby_bear_verifier_relation(&verifier_bytes, limits, |relation| {
                relation.non_primitives.push(NpoDescriptorV1 {
                    kind: BuiltinNpoV1::Recompose,
                    rows: u32::MAX as usize,
                    lanes: 1,
                    air_variant: p3_circuit_prover::AirVariant::Baseline,
                    public_values: NpoPublicValuesV1::Static(Vec::new()),
                });
                relation.trace_degree_bits.push(31);
            });
        let mut platform_safe = limits;
        platform_safe.verifier.max_total_scalar_elements = usize::MAX;
        assert!(matches!(
            PortableVerifier::decode(
                &max_u32_rows,
                ExpectedVerifierArtifact::from_trusted_bytes(&max_u32_rows),
                platform_safe,
            ),
            Err(ArtifactError::NonCanonicalMetadata)
        ));
    }

    #[test]
    fn imported_random_codeword_verification_draws_no_rng_bytes() {
        type VerifyingConfig = BabyBearD4Poseidon2RandomCodewordConfig<AuditedRng>;

        let limits = ArtifactLimits::default();
        let suite = SuiteIdV1::BabyBearD4Poseidon2RandomCodewordFri;
        let descriptor = FriConfigV1::new(suite, 1, 0, 2, 2, 0, 0, 0, 0, 2, 0);
        let config = baby_bear_d4_poseidon2_random_codeword(
            &descriptor,
            &limits.verifier,
            StdRng::seed_from_u64(7),
        )
        .unwrap();
        let mut builder = CircuitBuilder::<BabyBear>::new();
        let _ = builder.define_const(BabyBear::from_u32(5));
        let circuit = builder.build().unwrap();
        let traces = circuit.runner().run().unwrap();
        let prepared = BatchStarkProver::new(config)
            .with_table_packing(TablePacking::new(4, 4).with_min_trace_height(32))
            .prepare_circuit::<BabyBear, 1>(&circuit, &[], &[], ConstraintProfile::Standard)
            .unwrap();
        let proof = prepared.prove(&traces).unwrap();
        let verifier = prepared.verifier();
        let verifier_bytes = verifier.encode_verifier_artifact(limits).unwrap();
        let proof_bytes = verifier.encode_proof_artifact(&proof, limits).unwrap();
        drop(proof);
        drop(verifier);
        drop(prepared);
        drop(traces);
        drop(circuit);

        let imported = super::decode_typed::<VerifyingConfig>(&verifier_bytes, suite, limits)
            .expect("the verification-only audited RNG config reconstructs");
        let retained = imported.clone();
        drop(imported);
        VERIFICATION_RNG_DRAWS.store(0, Ordering::Relaxed);
        retained
            .verify_encoded(&proof_bytes, CanonicalStatement::new(&[], 0))
            .unwrap();
        assert_eq!(VERIFICATION_RNG_DRAWS.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn trusted_recursive_aggregation_roundtrips_after_proving_owners_are_dropped() {
        type InputConfig = test_common::KoalaBearD4RecursionConfig;
        type PortableConfig = KoalaBearD4Poseidon2BinaryConfig;

        let limits = ArtifactLimits::default();
        let fixture = test_common::KoalaBearD4StatementFixture::new();
        let left_statement = [KoalaBear::from_u64(7), KoalaBear::from_u64(9)];
        let right_statement = [KoalaBear::from_u64(11), KoalaBear::from_u64(13)];
        let left_proof = fixture.prove([7, 9]);
        let right_proof = fixture.prove([11, 13]);
        let output_config = fixture.layer_config.clone();
        let native_params = output_config.native_fri_validation_params().unwrap();
        let output_params = ProveNextLayerParams {
            table_packing: TablePacking::new(1, 4)
                .with_npo_lanes(NpoTypeId::recompose(), 1)
                .with_npo_min_height(NpoTypeId::recompose(), 32),
            ..ProveNextLayerParams::default()
        };
        let owner = TrustedPreparedAggregation::<
            InputConfig,
            InputConfig,
            BatchOnly,
            BatchOnly,
            _,
            4,
        >::new(
            TrustedPreparedSource::BatchStark {
                verifier: fixture.verifier(),
                proof: &left_proof,
                statement: &left_statement,
            },
            TrustedPreparedSource::BatchStark {
                verifier: fixture.verifier(),
                proof: &right_proof,
                statement: &right_statement,
            },
            output_config,
            fixture.backend.clone(),
            output_params,
        )
        .unwrap();
        let output = owner
            .prove(
                TrustedPreparedInput::BatchStark {
                    proof: &left_proof,
                    statement: &left_statement,
                },
                TrustedPreparedInput::BatchStark {
                    proof: &right_proof,
                    statement: &right_statement,
                },
            )
            .unwrap();
        let parent = owner.verifier();
        let layout = parent.aggregation_statement_layout().unwrap();
        assert_eq!(layout.split_at(), 2);
        assert_eq!(layout.output().base_len(), 4);

        let descriptor = FriConfigV1::new(
            SuiteIdV1::KoalaBearD4Poseidon2BinaryFri,
            native_params.log_blowup() as u32,
            native_params.log_final_poly_len() as u32,
            native_params.max_log_arity() as u32,
            native_params.num_queries() as u32,
            native_params.commit_pow_bits() as u32,
            native_params.query_pow_bits() as u32,
            0,
            0,
            0,
            0,
        );
        let portable_config =
            koala_bear_d4_poseidon2_binary(&descriptor, &limits.verifier).unwrap();
        let relation = RelationDescriptorV1::from_native(parent.relation()).unwrap();
        let trusted_npo_count = relation.non_primitives.len();
        assert!(trusted_npo_count > 1);
        let native_relation = parent.relation();
        let statement_npo = native_relation
            .statement_layout()
            .table_instance()
            .map(|instance| instance - p3_circuit_prover::NUM_PRIMITIVE_TABLES);
        let npo_adapter_allocation = accounted_vec_allocation::<
            NonPrimitiveTableEntry<PortableConfig>,
        >(native_relation.non_primitives().len())
            + native_relation
                .non_primitives()
                .iter()
                .enumerate()
                .map(|(index, npo)| {
                    accounted_vec_allocation::<u8>(npo.op_type().as_str().len())
                        + if statement_npo == Some(index) {
                            0
                        } else {
                            accounted_vec_allocation::<KoalaBear>(npo.public_values().len())
                        }
                })
                .sum::<usize>();
        let packing = native_relation.table_packing();
        let lane_overrides = packing.npo_lanes_iter().collect::<Vec<_>>();
        let height_overrides = packing.npo_min_heights().collect::<Vec<_>>();
        assert!(!lane_overrides.is_empty());
        assert!(!height_overrides.is_empty());
        let packing_adapter_allocation =
            accounted_vec_allocation::<(NpoTypeId, usize)>(lane_overrides.len())
                + lane_overrides
                    .iter()
                    .map(|(id, _)| accounted_vec_allocation::<u8>(id.as_str().len()))
                    .sum::<usize>()
                + accounted_vec_allocation::<(NpoTypeId, usize)>(height_overrides.len())
                + height_overrides
                    .iter()
                    .map(|(id, _)| accounted_vec_allocation::<u8>(id.as_str().len()))
                    .sum::<usize>();
        let proof_adapter_allocation = npo_adapter_allocation
            + packing_adapter_allocation
            + accounted_vec_allocation::<KoalaBear>(4)
            + accounted_vec_allocation::<()>(0);
        let expected_poseidon_width = relation
            .non_primitives
            .iter()
            .filter_map(|npo| {
                let per_lane = match npo.kind {
                    BuiltinNpoV1::Poseidon1(config) => {
                        let prover = Poseidon1Prover::new(config, relation.constraint_profile);
                        prover
                            .main_width_from_config()
                            .max(prover.preprocessed_width_from_config())
                    }
                    BuiltinNpoV1::Poseidon2(config) => {
                        let prover = Poseidon2Prover::new(config, relation.constraint_profile);
                        prover
                            .main_width_from_config()
                            .max(prover.preprocessed_width_from_config())
                    }
                    _ => return None,
                };
                Some(npo.lanes * per_lane)
            })
            .max()
            .unwrap();

        let mut common_writer = Writer::new(limits.max_verifier_bytes);
        write_common::<InputConfig>(
            &mut common_writer,
            parent.common_data(),
            |writer, commitment| {
                write_merkle_cap::<KoalaBear, 8>(writer, commitment, FieldEncoding::u32())
            },
        )
        .unwrap();
        let common_bytes = common_writer.finish().unwrap();
        let mut common_reader = Reader::new(&common_bytes, &limits);
        let common = read_common::<PortableConfig>(&mut common_reader, |reader| {
            read_merkle_cap::<KoalaBear, 8>(reader, FieldEncoding::u32())
        })
        .unwrap();
        common_reader.finish().unwrap();
        let mut substituted_relation = relation.clone();
        let mut replaced_shared_role = false;
        for npo in &mut substituted_relation.non_primitives {
            if let BuiltinNpoV1::Poseidon2(config) = npo.kind {
                if config.is_shared() {
                    npo.kind = BuiltinNpoV1::Poseidon2(config.without_shared_role());
                    replaced_shared_role = true;
                }
            }
        }
        assert!(
            replaced_shared_role,
            "recursive artifact must contain a shared Poseidon2 NPO"
        );
        let substituted_bytes = encode_framed(
            ArtifactKind::Verifier,
            SuiteIdV1::KoalaBearD4Poseidon2BinaryFri.as_u16(),
            limits.max_verifier_bytes,
            |writer| {
                writer.write_u16(
                    SuiteIdV1::KoalaBearD4Poseidon2BinaryFri
                        .spec()
                        .protocol_revision,
                )?;
                write_config(writer, &BuiltinConfigDescriptorV1::Fri(descriptor))?;
                write_relation(writer, &substituted_relation, FieldEncoding::u32())?;
                write_common::<PortableConfig>(writer, &common, |writer, commitment| {
                    write_merkle_cap::<KoalaBear, 8>(writer, commitment, FieldEncoding::u32())
                })
            },
        )
        .unwrap();
        let portable_native_verifier =
            CircuitVerifier::from_independently_trusted_builtin_artifact(
                portable_config,
                relation.into_trusted().unwrap(),
                common,
            )
            .unwrap();
        let verifier_bytes = portable_native_verifier
            .encode_verifier_artifact(limits)
            .unwrap();
        assert!(matches!(
            PortableVerifier::decode(
                &substituted_bytes,
                ExpectedVerifierArtifact::from_trusted_bytes(&verifier_bytes),
                limits,
            ),
            Err(ArtifactError::TrustedArtifactMismatch)
        ));

        let recursive_proof = output.0;
        let mut proof_writer = Writer::new(limits.max_proof_bytes);
        super::write_batch_proof::<InputConfig, KoalaBear>(
            &mut proof_writer,
            &recursive_proof.proof,
            FieldEncoding::u32(),
            |writer, commitment| {
                write_merkle_cap::<KoalaBear, 8>(writer, commitment, FieldEncoding::u32())
            },
            |writer, proof| {
                let codec = super::MerkleMmcsCodec::<KoalaBear, 8>::new(FieldEncoding::u32());
                super::write_fri_proof::<
                    KoalaBear,
                    BinomialExtensionField<KoalaBear, 4>,
                    _,
                    _,
                    _,
                    _,
                >(writer, proof, FieldEncoding::u32(), &codec, &codec)
            },
        )
        .unwrap();
        let proof_core_bytes = proof_writer.finish().unwrap();
        let mut proof_reader = Reader::new(&proof_core_bytes, &limits);
        let portable_proof_core = super::read_batch_proof::<PortableConfig, KoalaBear>(
            &mut proof_reader,
            FieldEncoding::u32(),
            <PortableConfig as super::BuiltinArtifactConfig>::read_commitment,
            <PortableConfig as super::BuiltinArtifactConfig>::read_opening_proof,
        )
        .unwrap();
        proof_reader.finish().unwrap();
        let portable_non_primitives = recursive_proof
            .non_primitives
            .into_iter()
            .map(|entry| NonPrimitiveTableEntry::<PortableConfig> {
                op_type: entry.op_type,
                rows: entry.rows,
                lanes: entry.lanes,
                public_values: entry.public_values,
                air_variant: entry.air_variant,
            })
            .collect();
        let portable_native_proof = BatchStarkProof::<PortableConfig> {
            proof: portable_proof_core,
            table_packing: recursive_proof.table_packing,
            rows: recursive_proof.rows,
            alu_variant: recursive_proof.alu_variant,
            ext_degree: recursive_proof.ext_degree,
            w_binomial: recursive_proof.w_binomial,
            alu_quintic_trinomial: recursive_proof.alu_quintic_trinomial,
            non_primitives: portable_non_primitives,
            stark_common: p3_batch_stark::CommonData::new(None, Vec::new()),
        };
        let proof_bytes = portable_native_verifier
            .encode_proof_artifact(&portable_native_proof, limits)
            .unwrap();
        let bare_wire_allocation = decode_framed(
            &proof_bytes,
            ArtifactKind::Proof,
            &limits,
            |raw| raw == SuiteIdV1::KoalaBearD4Poseidon2BinaryFri.as_u16(),
            |_, reader| {
                reader.read_u16().unwrap();
                reader
                    .read_vec_exact(
                        "attached statement",
                        parent.statement_layout().schema().base_len(),
                        FieldEncoding::<KoalaBear>::u32().encoded_bytes(),
                        |reader| reader.read_field(FieldEncoding::<KoalaBear>::u32()),
                    )
                    .unwrap();
                super::read_batch_proof::<PortableConfig, KoalaBear>(
                    reader,
                    FieldEncoding::u32(),
                    <PortableConfig as super::BuiltinArtifactConfig>::read_commitment,
                    <PortableConfig as super::BuiltinArtifactConfig>::read_opening_proof,
                )
                .unwrap();
                Ok(reader.requested_allocation_bytes())
            },
        )
        .unwrap();

        drop(portable_native_proof);
        drop(portable_native_verifier);
        drop(parent);
        drop(owner);
        drop(left_proof);
        drop(right_proof);
        drop(fixture);

        let mut lower_width = 0;
        let mut upper_width = limits.verifier.max_matrix_width;
        while lower_width < upper_width {
            let candidate = lower_width + (upper_width - lower_width) / 2;
            let mut bounded = limits;
            bounded.verifier.max_matrix_width = candidate;
            if PortableVerifier::decode(
                &verifier_bytes,
                ExpectedVerifierArtifact::from_trusted_bytes(&verifier_bytes),
                bounded,
            )
            .is_ok()
            {
                upper_width = candidate;
            } else {
                lower_width = candidate + 1;
            }
        }
        assert_eq!(lower_width, expected_poseidon_width);
        let mut below_poseidon_width = limits;
        below_poseidon_width.verifier.max_matrix_width = expected_poseidon_width - 1;
        assert!(matches!(
            PortableVerifier::decode(
                &verifier_bytes,
                ExpectedVerifierArtifact::from_trusted_bytes(&verifier_bytes),
                below_poseidon_width,
            ),
            Err(ArtifactError::DecodeLimitExceeded {
                component: "NPO matrix width",
                actual,
                limit,
            }) if actual == expected_poseidon_width && limit + 1 == expected_poseidon_width
        ));

        let conversion_allocation = size_of::<Vec<BuiltinArtifactNpo<KoalaBear>>>()
            + trusted_npo_count * size_of::<BuiltinArtifactNpo<KoalaBear>>();
        let bare_verifier_allocation = decode_framed(
            &verifier_bytes,
            ArtifactKind::Verifier,
            &limits,
            |raw| raw == SuiteIdV1::KoalaBearD4Poseidon2BinaryFri.as_u16(),
            |_, reader| {
                reader.read_u16().unwrap();
                read_config(reader, SuiteIdV1::KoalaBearD4Poseidon2BinaryFri).unwrap();
                read_relation_without_trusted_conversion_charge(
                    reader,
                    FieldEncoding::<KoalaBear>::u32(),
                )
                .unwrap();
                read_common::<PortableConfig>(
                    reader,
                    <PortableConfig as super::BuiltinArtifactConfig>::read_commitment,
                )
                .unwrap();
                Ok(reader.requested_allocation_bytes())
            },
        )
        .unwrap();
        let exact_allocation = bare_verifier_allocation + conversion_allocation;
        let mut exact_limits = limits;
        exact_limits.max_decoded_bytes = exact_allocation;
        PortableVerifier::decode(
            &verifier_bytes,
            ExpectedVerifierArtifact::from_trusted_bytes(&verifier_bytes),
            exact_limits,
        )
        .unwrap();
        let mut below_exact = exact_limits;
        below_exact.max_decoded_bytes -= 1;
        assert!(matches!(
            PortableVerifier::decode(
                &verifier_bytes,
                ExpectedVerifierArtifact::from_trusted_bytes(&verifier_bytes),
                below_exact,
            ),
            Err(ArtifactError::DecodeLimitExceeded {
                component: "decoded allocation bytes",
                actual,
                limit,
            }) if actual == exact_allocation && limit + 1 == exact_allocation
        ));
        let expected = [7_u32, 9, 11, 13]
            .into_iter()
            .flat_map(u32::to_le_bytes)
            .collect::<Vec<_>>();
        let exact_proof_allocation = bare_wire_allocation + proof_adapter_allocation;
        let mut exact_proof_limits = limits;
        exact_proof_limits.max_decoded_bytes = exact_proof_allocation;
        let imported = PortableVerifier::decode(
            &verifier_bytes,
            ExpectedVerifierArtifact::from_trusted_bytes(&verifier_bytes),
            exact_proof_limits,
        )
        .unwrap();
        imported
            .verify_encoded(&proof_bytes, CanonicalStatement::new(&expected, 4))
            .unwrap();
        let mut trailing_expected = expected.clone();
        trailing_expected.push(0);
        assert_eq!(
            imported
                .verify_encoded(&proof_bytes, CanonicalStatement::new(&trailing_expected, 4),)
                .unwrap_err(),
            ArtifactError::TrailingBytes
        );
        let mut noncanonical_expected = expected.clone();
        noncanonical_expected[..4]
            .copy_from_slice(&(p3_circuit_prover::KOALA_BEAR_MODULUS as u32).to_le_bytes());
        assert_eq!(
            imported
                .verify_encoded(
                    &proof_bytes,
                    CanonicalStatement::new(&noncanonical_expected, 4),
                )
                .unwrap_err(),
            ArtifactError::NonCanonicalField
        );
        let mut below_proof_allocation = exact_proof_limits;
        below_proof_allocation.max_decoded_bytes -= 1;
        let below = PortableVerifier::decode(
            &verifier_bytes,
            ExpectedVerifierArtifact::from_trusted_bytes(&verifier_bytes),
            below_proof_allocation,
        )
        .unwrap();
        assert!(matches!(
            below.verify_encoded(&proof_bytes, CanonicalStatement::new(&expected, 4)),
            Err(ArtifactError::DecodeLimitExceeded {
                component: "decoded allocation bytes",
                actual,
                limit,
            }) if actual == exact_proof_allocation && limit + 1 == exact_proof_allocation
        ));
        let swapped = [11_u32, 13, 7, 9]
            .into_iter()
            .flat_map(u32::to_le_bytes)
            .collect::<Vec<_>>();
        assert!(
            imported
                .verify_encoded(&proof_bytes, CanonicalStatement::new(&swapped, 4))
                .is_err()
        );
    }
}
