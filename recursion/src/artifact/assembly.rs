use alloc::boxed::Box;
use alloc::vec::Vec;
use p3_baby_bear::BabyBear;

use p3_circuit::{StatementError, StatementSchema};
use p3_circuit_prover::{BatchStarkProof, CircuitVerifier, NonPrimitiveTableEntry};
use p3_field::PrimeField64;
use p3_field::extension::{BinomialExtensionField, QuinticTrinomialExtensionField};
use p3_field::{Algebra, BasedVectorSpace};
use p3_goldilocks::Goldilocks;
use p3_koala_bear::KoalaBear;
use p3_uni_stark::StarkGenericConfig;
use p3_uni_stark::{SymbolicExpression, SymbolicExpressionExt};
use rand::rngs::StdRng;
use rand::{CryptoRng, SeedableRng};

use crate::builtin_config::*;

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

    fn suite(&self) -> SuiteIdV1 {
        self.suite
    }

    fn verify_encoded(
        &self,
        bytes: &[u8],
        expected: CanonicalStatement<'_>,
    ) -> Result<(), ArtifactError> {
        let expected_statement = decode_canonical_statement::<p3_batch_stark::Val<SC>>(
            expected,
            self.schema(),
            SC::field_encoding(),
            &self.limits,
        )?;
        let proof = decode_framed(
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
                Ok((attached, proof))
            },
        )?;
        let relation = self.verifier.relation();
        let non_primitives = relation
            .non_primitives()
            .iter()
            .enumerate()
            .map(|(index, npo)| NonPrimitiveTableEntry {
                op_type: npo.op_type().clone(),
                rows: npo.rows(),
                lanes: npo.lanes(),
                public_values: if self.verifier.statement_layout().table_instance()
                    == Some(p3_circuit_prover::NUM_PRIMITIVE_TABLES + index)
                {
                    proof.0.clone()
                } else {
                    npo.public_values().to_vec()
                },
                air_variant: npo.air_variant(),
            })
            .collect();
        let (w_binomial, alu_quintic_trinomial) = match relation.reduction() {
            p3_circuit_prover::air::AluExtMulKind::Base => (None, false),
            p3_circuit_prover::air::AluExtMulKind::Binomial { w } => (Some(w), false),
            p3_circuit_prover::air::AluExtMulKind::QuinticTrinomial => (None, true),
        };
        let native = BatchStarkProof {
            proof: proof.1,
            table_packing: relation.table_packing().clone(),
            rows: relation.rows().clone(),
            alu_variant: relation.alu_variant(),
            ext_degree: relation.ext_degree(),
            w_binomial,
            alu_quintic_trinomial,
            non_primitives,
            stark_common: p3_batch_stark::CommonData::new(None, Vec::new()),
        };
        self.verifier
            .verify(&native, &expected_statement)
            .map_err(|_| ArtifactError::VerificationRejected)
    }
}

fn decode_canonical_statement<F: PrimeField64>(
    expected: CanonicalStatement<'_>,
    schema: &StatementSchema,
    field: FieldEncoding<F>,
    limits: &ArtifactLimits,
) -> Result<Vec<F>, ArtifactError> {
    if expected.element_count != schema.base_len() {
        return Err(ArtifactError::Statement(
            StatementError::ValueLengthMismatch {
                expected: schema.base_len(),
                got: expected.element_count,
            },
        ));
    }
    let mut reader = Reader::new(expected.canonical_bytes, limits);
    let values = reader.read_exact_items(
        "expected statement",
        expected.element_count,
        field.encoded_bytes(),
        |reader| reader.read_field(field),
    )?;
    reader.finish()?;
    Ok(values)
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
    Ok(PortableVerifier {
        inner: Box::new(TypedPortableVerifier {
            verifier,
            suite,
            limits,
        }),
        canonical_bytes: canonical,
    })
}

#[cfg(test)]
mod tests {
    use p3_baby_bear::BabyBear;
    use p3_circuit::CircuitBuilder;
    use p3_circuit_prover::{BatchStarkProver, ConstraintProfile, TablePacking};
    use p3_field::PrimeCharacteristicRing;

    use crate::artifact::{
        ArtifactLimits, CanonicalStatement, ExpectedVerifierArtifact, PortableArtifactExport,
        PortableVerifier,
    };
    use crate::builtin_config::{FriConfigV1, SuiteIdV1, baby_bear_d4_poseidon2_binary};

    #[test]
    fn generated_proof_survives_dropping_all_native_owners() {
        let limits = ArtifactLimits::default();
        let suite = SuiteIdV1::BabyBearD4Poseidon2BinaryFri;
        let descriptor = FriConfigV1::new(suite, 1, 0, 2, 2, 0, 0, 0, 0, 0, 0);
        let config = baby_bear_d4_poseidon2_binary(&descriptor, &limits.verifier).unwrap();

        let mut builder = CircuitBuilder::<BabyBear>::new();
        let input = builder.public_input();
        let multiplier = builder.define_const(BabyBear::TWO);
        let output = builder.public_input();
        let product = builder.mul(input, multiplier);
        builder.connect(product, output);
        let circuit = builder.build().unwrap();
        let mut runner = circuit.runner();
        runner
            .set_public_inputs(&[BabyBear::from_u32(4), BabyBear::from_u32(8)])
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

        let imported = PortableVerifier::decode(
            &verifier_bytes,
            ExpectedVerifierArtifact::from_trusted_bytes(&verifier_bytes),
            limits,
        )
        .unwrap();
        imported
            .verify_encoded(&proof_bytes, CanonicalStatement::new(&[], 0))
            .unwrap();
    }
}
