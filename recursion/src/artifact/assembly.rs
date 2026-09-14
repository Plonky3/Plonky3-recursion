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
            rows: *relation.rows(),
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
    use alloc::vec::Vec;

    use p3_baby_bear::BabyBear;
    use p3_circuit::CircuitBuilder;
    use p3_circuit_prover::{
        BatchStarkProof, BatchStarkProver, CircuitVerifier, ConstraintProfile,
        NonPrimitiveTableEntry, TablePacking,
    };
    use p3_field::PrimeCharacteristicRing;
    use p3_field::extension::BinomialExtensionField;
    use p3_koala_bear::KoalaBear;

    use crate::artifact::{
        ArtifactError, ArtifactLimits, CanonicalStatement, ExpectedVerifierArtifact,
        PortableArtifactExport, PortableVerifier,
    };
    use crate::builtin_config::{
        FriConfigV1, KoalaBearD4Poseidon2BinaryConfig, SuiteIdV1, baby_bear_d4_poseidon2_binary,
        koala_bear_d4_poseidon2_binary,
    };
    use crate::prepared::test_common;
    use crate::{
        BatchOnly, FriRecursionConfig, ProveNextLayerParams, TrustedPreparedAggregation,
        TrustedPreparedInput, TrustedPreparedSource,
    };

    use super::super::descriptor::{RelationDescriptorV1, read_common, write_common};
    use super::super::native::{read_merkle_cap, write_merkle_cap};
    use super::super::wire::{FieldEncoding, Reader, Writer};

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
        let mut trailing = proof_bytes.clone();
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
            ProveNextLayerParams::default(),
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
        let portable_native_verifier =
            CircuitVerifier::from_independently_trusted_builtin_artifact(
                portable_config,
                relation.into_trusted().unwrap(),
                common,
            )
            .unwrap();

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
        let verifier_bytes = portable_native_verifier
            .encode_verifier_artifact(limits)
            .unwrap();
        let proof_bytes = portable_native_verifier
            .encode_proof_artifact(&portable_native_proof, limits)
            .unwrap();

        drop(portable_native_proof);
        drop(portable_native_verifier);
        drop(parent);
        drop(owner);
        drop(left_proof);
        drop(right_proof);
        drop(fixture);

        let imported = PortableVerifier::decode(
            &verifier_bytes,
            ExpectedVerifierArtifact::from_trusted_bytes(&verifier_bytes),
            limits,
        )
        .unwrap();
        let expected = [7_u32, 9, 11, 13]
            .into_iter()
            .flat_map(u32::to_le_bytes)
            .collect::<Vec<_>>();
        imported
            .verify_encoded(&proof_bytes, CanonicalStatement::new(&expected, 4))
            .unwrap();
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
