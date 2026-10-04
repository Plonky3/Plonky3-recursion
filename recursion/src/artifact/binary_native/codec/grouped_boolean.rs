//! Trusted-shape bounded trace and bit-ring proof bytes.
use p3_binary_pcs::{
    BooleanProof, BooleanTraceCommitmentProof, BooleanTraceProof, GroupedCodewordMmcs,
};
use p3_sumcheck::ring_switch::bits::{
    BitRingSwitchClaimsProof, BitTensor, ClaimElements, SuccessorTensors,
};

use super::super::{
    BinaryNativeGroupedBooleanTraceAuthority, BinaryNativeGroupedBooleanTraceConfig,
    VerifiedBinaryNativeGroupedBooleanTraceProof,
};
use super::*;

type GroupedTree<E> = GroupedCodewordMmcs<NativeMmcs<E>>;
type TraceProof<E> = BooleanTraceProof<E, GroupedTree<E>, GroupedTree<E>>;

impl<E, A> BinaryNativeGroupedBooleanTraceAuthority<E, A>
where
    E: RecursiveBinaryChallengeField
        + EncodableLevel
        + ExtensionField<E>
        + ChallengeField<E>
        + FoldAlphabet<E>
        + p3_binary_pcs::Coordinates
        + PackedValue<Value = E>
        + serde::Serialize
        + serde::de::DeserializeOwned,
    A: VerifierAir<E, E>,
{
    pub fn encode_statement(&self, public: &[Vec<E>]) -> Result<Vec<u8>, ArtifactError> {
        self.state
            .check_public(public)
            .map_err(|_| ArtifactError::VerificationRejected)?;
        let mut writer = Writer::new(self.state.limits.max_proof_bytes);
        write_public(&mut writer, public)?;
        writer.finish()
    }
    /// Full retained native verification precedes encoding, including the
    /// exact routed ring round count and its required empty grinding vector.
    pub fn encode_native_proof(
        &self,
        proof: &MultiStarkProof<BinaryNativeGroupedBooleanTraceConfig<E>>,
        public: &[Vec<E>],
    ) -> Result<Vec<u8>, ArtifactError> {
        self.verify_native(proof, public)
            .map_err(|_| ArtifactError::VerificationRejected)?;
        encode_multi::<BinaryNativeGroupedBooleanTraceConfig<E>>(
            proof,
            public,
            suite::<E, E>() | 0x200,
            &self.state.limits,
            write_trace::<E>,
        )
    }
    /// Trust anchors and the independent statement are checked before proof
    /// decoding. Main and preprocessing share one allocation/frontier budget.
    pub fn decode_and_verify(
        &self,
        candidate: &[u8],
        expected: ExpectedVerifierArtifact<'_>,
        proof_bytes: &[u8],
        statement: CanonicalBinaryStatement<'_>,
    ) -> Result<VerifiedBinaryNativeGroupedBooleanTraceProof<E>, ArtifactError> {
        let authority = DecodeAuthority {
            identity: &self.state.identity,
            shape: &self.state.decode,
            limits: &self.state.limits,
            usage: self.state.binary.input_resource_usage(),
            suite: suite::<E, E>() | 0x200,
        };
        let (proof, public) = authority.decode::<BinaryNativeGroupedBooleanTraceConfig<E>>(
            candidate,
            expected,
            proof_bytes,
            statement,
            read_trace::<E>,
        )?;
        self.verify_native(&proof, &public)
            .map_err(|_| ArtifactError::VerificationRejected)
    }
}

fn write_trace<E>(w: &mut Writer, p: &TraceProof<E>) -> Result<(), ArtifactError>
where
    E: RecursiveBinaryChallengeField + PackedValue<Value = E>,
{
    write_fields(w, &p.values)?;
    write_ring(w, &p.opening.reduction)?;
    grouped::write_grouped_pcs(w, &p.opening.opening)
}
pub(super) fn write_ring<E: RecursiveBinaryChallengeField>(
    w: &mut Writer,
    p: &BitRingSwitchClaimsProof<E>,
) -> Result<(), ArtifactError> {
    for claim in &p.claims {
        write_fields(w, claim.tensor.rows())?;
        if let Some(successor) = &claim.successor {
            write_fields(w, successor.carry.rows())?;
            write_fields(w, successor.last.rows())?;
        }
    }
    w.write_count(
        "binary ring rounds",
        p.sumcheck.polynomial_evaluations.len(),
    )?;
    for row in &p.sumcheck.polynomial_evaluations {
        write_fields(w, row)?;
    }
    write_field(w, p.final_eval)
}
fn read_trace<E>(
    r: &mut Reader<'_>,
    s: &BooleanTraceDecode,
    total: &mut usize,
) -> Result<TraceProof<E>, ArtifactError>
where
    E: RecursiveBinaryChallengeField + PackedValue<Value = E>,
{
    Ok(BooleanTraceCommitmentProof {
        values: read_fields(r, s.value_count)?,
        opening: BooleanProof {
            reduction: read_ring(r, &s.ring)?,
            opening: grouped::read_grouped_pcs(r, &s.packed, total)?,
        },
    })
}
fn read_tensor<E: RecursiveBinaryChallengeField>(
    r: &mut Reader<'_>,
) -> Result<BitTensor<E>, ArtifactError> {
    // The native checked constructor takes ownership of the charged vector;
    // no generic serde value or second tensor projection is allocated.
    BitTensor::try_from(read_fields(r, E::RAW_BITS)?).map_err(|_| malformed("binary ring tensor"))
}
pub(super) fn read_ring<E: RecursiveBinaryChallengeField>(
    r: &mut Reader<'_>,
    s: &RingDecode,
) -> Result<BitRingSwitchClaimsProof<E>, ArtifactError> {
    let mut index = 0;
    let claims = r.read_exact_items("binary ring claims", s.successor.len(), 0, |r| {
        let successor = s.successor[index];
        index += 1;
        Ok(ClaimElements {
            tensor: read_tensor(r)?,
            successor: successor
                .then(|| {
                    Ok::<_, ArtifactError>(SuccessorTensors {
                        carry: read_tensor(r)?,
                        last: read_tensor(r)?,
                    })
                })
                .transpose()?,
        })
    })?;
    let rounds = usize::try_from(r.read_u32()?).map_err(|_| ArtifactError::LengthOverflow)?;
    if rounds > s.max_rounds {
        return Err(ArtifactError::DecodeLimitExceeded {
            component: "binary ring rounds",
            actual: rounds,
            limit: s.max_rounds,
        });
    }
    if rounds < s.min_rounds {
        return Err(malformed("binary ring rounds"));
    }
    Ok(BitRingSwitchClaimsProof {
        claims,
        sumcheck: SumcheckData {
            polynomial_evaluations: r.read_exact_items(
                "binary ring rounds",
                rounds,
                E::RAW_BITS / 4,
                read_array,
            )?,
            pow_witnesses: r.read_exact_items(
                "binary ring empty sumcheck PoW",
                0,
                0,
                read_field::<E>,
            )?,
        },
        final_eval: read_field(r)?,
    })
}

#[cfg(test)]
mod tests {
    use p3_binary_field::{BinaryField64, BinaryField128};

    use super::*;

    fn round_trip<E: RecursiveBinaryChallengeField>() {
        let shape = RingDecode {
            successor: alloc::vec![false, true],
            min_rounds: 0,
            max_rounds: 2,
        };
        for count in 0..=2 {
            let proof = BitRingSwitchClaimsProof {
                claims: alloc::vec![
                    ClaimElements {
                        tensor: BitTensor::<E>::zero(),
                        successor: None
                    },
                    ClaimElements {
                        tensor: BitTensor::<E>::zero(),
                        successor: Some(SuccessorTensors {
                            carry: BitTensor::one(),
                            last: BitTensor::zero(),
                        })
                    }
                ],
                sumcheck: SumcheckData {
                    polynomial_evaluations: alloc::vec![[E::ZERO, E::ONE]; count],
                    pow_witnesses: Vec::new(),
                },
                final_eval: E::ONE,
            };
            let mut writer = Writer::new(1 << 20);
            write_ring(&mut writer, &proof).unwrap();
            let bytes = writer.finish().unwrap();
            let limits = ArtifactLimits::default();
            let mut reader = Reader::new(&bytes, &limits);
            let decoded = read_ring::<E>(&mut reader, &shape).unwrap();
            reader.finish().unwrap();
            assert_eq!(decoded.claims, proof.claims);
            assert_eq!(
                decoded.sumcheck.polynomial_evaluations,
                proof.sumcheck.polynomial_evaluations
            );
            assert!(decoded.sumcheck.pow_witnesses.is_empty());
            assert_eq!(decoded.final_eval, proof.final_eval);
            let round_at = 4 * E::RAW_BITS * (E::RAW_BITS / 8);
            for bad in [3, u32::MAX] {
                let mut changed = bytes.clone();
                changed[round_at..round_at + 4].copy_from_slice(&bad.to_le_bytes());
                assert!(matches!(
                    read_ring::<E>(&mut Reader::new(&changed, &limits), &shape),
                    Err(ArtifactError::DecodeLimitExceeded {
                        component: "binary ring rounds",
                        ..
                    })
                ));
            }
            for len in 0..bytes.len() {
                assert!(read_ring::<E>(&mut Reader::new(&bytes[..len], &limits), &shape).is_err());
            }
        }
    }
    #[test]
    fn ring_codec_has_bounded_variable_rounds_and_fixed_successor_tensors() {
        round_trip::<BinaryField64>();
        round_trip::<BinaryField128>();
    }
}
