//! Public native Boolean trace routing, without a verifier authority or prover.

use alloc::rc::Rc;
use alloc::vec::Vec;
use core::cell::RefCell;
use core::marker::PhantomData;

use p3_binary_field::{PackedGf2, Underlier};
use p3_binary_pcs::{
    BitOpening, BitReadings, BooleanBackend, BooleanMultilinearPcs, BooleanTraceCommitment,
    BooleanTraceCommitmentProof, ChallengeField, Coordinates, FoldAlphabet,
};
use p3_challenger::{CanSampleUniformBits, FieldChallenger, GrindingChallenger};
use p3_multilinear_util::point::Point;
use p3_sumcheck::{OpeningProtocol, PrescribedOpeningSecurity, PrescribedPointPcs};
use serde::Serialize;
use serde::de::DeserializeOwned;

use super::RecursiveBinaryChallengeField;
use crate::verifier::VerificationError;

pub(super) struct TraceReadings<E> {
    pub openings: Vec<BitOpening<E>>,
    pub readings: Vec<BitReadings<E>>,
}

/// Captures routing and the column transcript through the released adapter.
/// Its recorder's success is NOT verification. The real child verifier must
/// subsequently check every captured reading and the commitment opening.
pub(super) fn route<E, Ch>(
    num_variables: usize,
    protocol: &OpeningProtocol,
    points: &[Point<E>],
    values: &[E],
    challenger: &mut Ch,
) -> Result<TraceReadings<E>, VerificationError>
where
    E: RecursiveBinaryChallengeField
        + ChallengeField<E>
        + FoldAlphabet<E>
        + Coordinates
        + Serialize
        + DeserializeOwned,
    Ch: FieldChallenger<E> + CanSampleUniformBits<E> + GrindingChallenger<Witness = E>,
{
    let captured = Rc::new(RefCell::new(None));
    let backend = Recorder {
        num_variables,
        captured: captured.clone(),
        field: PhantomData,
    };
    let wrapper = BooleanTraceCommitment::<E, _>::from_commitment(backend);
    wrapper
        .verify_at(
            &E::ZERO,
            &BooleanTraceCommitmentProof {
                values: values.to_vec(),
                opening: (),
            },
            protocol,
            points,
            challenger,
        )
        .map_err(|_| {
            VerificationError::InvalidProofShape("binary trace native routing failed".into())
        })?;
    let result = captured.borrow_mut().take().ok_or_else(|| {
        VerificationError::InvalidProofShape(
            "binary trace native routing produced no claims".into(),
        )
    })?;
    Ok(result)
}

struct Recorder<E> {
    num_variables: usize,
    captured: Rc<RefCell<Option<TraceReadings<E>>>>,
    field: PhantomData<E>,
}

impl<E: Clone + Serialize + DeserializeOwned> BooleanBackend<E> for Recorder<E> {
    type Commitment = E;
    type ProverData = ();
    type Proof = ();
    type Error = &'static str;
    fn num_variables(&self) -> usize {
        self.num_variables
    }
}

impl<E, Ch> BooleanMultilinearPcs<E, Ch> for Recorder<E>
where
    E: Clone + Serialize + DeserializeOwned,
{
    fn observe_commitment(&self, _: &E, _: &mut Ch) {
        panic!("a routing recorder cannot bind commitments");
    }
    fn commit_bits<U: Underlier>(
        &self,
        _: &[PackedGf2<U>],
        _: &mut Ch,
    ) -> Result<(E, ()), Self::Error> {
        Err("a routing recorder cannot commit")
    }
    fn open_readings(
        &self,
        _: (),
        _: &[BitOpening<E>],
        _: &mut Ch,
    ) -> Result<(Vec<BitReadings<E>>, ()), Self::Error> {
        Err("a routing recorder cannot prove")
    }
    fn verify_readings(
        &self,
        _: &E,
        openings: &[BitOpening<E>],
        readings: &[BitReadings<E>],
        _: &(),
        _: &mut Ch,
    ) -> Result<(), Self::Error> {
        let mut captured = self.captured.borrow_mut();
        if captured.is_some() {
            return Err("a routing recorder cannot capture twice");
        }
        *captured = Some(TraceReadings {
            openings: openings.to_vec(),
            readings: readings.to_vec(),
        });
        Ok(())
    }
    fn readings_security(&self, _: usize, _: bool) -> Option<PrescribedOpeningSecurity> {
        None
    }
    fn open_at_points(
        &self,
        _: (),
        _: &[Point<E>],
        _: &mut Ch,
    ) -> Result<(Vec<E>, ()), Self::Error> {
        Err("a routing recorder cannot prove")
    }
    fn verify_at_points(
        &self,
        _: &E,
        _: &[Point<E>],
        _: &[E],
        _: &(),
        _: &mut Ch,
    ) -> Result<(), Self::Error> {
        Err("a routing recorder only captures requested readings")
    }
}
