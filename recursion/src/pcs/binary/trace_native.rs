//! Public native Boolean trace routing, without a verifier authority or prover.

use alloc::rc::Rc;
use alloc::vec::Vec;
use core::cell::RefCell;
use core::marker::PhantomData;

use p3_binary_field::{BitCoordinates, PackedGf2, TowerLevel, Underlier};
use p3_binary_pcs::{
    BitOpening, BitReadings, BooleanBackend, BooleanMultilinearPcs, BooleanTraceCommitment,
    BooleanTraceCommitmentProof,
};
use p3_challenger::fs::TranscriptField;
use p3_challenger::{CanSampleUniformBits, FieldChallenger, GrindingChallenger};
use p3_field::{ExtensionField, Field};
use p3_multilinear_util::point::Point;
use p3_sumcheck::{OpeningProtocol, PrescribedOpeningSecurity, PrescribedPointPcs};
use serde::Serialize;
use serde::de::DeserializeOwned;

use crate::verifier::VerificationError;

pub(super) struct TraceReadings<E> {
    pub openings: Vec<BitOpening<E>>,
    pub readings: Vec<BitReadings<E>>,
}

/// Captures routing and the column transcript through the released adapter,
/// over packed values of `F` and challenges of `E`.
/// Its recorder's success is NOT verification. The real child verifier must
/// subsequently check every captured reading and the commitment opening.
pub(super) fn route<F, E, Ch>(
    num_variables: usize,
    protocol: &OpeningProtocol,
    points: &[Point<E>],
    values: &[E],
    challenger: &mut Ch,
) -> Result<TraceReadings<E>, VerificationError>
where
    F: TranscriptField + TowerLevel + Serialize + DeserializeOwned,
    E: BitCoordinates + ExtensionField<F>,
    Ch: FieldChallenger<F> + CanSampleUniformBits<F> + GrindingChallenger<Witness = F>,
{
    let captured = Rc::new(RefCell::new(None));
    let backend = Recorder::<F, E> {
        num_variables,
        captured: captured.clone(),
        field: PhantomData,
    };
    let wrapper = BooleanTraceCommitment::<E, _>::from_commitment(backend);
    wrapper
        .verify_at(
            &F::ZERO,
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

/// A bit commitment over packed values of `F` that records the readings it is asked to verify.
struct Recorder<F, E> {
    num_variables: usize,
    captured: Rc<RefCell<Option<TraceReadings<E>>>>,
    field: PhantomData<F>,
}

impl<F, E> BooleanBackend<E> for Recorder<F, E>
where
    F: Field + Serialize + DeserializeOwned,
{
    type Val = F;
    type Commitment = F;
    type ProverData = ();
    type Proof = ();
    type Error = &'static str;
    fn num_variables(&self) -> usize {
        self.num_variables
    }
}

impl<F, E, Ch> BooleanMultilinearPcs<E, Ch> for Recorder<F, E>
where
    F: Field + Serialize + DeserializeOwned,
    E: Field,
{
    fn observe_commitment(&self, _: &F, _: &mut Ch) {
        panic!("a routing recorder cannot bind commitments");
    }
    fn commit_bits<U: Underlier>(
        &self,
        _: &[PackedGf2<U>],
        _: &mut Ch,
    ) -> Result<(F, ()), Self::Error> {
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
        _: &F,
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
        _: &F,
        _: &[Point<E>],
        _: &[E],
        _: &(),
        _: &mut Ch,
    ) -> Result<(), Self::Error> {
        Err("a routing recorder only captures requested readings")
    }
}
