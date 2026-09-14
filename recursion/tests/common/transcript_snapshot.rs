//! Test-only native duplex challenger snapshots for transcript assurance.

use std::sync::{Arc, Mutex};
use std::vec::Vec;

use p3_challenger::{
    CanObserve, CanSample, CanSampleBits, CanSampleUniformBits, DuplexChallenger, FieldChallenger,
    GrindingChallenger, ResamplingError, UniformGrindingChallenger,
};
use p3_field::{Field, PrimeField64};
use p3_symmetric::CryptographicPermutation;

/// The complete externally visible state of a native duplex challenger at one checkpoint.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DuplexSnapshot<F, const WIDTH: usize> {
    pub branch: &'static str,
    pub checkpoint: &'static str,
    pub sponge_state: [F; WIDTH],
    pub input_buffer: Vec<F>,
    pub output_buffer: Vec<F>,
}

/// A concrete test-only wrapper that delegates every operation to the native challenger.
///
/// Clones share a synchronized sink, which is necessary because native verifier entry points
/// obtain their challenger by cloning the one retained by `StarkConfig`.
#[derive(Clone, Debug)]
pub struct RecordingDuplexChallenger<F, P, const WIDTH: usize, const RATE: usize>
where
    F: Clone,
    P: CryptographicPermutation<[F; WIDTH]>,
{
    inner: DuplexChallenger<F, P, WIDTH, RATE>,
    sink: Arc<Mutex<Vec<DuplexSnapshot<F, WIDTH>>>>,
    branch: &'static str,
}

impl<F, P, const WIDTH: usize, const RATE: usize> RecordingDuplexChallenger<F, P, WIDTH, RATE>
where
    F: Clone,
    P: CryptographicPermutation<[F; WIDTH]>,
{
    pub const fn new(
        inner: DuplexChallenger<F, P, WIDTH, RATE>,
        sink: Arc<Mutex<Vec<DuplexSnapshot<F, WIDTH>>>>,
        branch: &'static str,
    ) -> Self {
        Self {
            inner,
            sink,
            branch,
        }
    }

    pub fn snapshot(&self, checkpoint: &'static str) -> DuplexSnapshot<F, WIDTH> {
        DuplexSnapshot {
            branch: self.branch,
            checkpoint,
            sponge_state: self.inner.sponge_state.clone(),
            input_buffer: self.inner.input_buffer.clone(),
            output_buffer: self.inner.output_buffer.clone(),
        }
    }

    fn record(&self, checkpoint: &'static str) {
        self.sink
            .lock()
            .expect("snapshot sink is not poisoned")
            .push(self.snapshot(checkpoint));
    }
}

impl<F, P, T, const WIDTH: usize, const RATE: usize> CanObserve<T>
    for RecordingDuplexChallenger<F, P, WIDTH, RATE>
where
    F: Clone,
    P: CryptographicPermutation<[F; WIDTH]>,
    DuplexChallenger<F, P, WIDTH, RATE>: CanObserve<T>,
{
    fn observe(&mut self, value: T) {
        self.inner.observe(value);
        self.record("observe");
    }
}

impl<F, P, T, const WIDTH: usize, const RATE: usize> CanSample<T>
    for RecordingDuplexChallenger<F, P, WIDTH, RATE>
where
    F: Clone,
    P: CryptographicPermutation<[F; WIDTH]>,
    DuplexChallenger<F, P, WIDTH, RATE>: CanSample<T>,
{
    fn sample(&mut self) -> T {
        let value = self.inner.sample();
        self.record("sample");
        value
    }
}

impl<F, P, const WIDTH: usize, const RATE: usize> CanSampleBits<usize>
    for RecordingDuplexChallenger<F, P, WIDTH, RATE>
where
    F: Clone,
    P: CryptographicPermutation<[F; WIDTH]>,
    DuplexChallenger<F, P, WIDTH, RATE>: CanSampleBits<usize>,
{
    fn sample_bits(&mut self, bits: usize) -> usize {
        let value = self.inner.sample_bits(bits);
        self.record("sample-bits");
        value
    }
}

impl<F, P, const WIDTH: usize, const RATE: usize> CanSampleUniformBits<F>
    for RecordingDuplexChallenger<F, P, WIDTH, RATE>
where
    F: Clone,
    P: CryptographicPermutation<[F; WIDTH]>,
    DuplexChallenger<F, P, WIDTH, RATE>: CanSampleUniformBits<F>,
{
    fn sample_uniform_bits<const RESAMPLE: bool>(
        &mut self,
        bits: usize,
    ) -> Result<usize, ResamplingError> {
        let value = self.inner.sample_uniform_bits::<RESAMPLE>(bits);
        self.record("sample-uniform-bits");
        value
    }
}

impl<F, P, const WIDTH: usize, const RATE: usize> FieldChallenger<F>
    for RecordingDuplexChallenger<F, P, WIDTH, RATE>
where
    F: PrimeField64 + Sync,
    P: CryptographicPermutation<[F; WIDTH]> + Sync,
{
}

impl<F, P, const WIDTH: usize, const RATE: usize> GrindingChallenger
    for RecordingDuplexChallenger<F, P, WIDTH, RATE>
where
    F: PrimeField64 + Sync,
    P: CryptographicPermutation<[F; WIDTH]> + Sync,
    DuplexChallenger<F, P, WIDTH, RATE>: GrindingChallenger<Witness = F>,
{
    type Witness = F;

    fn grind(&mut self, bits: usize) -> Self::Witness {
        let witness = self.inner.grind(bits);
        self.record("grind");
        witness
    }
}

impl<F, P, const WIDTH: usize, const RATE: usize> UniformGrindingChallenger
    for RecordingDuplexChallenger<F, P, WIDTH, RATE>
where
    F: Field + PrimeField64 + Sync,
    P: CryptographicPermutation<[F; WIDTH]> + Sync,
    DuplexChallenger<F, P, WIDTH, RATE>:
        UniformGrindingChallenger<Witness = F> + CanSampleUniformBits<F>,
{
    fn grind_uniform(&mut self, bits: usize) -> Self::Witness {
        let witness = self.inner.grind_uniform(bits);
        self.record("grind-uniform");
        witness
    }

    fn grind_uniform_may_error(&mut self, bits: usize) -> Self::Witness {
        let witness = self.inner.grind_uniform_may_error(bits);
        self.record("grind-uniform-may-error");
        witness
    }
}
