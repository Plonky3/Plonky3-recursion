//! PCS-specific backends for the unified recursion API.

mod context;
pub mod fri;
pub mod transcript;
pub mod whir;

use core::marker::PhantomData;

use context::{StarkLayoutPolicy, StarkPackingAuthority};
pub use fri::{FriRecursionBackend, FriRecursionBackendD5, FriRecursionBackendForExt};
pub use transcript::{replay_batch_layer_transcript, replay_recursion_input_transcript};
pub use whir::{WhirRecursionBackend, WhirRecursionBackendForExt, WhirRecursionConfig};

/// Opaque checked verifier result used by built-in PCS backends.  The inner
/// low-level result remains available as its own explicitly trusted API, while
/// this envelope retains the authority required for safe replacement packing.
pub struct CheckedVerifierResult<R, C, F> {
    pub(crate) inner: R,
    pub(crate) pcs: C,
    pub(crate) stark: StarkPackingAuthority<F>,
    pub(crate) policy: StarkLayoutPolicy,
    _marker: PhantomData<F>,
}

impl<R, C, F> CheckedVerifierResult<R, C, F> {
    pub(crate) const fn new(
        inner: R,
        pcs: C,
        stark: StarkPackingAuthority<F>,
        policy: StarkLayoutPolicy,
    ) -> Self {
        Self {
            inner,
            pcs,
            stark,
            policy,
            _marker: PhantomData,
        }
    }
}
