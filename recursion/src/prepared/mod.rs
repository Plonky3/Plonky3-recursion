//! Prepared-verifier native input contracts and borrowed input views.

pub(crate) mod input;
mod layer;
pub(crate) mod prover;

use p3_lookup::logup::LogUpGadget;
use p3_uni_stark::{StarkGenericConfig, Val};

pub use input::{NativeCommitment, PreparedInput, PreparedSource};
pub use layer::PreparedLayer;
use p3_lookup::logup::LogUpGadget;
use p3_uni_stark::{StarkGenericConfig, Val};

use crate::recursion::{PcsRecursionBackend, RecursionInput};
use crate::traits::RecursiveAir;
use crate::verifier::VerificationError;

/// Explicit backend opt-in for safe prepared-verifier circuit reuse.
///
/// Implementations are trusted to capture every native input property that can affect target
/// allocation or compiled verifier behavior. A backend implementing only
/// [`PcsRecursionBackend`] continues to work with uncached APIs and is deliberately excluded from
/// prepared owners.
///
/// ```compile_fail
/// use p3_lookup::logup::LogUpGadget;
/// use p3_recursion::{PcsRecursionBackend, PreparedPcsRecursionBackend, RecursiveAir};
/// use p3_uni_stark::{StarkGenericConfig, Val};
///
/// fn generic_backend_is_not_implicitly_prepared<SC, A, B, const D: usize>()
/// where
///     SC: StarkGenericConfig,
///     A: RecursiveAir<Val<SC>, SC::Challenge, LogUpGadget>,
///     B: PcsRecursionBackend<SC, A, D>,
/// {
///     fn needs_opt_in<SC, A, B, const D: usize>()
///     where
///         SC: StarkGenericConfig,
///         A: RecursiveAir<Val<SC>, SC::Challenge, LogUpGadget>,
///         B: PreparedPcsRecursionBackend<SC, A, D>,
///     {}
///     needs_opt_in::<SC, A, B, D>();
/// }
/// ```
///
/// A generic caller that requests the explicit prepared-backend contract compiles:
///
/// ```
/// use p3_lookup::logup::LogUpGadget;
/// use p3_recursion::{PreparedPcsRecursionBackend, RecursiveAir};
/// use p3_uni_stark::{StarkGenericConfig, Val};
///
/// fn accepts_explicit_opt_in<SC, A, B, const D: usize>()
/// where
///     SC: StarkGenericConfig,
///     A: RecursiveAir<Val<SC>, SC::Challenge, LogUpGadget>,
///     B: PreparedPcsRecursionBackend<SC, A, D>,
/// {
/// }
/// ```
pub trait PreparedPcsRecursionBackend<SC, A, const D: usize>:
    PcsRecursionBackend<SC, A, D>
where
    SC: StarkGenericConfig,
    A: RecursiveAir<Val<SC>, SC::Challenge, LogUpGadget>,
{
    /// Complete native contract used to authorize reuse.
    type InputContract;

    /// Capture and validate the trusted construction reference.
    fn capture_input_contract(
        &self,
        config: &SC,
        source: &RecursionInput<'_, SC, A>,
    ) -> Result<Self::InputContract, VerificationError>;

    /// Validate a later witness-only input against a captured contract.
    fn validate_prepared_input(
        &self,
        config: &SC,
        contract: &Self::InputContract,
        input: &PreparedInput<'_, SC>,
    ) -> Result<(), VerificationError>;
}
