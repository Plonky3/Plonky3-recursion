mod common;

use p3_recursion::backend::whir::WhirRecursionBackendForExt;
use p3_recursion::recursion::PcsRecursionBackend;

use crate::common::whir_config::BbWhirConfig;

/// `WhirRecursionBackendForExt<4, ...>` must satisfy the exact `PcsRecursionBackend` bound
/// `recursion.rs`'s pipeline functions require; this fails to compile otherwise.
#[test]
fn whir_recursion_backend_satisfies_the_pcs_recursion_backend_bound() {
    fn assert_bound<B, SC, A>()
    where
        SC: p3_uni_stark::StarkGenericConfig,
        A: p3_recursion::traits::RecursiveAir<
                p3_uni_stark::Val<SC>,
                SC::Challenge,
                p3_lookup::logup::LogUpGadget,
            >,
        B: PcsRecursionBackend<SC, A, 4>,
    {
    }
    assert_bound::<WhirRecursionBackendForExt<4>, BbWhirConfig, p3_circuit::test_utils::FibonacciAir>(
    );
}
