mod common;

use p3_commit::Pcs;
use p3_recursion::pcs::fri::MerkleCapTargets;
use p3_recursion::pcs::whir::uni::WhirUniProofTargets;
use p3_recursion::traits::RecursivePcs;
use p3_uni_stark::StarkGenericConfig;

use crate::common::whir_config::{BB_DIGEST_ELEMS, BbEF, BbF, BbMmcs, BbWhirConfig, BbWhirPcs};

/// The WHIR PCS must satisfy the exact `RecursivePcs` bound
/// `verify_p3_uni_proof_circuit` requires; this fails to compile otherwise.
#[test]
fn whir_pcs_satisfies_the_recursive_pcs_bound() {
    fn assert_bound<P>()
    where
        P: RecursivePcs<
                BbWhirConfig,
                (),
                WhirUniProofTargets<BbF, BbEF, BbMmcs, BB_DIGEST_ELEMS>,
                MerkleCapTargets<BbF, BB_DIGEST_ELEMS>,
                <BbWhirPcs as Pcs<BbEF, <BbWhirConfig as StarkGenericConfig>::Challenger>>::Domain,
            >,
    {
    }
    assert_bound::<BbWhirPcs>();
}
