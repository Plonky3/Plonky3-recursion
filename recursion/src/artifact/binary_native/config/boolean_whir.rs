//! Closed Tower128 Boolean trace commitments over additive WHIR.
use super::*;
use p3_binary_field::BinaryField128;
use p3_binary_pcs::whir::{BinaryWhirDomain, BooleanWhirData, BooleanWhirPcs};
use p3_binary_pcs::{BooleanTraceCommitment, BooleanTraceCommitmentData};
type E = BinaryField128;
pub(in crate::artifact::binary_native) type NativeBooleanWhirTracePcs = BooleanTraceCommitment<
    E,
    BooleanWhirPcs<E, BinaryWhirDomain<E>, NativeMmcs<E>, BinaryNativeChallenger<E>>,
>;
/// Complete native Boolean WHIR trace configuration constructed by its owner.
pub struct BinaryNativeBooleanWhirTraceConfig {
    pub(in crate::artifact::binary_native) main: NativeBooleanWhirTracePcs,
    pub(in crate::artifact::binary_native) main_parameters: BinaryNativeWhirPcsParameters<E>,
    pub(in crate::artifact::binary_native) preprocessed: Option<NativeBooleanWhirTracePcs>,
    pub(in crate::artifact::binary_native) preprocessed_parameters:
        Option<BinaryNativeWhirPcsParameters<E>>,
}
impl MultiStarkConfig for BinaryNativeBooleanWhirTraceConfig {
    type Val = E;
    type Challenge = E;
    type Challenger = BinaryNativeChallenger<E>;
    type Pcs = NativeBooleanWhirTracePcs;
    fn pcs(&self) -> &Self::Pcs {
        &self.main
    }
    fn preprocessed_pcs(&self) -> &Self::Pcs {
        self.preprocessed.as_ref().unwrap_or(&self.main)
    }
    fn collision_resistance_bits(&self) -> Option<usize> {
        Some(128)
    }
    fn min_num_variables(&self) -> usize {
        1
    }
    fn build_witness(&self, tables: Vec<Table<E>>) -> Vec<Table<E>> {
        tables
    }
    fn committed_table<'a>(
        &self,
        data: &'a BooleanTraceCommitmentData<E, BooleanWhirData<E, NativeMmcs<E>>>,
        index: usize,
    ) -> &'a Table<E> {
        data.table(index)
    }
}
