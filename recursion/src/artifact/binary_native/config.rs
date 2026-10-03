//! Closed native cryptographic configuration and setup-only cap capture.

mod boolean_whir;
pub use boolean_whir::BinaryNativeBooleanWhirTraceConfig;
pub(super) use boolean_whir::NativeBooleanWhirTracePcs;
mod poly_whir;
pub use poly_whir::{
    BinaryNativePolyWhirConfig, BinaryNativePolyWhirLayout, BinaryNativePolyWhirPcsParameters,
};
pub(super) use poly_whir::NativePolyWhirPcs;
mod whir;
pub use whir::{BinaryNativeWhirConfig, BinaryNativeWhirLayout, BinaryNativeWhirPcsParameters};
pub(super) use whir::NativeWhirPcs;

use alloc::vec::Vec;

use p3_binary_dft::EncodableLevel;
use p3_binary_field::{BinaryChallenger, TowerLevel};
use p3_binary_pcs::{BinaryPcs, ChallengeField, FoldAlphabet, GroupedCodewordMmcs};
use p3_challenger::{
    CanObserve, CanSample, CanSampleBits, CanSampleUniformBits, FieldChallenger,
    GrindingChallenger, HashChallenger, ResamplingError,
};
use p3_circuit::ops::ByteHash;
use p3_field::{BasedVectorSpace, ExtensionField, PackedValue};
use p3_merkle_tree::{MerkleCap, MerkleTreeMmcs};
use p3_multi_stark::config::{MultiStarkConfig, ProverData};
use p3_sumcheck::layout::{Layout, SuffixProver, Table, Witness};
use p3_symmetric::{CompressionFunctionFromHasher, CryptographicHasher, SerializingHasher};

use crate::pcs::binary::{RecursiveBinaryChallengeField, RecursiveBinaryTowerField};
use crate::verifier::VerificationError;

/// Closed byte hasher used only through the factory's native configuration.
#[derive(Clone, Copy, Debug)]
pub struct BinaryNativeHash(pub(super) ByteHash);
impl CryptographicHasher<u8, [u8; 32]> for BinaryNativeHash {
    fn hash_iter<I: IntoIterator<Item = u8>>(&self, input: I) -> [u8; 32] {
        match self.0 {
            ByteHash::Keccak256 => p3_keccak::Keccak256Hash.hash_iter(input),
            ByteHash::Blake3 => p3_blake3::Blake3.hash_iter(input),
        }
    }
}

pub(super) type NativeMmcs<F> = MerkleTreeMmcs<
    F,
    u8,
    SerializingHasher<BinaryNativeHash>,
    CompressionFunctionFromHasher<BinaryNativeHash, 2, 32>,
    2,
    32,
>;
pub(super) type NativePcs<F, E> = BinaryPcs<F, E, NativeMmcs<F>, NativeMmcs<E>>;
type Inner<F> = BinaryChallenger<F, HashChallenger<u8, BinaryNativeHash, 32>>;

#[derive(Clone)]
enum Capture {
    Off,
    Waiting(usize),
    Got(Vec<[u8; 32]>),
    Bad,
}

/// Native transcript with private configuration and setup capture state.
#[derive(Clone)]
pub struct BinaryNativeChallenger<F> {
    inner: Inner<F>,
    capture: Capture,
}

impl<F> BinaryNativeChallenger<F> {
    pub(super) fn fresh(initial: Vec<u8>, hash: ByteHash) -> Self {
        Self {
            inner: Inner::from_hasher(initial, BinaryNativeHash(hash)),
            capture: Capture::Off,
        }
    }
    pub(super) fn for_setup(expected_roots: usize, hash: ByteHash) -> Self {
        let mut ch = Self::fresh(Vec::new(), hash);
        ch.capture = Capture::Waiting(expected_roots);
        ch
    }
    pub(super) fn finish_setup(
        self,
        expected_roots: usize,
    ) -> Result<Option<Vec<[u8; 32]>>, VerificationError> {
        match self.capture {
            Capture::Waiting(0) if expected_roots == 0 => Ok(None),
            Capture::Got(roots) if expected_roots != 0 && roots.len() == expected_roots => {
                Ok(Some(roots))
            }
            _ => Err(super::invalid(
                "binary native setup preprocessing capture failed",
            )),
        }
    }
    fn record_cap(&mut self, roots: &[[u8; 32]]) {
        self.capture = match core::mem::replace(&mut self.capture, Capture::Off) {
            Capture::Off => Capture::Off,
            Capture::Waiting(n) if roots.len() == n => {
                let mut copy = Vec::new();
                if copy.try_reserve_exact(n).is_err() {
                    Capture::Bad
                } else {
                    copy.extend_from_slice(roots);
                    Capture::Got(copy)
                }
            }
            _ => Capture::Bad,
        };
    }
}

// Local closed alphabet avoids overlapping scalar/cap observation impls.
pub(super) trait NativeAlphabet: TowerLevel {}
impl<F: RecursiveBinaryTowerField> NativeAlphabet for F {}
impl NativeAlphabet for p3_binary_field::Poly64 {}

impl<F: NativeAlphabet> CanObserve<F> for BinaryNativeChallenger<F> {
    fn observe(&mut self, value: F) {
        self.inner.observe(value);
    }
}
impl<F: NativeAlphabet, G> CanObserve<MerkleCap<G, [u8; 32]>>
    for BinaryNativeChallenger<F>
{
    fn observe(&mut self, cap: MerkleCap<G, [u8; 32]>) {
        self.record_cap(cap.roots());
        self.inner.observe(cap);
    }
}
impl<F: NativeAlphabet, T: BasedVectorSpace<F>> CanSample<T>
    for BinaryNativeChallenger<F>
{
    fn sample(&mut self) -> T {
        <Inner<F> as CanSample<T>>::sample(&mut self.inner)
    }
}
impl<F: NativeAlphabet> CanSampleBits<usize> for BinaryNativeChallenger<F> {
    fn sample_bits(&mut self, bits: usize) -> usize {
        self.inner.sample_bits(bits)
    }
}
impl<F: NativeAlphabet> CanSampleUniformBits<F> for BinaryNativeChallenger<F> {
    fn sample_uniform_bits<const RESAMPLE: bool>(
        &mut self,
        bits: usize,
    ) -> Result<usize, ResamplingError> {
        self.inner.sample_uniform_bits::<RESAMPLE>(bits)
    }
}
impl<F: NativeAlphabet> GrindingChallenger for BinaryNativeChallenger<F> {
    type Witness = F;
    fn grind(&mut self, bits: usize) -> F {
        self.inner.grind(bits)
    }
    fn check_witness(&mut self, bits: usize, witness: F) -> bool {
        self.inner.check_witness(bits, witness)
    }
}
impl<F: NativeAlphabet> FieldChallenger<F> for BinaryNativeChallenger<F> {}

/// Opaque native configuration appearing in the factory's proof type. Its
/// fields and constructor are private; callers cannot replace the PCS or hash.
pub struct BinaryNativeConfig<F: EncodableLevel, E> {
    pub(super) main: NativePcs<F, E>,
    pub(super) preprocessed: Option<NativePcs<F, E>>,
}

impl<F, E> MultiStarkConfig for BinaryNativeConfig<F, E>
where
    F: RecursiveBinaryTowerField + EncodableLevel + FoldAlphabet<E> + PackedValue<Value = F>,
    E: RecursiveBinaryChallengeField
        + ExtensionField<F>
        + ChallengeField<F>
        + FoldAlphabet<E>
        + PackedValue<Value = E>,
{
    type Val = F;
    type Challenge = E;
    type Challenger = BinaryNativeChallenger<F>;
    type Pcs = NativePcs<F, E>;
    fn pcs(&self) -> &Self::Pcs {
        &self.main
    }
    fn preprocessed_pcs(&self) -> &Self::Pcs {
        self.preprocessed
            .as_ref()
            .expect("factory checked preprocessing configuration")
    }
    fn min_num_variables(&self) -> usize {
        1
    }
    fn collision_resistance_bits(&self) -> Option<usize> {
        Some(128)
    }
    fn build_witness(&self, tables: Vec<Table<F>>) -> Witness<F> {
        SuffixProver::<F, E>::new_witness(tables, 0)
    }
    fn committed_table<'a>(&self, data: &'a ProverData<Self>, index: usize) -> &'a Table<F> {
        data.table(index)
    }
}

pub(super) type NativeGroupedPcs<F, E> =
    BinaryPcs<F, E, GroupedCodewordMmcs<NativeMmcs<F>>, GroupedCodewordMmcs<NativeMmcs<E>>>;

/// Opaque native configuration appearing in the factory's proof type. Its
/// fields and constructor are private; callers cannot replace the PCS or hash.
pub struct BinaryNativeGroupedConfig<F: EncodableLevel, E> {
    pub(super) main: NativeGroupedPcs<F, E>,
    pub(super) preprocessed: Option<NativeGroupedPcs<F, E>>,
}

impl<F, E> MultiStarkConfig for BinaryNativeGroupedConfig<F, E>
where
    F: RecursiveBinaryTowerField + EncodableLevel + FoldAlphabet<E> + PackedValue<Value = F>,
    E: RecursiveBinaryChallengeField
        + ExtensionField<F>
        + ChallengeField<F>
        + FoldAlphabet<E>
        + PackedValue<Value = E>,
{
    type Val = F;
    type Challenge = E;
    type Challenger = BinaryNativeChallenger<F>;
    type Pcs = NativeGroupedPcs<F, E>;
    fn pcs(&self) -> &Self::Pcs {
        &self.main
    }
    fn preprocessed_pcs(&self) -> &Self::Pcs {
        self.preprocessed
            .as_ref()
            .expect("factory checked preprocessing configuration")
    }
    fn min_num_variables(&self) -> usize {
        1
    }
    fn collision_resistance_bits(&self) -> Option<usize> {
        Some(128)
    }
    fn build_witness(&self, tables: Vec<Table<F>>) -> Witness<F> {
        SuffixProver::<F, E>::new_witness(tables, 0)
    }
    fn committed_table<'a>(&self, data: &'a ProverData<Self>, index: usize) -> &'a Table<F> {
        data.table(index)
    }
}

pub(super) type NativeGroupedBooleanTracePcs<E> = p3_binary_pcs::BooleanTracePcs<
    E,
    GroupedCodewordMmcs<NativeMmcs<E>>,
    GroupedCodewordMmcs<NativeMmcs<E>>,
>;

/// Factory-owned Boolean trace configuration with independent main and
/// preprocessing commitment schedules.
pub struct BinaryNativeGroupedBooleanTraceConfig<E: EncodableLevel> {
    pub(super) main: NativeGroupedBooleanTracePcs<E>,
    pub(super) preprocessed: Option<NativeGroupedBooleanTracePcs<E>>,
}

impl<E> MultiStarkConfig for BinaryNativeGroupedBooleanTraceConfig<E>
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
{
    type Val = E;
    type Challenge = E;
    type Challenger = BinaryNativeChallenger<E>;
    type Pcs = NativeGroupedBooleanTracePcs<E>;
    fn pcs(&self) -> &Self::Pcs {
        &self.main
    }
    fn preprocessed_pcs(&self) -> &Self::Pcs {
        self.preprocessed
            .as_ref()
            .expect("factory checked preprocessing configuration")
    }
    fn min_num_variables(&self) -> usize {
        1
    }
    fn collision_resistance_bits(&self) -> Option<usize> {
        Some(128)
    }
    fn build_witness(&self, tables: Vec<Table<E>>) -> Vec<Table<E>> {
        tables
    }
    fn committed_table<'a>(&self, data: &'a ProverData<Self>, index: usize) -> &'a Table<E> {
        data.table(index)
    }
}

pub(super) type NativeBooleanTracePcs<E> =
    p3_binary_pcs::BooleanTracePcs<E, NativeMmcs<E>, NativeMmcs<E>>;

/// Factory-owned Boolean trace configuration with independent main and
/// preprocessing commitment schedules.
pub struct BinaryNativeBooleanTraceConfig<E: EncodableLevel> {
    pub(super) main: NativeBooleanTracePcs<E>,
    pub(super) preprocessed: Option<NativeBooleanTracePcs<E>>,
}

impl<E> MultiStarkConfig for BinaryNativeBooleanTraceConfig<E>
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
{
    type Val = E;
    type Challenge = E;
    type Challenger = BinaryNativeChallenger<E>;
    type Pcs = NativeBooleanTracePcs<E>;
    fn pcs(&self) -> &Self::Pcs {
        &self.main
    }
    fn preprocessed_pcs(&self) -> &Self::Pcs {
        self.preprocessed
            .as_ref()
            .expect("factory checked preprocessing configuration")
    }
    fn min_num_variables(&self) -> usize {
        1
    }
    fn collision_resistance_bits(&self) -> Option<usize> {
        Some(128)
    }
    fn build_witness(&self, tables: Vec<Table<E>>) -> Vec<Table<E>> {
        tables
    }
    fn committed_table<'a>(&self, data: &'a ProverData<Self>, index: usize) -> &'a Table<E> {
        data.table(index)
    }
}

pub(super) fn tree<F>(hash: ByteHash, cap_height: usize) -> NativeMmcs<F> {
    NativeMmcs::new(
        SerializingHasher::new(BinaryNativeHash(hash)),
        CompressionFunctionFromHasher::new(BinaryNativeHash(hash)),
        cap_height,
    )
}
