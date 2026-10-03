//! Closed native 0.8 proof wire layout. All geometry is retained authority;
//! dynamic lengths are bounded before their allocation.

use alloc::vec::Vec;
mod scalar;
use scalar::ScalarWire;

use p3_binary_dft::EncodableLevel;
use p3_binary_pcs::{BinaryPcsProof, ChallengeField, FoldAlphabet, RoundProof};
use p3_bus::{BusProof, ProductGkrLayerProof, ProductGkrProof};
use p3_commit::{Mmcs, MultilinearPcs};
use p3_field::{ExtensionField, PackedValue};
use p3_merkle_tree::{MerkleCap, PrunedMerklePaths};
use p3_multi_stark::MultiStarkProof;
use p3_multi_stark::config::{MultiStarkConfig, PcsProof as ConfigPcsProof};
use p3_multi_stark::folder::VerifierAir;
use p3_multi_stark::fractional_gkr::{FractionGkrLayerProof, FractionGkrProof, SplitFraction};
use p3_multi_stark::logup_star::LogupStarProof;
use p3_multi_stark::proof::IndexedLookupProof;
use p3_multilinear_util::poly::Poly;
use p3_sumcheck::generic_degree::GenericDegreeProof;
use p3_sumcheck::{OpeningBatch, SumcheckData};

use super::config::NativeMmcs;
use super::{BinaryNativeAuthority, BinaryNativeConfig, VerifiedBinaryNativeProof};
use crate::artifact::wire::{Reader, Writer, checked_product, decode_framed, encode_framed};
use crate::artifact::{ArtifactError, ArtifactKind, ArtifactLimits, ExpectedVerifierArtifact};
use crate::pcs::binary::{RecursiveBinaryChallengeField, RecursiveBinaryTowerField};
use crate::verifier::InputResourceUsage;

/// Independent binary values in AIR order, then public-value order, encoded
/// using the base field's exact raw little-endian width. No length prefix.
#[derive(Clone, Copy, Debug)]
pub struct CanonicalBinaryStatement<'a> {
    bytes: &'a [u8],
    element_count: usize,
}
impl<'a> CanonicalBinaryStatement<'a> {
    pub const fn new(bytes: &'a [u8], element_count: usize) -> Self {
        Self {
            bytes,
            element_count,
        }
    }
}

pub(crate) struct GenericDecode {
    pub rounds: usize,
    pub degree: usize,
    pub pow_count: usize,
}
pub(crate) struct ProductDecode {
    pub roots: usize,
    pub trees: usize,
    pub layers: Vec<(usize, usize)>,
}
pub(crate) struct LogupDecode {
    pub pushforward_lengths: Vec<usize>,
    pub fraction_height: usize,
    pub position_claims: usize,
    pub product: GenericDecode,
    pub column_widths: Vec<usize>,
}
pub(crate) struct IndexedDecode {
    pub reader_widths: Vec<usize>,
    pub reduction: LogupDecode,
}
pub(crate) struct OracleDecode {
    pub rows: usize,
    pub path_len: usize,
}
pub(crate) struct GroupedOracleDecode {
    pub rows: usize,
    pub symbol_bits: usize,
    pub group_size: usize,
    pub coset_width: usize,
    pub path_len: usize,
}

pub(super) trait OracleRows {
    fn rows(&self) -> usize;
}
impl OracleRows for OracleDecode {
    fn rows(&self) -> usize {
        self.rows
    }
}
impl OracleRows for GroupedOracleDecode {
    fn rows(&self) -> usize {
        self.rows
    }
}

pub(crate) struct PcsDecode<O = OracleDecode> {
    pub cap_roots: usize,
    pub sumcheck_rounds: usize,
    pub eval_widths: Vec<(usize, usize)>,
    pub rounds: Vec<O>,
    pub base: O,
    pub final_codeword: usize,
}
pub(crate) struct MultiDecode<O = PcsDecode> {
    pub public_counts: Vec<usize>,
    pub cap_roots: usize,
    pub bus: Option<ProductDecode>,
    pub sumcheck: GenericDecode,
    pub indexed: Option<IndexedDecode>,
    pub opening: O,
    pub preprocessed: Option<O>,
}

pub(crate) struct RingDecode {
    pub successor: Vec<bool>,
    pub min_rounds: usize,
    pub max_rounds: usize,
}

pub(crate) struct BooleanTraceDecode<P = PcsDecode<GroupedOracleDecode>> {
    pub value_count: usize,
    pub ring: RingDecode,
    pub packed: P,
}

pub(crate) struct WhirFoldDecode {
    pub rounds: usize,
    pub pow_count: usize,
}
pub(crate) struct WhirSiteDecode {
    pub width: usize,
    pub oracle: OracleDecode,
    pub query_pow_bits: usize,
    pub ood: usize,
    pub fold: WhirFoldDecode,
}
pub(crate) struct WhirDecode {
    pub eval_widths: Vec<(usize, usize)>,
    pub cap_roots: usize,
    pub initial_ood: usize,
    pub initial_fold: WhirFoldDecode,
    pub sites: Vec<WhirSiteDecode>,
    pub final_poly_len: usize,
}

mod boolean;
mod boolean_whir;
mod grouped;
mod grouped_boolean;
mod grouped_shell;
mod poly_whir;
mod whir;

type PcsProof<F, E> = BinaryPcsProof<F, E, NativeMmcs<F>, NativeMmcs<E>>;

impl<F, E, A> BinaryNativeAuthority<F, E, A>
where
    F: RecursiveBinaryTowerField + EncodableLevel + FoldAlphabet<E> + PackedValue<Value = F>,
    E: RecursiveBinaryChallengeField
        + ExtensionField<F>
        + ChallengeField<F>
        + FoldAlphabet<E>
        + PackedValue<Value = E>,
    A: VerifierAir<F, E>,
{
    pub fn encode_statement(&self, public: &[Vec<F>]) -> Result<Vec<u8>, ArtifactError> {
        self.state
            .check_public(public)
            .map_err(|_| ArtifactError::VerificationRejected)?;
        let mut writer = Writer::new(self.state.limits.max_proof_bytes);
        write_public(&mut writer, public)?;
        writer.finish()
    }

    /// Encoding accepts a proof only after the same complete native checks used
    /// for imports. Its geometry cannot silently alter the fixed wire layout.
    pub fn encode_native_proof(
        &self,
        proof: &MultiStarkProof<BinaryNativeConfig<F, E>>,
        public: &[Vec<F>],
    ) -> Result<Vec<u8>, ArtifactError> {
        self.verify_native(proof, public)
            .map_err(|_| ArtifactError::VerificationRejected)?;
        encode_multi::<BinaryNativeConfig<F, E>>(
            proof,
            public,
            suite::<F, E>(),
            &self.state.limits,
            write_pcs::<F, E>,
        )
    }

    /// Match both the application trust anchor and this factory's retained
    /// identity before decoding any statement or proof-dependent allocation.
    /// Attached public values are compared to the independent statement, then
    /// bounded transcript replay and full native authentication mint the token.
    pub fn decode_and_verify(
        &self,
        candidate: &[u8],
        expected: ExpectedVerifierArtifact<'_>,
        proof_bytes: &[u8],
        statement: CanonicalBinaryStatement<'_>,
    ) -> Result<VerifiedBinaryNativeProof<F, E>, ArtifactError> {
        let authority = DecodeAuthority {
            identity: &self.state.identity,
            shape: &self.state.decode,
            limits: &self.state.limits,
            usage: self.state.binary.input_resource_usage(),
            suite: suite::<F, E>(),
        };
        let (proof, public) = authority.decode::<BinaryNativeConfig<F, E>>(
            candidate,
            expected,
            proof_bytes,
            statement,
            read_pcs::<F, E>,
        )?;
        self.verify_native(&proof, &public)
            .map_err(|_| ArtifactError::VerificationRejected)
    }
}

/// Shared outer framing for the closed native opening frontends. Encoding
/// callers first run their complete retained native verification authority.
pub(super) fn encode_multi<C>(
    proof: &MultiStarkProof<C>,
    public: &[Vec<C::Val>],
    suite: u16,
    limits: &ArtifactLimits,
    write_opening: fn(&mut Writer, &ConfigPcsProof<C>) -> Result<(), ArtifactError>,
) -> Result<Vec<u8>, ArtifactError>
where
    C: MultiStarkConfig,
    C::Val: ScalarWire,
    C::Challenge: ScalarWire,
    C::Pcs: MultilinearPcs<C::Challenge, C::Challenger, Commitment = MerkleCap<C::Val, [u8; 32]>>,
{
    encode_framed(ArtifactKind::Proof, suite, limits.max_proof_bytes, |w| {
        w.write_u16(1)?;
        write_public(w, public)?;
        write_cap(w, &proof.commitment)?;
        if let Some(bus) = &proof.bus {
            write_product(w, &bus.product)?;
        }
        write_generic(w, &proof.sumcheck)?;
        if let Some(indexed) = &proof.indexed {
            write_indexed(w, indexed)?;
        }
        write_opening(w, &proof.opening)?;
        if let Some(pp) = &proof.preprocessed_opening {
            write_opening(w, pp)?;
        }
        Ok(())
    })
}

/// Retained authority only: no proof-derived geometry or caller verifier hooks.
pub(super) struct DecodeAuthority<'a, O> {
    pub(super) identity: &'a [u8],
    pub(super) shape: &'a MultiDecode<O>,
    pub(super) limits: &'a ArtifactLimits,
    pub(super) usage: InputResourceUsage,
    pub(super) suite: u16,
}
impl<O> DecodeAuthority<'_, O> {
    pub(super) fn decode<C>(
        &self,
        candidate: &[u8],
        expected: ExpectedVerifierArtifact<'_>,
        proof_bytes: &[u8],
        statement: CanonicalBinaryStatement<'_>,
        mut read_opening: impl FnMut(
            &mut Reader<'_>,
            &O,
            &mut usize,
        ) -> Result<ConfigPcsProof<C>, ArtifactError>,
    ) -> Result<(MultiStarkProof<C>, Vec<Vec<C::Val>>), ArtifactError>
    where
        C: MultiStarkConfig,
        C::Val: ScalarWire,
        C::Challenge: ScalarWire,
        C::Pcs:
            MultilinearPcs<C::Challenge, C::Challenger, Commitment = MerkleCap<C::Val, [u8; 32]>>,
    {
        if candidate != expected.canonical_bytes || candidate != self.identity {
            return Err(ArtifactError::TrustedArtifactMismatch);
        }
        let shape = self.shape;
        let count = shape.public_counts.iter().try_fold(0usize, |n, &m| {
            n.checked_add(m).ok_or(ArtifactError::LengthOverflow)
        })?;
        if statement.element_count != count
            || statement.bytes.len() != checked_product(count, <C::Val as ScalarWire>::WIRE_BYTES)?
        {
            return Err(malformed("binary independent statement"));
        }
        let (proof, public) = decode_framed(
            proof_bytes,
            ArtifactKind::Proof,
            self.limits,
            |tag| tag == self.suite,
            |_, r| {
                if r.read_u16()? != 1 {
                    return Err(malformed("binary proof revision"));
                }
                let expected = r.read_alternate_slice(statement.bytes, |r| {
                    read_public::<C::Val>(r, &shape.public_counts)
                })?;
                let attached = read_public::<C::Val>(r, &shape.public_counts)?;
                if attached != expected {
                    return Err(ArtifactError::VerificationRejected);
                }
                // Native replay produces additional shape-bounded witness storage.
                // Charge a conservative limb-sized conversion before invoking it.
                let usage = self.usage;
                r.charge_conversion_vec::<u128>(usage.scalar_elements)?;
                // The returned witness retains deep copies of trusted shape
                // metadata, including nested reduction shapes. Charge those
                // independently of its proof scalars and restored paths.
                r.charge_conversion_vec::<[u8; 128]>(usage.metadata_entries)?;
                r.charge_conversion_vec::<u8>(usage.metadata_string_bytes)?;
                let mut frontiers = 0;
                let proof = MultiStarkProof {
                    commitment: read_cap(r, shape.cap_roots)?,
                    lookup: None,
                    bus: shape
                        .bus
                        .as_ref()
                        .map(|s| read_product(r, s).map(|product| BusProof { product }))
                        .transpose()?,
                    sumcheck: read_generic(r, &shape.sumcheck)?,
                    indexed: shape
                        .indexed
                        .as_ref()
                        .map(|s| read_indexed(r, s))
                        .transpose()?,
                    opening: read_opening(r, &shape.opening, &mut frontiers)?,
                    preprocessed_opening: shape
                        .preprocessed
                        .as_ref()
                        .map(|s| read_opening(r, s, &mut frontiers))
                        .transpose()?,
                };
                Ok((proof, expected))
            },
        )?;
        Ok((proof, public))
    }
}

fn suite<F: RecursiveBinaryTowerField, E: RecursiveBinaryChallengeField>() -> u16 {
    let base = match F::RAW_BITS {
        8 => 1,
        16 => 2,
        32 => 3,
        64 => 4,
        128 => 5,
        _ => unreachable!(),
    };
    let challenge = match E::RAW_BITS {
        64 => 1,
        128 => 2,
        _ => unreachable!(),
    };
    0xb000 | (base << 4) | challenge
}
fn malformed(component: &'static str) -> ArtifactError {
    ArtifactError::MalformedProof { component }
}
fn write_field<F: ScalarWire>(w: &mut Writer, value: F) -> Result<(), ArtifactError> {
    value.write_le(w)
}
fn read_field<F: ScalarWire>(r: &mut Reader<'_>) -> Result<F, ArtifactError> {
    r.charge_binary_scalars(F::INPUT_LIMBS)?;
    F::read_le(r)
}
fn write_fields<F: ScalarWire>(w: &mut Writer, values: &[F]) -> Result<(), ArtifactError> {
    for &value in values {
        write_field(w, value)?;
    }
    Ok(())
}
fn read_fields<F: ScalarWire>(r: &mut Reader<'_>, count: usize) -> Result<Vec<F>, ArtifactError> {
    r.read_exact_items("binary fields", count, F::WIRE_BYTES, read_field::<F>)
}
fn write_public<F: ScalarWire>(w: &mut Writer, values: &[Vec<F>]) -> Result<(), ArtifactError> {
    for row in values {
        write_fields(w, row)?;
    }
    Ok(())
}
fn read_public<F: ScalarWire>(
    r: &mut Reader<'_>,
    counts: &[usize],
) -> Result<Vec<Vec<F>>, ArtifactError> {
    let mut i = 0;
    r.read_exact_items("binary statement AIRs", counts.len(), 0, |r| {
        let count = counts[i];
        i += 1;
        read_fields(r, count)
    })
}
fn write_cap<F>(w: &mut Writer, cap: &MerkleCap<F, [u8; 32]>) -> Result<(), ArtifactError> {
    for root in cap.roots() {
        w.write_bytes(root)?;
    }
    Ok(())
}
fn read_cap<F>(r: &mut Reader<'_>, roots: usize) -> Result<MerkleCap<F, [u8; 32]>, ArtifactError> {
    r.read_exact_items("binary cap", roots, 32, read_digest)
        .map(MerkleCap::new)
}
fn read_digest(r: &mut Reader<'_>) -> Result<[u8; 32], ArtifactError> {
    r.charge_binary_scalars(16)?;
    Ok(r.read_bytes(32)?.try_into().unwrap())
}
fn write_generic<F: ScalarWire, E: ScalarWire>(
    w: &mut Writer,
    p: &GenericDegreeProof<F, E>,
) -> Result<(), ArtifactError> {
    write_field(w, p.claimed_sum)?;
    for row in &p.round_polys {
        write_fields(w, row)?;
    }
    write_fields(w, &p.pow_witnesses)
}
fn read_generic<F: ScalarWire, E: ScalarWire>(
    r: &mut Reader<'_>,
    s: &GenericDecode,
) -> Result<GenericDegreeProof<F, E>, ArtifactError> {
    Ok(GenericDegreeProof {
        claimed_sum: read_field(r)?,
        round_polys: r.read_exact_items(
            "binary generic rounds",
            s.rounds,
            checked_product(s.degree, E::WIRE_BYTES)?,
            |r| read_fields(r, s.degree),
        )?,
        pow_witnesses: read_fields(r, s.pow_count)?,
    })
}
fn write_product<E: ScalarWire>(
    w: &mut Writer,
    p: &ProductGkrProof<E>,
) -> Result<(), ArtifactError> {
    write_fields(w, &p.roots)?;
    for layer in &p.layers {
        match layer {
            ProductGkrLayerProof::Binary { children } => {
                for child in children {
                    write_fields(w, child)?;
                }
            }
            ProductGkrLayerProof::RadixFour {
                round_polys,
                children,
            } => {
                for row in round_polys {
                    write_fields(w, row)?;
                }
                for child in children {
                    write_fields(w, child)?;
                }
            }
        }
    }
    Ok(())
}
fn read_array<F: ScalarWire, const N: usize>(r: &mut Reader<'_>) -> Result<[F; N], ArtifactError> {
    let mut values = [F::ZERO; N];
    for value in &mut values {
        *value = read_field(r)?;
    }
    Ok(values)
}
fn read_product<E: ScalarWire>(
    r: &mut Reader<'_>,
    s: &ProductDecode,
) -> Result<ProductGkrProof<E>, ArtifactError> {
    let roots = read_fields(r, s.roots)?;
    let mut index = 0;
    let layers = r.read_exact_items("binary product layers", s.layers.len(), 0, |r| {
        let (arity, rounds) = s.layers[index];
        index += 1;
        if arity == 2 {
            Ok(ProductGkrLayerProof::Binary {
                children: r.read_exact_items(
                    "binary product children",
                    s.trees,
                    2 * E::WIRE_BYTES,
                    read_array,
                )?,
            })
        } else {
            Ok(ProductGkrLayerProof::RadixFour {
                round_polys: r.read_exact_items(
                    "binary product rounds",
                    rounds,
                    5 * E::WIRE_BYTES,
                    read_array,
                )?,
                children: r.read_exact_items(
                    "binary product children",
                    s.trees,
                    4 * E::WIRE_BYTES,
                    read_array,
                )?,
            })
        }
    })?;
    Ok(ProductGkrProof { roots, layers })
}
fn write_fraction<E: ScalarWire>(
    w: &mut Writer,
    p: &FractionGkrProof<E>,
) -> Result<(), ArtifactError> {
    write_field(w, p.root_denominator)?;
    for layer in &p.layers {
        for row in &layer.round_polys {
            write_fields(w, row)?;
        }
        let c = &layer.claims;
        write_fields(w, &[c.n0, c.d0, c.n1, c.d1])?;
    }
    Ok(())
}
fn read_fraction<E: ScalarWire>(
    r: &mut Reader<'_>,
    height: usize,
) -> Result<FractionGkrProof<E>, ArtifactError> {
    let root_denominator = read_field(r)?;
    let mut round = 0;
    let layers = r.read_exact_items("binary fraction layers", height, 4 * E::WIRE_BYTES, |r| {
        let round_polys = r.read_exact_items(
            "binary fraction rounds",
            round,
            3 * E::WIRE_BYTES,
            read_array,
        )?;
        round += 1;
        let [n0, d0, n1, d1] = read_array(r)?;
        Ok(FractionGkrLayerProof {
            round_polys,
            claims: SplitFraction { n0, d0, n1, d1 },
        })
    })?;
    Ok(FractionGkrProof {
        root_denominator,
        layers,
    })
}
fn write_indexed<F: ScalarWire, E: ScalarWire>(
    w: &mut Writer,
    p: &IndexedLookupProof<F, E>,
) -> Result<(), ArtifactError> {
    for row in &p.reader_claims {
        write_fields(w, row)?;
    }
    let p = &p.reduction;
    for row in &p.pushforwards {
        write_fields(w, row)?;
    }
    write_fraction(w, &p.fraction_gkr)?;
    write_fields(w, &p.position_claims)?;
    write_generic(w, &p.product)?;
    for row in &p.column_claims {
        write_fields(w, row)?;
    }
    Ok(())
}
fn read_indexed<F: ScalarWire, E: ScalarWire>(
    r: &mut Reader<'_>,
    s: &IndexedDecode,
) -> Result<IndexedLookupProof<F, E>, ArtifactError> {
    Ok(IndexedLookupProof {
        reader_claims: read_public(r, &s.reader_widths)?,
        reduction: LogupStarProof {
            pushforwards: read_public(r, &s.reduction.pushforward_lengths)?,
            fraction_gkr: read_fraction(r, s.reduction.fraction_height)?,
            position_claims: read_fields(r, s.reduction.position_claims)?,
            product: read_generic(r, &s.reduction.product)?,
            column_claims: read_public(r, &s.reduction.column_widths)?,
        },
    })
}
fn write_frontier(w: &mut Writer, p: &PrunedMerklePaths<u8, 32>) -> Result<(), ArtifactError> {
    w.write_vec(
        "binary compressed frontier",
        &p.sibling_hashes,
        |w, hash| w.write_bytes(hash),
    )
}
fn read_frontier(
    r: &mut Reader<'_>,
    s: &OracleDecode,
    total: &mut usize,
) -> Result<PrunedMerklePaths<u8, 32>, ArtifactError> {
    let per_oracle = checked_product(s.rows, s.path_len)?;
    let limit = r.limits().verifier.max_compressed_frontier_hashes;
    let remaining = limit
        .checked_sub(*total)
        .ok_or(ArtifactError::LengthOverflow)?;
    let hashes = r.read_vec_limited(
        "binary compressed frontier",
        per_oracle.min(remaining),
        32,
        read_digest,
    )?;
    *total = total
        .checked_add(hashes.len())
        .ok_or(ArtifactError::LengthOverflow)?;
    Ok(PrunedMerklePaths {
        sibling_hashes: hashes,
    })
}
fn write_pcs<F: RecursiveBinaryTowerField, E: RecursiveBinaryChallengeField>(
    w: &mut Writer,
    p: &PcsProof<F, E>,
) -> Result<(), ArtifactError> {
    write_pcs_with(w, p, write_frontier, write_frontier)
}
pub(super) fn write_pcs_with<F, E, M, MX>(
    w: &mut Writer,
    p: &BinaryPcsProof<F, E, M, MX>,
    write_base: fn(&mut Writer, &M::MultiProof) -> Result<(), ArtifactError>,
    write_round: fn(&mut Writer, &MX::MultiProof) -> Result<(), ArtifactError>,
) -> Result<(), ArtifactError>
where
    F: RecursiveBinaryTowerField,
    E: RecursiveBinaryChallengeField,
    M: Mmcs<F, Commitment = MerkleCap<F, [u8; 32]>>,
    MX: Mmcs<E, Commitment = MerkleCap<E, [u8; 32]>>,
{
    for pair in &p.sumcheck.polynomial_evaluations {
        write_fields(w, pair)?;
    }
    for eval in &p.evals {
        write_fields(w, eval.current())?;
        write_fields(w, eval.next())?;
    }
    for round in &p.rounds {
        write_cap(w, &round.commitment)?;
        for row in &round.opened_values {
            write_fields(w, row)?;
        }
        write_round(w, &round.multi_proof)?;
    }
    for row in &p.base_opened_values {
        write_fields(w, row)?;
    }
    write_base(w, &p.base_multi_proof)?;
    write_fields(w, p.final_codeword.as_slice())?;
    write_field(w, p.pow_witness)
}
fn read_pcs<F: RecursiveBinaryTowerField, E: RecursiveBinaryChallengeField>(
    r: &mut Reader<'_>,
    s: &PcsDecode,
    total: &mut usize,
) -> Result<PcsProof<F, E>, ArtifactError> {
    read_pcs_with::<F, E, NativeMmcs<F>, NativeMmcs<E>, _>(
        r,
        s,
        total,
        read_frontier,
        read_frontier,
    )
}
pub(super) fn read_pcs_with<F, E, M, MX, O>(
    r: &mut Reader<'_>,
    s: &PcsDecode<O>,
    total: &mut usize,
    read_base: fn(&mut Reader<'_>, &O, &mut usize) -> Result<M::MultiProof, ArtifactError>,
    read_round: fn(&mut Reader<'_>, &O, &mut usize) -> Result<MX::MultiProof, ArtifactError>,
) -> Result<BinaryPcsProof<F, E, M, MX>, ArtifactError>
where
    F: RecursiveBinaryTowerField,
    E: RecursiveBinaryChallengeField,
    M: Mmcs<F, Commitment = MerkleCap<F, [u8; 32]>>,
    MX: Mmcs<E, Commitment = MerkleCap<E, [u8; 32]>>,
    O: OracleRows,
{
    let sumcheck = SumcheckData {
        polynomial_evaluations: r.read_exact_items(
            "binary PCS rounds",
            s.sumcheck_rounds,
            E::RAW_BITS / 4,
            read_array,
        )?,
        pow_witnesses: r.read_exact_items(
            "binary PCS empty sumcheck PoW",
            0,
            0,
            read_field::<F>,
        )?,
    };
    let mut index = 0;
    let evals = r.read_exact_items(
        "binary PCS evaluation batches",
        s.eval_widths.len(),
        0,
        |r| {
            let (current, next) = s.eval_widths[index];
            index += 1;
            Ok(OpeningBatch::new(
                read_fields(r, current)?,
                read_fields(r, next)?,
            ))
        },
    )?;
    let mut index = 0;
    let rounds = r.read_exact_items("binary PCS intermediate rounds", s.rounds.len(), 0, |r| {
        let oracle = &s.rounds[index];
        index += 1;
        Ok(RoundProof {
            commitment: read_cap(r, s.cap_roots)?,
            opened_values: r.read_exact_items(
                "binary PCS intermediate rows",
                oracle.rows(),
                E::RAW_BITS / 8,
                |r| read_fields(r, 1),
            )?,
            multi_proof: read_round(r, oracle, total)?,
        })
    })?;
    let base_opened_values = r.read_exact_items(
        "binary PCS base rows",
        s.base.rows(),
        F::RAW_BITS / 8,
        |r| read_fields(r, 1),
    )?;
    let base_multi_proof = read_base(r, &s.base, total)?;
    let final_codeword = Poly::new(read_fields(r, s.final_codeword)?);
    let pow_witness = read_field(r)?;
    Ok(BinaryPcsProof {
        sumcheck,
        evals,
        rounds,
        base_opened_values,
        base_multi_proof,
        final_codeword,
        pow_witness,
    })
}
