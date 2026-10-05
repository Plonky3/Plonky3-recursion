//! Trusted binary product-tree GKR reductions.
use p3_circuit::ops::{binary_encoding::PrimeBinaryEncoding, binary_host::BinaryCircuitHost};

use alloc::vec;
use alloc::vec::Vec;
use core::hash::Hash;
use core::marker::PhantomData;

use p3_binary_field::{BinaryField128, TowerLevel};
use p3_bus::{
    ProductGkrLayerProof, ProductGkrOutput, ProductGkrProof, ProductGkrRootShape, ProductGkrShape,
};
use p3_challenger::FieldChallenger;
use p3_circuit::ops::{BinaryTower128Target, NativeTower128Target};
use p3_circuit::{CircuitBuilder, ExprId};
use p3_field::{ExtensionField, Field, PrimeField64};

use super::binary_field_policy::{BinaryProtocolPolicy, NativeTower128Relation, TowerRelation};
use super::{InputResourceUsage, VerificationError, VerifierLimits};
use crate::BinaryTower128Challenger;
use crate::pcs::binary::{
    Binary128SumcheckInterpolator, RecursiveBinaryChallengeField, RecursiveBinaryTowerField,
    observe_seed_with_host,
};
use crate::transcript::SeedTap;
pub(crate) mod kernel;
use kernel::{ProductLayerView, verify_layers};

/// One shape-derived layer, with tree-major child evaluations.
#[derive(Clone, Debug)]
pub struct BinaryProductGkrLayerTargets<T = BinaryTower128Target> {
    pub round_polys: Vec<Vec<T>>,
    pub children: Vec<Vec<T>>,
}

#[derive(Clone, Debug)]
pub struct BinaryProductGkrProofTargets<T = BinaryTower128Target> {
    pub roots: Vec<T>,
    pub layers: Vec<BinaryProductGkrLayerTargets<T>>,
}

/// Internally consistent product claims awaiting authentication by the caller's
/// committed-polynomial or AIR relation. This is not a verified statement.
#[must_use = "product leaf evaluations must be authenticated by the surrounding protocol"]
#[derive(Clone, Debug)]
pub struct BinaryProductGkrOutput<T = BinaryTower128Target> {
    pub roots: Vec<T>,
    /// Most-significant-variable-first multilinear point.
    pub point: Vec<T>,
    pub values: Vec<T>,
    pub challenger: BinaryTower128Challenger,
}

/// The complete verifier-owned product schedule and native field encodings.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BinaryProductGkrInputShape<F = BinaryField128, E = BinaryField128> {
    seed: Vec<F>,
    native: ProductGkrShape,
    layers: Vec<(usize, usize)>,
    challenge: PhantomData<E>,
}

impl<F: RecursiveBinaryTowerField, E: RecursiveBinaryChallengeField>
    BinaryProductGkrInputShape<F, E>
{
    pub(crate) fn native_decode_shape(
        &self,
    ) -> crate::artifact::binary_native::codec::ProductDecode {
        crate::artifact::binary_native::codec::ProductDecode {
            roots: self.root_count(),
            trees: self.native.num_trees(),
            layers: self.layers.clone(),
        }
    }

    fn root_count(&self) -> usize {
        self.native.num_trees()
            - usize::from(self.native.root_shape() == ProductGkrRootShape::FirstTwoShared)
    }

    pub fn allocate_targets<BF, EF>(
        &self,
        b: &mut CircuitBuilder<EF>,
    ) -> Result<BinaryProductGkrProofTargets, VerificationError>
    where
        BF: PrimeField64,
        EF: ExtensionField<BF> + Eq + Hash,
    {
        self.allocate_with(|| {
            let limbs = b.alloc_private_input_array::<8>("binary product GKR field");
            Ok(b.binary128_from_limbs::<BF>(limbs)?)
        })
    }

    fn allocate_with<T>(
        &self,
        mut field: impl FnMut() -> Result<T, VerificationError>,
    ) -> Result<BinaryProductGkrProofTargets<T>, VerificationError> {
        let roots = (0..self.root_count())
            .map(|_| field())
            .collect::<Result<_, VerificationError>>()?;
        let layers = self
            .layers
            .iter()
            .map(|&(arity, rounds)| {
                let round_polys = (0..rounds)
                    .map(|_| (0..5).map(|_| field()).collect())
                    .collect::<Result<_, VerificationError>>()?;
                let children = (0..self.native.num_trees())
                    .map(|_| (0..arity).map(|_| field()).collect())
                    .collect::<Result<_, VerificationError>>()?;
                Ok(BinaryProductGkrLayerTargets {
                    round_polys,
                    children,
                })
            })
            .collect::<Result<_, VerificationError>>()?;
        Ok(BinaryProductGkrProofTargets { roots, layers })
    }
}

/// Bounded witness data carrying no independent leaf-authentication authority.
#[derive(Clone, Debug)]
pub struct NativeBinaryProductGkrInput<F = BinaryField128, E = BinaryField128> {
    shape: BinaryProductGkrInputShape<F, E>,
    fields: Vec<u128>,
}

impl<F: RecursiveBinaryTowerField, E: RecursiveBinaryChallengeField>
    NativeBinaryProductGkrInput<F, E>
{
    pub fn shape(&self) -> &BinaryProductGkrInputShape<F, E> {
        &self.shape
    }

    pub fn private_values<EF: Field>(
        &self,
        expected: &BinaryProductGkrInputShape<F, E>,
    ) -> Result<Vec<EF>, VerificationError> {
        if &self.shape != expected {
            return Err(invalid("binary product input belongs to another verifier"));
        }
        Ok(self
            .fields
            .iter()
            .flat_map(|&value| (0..8).map(move |i| EF::from_u16((value >> (16 * i)) as u16)))
            .collect())
    }
}

/// Released radix-four product GKR over Tower64 or Tower128. Tree geometry and
/// root sharing are fixed independently of the proof. Returned leaf values
/// must be closed by the surrounding authenticated reduction.
#[derive(Clone, Debug)]
pub struct BinaryProductGkrVerifier<F = BinaryField128, E = BinaryField128> {
    input: BinaryProductGkrInputShape<F, E>,
    interpolator: Binary128SumcheckInterpolator,
    usage: InputResourceUsage,
}

impl<F, E> BinaryProductGkrVerifier<F, E>
where
    F: RecursiveBinaryTowerField,
    E: RecursiveBinaryChallengeField + ExtensionField<F>,
{
    pub fn new(
        height: usize,
        trees: usize,
        roots: ProductGkrRootShape,
    ) -> Result<Self, VerificationError> {
        Self::with_limits(height, trees, roots, &VerifierLimits::default())
    }

    pub fn with_limits(
        height: usize,
        trees: usize,
        roots: ProductGkrRootShape,
        limits: &VerifierLimits,
    ) -> Result<Self, VerificationError> {
        Self::with_limits_impl(height, trees, roots, limits, true)
    }

    /// Embedded push/pull trees are derived channels of already-counted AIRs.
    pub(super) fn with_embedded_bus_limits(
        height: usize,
        trees: usize,
        roots: ProductGkrRootShape,
        limits: &VerifierLimits,
    ) -> Result<Self, VerificationError> {
        Self::with_limits_impl(height, trees, roots, limits, false)
    }

    fn with_limits_impl(
        height: usize,
        trees: usize,
        roots: ProductGkrRootShape,
        limits: &VerifierLimits,
        account_instances: bool,
    ) -> Result<Self, VerificationError> {
        let native = ProductGkrShape::new(height, trees, roots)
            .map_err(|_| invalid("binary product geometry is invalid"))?;
        let mut usage = InputResourceUsage::default();
        usage.check_log_degree(limits, height)?;
        if account_instances {
            usage.add_instances(limits, trees)?;
        }
        usage.add_metadata_entries(limits, trees)?;
        let mut layers = Vec::new();
        let mut remaining = height;
        let mut point_len = 0;
        let mut fields = trees - usize::from(roots == ProductGkrRootShape::FirstTwoShared);
        while remaining > 0 {
            let arity: usize = if remaining == height && remaining % 2 == 1 {
                2
            } else {
                4
            };
            usage.add_rounds(limits, point_len)?;
            usage.add_metadata_entries(limits, 2)?;
            let count = point_len
                .checked_mul(5)
                .and_then(|n| {
                    trees
                        .checked_mul(arity)
                        .and_then(|children| n.checked_add(children))
                })
                .ok_or(VerificationError::ResourceArithmeticOverflow {
                    component: "binary product messages",
                })?;
            fields = InputResourceUsage::checked_add("binary product fields", fields, count)?;
            layers.push((arity, point_len));
            let branches = arity.trailing_zeros() as usize;
            point_len += branches;
            remaining -= branches;
        }
        usage.add_scalar_elements(
            limits,
            fields
                .checked_mul(8)
                .ok_or(VerificationError::ResourceArithmeticOverflow {
                    component: "binary product input limbs",
                })?,
        )?;
        let interpolator = Binary128SumcheckInterpolator::with_limits(5, limits)?;
        usage.add_metadata_entries(limits, 36)?;
        // The native shape's seed is private. A bounded, internally consistent
        // zero reduction captures it through the public verifier, including
        // the height-zero case, without allocating a tree's leaf table.
        let dummy = zero_proof::<E>(
            trees - usize::from(roots == ProductGkrRootShape::FirstTwoShared),
            trees,
            &layers,
        );
        let mut tap = SeedTap::<F>::new();
        let _ = dummy
            .verify::<F, _>(native, &mut tap)
            .map_err(|_| invalid("binary product seed capture failed"))?;
        let seed = tap.binary_seed();
        usage.add_metadata_entries(limits, seed.len())?;
        Ok(Self {
            input: BinaryProductGkrInputShape {
                seed,
                native,
                layers,
                challenge: PhantomData,
            },
            interpolator,
            usage,
        })
    }

    pub fn input_shape(&self) -> BinaryProductGkrInputShape<F, E> {
        self.input.clone()
    }
    pub fn input_resource_usage(&self) -> InputResourceUsage {
        self.usage
    }

    pub(super) fn zero_native_proof(&self) -> ProductGkrProof<E> {
        zero_proof(
            self.input.root_count(),
            self.input.native.num_trees(),
            &self.input.layers,
        )
    }

    /// Checks every message shape before adding constraints. Targets must
    /// belong to this builder. This establishes internal product consistency
    /// and returns the exact native transcript and unauthenticated leaves.
    pub fn verify_reduction<BF, EF>(
        &self,
        b: &mut CircuitBuilder<EF>,
        ch: BinaryTower128Challenger,
        proof: &BinaryProductGkrProofTargets,
    ) -> Result<BinaryProductGkrOutput, VerificationError>
    where
        BF: PrimeField64,
        EF: ExtensionField<BF> + Eq + Hash,
    {
        self.verify_using::<TowerRelation<F, E>, PrimeBinaryEncoding<BF>, EF>(b, ch, proof)
    }

    pub(super) fn verify_using<P, H, EF>(
        &self,
        b: &mut CircuitBuilder<EF>,
        mut ch: BinaryTower128Challenger,
        proof: &BinaryProductGkrProofTargets<P::ChallengeTarget>,
    ) -> Result<BinaryProductGkrOutput<P::ChallengeTarget>, VerificationError>
    where
        EF: Field + Eq + Hash,
        H: BinaryCircuitHost<EF>,
        P: BinaryProtocolPolicy<EF, Base = F, Challenge = E>,
    {
        self.check_targets(proof)?;
        for value in proof.roots.iter().chain(
            proof
                .layers
                .iter()
                .flat_map(|layer| layer.round_polys.iter().chain(&layer.children).flatten()),
        ) {
            P::constrain_challenge(b, value);
        }
        observe_seed_with_host::<F, H, EF>(b, &mut ch, &self.input.seed)?;
        let layers = proof
            .layers
            .iter()
            .map(|layer| ProductLayerView {
                messages: &layer.round_polys,
                children: &layer.children,
            })
            .collect::<Vec<_>>();
        let output = verify_layers::<P, H, EF>(
            b,
            ch,
            &proof.roots,
            self.input.native.root_shape(),
            &self.input.layers,
            &layers,
            |b, claim, polynomial, challenge| {
                self.interpolator
                    .reduce_claim_using::<P, EF>(b, claim, polynomial, challenge)
            },
        )?;
        Ok(BinaryProductGkrOutput {
            roots: output.roots,
            point: output.point,
            values: output.values,
            challenger: output.challenger,
        })
    }

    pub(crate) fn check_targets<T>(
        &self,
        proof: &BinaryProductGkrProofTargets<T>,
    ) -> Result<(), VerificationError> {
        if proof.roots.len() != self.input.root_count()
            || proof.layers.len() != self.input.layers.len()
        {
            return Err(invalid("binary product target shape mismatch"));
        }
        for (&(arity, rounds), layer) in self.input.layers.iter().zip(&proof.layers) {
            if layer.round_polys.len() != rounds
                || layer.round_polys.iter().any(|p| p.len() != 5)
                || layer.children.len() != self.input.native.num_trees()
                || layer.children.iter().any(|c| c.len() != arity)
            {
                return Err(invalid("binary product target layer mismatch"));
            }
        }
        Ok(())
    }

    pub(crate) fn check_native(&self, proof: &ProductGkrProof<E>) -> Result<(), VerificationError> {
        if proof.roots.len() != self.input.root_count()
            || proof.layers.len() != self.input.layers.len()
        {
            return Err(invalid("binary product native shape mismatch"));
        }
        for (&(arity, rounds), layer) in self.input.layers.iter().zip(&proof.layers) {
            let valid = match layer {
                ProductGkrLayerProof::Binary { children } => {
                    arity == 2 && rounds == 0 && children.len() == self.input.native.num_trees()
                }
                ProductGkrLayerProof::RadixFour {
                    round_polys,
                    children,
                } => {
                    arity == 4
                        && round_polys.len() == rounds
                        && children.len() == self.input.native.num_trees()
                }
            };
            if !valid {
                return Err(invalid("binary product native layer mismatch"));
            }
        }
        Ok(())
    }

    /// Replays only a bounded, internally consistent native reduction. On any
    /// failure the caller's challenger is unchanged. Leaf values still require
    /// authentication by the surrounding protocol.
    pub fn import_native<Ch>(
        &self,
        proof: &ProductGkrProof<E>,
        ch: &mut Ch,
    ) -> Result<NativeBinaryProductGkrInput<F, E>, VerificationError>
    where
        Ch: FieldChallenger<F> + Clone,
    {
        self.import_native_with_reduction(proof, ch)
            .map(|(input, _)| input)
    }

    pub(crate) fn import_native_with_reduction<Ch>(
        &self,
        proof: &ProductGkrProof<E>,
        ch: &mut Ch,
    ) -> Result<(NativeBinaryProductGkrInput<F, E>, ProductGkrOutput<E>), VerificationError>
    where
        Ch: FieldChallenger<F> + Clone,
    {
        self.check_native(proof)?;
        let mut staged = ch.clone();
        let output = proof
            .verify::<F, _>(self.input.native, &mut staged)
            .map_err(|_| invalid("binary product native replay failed"))?;
        let mut fields: Vec<_> = proof
            .roots
            .iter()
            .copied()
            .map(E::raw_coordinates)
            .collect();
        for layer in &proof.layers {
            match layer {
                ProductGkrLayerProof::Binary { children } => {
                    fields.extend(children.iter().flatten().copied().map(E::raw_coordinates))
                }
                ProductGkrLayerProof::RadixFour {
                    round_polys,
                    children,
                } => {
                    fields.extend(
                        round_polys
                            .iter()
                            .flatten()
                            .copied()
                            .map(E::raw_coordinates),
                    );
                    fields.extend(children.iter().flatten().copied().map(E::raw_coordinates));
                }
            }
        }
        *ch = staged;
        Ok((
            NativeBinaryProductGkrInput {
                shape: self.input.clone(),
                fields,
            },
            output,
        ))
    }
}

pub(super) fn sample<E, BF, EF>(
    b: &mut CircuitBuilder<EF>,
    ch: &mut BinaryTower128Challenger,
) -> Result<BinaryTower128Target, VerificationError>
where
    E: RecursiveBinaryChallengeField,
    BF: PrimeField64,
    EF: ExtensionField<BF> + Eq + Hash,
{
    sample_with_host::<E, PrimeBinaryEncoding<BF>, EF>(b, ch)
}

pub(super) fn sample_with_host<E, H, EF>(
    b: &mut CircuitBuilder<EF>,
    ch: &mut BinaryTower128Challenger,
) -> Result<BinaryTower128Target, VerificationError>
where
    E: RecursiveBinaryChallengeField,
    H: BinaryCircuitHost<EF>,
    EF: Field + Eq + Hash,
{
    let bytes = ch.sample_bytes_with_host::<H, EF>(b, E::RAW_BITS / 8)?;
    let mut bits = [ExprId::ZERO; 128];
    for (i, byte) in bytes.into_iter().enumerate() {
        let byte = H::decompose_word(b, byte, 8)?;
        bits[8 * i..8 * i + 8].copy_from_slice(&byte);
    }
    Ok(b.binary128_from_bits(bits)?)
}

fn invalid(message: &str) -> VerificationError {
    VerificationError::InvalidProofShape(message.into())
}

pub(super) fn zero_proof<E: Field>(
    roots: usize,
    trees: usize,
    layers: &[(usize, usize)],
) -> ProductGkrProof<E> {
    ProductGkrProof {
        roots: vec![E::ZERO; roots],
        layers: layers
            .iter()
            .map(|&(arity, rounds)| {
                if arity == 2 {
                    ProductGkrLayerProof::Binary {
                        children: vec![[E::ZERO; 2]; trees],
                    }
                } else {
                    ProductGkrLayerProof::RadixFour {
                        round_polys: vec![[E::ZERO; 5]; rounds],
                        children: vec![[E::ZERO; 4]; trees],
                    }
                }
            })
            .collect(),
    }
}

impl<F: RecursiveBinaryTowerField> BinaryProductGkrInputShape<F, BinaryField128>
where
    BinaryField128: ExtensionField<F>,
{
    /// Allocates one native carrier cell per field in the frozen proof schedule.
    pub fn allocate_native_targets(
        &self,
        b: &mut CircuitBuilder<BinaryField128>,
    ) -> Result<BinaryProductGkrProofTargets<NativeTower128Target>, VerificationError> {
        self.allocate_with(|| {
            let value = b.alloc_private_input("native product GKR field");
            Ok(b.native_tower128_from_expr(value))
        })
    }
}
impl<F: RecursiveBinaryTowerField> NativeBinaryProductGkrInput<F, BinaryField128>
where
    BinaryField128: ExtensionField<F>,
{
    /// Raw native scalars, in the same order as `allocate_native_targets`.
    pub fn private_native_values(
        &self,
        expected: &BinaryProductGkrInputShape<F, BinaryField128>,
    ) -> Result<Vec<BinaryField128>, VerificationError> {
        if &self.shape != expected {
            return Err(invalid("binary product input belongs to another verifier"));
        }
        Ok(self
            .fields
            .iter()
            .copied()
            .map(BinaryField128::from_repr)
            .collect())
    }
}
impl<F: RecursiveBinaryTowerField> BinaryProductGkrVerifier<F, BinaryField128>
where
    BinaryField128: ExtensionField<F>,
{
    /// A scalar reduction requiring the caller to authenticate all returned leaves.
    pub fn verify_reduction_native(
        &self,
        b: &mut CircuitBuilder<BinaryField128>,
        ch: BinaryTower128Challenger,
        proof: &BinaryProductGkrProofTargets<NativeTower128Target>,
    ) -> Result<BinaryProductGkrOutput<NativeTower128Target>, VerificationError> {
        self.verify_using::<NativeTower128Relation<F>, p3_circuit::ops::binary_encoding::NativeBinaryEncoding, BinaryField128>(b,ch,proof)
    }
}
