//! Released product-tree GKR with Poly64 seeds and full Poly192 challenges.
use alloc::vec::Vec;
use core::hash::Hash;

use p3_binary_field::{Poly64, Poly192};
use p3_bus::{
    ProductGkrLayerProof, ProductGkrOutput, ProductGkrProof, ProductGkrRootShape, ProductGkrShape,
};
use p3_challenger::FieldChallenger;
use p3_circuit::CircuitBuilder;
use p3_circuit::ops::binary_encoding::{NativeBinaryEncoding, PrimeBinaryEncoding};
use p3_circuit::ops::binary_host::BinaryCircuitHost;
use p3_circuit::ops::{BinaryPoly192Target, NativePoly192Target};
use p3_field::{ExtensionField, Field, PrimeField64};

use super::binary_field_policy::{
    BinaryPolyPolicy, BinaryProtocolPolicy, NativePoly64Relation, Poly64Relation,
    poly_native_values, poly_observe_seed_with_host,
};
use super::binary_product::kernel::{ProductLayerView, verify_layers};
use super::binary_product::zero_proof;
use super::{InputResourceUsage, VerificationError, VerifierLimits};
use crate::BinaryTower128Challenger;
use crate::pcs::binary::Poly192SumcheckInterpolator;
use crate::transcript::SeedTap;

/// One shape-derived layer, with tree-major child evaluations.
#[derive(Clone, Debug)]
pub struct BinaryPolyProductGkrLayerTargets<T = BinaryPoly192Target> {
    pub round_polys: Vec<Vec<T>>,
    pub children: Vec<Vec<T>>,
}

#[derive(Clone, Debug)]
pub struct BinaryPolyProductGkrProofTargets<T = BinaryPoly192Target> {
    pub roots: Vec<T>,
    pub layers: Vec<BinaryPolyProductGkrLayerTargets<T>>,
}

/// Internally consistent product claims awaiting authentication by the caller's
/// committed-polynomial or AIR relation. This is not a verified statement.
#[must_use = "product leaf evaluations must be authenticated by the surrounding protocol"]
#[derive(Clone, Debug)]
pub struct BinaryPolyProductGkrOutput<T = BinaryPoly192Target> {
    pub roots: Vec<T>,
    /// Most-significant-variable-first multilinear point.
    pub point: Vec<T>,
    pub values: Vec<T>,
    pub challenger: BinaryTower128Challenger,
}

/// The complete verifier-owned product schedule and native field encodings.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BinaryPolyProductGkrInputShape {
    seed: Vec<Poly64>,
    native: ProductGkrShape,
    layers: Vec<(usize, usize)>,
}

impl BinaryPolyProductGkrInputShape {
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
    ) -> Result<BinaryPolyProductGkrProofTargets, VerificationError>
    where
        BF: PrimeField64,
        EF: ExtensionField<BF> + Eq + Hash,
    {
        self.allocate_with(|| {
            let limbs = b.alloc_private_input_array::<12>("binary product GKR field");
            Ok(b.binary_poly192_from_limbs::<BF>(limbs)?)
        })
    }

    fn allocate_with<T>(
        &self,
        mut field: impl FnMut() -> Result<T, VerificationError>,
    ) -> Result<BinaryPolyProductGkrProofTargets<T>, VerificationError> {
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
                Ok(BinaryPolyProductGkrLayerTargets {
                    round_polys,
                    children,
                })
            })
            .collect::<Result<_, VerificationError>>()?;
        Ok(BinaryPolyProductGkrProofTargets { roots, layers })
    }
}

/// Bounded witness data carrying no independent leaf-authentication authority.
#[derive(Clone, Debug)]
pub struct NativeBinaryPolyProductGkrInput {
    shape: BinaryPolyProductGkrInputShape,
    limbs: Vec<u16>,
}

impl NativeBinaryPolyProductGkrInput {
    pub const fn shape(&self) -> &BinaryPolyProductGkrInputShape {
        &self.shape
    }

    pub fn private_values<EF: Field>(
        &self,
        expected: &BinaryPolyProductGkrInputShape,
    ) -> Result<Vec<EF>, VerificationError> {
        if &self.shape != expected {
            return Err(invalid("binary product input belongs to another verifier"));
        }
        Ok(self.limbs.iter().copied().map(EF::from_u16).collect())
    }
}

/// Released radix-four product GKR over Poly64 and Poly192. Tree geometry and
/// root sharing are fixed independently of the proof. Returned leaf values
/// must be closed by the surrounding authenticated reduction.
#[derive(Clone, Debug)]
pub struct BinaryPolyProductGkrVerifier {
    input: BinaryPolyProductGkrInputShape,
    interpolator: Poly192SumcheckInterpolator,
    usage: InputResourceUsage,
}

impl BinaryPolyProductGkrVerifier {
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
                .checked_mul(12)
                .ok_or(VerificationError::ResourceArithmeticOverflow {
                    component: "binary product input limbs",
                })?,
        )?;
        let interpolator = Poly192SumcheckInterpolator::with_limits(5, limits)?;
        usage.add_metadata_entries(limits, 36)?;
        // The native shape's seed is private. A bounded, internally consistent
        // zero reduction captures it through the public verifier, including
        // the height-zero case, without allocating a tree's leaf table.
        let dummy = zero_proof::<Poly192>(
            trees - usize::from(roots == ProductGkrRootShape::FirstTwoShared),
            trees,
            &layers,
        );
        let mut tap = SeedTap::<Poly64>::new();
        let _ = dummy
            .verify::<Poly64, _>(native, &mut tap)
            .map_err(|_| invalid("binary product seed capture failed"))?;
        let seed = tap.binary_seed();
        usage.add_metadata_entries(limits, seed.len())?;
        Ok(Self {
            input: BinaryPolyProductGkrInputShape {
                seed,
                native,
                layers,
            },
            interpolator,
            usage,
        })
    }

    pub fn input_shape(&self) -> BinaryPolyProductGkrInputShape {
        self.input.clone()
    }
    pub const fn input_resource_usage(&self) -> InputResourceUsage {
        self.usage
    }

    pub(super) fn zero_native_proof(&self) -> ProductGkrProof<Poly192> {
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
        proof: &BinaryPolyProductGkrProofTargets,
    ) -> Result<BinaryPolyProductGkrOutput, VerificationError>
    where
        BF: PrimeField64,
        EF: ExtensionField<BF> + Eq + Hash,
    {
        self.verify_using::<Poly64Relation, PrimeBinaryEncoding<BF>, EF>(b, ch, proof)
    }

    pub(super) fn verify_using<P, H, CF>(
        &self,
        b: &mut CircuitBuilder<CF>,
        mut ch: BinaryTower128Challenger,
        proof: &BinaryPolyProductGkrProofTargets<P::ChallengeTarget>,
    ) -> Result<BinaryPolyProductGkrOutput<P::ChallengeTarget>, VerificationError>
    where
        CF: Field + Eq + Hash,
        H: BinaryCircuitHost<CF>,
        P: BinaryPolyPolicy<CF> + BinaryProtocolPolicy<CF>,
    {
        self.check_targets(proof)?;
        poly_observe_seed_with_host::<H, CF>(b, &mut ch, &self.input.seed)?;
        let layers = proof
            .layers
            .iter()
            .map(|layer| ProductLayerView {
                messages: &layer.round_polys,
                children: &layer.children,
            })
            .collect::<Vec<_>>();
        let output = verify_layers::<P, H, CF>(
            b,
            ch,
            &proof.roots,
            self.input.native.root_shape(),
            &self.input.layers,
            &layers,
            |b, claim, polynomial, challenge| {
                self.interpolator
                    .reduce_claim_using::<P, CF>(b, claim, polynomial, challenge)
            },
        )?;
        Ok(BinaryPolyProductGkrOutput {
            roots: output.roots,
            point: output.point,
            values: output.values,
            challenger: output.challenger,
        })
    }

    pub(crate) fn check_targets<T>(
        &self,
        proof: &BinaryPolyProductGkrProofTargets<T>,
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

    pub(crate) fn check_native(
        &self,
        proof: &ProductGkrProof<Poly192>,
    ) -> Result<(), VerificationError> {
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
        proof: &ProductGkrProof<Poly192>,
        ch: &mut Ch,
    ) -> Result<NativeBinaryPolyProductGkrInput, VerificationError>
    where
        Ch: FieldChallenger<Poly64> + Clone,
    {
        self.import_native_with_reduction(proof, ch)
            .map(|(input, _)| input)
    }

    pub(crate) fn import_native_with_reduction<Ch>(
        &self,
        proof: &ProductGkrProof<Poly192>,
        ch: &mut Ch,
    ) -> Result<(NativeBinaryPolyProductGkrInput, ProductGkrOutput<Poly192>), VerificationError>
    where
        Ch: FieldChallenger<Poly64> + Clone,
    {
        self.check_native(proof)?;
        let mut staged = ch.clone();
        let output = proof
            .verify::<Poly64, _>(self.input.native, &mut staged)
            .map_err(|_| invalid("binary product native replay failed"))?;
        let mut limbs = Vec::new();
        let mut append = |value: Poly192| {
            for coefficient in value.coefficients() {
                limbs.extend((0..4).map(|i| (coefficient.to_bits() >> (16 * i)) as u16));
            }
        };
        for &root in &proof.roots {
            append(root);
        }
        for layer in &proof.layers {
            match layer {
                ProductGkrLayerProof::Binary { children } => {
                    for &value in children.iter().flatten() {
                        append(value);
                    }
                }
                ProductGkrLayerProof::RadixFour {
                    round_polys,
                    children,
                } => {
                    for &value in round_polys
                        .iter()
                        .flatten()
                        .chain(children.iter().flatten())
                    {
                        append(value);
                    }
                }
            }
        }
        *ch = staged;
        Ok((
            NativeBinaryPolyProductGkrInput {
                shape: self.input.clone(),
                limbs,
            },
            output,
        ))
    }
}

fn invalid(message: &str) -> VerificationError {
    VerificationError::InvalidProofShape(message.into())
}

impl BinaryPolyProductGkrInputShape {
    /// Three native Poly64 coefficient cells per Poly192 message.
    pub fn allocate_native_targets(
        &self,
        b: &mut CircuitBuilder<Poly64>,
    ) -> Result<BinaryPolyProductGkrProofTargets<NativePoly192Target>, VerificationError> {
        self.allocate_with(|| {
            let coefficients = b.alloc_private_input_array::<3>("native Poly product GKR field");
            b.check_construction_limits()?;
            Ok(b.native_poly192_from_coefficients(coefficients))
        })
    }
}
impl NativeBinaryPolyProductGkrInput {
    /// Raw coefficients in the frozen allocator's order.
    pub fn private_native_values(
        &self,
        expected: &BinaryPolyProductGkrInputShape,
    ) -> Result<Vec<Poly64>, VerificationError> {
        if &self.shape != expected {
            return Err(invalid("binary product input belongs to another verifier"));
        }
        // Construction has already bounded every schedule product and sum.
        let fields = self.shape.root_count()
            + self
                .shape
                .layers
                .iter()
                .map(|&(arity, rounds)| 5 * rounds + self.shape.native.num_trees() * arity)
                .sum::<usize>();
        poly_native_values(&self.limbs, fields * 3)
    }
}
impl BinaryPolyProductGkrVerifier {
    /// Native reduction; the surrounding authenticated relation closes its leaves.
    pub fn verify_reduction_native(
        &self,
        b: &mut CircuitBuilder<Poly64>,
        ch: BinaryTower128Challenger,
        proof: &BinaryPolyProductGkrProofTargets<NativePoly192Target>,
    ) -> Result<BinaryPolyProductGkrOutput<NativePoly192Target>, VerificationError> {
        self.verify_using::<NativePoly64Relation, NativeBinaryEncoding, Poly64>(b, ch, proof)
    }
}
