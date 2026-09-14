//! Circuit-target mirror of a WHIR-backed univariate opening proof.
//!
//! Allocation follows the observed-vs-advice split the WHIR targets already
//! use: everything the Fiat–Shamir transcript absorbs — commitment caps, OOD
//! answers, sumcheck round polynomials, PoW witnesses, the final polynomial and
//! the bound multilinear opening values — is a public input, while STIR query
//! leaf rows are private and their Merkle siblings arrive through the
//! non-primitive-op channel.

use alloc::string::ToString;
use alloc::vec::Vec;
use core::marker::PhantomData;

use p3_circuit::CircuitBuilder;
use p3_commit::Mmcs;
use p3_field::{BasedVectorSpace, ExtensionField, Field};
use p3_merkle_tree::MerkleCap;
use p3_whir::pcs::proof::QueryOpenings;

use crate::Target;
use crate::input_contract::whir::{
    CheckedWhirOpening, ValidatedWhirContext, WhirContextParams, WhirResourceProof, WhirUniShape,
    capture_whir_uni_shape, check_whir_resource_limits, validate_whir_pcs_context_iter,
    validate_whir_uni_input,
};
use crate::input_contract::{FriOpeningLayout, MerkleCapShape};
use crate::pcs::fri::CheckedFriCommitment;
use crate::pcs::mmcs::convert_merkle_proof_to_siblings;
use crate::pcs::whir::targets::{QueryOpeningTargets, SumcheckDataTargets, WhirProofTargets};
use crate::pcs::whir::uni::WhirUniVerifierParams;
use crate::pcs::whir::uni::pcs::WhirUniProof;
use crate::pcs::whir::uni::recursive_pcs::DummyChallenger;
use crate::traits::{CheckedRecursive, PreparedRecursive, Recursive};
use crate::verifier::{InputResourceUsage, VerifierLimits};

/// Number of extension targets one Merkle digest occupies in-circuit.
///
/// Mirrors [`convert_merkle_proof_to_siblings`]: when the extension degree
/// divides the digest length the base elements pack into full extension
/// elements, otherwise each base element occupies its own extension limb.
pub const fn packed_digest_len(digest_elems: usize, ext_degree: usize) -> usize {
    if ext_degree > 1 && digest_elems.is_multiple_of(ext_degree) {
        digest_elems / ext_degree
    } else {
        digest_elems
    }
}

/// One commitment round's targets.
pub struct WhirRoundTargets {
    /// Multilinear opening values the WHIR argument binds, `[batch][column]`.
    pub evals: Vec<Vec<Target>>,
    /// The WHIR proximity transcript for this commitment.
    pub whir: WhirProofTargets,
}

/// Circuit-target mirror of [`WhirUniProof`].
///
/// # Shape
///
/// Every allocation size here is read from the **prover-supplied proof**, not
/// from [`WhirVerifierParams`](super::super::params::WhirVerifierParams):
/// `input.rounds.len()`, each `cap.num_roots()`, `ood_answers.len()`,
/// `sumcheck.pow_witnesses.len()`, `evals[*].current().len()`,
/// `final_poly.num_evals()`, whether `commitment` / `final_poly` /
/// `final_sumcheck` are `Some`, and which [`QueryOpenings`] variant
/// (`Base`/`Extension`) is present on each round. That mirrors how the FRI
/// targets allocate from `FriProof`'s own shape, but it means a proof whose
/// self-reported shape is internally consistent yet wrong (e.g. a shorter
/// `pow_witnesses` than `pow_bits > 0` requires, an OOD-answer count that
/// disagrees with the round's committed `ood_samples`, or a query opening in
/// the wrong `Base`/`Extension` variant for its round) allocates a
/// self-consistent but incorrect circuit. The verifier built on these targets
/// (`verify_whir_uni_circuit`) is responsible for independently cross-checking
/// every one of these against the trusted `WhirVerifierParams` before trusting
/// the allocated shape — this type only guarantees that its own allocation and
/// value extraction agree with *each other*, not that either agrees with the
/// protocol parameters.
pub struct WhirUniProofTargets<F, EF, MT, const DIGEST_ELEMS: usize> {
    /// One entry per commitment, in commit order.
    pub rounds: Vec<WhirRoundTargets>,
    _marker: PhantomData<(F, EF, MT)>,
}

/// Allocates a sumcheck block matching a native one.
fn alloc_sumcheck<F: Field, EF: Field>(
    circuit: &mut CircuitBuilder<EF>,
    native: &p3_sumcheck::SumcheckData<F, EF>,
    label: &'static str,
) -> SumcheckDataTargets {
    SumcheckDataTargets {
        round_polys: (0..native.num_rounds())
            .map(|_| circuit.alloc_public_input_array(label))
            .collect(),
        pow_witnesses: circuit.alloc_public_inputs(native.pow_witnesses.len(), label),
    }
}

/// Allocates the leaf rows of one round's query openings.
fn alloc_query_openings<F, EF, P>(
    circuit: &mut CircuitBuilder<EF>,
    openings: &QueryOpenings<F, EF, P>,
) -> Vec<QueryOpeningTargets>
where
    EF: Field,
{
    match openings {
        QueryOpenings::Base(opening) => opening
            .rows
            .iter()
            .map(|row| QueryOpeningTargets::alloc_base(circuit, row.len()))
            .collect(),
        QueryOpenings::Extension(opening) => opening
            .rows
            .iter()
            .map(|row| QueryOpeningTargets::alloc_extension(circuit, row.len()))
            .collect(),
    }
}

impl<F, EF, MT, const DIGEST_ELEMS: usize> Recursive<EF>
    for WhirUniProofTargets<F, EF, MT, DIGEST_ELEMS>
where
    F: Field,
    EF: ExtensionField<F> + BasedVectorSpace<F>,
    MT: Mmcs<F, Commitment = MerkleCap<F, [F; DIGEST_ELEMS]>>,
{
    type Input = WhirUniProof<F, EF, MT>;

    fn new(circuit: &mut CircuitBuilder<EF>, input: &Self::Input) -> Self {
        #[cfg(test)]
        crate::pcs::whir::uni::acceptance_probe::target_new();
        let dimension = <EF as BasedVectorSpace<F>>::DIMENSION;
        // `verify_whir_circuit`'s round-cap absorption (`observe_ext_slice`)
        // unpacks each cap-entry target into `dimension` base coefficients and
        // observes each — correct only when a cap entry holds full digests
        // packed into extension elements (`dimension == 1`, where
        // `observe_ext` degenerates to `observe`, or `dimension` evenly
        // dividing `DIGEST_ELEMS`). Outside that, `packed_digest_len` falls
        // back to one lifted base element per target, and `observe_ext_slice`
        // would absorb `dimension - 1` spurious zeros per digest element.
        debug_assert!(
            dimension == 1 || DIGEST_ELEMS.is_multiple_of(dimension),
            "WHIR cap absorption assumes packed digests: EF::DIMENSION ({dimension}) must be \
             1 or evenly divide DIGEST_ELEMS ({DIGEST_ELEMS})"
        );
        let cap_entry_len = packed_digest_len(DIGEST_ELEMS, dimension);
        let rounds = input
            .rounds
            .iter()
            .map(|round| {
                let evals = round
                    .evals
                    .iter()
                    .map(|batch| {
                        assert!(
                            batch.next().is_empty(),
                            "WHIR uni openings use no next group"
                        );
                        circuit.alloc_public_inputs(batch.current().len(), "WHIR opening evals")
                    })
                    .collect();

                let whir_native = &round.whir;
                let initial_ood_answers = circuit
                    .alloc_public_inputs(whir_native.initial_ood_answers.len(), "WHIR initial OOD");
                let initial_sumcheck = alloc_sumcheck(
                    circuit,
                    &whir_native.initial_sumcheck,
                    "WHIR initial sumcheck",
                );
                let rounds_targets = whir_native
                    .rounds
                    .iter()
                    .map(|r| {
                        let cap = r
                            .commitment
                            .as_ref()
                            .expect("intermediate round commitment");
                        let commitment_cap = (0..cap.num_roots())
                            .map(|_| {
                                circuit.alloc_public_inputs(cap_entry_len, "WHIR round cap entry")
                            })
                            .collect();
                        let ood_answers =
                            circuit.alloc_public_inputs(r.ood_answers.len(), "WHIR round OOD");
                        let pow_witness = circuit.alloc_public_input("WHIR round PoW witness");
                        let queries = alloc_query_openings(circuit, &r.openings);
                        let sumcheck = alloc_sumcheck(circuit, &r.sumcheck, "WHIR round sumcheck");
                        crate::pcs::whir::targets::WhirRoundProofTargets {
                            commitment_cap,
                            ood_answers,
                            pow_witness,
                            queries,
                            sumcheck,
                        }
                    })
                    .collect();

                let final_poly_native = whir_native.final_poly.as_ref().expect("final polynomial");
                let final_poly = circuit
                    .alloc_public_inputs(final_poly_native.num_evals(), "WHIR final polynomial");
                let final_pow_witness = circuit.alloc_public_input("WHIR final PoW witness");
                let final_queries = alloc_query_openings(circuit, &whir_native.final_openings);
                let final_sumcheck = whir_native
                    .final_sumcheck
                    .as_ref()
                    .map(|sc| alloc_sumcheck(circuit, sc, "WHIR final sumcheck"));

                WhirRoundTargets {
                    evals,
                    whir: WhirProofTargets {
                        initial_ood_answers,
                        initial_sumcheck,
                        rounds: rounds_targets,
                        final_poly,
                        final_pow_witness,
                        final_queries,
                        final_sumcheck,
                    },
                }
            })
            .collect();

        Self {
            rounds,
            _marker: PhantomData,
        }
    }

    fn get_values(input: &Self::Input) -> Vec<EF> {
        #[cfg(test)]
        crate::pcs::whir::uni::acceptance_probe::get_values();
        let mut out = Vec::new();
        for round in &input.rounds {
            for batch in &round.evals {
                out.extend(batch.current().iter().copied());
            }
            let whir = &round.whir;
            out.extend(whir.initial_ood_answers.iter().copied());
            out.extend(SumcheckDataTargets::get_values(&whir.initial_sumcheck));
            for r in &whir.rounds {
                let cap = r
                    .commitment
                    .as_ref()
                    .expect("intermediate round commitment");
                for digest in cap.roots() {
                    out.extend(
                        convert_merkle_proof_to_siblings::<F, EF, DIGEST_ELEMS>(
                            core::slice::from_ref(digest),
                        )
                        .into_iter()
                        .next()
                        .expect("one digest yields one sibling entry"),
                    );
                }
                out.extend(r.ood_answers.iter().copied());
                out.push(r.pow_witness.into());
                out.extend(SumcheckDataTargets::get_values(&r.sumcheck));
            }
            out.extend(
                whir.final_poly
                    .as_ref()
                    .expect("final polynomial")
                    .as_slice()
                    .iter()
                    .copied(),
            );
            out.push(whir.final_pow_witness.into());
            if let Some(sc) = whir.final_sumcheck.as_ref() {
                out.extend(SumcheckDataTargets::get_values(sc));
            }
        }
        out
    }

    fn get_private_values(input: &Self::Input) -> Vec<EF> {
        #[cfg(test)]
        crate::pcs::whir::uni::acceptance_probe::get_private_values();
        let mut out = Vec::new();
        let push =
            |openings: &QueryOpenings<F, EF, MT::MultiProof>, out: &mut Vec<EF>| match openings {
                QueryOpenings::Base(opening) => {
                    for row in &opening.rows {
                        out.extend(row.iter().map(|&v| EF::from(v)));
                    }
                }
                QueryOpenings::Extension(opening) => {
                    for row in &opening.rows {
                        out.extend(row.iter().copied());
                    }
                }
            };
        for round in &input.rounds {
            for r in &round.whir.rounds {
                push(&r.openings, &mut out);
            }
            push(&round.whir.final_openings, &mut out);
        }
        out
    }
}

impl<F, EF, MT, const DIGEST_ELEMS: usize> PreparedRecursive<EF>
    for WhirUniProofTargets<F, EF, MT, DIGEST_ELEMS>
where
    F: Field,
    EF: ExtensionField<F> + BasedVectorSpace<F>,
    MT: Mmcs<F, Commitment = MerkleCap<F, [F; DIGEST_ELEMS]>>,
{
    type Shape = WhirUniShape<MerkleCapShape>;

    fn input_shape(input: &Self::Input) -> Result<Self::Shape, crate::VerificationError> {
        capture_whir_uni_shape::<F, EF, MT, DIGEST_ELEMS>(input)
    }
}

impl<F, EF, MT, const DIGEST_ELEMS: usize> CheckedRecursive<EF>
    for WhirUniProofTargets<F, EF, MT, DIGEST_ELEMS>
where
    F: Field,
    EF: ExtensionField<F> + BasedVectorSpace<F>,
    MT: Mmcs<F, Commitment = MerkleCap<F, [F; DIGEST_ELEMS]>>,
{
    fn validate_input(input: &Self::Input) -> Result<(), crate::VerificationError> {
        validate_whir_uni_input::<F, EF, MT, DIGEST_ELEMS>(input)
    }
}

fn checked_tree_height(log_height: usize) -> Result<usize, crate::VerificationError> {
    1usize
        .checked_shl(u32::try_from(log_height).map_err(|_| {
            crate::VerificationError::InvalidProofShape(
                "WHIR Merkle tree exponent does not fit in u32".into(),
            )
        })?)
        .ok_or_else(|| {
            crate::VerificationError::InvalidProofShape(
                "WHIR Merkle tree height overflows usize".into(),
            )
        })
}

fn consumed_tree_log(
    domain_size: usize,
    folding_factor: usize,
) -> Result<usize, crate::VerificationError> {
    let height = domain_size
        .checked_shr(u32::try_from(folding_factor).map_err(|_| {
            crate::VerificationError::InvalidProofShape(
                "WHIR folding factor does not fit in u32".into(),
            )
        })?)
        .ok_or_else(|| {
            crate::VerificationError::InvalidProofShape(
                "WHIR folding factor exceeds the domain word width".into(),
            )
        })?;
    if height == 0 || !height.is_power_of_two() {
        return Err(crate::VerificationError::InvalidProofShape(
            "WHIR queried Merkle tree height must be a positive power of two".into(),
        ));
    }
    Ok(height.trailing_zeros() as usize)
}

impl<F, EF, MT, C, const DIGEST_ELEMS: usize> CheckedWhirOpening<F, EF, C>
    for WhirUniProofTargets<F, EF, MT, DIGEST_ELEMS>
where
    F: p3_field::PrimeField64 + p3_field::TwoAdicField,
    EF: ExtensionField<F> + BasedVectorSpace<F> + p3_field::TwoAdicField,
    MT: Mmcs<F, Commitment = MerkleCap<F, [F; DIGEST_ELEMS]>>,
    MT::MultiProof: WhirResourceProof,
    C: CheckedFriCommitment<EF, Input = MerkleCap<F, [F; DIGEST_ELEMS]>>,
{
    fn check_whir_resources(
        input: &Self::Input,
        limits: &VerifierLimits,
    ) -> Result<InputResourceUsage, crate::VerificationError> {
        check_whir_resource_limits::<F, EF, MT, DIGEST_ELEMS>(input, limits)
    }

    fn validate_whir_context(
        input: &Self::Input,
        params: &WhirUniVerifierParams<F>,
        layout: FriOpeningLayout<'_>,
        caps: &[&C::Input],
    ) -> Result<ValidatedWhirContext<F>, crate::VerificationError> {
        <Self as CheckedRecursive<EF>>::validate_input(input)?;
        if input.rounds.len() != layout.commitment_count()
            || caps.len() != layout.commitment_count()
        {
            return Err(crate::VerificationError::InvalidProofShape(
                "WHIR proof, cap, and statement commitment counts disagree".into(),
            ));
        }

        let permutation = params.permutation_config();
        if permutation.is_arity4_shape() {
            return Err(crate::VerificationError::InvalidProofShape(
                "recursive WHIR supports only binary Merkle commitments".into(),
            ));
        }
        let mut canonical = Vec::with_capacity(input.rounds.len());
        let mut retained_verifier_params = Vec::with_capacity(input.rounds.len());
        let mut outside_cap_roots = Vec::with_capacity(input.rounds.len());
        for (ordinal, (round, cap)) in input.rounds.iter().zip(caps).enumerate() {
            let matrices = layout
                .matrices(ordinal)
                .map(|matrix| (matrix.log_height(), matrix.width(), matrix.point_count()));
            let stacked_num_variables = crate::pcs::whir::uni::plan::checked_stacked_num_variables(
                matrices.clone().map(|(log_height, width, _)| {
                    (
                        crate::pcs::whir::uni::plan::padded_arity(log_height, params.folding()),
                        width,
                    )
                }),
            )
            .map_err(|error| crate::VerificationError::InvalidProofShape(error.to_string()))?;
            let verifier_params = params
                .round_params::<EF, DummyChallenger<F>>(stacked_num_variables)
                .map_err(|error| crate::VerificationError::InvalidProofShape(error.to_string()))?;
            let context = WhirContextParams::from_recursive(&verifier_params);
            validate_whir_pcs_context_iter::<F, EF, MT, _>(round, &context, matrices)?;

            let outside_log = context.rounds.first().map_or_else(
                || consumed_tree_log(context.final_domain_size, context.final_folding_factor),
                |first| consumed_tree_log(first.domain_size, first.folding_factor),
            )?;
            let outside_height = checked_tree_height(outside_log)?;
            outside_cap_roots.push(C::validate_fri_cap(
                cap,
                permutation,
                outside_log,
                core::iter::once(outside_height),
            )?);

            for (step, next) in round.whir.rounds.iter().zip(0..) {
                let commitment = step.commitment.as_ref().ok_or_else(|| {
                    crate::VerificationError::InvalidProofShape(
                        "WHIR intermediate commitment is missing".into(),
                    )
                })?;
                let tree_log = context.rounds.get(next + 1).map_or_else(
                    || consumed_tree_log(context.final_domain_size, context.final_folding_factor),
                    |round| consumed_tree_log(round.domain_size, round.folding_factor),
                )?;
                let tree_height = checked_tree_height(tree_log)?;
                crate::pcs::fri::validate_merkle_cap_context::<F, EF, DIGEST_ELEMS, _>(
                    commitment,
                    permutation,
                    tree_log,
                    core::iter::once(tree_height),
                )?;
            }
            canonical.push(context);
            retained_verifier_params.push(verifier_params);
        }
        let shape = capture_whir_uni_shape::<F, EF, MT, DIGEST_ELEMS>(input)?;
        Ok(ValidatedWhirContext {
            layout: layout.to_owned_layout(),
            permutation,
            canonical,
            verifier_params: retained_verifier_params,
            outside_cap_roots,
            shape,
            _field: PhantomData,
        })
    }

    fn validate_whir_replacement(
        input: &Self::Input,
        expected: &ValidatedWhirContext<F>,
        layout: FriOpeningLayout<'_>,
        caps: &[&C::Input],
    ) -> Result<(), crate::VerificationError> {
        <Self as CheckedRecursive<EF>>::validate_input(input)?;
        if !layout.matches_layout(expected.layout()) {
            return Err(crate::VerificationError::InvalidProofShape(
                "WHIR replacement statement layout changed".into(),
            ));
        }
        if input.rounds.len() != expected.canonical().len()
            || caps.len() != expected.canonical().len()
        {
            return Err(crate::VerificationError::InvalidProofShape(
                "WHIR replacement commitment count changed".into(),
            ));
        }
        let mut outside_cap_roots = Vec::with_capacity(input.rounds.len());
        for (ordinal, ((round, cap), context)) in input
            .rounds
            .iter()
            .zip(caps)
            .zip(expected.canonical())
            .enumerate()
        {
            let matrices = layout
                .matrices(ordinal)
                .map(|matrix| (matrix.log_height(), matrix.width(), matrix.point_count()));
            validate_whir_pcs_context_iter::<F, EF, MT, _>(round, context, matrices)?;
            let outside_log = context.rounds.first().map_or_else(
                || consumed_tree_log(context.final_domain_size, context.final_folding_factor),
                |first| consumed_tree_log(first.domain_size, first.folding_factor),
            )?;
            outside_cap_roots.push(C::validate_fri_cap(
                cap,
                expected.permutation(),
                outside_log,
                core::iter::once(checked_tree_height(outside_log)?),
            )?);
            for (step, next) in round.whir.rounds.iter().zip(0..) {
                let commitment = step.commitment.as_ref().ok_or_else(|| {
                    crate::VerificationError::InvalidProofShape(
                        "WHIR intermediate commitment is missing".into(),
                    )
                })?;
                let tree_log = context.rounds.get(next + 1).map_or_else(
                    || consumed_tree_log(context.final_domain_size, context.final_folding_factor),
                    |round| consumed_tree_log(round.domain_size, round.folding_factor),
                )?;
                crate::pcs::fri::validate_merkle_cap_context::<F, EF, DIGEST_ELEMS, _>(
                    commitment,
                    expected.permutation(),
                    tree_log,
                    core::iter::once(checked_tree_height(tree_log)?),
                )?;
            }
        }
        if outside_cap_roots != expected.outside_cap_roots
            || capture_whir_uni_shape::<F, EF, MT, DIGEST_ELEMS>(input)? != expected.shape
        {
            return Err(crate::VerificationError::InvalidProofShape(
                "WHIR replacement allocation or cap authority changed".into(),
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use alloc::vec;

    use p3_circuit::CircuitBuilder;
    use p3_field::PrimeCharacteristicRing;

    use super::{WhirUniProofTargets, packed_digest_len};
    use crate::Recursive;

    /// Digest packing follows `convert_merkle_proof_to_siblings`: pack when the
    /// extension degree divides the digest, one limb per base element otherwise.
    #[test]
    fn packed_digest_len_follows_the_sibling_encoding() {
        assert_eq!(packed_digest_len(8, 4), 2);
        assert_eq!(packed_digest_len(8, 1), 8);
        assert_eq!(packed_digest_len(8, 5), 8);
    }

    /// Allocation and value extraction must agree: the number of public inputs
    /// allocated equals the number of public values produced, and likewise for
    /// private inputs. A drift here silently misaligns the whole witness.
    #[test]
    fn allocation_and_values_agree_in_length() {
        use p3_baby_bear::BabyBear;
        use p3_field::extension::BinomialExtensionField;

        use crate::pcs::whir::uni::pcs::tests::{MyMmcs, open_two_matrices};

        type F = BabyBear;
        type EF = BinomialExtensionField<F, 4>;

        let (_pcs, _commit, _coms, proof) = open_two_matrices();

        let ((public_allocated, private_allocated, public_values, private_values), counters) =
            crate::pcs::whir::uni::acceptance_probe::measure(|| {
                let mut builder = CircuitBuilder::<EF>::new();
                let before_public = builder.public_input_count();
                let before_private = builder.private_input_count();
                let _targets = <WhirUniProofTargets<F, EF, MyMmcs, 8> as Recursive<EF>>::new(
                    &mut builder,
                    &proof,
                );
                let public_allocated = builder.public_input_count() - before_public;
                let private_allocated = builder.private_input_count() - before_private;

                let public_values =
                    <WhirUniProofTargets<F, EF, MyMmcs, 8> as Recursive<EF>>::get_values(&proof);
                let private_values =
                    <WhirUniProofTargets<F, EF, MyMmcs, 8> as Recursive<EF>>::get_private_values(
                        &proof,
                    );
                (
                    public_allocated,
                    private_allocated,
                    public_values,
                    private_values,
                )
            });

        assert_eq!(public_allocated, public_values.len());
        assert_eq!(private_allocated, private_values.len());
        assert!(!public_values.is_empty());
        assert!(!private_values.is_empty());
        assert_eq!(counters.target_new, 1);
        assert_eq!(counters.get_values, 1);
        assert_eq!(counters.get_private_values, 1);
        let _ = vec![EF::ZERO];
    }
}
