//! Circuit-target mirror of a WHIR-backed univariate opening proof.
//!
//! Allocation follows the observed-vs-advice split the WHIR targets already
//! use: everything the Fiat–Shamir transcript absorbs — commitment caps, OOD
//! answers, sumcheck round polynomials, PoW witnesses, the final polynomial and
//! the bound multilinear opening values — is a public input, while STIR query
//! leaf rows are private and their Merkle siblings arrive through the
//! non-primitive-op channel.

use alloc::vec::Vec;
use core::marker::PhantomData;

use p3_circuit::CircuitBuilder;
use p3_commit::Mmcs;
use p3_field::{BasedVectorSpace, ExtensionField, Field};
use p3_merkle_tree::MerkleCap;
use p3_whir::pcs::proof::QueryOpenings;

use crate::Target;
use crate::pcs::mmcs::convert_merkle_proof_to_siblings;
use crate::pcs::whir::targets::{QueryOpeningTargets, SumcheckDataTargets, WhirProofTargets};
use crate::pcs::whir::uni::pcs::WhirUniProof;
use crate::traits::Recursive;

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

        let mut builder = CircuitBuilder::<EF>::new();
        let before_public = builder.public_input_count();
        let before_private = builder.private_input_count();
        let _targets =
            <WhirUniProofTargets<F, EF, MyMmcs, 8> as Recursive<EF>>::new(&mut builder, &proof);
        let public_allocated = builder.public_input_count() - before_public;
        let private_allocated = builder.private_input_count() - before_private;

        let public_values =
            <WhirUniProofTargets<F, EF, MyMmcs, 8> as Recursive<EF>>::get_values(&proof);
        let private_values =
            <WhirUniProofTargets<F, EF, MyMmcs, 8> as Recursive<EF>>::get_private_values(&proof);

        assert_eq!(public_allocated, public_values.len());
        assert_eq!(private_allocated, private_values.len());
        assert!(!public_values.is_empty());
        assert!(!private_values.is_empty());
        let _ = (before_public, before_private, vec![EF::ZERO]);
    }
}
