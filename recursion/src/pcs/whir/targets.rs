//! Circuit-target mirrors of WHIR proof types.
//!
//! Each type allocates circuit inputs following the observed-vs-advice split:
//!
//! - **Public inputs** (`alloc_public_input*`): values that enter the Fiat–Shamir
//!   transcript (commitments, OOD answers, sumcheck round polys, PoW witnesses, final poly).
//! - **Private inputs** (`alloc_private_inputs`): leaf values that are authenticated
//!   by the MMCS gadget but never directly absorbed by the challenger.
//! - **Non-primitive ops** (returned by MMCS verify calls): Merkle sibling digests
//!   supplied by the runner's non-primitive op mechanism.

use alloc::vec::Vec;

use p3_circuit::CircuitBuilder;
use p3_field::{ExtensionField, Field};

use crate::Target;
pub use crate::pcs::whir::gadgets::ConstraintWeightData;

// ─── SumcheckData ───────────────────────────────────────────────────────────

/// In-circuit mirror of `p3_sumcheck::SumcheckData<F, EF>`.
///
/// Stores the compact `[h(0), h(inf)]` representation per round plus an optional
/// per-round PoW witness (present when `pow_bits > 0`).
pub struct SumcheckDataTargets {
    /// Sent round polynomial evaluations: `round_polys[i] = [h_i(0), h_i(inf)]`.
    pub round_polys: Vec<[Target; 2]>,
    /// Per-round proof-of-work witnesses (`pow_witnesses[i]` for round `i`).
    /// Empty when `pow_bits == 0`.
    pub pow_witnesses: Vec<Target>,
}

impl SumcheckDataTargets {
    /// Allocate targets for a `SumcheckData` with `num_rounds` rounds.
    ///
    /// Both `round_polys` and `pow_witnesses` are public inputs: they are observed
    /// into the challenger transcript and so must be committed on-chain.
    pub fn alloc<EF: Field>(
        circuit: &mut CircuitBuilder<EF>,
        num_rounds: usize,
        pow_bits: usize,
        label: &'static str,
    ) -> Self {
        let round_polys = (0..num_rounds)
            .map(|_| circuit.alloc_public_input_array(label))
            .collect();
        let pow_witnesses = if pow_bits > 0 {
            circuit.alloc_public_inputs(num_rounds, label)
        } else {
            Vec::new()
        };
        Self {
            round_polys,
            pow_witnesses,
        }
    }

    /// Populate public-input values from a native `SumcheckData`.
    pub fn get_values<F: Field, EF: ExtensionField<F>>(
        data: &p3_sumcheck::SumcheckData<F, EF>,
    ) -> Vec<EF> {
        let mut vals: Vec<EF> = Vec::new();
        for &[c0, cinf] in data.polynomial_evaluations() {
            vals.push(c0);
            vals.push(cinf);
        }
        for &w in &data.pow_witnesses {
            vals.push(w.into());
        }
        vals
    }
}

// ─── QueryOpening ────────────────────────────────────────────────────────────

/// In-circuit mirror of `p3_whir::pcs::proof::QueryOpening<F, EF, Proof>`.
///
/// The leaf values are the `2^folding_factor` opened values at one STIR query
/// position.  The Merkle sibling digests are supplied as MMCS non-primitive-op
/// private data (not stored here).
pub enum QueryOpeningTargets {
    /// Base-field leaf (round 0, committed with a plain `MerkleTreeMmcs<F, …>`).
    Base {
        /// `2^folding_factor` base-field values (embedded in EF), allocated as private inputs.
        leaf_values: Vec<Target>,
    },
    /// Extension-field leaf (rounds ≥ 1, committed with `ExtensionMmcs<F, EF, …>`).
    Extension {
        /// `2^folding_factor` extension-field values, each a single EF-element Target.
        leaf_values: Vec<Target>,
    },
}

impl QueryOpeningTargets {
    /// Allocate a base-field query opening with `leaf_len = 2^folding_factor` elements.
    pub fn alloc_base<EF: Field>(circuit: &mut CircuitBuilder<EF>, leaf_len: usize) -> Self {
        Self::Base {
            leaf_values: circuit.alloc_private_inputs(leaf_len, "WHIR base query leaf"),
        }
    }

    /// Allocate an extension-field query opening with `leaf_len = 2^folding_factor` elements.
    pub fn alloc_extension<EF: Field>(circuit: &mut CircuitBuilder<EF>, leaf_len: usize) -> Self {
        Self::Extension {
            leaf_values: circuit.alloc_private_inputs(leaf_len, "WHIR extension query leaf"),
        }
    }

    /// Return the leaf `Target` slice regardless of base vs extension variant.
    pub fn leaf_values(&self) -> &[Target] {
        match self {
            Self::Base { leaf_values } | Self::Extension { leaf_values } => leaf_values,
        }
    }

    /// Private-input values for a `Base` opening from native proof data.
    pub fn private_values_base<F: Field, EF: ExtensionField<F>>(values: &[F]) -> Vec<EF> {
        values.iter().map(|&v| v.into()).collect()
    }

    /// Private-input values for an `Extension` opening from native proof data.
    pub fn private_values_extension<EF: Copy>(values: &[EF]) -> Vec<EF> {
        values.to_vec()
    }
}

// ─── WhirRoundProof ──────────────────────────────────────────────────────────

/// In-circuit mirror of `WhirRoundProof<F, EF, MT>`.
pub struct WhirRoundProofTargets {
    /// Merkle cap targets for the round commitment (public inputs, observed into challenger).
    ///
    /// `commitment_cap[i]` is one hash-output digest of `cap_entry_len` EF-element Targets.
    pub commitment_cap: Vec<Vec<Target>>,
    /// OOD evaluation answers for this round (public inputs, observed into challenger).
    pub ood_answers: Vec<Target>,
    /// PoW witness after the commitment (public input).
    pub pow_witness: Target,
    /// STIR query openings.
    pub queries: Vec<QueryOpeningTargets>,
    /// Sumcheck data for this round's folding sumcheck.
    pub sumcheck: SumcheckDataTargets,
}

impl WhirRoundProofTargets {
    /// Allocate targets for one WHIR intermediate round.
    ///
    /// `cap_entry_len` is the number of EF-element Targets per Merkle cap entry
    /// (= the hash output size; equals `permutation_config.rate_ext()` for the
    /// Poseidon2 hasher).  Pass `1` for arithmetic-only test circuits where MMCS
    /// verification is skipped.
    #[allow(clippy::too_many_arguments)] // TODO: refactor
    pub fn alloc<EF: Field>(
        circuit: &mut CircuitBuilder<EF>,
        ood_samples: usize,
        num_queries: usize,
        folding_factor: usize,
        folding_pow_bits: usize,
        cap_entries: usize,
        cap_entry_len: usize,
        is_base_round: bool,
    ) -> Self {
        let commitment_cap = (0..cap_entries)
            .map(|_| circuit.alloc_public_inputs(cap_entry_len, "WHIR round commitment cap entry"))
            .collect();
        let ood_answers = circuit.alloc_public_inputs(ood_samples, "WHIR round OOD answers");
        let pow_witness = circuit.alloc_public_input("WHIR round PoW witness");
        let leaf_len = 1usize << folding_factor;
        let queries = if is_base_round {
            (0..num_queries)
                .map(|_| QueryOpeningTargets::alloc_base(circuit, leaf_len))
                .collect()
        } else {
            (0..num_queries)
                .map(|_| QueryOpeningTargets::alloc_extension(circuit, leaf_len))
                .collect()
        };
        let sumcheck = SumcheckDataTargets::alloc(
            circuit,
            folding_factor,
            folding_pow_bits,
            "WHIR round sumcheck",
        );
        Self {
            commitment_cap,
            ood_answers,
            pow_witness,
            queries,
            sumcheck,
        }
    }
}

// ─── WhirProof ───────────────────────────────────────────────────────────────

/// In-circuit mirror of `WhirProof<F, EF, MT>`.
pub struct WhirProofTargets {
    /// Initial OOD evaluation answers (public inputs).
    pub initial_ood_answers: Vec<Target>,
    /// Initial folding sumcheck data.
    pub initial_sumcheck: SumcheckDataTargets,
    /// Per-intermediate-round proof data.
    pub rounds: Vec<WhirRoundProofTargets>,
    /// Final polynomial evaluations over the hypercube (public inputs).
    pub final_poly: Vec<Target>,
    /// Final round PoW witness (public input).
    pub final_pow_witness: Target,
    /// Final round STIR query openings.
    pub final_queries: Vec<QueryOpeningTargets>,
    /// Optional final sumcheck (present when `final_sumcheck_rounds > 0`).
    pub final_sumcheck: Option<SumcheckDataTargets>,
}

impl WhirProofTargets {
    /// Allocate all targets for a WHIR proof, driven by the verifier params.
    ///
    /// - `cap_entries`: number of Merkle roots in each commitment cap (typically 1).
    /// - `cap_entry_len`: number of EF-element Targets per cap entry
    ///   (= `permutation_config.rate_ext()`; pass `1` for arithmetic-only tests).
    pub fn alloc<F: Field, EF: ExtensionField<F>>(
        circuit: &mut CircuitBuilder<EF>,
        params: &super::params::WhirVerifierParams<F>,
        cap_entries: usize,
        cap_entry_len: usize,
    ) -> Self {
        let initial_ood_answers =
            circuit.alloc_public_inputs(params.commitment_ood_samples, "WHIR initial OOD answers");

        let initial_folding_factor = if params.n_rounds() > 0 {
            params.round_params[0].folding_factor
        } else {
            params.final_sumcheck_rounds
        };
        let initial_sumcheck = SumcheckDataTargets::alloc(
            circuit,
            initial_folding_factor,
            params.starting_folding_pow_bits,
            "WHIR initial sumcheck",
        );

        let rounds = params
            .round_params
            .iter()
            .enumerate()
            .map(|(i, rp)| {
                WhirRoundProofTargets::alloc(
                    circuit,
                    rp.ood_samples,
                    rp.num_queries,
                    rp.folding_factor,
                    rp.folding_pow_bits,
                    cap_entries,
                    cap_entry_len,
                    i == 0,
                )
            })
            .collect();

        let final_poly_len = 1usize << params.final_poly_num_variables;
        let final_poly =
            circuit.alloc_public_inputs(final_poly_len, "WHIR final polynomial evaluations");
        let final_pow_witness = circuit.alloc_public_input("WHIR final PoW witness");

        let final_leaf_len = if params.n_rounds() > 0 {
            1usize << params.round_params.last().unwrap().folding_factor
        } else {
            1usize << initial_folding_factor
        };
        let final_queries = (0..params.final_queries)
            .map(|_| {
                if params.n_rounds() == 0 {
                    QueryOpeningTargets::alloc_base(circuit, final_leaf_len)
                } else {
                    QueryOpeningTargets::alloc_extension(circuit, final_leaf_len)
                }
            })
            .collect();

        let final_sumcheck = if params.final_sumcheck_rounds > 0 {
            Some(SumcheckDataTargets::alloc(
                circuit,
                params.final_sumcheck_rounds,
                params.final_folding_pow_bits,
                "WHIR final sumcheck",
            ))
        } else {
            None
        };

        Self {
            initial_ood_answers,
            initial_sumcheck,
            rounds,
            final_poly,
            final_pow_witness,
            final_queries,
            final_sumcheck,
        }
    }
}

// ─── Opening-proof wrapper ───────────────────────────────────────────────────

/// In-circuit mirror of `PcsProof<F, EF, MT>`: the full WHIR PCS opening proof.
pub struct WhirPcsProofTargets {
    /// The WHIR proximity transcript.
    pub whir: WhirProofTargets,
    /// Opening evaluation values indexed `[batch][column]` (public inputs).
    pub evals: Vec<Vec<Target>>,
}

impl WhirPcsProofTargets {
    /// Allocate targets for the full PCS proof.
    ///
    /// `cap_entry_len`: number of EF-element Targets per Merkle cap entry.
    pub fn alloc<F: Field, EF: ExtensionField<F>>(
        circuit: &mut CircuitBuilder<EF>,
        params: &super::params::WhirVerifierParams<F>,
        cap_entries: usize,
        cap_entry_len: usize,
        batch_evals: &[usize],
    ) -> Self {
        let whir = WhirProofTargets::alloc(circuit, params, cap_entries, cap_entry_len);
        let evals = batch_evals
            .iter()
            .map(|&n| circuit.alloc_public_inputs(n, "WHIR opening evals"))
            .collect();
        Self { whir, evals }
    }
}
