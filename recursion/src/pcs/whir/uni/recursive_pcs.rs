//! Verifier-side configuration for the WHIR-backed univariate PCS.

use alloc::vec::Vec;

use p3_challenger::{FieldChallenger, GrindingChallenger};
use p3_circuit::ops::{PermConfig, Poseidon2Config};
use p3_circuit::symbolic::RowSelectorsTargets;
use p3_circuit::{CircuitBuilder, CircuitBuilderError, NonPrimitiveOpId};
use p3_commit::{Mmcs, PolynomialSpace};
use p3_dft::TwoAdicSubgroupDft;
use p3_field::coset::TwoAdicMultiplicativeCoset;
use p3_field::{ExtensionField, Field, PrimeCharacteristicRing, PrimeField64, TwoAdicField};
use p3_merkle_tree::MerkleCap;
use p3_sumcheck::layout::Layout;
use p3_sumcheck::strategy::VariableOrder;
use p3_uni_stark::{StarkGenericConfig, Val};
use p3_whir::parameters::{ProtocolParameters, WhirConfig};

use crate::Target;
use crate::challenger::CircuitChallenger;
use crate::challenger_perm::ChallengerPermConfig;
use crate::pcs::whir::params::WhirVerifierParams;
use crate::pcs::whir::uni::circuit::verify_whir_uni_circuit;
use crate::pcs::whir::uni::pcs::WhirUniPcs;
use crate::pcs::whir::uni::targets::WhirUniProofTargets;
use crate::traits::{ComsWithOpeningsTargets, Recursive, RecursivePcs};
use crate::types::{OpenedValuesTargetsWithLookups, RecursiveLagrangeSelectors};
use crate::verifier::{ObservableCommitment, VerificationError};

/// WHIR parameters shared by every commitment a proof carries.
///
/// A commitment's WHIR configuration depends on the arity of the stacked
/// polynomial it covers, which varies per commitment, so the per-round
/// [`WhirVerifierParams`] are derived on demand rather than stored.
#[derive(Clone, Debug)]
pub struct WhirUniVerifierParams<F> {
    /// Protocol parameters used for every commitment.
    pub protocol_params: ProtocolParameters,
    /// First-round folding factor, read from `protocol_params`.
    pub folding: usize,
    /// Folding variable order declared by the prover's layout.
    pub variable_order: VariableOrder,
    /// Poseidon2 configuration for in-circuit MMCS path verification.
    ///
    /// `None` skips MMCS verification, which is **unsound** and exists only for
    /// tests that isolate the WHIR arithmetic.
    pub permutation_config: Option<PermConfig>,
    _marker: core::marker::PhantomData<F>,
}

impl<F: TwoAdicField> WhirUniVerifierParams<F> {
    /// Builds the shared parameters.
    ///
    /// `permutation_config: None` skips MMCS verification for every
    /// commitment this configuration derives params for — **unsound for
    /// production use**, since a prover could then open WHIR commitments to
    /// arbitrary values without detection. Pass `None` only for tests that
    /// isolate the WHIR arithmetic path; production callers must pass
    /// `Some(_)`.
    ///
    /// # Panics
    /// Panics unless the folding factor is
    /// [`p3_whir::parameters::FoldingFactor::Constant`].
    pub fn new(
        protocol_params: ProtocolParameters,
        variable_order: VariableOrder,
        permutation_config: Option<PermConfig>,
    ) -> Self {
        let p3_whir::parameters::FoldingFactor::Constant(folding) = protocol_params.folding_factor
        else {
            panic!("WhirUniVerifierParams requires FoldingFactor::Constant");
        };
        Self {
            protocol_params,
            folding,
            variable_order,
            permutation_config,
            _marker: core::marker::PhantomData,
        }
    }

    /// WHIR verifier parameters for a commitment whose stacked polynomial has
    /// the given arity.
    ///
    /// # Panics
    /// Panics if the protocol parameters are invalid for that arity.
    pub fn round_params<EF, Ch>(&self, stacked_num_variables: usize) -> WhirVerifierParams<F>
    where
        EF: ExtensionField<F> + TwoAdicField,
        Ch: FieldChallenger<F> + GrindingChallenger<Witness = F>,
    {
        let config =
            WhirConfig::<EF, F, Ch>::new(stacked_num_variables, self.protocol_params.clone())
                .expect("WHIR parameters are valid for the committed arity");
        #[allow(clippy::option_if_let_else)]
        match self.permutation_config {
            Some(perm) => WhirVerifierParams::from_config(&config, self.variable_order, perm),
            None => WhirVerifierParams::unsafe_arithmetic_only_for_tests(
                &config,
                self.variable_order,
                Poseidon2Config::BABY_BEAR_D4_W16,
            ),
        }
    }
}

/// Zero-sized stand-in for `WhirConfig`'s challenger type parameter, which the
/// verifier-side configuration never uses.
#[derive(Clone, Debug, Default)]
pub struct DummyChallenger<F>(core::marker::PhantomData<F>);

impl<F: p3_field::Field> p3_challenger::CanObserve<F> for DummyChallenger<F> {
    fn observe(&mut self, _value: F) {
        unreachable!("DummyChallenger only satisfies WhirConfig's phantom bound")
    }
}
impl<F: p3_field::Field> p3_challenger::CanSample<F> for DummyChallenger<F> {
    fn sample(&mut self) -> F {
        unreachable!("DummyChallenger only satisfies WhirConfig's phantom bound")
    }
}
impl<F: p3_field::Field> p3_challenger::CanSampleBits<usize> for DummyChallenger<F> {
    fn sample_bits(&mut self, _bits: usize) -> usize {
        unreachable!("DummyChallenger only satisfies WhirConfig's phantom bound")
    }
}
impl<F: p3_field::Field> p3_challenger::GrindingChallenger for DummyChallenger<F> {
    type Witness = F;
    fn grind(&mut self, _bits: usize) -> Self::Witness {
        unreachable!("DummyChallenger only satisfies WhirConfig's phantom bound")
    }
}
impl<F: p3_field::PrimeField64> p3_challenger::FieldChallenger<F> for DummyChallenger<F> {}

/// WHIR carries no per-query input-proof object, so the trait's `InputProof`
/// slot is filled by the unit type.
impl<F: p3_field::Field> Recursive<F> for () {
    type Input = ();

    fn new(_circuit: &mut CircuitBuilder<F>, _input: &Self::Input) -> Self {}

    fn get_values(_input: &Self::Input) -> Vec<F> {
        Vec::new()
    }
}

/// No WHIR variant in this adapter splits off random codewords.
const NO_RANDOM_OPENED_VALUES: &[Vec<Vec<Vec<Target>>>] = &[];

impl<SC, Dft, MT, Comm, L, const DIGEST_ELEMS: usize>
    RecursivePcs<
        SC,
        (),
        WhirUniProofTargets<Val<SC>, SC::Challenge, MT, DIGEST_ELEMS>,
        Comm,
        TwoAdicMultiplicativeCoset<Val<SC>>,
    > for WhirUniPcs<SC::Challenge, Val<SC>, Dft, MT, SC::Challenger, L>
where
    SC: StarkGenericConfig,
    Val<SC>: TwoAdicField + PrimeField64 + Ord,
    SC::Challenge: TwoAdicField + ExtensionField<Val<SC>>,
    Dft: TwoAdicSubgroupDft<Val<SC>> + Clone,
    MT: Mmcs<Val<SC>, Commitment = MerkleCap<Val<SC>, [Val<SC>; DIGEST_ELEMS]>> + Clone,
    Comm: Recursive<SC::Challenge> + ObservableCommitment,
    L: Layout<Val<SC>, SC::Challenge>,
{
    type VerifierParams = WhirUniVerifierParams<Val<SC>>;
    type RecursiveProof = WhirUniProofTargets<Val<SC>, SC::Challenge, MT, DIGEST_ELEMS>;

    /// WHIR's native `verify_at` interleaves per-commitment OOD sampling with its
    /// own opened-value observation (see `verify_whir_uni_circuit`/`build_round_claims`),
    /// so the generic caller must not pre-observe opened values on WHIR's behalf.
    const PRE_OBSERVES_OPENED_VALUES: bool = false;

    /// WHIR interleaves every challenge with a proof observation, so all of them
    /// are sampled inside [`Self::verify_circuit`]; nothing is produced here. This
    /// is correct precisely because [`Self::PRE_OBSERVES_OPENED_VALUES`] is `false`:
    /// the generic caller has not touched the transcript with opened values before
    /// this is called, so there is nothing to compensate for here.
    fn get_challenges_circuit<const WIDTH: usize, const RATE: usize, C: ChallengerPermConfig>(
        _circuit: &mut CircuitBuilder<SC::Challenge>,
        _challenger: &mut CircuitChallenger<WIDTH, RATE, C>,
        _proof_targets: &Self::RecursiveProof,
        _opened_values: &OpenedValuesTargetsWithLookups<SC>,
        _params: &Self::VerifierParams,
    ) -> Result<Vec<Target>, CircuitBuilderError> {
        Ok(Vec::new())
    }

    fn verify_circuit<const WIDTH: usize, const RATE: usize, C: ChallengerPermConfig>(
        &self,
        circuit: &mut CircuitBuilder<SC::Challenge>,
        _challenges: &[Target],
        challenger: &mut CircuitChallenger<WIDTH, RATE, C>,
        commitments_with_opening_points: &ComsWithOpeningsTargets<
            Comm,
            TwoAdicMultiplicativeCoset<Val<SC>>,
        >,
        opening_proof: &Self::RecursiveProof,
        params: &Self::VerifierParams,
    ) -> Result<Vec<NonPrimitiveOpId>, VerificationError> {
        verify_whir_uni_circuit::<Val<SC>, SC::Challenge, _, Comm>(
            circuit,
            challenger,
            params,
            commitments_with_opening_points,
            &opening_proof.rounds,
        )
    }

    /// Lagrange selectors and the vanishing inverse for a two-adic coset.
    ///
    /// With `u = point / shift` and `Z(u) = u^n - 1` over a domain of `n`
    /// points generated by `g`:
    /// `is_first_row = Z(u)/(u - 1)`, `is_last_row = Z(u)/(u - g^-1)`,
    /// `is_transition = u - g^-1`, `inv_vanishing = 1/Z(u)`.
    fn selectors_at_point_circuit(
        &self,
        circuit: &mut CircuitBuilder<SC::Challenge>,
        domain: &TwoAdicMultiplicativeCoset<Val<SC>>,
        point: &Target,
    ) -> RecursiveLagrangeSelectors {
        let shift_inv = circuit.alloc_const(
            SC::Challenge::from(domain.shift_inverse()),
            "whir shift_inv",
        );
        let one = circuit.alloc_const(SC::Challenge::from(Val::<SC>::ONE), "whir one");
        let subgroup_gen_inv = circuit.alloc_const(
            SC::Challenge::from(domain.subgroup_generator().inverse()),
            "whir subgroup_gen_inv",
        );

        let unshifted_point = circuit.alloc_mul(shift_inv, *point, "whir unshifted_point");
        let us_exp = circuit.exp_power_of_2(unshifted_point, domain.log_size());
        let z_h = circuit.alloc_sub(us_exp, one, "whir z_h");

        let us_minus_one = circuit.alloc_sub(unshifted_point, one, "whir us_minus_one");
        let us_minus_gen_inv =
            circuit.alloc_sub(unshifted_point, subgroup_gen_inv, "whir us_minus_gen_inv");

        RecursiveLagrangeSelectors {
            row_selectors: RowSelectorsTargets {
                is_first_row: circuit.alloc_div(z_h, us_minus_one, "whir is_first_row"),
                is_last_row: circuit.alloc_div(z_h, us_minus_gen_inv, "whir is_last_row"),
                is_transition: us_minus_gen_inv,
            },
            inv_vanishing: circuit.alloc_div(one, z_h, "whir inv_vanishing"),
        }
    }

    fn evaluate_periodic_columns_at_point_circuit(
        &self,
        circuit: &mut CircuitBuilder<SC::Challenge>,
        domain: &TwoAdicMultiplicativeCoset<Val<SC>>,
        periodic_columns: &[Vec<Val<SC>>],
        point: Target,
    ) -> Result<Vec<Target>, VerificationError> {
        crate::verifier::evaluate_periodic_columns_circuit(circuit, domain, periodic_columns, point)
    }

    fn create_disjoint_domain(
        &self,
        trace_domain: TwoAdicMultiplicativeCoset<Val<SC>>,
        degree: usize,
    ) -> TwoAdicMultiplicativeCoset<Val<SC>> {
        trace_domain.create_disjoint_domain(degree)
    }

    fn split_domains(
        &self,
        trace_domain: &TwoAdicMultiplicativeCoset<Val<SC>>,
        degree: usize,
    ) -> Vec<TwoAdicMultiplicativeCoset<Val<SC>>> {
        trace_domain.split_domains(degree)
    }

    fn log_size(&self, trace_domain: &TwoAdicMultiplicativeCoset<Val<SC>>) -> usize {
        trace_domain.log_size()
    }

    fn first_point(&self, trace_domain: &TwoAdicMultiplicativeCoset<Val<SC>>) -> SC::Challenge {
        SC::Challenge::from(trace_domain.first_point())
    }

    fn get_fri_random_opened_values(_proof: &Self::RecursiveProof) -> &[Vec<Vec<Vec<Target>>>] {
        NO_RANDOM_OPENED_VALUES
    }
}
