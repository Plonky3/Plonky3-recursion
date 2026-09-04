//! Verifier-side configuration for the WHIR-backed univariate PCS.

use p3_challenger::{FieldChallenger, GrindingChallenger};
use p3_circuit::ops::{PermConfig, Poseidon2Config};
use p3_field::{ExtensionField, TwoAdicField};
use p3_sumcheck::strategy::VariableOrder;
use p3_whir::parameters::{ProtocolParameters, WhirConfig};

use crate::pcs::whir::params::WhirVerifierParams;

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
