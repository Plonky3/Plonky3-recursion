//! Plain Poly64 AIR and full Poly192 zerocheck reduction.

use super::super::binary_indexed::BinaryOpeningSchedule;
use super::super::binary_poly_bus::{
    BinaryPolyBusClaims, BinaryPolyBusInputShape, BinaryPolyBusVerifier,
};
use super::*;
use crate::pcs::binary::{
    BinaryPolyGenericSumcheckInputShape, BinaryPolyGenericSumcheckVerifier,
    BinaryPolyNonzeroChallengePlan, poly_assert_equal, poly_observe_seed, poly192_eq_eval,
};
use crate::transcript::domain_separator_seed;
use alloc::sync::Arc;
use p3_bus::{BusPlan, BusPlanInput};
use p3_multi_stark::rounds::AirDegrees;
use p3_multi_stark::transcript::{MultiStarkInstanceShape, MultiStarkShape};
use p3_multi_stark::zerocheck::transcript::ZerocheckShape;
use p3_sumcheck::OpeningProtocol;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct PolyMultiStarkRelationShape {
    pub(super) airs: Vec<BinaryPolyAirConstraintPlan>,
    outer_seed: Vec<Poly64>,
    zerocheck_seed: Vec<Poly64>,
    pub(super) sumcheck: BinaryPolyGenericSumcheckInputShape,
    pub(super) bus: Option<BinaryPolyBusInputShape>,
    main_schedule: BinaryOpeningSchedule,
    preprocessed_schedule: Option<BinaryOpeningSchedule>,
    max_tau_draws: usize,
}

#[derive(Clone, Debug)]
pub(super) struct PolyMultiStarkRelation {
    pub(super) input: Arc<PolyMultiStarkRelationShape>,
    sumcheck: BinaryPolyGenericSumcheckVerifier,
    tau: BinaryPolyNonzeroChallengePlan,
    bus: Option<BinaryPolyBusVerifier>,
    pub(super) usage: InputResourceUsage,
}

pub(super) struct Reduction {
    alpha: BinaryPoly192Target,
    beta: BinaryPoly192Target,
    lambda: Option<BinaryPoly192Target>,
    bus_claims: Option<BinaryPolyBusClaims>,
    tau: Vec<BinaryPoly192Target>,
    point: Vec<BinaryPoly192Target>,
    claim: BinaryPoly192Target,
    pub(super) challenger: BinaryTower128Challenger,
    pub(super) main_points: Vec<Vec<BinaryPoly192Target>>,
    pub(super) preprocessed_points: Option<Vec<Vec<BinaryPoly192Target>>>,
}

pub(super) struct NativeReduction {
    pub(super) bus: Option<super::super::NativeBinaryPolyProductGkrInput>,
    pub(super) sumcheck: NativeBinaryPolyGenericSumcheckInput,
    pub(super) main_points: Vec<Point<Poly192>>,
    pub(super) preprocessed_points: Option<Vec<Point<Poly192>>>,
}

impl PolyMultiStarkRelationShape {
    pub(super) fn write_identity(
        &self,
        w: &mut crate::artifact::wire::Writer,
    ) -> Result<(), crate::artifact::ArtifactError> {
        use p3_binary_field::TowerLevel;
        w.write_vec("polynomial native AIRs", &self.airs, |w, air| {
            air.write_identity(w)
        })?;
        for seed in [&self.outer_seed, &self.zerocheck_seed] {
            w.write_vec("polynomial native transcript seed", seed, |w, value| {
                w.write_bytes(&value.to_repr().to_le_bytes())
            })?;
        }
        Ok(())
    }
}

impl PolyMultiStarkRelation {
    pub(super) fn build<A>(
        airs: &[&A],
        heights: &[usize],
        pow_bits: usize,
        max_tau_draws: usize,
        has_preprocessing: bool,
        limits: &VerifierLimits,
    ) -> Result<(Self, OpeningProtocol, Option<OpeningProtocol>), VerificationError>
    where
        A: Air<InteractionSymbolicBuilder<Poly64, Poly192>>
            + Air<BusSymbolicBuilder<Poly64, Poly192>>,
    {
        if airs.is_empty() || airs.len() != heights.len() || heights.contains(&0) {
            return Err(invalid(
                "polynomial MultiStark trusted instance shape mismatch",
            ));
        }
        if let Some(&height) = heights
            .iter()
            .find(|&&height| height >= usize::BITS as usize)
        {
            return Err(VerificationError::ResourceLimitExceeded {
                component: "polynomial MultiStark trace log height",
                actual: height,
                limit: usize::BITS as usize - 1,
            });
        }
        let mut usage = InputResourceUsage::default();
        usage.add_instances(limits, airs.len())?;
        let mut plans = Vec::with_capacity(airs.len());
        let mut declarations = Vec::with_capacity(airs.len());
        for (&air, &height) in airs.iter().zip(heights) {
            let (plan, bus) = BinaryPolyAirConstraintPlan::with_bus_limits(air, height, limits)?;
            declarations.push(bus);
            if plan.preprocessed_width() != 0 && !has_preprocessing {
                return Err(invalid(
                    "polynomial MultiStark preprocessing requires trusted authority",
                ));
            }
            usage.merge(limits, plan.input_resource_usage())?;
            let public_limbs = plan.public_value_count().checked_mul(4).ok_or(
                VerificationError::ResourceArithmeticOverflow {
                    component: "polynomial MultiStark public limbs",
                },
            )?;
            usage.add_scalar_elements(limits, public_limbs)?;
            plans.push(plan);
        }
        let bus_inputs: Vec<_> = declarations
            .iter()
            .zip(heights)
            .map(|(interactions, &log_height)| BusPlanInput {
                log_height,
                interactions,
            })
            .collect();
        let bus = BusPlan::build(&bus_inputs)
            .map_err(|_| invalid("binary Poly MultiStark bus geometry is invalid"))?
            .map(|plan| BinaryPolyBusVerifier::with_limits(plan, &plans, limits))
            .transpose()?;
        if let Some(bus) = &bus {
            usage.merge(limits, bus.input_resource_usage())?;
        }
        let height = *heights.iter().max().unwrap();
        let degree = plans
            .iter()
            .map(BinaryPolyAirConstraintPlan::constraint_degree)
            .max()
            .unwrap()
            .checked_add(1)
            .ok_or(VerificationError::ResourceArithmeticOverflow {
                component: "polynomial MultiStark sumcheck degree",
            })?;
        let degree = degree.max(bus.as_ref().map(|bus| bus.degree()).unwrap_or(0));
        let sumcheck =
            BinaryPolyGenericSumcheckVerifier::with_limits(height, degree, pow_bits, limits)?;
        usage.merge(limits, sumcheck.input_resource_usage())?;
        let tau = BinaryPolyNonzeroChallengePlan::with_limits(height, max_tau_draws, limits)?;
        usage.merge(limits, tau.input_resource_usage())?;
        let geometry = |pp: bool| {
            plans.iter().map(move |air| {
                (
                    air.log_height(),
                    if pp {
                        air.preprocessed_width()
                    } else {
                        air.main_width()
                    },
                    if pp {
                        air.preprocessed_next_columns()
                    } else {
                        air.next_columns()
                    },
                )
            })
        };
        let (tables, main_schedule) = BinaryOpeningSchedule::plain(geometry(false));
        usage.add_metadata_entries(limits, main_schedule.len())?;
        let indices: Vec<_> = plans
            .iter()
            .enumerate()
            .filter_map(|(i, air)| (air.preprocessed_width() != 0).then_some(i))
            .collect();
        usage.add_metadata_entries(limits, indices.len())?;
        if indices.is_empty() && has_preprocessing {
            return Err(invalid(
                "polynomial MultiStark has unused preprocessing authority",
            ));
        }
        let (preprocessed_protocol, preprocessed_schedule) = if has_preprocessing {
            let (tables, schedule) = BinaryOpeningSchedule::plain(geometry(true));
            usage.add_metadata_entries(limits, schedule.len())?;
            (Some(OpeningProtocol::new(tables)), Some(schedule))
        } else {
            (None, None)
        };
        let outer = MultiStarkShape {
            instances: plans
                .iter()
                .map(|air| MultiStarkInstanceShape {
                    num_variables: air.log_height(),
                    main_width: air.main_width(),
                    preprocessed_width: air.preprocessed_width(),
                    num_public_values: air.public_value_count(),
                    main_next_row_columns: air.next_columns().to_vec(),
                    preprocessed_next_row_columns: air.preprocessed_next_columns().to_vec(),
                })
                .collect(),
            pow_bits,
            has_indexed: false,
            has_bus: bus.is_some(),
        };
        let degrees: Vec<_> = plans
            .iter()
            .map(|air| AirDegrees {
                constraints: air.constraint_degree(),
                interactions: 0,
            })
            .collect();
        let mut zerocheck = ZerocheckShape::new(&degrees, height, 0, pow_bits);
        if let Some(bus) = &bus {
            zerocheck = zerocheck.with_bus(bus.degree());
        }
        let input = Arc::new(PolyMultiStarkRelationShape {
            airs: plans,
            outer_seed: domain_separator_seed(&outer.domain_separator::<Poly64>()),
            zerocheck_seed: domain_separator_seed(&zerocheck.domain_separator::<Poly64, Poly192>()),
            sumcheck: sumcheck.input_shape(),
            bus: bus.as_ref().map(|bus| bus.input_shape()),
            main_schedule,
            preprocessed_schedule,
            max_tau_draws,
        });
        Ok((
            Self {
                input,
                sumcheck,
                tau,
                bus,
                usage,
            },
            OpeningProtocol::new(tables),
            preprocessed_protocol,
        ))
    }

    pub(super) fn check_targets<T>(
        &self,
        public: &[Vec<T>],
        proof: &BinaryPolyWhirMultiStarkProofTargets,
    ) -> Result<(), VerificationError> {
        self.check_public(public)?;
        match (&self.bus, &proof.bus) {
            (Some(verifier), Some(proof)) => verifier.check_targets(proof)?,
            (None, None) => {}
            _ => return Err(invalid("binary Poly MultiStark bus target shape mismatch")),
        }
        self.sumcheck.check_targets(&proof.sumcheck)
    }

    pub(super) fn check_public<T>(&self, public: &[Vec<T>]) -> Result<(), VerificationError> {
        if public.len() != self.input.airs.len()
            || public
                .iter()
                .zip(&self.input.airs)
                .any(|(values, air)| values.len() != air.public_value_count())
        {
            return Err(invalid("polynomial MultiStark public value shape mismatch"));
        }
        Ok(())
    }

    pub(super) fn zero_points<T: Clone>(&self, pp: bool, zero: T) -> Vec<Vec<T>> {
        let heights: Vec<_> = self.input.airs.iter().map(|a| a.log_height()).collect();
        let schedule = if pp {
            self.input.preprocessed_schedule.as_ref().unwrap()
        } else {
            &self.input.main_schedule
        };
        schedule.zero_points(&heights, zero)
    }

    pub(super) fn observe_prefix<BF, EF>(
        &self,
        b: &mut CircuitBuilder<EF>,
        ch: &mut BinaryTower128Challenger,
        preprocessed: Option<&[Vec<ExprId>]>,
    ) -> Result<(), VerificationError>
    where
        BF: PrimeField64,
        EF: ExtensionField<BF> + Eq + Hash,
    {
        poly_observe_seed::<BF, EF>(b, ch, &self.input.outer_seed)?;
        if let Some(cap) = preprocessed {
            crate::pcs::binary::observe_cap::<BF, EF>(b, ch, cap)?;
        }
        Ok(())
    }

    pub(super) fn reduce<BF, EF>(
        &self,
        b: &mut CircuitBuilder<EF>,
        mut ch: BinaryTower128Challenger,
        public: &[Vec<BinaryPoly64Target>],
        proof: &BinaryPolyWhirMultiStarkProofTargets,
    ) -> Result<Reduction, VerificationError>
    where
        BF: PrimeField64,
        EF: ExtensionField<BF> + Eq + Hash,
    {
        for values in public {
            for value in values {
                ch.observe_poly64::<BF, EF>(b, value)?;
            }
        }
        let bus_claims = if let (Some(verifier), Some(proof)) = (&self.bus, &proof.bus) {
            let (claims, next) = verifier.verify::<BF, EF>(b, ch, proof)?;
            ch = next;
            Some(claims)
        } else {
            None
        };
        poly_observe_seed::<BF, EF>(b, &mut ch, &self.input.zerocheck_seed)?;
        let alpha = ch.sample_poly192::<BF, EF>(b)?;
        let beta = ch.sample_poly192::<BF, EF>(b)?;
        let lambda = if bus_claims.is_some() {
            Some(ch.sample_poly192::<BF, EF>(b)?)
        } else {
            None
        };
        let initial = if let (Some(claims), Some(lambda)) = (&bus_claims, &lambda) {
            let one = b.binary_poly192_constant([1, 0, 0])?;
            let push = b.binary_poly192_add(&claims.values[0], &one);
            let pull = b.binary_poly192_add(&claims.values[1], &one);
            let pull = b.binary_poly192_mul(lambda, &pull);
            let batched = b.binary_poly192_add(&push, &pull);
            b.binary_poly192_mul(lambda, &batched)
        } else {
            b.binary_poly192_constant([0; 3])?
        };
        let sampled = self.tau.sample::<BF, EF>(b, ch)?;
        let reduced = self.sumcheck.verify_reduction_after_queries::<BF, EF>(
            b,
            sampled.continuation,
            &initial,
            &proof.sumcheck,
        )?;
        let heights: Vec<_> = self.input.airs.iter().map(|a| a.log_height()).collect();
        let main_points = self
            .input
            .main_schedule
            .points(&heights, &reduced.point, None);
        let preprocessed_points = self
            .input
            .preprocessed_schedule
            .as_ref()
            .map(|s| s.points(&heights, &reduced.point, None));
        Ok(Reduction {
            alpha,
            beta,
            lambda,
            bus_claims,
            tau: sampled.values,
            point: reduced.point,
            claim: reduced.claim,
            challenger: reduced.challenger,
            main_points,
            preprocessed_points,
        })
    }

    pub(super) fn finish<EF: Field + Eq + Hash>(
        &self,
        b: &mut CircuitBuilder<EF>,
        public: &[Vec<BinaryPoly64Target>],
        reduction: &Reduction,
        evals: &[p3_sumcheck::OpeningBatch<BinaryPoly192Target>],
        preprocessed: Option<&[p3_sumcheck::OpeningBatch<BinaryPoly192Target>]>,
    ) -> Result<(), VerificationError> {
        let mut folded = b.binary_poly192_constant([0; 3])?;
        let mut weight = b.binary_poly192_constant([1, 0, 0])?;
        let mut air_evaluations = Vec::with_capacity(self.input.airs.len());
        for (i, air) in self.input.airs.iter().enumerate() {
            let values = &evals[self.input.main_schedule.air_batch(i)];
            let (pp_current, pp_next) = if air.preprocessed_width() != 0 {
                let slot = self
                    .input
                    .preprocessed_schedule
                    .as_ref()
                    .unwrap()
                    .air_batch(i);
                let values = &preprocessed.expect("checked preprocessing evaluations")[slot];
                (values.current(), values.next())
            } else {
                (&[][..], &[][..])
            };
            let evaluation = air.evaluate_with_bus(
                b,
                &reduction.point[reduction.point.len() - air.log_height()..],
                values.current(),
                values.next(),
                pp_current,
                pp_next,
                &public[i],
                &reduction.alpha,
            )?;
            let term = b.binary_poly192_mul(&weight, &evaluation.folded);
            folded = b.binary_poly192_add(&folded, &term);
            weight = b.binary_poly192_mul(&weight, &reduction.beta);
            air_evaluations.push(evaluation);
        }
        let eq = poly192_eq_eval(b, &reduction.tau, &reduction.point)?;
        let mut terminal = b.binary_poly192_mul(&eq, &folded);
        if let (Some(verifier), Some(claims), Some(lambda)) =
            (&self.bus, &reduction.bus_claims, &reduction.lambda)
        {
            let bus = verifier.terminal(b, claims, &air_evaluations, &reduction.point, lambda)?;
            let weighted = b.binary_poly192_mul(lambda, &bus);
            terminal = b.binary_poly192_add(&terminal, &weighted);
        }
        poly_assert_equal(b, &reduction.claim, &terminal);
        Ok(())
    }

    pub(super) fn check_native<C>(
        &self,
        public: &[Vec<Poly64>],
        proof: &MultiStarkProof<C>,
    ) -> Result<(), VerificationError>
    where
        C: MultiStarkConfig<Val = Poly64, Challenge = Poly192>,
    {
        self.check_public(public)?;
        if proof.lookup.is_some()
            || proof.indexed.is_some()
            || (self.bus.is_none() && proof.sumcheck.claimed_sum != Poly192::ZERO)
        {
            return Err(invalid(
                "polynomial MultiStark proof has unsupported reductions or initial sum",
            ));
        }
        match (&self.bus, &proof.bus) {
            (Some(verifier), Some(proof)) => verifier.check_native(proof)?,
            (None, None) => {}
            _ => return Err(invalid("binary Poly MultiStark native bus shape mismatch")),
        }
        self.sumcheck.check_native(&proof.sumcheck)
    }

    pub(super) fn observe_native_prefix<Ch>(
        &self,
        ch: &mut Ch,
        pp: Option<&MerkleCap<Poly64, [u8; 32]>>,
    ) where
        Ch: FieldChallenger<Poly64> + CanObserve<MerkleCap<Poly64, [u8; 32]>>,
    {
        ch.observe_slice(&self.input.outer_seed);
        if let Some(cap) = pp {
            ch.observe(cap.clone());
        }
    }

    pub(super) fn reduce_native<C, Ch>(
        &self,
        public: &[Vec<Poly64>],
        proof: &MultiStarkProof<C>,
        ch: &mut Ch,
    ) -> Result<NativeReduction, VerificationError>
    where
        C: MultiStarkConfig<Val = Poly64, Challenge = Poly192>,
        Ch: FieldChallenger<Poly64> + GrindingChallenger<Witness = Poly64> + Clone,
    {
        for values in public {
            ch.observe_slice(values);
        }
        let bus_reduction = if let (Some(verifier), Some(proof)) = (&self.bus, &proof.bus) {
            Some(verifier.import_native(proof, ch)?)
        } else {
            None
        };
        ch.observe_slice(&self.input.zerocheck_seed);
        let _alpha = ch.sample_algebra_element::<Poly192>();
        let _beta = ch.sample_algebra_element::<Poly192>();
        if let Some((_, values)) = &bus_reduction {
            let lambda = ch.sample_algebra_element::<Poly192>();
            let expected =
                lambda * ((values[0] + Poly192::ONE) + lambda * (values[1] + Poly192::ONE));
            if proof.sumcheck.claimed_sum != expected {
                return Err(invalid("binary Poly MultiStark bus initial sum mismatch"));
            }
        }
        let _ = self.tau.sample_native(ch)?;
        let (sumcheck, point, _) = self
            .sumcheck
            .import_native_with_reduction(&proof.sumcheck, ch)?;
        let heights: Vec<_> = self.input.airs.iter().map(|a| a.log_height()).collect();
        let main_points = self
            .input
            .main_schedule
            .points(&heights, point.as_slice(), None)
            .into_iter()
            .map(Point::new)
            .collect();
        let preprocessed_points = self.input.preprocessed_schedule.as_ref().map(|s| {
            s.points(&heights, point.as_slice(), None)
                .into_iter()
                .map(Point::new)
                .collect()
        });
        Ok(NativeReduction {
            bus: bus_reduction.map(|(input, _)| input),
            sumcheck,
            main_points,
            preprocessed_points,
        })
    }
}
