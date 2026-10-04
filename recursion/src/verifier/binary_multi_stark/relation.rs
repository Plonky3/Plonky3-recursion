//! PCS-independent trusted AIR and reduction planning.

use alloc::sync::Arc;

use super::*;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(in crate::verifier) struct BinaryMultiStarkRelationShape<F, E> {
    pub(in crate::verifier) airs: Vec<BinaryAirConstraintPlan<F, E>>,
    pub(in crate::verifier) outer_seed: Vec<F>,
    pub(in crate::verifier) zerocheck_seed: Vec<F>,
    pub(in crate::verifier) sumcheck: BinaryGenericSumcheckInputShape<F, E>,
    pub(in crate::verifier) bus: Option<BinaryBusInputShape<F, E>>,
    pub(in crate::verifier) indexed: Option<IndexedInputShape<F, E>>,
    pub(in crate::verifier) main_schedule: BinaryOpeningSchedule,
    pub(in crate::verifier) preprocessed_schedule: Option<BinaryOpeningSchedule>,
    pub(in crate::verifier) max_tau_draws: usize,
}

#[derive(Clone, Debug)]
pub(in crate::verifier) struct BinaryMultiStarkRelation<F, E> {
    pub(in crate::verifier) input: Arc<BinaryMultiStarkRelationShape<F, E>>,
    pub(in crate::verifier) sumcheck: BinaryGenericSumcheckVerifier<F, E>,
    pub(in crate::verifier) tau: BinaryNonzeroChallengePlan<E>,
    pub(in crate::verifier) bus: Option<BinaryBusVerifier<F, E>>,
    pub(in crate::verifier) indexed: Option<BinaryIndexedVerifier<F, E>>,
    pub(in crate::verifier) usage: InputResourceUsage,
}

pub(in crate::verifier) struct BinaryRelationProof<'a> {
    pub(in crate::verifier) bus: Option<&'a BinaryProductGkrProofTargets>,
    pub(in crate::verifier) sumcheck: &'a BinaryGenericSumcheckProofTargets,
    pub(in crate::verifier) indexed: Option<&'a BinaryIndexedLookupProofTargets>,
}

pub(in crate::verifier) struct BinaryMultiStarkReduction {
    alpha: BinaryTower128Target,
    beta: BinaryTower128Target,
    lambda: Option<BinaryTower128Target>,
    bus_claims: Option<super::super::binary_bus::BinaryBusClaims>,
    tau: Vec<BinaryTower128Target>,
    point: Vec<BinaryTower128Target>,
    claim: BinaryTower128Target,
    indexed: Option<super::super::BinaryLogupStarOutput>,
    pub(in crate::verifier) challenger: BinaryTower128Challenger,
    pub(in crate::verifier) main_points: Vec<Vec<BinaryTower128Target>>,
    pub(in crate::verifier) preprocessed_points: Option<Vec<Vec<BinaryTower128Target>>>,
}

pub(in crate::verifier) struct NativeBinaryMultiStarkReduction<F, E> {
    pub(in crate::verifier) bus: Option<NativeBinaryProductGkrInput<F, E>>,
    pub(in crate::verifier) sumcheck: NativeBinaryGenericSumcheckInput<F, E>,
    pub(in crate::verifier) indexed: Option<NativeIndexedInput<F, E>>,
    pub(in crate::verifier) main_points: Vec<Point<E>>,
    pub(in crate::verifier) preprocessed_points: Option<Vec<Point<E>>>,
}

impl<F, E> BinaryMultiStarkRelationShape<F, E>
where
    F: RecursiveBinaryTowerField,
    E: RecursiveBinaryChallengeField + ExtensionField<F>,
{
    pub(in crate::verifier) fn write_identity(
        &self,
        w: &mut crate::artifact::wire::Writer,
    ) -> Result<(), crate::artifact::ArtifactError> {
        w.write_vec("binary native AIRs", &self.airs, |w, air| {
            air.write_identity(w)
        })?;
        for seed in [&self.outer_seed, &self.zerocheck_seed] {
            w.write_vec("binary native transcript seed", seed, |w, value| {
                w.write_bytes(&value.raw_coordinates().to_le_bytes()[..F::RAW_BITS / 8])
            })?;
        }
        Ok(())
    }
}

impl<F, E> BinaryMultiStarkRelation<F, E>
where
    F: RecursiveBinaryTowerField,
    E: RecursiveBinaryChallengeField + ExtensionField<F>,
{
    pub(in crate::verifier) fn build<A>(
        airs: &[&A],
        heights: &[usize],
        pow_bits: usize,
        max_tau_draws: usize,
        has_preprocessing: bool,
        limits: &VerifierLimits,
    ) -> Result<(Self, OpeningProtocol, Option<OpeningProtocol>), VerificationError>
    where
        A: Air<InteractionSymbolicBuilder<F, E>> + Air<BusSymbolicBuilder<F, E>>,
    {
        if airs.is_empty() || airs.len() != heights.len() || heights.contains(&0) {
            return Err(invalid("binary MultiStark trusted instance shape mismatch"));
        }
        // TableShape stores its height as usize and shifts by this exponent.
        // A caller may widen resource limits, but cannot widen the platform.
        if let Some(&height) = heights
            .iter()
            .find(|&&height| height >= usize::BITS as usize)
        {
            return Err(VerificationError::ResourceLimitExceeded {
                component: "binary MultiStark trace log height",
                actual: height,
                limit: usize::BITS as usize - 1,
            });
        }
        let mut usage = InputResourceUsage::default();
        // Check the axis before compiling any trusted callback or cloning lists.
        usage.add_instances(limits, airs.len())?;
        let mut plans = Vec::with_capacity(airs.len());
        let mut bus_declarations = Vec::with_capacity(airs.len());
        for (&air, &height) in airs.iter().zip(heights) {
            let (plan, declarations) =
                BinaryAirConstraintPlan::<F, E>::with_interaction_limits(air, height, limits)?;
            if plan.preprocessed_width() != 0 && !has_preprocessing {
                return Err(invalid(
                    "binary MultiStark preprocessing requires a trusted commitment plan",
                ));
            }
            usage.merge(limits, plan.input_resource_usage())?;
            let public_limbs = plan.public_value_count().checked_mul(8).ok_or(
                VerificationError::ResourceArithmeticOverflow {
                    component: "binary MultiStark public limbs",
                },
            )?;
            usage.add_scalar_elements(limits, public_limbs)?;
            plans.push(plan);
            bus_declarations.push(declarations);
        }
        let bus_inputs: Vec<_> = bus_declarations
            .iter()
            .zip(heights)
            .map(|(interactions, &log_height)| BusPlanInput {
                log_height,
                interactions,
            })
            .collect();
        let bus = BusPlan::build(&bus_inputs)
            .map_err(|_| invalid("binary MultiStark bus geometry is invalid"))?
            .map(|plan| BinaryBusVerifier::<F, E>::with_limits(plan, &plans, limits))
            .transpose()?;
        if let Some(bus) = &bus {
            usage.merge(limits, bus.input_resource_usage())?;
        }
        let indexed = BinaryIndexedVerifier::<F, E>::build(&plans, max_tau_draws, limits)?;
        if let Some(indexed) = &indexed {
            usage.merge(limits, indexed.usage())?;
        }
        let height = *heights.iter().max().unwrap();
        let degree = plans
            .iter()
            .map(BinaryAirConstraintPlan::constraint_degree)
            .max()
            .unwrap();
        let degree =
            degree
                .checked_add(1)
                .ok_or(VerificationError::ResourceArithmeticOverflow {
                    component: "binary MultiStark sumcheck degree",
                })?;
        let degree = degree.max(bus.as_ref().map(|bus| bus.degree()).unwrap_or(0));
        let sumcheck =
            BinaryGenericSumcheckVerifier::<F, E>::with_limits(height, degree, pow_bits, limits)?;
        usage.merge(limits, sumcheck.input_resource_usage())?;
        let tau = BinaryNonzeroChallengePlan::<E>::with_limits(height, max_tau_draws, limits)?;
        usage.merge(limits, tau.input_resource_usage())?;
        let (main_tables, main_schedule) = schedule(&plans, indexed.as_ref(), false);
        usage.add_metadata_entries(limits, main_schedule.len())?;
        let indices: Vec<_> = plans
            .iter()
            .enumerate()
            .filter_map(|(i, air)| (air.preprocessed_width() != 0).then_some(i))
            .collect();
        usage.add_metadata_entries(limits, indices.len())?;
        if indices.is_empty() && has_preprocessing {
            return Err(invalid(
                "binary MultiStark has an unused preprocessing authority",
            ));
        }
        let (preprocessed_protocol, preprocessed_schedule) = if has_preprocessing {
            let (tables, schedule) = schedule(&plans, indexed.as_ref(), true);
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
            has_indexed: indexed.is_some(),
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
        let input = Arc::new(BinaryMultiStarkRelationShape {
            airs: plans,
            outer_seed: domain_separator_seed(&outer.domain_separator::<F>()),
            zerocheck_seed: domain_separator_seed(&zerocheck.domain_separator::<F, E>()),
            sumcheck: sumcheck.input_shape(),
            bus: bus.as_ref().map(|bus| bus.input_shape()),
            indexed: indexed.as_ref().map(|indexed| indexed.input_shape()),
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
                indexed,
                usage,
            },
            OpeningProtocol::new(main_tables),
            preprocessed_protocol,
        ))
    }

    pub(in crate::verifier) fn check_targets<T>(
        &self,
        public: &[Vec<T>],
        proof: &BinaryRelationProof<'_>,
    ) -> Result<(), VerificationError> {
        self.check_public(public)?;
        match (&self.bus, proof.bus) {
            (Some(verifier), Some(proof)) => verifier.check_targets(proof)?,
            (None, None) => {}
            _ => return Err(invalid("binary MultiStark bus proof shape mismatch")),
        }
        self.sumcheck.check_targets(proof.sumcheck)?;
        match (&self.indexed, proof.indexed) {
            (Some(verifier), Some(proof)) => verifier.check_proof_targets(proof)?,
            (None, None) => {}
            _ => return Err(invalid("binary MultiStark indexed proof shape mismatch")),
        }
        Ok(())
    }

    pub(in crate::verifier) fn observe_prefix<BF, EF>(
        &self,
        b: &mut CircuitBuilder<EF>,
        ch: &mut BinaryTower128Challenger,
        preprocessed: Option<&[Vec<ExprId>]>,
    ) -> Result<(), VerificationError>
    where
        BF: PrimeField64,
        EF: ExtensionField<BF> + Eq + Hash,
    {
        observe_seed::<F, BF, EF>(b, ch, &self.input.outer_seed)?;
        if let Some(cap) = preprocessed {
            observe_cap::<BF, EF>(b, ch, cap)?;
        }
        Ok(())
    }

    pub(in crate::verifier) fn zero_points<T: Clone>(
        &self,
        preprocessed: bool,
        zero: T,
    ) -> Vec<Vec<T>> {
        let heights: Vec<_> = self.input.airs.iter().map(|air| air.log_height()).collect();
        let schedule = if preprocessed {
            self.input
                .preprocessed_schedule
                .as_ref()
                .expect("checked preprocessing schedule")
        } else {
            &self.input.main_schedule
        };
        schedule.zero_points(&heights, zero)
    }

    pub(in crate::verifier) fn reduce<BF, EF>(
        &self,
        b: &mut CircuitBuilder<EF>,
        mut ch: BinaryTower128Challenger,
        public: &[Vec<BinaryTower128Target>],
        proof: &BinaryRelationProof<'_>,
    ) -> Result<BinaryMultiStarkReduction, VerificationError>
    where
        BF: PrimeField64,
        EF: ExtensionField<BF> + Eq + Hash,
    {
        let zero = b.binary128_constant(0)?;
        let heights: Vec<_> = self.input.airs.iter().map(|air| air.log_height()).collect();
        for values in public {
            for value in values {
                constrain_width(b, value, F::RAW_BITS);
            }
            observe_values::<BF, EF>(b, &mut ch, values, F::RAW_BITS)?;
        }
        let bus_claims = if let (Some(verifier), Some(proof)) = (&self.bus, proof.bus) {
            let (claims, next) = verifier.verify::<BF, EF>(b, ch, proof)?;
            ch = next;
            Some(claims)
        } else {
            None
        };
        observe_seed::<F, BF, EF>(b, &mut ch, &self.input.zerocheck_seed)?;
        let alpha = super::super::binary_product::sample::<E, BF, EF>(b, &mut ch)?;
        let beta = super::super::binary_product::sample::<E, BF, EF>(b, &mut ch)?;
        let lambda = if bus_claims.is_some() {
            Some(super::super::binary_product::sample::<E, BF, EF>(
                b, &mut ch,
            )?)
        } else {
            None
        };
        let initial = if let (Some(claims), Some(lambda)) = (&bus_claims, &lambda) {
            let one = b.binary128_constant(1)?;
            let push = b.binary128_add(&claims.values[0], &one);
            let pull = b.binary128_add(&claims.values[1], &one);
            let pull = b.binary128_mul(lambda, &pull);
            let batched = b.binary128_add(&push, &pull);
            b.binary128_mul(lambda, &batched)
        } else {
            zero.clone()
        };
        let output = self.tau.sample::<BF, EF>(b, ch)?;
        let reduction = self.sumcheck.verify_reduction_after_queries::<BF, EF>(
            b,
            output.continuation,
            &initial,
            proof.sumcheck,
        )?;
        let tau = output.values;
        let indexed = if let (Some(verifier), Some(proof)) = (&self.indexed, proof.indexed) {
            Some(verifier.verify::<BF, EF>(
                b,
                reduction.challenger.clone(),
                &reduction.point,
                proof,
            )?)
        } else {
            None
        };
        let indexed_points = indexed.as_ref().map(|output| {
            (
                output.position_point.as_slice(),
                output.table_point.as_slice(),
            )
        });
        let main_points =
            self.input
                .main_schedule
                .points(&heights, &reduction.point, indexed_points);
        let challenger = indexed
            .as_ref()
            .map(|output| output.challenger.clone())
            .unwrap_or(reduction.challenger);
        let preprocessed_points = self
            .input
            .preprocessed_schedule
            .as_ref()
            .map(|schedule| schedule.points(&heights, &reduction.point, indexed_points));
        Ok(BinaryMultiStarkReduction {
            alpha,
            beta,
            lambda,
            bus_claims,
            tau,
            point: reduction.point,
            claim: reduction.claim,
            indexed,
            challenger,
            main_points,
            preprocessed_points,
        })
    }

    pub(in crate::verifier) fn finish<EF>(
        &self,
        b: &mut CircuitBuilder<EF>,
        public: &[Vec<BinaryTower128Target>],
        proof: &BinaryRelationProof<'_>,
        reduction: &BinaryMultiStarkReduction,
        evals: &[p3_sumcheck::OpeningBatch<BinaryTower128Target>],
        preprocessed: Option<&[p3_sumcheck::OpeningBatch<BinaryTower128Target>]>,
    ) -> Result<(), VerificationError>
    where
        EF: Field + Eq + Hash,
    {
        if let (Some(verifier), Some(indexed_proof), Some(output)) =
            (&self.indexed, proof.indexed, &reduction.indexed)
        {
            let preprocessing = self.input.preprocessed_schedule.as_ref().zip(preprocessed);
            verifier.authenticate(
                b,
                indexed_proof,
                output,
                &self.input.main_schedule,
                evals,
                preprocessing,
            );
        }
        let mut folded = b.binary128_constant(0)?;
        let mut weight = b.binary128_constant(1)?;
        let mut air_evaluations = Vec::with_capacity(self.input.airs.len());
        for (i, air) in self.input.airs.iter().enumerate() {
            let values = &evals[self.input.main_schedule.air_batch(i)];
            let (preprocessed_current, preprocessed_next) = if air.preprocessed_width() != 0 {
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
                preprocessed_current,
                preprocessed_next,
                &public[i],
                &reduction.alpha,
            )?;
            let term = b.binary128_mul(&weight, &evaluation.folded);
            folded = b.binary128_add(&folded, &term);
            weight = b.binary128_mul(&weight, &reduction.beta);
            air_evaluations.push(evaluation);
        }
        let equality = binary128_eq_eval(b, &reduction.tau, &reduction.point)?;
        let mut terminal = b.binary128_mul(&equality, &folded);
        if let (Some(verifier), Some(claims), Some(lambda)) =
            (&self.bus, &reduction.bus_claims, &reduction.lambda)
        {
            let bus = verifier.terminal(b, claims, &air_evaluations, &reduction.point, lambda)?;
            let weighted = b.binary128_mul(lambda, &bus);
            terminal = b.binary128_add(&terminal, &weighted);
        }
        assert_equal(b, &reduction.claim, &terminal);
        Ok(())
    }

    pub(in crate::verifier) fn check_public<T>(
        &self,
        public: &[Vec<T>],
    ) -> Result<(), VerificationError> {
        if public.len() != self.input.airs.len()
            || public
                .iter()
                .zip(&self.input.airs)
                .any(|(values, air)| values.len() != air.public_value_count())
        {
            return Err(invalid("binary MultiStark public value shape mismatch"));
        }
        Ok(())
    }

    pub(in crate::verifier) fn check_native<C>(
        &self,
        public: &[Vec<F>],
        proof: &MultiStarkProof<C>,
    ) -> Result<(), VerificationError>
    where
        C: MultiStarkConfig<Val = F, Challenge = E>,
    {
        self.check_public(public)?;
        if proof.lookup.is_some() || (self.bus.is_none() && proof.sumcheck.claimed_sum != E::ZERO) {
            return Err(invalid(
                "binary MultiStark proof has unsupported parts or a nonzero initial sum",
            ));
        }
        match (&self.bus, &proof.bus) {
            (Some(verifier), Some(proof)) => verifier.check_native(proof)?,
            (None, None) => {}
            _ => return Err(invalid("binary MultiStark native bus proof shape mismatch")),
        }
        self.sumcheck.check_native(&proof.sumcheck)?;
        let heights: Vec<_> = self.input.airs.iter().map(|air| air.log_height()).collect();
        let height = *heights.iter().max().unwrap();
        match (&self.indexed, &proof.indexed) {
            (Some(verifier), Some(proof)) => {
                verifier.check_native(&Point::new(vec![E::ZERO; height]), proof)?
            }
            (None, None) => {}
            _ => {
                return Err(invalid(
                    "binary MultiStark native indexed proof shape mismatch",
                ));
            }
        }
        Ok(())
    }

    pub(in crate::verifier) fn observe_native_prefix<Ch>(
        &self,
        ch: &mut Ch,
        preprocessed: Option<&MerkleCap<F, [u8; 32]>>,
    ) where
        Ch: FieldChallenger<F> + CanObserve<MerkleCap<F, [u8; 32]>>,
    {
        ch.observe_slice(&self.input.outer_seed);
        if let Some(cap) = preprocessed {
            ch.observe(cap.clone());
        }
    }

    pub(in crate::verifier) fn reduce_native<C, Ch>(
        &self,
        public: &[Vec<F>],
        proof: &MultiStarkProof<C>,
        staged: &mut Ch,
    ) -> Result<NativeBinaryMultiStarkReduction<F, E>, VerificationError>
    where
        C: MultiStarkConfig<Val = F, Challenge = E>,
        Ch: FieldChallenger<F> + GrindingChallenger<Witness = F> + Clone,
    {
        let heights: Vec<_> = self.input.airs.iter().map(|air| air.log_height()).collect();
        for values in public {
            staged.observe_slice(values);
        }
        let bus_reduction = if let (Some(verifier), Some(proof)) = (&self.bus, &proof.bus) {
            Some(verifier.import_native(proof, staged)?)
        } else {
            None
        };
        staged.observe_slice(&self.input.zerocheck_seed);
        let _alpha = staged.sample_algebra_element::<E>();
        let _beta = staged.sample_algebra_element::<E>();
        if let Some((_, values)) = &bus_reduction {
            let lambda = staged.sample_algebra_element::<E>();
            let expected = lambda * ((values[0] + E::ONE) + lambda * (values[1] + E::ONE));
            if proof.sumcheck.claimed_sum != expected {
                return Err(invalid("binary MultiStark bus initial sum mismatch"));
            }
        }
        let _ = self.tau.sample_native::<F, _>(staged)?;
        let (sumcheck, point, _) = self
            .sumcheck
            .import_native_with_reduction(&proof.sumcheck, &mut *staged)?;
        let indexed = if let (Some(verifier), Some(proof)) = (&self.indexed, &proof.indexed) {
            Some(verifier.import_native(&point, proof, staged)?)
        } else {
            None
        };
        let indexed_points = indexed.as_ref().map(|(_, output)| {
            (
                output.position_point.as_slice(),
                output.table_point.as_slice(),
            )
        });
        let main_points: Vec<_> = self
            .input
            .main_schedule
            .points(&heights, point.as_slice(), indexed_points)
            .into_iter()
            .map(Point::new)
            .collect();
        let preprocessed_points = self.input.preprocessed_schedule.as_ref().map(|schedule| {
            schedule
                .points(&heights, point.as_slice(), indexed_points)
                .into_iter()
                .map(Point::new)
                .collect()
        });
        Ok(NativeBinaryMultiStarkReduction {
            bus: bus_reduction.map(|(input, _)| input),
            sumcheck,
            indexed: indexed.map(|(input, _)| input),
            main_points,
            preprocessed_points,
        })
    }
}
