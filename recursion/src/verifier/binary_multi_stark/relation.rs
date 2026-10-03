//! PCS-independent trusted AIR and reduction planning.

use super::*;
use alloc::sync::Arc;

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
            let mut bus_usage = bus.input_resource_usage();
            bus_usage.instances = 0;
            usage.merge(limits, bus_usage)?;
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
}
