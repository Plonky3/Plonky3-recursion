//! Checked, proof-independent Boolean trace routing metadata.

use alloc::vec;
use alloc::vec::Vec;

use p3_binary_field::BinaryField128;
use p3_field::PrimeCharacteristicRing;
use p3_sumcheck::OpeningProtocol;
use p3_sumcheck::layout::plan_stacked_layout;

use super::BinaryRingClaimSpec;
use crate::verifier::{InputResourceUsage, VerificationError, VerifierLimits};

#[derive(Clone, Debug)]
pub(super) struct TracePlan {
    pub protocol: OpeningProtocol,
    pub num_variables: usize,
    pub point_arities: Vec<usize>,
    pub value_count: usize,
    pub specs: Vec<BinaryRingClaimSpec>,
    pub route: Route,
    pub usage: InputResourceUsage,
}

#[derive(Clone, Debug)]
pub(super) enum Route {
    Batched {
        width: usize,
        columns: usize,
        next: bool,
    },
    Columns(Vec<ColumnClaim>),
}

#[derive(Clone, Debug)]
pub(super) struct ColumnClaim {
    pub opening: usize,
    pub selector: Vec<bool>,
    pub current_at: Option<usize>,
    pub next_at: Option<usize>,
}

impl TracePlan {
    pub fn new(
        protocol: OpeningProtocol,
        num_variables: usize,
        limits: &VerifierLimits,
    ) -> Result<Self, VerificationError> {
        if num_variables > limits.max_log_domain_or_degree || num_variables >= usize::BITS as usize
        {
            return Err(VerificationError::ResourceLimitExceeded {
                component: "binary trace variables",
                actual: num_variables,
                limit: limits
                    .max_log_domain_or_degree
                    .min(usize::BITS as usize - 1),
            });
        }
        let cells =
            protocol
                .checked_num_cells()
                .ok_or(VerificationError::ResourceArithmeticOverflow {
                    component: "binary trace cells",
                })?;
        if cells == 0 || p3_util::log2_ceil_usize(cells) != num_variables {
            return Err(invalid(
                "binary trace tables do not match the committed bit arity",
            ));
        }
        let value_count =
            protocol
                .checked_num_claims()
                .ok_or(VerificationError::ResourceArithmeticOverflow {
                    component: "binary trace values",
                })?;
        if value_count == 0 {
            return Err(invalid("binary trace protocol has no readings"));
        }
        let shapes = protocol.table_shapes();
        let mut usage = InputResourceUsage::default();
        usage.add_instances(limits, shapes.len())?;
        usage.add_metadata_entries(limits, value_count)?;
        usage.add_scalar_elements(
            limits,
            value_count
                .checked_mul(8)
                .ok_or(VerificationError::ResourceArithmeticOverflow {
                    component: "binary trace value limbs",
                })?,
        )?;
        for shape in &shapes {
            if shape.width() == 0 || shape.width() > limits.max_matrix_width {
                return Err(VerificationError::ResourceLimitExceeded {
                    component: "binary trace table width",
                    actual: shape.width(),
                    limit: limits.max_matrix_width,
                });
            }
        }
        let mut point_arities = Vec::new();
        for (table, batch) in protocol.iter_openings() {
            if batch.is_empty()
                || batch
                    .current()
                    .iter()
                    .chain(batch.next())
                    .any(|&column| column >= shapes[table].width())
            {
                return Err(invalid(
                    "binary trace request is empty or outside its table",
                ));
            }
            for columns in [batch.current(), batch.next()] {
                let mut seen = hashbrown::HashSet::new();
                if columns.iter().any(|&column| !seen.insert(column)) {
                    return Err(invalid(
                        "binary trace request repeats a column within one view",
                    ));
                }
            }
            let arity = shapes[table].num_variables();
            usage.add_scalar_elements(
                limits,
                arity
                    .checked_mul(8)
                    .ok_or(VerificationError::ResourceArithmeticOverflow {
                        component: "binary trace point limbs",
                    })?,
            )?;
            point_arities.push(arity);
        }
        // Every request is now nonempty and the checked claim count bounds the
        // batch count. Only checked metadata reaches the native placement helper.
        let (_, placements) = plan_stacked_layout(&shapes);
        let mut by_table = vec![None; shapes.len()];
        for placement in &placements {
            by_table[placement.idx()] = Some(placement);
        }
        let next = protocol
            .iter_openings()
            .next()
            .is_some_and(|(_, b)| !b.next().is_empty());
        let width = shapes[0].width();
        let complete =
            |columns: &[usize]| columns.len() == width && columns.iter().copied().eq(0..width);
        let batched = shapes.len() == 1
            && protocol.iter_openings().all(|(_, batch)| {
                complete(batch.current())
                    && if next {
                        complete(batch.next())
                    } else {
                        batch.next().is_empty()
                    }
            });
        let mut specs = Vec::new();
        let route = if batched {
            specs.resize(
                point_arities.len(),
                BinaryRingClaimSpec {
                    current: true,
                    next_rows: next.then_some(shapes[0].num_variables()),
                },
            );
            Route::Batched {
                width,
                columns: p3_util::log2_ceil_usize(width),
                next,
            }
        } else {
            let mut claims = Vec::new();
            let mut cursor = 0;
            for (opening, (table, batch)) in protocol.iter_openings().enumerate() {
                let next_cursor = cursor + batch.current().len();
                let mut answered = vec![false; batch.next().len()];
                let mut push =
                    |column: usize, current_at: Option<usize>, next_at: Option<usize>| {
                        let selector = by_table[table]
                            .expect("every checked table is placed")
                            .selectors()[column]
                            .point::<BinaryField128>()
                            .as_slice()
                            .iter()
                            .map(|&v| v == BinaryField128::ONE)
                            .collect();
                        claims.push(ColumnClaim {
                            opening,
                            selector,
                            current_at,
                            next_at,
                        });
                        specs.push(BinaryRingClaimSpec {
                            current: current_at.is_some(),
                            next_rows: next_at.map(|_| shapes[table].num_variables()),
                        });
                    };
                for (offset, &column) in batch.current().iter().enumerate() {
                    let at = batch
                        .next()
                        .iter()
                        .zip(&answered)
                        .position(|(&other, &taken)| other == column && !taken);
                    if let Some(at) = at {
                        answered[at] = true;
                    }
                    push(column, Some(cursor + offset), at.map(|at| next_cursor + at));
                }
                for (at, &column) in batch.next().iter().enumerate() {
                    if !answered[at] {
                        push(column, None, Some(next_cursor + at));
                    }
                }
                cursor = next_cursor + batch.next().len();
            }
            Route::Columns(claims)
        };
        Ok(Self {
            protocol,
            num_variables,
            point_arities,
            value_count,
            specs,
            route,
            usage,
        })
    }
}

fn invalid(message: &'static str) -> VerificationError {
    VerificationError::InvalidProofShape(message.into())
}
