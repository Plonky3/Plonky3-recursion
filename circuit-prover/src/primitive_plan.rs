//! A frozen primitive relation, independent of table addresses and lookup counts.

use alloc::vec::Vec;

use p3_circuit::Circuit;
use p3_circuit::ops::{AluOpKind, NpoTypeId, Op};
use p3_circuit::types::WitnessId;
use p3_field::Field;

use crate::direct::{DirectCircuitError, DirectCircuitLimits};

#[derive(Clone, Debug)]
pub(crate) enum PrimitiveConstraint<F> {
    Constant {
        out: usize,
        value: F,
    },
    Add {
        a: usize,
        b: usize,
        out: usize,
    },
    Mul {
        a: usize,
        b: usize,
        out: usize,
    },
    Boolean {
        value: usize,
        out: usize,
    },
    MulAdd {
        a: usize,
        b: usize,
        c: Option<usize>,
        out: usize,
    },
    Horner {
        a: usize,
        b: usize,
        c: usize,
        accumulator: usize,
        out: usize,
    },
}

#[derive(Clone, Debug)]
pub(crate) struct PrimitivePlan<F> {
    pub(crate) width: usize,
    pub(crate) public: Vec<usize>,
    pub(crate) constraints: Vec<PrimitiveConstraint<F>>,
}

impl<F: Field> PrimitivePlan<F> {
    pub(crate) fn new(
        circuit: &Circuit<F>,
        limits: DirectCircuitLimits,
    ) -> Result<Self, DirectCircuitError> {
        Self::with_supported_npos(circuit, limits, &[])
    }

    /// Only a backend supplying the corresponding AIRs may allow these NPOs.
    pub(crate) fn with_supported_npos(
        circuit: &Circuit<F>,
        limits: DirectCircuitLimits,
        supported: &[NpoTypeId],
    ) -> Result<Self, DirectCircuitError> {
        let width = circuit.witness_count as usize;
        if width == 0 {
            return Err(DirectCircuitError::EmptyRelation);
        }
        limits.check("witnesses", width, limits.max_witnesses)?;
        limits.check("operations", circuit.ops.len(), limits.max_operations)?;
        limits.check(
            "public values",
            circuit.public_rows.len(),
            limits.max_witnesses,
        )?;
        if circuit.public_rows.len() != circuit.public_flat_len
            || circuit.private_input_rows.len() != circuit.private_flat_len
        {
            return Err(DirectCircuitError::PublicMapping);
        }
        let check = |id: WitnessId| -> Result<usize, DirectCircuitError> {
            let index = id.0 as usize;
            if index >= width {
                Err(DirectCircuitError::WitnessOutOfBounds { index, width })
            } else {
                Ok(index)
            }
        };
        let public = circuit
            .public_rows
            .iter()
            .copied()
            .map(check)
            .collect::<Result<Vec<_>, _>>()?;
        for &id in &circuit.private_input_rows {
            check(id)?;
        }
        let mut constraints = Vec::with_capacity(circuit.ops.len());
        let mut has_supported_npo = false;
        for (operation, op) in circuit.ops.iter().enumerate() {
            match op {
                Op::Const { out, val } => constraints.push(PrimitiveConstraint::Constant {
                    out: check(*out)?,
                    value: *val,
                }),
                Op::Public { out, public_pos } => {
                    let out = check(*out)?;
                    if public.get(*public_pos) != Some(&out) {
                        return Err(DirectCircuitError::PublicMapping);
                    }
                }
                Op::Hint {
                    inputs, outputs, ..
                } => {
                    for &id in inputs.iter().chain(outputs) {
                        check(id)?;
                    }
                }
                Op::NonPrimitiveOpWithExecutor {
                    inputs,
                    outputs,
                    executor,
                    ..
                } => {
                    if !supported.contains(executor.op_type()) {
                        return Err(DirectCircuitError::UnsupportedOperation { operation });
                    }
                    for &id in inputs.iter().chain(outputs).flatten() {
                        check(id)?;
                    }
                    has_supported_npo = true;
                }
                Op::Alu {
                    kind,
                    a,
                    b,
                    c,
                    out,
                    intermediate_out,
                } => {
                    let a = check(*a)?;
                    let b = check(*b)?;
                    let c = c.map(check).transpose()?;
                    let out = check(*out)?;
                    let intermediate = intermediate_out.map(check).transpose()?;
                    if matches!(kind, AluOpKind::Add | AluOpKind::Mul)
                        && (c.is_some() || intermediate.is_some())
                    {
                        return Err(DirectCircuitError::MalformedAlu { operation });
                    }
                    // The compiler records BoolCheck's forwarded operand in c;
                    // the convenience Op constructor leaves that redundant slot empty.
                    if *kind == AluOpKind::BoolCheck
                        && (intermediate.is_some() || c.is_some_and(|column| column != a))
                    {
                        return Err(DirectCircuitError::MalformedAlu { operation });
                    }
                    let constraint = match kind {
                        AluOpKind::Add => PrimitiveConstraint::Add { a, b, out },
                        AluOpKind::Mul => PrimitiveConstraint::Mul { a, b, out },
                        AluOpKind::BoolCheck => PrimitiveConstraint::Boolean { value: a, out },
                        AluOpKind::MulAdd => {
                            if let Some(out) = intermediate {
                                constraints.push(PrimitiveConstraint::Mul { a, b, out });
                            }
                            PrimitiveConstraint::MulAdd { a, b, c, out }
                        }
                        AluOpKind::HornerAcc => {
                            let (Some(c), Some(accumulator)) = (c, intermediate) else {
                                return Err(DirectCircuitError::MalformedAlu { operation });
                            };
                            PrimitiveConstraint::Horner {
                                a,
                                b,
                                c,
                                accumulator,
                                out,
                            }
                        }
                    };
                    constraints.push(constraint);
                }
            }
        }
        if constraints.is_empty() && public.is_empty() && !has_supported_npo {
            return Err(DirectCircuitError::EmptyRelation);
        }
        Ok(Self {
            width,
            public,
            constraints,
        })
    }
}
