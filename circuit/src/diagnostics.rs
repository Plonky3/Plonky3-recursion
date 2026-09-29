//! Owned, structured context for circuit execution errors.
//!
//! The `debugging` feature records builder provenance. Diagnostics describe the
//! compiled snapshot; mutating public circuit operations after construction can
//! invalidate that relationship. Rendering shows at most eight items per repeated
//! section and at most 4096 Unicode characters plus an omission suffix overall,
//! while accessors retain every recorded item.
//!
//! ```
//! # #[cfg(feature = "debugging")]
//! # {
//! use p3_circuit::{Circuit, CircuitError};
//! use p3_test_utils::baby_bear_params::BabyBear;
//! let circuit = Circuit::<BabyBear>::new(0, Default::default());
//! let diagnostic = circuit.diagnose_error(CircuitError::DivisionByZero);
//! assert!(matches!(diagnostic.error(), CircuitError::DivisionByZero));
//! assert!(matches!(diagnostic.into_error(), CircuitError::DivisionByZero));
//! # }
//! ```
//!
//! A runner failure keeps its original typed error and identifies the compiled
//! operation and builder allocation when those records are available:
//!
//! ```
//! # #[cfg(feature = "debugging")]
//! # {
//! use p3_circuit::{CircuitBuilder, CircuitError, DiagnosticPhase};
//! use p3_test_utils::baby_bear_params::BabyBear;
//! let mut builder = CircuitBuilder::<BabyBear>::new();
//! builder.alloc_public_input("amount");
//! let circuit = builder.build().unwrap();
//! let report = circuit.runner().run_with_diagnostics().unwrap_err();
//! assert!(matches!(report.error(), CircuitError::PublicInputNotSet { .. }));
//! assert!(matches!(report.phase(), DiagnosticPhase::Execution { .. }));
//! assert_eq!(report.operation_origins()[0].allocation.as_ref().unwrap().label, "amount");
//! let typed_error = report.into_error();
//! assert!(matches!(typed_error, CircuitError::PublicInputNotSet { .. }));
//! # }
//! ```

use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec::Vec;
use core::error::Error;
use core::fmt;

use p3_field::Field;

use crate::alloc_entry::AllocationEntry;
use crate::circuit::Circuit;
use crate::ops::{NpoTypeId, Op};
use crate::types::{ExprId, NonPrimitiveOpId, WitnessId};
use crate::{AluOpKind, CircuitError};

const DISPLAY_LIMIT: usize = 8;
const DISPLAY_CHAR_LIMIT: usize = 4096;

/// Stage at which an error was returned.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DiagnosticPhase {
    /// Execution of the zero-based operation in `Circuit::ops`.
    Execution { compiled_op_index: usize },
    /// Replay of deduplicated witness aliases.
    WitnessAliases,
    /// Final witness table scan.
    WitnessTrace,
    /// Constant trace generation.
    ConstTrace,
    /// Public trace generation.
    PublicTrace,
    /// Non-primitive trace generation, keyed by its generator type.
    NonPrimitiveTrace { op_type: NpoTypeId },
    /// An error passed by a caller from a setter or other API.
    Caller,
}

/// Field-independent kind of an actual compiled operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CompiledOpKind {
    Const,
    Public,
    Alu(AluOpKind),
    Hint,
    NonPrimitive {
        op_id: NonPrimitiveOpId,
        op_type: NpoTypeId,
    },
}

/// Zero-based compiled operation position and its owned kind.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompiledOperation {
    pub compiled_op_index: usize,
    pub kind: CompiledOpKind,
}

/// Original expression identity and available allocation metadata.
///
/// `dependencies` is one hop deep, in the allocation's operand-group order.
/// Dependency records have empty `dependencies` themselves.
#[derive(Debug, Clone)]
pub struct DiagnosticSource {
    pub expr_id: ExprId,
    pub allocation: Option<AllocationEntry>,
    pub dependencies: Vec<Vec<Self>>,
}

/// An execution error with owned context that outlives its circuit and runner.
#[derive(Debug)]
pub struct CircuitDiagnostic {
    error: CircuitError,
    phase: DiagnosticPhase,
    context: Box<DiagnosticContext>,
}

#[derive(Debug)]
struct DiagnosticContext {
    compiled_operation: Option<CompiledOperation>,
    implicated_witness: Option<WitnessId>,
    canonical_witness: Option<WitnessId>,
    operation_origins: Vec<DiagnosticSource>,
    witness_aliases: Vec<DiagnosticSource>,
    related_sources: Vec<DiagnosticSource>,
    tags: Vec<String>,
}

impl CircuitDiagnostic {
    pub const fn error(&self) -> &CircuitError {
        &self.error
    }
    pub fn into_error(self) -> CircuitError {
        self.error
    }
    pub const fn phase(&self) -> &DiagnosticPhase {
        &self.phase
    }
    pub fn compiled_operation(&self) -> Option<&CompiledOperation> {
        self.context.compiled_operation.as_ref()
    }
    pub fn operation_origins(&self) -> &[DiagnosticSource] {
        &self.context.operation_origins
    }
    pub fn witness_aliases(&self) -> &[DiagnosticSource] {
        &self.context.witness_aliases
    }
    pub fn related_sources(&self) -> &[DiagnosticSource] {
        &self.context.related_sources
    }
    pub fn implicated_witness(&self) -> Option<WitnessId> {
        self.context.implicated_witness
    }
    pub fn canonical_witness(&self) -> Option<WitnessId> {
        self.context.canonical_witness
    }
    pub fn tags(&self) -> &[String] {
        &self.context.tags
    }

    pub(crate) fn from_error<F: Field>(
        circuit: &Circuit<F>,
        mut error: CircuitError,
        phase: DiagnosticPhase,
    ) -> Self {
        let implicated_witness = error_witness(&error);
        let canonical_witness = implicated_witness.map(|w| {
            circuit
                .witness_rewrite
                .as_ref()
                .map_or(w, |rewrite| w.resolve(rewrite))
        });

        let compiled_op_index = match &phase {
            DiagnosticPhase::Execution { compiled_op_index } => Some(*compiled_op_index),
            DiagnosticPhase::Caller => error_op_id(&error).and_then(|id| {
                circuit.ops.iter().position(|op| {
                    matches!(op,
                    Op::NonPrimitiveOpWithExecutor { op_id, .. } if *op_id == id)
                })
            }),
            DiagnosticPhase::WitnessAliases
            | DiagnosticPhase::WitnessTrace
            | DiagnosticPhase::ConstTrace
            | DiagnosticPhase::PublicTrace
            | DiagnosticPhase::NonPrimitiveTrace { .. } => None,
        };
        let compiled_operation = compiled_op_index.and_then(|index| {
            circuit.ops.get(index).map(|op| CompiledOperation {
                compiled_op_index: index,
                kind: match op {
                    Op::Const { .. } => CompiledOpKind::Const,
                    Op::Public { .. } => CompiledOpKind::Public,
                    Op::Alu { kind, .. } => CompiledOpKind::Alu(*kind),
                    Op::Hint { .. } => CompiledOpKind::Hint,
                    Op::NonPrimitiveOpWithExecutor {
                        executor, op_id, ..
                    } => CompiledOpKind::NonPrimitive {
                        op_id: *op_id,
                        op_type: executor.op_type().clone(),
                    },
                },
            })
        });

        let provenance = circuit.provenance();
        let operation_origins = compiled_operation.as_ref().map_or_else(Vec::new, |op| {
            let mut ids = provenance
                .map_or(&[][..], |p| p.operation_origins(op.compiled_op_index))
                .to_vec();
            ids.sort_unstable();
            ids.dedup();
            ids.into_iter()
                .map(|id| source(provenance, id, true))
                .collect()
        });

        let witness_aliases = canonical_witness.map_or_else(Vec::new, |canonical| {
            let mut ids = provenance
                .map_or(&[][..], |p| p.witness_origins(canonical))
                .to_vec();
            // The public expression map is also useful for manually assembled circuits.
            ids.extend(circuit.expr_to_widx.iter().filter_map(|(expr_id, &wid)| {
                let mapped = circuit
                    .witness_rewrite
                    .as_ref()
                    .map_or(wid, |rewrite| wid.resolve(rewrite));
                (mapped == canonical).then_some(*expr_id)
            }));
            if let CircuitError::WitnessConflict { expr_ids, .. } = &error {
                ids.extend(expr_ids.iter().copied());
            }
            ids.sort_unstable();
            ids.dedup();
            ids.into_iter()
                .map(|id| source(provenance, id, true))
                .collect::<Vec<_>>()
        });

        if let CircuitError::WitnessConflict { expr_ids, .. } = &mut error {
            expr_ids.clear();
            expr_ids.extend(witness_aliases.iter().map(|s| s.expr_id));
        }

        let related_sources = match &error {
            CircuitError::ExprIdNotFound { expr_id } => {
                alloc::vec![source(provenance, *expr_id, true)]
            }
            _ => Vec::new(),
        };
        let mut tags = Vec::new();
        if let Some(CompiledOperation {
            kind: CompiledOpKind::NonPrimitive { op_id, .. },
            ..
        }) = &compiled_operation
        {
            tags.extend(
                circuit
                    .tag_to_op_id
                    .iter()
                    .filter_map(|(tag, id)| (id == op_id).then_some(tag.clone())),
            );
            tags.sort();
            tags.dedup();
        }

        Self {
            error,
            phase,
            context: Box::new(DiagnosticContext {
                compiled_operation,
                implicated_witness,
                canonical_witness,
                operation_origins,
                witness_aliases,
                related_sources,
                tags,
            }),
        }
    }
}

impl<F: Field> Circuit<F> {
    /// Attach demonstrable caller-side context to an existing typed error.
    pub fn diagnose_error(&self, error: CircuitError) -> CircuitDiagnostic {
        CircuitDiagnostic::from_error(self, error, DiagnosticPhase::Caller)
    }
}

fn source(
    provenance: Option<&crate::CircuitProvenance>,
    id: ExprId,
    with_dependencies: bool,
) -> DiagnosticSource {
    let allocation = provenance.and_then(|p| p.allocation(id)).cloned();
    let dependencies = if with_dependencies {
        allocation.as_ref().map_or_else(Vec::new, |entry| {
            entry
                .dependencies
                .iter()
                .map(|group| {
                    group
                        .iter()
                        .map(|dep| source(provenance, *dep, false))
                        .collect()
                })
                .collect()
        })
    } else {
        Vec::new()
    };
    DiagnosticSource {
        expr_id: id,
        allocation,
        dependencies,
    }
}

fn error_witness(error: &CircuitError) -> Option<WitnessId> {
    match error {
        CircuitError::PublicInputNotSet { witness_id }
        | CircuitError::WitnessNotSet { witness_id }
        | CircuitError::UnclaimedPrivateInput { witness_id }
        | CircuitError::UnsourcedStatementExport { witness_id, .. }
        | CircuitError::WitnessIdOutOfBounds { witness_id }
        | CircuitError::WitnessConflict { witness_id, .. }
        | CircuitError::InvalidNonPrimitiveOpInput { witness_id, .. } => Some(*witness_id),
        CircuitError::InvalidBitValue {
            input_witness_id, ..
        }
        | CircuitError::BitDecompositionMismatch {
            input_witness_id, ..
        } => Some(*input_witness_id),
        CircuitError::WitnessNotSetForIndex { index } => u32::try_from(*index).ok().map(WitnessId),
        _ => None,
    }
}

const fn error_op_id(error: &CircuitError) -> Option<NonPrimitiveOpId> {
    match error {
        CircuitError::NonPrimitiveOpWitnessNotSet { operation_index }
        | CircuitError::NonPrimitiveOpMissingPrivateData { operation_index }
        | CircuitError::IncorrectNonPrimitiveOpPrivateData {
            operation_index, ..
        }
        | CircuitError::Poseidon2ChainMissingPreviousState { operation_index }
        | CircuitError::Poseidon1ChainMissingPreviousState { operation_index }
        | CircuitError::Poseidon2MerkleMissingSiblingInput {
            operation_index, ..
        }
        | CircuitError::Poseidon2MissingInput {
            operation_index, ..
        } => Some(*operation_index),
        _ => None,
    }
}

impl fmt::Display for CircuitDiagnostic {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut output = CappedWriter {
            inner: f,
            written: 0,
            omitted: 0,
        };
        self.write_report(&mut output)?;
        output.finish()
    }
}

impl CircuitDiagnostic {
    fn write_report<W: fmt::Write>(&self, f: &mut W) -> fmt::Result {
        match &self.error {
            CircuitError::WitnessConflict {
                witness_id,
                existing,
                new,
                ..
            } => write!(
                f,
                "Witness conflict: WitnessId({witness_id}) already set to {existing}, cannot reassign to {new}"
            )?,
            other => write!(f, "{other}")?,
        }
        write!(f, "\nphase: {:?}", self.phase)?;
        if let Some(op) = &self.context.compiled_operation {
            write!(f, "\ncompiled op #{}: {:?}", op.compiled_op_index, op.kind)?;
        }
        if let Some(witness) = self.context.implicated_witness {
            write!(f, "\nwitness: {witness}")?;
            if let Some(canonical) = self.context.canonical_witness
                && canonical != witness
            {
                write!(f, " (canonical {canonical})")?;
            }
        }
        if !self.context.operation_origins.is_empty() {
            write!(f, "\noriginal operation origins:")?;
            write_sources(f, &self.context.operation_origins)?;
        } else if self.context.compiled_operation.is_some() {
            write!(f, "\noriginal operation origins: unavailable")?;
        }
        if !self.context.witness_aliases.is_empty() {
            write!(f, "\nwitness aliases:")?;
            write_sources(f, &self.context.witness_aliases)?;
        }
        if !self.context.related_sources.is_empty() {
            write!(f, "\nrelated expressions:")?;
            write_sources(f, &self.context.related_sources)?;
        }
        if !self.context.tags.is_empty() {
            write!(f, "\ntags:")?;
            for tag in self.context.tags.iter().take(DISPLAY_LIMIT) {
                write!(f, " {tag}")?;
            }
            write_omitted(f, self.context.tags.len())?;
        }
        Ok(())
    }
}

fn write_sources<W: fmt::Write>(f: &mut W, sources: &[DiagnosticSource]) -> fmt::Result {
    for source in sources.iter().take(DISPLAY_LIMIT) {
        write!(f, "\n  {}", source.expr_id)?;
        if let Some(entry) = &source.allocation {
            write!(f, " {}", entry.alloc_type)?;
            if !entry.label.is_empty() {
                write!(f, " label={:?}", entry.label)?;
            }
            if let Some(scope) = &entry.scope {
                write!(f, " scope={scope:?}")?;
            }
            if !source.dependencies.is_empty() {
                write!(f, " dependencies=")?;
                for (index, group) in source.dependencies.iter().take(DISPLAY_LIMIT).enumerate() {
                    if index != 0 {
                        write!(f, ",")?;
                    }
                    write!(f, "[")?;
                    for (i, dep) in group.iter().take(DISPLAY_LIMIT).enumerate() {
                        if i != 0 {
                            write!(f, ",")?;
                        }
                        write!(f, "{}", dep.expr_id)?;
                    }
                    write_omitted(f, group.len())?;
                    write!(f, "]")?;
                }
                write_omitted(f, source.dependencies.len())?;
            }
        } else {
            write!(f, " (allocation unavailable)")?;
        }
    }
    if sources.len() > DISPLAY_LIMIT {
        write!(f, "\n ")?;
        write_omitted(f, sources.len())?;
    }
    Ok(())
}

fn write_omitted<W: fmt::Write>(f: &mut W, len: usize) -> fmt::Result {
    if len > DISPLAY_LIMIT {
        write!(f, " … (+{} more)", len - DISPLAY_LIMIT)?;
    }
    Ok(())
}

struct CappedWriter<'a, 'b> {
    inner: &'a mut fmt::Formatter<'b>,
    written: usize,
    omitted: usize,
}

impl fmt::Write for CappedWriter<'_, '_> {
    fn write_str(&mut self, text: &str) -> fmt::Result {
        let remaining = DISPLAY_CHAR_LIMIT.saturating_sub(self.written);
        let mut count = 0;
        let mut byte_limit = text.len();
        for (byte_index, _) in text.char_indices() {
            if count == remaining {
                byte_limit = byte_index;
                break;
            }
            count += 1;
        }
        fmt::Write::write_str(self.inner, &text[..byte_limit])?;
        self.written += count;
        self.omitted += text[byte_limit..].chars().count();
        Ok(())
    }
}

impl CappedWriter<'_, '_> {
    fn finish(self) -> fmt::Result {
        if self.omitted > 0 {
            write!(self.inner, "… (+{} characters omitted)", self.omitted)?;
        }
        Ok(())
    }
}

impl Error for CircuitDiagnostic {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(&self.error)
    }
}

#[cfg(test)]
mod tests {
    use alloc::string::ToString;
    use alloc::vec;

    use p3_test_utils::baby_bear_params::BabyBear;

    use super::*;

    #[test]
    fn display_is_unicode_safe_and_structured_aliases_remain_complete() {
        let mut map = hashbrown::HashMap::new();
        for index in (0..32).rev() {
            map.insert(ExprId(index), WitnessId(0));
        }
        let circuit = Circuit::<BabyBear>::new(1, map);
        let report = circuit.diagnose_error(CircuitError::WitnessConflict {
            witness_id: WitnessId(0),
            existing: "λ".repeat(5000),
            new: "β".to_string(),
            expr_ids: vec![],
        });
        assert_eq!(report.witness_aliases().len(), 32);
        assert_eq!(report.witness_aliases()[0].expr_id, ExprId(0));
        assert_eq!(report.witness_aliases()[31].expr_id, ExprId(31));
        assert!(report.error().to_string().chars().count() > 5000);
        let shown = report.to_string();
        assert!(shown.contains("characters omitted"));
        assert!(shown.chars().count() < 4200);
    }
}
