//! Module defining allocation entries for debugging purposes.
//! These complement circuit building by logging all allocations happening
//! within the expression graph.

use alloc::format;
use alloc::vec::Vec;

use crate::ExprId;
use crate::op::NonPrimitiveOpType;

/// Type of allocation for debugging purposes
#[derive(Debug, Clone)]
pub enum AllocationType {
    Public,
    Const,
    Add,
    Sub,
    Mul,
    Div,
    NonPrimitiveOp(NonPrimitiveOpType),
}

/// Detailed allocation entry for debugging
#[derive(Debug, Clone)]
pub struct AllocationEntry {
    /// The expression ID allocated
    pub expr_id: ExprId,
    /// Type of allocation
    pub alloc_type: AllocationType,
    /// User-provided label (if any)
    pub label: &'static str,
    /// Dependencies (for operations)
    pub dependencies: Vec<ExprId>,
}

/// Dump an allocation log (debug builds only).
///
/// Shows all allocations with their types, labels, and dependencies,
/// grouped by allocation type.
#[cfg(debug_assertions)]
pub(crate) fn dump_allocation_log(allocation_log: &[AllocationEntry]) {
    use alloc::string::ToString;

    tracing::debug!("=== Circuit Allocation Log ===");
    tracing::debug!("Total allocations: {}\n", allocation_log.len());

    // Group by type
    let mut publics = Vec::new();
    let mut consts = Vec::new();
    let mut adds = Vec::new();
    let mut subs = Vec::new();
    let mut muls = Vec::new();
    let mut divs = Vec::new();
    let mut non_primitives = Vec::new();

    for entry in allocation_log.iter() {
        match entry.alloc_type {
            AllocationType::Public => publics.push(entry),
            AllocationType::Const => consts.push(entry),
            AllocationType::Add => adds.push(entry),
            AllocationType::Sub => subs.push(entry),
            AllocationType::Mul => muls.push(entry),
            AllocationType::Div => divs.push(entry),
            AllocationType::NonPrimitiveOp(_) => non_primitives.push(entry),
        }
    }

    // Dump all operations per group

    if !publics.is_empty() {
        tracing::debug!("--- Public Inputs ({}) ---", publics.len());
        for entry in publics {
            tracing::debug!("  expr_{} (Public): {}", entry.expr_id.0, entry.label);
        }
        tracing::debug!("");
    }

    if !consts.is_empty() {
        tracing::debug!("--- Constants ({}) ---", consts.len());
        for entry in consts {
            tracing::debug!("  expr_{} (Const): {}", entry.expr_id.0, entry.label);
        }
        tracing::debug!("");
    }

    if !adds.is_empty() {
        tracing::debug!("--- Additions ({}) ---", adds.len());
        for entry in adds {
            if entry.dependencies.len() == 2 {
                tracing::debug!(
                    "  expr_{} = expr_{} + expr_{}: {}",
                    entry.expr_id.0,
                    entry.dependencies[0].0,
                    entry.dependencies[1].0,
                    entry.label
                );
            } else {
                tracing::debug!("  expr_{} (Add): {}", entry.expr_id.0, entry.label);
            }
        }
        tracing::debug!("");
    }

    if !subs.is_empty() {
        tracing::debug!("--- Subtractions ({}) ---", subs.len());
        for entry in subs {
            if entry.dependencies.len() == 2 {
                tracing::debug!(
                    "  expr_{} = expr_{} - expr_{}: {}",
                    entry.expr_id.0,
                    entry.dependencies[0].0,
                    entry.dependencies[1].0,
                    entry.label
                );
            } else {
                tracing::debug!("  expr_{} (Sub): {}", entry.expr_id.0, entry.label);
            }
        }
        tracing::debug!("");
    }

    if !muls.is_empty() {
        tracing::debug!("--- Multiplications ({}) ---", muls.len());
        for entry in muls {
            if entry.dependencies.len() == 2 {
                tracing::debug!(
                    "  expr_{} = expr_{} * expr_{}: {}",
                    entry.expr_id.0,
                    entry.dependencies[0].0,
                    entry.dependencies[1].0,
                    entry.label
                );
            } else {
                tracing::debug!("  expr_{} (Mul): {}", entry.expr_id.0, entry.label);
            }
        }
        tracing::debug!("");
    }

    if !divs.is_empty() {
        tracing::debug!("--- Divisions ({}) ---", divs.len());
        for entry in divs {
            if entry.dependencies.len() == 2 {
                tracing::debug!(
                    "  expr_{} = expr_{} / expr_{}: {}",
                    entry.expr_id.0,
                    entry.dependencies[0].0,
                    entry.dependencies[1].0,
                    entry.label
                );
            } else {
                tracing::debug!("  expr_{} (Div): {}", entry.expr_id.0, entry.label);
            }
        }
        tracing::debug!("");
    }

    if !non_primitives.is_empty() {
        tracing::debug!(
            "--- Non-Primitive Operations ({}) ---",
            non_primitives.len()
        );
        for entry in non_primitives {
            let op_name = match &entry.alloc_type {
                AllocationType::NonPrimitiveOp(op_type) => format!("{:?}", op_type).to_string(),
                _ => "Unknown".to_string(),
            };
            if !entry.dependencies.is_empty() {
                let deps: Vec<_> = entry
                    .dependencies
                    .iter()
                    .map(|e| format!("expr_{}", e.0).to_string())
                    .collect();
                tracing::debug!(
                    "  {} (inputs: [{}]): {}",
                    op_name,
                    deps.join(", "),
                    entry.label
                );
            } else {
                tracing::debug!("  {}: {}", op_name, entry.label);
            }
        }
        tracing::debug!("");
    }

    tracing::debug!("=== End Allocation Log ===");
}
