//! Module defining allocation entries for debugging purposes.
//! These complement circuit building by logging all allocations happening
//! within the expression graph.

use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use hashbrown::HashSet;

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
    HornerAcc,
    NonPrimitiveOp(NonPrimitiveOpType),
    NonPrimitiveOutput,
    WitnessHint,
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
    /// Dependencies for this entry, i.e. the expressions that this entry depends on.
    pub dependencies: Vec<Vec<ExprId>>,
    /// Scope/sub-circuit this allocation belongs to (if any)
    pub scope: Option<String>,
}

/// Look up allocation info for specific ExprIds and dump to debug log.
///
/// This is useful for debugging WitnessConflict errors where two ExprIds
/// have been merged to the same WitnessId.
pub fn dump_expr_ids(allocation_log: &[AllocationEntry], expr_ids: &[ExprId]) {
    tracing::debug!("=== Allocation Info for ExprIds {:?} ===", expr_ids);
    for expr_id in expr_ids {
        if let Some(entry) = allocation_log.iter().find(|e| e.expr_id == *expr_id) {
            tracing::debug!(
                "  ExprId({}) = {:?}, label='{}', scope={:?}, deps={:?}",
                entry.expr_id.0,
                entry.alloc_type,
                entry.label,
                entry.scope,
                entry.dependencies
            );
        } else {
            tracing::debug!("  ExprId({}) not found in allocation log", expr_id.0);
        }
    }
    tracing::debug!("=== End ExprId Info ===\n");
}

/// Dump an allocation log (debug builds only).
///
/// Shows all allocations with their types, labels, and dependencies,
/// grouped by allocation type.
pub(crate) fn dump_allocation_log(allocation_log: &[AllocationEntry]) {
    tracing::debug!("=== Circuit Allocation Log ===");
    tracing::debug!("Total allocations: {}\n", allocation_log.len());

    let all_scopes = list_scopes(allocation_log);

    for scope in all_scopes {
        dump_allocation_log_scope(allocation_log, Some(&scope));
    }

    // Dump also allocations that do not fall under a particular scope
    dump_allocation_log_scope(allocation_log, None);

    tracing::debug!("=== End Allocation Log ===\n");
}

/// Dump an allocation log filtered by scope (debug builds only).
///
/// Shows only allocations within the specified scope, grouped by allocation type.
pub(crate) fn dump_allocation_log_scope(allocation_log: &[AllocationEntry], scope: Option<&str>) {
    let filtered: Vec<_> = allocation_log
        .iter()
        .filter(|e| e.scope == scope.map(|s| s.to_string()))
        .cloned()
        .collect();

    let scope_name = scope.unwrap_or("main");

    if filtered.is_empty() {
        tracing::debug!("\nScope '{}' has no allocations\n", scope_name);
        return;
    }

    tracing::debug!("=== Allocation Log for scope '{}' ===", scope_name);
    tracing::debug!("Total allocations in scope: {}\n", filtered.len());

    dump_internal_log(&filtered);

    tracing::debug!("=== End Scope Log ===\n");
}

fn dump_internal_log(allocation_log: &[AllocationEntry]) {
    // Group by type
    let mut publics = Vec::new();
    let mut consts = Vec::new();
    let mut adds = Vec::new();
    let mut subs = Vec::new();
    let mut muls = Vec::new();
    let mut divs = Vec::new();
    let mut horner_accs = Vec::new();
    let mut non_primitives = Vec::new();
    let mut witness_hints = Vec::new();

    fn display_label(label: &str) -> String {
        if label.is_empty() {
            "".to_string()
        } else {
            format!(": {label}")
        }
    }

    for entry in allocation_log {
        match entry.alloc_type {
            AllocationType::Public => publics.push(entry),
            AllocationType::Const => consts.push(entry),
            AllocationType::Add => adds.push(entry),
            AllocationType::Sub => subs.push(entry),
            AllocationType::Mul => muls.push(entry),
            AllocationType::Div => divs.push(entry),
            AllocationType::HornerAcc => horner_accs.push(entry),
            AllocationType::NonPrimitiveOp(_) | AllocationType::NonPrimitiveOutput => {
                non_primitives.push(entry);
            }
            AllocationType::WitnessHint => witness_hints.push(entry),
        }
    }

    // Dump all operations per group

    if !publics.is_empty() {
        tracing::debug!("--- Public Inputs ({}) ---", publics.len());
        for entry in publics {
            tracing::debug!(
                "  expr_{} (Public){}",
                entry.expr_id.0,
                display_label(entry.label)
            );
        }
        tracing::debug!("");
    }

    if !consts.is_empty() {
        tracing::debug!("--- Constants ({}) ---", consts.len());
        for entry in consts {
            tracing::debug!(
                "  expr_{} (Const){}",
                entry.expr_id.0,
                display_label(entry.label)
            );
        }
        tracing::debug!("");
    }

    if !adds.is_empty() {
        tracing::debug!("--- Additions ({}) ---", adds.len());
        for entry in adds {
            if entry.dependencies.len() == 2 {
                tracing::debug!(
                    "  expr_{} = expr_{} + expr_{}{}",
                    entry.expr_id.0,
                    entry.dependencies[0][0].0,
                    entry.dependencies[1][0].0,
                    display_label(entry.label)
                );
            } else {
                tracing::debug!(
                    "  expr_{} (Add){}",
                    entry.expr_id.0,
                    display_label(entry.label)
                );
            }
        }
        tracing::debug!("");
    }

    if !subs.is_empty() {
        tracing::debug!("--- Subtractions ({}) ---", subs.len());
        for entry in subs {
            if entry.dependencies.len() == 2 {
                tracing::debug!(
                    "  expr_{} = expr_{} - expr_{}{}",
                    entry.expr_id.0,
                    entry.dependencies[0][0].0,
                    entry.dependencies[1][0].0,
                    display_label(entry.label)
                );
            } else {
                tracing::debug!(
                    "  expr_{} (Sub){}",
                    entry.expr_id.0,
                    display_label(entry.label)
                );
            }
        }
        tracing::debug!("");
    }

    if !muls.is_empty() {
        tracing::debug!("--- Multiplications ({}) ---", muls.len());
        for entry in muls {
            if entry.dependencies.len() == 2 {
                tracing::debug!(
                    "  expr_{} = expr_{} * expr_{}{}",
                    entry.expr_id.0,
                    entry.dependencies[0][0].0,
                    entry.dependencies[1][0].0,
                    display_label(entry.label)
                );
            } else {
                tracing::debug!(
                    "  expr_{} (Mul){}",
                    entry.expr_id.0,
                    display_label(entry.label)
                );
            }
        }
        tracing::debug!("");
    }

    if !divs.is_empty() {
        tracing::debug!("--- Divisions ({}) ---", divs.len());
        for entry in divs {
            if entry.dependencies.len() == 2 {
                tracing::debug!(
                    "  expr_{} = expr_{} / expr_{}{}",
                    entry.expr_id.0,
                    entry.dependencies[0][0].0,
                    entry.dependencies[1][0].0,
                    display_label(entry.label)
                );
            } else {
                tracing::debug!(
                    "  expr_{} (Div){}",
                    entry.expr_id.0,
                    display_label(entry.label)
                );
            }
        }
        tracing::debug!("");
    }

    if !horner_accs.is_empty() {
        tracing::debug!("--- Horner Accumulator Steps ({}) ---", horner_accs.len());
        for entry in horner_accs {
            tracing::debug!(
                "  expr_{} (HornerAcc){}",
                entry.expr_id.0,
                display_label(entry.label)
            );
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
                AllocationType::NonPrimitiveOp(op_type) => format!("{op_type:?}").to_string(),
                AllocationType::NonPrimitiveOutput => "NonPrimitiveOutput".to_string(),
                _ => "Unknown".to_string(),
            };
            if !entry.dependencies.is_empty() {
                let deps: Vec<_> = entry
                    .dependencies
                    .iter()
                    .flatten()
                    .map(|e| format!("expr_{}", e.0))
                    .collect();
                tracing::debug!(
                    "  {} (inputs: [{}]){}",
                    op_name,
                    deps.join(", "),
                    display_label(entry.label)
                );
            } else {
                tracing::debug!("  {}{}", op_name, display_label(entry.label));
            }
        }
        tracing::debug!("");
    }

    if !witness_hints.is_empty() {
        tracing::debug!("--- Witness Hints ({}) ---", witness_hints.len());
        for entry in witness_hints {
            tracing::debug!(
                "  expr_{} (WitnessHint){}",
                entry.expr_id.0,
                display_label(entry.label)
            );
        }
        tracing::debug!("");
    }
}

/// List all unique scopes present in the allocation log.
pub(crate) fn list_scopes(allocation_log: &[AllocationEntry]) -> Vec<String> {
    let mut scopes = HashSet::new();
    for entry in allocation_log {
        if let Some(scope) = &entry.scope {
            scopes.insert(scope.clone());
        }
    }

    let mut scope_list: Vec<_> = scopes.into_iter().collect();
    scope_list.sort_unstable();
    scope_list
}
