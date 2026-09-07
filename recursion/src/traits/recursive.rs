use alloc::vec;
use alloc::vec::Vec;

use p3_circuit::CircuitBuilder;
use p3_field::Field;
use p3_lookup::LookupProtocol;
use p3_lookup::logup::LogUpGadget;

use crate::Target;
use crate::verifier::VerificationError;

/// Trait for converting a non-recursive type into its circuit representation.
///
/// Types implementing this trait can be used in recursive verification circuits.
/// The trait handles allocation of circuit targets and extraction of field element values.
pub trait Recursive<F: Field> {
    /// The non-recursive type associated with this recursive type.
    type Input;

    /// Creates a new instance of the recursive type by allocating targets in the circuit.
    ///
    /// This method should allocate all necessary public/private inputs and return
    /// a structure containing the allocated targets.
    ///
    /// # Parameters
    /// - `circuit`: Circuit builder to allocate targets in
    /// - `input`: The non-recursive input (used only for structure, not values)
    fn new(circuit: &mut CircuitBuilder<F>, input: &Self::Input) -> Self;

    /// Extracts private field element values from the input.
    ///
    /// Values returned here will be used to populate private inputs during execution.
    /// Default implementation returns an empty vector (no private inputs).
    ///
    /// # Parameters
    /// - `input`: The non-recursive input to extract private values from
    fn get_private_values(_input: &Self::Input) -> Vec<F> {
        vec![]
    }

    /// Extracts public field element values from the input.
    ///
    /// Values returned here will be used to populate public inputs during execution.
    /// The order must match the order in which targets were allocated in `new()`.
    ///
    /// # Parameters
    /// - `input`: The non-recursive input to extract public values from
    fn get_values(input: &Self::Input) -> Vec<F>;
}

/// Explicit, trusted semantic contract for reusing a recursive target shape.
///
/// Equal shapes must guarantee that the two native inputs select exactly the same
/// input-dependent allocations, branches, loop counts, constants, layouts, and runtime value
/// extraction boundaries used by both target construction and recursive verification. A native
/// scalar, enum discriminant, or other value belongs in the shape whenever it selects compiled
/// circuit behavior, even if it looks like witness data. Only values whose changes leave all of
/// those behaviors unchanged are dynamic witnesses and may be excluded.
///
/// Shape capture must be a pure inspection of the native input. It must not pack values, allocate
/// a trial circuit, or recover/replay a transcript. Malformed native structures should be rejected
/// here before target allocation. Implementing this trait for a custom recursive target is an
/// explicit opt-in whose completeness is trusted in the same way as the target's recursive
/// verification implementation.
pub trait PreparedRecursive<F: Field>: Recursive<F> {
    /// Native semantic shape used to decide whether a prepared circuit may be reused.
    type Shape: Clone + PartialEq;

    /// Capture the complete reuse-relevant native shape under the contract above.
    fn input_shape(input: &Self::Input) -> Result<Self::Shape, VerificationError>;
}

pub trait RecursiveLookupGadget<F: Field>: LookupProtocol {
    /// Enforce the single-terminal LogUp cross-AIR check: the sum of every present per-AIR
    /// terminal must be zero.
    fn verify_terminal_sum_circuit(&self, circuit: &mut CircuitBuilder<F>, terminals: &[Target]);
}

impl<F: Field> RecursiveLookupGadget<F> for LogUpGadget {
    fn verify_terminal_sum_circuit(&self, circuit: &mut CircuitBuilder<F>, terminals: &[Target]) {
        let mut total = circuit.define_const(F::ZERO);
        for terminal in terminals {
            total = circuit.add(total, *terminal);
        }

        circuit.assert_zero(total);
    }
}
