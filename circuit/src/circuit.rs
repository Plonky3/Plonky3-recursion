use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;
use core::fmt::Debug;
use core::ops::{Add, Mul, Sub};

use hashbrown::HashMap;
use p3_field::Field;
use strum::EnumCount;

use crate::op::{
    NonPrimitiveOpConfig, NonPrimitiveOpType, NonPrimitivePreprocessedMap, Op, PrimitiveOpType,
};
use crate::tables::{CircuitRunner, TraceGeneratorFn};
use crate::types::{ExprId, NonPrimitiveOpId, WitnessId};
use crate::{AluOpKind, CircuitError};

/// Trait encapsulating the required field operations for circuits
pub trait CircuitField:
    Clone
    + Default
    + Add<Output = Self>
    + Sub<Output = Self>
    + Mul<Output = Self>
    + PartialEq
    + Debug
    + Field
{
}

impl<F> CircuitField for F where
    F: Clone
        + Default
        + Add<Output = F>
        + Sub<Output = F>
        + Mul<Output = F>
        + PartialEq
        + Debug
        + Field
{
}

/// Preprocessed data for primitive and non-primitive operation tables.
pub struct PreprocessedColumns<F> {
    pub primitive: Vec<Vec<F>>,
    pub non_primitive: NonPrimitivePreprocessedMap<F>,
    /// Extension degree used for base-field index scaling.
    /// A `WitnessId(n)` is stored as base-field index `n * d` in CTL lookup tuples.
    pub d: usize,
    /// Ext-field read counts per witness index (indexed by `WitnessId.0`).
    ///
    /// `ext_reads[i]` is the number of times `WitnessId(i)` is read by any table
    /// as an extension-field value. This is used by creator tables to set their
    /// signed multiplicity on the `WitnessChecks` bus.
    pub ext_reads: Vec<u32>,
    /// Tracks WitnessIds that are duplicate Poseidon2 rate outputs.
    ///
    /// Due to the circuit optimizer's witness_rewrite deduplication, two distinct Poseidon2
    /// operations can end up sharing the same output WitnessId (when they hash identical inputs).
    /// The FIRST operation is the creator; subsequent ones must be treated as readers (out_ctl=-1).
    ///
    /// `poseidon2_dup_wids[i] = true` means WitnessId(i) is a duplicate Poseidon2 output:
    /// the creator was a previous op. Used by `common.rs` Phase 2 to set out_ctl = -1 instead
    /// of +ext_reads[i].
    pub poseidon2_dup_wids: Vec<bool>,
}

impl<F: Field + Clone> Clone for PreprocessedColumns<F> {
    fn clone(&self) -> Self {
        Self {
            primitive: self.primitive.clone(),
            non_primitive: self.non_primitive.clone(),
            d: self.d,
            ext_reads: self.ext_reads.clone(),
            poseidon2_dup_wids: self.poseidon2_dup_wids.clone(),
        }
    }
}

impl<F: Field> PreprocessedColumns<F> {
    /// Creates an empty [`PreprocessedColumns`] with one primitive entry per [`PrimitiveOpType`]
    /// and extension degree 1 (base field, no index scaling).
    pub fn new() -> Self {
        Self {
            primitive: vec![vec![]; PrimitiveOpType::COUNT],
            non_primitive: NonPrimitivePreprocessedMap::new(),
            d: 1,
            ext_reads: Vec::new(),
            poseidon2_dup_wids: Vec::new(),
        }
    }

    /// Creates an empty [`PreprocessedColumns`] with the given extension degree `d`.
    ///
    /// With `d > 1`, `WitnessId(n)` is stored as base-field index `n * d` in CTL lookup tuples.
    pub fn new_with_d(d: usize) -> Self {
        assert!(d >= 1, "extension degree must be at least 1");
        Self {
            primitive: vec![vec![]; PrimitiveOpType::COUNT],
            non_primitive: NonPrimitivePreprocessedMap::new(),
            d,
            ext_reads: Vec::new(),
            poseidon2_dup_wids: Vec::new(),
        }
    }

    /// Returns the D-scaled base-field index for a given witness ID as a field element.
    ///
    /// `WitnessId(n)` maps to base-field index `n * d`.
    pub fn witness_index_as_field(&self, wid: WitnessId) -> F {
        F::from_u32(wid.0 * self.d as u32)
    }

    /// Increments the ext-field read count for each of the given witness indices.
    pub fn increment_ext_reads(&mut self, wids: &[WitnessId]) {
        for wid in wids {
            let idx = wid.0 as usize;
            if idx >= self.ext_reads.len() {
                self.ext_reads.resize(idx + 1, 0);
            }
            self.ext_reads[idx] += 1;
        }
    }

    /// Extends the preprocessed data of `op_type`'s non-primitive operation
    /// with `wids`'s witness indices (D-scaled). Does NOT increment ext-field read counts.
    ///
    /// Use this for non-primitive OUTPUTS: the table creates these witnesses on the
    /// `WitnessChecks` bus, so they are not readers. The `out_ctl` multiplicity is
    /// set separately by `get_airs_and_degrees_with_prep` based on `ext_reads`.
    pub fn register_non_primitive_output_index(
        &mut self,
        op_type: NonPrimitiveOpType,
        wids: &[WitnessId],
    ) {
        let entry = self.non_primitive.entry(op_type).or_default();
        let d = self.d as u32;
        let wids_field = wids.iter().map(|wid| F::from_u32(wid.0 * d));
        entry.extend(wids_field);
    }

    /// Extends the preprocessed data of `op_type`'s non-primitive operation
    /// with `wids`'s witness indices (D-scaled), and increments their ext-field read counts.
    ///
    /// Use this for non-primitive inputs that the table reads from the `WitnessChecks` bus.
    pub fn register_non_primitive_witness_reads(
        &mut self,
        op_type: NonPrimitiveOpType,
        wids: &[WitnessId],
    ) -> Result<(), CircuitError> {
        let entry = self.non_primitive.entry(op_type).or_default();

        let d = self.d as u32;
        let wids_field = wids.iter().map(|wid| F::from_u32(wid.0 * d));
        entry.extend(wids_field);

        self.increment_ext_reads(wids);

        Ok(())
    }

    /// Extends the preprocessed data of `op_type`'s non-primitive operation
    /// with a single witness index (D-scaled), and increments its ext-field read count.
    pub fn register_non_primitive_witness_read(
        &mut self,
        op_type: NonPrimitiveOpType,
        wid: WitnessId,
    ) -> Result<(), CircuitError> {
        self.register_non_primitive_witness_reads(op_type, &[wid])
    }

    /// Extends the preprocessed data of `op_type`'s primitive operation with `values`.
    /// Does not update read counts.
    pub fn register_primitive_preprocessed_no_read(
        &mut self,
        op_type: PrimitiveOpType,
        values: &[F],
    ) -> Result<(), CircuitError> {
        if self.primitive.len() != PrimitiveOpType::COUNT {
            return Err(CircuitError::InvalidPreprocessing {
                reason: "primitive vector length does not match PrimitiveOpType::COUNT",
            });
        }

        self.primitive[op_type as usize].extend(values);

        Ok(())
    }

    /// Extends the preprocessed data of `op_type`'s non-primitive operation with `values`.
    /// Does not update read counts.
    pub fn register_non_primitive_preprocessed_no_read(
        &mut self,
        op_type: NonPrimitiveOpType,
        values: &[F],
    ) {
        let entry = self.non_primitive.entry(op_type).or_default();
        entry.extend(values);
    }
}

impl<F: Field> Default for PreprocessedColumns<F> {
    fn default() -> Self {
        Self::new()
    }
}

impl<F: Field> PreprocessedColumns<F> {
    pub const fn extension_degree(&self) -> usize {
        self.d
    }
}

/// Static circuit specification containing constraint system and metadata
///
/// This represents the compiled output of a `CircuitBuilder`. It contains:
/// - Primitive operations (add, multiply, subtract, constants, public inputs)
/// - Non-primitive operations (complex operations like MMCS verification)
/// - Public input metadata and witness table structure
///
/// The circuit is static and serializable. Use `.runner()` to create
/// a `CircuitRunner` for execution with specific input values.
#[derive(Debug)]
pub struct Circuit<F> {
    /// Number of witness table rows
    pub witness_count: u32,
    /// Operations in execution order (primitive + non-primitive).
    pub ops: Vec<Op<F>>,
    /// Public input witness indices
    pub public_rows: Vec<WitnessId>,
    /// Total number of public field elements
    pub public_flat_len: usize,
    /// Enabled non-primitive operation types with their respective configuration
    pub enabled_ops: HashMap<NonPrimitiveOpType, NonPrimitiveOpConfig<F>>,
    /// Expression to witness index map
    pub expr_to_widx: HashMap<ExprId, WitnessId>,
    /// Registered non-primitive trace generators.
    pub non_primitive_trace_generators: HashMap<NonPrimitiveOpType, TraceGeneratorFn<F>>,
    /// Sorted keys of `non_primitive_trace_generators` for deterministic iteration without sorting each run.
    pub non_primitive_trace_generator_order: Vec<NonPrimitiveOpType>,
    /// Tag to witness index mapping for probing values by name.
    pub tag_to_witness: HashMap<String, WitnessId>,
    /// Tag to non-primitive operation ID mapping.
    pub tag_to_op_id: HashMap<String, NonPrimitiveOpId>,
    /// After ALU deduplication, duplicate outputs are rewritten to canonical.
    /// This map is used by the runner to fill those slots.
    pub witness_rewrite: Option<HashMap<WitnessId, WitnessId>>,
}

impl<F: Field + Clone> Clone for Circuit<F> {
    fn clone(&self) -> Self {
        Self {
            witness_count: self.witness_count,
            ops: self.ops.clone(),
            public_rows: self.public_rows.clone(),
            public_flat_len: self.public_flat_len,
            enabled_ops: self.enabled_ops.clone(),
            expr_to_widx: self.expr_to_widx.clone(),
            non_primitive_trace_generators: self.non_primitive_trace_generators.clone(),
            non_primitive_trace_generator_order: self.non_primitive_trace_generator_order.clone(),
            tag_to_witness: self.tag_to_witness.clone(),
            tag_to_op_id: self.tag_to_op_id.clone(),
            witness_rewrite: self.witness_rewrite.clone(),
        }
    }
}

impl<F: Field> Circuit<F> {
    /// Create a new circuit with the given witness count and expression to witness index map.
    pub fn new(witness_count: u32, expr_to_widx: HashMap<ExprId, WitnessId>) -> Self {
        Self {
            witness_count,
            ops: Vec::new(),
            public_rows: Vec::new(),
            public_flat_len: 0,
            enabled_ops: HashMap::new(),
            expr_to_widx,
            non_primitive_trace_generators: HashMap::new(),
            non_primitive_trace_generator_order: Vec::new(),
            tag_to_witness: HashMap::new(),
            tag_to_op_id: HashMap::new(),
            witness_rewrite: None,
        }
    }

    /// Generates preprocessed columns for all primitive operation types.
    ///
    /// Returns a [`PreprocessedColumns`] with one primitive entry per [`PrimitiveOpType`]:
    ///
    /// | Index | Operation | Column Layout                                                              | Width (per op) |
    /// |-------|-----------|----------------------------------------------------------------------------|----------------|
    /// | 0     | Const     | `[out_0, out_1, ...]` (D-scaled indices)                                   | 1              |
    /// | 1     | Public    | `[out_0, out_1, ...]` (D-scaled indices)                                   | 1              |
    /// | 2     | Alu       | `[sel_add_vs_mul, sel_bool, sel_muladd, a_idx, b_idx, c_idx, out_idx, a_is_reader, b_is_creator, c_is_reader, out_is_creator]` | 11 |
    ///
    /// Signed multiplicities are not stored here; they are computed in `get_airs_and_degrees_with_prep`
    /// using the `ext_reads` field, which tracks how many times each witness is read.
    ///
    /// Indices in CTL lookups are stored as `WitnessId(n) * d`; use `d = EF::DIMENSION` for extension field.
    pub fn generate_preprocessed_columns(
        &self,
        d: usize,
    ) -> Result<PreprocessedColumns<F>, CircuitError> {
        let mut preprocessed = PreprocessedColumns::new_with_d(d);

        // Track which witnesses have been defined (first-occurrence = creator).
        // Const and Public define their outputs first. ALU ops define their output (forward)
        // or their `b` operand (backward/sub encoding where `out` was already defined).
        let mut defined = alloc::vec![false; self.witness_count as usize];

        // Process each primitive operation.
        for op in &self.ops {
            match op {
                // Const: creates the output witness value. Store D-scaled out index.
                // No ext_reads increment: Const is a creator, not a reader.
                Op::Const { out, .. } => {
                    let idx = preprocessed.witness_index_as_field(*out);
                    preprocessed.primitive[PrimitiveOpType::Const as usize].push(idx);
                    let out_idx = out.0 as usize;
                    if out_idx >= defined.len() {
                        defined.resize(out_idx + 1, false);
                    }
                    defined[out_idx] = true;
                }
                // Public: creates the output witness value. Store D-scaled out index.
                // No ext_reads increment: Public is a creator, not a reader.
                Op::Public { out, .. } => {
                    let idx = preprocessed.witness_index_as_field(*out);
                    preprocessed.primitive[PrimitiveOpType::Public as usize].push(idx);
                    let out_idx = out.0 as usize;
                    if out_idx >= defined.len() {
                        defined.resize(out_idx + 1, false);
                    }
                    defined[out_idx] = true;
                }
                // Unified ALU operations with selectors for operation kind.
                //
                // Preprocessed per op (12 values, no multiplicities):
                // [sel_add_vs_mul, sel_bool, sel_muladd, sel_horner, a_idx, b_idx, c_idx, out_idx,
                //  a_is_reader, b_is_creator, c_is_reader, out_is_creator]
                //
                // a_is_reader: 1 if `a` is a constrained witness (defined by Const/Public/ALU/Poseidon2).
                // c_is_reader: 1 if `c` is a constrained witness.
                // 0 means unconstrained (Unconstrained NonPrimitive op output): no bus contribution.
                //
                // Three cases based on which operands are already defined:
                //
                // Forward (out not yet defined): b_is_creator=0, out_is_creator=1.
                //   Creator: out. Readers: b (always), a (if a_is_reader), c (if c_is_reader).
                //
                // Backward (out defined, b not yet defined, e.g. backward-encoded Sub):
                //   b_is_creator=1, out_is_creator=0. Creator: b.
                //   Readers: out (always), a (if a_is_reader), c (if c_is_reader).
                //
                // All-reader (out and b both already defined, e.g. assert_zero rewrite):
                //   b_is_creator=0, out_is_creator=0. No creator.
                //   Readers: b, out (always), a (if a_is_reader), c (if c_is_reader).
                Op::Alu {
                    kind, a, b, c, out, ..
                } => {
                    let (sel_add_vs_mul, sel_bool, sel_muladd, sel_horner) = match kind {
                        AluOpKind::Add => (F::ONE, F::ZERO, F::ZERO, F::ZERO),
                        AluOpKind::Mul => (F::ZERO, F::ZERO, F::ZERO, F::ZERO),
                        AluOpKind::BoolCheck => (F::ZERO, F::ONE, F::ZERO, F::ZERO),
                        AluOpKind::MulAdd => (F::ZERO, F::ZERO, F::ONE, F::ZERO),
                        AluOpKind::HornerAcc => (F::ZERO, F::ZERO, F::ZERO, F::ONE),
                    };
                    let c_wid = c.unwrap_or(WitnessId(0));
                    let d_u32 = d as u32;

                    let out_already_defined =
                        (out.0 as usize) < defined.len() && defined[out.0 as usize];
                    let b_already_defined = (b.0 as usize) < defined.len() && defined[b.0 as usize];

                    // Determine whether a and c are constrained witnesses (have creator AIRs).
                    // Unconstrained witnesses are never marked defined; their reads don't
                    // contribute to the WitnessChecks bus.
                    let a_is_reader = (a.0 as usize) < defined.len() && defined[a.0 as usize];
                    let c_is_reader =
                        (c_wid.0 as usize) < defined.len() && defined[c_wid.0 as usize];

                    let (b_is_creator, out_is_creator) = if !out_already_defined {
                        (F::ZERO, F::ONE) // forward: out is new creator
                    } else if !b_already_defined {
                        (F::ONE, F::ZERO) // backward: b is new creator
                    } else {
                        (F::ZERO, F::ZERO) // all-reader: no new creator
                    };

                    preprocessed.primitive[PrimitiveOpType::Alu as usize].extend([
                        sel_add_vs_mul,
                        sel_bool,
                        sel_muladd,
                        sel_horner,
                        F::from_u32(a.0 * d_u32),
                        F::from_u32(b.0 * d_u32),
                        F::from_u32(c_wid.0 * d_u32),
                        F::from_u32(out.0 * d_u32),
                        if a_is_reader { F::ONE } else { F::ZERO },
                        b_is_creator,
                        if c_is_reader { F::ONE } else { F::ZERO },
                        out_is_creator,
                    ]);

                    if !out_already_defined {
                        // Forward: out is the creator, b is always a reader.
                        // a and c contribute to ext_reads only if they are constrained.
                        let out_idx = out.0 as usize;
                        if out_idx >= defined.len() {
                            defined.resize(out_idx + 1, false);
                        }
                        defined[out_idx] = true;
                        let mut readers = alloc::vec![*b];
                        if a_is_reader {
                            readers.push(*a);
                        }
                        if c_is_reader {
                            readers.push(c_wid);
                        }
                        preprocessed.increment_ext_reads(&readers);
                    } else if !b_already_defined {
                        // Backward: b is the creator, out is always a reader.
                        // a and c contribute to ext_reads only if they are constrained.
                        let b_idx = b.0 as usize;
                        if b_idx >= defined.len() {
                            defined.resize(b_idx + 1, false);
                        }
                        defined[b_idx] = true;
                        let mut readers = alloc::vec![*out];
                        if a_is_reader {
                            readers.push(*a);
                        }
                        if c_is_reader {
                            readers.push(c_wid);
                        }
                        preprocessed.increment_ext_reads(&readers);
                    } else {
                        // All-reader: b and out are always readers.
                        // a and c contribute to ext_reads only if they are constrained.
                        let mut readers = alloc::vec![*b, *out];
                        if a_is_reader {
                            readers.push(*a);
                        }
                        if c_is_reader {
                            readers.push(c_wid);
                        }
                        preprocessed.increment_ext_reads(&readers);
                    }
                }
                Op::NonPrimitiveOpWithExecutor {
                    executor,
                    inputs,
                    outputs,
                    ..
                } => {
                    executor.preprocess(inputs, outputs, &mut preprocessed)?;

                    // Mark Poseidon2 rate outputs as 'defined': they are created on the
                    // WitnessChecks bus by the Poseidon2 AIR, so subsequent ALU ops that
                    // read them are constrained readers (mult = -1).
                    //
                    // The circuit optimizer's witness_rewrite deduplication can cause two
                    // Poseidon2 ops to share the same output WitnessId (when hashing the same
                    // inputs). The FIRST op is the creator; subsequent ops are readers. Duplicates
                    // are recorded in `preprocessed.poseidon2_dup_wids` so that Phase 2 in
                    // common.rs can set out_ctl = -1 (reader) instead of +ext_reads (creator).
                    //
                    // Unconstrained ops have no AIR; their outputs remain undefined so
                    // ALU reads are treated as unconstrained (mult = 0, no bus lookup).
                    match executor.op_type() {
                        NonPrimitiveOpType::Poseidon2Perm(_) => {
                            for out_limb in outputs.iter().take(2) {
                                for wid in out_limb {
                                    let wid_idx = wid.0 as usize;
                                    if wid_idx < defined.len() && defined[wid_idx] {
                                        // Duplicate: a previous Poseidon2 op already created
                                        // this WitnessId. Record it as a duplicate reader.
                                        let dup_len = preprocessed.poseidon2_dup_wids.len();
                                        if wid_idx >= dup_len {
                                            preprocessed
                                                .poseidon2_dup_wids
                                                .resize(wid_idx + 1, false);
                                        }
                                        preprocessed.poseidon2_dup_wids[wid_idx] = true;
                                        // Increment ext_reads: this op reads the witness.
                                        preprocessed.increment_ext_reads(&[*wid]);
                                    } else {
                                        // First occurrence: mark as defined (creator).
                                        if wid_idx >= defined.len() {
                                            defined.resize(wid_idx + 1, false);
                                        }
                                        defined[wid_idx] = true;
                                    }
                                }
                            }
                        }
                        NonPrimitiveOpType::Unconstrained => {}
                    }
                }
            }
        }

        // Ensure ext_reads covers at least all witnesses.
        let size = self.witness_count as usize;
        if preprocessed.ext_reads.len() < size {
            preprocessed.ext_reads.resize(size, 0);
        }

        Ok(preprocessed)
    }
}

impl<F: CircuitField> Circuit<F> {
    /// Create a circuit runner for execution and trace generation
    pub fn runner(self) -> CircuitRunner<F> {
        CircuitRunner::new(self)
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec;

    use hashbrown::HashMap;
    use p3_baby_bear::BabyBear;
    use p3_field::PrimeCharacteristicRing;
    use strum::EnumCount;

    use super::*;
    use crate::op::PrimitiveOpType;
    use crate::types::WitnessId;

    type F = BabyBear;

    fn make_circuit(ops: Vec<Op<F>>) -> Circuit<F> {
        let mut circuit = Circuit::new(0, HashMap::new());
        circuit.ops = ops;
        circuit
    }

    #[test]
    fn test_empty_circuit() {
        let mut circuit: Circuit<F> = make_circuit(vec![]);
        circuit.witness_count = 1;
        let result = circuit.generate_preprocessed_columns(1).unwrap();

        assert_eq!(result.primitive.len(), PrimitiveOpType::COUNT);
        assert!(result.primitive[PrimitiveOpType::Const as usize].is_empty());
        assert!(result.primitive[PrimitiveOpType::Public as usize].is_empty());
        assert!(result.primitive[PrimitiveOpType::Alu as usize].is_empty());
        // ext_reads sized to at least witness_count
        assert_eq!(result.ext_reads.len(), 1);
    }

    #[test]
    fn test_mixed_operations() {
        // Test covering various operation types and behaviors:
        // - Each operation type populates its correct column
        // - ext_reads tracks ALU input reads correctly
        // - Column data preserves operation order
        let ops = vec![
            Op::Const {
                out: WitnessId(0),
                val: F::from_u64(100),
            },
            Op::Public {
                out: WitnessId(1),
                public_pos: 0,
            },
            Op::Const {
                out: WitnessId(2),
                val: F::from_u64(200),
            },
            Op::add(WitnessId(0), WitnessId(1), WitnessId(3)),
            Op::add(WitnessId(3), WitnessId(2), WitnessId(4)),
            Op::mul(WitnessId(4), WitnessId(2), WitnessId(5)),
        ];

        let circuit = make_circuit(ops);
        let result = circuit.generate_preprocessed_columns(1).unwrap();

        // Const column: D-scaled output indices in order (D=1, no scaling)
        assert_eq!(
            result.primitive[PrimitiveOpType::Const as usize],
            vec![F::ZERO, F::from_u32(2)]
        );

        // Public column: D-scaled output index
        assert_eq!(
            result.primitive[PrimitiveOpType::Public as usize],
            vec![F::from_u32(1)]
        );

        // ALU column: [sel1, sel2, sel3, sel4, a, b, c, out, a_is_reader, b_is_creator, c_is_reader, out_is_creator] per op
        // All operands are Const/Public defined: a_is_reader=1, c_is_reader=1. All forward: out_is_creator=1.
        let expected_alu = vec![
            // add(0, 1, 3): forward, a=0(defined), c=0(defined) → a_is_reader=1, c_is_reader=1
            F::ONE,
            F::ZERO,
            F::ZERO,
            F::ZERO,
            F::ZERO,
            F::from_u32(1),
            F::ZERO,
            F::from_u32(3),
            F::ONE,
            F::ZERO,
            F::ONE,
            F::ONE,
            // add(3, 2, 4): forward, a=3(defined by prev ALU), c=0(defined) → a_is_reader=1, c_is_reader=1
            F::ONE,
            F::ZERO,
            F::ZERO,
            F::ZERO,
            F::from_u32(3),
            F::from_u32(2),
            F::ZERO,
            F::from_u32(4),
            F::ONE,
            F::ZERO,
            F::ONE,
            F::ONE,
            // mul(4, 2, 5): forward, a=4(defined by prev ALU), c=0(defined) → a_is_reader=1, c_is_reader=1
            F::ZERO,
            F::ZERO,
            F::ZERO,
            F::ZERO, // sel_horner
            F::from_u32(4),
            F::from_u32(2),
            F::ZERO,
            F::from_u32(5),
            F::ONE,
            F::ZERO,
            F::ONE,
            F::ONE,
        ];
        assert_eq!(
            result.primitive[PrimitiveOpType::Alu as usize],
            expected_alu
        );

        // ext_reads[i] = number of times WitnessId(i) is read by ALU inputs (a, b, c).
        // Const/Public outputs are NOT reads. ALU outputs are NOT reads.
        // add(0, 1, 3): reads 0(a), 1(b), 0(c=default)
        // add(3, 2, 4): reads 3(a), 2(b), 0(c=default)
        // mul(4, 2, 5): reads 4(a), 2(b), 0(c=default)
        // Index 0: 1(a) + 1(c_default) + 1(c_default) + 1(c_default) = 4? Wait:
        // add(0,1,3): a=0, b=1, c=WitnessId(0) → reads 0,1,0
        // add(3,2,4): a=3, b=2, c=WitnessId(0) → reads 3,2,0
        // mul(4,2,5): a=4, b=2, c=WitnessId(0) → reads 4,2,0
        // Index 0: 3 reads (a from op1 + c_default from all 3 ops = 1+3=4? No: a=0 for op1, plus c=0 for ops 1,2,3)
        // Actually op1: a=WitnessId(0), c=WitnessId(0) → 2 reads for wid 0
        // op2: a=WitnessId(3), c=WitnessId(0) → 1 read for wid 0
        // op3: a=WitnessId(4), c=WitnessId(0) → 1 read for wid 0
        // Total reads for wid 0: 2 + 1 + 1 = 4
        assert_eq!(result.ext_reads[0], 4); // WitnessId(0): a in op1, c-default in all 3 ops
        assert_eq!(result.ext_reads[1], 1); // WitnessId(1): b in op1
        assert_eq!(result.ext_reads[2], 2); // WitnessId(2): b in op2, b in op3
        assert_eq!(result.ext_reads[3], 1); // WitnessId(3): a in op2
        assert_eq!(result.ext_reads[4], 1); // WitnessId(4): a in op3
        // WitnessId(5) is created by mul output - not read
    }

    #[test]
    fn test_input_indices_contribute_to_ext_reads() {
        // Ensures input indices are tracked for ext_reads
        let ops = vec![Op::add(
            WitnessId(0),
            WitnessId(15), // Highest index is an input, not output
            WitnessId(5),
        )];

        let mut circuit = make_circuit(ops);
        circuit.witness_count = 16;
        let result = circuit.generate_preprocessed_columns(1).unwrap();

        // add(0, 15, 5): a=WitnessId(0) (undefined), c=WitnessId(0) (undefined) → a_is_reader=0, c_is_reader=0
        // Only b=WitnessId(15) is counted (always a reader in forward case).
        assert_eq!(result.ext_reads[0], 0); // a and c_default: undefined → no ext_reads increment
        assert_eq!(result.ext_reads[15], 1); // b: always counted as reader
        // output (5) is not a read
        assert_eq!(result.ext_reads[5], 0);
    }

    #[test]
    fn test_muladd_operation() {
        // Test the MulAdd operation preprocessed format
        let ops = vec![
            Op::Const {
                out: WitnessId(0),
                val: F::from_u64(3),
            },
            Op::Const {
                out: WitnessId(1),
                val: F::from_u64(5),
            },
            Op::Const {
                out: WitnessId(2),
                val: F::from_u64(7),
            },
            Op::mul_add(WitnessId(0), WitnessId(1), WitnessId(2), WitnessId(3)), // 3*5+7=22
        ];

        let circuit = make_circuit(ops);
        let result = circuit.generate_preprocessed_columns(1).unwrap();

        // ALU column for MulAdd (forward): [sel1, sel2, sel3, sel_horner, a, b, c, out, a_is_reader, b_is_creator, c_is_reader, out_is_creator]
        // a=0(defined), c=2(defined) → a_is_reader=1, c_is_reader=1
        let expected_alu = vec![
            F::ZERO,
            F::ZERO,
            F::ONE,
            F::ZERO, // sel_horner
            F::ZERO,
            F::from_u32(1),
            F::from_u32(2),
            F::from_u32(3),
            F::ONE,
            F::ZERO,
            F::ONE,
            F::ONE, // a_is_reader=1, b_is_creator=0, c_is_reader=1, out_is_creator=1
        ];
        assert_eq!(
            result.primitive[PrimitiveOpType::Alu as usize],
            expected_alu
        );

        // ext_reads: mul_add(0,1,2,3) reads 0(a), 1(b), 2(c); creates 3(out).
        assert_eq!(result.ext_reads[0], 1); // WitnessId(0): a
        assert_eq!(result.ext_reads[1], 1); // WitnessId(1): b
        assert_eq!(result.ext_reads[2], 1); // WitnessId(2): c
        // WitnessId(3) is created (out), not read
    }
}
