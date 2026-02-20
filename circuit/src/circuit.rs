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
}

impl<F: Field> PreprocessedColumns<F> {
    /// Creates an empty [`PreprocessedColumns`] with one primitive entry per [`PrimitiveOpType`].
    pub fn new() -> Self {
        Self {
            primitive: vec![vec![]; PrimitiveOpType::COUNT],
            non_primitive: NonPrimitivePreprocessedMap::new(),
        }
    }

    /// Updates the witness table multiplicities for all the given witness indices.
    pub fn update_witness_multiplicities(
        &mut self,
        wids: &[WitnessId],
    ) -> Result<(), CircuitError> {
        if self.primitive.len() != PrimitiveOpType::COUNT {
            return Err(CircuitError::InvalidPreprocessing {
                reason: "primitive vector length does not match PrimitiveOpType::COUNT",
            });
        }

        const WITNESS_TABLE_IDX: usize = PrimitiveOpType::Witness as usize;
        for wid in wids {
            let idx = wid.0 as usize;
            if idx >= self.primitive[WITNESS_TABLE_IDX].len() {
                self.primitive[WITNESS_TABLE_IDX].resize(idx + 1, F::ZERO);
            }
            self.primitive[WITNESS_TABLE_IDX][idx] += F::ONE;
        }
        Ok(())
    }

    /// Extends the preprocessed data of `op_type`'s primitive operation
    /// with `wids`'s witness indices, and updates the witness multiplicities.
    pub fn register_primitive_witness_reads(
        &mut self,
        op_type: PrimitiveOpType,
        wids: &[WitnessId],
    ) -> Result<(), CircuitError> {
        if matches!(op_type, PrimitiveOpType::Witness) {
            return Err(CircuitError::InvalidPreprocessing {
                reason: "Witness reads cannot be made from the Witness bus",
            });
        }

        if self.primitive.len() != PrimitiveOpType::COUNT {
            return Err(CircuitError::InvalidPreprocessing {
                reason: "primitive vector length does not match PrimitiveOpType::COUNT",
            });
        }

        let wids_field = wids.iter().map(|wid| F::from_u32(wid.0));
        self.primitive[op_type as usize].extend(wids_field);

        self.update_witness_multiplicities(wids)?;

        Ok(())
    }

    /// Extends the preprocessed data of `op_type`'s non-primitive operation
    /// with `wids`'s witness indices, and updates the witness multiplicities.
    pub fn register_non_primitive_witness_reads(
        &mut self,
        op_type: NonPrimitiveOpType,
        wids: &[WitnessId],
    ) -> Result<(), CircuitError> {
        let entry = self.non_primitive.entry(op_type).or_default();

        let wids_field = wids.iter().map(|wid| F::from_u32(wid.0));
        entry.extend(wids_field);

        self.update_witness_multiplicities(wids)?;

        Ok(())
    }

    /// Extends the preprocessed data of `op_type`'s primitive operation
    /// with `wid`'s witness index, and updates the witness multiplicity.
    pub fn register_primitive_witness_read(
        &mut self,
        op_type: PrimitiveOpType,
        wid: WitnessId,
    ) -> Result<(), CircuitError> {
        self.register_primitive_witness_reads(op_type, &[wid])
    }

    /// Extends the preprocessed data of `op_type`'s non-primitive operation
    /// with `wid`'s witness index, and updates the witness multiplicity.
    pub fn register_non_primitive_witness_read(
        &mut self,
        op_type: NonPrimitiveOpType,
        wid: WitnessId,
    ) -> Result<(), CircuitError> {
        self.register_non_primitive_witness_reads(op_type, &[wid])
    }

    /// Extends the preprocessed data of `op_type`'s primitive operation with `values`.
    /// Does not update witness multiplicities.
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
        if matches!(op_type, PrimitiveOpType::Witness) {
            return Err(CircuitError::InvalidPreprocessing {
                reason: "cannot use register_primitive_preprocessed_no_read for Witness table",
            });
        }

        self.primitive[op_type as usize].extend(values);

        Ok(())
    }

    /// Extends the preprocessed data of `op_type`'s non-primitive operation with `values`.
    /// Does not update witness multiplicities.
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
    /// Tag to witness index mapping for probing values by name.
    pub tag_to_witness: HashMap<String, WitnessId>,
    /// Tag to non-primitive operation ID mapping.
    pub tag_to_op_id: HashMap<String, NonPrimitiveOpId>,
    /// Witness aliases produced by constant folding.
    /// Each `(dst, src)` pair means `witness[dst]` should be copied from `witness[src]`
    /// after all ops have executed, before trace building.
    pub witness_aliases: Vec<(WitnessId, WitnessId)>,
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
            tag_to_witness: self.tag_to_witness.clone(),
            tag_to_op_id: self.tag_to_op_id.clone(),
            witness_aliases: self.witness_aliases.clone(),
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
            tag_to_witness: HashMap::new(),
            tag_to_op_id: HashMap::new(),
            witness_aliases: Vec::new(),
        }
    }

    /// Generates preprocessed columns for all primitive operation types.
    ///
    /// Returns a [`PreprocessedColumns`] with one primitive entry per [`PrimitiveOpType`]:
    ///
    /// | Index | Operation | Column Layout                                                       | Width (per op) |
    /// |-------|-----------|---------------------------------------------------------------------|----------------|
    /// | 0     | Witness   | `[mul_0, mul_1, ...]`                                               | 1              |
    /// | 1     | Const     | `[out_0, out_1, ...]`                                               | 1              |
    /// | 2     | Public    | `[out_0, out_1, ...]`                                               | 1              |
    /// | 3     | Alu       | `[sel_add_vs_mul, sel_bool, sel_muladd, a_idx, b_idx, c_idx, out_idx, ...]` | 7 |
    ///
    /// Note that `mul_i` in the Witness table preprocessed column indicates how many times
    /// each witness index appears in the circuit.
    /// ALU rows include selectors followed by indices; multiplicity is handled when building the ALU table.
    pub fn generate_preprocessed_columns(&self) -> Result<PreprocessedColumns<F>, CircuitError> {
        let mut preprocessed = PreprocessedColumns::new();

        // We know that the Witness table has at least one entry for index 0 (multiplicity 0 at the start).
        preprocessed.primitive[PrimitiveOpType::Witness as usize].push(F::ZERO);

        // Process each primitive operation, extracting its witness indices.
        for op in &self.ops {
            match op {
                // Const: stores a constant value at witness[out].
                // Preprocessed data: the output witness index.
                // Since the values in ConstAir are looked up in WitnessAir,
                // we register the read to update multiplicities.
                Op::Const { out, .. } => {
                    preprocessed
                        .register_primitive_witness_reads(PrimitiveOpType::Const, &[*out])?;
                }
                // Public: loads a public input into witness[out].
                // Preprocessed data: the output witness index.
                // Since the values in PublicAir are looked up in WitnessAir,
                // we register the read to update multiplicities.
                Op::Public { out, .. } => {
                    preprocessed
                        .register_primitive_witness_reads(PrimitiveOpType::Public, &[*out])?;
                }
                // Unified ALU operations with selectors for operation kind.
                // Preprocessed per op (without multiplicity):
                // [sel_add_vs_mul, sel_bool, sel_muladd, a_idx, b_idx, c_idx, out_idx]
                Op::Alu {
                    kind, a, b, c, out, ..
                } => {
                    // Encode operation kind as:
                    // - sel_add_vs_mul: 1 for Add, 0 for Mul (when Bool/MulAdd are 0)
                    // - sel_bool: 1 for BoolCheck
                    // - sel_muladd: 1 for MulAdd
                    let (sel_add_vs_mul, sel_bool, sel_muladd) = match kind {
                        AluOpKind::Add => (F::ONE, F::ZERO, F::ZERO),
                        AluOpKind::Mul => (F::ZERO, F::ZERO, F::ZERO),
                        AluOpKind::BoolCheck => (F::ZERO, F::ONE, F::ZERO),
                        AluOpKind::MulAdd => (F::ZERO, F::ZERO, F::ONE),
                    };

                    preprocessed.register_primitive_preprocessed_no_read(
                        PrimitiveOpType::Alu,
                        &[sel_add_vs_mul, sel_bool, sel_muladd],
                    )?;

                    // Witness indices contribute to multiplicities and follow the selectors in order.
                    preprocessed.register_primitive_witness_reads(
                        PrimitiveOpType::Alu,
                        &[
                            *a,
                            *b,
                            c.unwrap_or(WitnessId(0)), // c is for non MulAdd operations
                            *out,
                        ],
                    )?;
                }
                Op::NonPrimitiveOpWithExecutor {
                    executor,
                    inputs,
                    outputs,
                    ..
                } => {
                    // Delegate preprocessing to the non-primitive operation.
                    executor.preprocess(inputs, outputs, &mut preprocessed)?;
                }
            }
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
        let circuit: Circuit<F> = make_circuit(vec![]);
        let result = circuit.generate_preprocessed_columns().unwrap();

        assert_eq!(result.primitive.len(), PrimitiveOpType::COUNT);
        assert_eq!(
            result.primitive[PrimitiveOpType::Witness as usize],
            vec![F::ZERO]
        );
        assert!(result.primitive[PrimitiveOpType::Const as usize].is_empty());
        assert!(result.primitive[PrimitiveOpType::Public as usize].is_empty());
        assert!(result.primitive[PrimitiveOpType::Alu as usize].is_empty());
    }

    #[test]
    fn test_mixed_operations() {
        // Test covering various operation types and behaviors:
        // - Each operation type populates its correct column
        // - Multiplicities in Witness table are accurate
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
        let result = circuit.generate_preprocessed_columns().unwrap();

        // Const column: output indices in order
        assert_eq!(
            result.primitive[PrimitiveOpType::Const as usize],
            vec![F::ZERO, F::from_u32(2)]
        );

        // Public column: output index
        assert_eq!(
            result.primitive[PrimitiveOpType::Public as usize],
            vec![F::from_u32(1)]
        );

        // ALU column: [sel_add_vs_mul, sel_bool, sel_muladd, a, b, c, out] per op
        // Layout per op: [sel_add_vs_mul, sel_bool, sel_muladd, a, b, c, out]
        // Op 1: add(0, 1, 3) -> [1, 0, 0, 0, 1, 0, 3]
        // Op 2: add(3, 2, 4) -> [1, 0, 0, 3, 2, 0, 4]
        // Op 3: mul(4, 2, 5) -> [0, 0, 0, 4, 2, 0, 5]
        let expected_alu = vec![
            // add(0, 1, 3)
            F::ONE,
            F::ZERO,
            F::ZERO,
            F::ZERO,
            F::from_u32(1),
            F::ZERO,
            F::from_u32(3),
            // add(3, 2, 4)
            F::ONE,
            F::ZERO,
            F::ZERO,
            F::from_u32(3),
            F::from_u32(2),
            F::ZERO,
            F::from_u32(4),
            // mul(4, 2, 5)
            F::ZERO,
            F::ZERO,
            F::ZERO,
            F::from_u32(4),
            F::from_u32(2),
            F::ZERO,
            F::from_u32(5),
        ];
        assert_eq!(
            result.primitive[PrimitiveOpType::Alu as usize],
            expected_alu
        );

        // We should have the following multiplicities in the Witness table, for indices 0 to 5:
        // Index 0: 2 (const out) + 3 (c_idx for 3 ALU ops that use c=0) = 5
        // Index 1: 2 (public out + add input a)
        // Index 2: 3 (const out + add input b + mul input b)
        // Index 3: 2 (add output + add input a)
        // Index 4: 2 (add output + mul input a)
        // Index 5: 1 (mul output)
        let expected_multiplicities = vec![
            F::from_u16(5), // Index 0: const + 3x c_idx (for add, add, mul operations)
            F::from_u16(2),
            F::from_u16(3),
            F::from_u16(2),
            F::from_u16(2),
            F::from_u16(1),
        ];
        assert_eq!(
            result.primitive[PrimitiveOpType::Witness as usize],
            expected_multiplicities
        );
    }

    #[test]
    fn test_input_indices_contribute_to_max_idx() {
        // Ensures input indices that exceed outputs are tracked for witness table size
        let ops = vec![Op::add(
            WitnessId(0),
            WitnessId(15), // Highest index is an input, not output
            WitnessId(5),
        )];

        let circuit = make_circuit(ops);
        let result = circuit.generate_preprocessed_columns().unwrap();

        // Index 0 has multiplicity 2 (once for 'a', once for 'c' which defaults to 0)
        // Index 5 and 15 have multiplicity 1
        let expected_witness: Vec<F> = (0..=15)
            .map(|i| {
                if i == 0 {
                    F::from_u16(2) // a + c_idx (c defaults to 0)
                } else if i == 5 || i == 15 {
                    F::ONE
                } else {
                    F::ZERO
                }
            })
            .collect();
        assert_eq!(
            result.primitive[PrimitiveOpType::Witness as usize],
            expected_witness
        );
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
        let result = circuit.generate_preprocessed_columns().unwrap();

        // ALU column for MulAdd: [sel_add_vs_mul=0, sel_bool=0, sel_muladd=1, a=0, b=1, c=2, out=3]
        let expected_alu = vec![
            F::ZERO,
            F::ZERO,
            F::ONE,
            F::ZERO,
            F::from_u32(1),
            F::from_u32(2),
            F::from_u32(3),
        ];
        assert_eq!(
            result.primitive[PrimitiveOpType::Alu as usize],
            expected_alu
        );

        // Multiplicities: 0,1,2,3 each appear once in const or ALU
        // Index 0: const out + ALU a = 2
        // Index 1: const out + ALU b = 2
        // Index 2: const out + ALU c = 2
        // Index 3: ALU out = 1
        let expected_multiplicities = vec![
            F::from_u16(2),
            F::from_u16(2),
            F::from_u16(2),
            F::from_u16(1),
        ];
        assert_eq!(
            result.primitive[PrimitiveOpType::Witness as usize],
            expected_multiplicities
        );
    }
}
