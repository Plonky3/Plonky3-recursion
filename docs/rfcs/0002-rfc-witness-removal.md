# RFC 0002: Removing Witness Table and Supporting Base Field Elements

---

- **Author(s):** @LindaGuiga
- **DRI:** @LindaGuiga
- **Status:** Draft
- **Created:** 2026-01-13
- **Tracking issue:** #103

## 1. Summary
The Witness table is very long and could potentially blow up easily. Moreover, it only supports extension field elements, which is a problem for verifying uni-stark proofs.

This RFC proposes a way to remove the Witness table without impacting soundness. It also suggests a way of supporting base field elements for the permutation table without impacting performance too much.

## 2. Motivation / Problem statement
We currently have two issues with the design of the Witness table.

The first is a performance issue related to the size of the Witness table. The latter could easily become very long and already takes the most time to prove. Moreover, its only goal is to ensure that values are not overwritten. While this is a critical soundness point, it could be ensured in other ways, as this RFC shows.

The second is that the Witness table only supports extension field elements. On the other hand, the uni-stark challenger observes and retrieves base field elements. The current design therefore makes it impossible to correctly reproduce the behaviour of the uni-stark verifier. We could easily add 3 global lookups to the Witness table, but it would lead to at least 3 more columns for the multiplicities (and, for degree reasons, we would also have extra lookup polynomials). Since, as mentioned in the previous paragraph, the Witness table is currently very heavy, I do not think it would be advisable to implement this approach for extension field support. If we get rid of the Witness table, the impact of supporting extension field elements becomes lighter.

## 3. Goals and non-goals
**Goals**
- Remove the Witness table without impacting soundness. This removal should bring performance benefit, to minimize the impact of supporting extension field elements.
- Support extension field elements for hashing.

**Non-goals**
- We could potentially support extension field elements for other operations, but I don't see the use case for now, and it would incur more overhead.

## 4. Proposed design
### 4.1 High-level approach
Let us first describe how we can get rid of the Witness table.

The role of the Witness table is to ensure, through the CTLs, that all values associated to a certain index are equal. It corresponds to a lookup table into which all other tables read their inputs and outputs.

To replace this pivotal role, I propose to keep the notion of witness indices and witness multiplicities, without storing them in any table. In each table, we can ensure that witness values are read-only as follows:
- If we encounter an index for the first time (in any table), its multiplicity is positive.
- If we have already encountered the index (in any table), then its multiplicity is negative.

This way, all values pairs (index, value) are "reading" from the same location (the one with positive multiplicity).

As a special case, `Public` and `Constant` always have positive multiplicities.

Overall, the changes, in the various tables, required to remove `Witness` are as follows:
- `Public` and `Constant`: nothing changes, except the way multiplicities are computed.
- `Add` and `Mul`: each operation element now need its own multiplicity column (the multiplicity cannot be shared by the inputs and output). So this amounts to two extra preprocessed columns.
- `Poseidon2Circuit`: We can use `in_ctl` and `out_ctl` to store the actual multiplicities (they would no longer just be flags). No other change would be necessary.

Now, let us describe how we can support extension field elements. As mentioned above, only hashing requires some base field elements.

For hashing, `Poseidon2CircuitAir` receives (at most 4 extension field) inputs from among the public values or constant values. And it creates new outputs (2 extension field elements).

The permutation table can get its inputs from the `Public` or `Constant` table. Since the challenger can observe base field values, `Public` and `Constant` either need to support both base field and extension field elements or only base field elements. The problem with the latter is that it would force `Add` and `Mul` to have 3 more CTLs per limb (and therefore 9 more permutation columns each). As `Public` and `Constant` should generally be shorter than `Add` and `Mul`, I believe it would be better for `Public` and `Const` to support both base field and extension field elements. `Add` and `Mul` can the remain unchanged -- with the exception of added multiplicities. I will explain later how this would work. 

#### Permutation table
For permutation inputs:
- Since the base field input limbs are not necessarily contiguous, we need to have an index column for each limb. We would also need a CTL for each base field limb. Thus, we would need to have 12 extra index columns and 12 extra multiplicity colmns (note that we can use `in_ctl` to store the multiplicity of the first base field element).
- For each base field input element, we send `(index, base_element)` with multiplicity -1. Since the hasher is reading from either the public inputs or the constant values, `(index, base_element)` is stored in one of the two tables, and we can update its multiplicity there as well.

For permutation outputs:
- The outputs are created -- which means we are introducing new indices and have complete control over them. Since the challenger can sample base field elements, the outputs need to be "stored" as base field elements, and so each element has its own index. The index is a multiple of `D`, so that each `(base_element, 0, 0, ...)` has its own index. The newly created indices are contiguous however, and so we only need one index column (we can deduce the rest of the indices from the first). In other words, if the first base field output is at index `i`, the second one is at index `i + D` etc.
- There should be no interaction between the newly created outputs and the public or constant values. And so for CTLs, we only need extension field CTLs with the `Add` or `Mul` tables, of the form `(index, base_element, 0, 0, 0)` (where `D = 4` here).

#### Public and Constant tables
The non-preprocessed columns remain unchanged: one index column (whose value now becomes a multiple of `D`), and `D` value columns. We can keep only one index column as values can be stored contiguously, and we can deduce the rest of the indices from the first. But each table now has 5 CTLs instead of just one if we follow the approach of supporting both base field and extension field elements:
- 1 CTL for extension field elements: send `(index, base_elt_1, base_elt_2, ..., base_elt_D)` with nonnegative multiplicity.
- 4 CTLs for base field elements: for `i=0` to `D`, send `(index + i, base_elt_i)` with nonnegative multiplicity.
Thus, we have 4 extra logup columns and 4 extra preprocessed multiplicity columns.

We might be able to pack some base field values together in the two tables, but it is not necessary in this first step.

#### Add and Mul tables
The non-reprocessed columns also remain unchanged here. Once again, we can assume that the base field elements pertaining to the same extension field are contiguous and we can use the index of the first element to deduce the rest. If we want to reconstruct an extension field element using the permutation base field outputs, we can directly use the created `(index, base_field, 0, ...)` values for that. 

However, we need some additional preprocessed multiplicities for `Add`. Indeed, the outputs of additions, multiplications or subtractions are generally a new index that needs to be stored. For `Mul`, it just means that we have to set the output multiplicity to -1 for non padding rows (and so we can still use the current multiplicity column). But for `Add`, the output can be either in the second operand or in the output (depending on whether the operation is an addition or a subtraction). We need a multiplicity column for the two operands and the output. So we would need 2 extra multiplicity columns for `Add`, and no new preprocessed columns for `Mul`.

### 4.2 APIs / traits / types
The only trait / API changes are related to the way multiplicities are computed. When it comes to adapting the lookups to extension field elements, we only need to update `get_lookups` for all tables using what we described above. Of course, we would also need to update preprocessed values with the multiplicities.

In order to keep track of the multiplicities for all tables, we can introduce a `WitnessMultiplicities` structure. Instead of a `Vec<F>`, `generate_preprocessed_columns` would update a `Vec<WitnessMultiplicities>`. In `WitnessMultiplicities>`, we need to keep track of the operation type and operation index where the index was created. Indeed, we need to update the multiplicity of that value every time the index is encountered again. Note that for the proposed approach to work, we need to ensure that indices are updated with increasing indices. 

```rust
pub struct WitnessMultiplicities {
    pub operation: OperationType,
    pub operation_index: usize
}
```

We also introduce:
```rust
pub struct Multiplicity {
    pub extension: usize,
    pub base: [usize; 4]
}
```
which represents a multiplicity for extension and base field elements. The differentiation is only needed for `Public` and `Constant` though.

We need to update `generate_preprocessed_columns` and `PrerocessedColumns`.

We need to remove `Witness` from `PrimitieOpType`. The indexing needs to be modified as well (each base field element needs to get an index). In the following, we assume that indexing is correct. In fact, if we still assume that a `WitnessId` represents an extension field element, we can just assume that the witness index is a multiple of 4, and the `Target` holds `D` base field elements.

Here is a sketch for updating `generate_preprocessed_columns` for primitive operations.

```rust
pub fn generate_preprocessed_columns(&self) -> Result<PreprocessedColumns<F>, CircuitError> {
        // Allocate one empty vector per primitive operation type (Const, Public, Add, Mul).
        // Notice we removed `Witness` here.
        let mut preprocessed = vec![vec![]; PrimitiveOpType::COUNT];
        let mut witness_multiplicities: Vec<WitnessMultiplicities> = vec![];
        let mut non_primitive_preprocessed = NonPrimitivePreprocessedMap::new();

        // Process each primitive operation, extracting its witness indices.
        for op in &self.ops {
            match op {
                // Const: stores a constant value at witness[out].
                // Preprocessed data: the output witness index.
                Op::Const { out, .. } => {
                    let table_idx = PrimitiveOpType::Const as usize;
                    

                    // Since the values in `PublicAir` are looked up in `WitnessAir`,
                    // we need to take the values into account in `WitnessAir`s preprocessed multiplicities.
                    if out.0 >= witness_multiplicities.len() as u32 {
                        assert!(out.0 = witness_multiplicities.len()); // ensure that we are not skipping indices
                        assert!((out.0 % D) == 0);
                        for i in 0..D {
                            witness_multiplicities.push(WitnessMultiplicities {
                                operation: PrimitiveOpType::Const,
                                operation_index: preprocessed[table_idx].len()
                                index
                            });  
                        }           
                    }

                    preprocessed[table_idx].push(WitnessMultiplicity {
                        extension: 0,
                        base: [0; D]
                    });
                }
                // Public: loads a public input into witness[out].
                // Preprocessed data: the output witness index.
                Op::Public { out, .. } => {
                    let table_idx = PrimitiveOpType::Public as usize;

                    // Since the values in `PublicAir` are looked up in `WitnessAir`,
                    // we need to take the values into account in `WitnessAir`s preprocessed multiplicities.
                    if out.0 >= witness_multiplicities.len() as u32 {
                        assert!(out.0 = witness_multiplicities.len()); // ensure that we are not skipping indices
                        assert!((out.0 % D) == 0);
                        for i in 0..D {
                            witness_multiplicities.push(WitnessMultiplicities {
                                operation: PrimitiveOpType::Public,
                                operation_index: preprocessed[table_idx].len()
                                index
                            });  
                        }
                                  
                    }

                    preprocessed[table_idx].push(WitnessMultiplicity {
                        extension: 0,
                        base: [0; D]
                    });
                }
                Op::Add { a, b, out } => {
                    let table_idx = PrimitiveOpType::Add as usize;

                    // If the index of the second operand exists, then this is not the output, and we are dealing with an `Add` operation.
                    let is_add = b.0 < witness_multiplicities.len() as u32
                    if b.0 >= witness_multiplicities.len() as u32 {
                        assert!(b.0 = witness_multiplicities.len() + D); // ensure that we are not skipping indices
                        assert!((b.0 % D) == 0);
                        witness_multiplicities.push(WitnessMultiplicities {
                            operation: PrimitiveOpType::Add,
                            operation_index: preprocessed[table_idx].len()
                            index: 1
                        });            
                    }
                    if out.0 >= witness_multiplicities.len() as u32 {
                        assert!(out.0 = witness_multiplicities.len() + D); // ensure that we are not skipping indices
                        assert!((out.0 % D) == 0);
                        witness_multiplicities.push(WitnessMultiplicities {
                            operation: PrimitiveOpType::Add,
                            operation_index: preprocessed[table_idx].len()
                            index: 1
                        });            
                    }
                    if is_add {
                        preprocessed[table_idx].extend(&[
                            F::from_u32(a.0),
                            F::ONE,
                            F::from_u32(b.0),
                            F::NEG_ONE,
                            F::from_u32(out.0),
                        ]);
                    } else {
                        preprocessed[table_idx].extend(&[
                            F::from_u32(a.0),
                            F::NEG_ONE,
                            F::from_u32(b.0),
                            F::ONE,
                            F::from_u32(out.0),
                        ]);
                    }
                   

                    // We need to update the multiplicities for `a`, `b`, and `out` in the location where they first appear.
                    // Here, we find the operation table index and the index within, and we update the multiplicity by adding +1 there. Note that we need to update the multiplicity of all 4 base field elements for each of a, b and out.
                    update_witness_multiplicity(&[a.0, b.0, out.0]); 
                }

                // Mul: computes witness[out] = witness[a] * witness[b].
                // Preprocessed data: input indices a, b and output index out.
                Op::Mul { a, b, out } => {
                    let table_idx = PrimitiveOpType::Mul as usize;

                    if out.0 >= witness_multiplicities.len() as u32 {
                        assert!(out.0 = witness_multiplicities.len() + D); // ensure that we are not skipping indices
                        assert!((out.0 % D) == 0);
                        witness_multiplicities.push(WitnessMultiplicities {
                            operation: PrimitiveOpType::Add,
                            operation_index: preprocessed[table_idx].len()
                            index: 1
                        });            
                    }
                    preprocessed[table_idx].extend(&[
                        F::from_u32(a.0),
                        F::from_u32(b.0),
                        F::from_u32(out.0),
                    ]);

                    // We need to update the multiplicities for `a`, `b`, and `out` in `WitnessAir`.
                    update_witness_multiplicity(&[a.0, b.0, out.0]); 
                }
                Op::NonPrimitiveOpWithExecutor {
                    executor,
                    inputs,
                    outputs,
                    ..
                } => {
                    // Delegate preprocessing to the non-primitive operation.
                    executor.preprocess(
                        inputs,
                        outputs,
                        &mut preprocessed,
                        &mut non_primitive_preprocessed,
                    );
                }
            }
        }

        Ok(PreprocessedColumns {
            primitive: preprocessed,
            non_primitive: non_primitive_preprocessed,
        })
    }
```