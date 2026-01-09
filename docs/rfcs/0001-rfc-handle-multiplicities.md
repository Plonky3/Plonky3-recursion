# RFC 0001: Handle Multiplicities

- **Author(s):** @LindaGuiga
- **DRI:** @LindaGuiga
- **Status:** In Review
- **Created:** 2026-01-09
- **Tracking issue:** #234

## 1. Summary
Currently, witness multiplicities are handled in an error-prone and not very user-friendly way.

I suggest having `PreprocessedColumns` handle the update of witness multiplicities directly with some specific methods. Since we would only use those specialised methods for witness indices, this would make things less error-prone.

Furthermore, I propose putting all the preprocessed traces generated when creating common data into a `ProverData` structure.
This structure would be passed to the prover instead of `CommonData`, thus making sure that the prover doesn't have to regenerate any preprocessing trace, while keeping everything hidden from the user. This would lead to a more user-friendly API. 


## 2. Motivation / Problem statement
For lookups, we need to keep track of the number of times each `Witness` table value is read in the other tables.
All primitive and non-primitive tables include columns whose values should be read from the `Witness` table.
This means that a lot of the preprocessed values for primitive and non-primitive operations correspond to witness table indices.

Thus, we need to generate preprocessed values for the various operations in parallel with the `Witness` table multiplicities.

In `generate_preprocessed_columns`, we update the preprocessed data as follows, for each primitive and non-primitive operation:
- first, we extend the operation's preprocessed data with the necessary values
- then, when the values include witness indice, we update the corresponding multiplicities accordingly.
Since this is currently a manual process, it is easy to forget to update multiplicities. 

Furthermore, the prover currently requires access to the `witness_multiplicities` so that it doesn't have to regenerate them. But having the user carry the multiplicities around is not user-friendly.

Therefore, we need to redesign the way we currently handle multiplicities in order to make it less error-prone and more user-friendly.

## 3. Goals and non-goals
**Goals**
- Handle witness multiplicities in a somewhat automated way, making their update easier and more manageable.
- Provide the prover with the necessary data without making the API worse for the user.

**Non-goals**
- We could possibly have a better design for the rest of the preprocessed data, for example by having each operation have control over what is pushed to the preprocessed data. But this is out of scope here.

## 4. Proposed design
### 4.1 High-level approach

- Add methods to the `PreprocessedColumns` structure so that it can update the preprocessed data itself. This way, we can have specialized methods for witness indices, which would update both the current table's preprocessed data and the witness multiplicities. We can have one method to register a primitive witness read, one for non-primitive reads, and the same methods for multiple reads. Additionally, we would have a method to add a value that is not a witness index. Note that at the end of `generate_preprocessed`, the structure could then already add a single `Add` and/or `Mul` operation if either is empty. It is currently done outside of `generate_preprocessed`, which might incur errors.
- On top of `CommonData`, we can have a `ProverData` structure which contains the common data, as well as `PreprocessedColumns` and any additional data that the prover might require. Currently, the prover is regenerating the preprocessed values based on the traces. And it could do the same for multiplicities, but this leads to more overhead when the values should already have been computed beforehand. So this approach should both simplify the API and very slightly improve the performance of the prover -- at the expense of storing more preprocessed data before proving.

### 4.2 APIs / traits / types

First, we would need to add methods to `PreprocessedColumns` for it to have more control over how preprocessed data is generated. I propose the following changes:

```rust
impl PreprocessedColumns {

    /// Updates the witness table multiplicities for all the given witness indices.
    fn update_witness_multiplicities(&mut self, wids: &[WitnessId]) {
        for wid in wids {
            if wid.0 >= self.primitive[witness_table_idx].len() as u32 {
                self.primitive[witness_table_idx].resize(wid.0 as usize + 1, F::from_u32(0));
            }
            self.primitive[witness_table_idx][wid.0 as usize] += F::ONE;
        }
        
    }

    /// Extends the preprocessed data of the `table_idx`-th primitive operation 
    /// with `wids`'s witness indices, and updates the witness multiplicities.
    fn register_primitive_witness_reads(&mut self, table_idx: usize, wids: WitnessId) {
        let wids_field = wids.iter().map(|wid| F::from_u32(wid.0));
        self.primitive[table_idx].extend(wids_field);

        self.update_witness_multiplicities(&wids);
    }

    /// Extends the preprocessed data of `op-type`'s non-primitive operation 
    /// with `wids`'s witness indices, and updates the witness multiplicities.
    fn register_non_primitive_witness_reads(&mut self, op_type: NonPrimitiveOpType, wid: WitnessId) {
        let entry = self.non_primitive.entry(op_type).or_default();

        let wids_field = wids.iter().map(|wid| F::from_u32(wid.0));
        self.primitive[table_idx].extend(wids_field);

        entry.extend(wids_field);

        self.update_witness_multiplicities(&[wid]);
    }

    /// Extends the preprocessed data of the `table_idx`-th primitive operation 
    /// with `wid`'s witness index, and updates the witness multiplicity.
    fn register_primitive_witness_read(&mut self, table_idx: usize, wid: WitnessId) {
        self.register_primitive_witness_read(table_ids, &[wid])
    }

    /// Extends the preprocessed data of `op-type`'s non-primitive operation 
    /// with `wid`'s witness index, and updates the witness multiplicity.
    fn register_non_primitive_witness_read(&mut self, op_type: NonPrimitiveOpType, wid: WitnessId) {
        let entry = self.non_primitive.entry(op_type).or_default();

        entry.push(wid.0);

        self.update_witness_multiplicities(&[wid]);
    }

    /// Extends the preprocessed data of the `table_idx`-th primitive operation 
    /// with `values`.
    fn register_primitive_preprocessed_no_read(&mut self, table_idx: usize, values: &[F]) {
        self.primitive[table_idx].extend(values);
    }

    /// Extends the preprocessed data of `op-type`'s non-primitive operation
    /// with `values`.
    fn register_non_primitive_preprocessed_no_read(&mut self, table_idx: usize, values: &[F]) {
        let entry = self.non_primitive.entry(op_type).or_default();

        entry.extend(values);
    }
}
```

The second part consists in introducing a new `ProverData` structure, which contains `common_data` and the preprocessed columns:

```rust
pub struct ProverData {
    common_data: CommonData,
    preprocessed_columns: PreprocessedColumns
}
```

We would pass this new structure to `prove_all_tables` and `prove` instead of `common_data`. 

```rust
pub fn prove_all_tables<EF, LG: LookupGadget + Sync>(
        &self,
        traces: &Traces<EF>,
        prover_data: &ProverData<SC>,
        witness_multiplicities: Vec<Val<SC>>,
        lookup_gadget: &LG,
    ) -> Result<BatchStarkProof<SC>, BatchStarkProverError>
    where
        // EF: Field + BasedVectorSpace<Val<SC>> + ExtractBinomialW<Val<SC>>,
        EF: Field + BasedVectorSpace<Val<SC>> + ExtractBinomialW<Val<SC>>,
        SymbolicExpression<SC::Challenge>: From<SymbolicExpression<Val<SC>>>{ .. }

fn prove<EF, const D: usize, LG: LookupGadget + Sync>(
        &self,
        traces: &Traces<EF>,
        w_binomial: Option<Val<SC>>,
        prover_data: &ProverData<SC>,
        witness_multiplicities: Vec<Val<SC>>,
        lookup_gadget: &LG,
    ) -> Result<BatchStarkProof<SC>, BatchStarkProverError>
    where
        EF: Field + BasedVectorSpace<Val<SC>> {
        let PreprocessedColumns {
            primitive,
            non_primitive
        } = prover_data.preprocessed_columns;

        // Unchanged code here
        ..

        // Witness
        let witness_rows = traces.witness_trace.values.len();
        let witness_air = WitnessAir::<Val<SC>, D>::new_with_preprocessed(
            witness_rows,
            witness_lanes,
            &primitive[PrimitiveOp::Witness as usize],
        );
        let witness_matrix: RowMajorMatrix<Val<SC>> =
            WitnessAir::<Val<SC>, D>::trace_to_matrix(&traces.witness_trace, witness_lanes);

        // Const
        let const_rows = traces.const_trace.values.len();
        let const_air = ConstAir::<Val<SC>, D>::new_with_preprocessed(const_rows, &primitive[PrimitiveOp::Const as usize],);
        let const_matrix: RowMajorMatrix<Val<SC>> =
            ConstAir::<Val<SC>, D>::trace_to_matrix(&traces.const_trace);

        // Apply similar changes to the rest of the primitive and non primitive operaitons.
        ..
    }
```

With this approach, we can also remove `trace_to_preprocessed` in the various airs where it is implemented. Currently, the method is a bit redundant with `generate_preprocessed` since it is also generating preprocessed data, even though it is basing itself on the traces to do so. The redundance also makes it error-prone, so being able to get rid of it would be, in my opinion, another benefit of this approach.

Note that ideally, we should also change `CommonData` in Plonky3, as it contains some prover data in `GlobalPreprocessed`.