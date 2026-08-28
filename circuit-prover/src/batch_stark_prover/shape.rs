//! Public, structured view of a batch STARK's per-table trace shapes.
//!
//! Gives callers that need per-table shapes without running a full proof the same
//! data `prove_all_tables` already logs.

use alloc::string::{String, ToString};
use alloc::vec::Vec;

use super::packing::TraceTablesLayout;

/// One table's committed shape: main/preprocessed column counts, logical row count
/// (before power-of-two padding), and lane packing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecursionTableShape {
    pub name: String,
    pub main_cols: usize,
    pub prep_cols: usize,
    pub rows: usize,
    pub lanes: usize,
}

/// Flatten a [`TraceTablesLayout`] into a name-ordered list: CONST, PUBLIC, ALU, then
/// every non-primitive table in the order `TraceTablesLayout::non_primitives` holds them.
#[allow(dead_code)]
pub(crate) fn table_shapes(layout: &TraceTablesLayout) -> Vec<RecursionTableShape> {
    let mut out = Vec::with_capacity(3 + layout.non_primitives.len());
    out.push(RecursionTableShape {
        name: "CONST".to_string(),
        main_cols: layout.const_.main_cols,
        prep_cols: layout.const_.prep_cols,
        rows: layout.const_.rows,
        lanes: layout.const_.lanes,
    });
    out.push(RecursionTableShape {
        name: "PUBLIC".to_string(),
        main_cols: layout.public.main_cols,
        prep_cols: layout.public.prep_cols,
        rows: layout.public.rows,
        lanes: layout.public.lanes,
    });
    out.push(RecursionTableShape {
        name: "ALU".to_string(),
        main_cols: layout.alu.main_cols,
        prep_cols: layout.alu.prep_cols,
        rows: layout.alu.rows,
        lanes: layout.alu.lanes,
    });
    for (op, shape) in &layout.non_primitives {
        out.push(RecursionTableShape {
            name: op.as_str().to_string(),
            main_cols: shape.main_cols,
            prep_cols: shape.prep_cols,
            rows: shape.rows,
            lanes: shape.lanes,
        });
    }
    out
}

#[cfg(test)]
mod tests {
    use alloc::vec;

    use super::*;
    use crate::batch_stark_prover::packing::{AirTableShape, TraceTablesLayout};

    #[test]
    fn table_shapes_includes_all_primitive_tables_by_name() {
        let layout = TraceTablesLayout {
            const_: AirTableShape {
                main_cols: 4,
                prep_cols: 2,
                rows: 8,
                lanes: 1,
            },
            public: AirTableShape {
                main_cols: 4,
                prep_cols: 2,
                rows: 4,
                lanes: 1,
            },
            alu: AirTableShape {
                main_cols: 80,
                prep_cols: 60,
                rows: 128,
                lanes: 3,
            },
            non_primitives: vec![],
        };
        let shapes = table_shapes(&layout);
        let names: Vec<&str> = shapes.iter().map(|s| s.name.as_str()).collect();
        assert_eq!(names, vec!["CONST", "PUBLIC", "ALU"]);
        assert_eq!(shapes[2].rows, 128);
        assert_eq!(shapes[2].lanes, 3);
        assert_eq!(shapes[2].main_cols, 80);
        assert_eq!(shapes[2].prep_cols, 60);
    }

    #[test]
    fn table_shapes_includes_non_primitives_with_exact_name() {
        use p3_circuit::ops::NpoTypeId;
        let layout = TraceTablesLayout {
            const_: AirTableShape {
                main_cols: 4,
                prep_cols: 2,
                rows: 1,
                lanes: 1,
            },
            public: AirTableShape {
                main_cols: 4,
                prep_cols: 2,
                rows: 1,
                lanes: 1,
            },
            alu: AirTableShape {
                main_cols: 80,
                prep_cols: 60,
                rows: 1,
                lanes: 1,
            },
            non_primitives: vec![(
                NpoTypeId::new("recompose"),
                AirTableShape {
                    main_cols: 4,
                    prep_cols: 2,
                    rows: 512,
                    lanes: 1,
                },
            )],
        };
        let shapes = table_shapes(&layout);
        assert_eq!(shapes.len(), 4);
        assert_eq!(shapes[3].name, "recompose");
        assert_eq!(shapes[3].rows, 512);
    }
}
