//! Transparent columns API (POC)
//!
//! Draft interfaces for “transparent columns”.
//! This POC focuses on API shape only; no prover/verifier integration is provided here.

extern crate alloc;

use alloc::boxed::Box;
use alloc::string::{String, ToString};
use alloc::vec;
use alloc::vec::Vec;

use p3_field::Field;

use crate::circuit::Circuit;
use crate::op::Prim;

/// A compact row-major container for transparent values.
///
/// - `values` is length = `width * height` in row-major order.
/// - `width` is the number of columns (transparent fields).
/// - `height` is the number of rows (table height).
#[derive(Clone, Debug)]
pub struct TransparentTrace<F> {
    pub values: Vec<F>,
    pub width: usize,
    pub height: usize,
}

impl<F> TransparentTrace<F> {
    pub fn new(values: Vec<F>, width: usize, height: usize) -> Self {
        Self {
            values,
            width,
            height,
        }
    }
}

/// A provider of transparent columns for a specific table (or “chip”).
///
/// Implementations describe how to deterministically generate the transparent columns for that table,
/// given only the program/circuit metadata. These columns are committed once at setup.
pub trait TransparentProvider<F> {
    /// A human-readable, unique name for this provider/table.
    fn name(&self) -> &'static str;

    /// The number of transparent columns exposed by this provider.
    fn transparent_width(&self) -> usize;

    /// Deterministically generate the transparent rows for this table.
    fn generate_transparent_rows(&self, circuit: &Circuit<F>) -> TransparentTrace<F>;
}

/// Metadata about a single transparent trace inside the committed bundle.
#[derive(Clone, Debug)]
pub struct TransparentTraceInfo {
    pub name: String,
    pub width: usize,
    pub height: usize,
}

/// A bundle of all transparent traces, computed at setup.
#[derive(Clone, Debug, Default)]
pub struct TransparentBundle<F> {
    pub traces: Vec<TransparentTrace<F>>,
    pub infos: Vec<TransparentTraceInfo>,
}

/// A placeholder commitment to the transparent bundle produced at setup.
///
/// In a full implementation this would contain a PCS commitment and any auxiliary data
/// needed for opening (domains, ordering, etc.).
#[derive(Clone, Debug, Default)]
pub struct TransparentCommitment {
    /// Opaque commit bytes (e.g., Merkle or PCS commitment). Empty in POC.
    pub commit: Vec<u8>,
}

/// Proving-time view of transparent setup artifacts.
#[derive(Clone, Debug, Default)]
pub struct TransparentProvingKey<F> {
    pub commitment: TransparentCommitment,
    pub bundle: TransparentBundle<F>,
    /// Name -> index mapping into `bundle.traces` (stable ordering).
    pub ordering: Vec<(String, usize)>,
}

/// Verifying-time view of transparent setup artifacts.
#[derive(Clone, Debug, Default)]
pub struct TransparentVerifyingKey {
    pub commitment: TransparentCommitment,
    pub traces: Vec<TransparentTraceInfo>,
    /// Name -> index mapping consistent with PK.
    pub ordering: Vec<(String, usize)>,
}

/// Setup the transparent columns once at circuit build time.
///
/// - Deterministically generates all transparent traces from the circuit and providers.
/// - Produces a placeholder commitment and parallel PK/VK views.
/// - No proof-generation or opening logic is implemented in this POC.
pub fn setup_transparent_columns<F: Field>(
    circuit: &Circuit<F>,
    providers: &[&dyn TransparentProvider<F>],
) -> (TransparentProvingKey<F>, TransparentVerifyingKey) {
    let mut bundle = TransparentBundle {
        traces: Vec::new(),
        infos: Vec::new(),
    };
    let mut ordering: Vec<(String, usize)> = Vec::new();

    for provider in providers {
        let name = provider.name().to_string();
        let mut rows = provider.generate_transparent_rows(circuit);
        // Pad to next power of two with zeros.
        let padded_h = next_power_of_two(rows.height);
        if padded_h > rows.height && rows.width > 0 {
            let deficit = (padded_h - rows.height) * rows.width;
            rows.values.extend((0..deficit).map(|_| F::from_u64(0)));
            rows.height = padded_h;
        }
        // Defensive: keep metadata alongside the trace.
        bundle.infos.push(TransparentTraceInfo {
            name: name.clone(),
            width: rows.width,
            height: rows.height,
        });
        ordering.push((name, bundle.traces.len()));
        bundle.traces.push(rows);
    }

    // POC: no real commitment; leave empty bytes.
    let commitment = TransparentCommitment { commit: Vec::new() };
    // Take infos clone for VK to avoid cloning F-typed traces.
    let traces_info = bundle.infos.clone();
    let pk = TransparentProvingKey {
        commitment: commitment.clone(),
        bundle,
        ordering: ordering.clone(),
    };
    let vk = TransparentVerifyingKey {
        commitment,
        traces: traces_info,
        ordering,
    };

    (pk, vk)
}

#[inline]
fn next_power_of_two(n: usize) -> usize {
    if n == 0 { 0 } else { n.next_power_of_two() }
}

// -----------------------------
// Default providers (indices)
// -----------------------------

struct WitnessIndexProvider;
struct ConstIndexProvider;
struct PublicIndexProvider;

impl<F: Field + Clone> TransparentProvider<F> for WitnessIndexProvider {
    fn name(&self) -> &'static str {
        "WitnessIndex"
    }
    fn transparent_width(&self) -> usize {
        1
    }
    fn generate_transparent_rows(&self, circuit: &Circuit<F>) -> TransparentTrace<F> {
        let n = circuit.witness_count as usize;
        let mut values = Vec::with_capacity(n);
        for i in 0..n {
            values.push(F::from_u64(i as u64));
        }
        TransparentTrace::new(values, 1, n)
    }
}

impl<F: Field + Clone> TransparentProvider<F> for ConstIndexProvider {
    fn name(&self) -> &'static str {
        "ConstIndex"
    }
    fn transparent_width(&self) -> usize {
        1
    }
    fn generate_transparent_rows(&self, circuit: &Circuit<F>) -> TransparentTrace<F> {
        let mut indices: Vec<u32> = Vec::new();
        for prim in &circuit.primitive_ops {
            if let Prim::Const { out, .. } = prim {
                indices.push(out.0);
            }
        }
        let height = indices.len();
        let mut values = Vec::with_capacity(height);
        for idx in indices {
            values.push(F::from_u64(idx as u64));
        }
        TransparentTrace::new(values, 1, height)
    }
}

impl<F: Field + Clone> TransparentProvider<F> for PublicIndexProvider {
    fn name(&self) -> &'static str {
        "PublicIndex"
    }
    fn transparent_width(&self) -> usize {
        1
    }
    fn generate_transparent_rows(&self, circuit: &Circuit<F>) -> TransparentTrace<F> {
        // Each Public op in lowering order contributes one row.
        let mut indices: Vec<u32> = Vec::new();
        for prim in &circuit.primitive_ops {
            if let Prim::Public { out, .. } = prim {
                indices.push(out.0);
            }
        }
        let height = indices.len();
        let mut values = Vec::with_capacity(height);
        for idx in indices {
            values.push(F::from_u64(idx as u64));
        }
        TransparentTrace::new(values, 1, height)
    }
}

macro_rules! impl_op_provider3 {
    ($name:ident, $chip:literal, $variant:ident, $a:ident, $b:ident, $out:ident) => {
        struct $name;
        impl<F: Field + Clone> TransparentProvider<F> for $name {
            fn name(&self) -> &'static str {
                $chip
            }
            fn transparent_width(&self) -> usize {
                3
            }
            fn generate_transparent_rows(&self, circuit: &Circuit<F>) -> TransparentTrace<F> {
                let mut lhs: Vec<u32> = Vec::new();
                let mut rhs: Vec<u32> = Vec::new();
                let mut res: Vec<u32> = Vec::new();
                for prim in &circuit.primitive_ops {
                    if let Prim::$variant { $a, $b, $out } = prim {
                        lhs.push($a.0);
                        rhs.push($b.0);
                        res.push($out.0);
                    }
                }
                let n = res.len();
                let mut values = Vec::with_capacity(n * 3);
                for i in 0..n {
                    values.push(F::from_u64(lhs[i] as u64));
                    values.push(F::from_u64(rhs[i] as u64));
                    values.push(F::from_u64(res[i] as u64));
                }
                TransparentTrace::new(values, 3, n)
            }
        }
    };
}

impl_op_provider3!(AddIndexProvider, "AddIndex", Add, a, b, out);
impl_op_provider3!(MulIndexProvider, "MulIndex", Mul, a, b, out);
impl_op_provider3!(SubIndexProvider, "SubIndex", Sub, a, b, out);

/// Build and commit (placeholder) the default transparent providers for index columns.
pub fn setup_default_transparent_indices<F: Field + Clone>(
    circuit: &Circuit<F>,
) -> (TransparentProvingKey<F>, TransparentVerifyingKey) {
    let providers: Vec<Box<dyn TransparentProvider<F>>> = vec![
        Box::new(WitnessIndexProvider),
        Box::new(ConstIndexProvider),
        Box::new(PublicIndexProvider),
        Box::new(AddIndexProvider),
        Box::new(MulIndexProvider),
        Box::new(SubIndexProvider),
    ];
    let refs: Vec<&dyn TransparentProvider<F>> = providers.iter().map(|b| b.as_ref()).collect();
    setup_transparent_columns(circuit, &refs)
}
