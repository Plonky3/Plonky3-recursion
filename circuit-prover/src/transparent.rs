//! Transparent columns API and providers (lives in prover crate).

extern crate alloc;

use alloc::boxed::Box;
use alloc::string::{String, ToString};
use alloc::vec;
use alloc::vec::Vec;

use p3_circuit::Circuit;
use p3_circuit::op::Prim;
use p3_field::{Field, PrimeCharacteristicRing};

/// A compact row-major container for transparent values.
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

/// A provider of transparent columns for a specific table.
pub trait TransparentProvider<F> {
    fn name(&self) -> &'static str;
    fn transparent_width(&self) -> usize;
    fn generate_transparent_rows(&self, circuit: &Circuit<F>) -> TransparentTrace<F>;
}

#[derive(Clone, Debug)]
pub struct TransparentTraceInfo {
    pub name: String,
    pub width: usize,
    pub height: usize,
}

#[derive(Clone, Debug, Default)]
pub struct TransparentCommitment {
    pub commit: Vec<u8>,
}

#[derive(Clone, Debug, Default)]
pub struct TransparentProvingKey<F> {
    pub commitment: TransparentCommitment,
    pub traces: Vec<TransparentTrace<F>>,
    pub infos: Vec<TransparentTraceInfo>,
    pub ordering: Vec<(String, usize)>,
}

#[derive(Clone, Debug, Default)]
pub struct TransparentVerifyingKey {
    pub commitment: TransparentCommitment,
    pub traces: Vec<TransparentTraceInfo>,
    pub ordering: Vec<(String, usize)>,
}

pub fn setup_transparent_columns<F: Field + PrimeCharacteristicRing>(
    circuit: &Circuit<F>,
    providers: &[&dyn TransparentProvider<F>],
) -> (TransparentProvingKey<F>, TransparentVerifyingKey) {
    let mut traces: Vec<TransparentTrace<F>> = Vec::new();
    let mut infos: Vec<TransparentTraceInfo> = Vec::new();
    let mut ordering: Vec<(String, usize)> = Vec::new();

    for provider in providers {
        let name = provider.name().to_string();
        let mut rows = provider.generate_transparent_rows(circuit);
        let padded_h = next_power_of_two(rows.height);
        if padded_h > rows.height && rows.width > 0 {
            let deficit = (padded_h - rows.height) * rows.width;
            rows.values.extend((0..deficit).map(|_| F::from_u64(0)));
            rows.height = padded_h;
        }
        infos.push(TransparentTraceInfo {
            name: name.clone(),
            width: rows.width,
            height: rows.height,
        });
        ordering.push((name, traces.len()));
        traces.push(rows);
    }

    let commitment = TransparentCommitment { commit: Vec::new() };
    let vk = TransparentVerifyingKey {
        commitment: commitment.clone(),
        traces: infos.clone(),
        ordering: ordering.clone(),
    };
    let pk = TransparentProvingKey {
        commitment,
        traces,
        infos,
        ordering,
    };

    (pk, vk)
}

#[inline]
fn next_power_of_two(n: usize) -> usize {
    if n == 0 { 0 } else { n.next_power_of_two() }
}

// Default providers (index columns)
struct WitnessIndexProvider;
struct ConstIndexProvider;
struct PublicIndexProvider;

impl<F: Field + Clone + PrimeCharacteristicRing> TransparentProvider<F> for WitnessIndexProvider {
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

impl<F: Field + Clone + PrimeCharacteristicRing> TransparentProvider<F> for ConstIndexProvider {
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

impl<F: Field + Clone + PrimeCharacteristicRing> TransparentProvider<F> for PublicIndexProvider {
    fn name(&self) -> &'static str {
        "PublicIndex"
    }
    fn transparent_width(&self) -> usize {
        1
    }
    fn generate_transparent_rows(&self, circuit: &Circuit<F>) -> TransparentTrace<F> {
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
        impl<F: Field + Clone + PrimeCharacteristicRing> TransparentProvider<F> for $name {
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

pub fn setup_default_transparent_indices<F: Field + Clone + PrimeCharacteristicRing>(
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
