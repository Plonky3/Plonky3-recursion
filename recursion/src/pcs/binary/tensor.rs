//! Bit tensors for Boolean ring switching, in the native tower coordinate basis.

use alloc::vec::Vec;
use alloc::{format, vec};
use core::hash::Hash;
use core::marker::PhantomData;

use p3_circuit::ops::BinaryTower128Target;
use p3_circuit::{CircuitBuilder, CircuitBuilderError, ExprId};
use p3_field::Field;

use super::RecursiveBinaryChallengeField;

/// An element of `E tensor E` over the bit field. Row u's bit v is the
/// coefficient of `basis_u tensor basis_v`. Both tensor legs use raw native
/// tower coordinates, zero-extended into checked 128-bit arithmetic targets.
#[derive(Clone, Debug)]
pub struct BinaryTowerTensorTarget<E> {
    rows: Vec<BinaryTower128Target>,
    field: PhantomData<E>,
}

impl<E: RecursiveBinaryChallengeField> BinaryTowerTensorTarget<E> {
    /// Checks the native row count and constrains every row to the native field.
    /// Targets must have been created by this builder.
    pub fn from_rows<F: Field + Eq + Hash>(
        circuit: &mut CircuitBuilder<F>,
        rows: Vec<BinaryTower128Target>,
    ) -> Result<Self, CircuitBuilderError> {
        check_len("BinaryTensorRows", rows.len(), E::RAW_BITS)?;
        constrain_width::<E, F>(circuit, &rows);
        Ok(Self {
            rows,
            field: PhantomData,
        })
    }

    pub fn rows(&self) -> &[BinaryTower128Target] {
        &self.rows
    }

    /// Transposes only bit coordinates; no tensor multiplication is involved.
    pub fn transpose<F: Field + Eq + Hash>(
        &self,
        circuit: &mut CircuitBuilder<F>,
    ) -> Result<Self, CircuitBuilderError> {
        let rows = (0..E::RAW_BITS)
            .map(|v| {
                circuit.binary128_from_bits(core::array::from_fn(|u| {
                    if u < E::RAW_BITS {
                        self.rows[u].bits()[v]
                    } else {
                        ExprId::ZERO
                    }
                }))
            })
            .collect::<Result<_, _>>()?;
        Ok(Self {
            rows,
            field: PhantomData,
        })
    }

    /// Reads the row multilinear extension at the native batching point.
    /// Native points use big-endian variable order, hence adjacent pairs fold
    /// under the point's last coordinate first. The column reading is the row
    /// reading of `transpose()`.
    pub fn evaluate_rows<F: Field + Eq + Hash>(
        &self,
        circuit: &mut CircuitBuilder<F>,
        point: &[BinaryTower128Target],
    ) -> Result<BinaryTower128Target, CircuitBuilderError> {
        check_len(
            "BinaryTensorPoint",
            point.len(),
            E::RAW_BITS.ilog2() as usize,
        )?;
        constrain_width::<E, F>(circuit, point);
        let mut rows = self.rows.clone();
        for coordinate in point.iter().rev() {
            rows = rows
                .as_chunks::<2>()
                .0
                .iter()
                .map(|pair| {
                    let slope = circuit.binary128_add(&pair[0], &pair[1]);
                    let increment = circuit.binary128_mul(coordinate, &slope);
                    circuit.binary128_add(&pair[0], &increment)
                })
                .collect();
        }
        Ok(rows.remove(0))
    }

    fn one<F: Field + Eq + Hash>(
        circuit: &mut CircuitBuilder<F>,
    ) -> Result<Self, CircuitBuilderError> {
        let mut rows = vec![circuit.binary128_constant(0)?; E::RAW_BITS];
        rows[0] = circuit.binary128_constant(1)?;
        Ok(Self {
            rows,
            field: PhantomData,
        })
    }

    // Multiply by 1 + a tensor 1 + 1 tensor b. The two scalings act on
    // opposite legs; combining the original tensor with row scaling gives
    // row scaling by 1+b instead of forming a third tensor state.
    fn equality_factor<F: Field + Eq + Hash>(
        &mut self,
        circuit: &mut CircuitBuilder<F>,
        a: &BinaryTower128Target,
        b: &BinaryTower128Target,
    ) -> Result<(), CircuitBuilderError> {
        let mut columns = self.transpose(circuit)?;
        for column in &mut columns.rows {
            *column = circuit.binary128_mul(a, column);
        }
        let first = columns.transpose(circuit)?;
        let one = circuit.binary128_constant(1)?;
        let not_b = circuit.binary128_add(&one, b);
        for (row, first) in self.rows.iter_mut().zip(&first.rows) {
            let second = circuit.binary128_mul(&not_b, row);
            *row = circuit.binary128_add(first, &second);
        }
        Ok(())
    }

    fn add_exterior<F: Field + Eq + Hash>(
        &mut self,
        circuit: &mut CircuitBuilder<F>,
        a: &BinaryTower128Target,
        b: &BinaryTower128Target,
    ) -> Result<(), CircuitBuilderError> {
        for (u, row) in self.rows.iter_mut().enumerate() {
            let bits = core::array::from_fn(|v| {
                if v < E::RAW_BITS {
                    circuit.mul(a.bits()[u], b.bits()[v])
                } else {
                    ExprId::ZERO
                }
            });
            let term = circuit.binary128_from_bits(bits)?;
            *row = circuit.binary128_add(row, &term);
        }
        Ok(())
    }
}

/// Closes a native bit ring-switch reduction at its full restored surviving
/// high point. `batch` has log2(E's bit width) coordinates. For a successor
/// wider than one packed element, provide `(kept_row_variables, alpha)`, where
/// `kept_row_variables = native_row_variables - log2(E's bit width)`.
/// Other claims use `None`, including successors contained in one element.
///
/// The result batches the equality tensor plus alpha times the successor carry
/// tensor plus alpha squared times the repeated-last tensor. Skipped common
/// Boolean prefix coordinates are restored in `survivor`; their factors are
/// one. Individual longer Boolean prefixes contribute native selector gates.
/// Even an empty high point still batches the identity tensor, not field one.
/// All targets must have been created by this builder.
pub fn binary_tensor_closing_weight<E, F>(
    circuit: &mut CircuitBuilder<F>,
    high: &[BinaryTower128Target],
    survivor: &[BinaryTower128Target],
    batch: &[BinaryTower128Target],
    successor: Option<(usize, &BinaryTower128Target)>,
) -> Result<BinaryTower128Target, CircuitBuilderError>
where
    E: RecursiveBinaryChallengeField,
    F: Field + Eq + Hash,
{
    check_len("BinaryTensorSurvivor", survivor.len(), high.len())?;
    check_len(
        "BinaryTensorBatch",
        batch.len(),
        E::RAW_BITS.ilog2() as usize,
    )?;
    if let Some((kept, _)) = successor
        && (kept == 0 || kept > high.len())
    {
        return Err(CircuitBuilderError::NonPrimitiveOpArity {
            op: "BinaryTensorSuccessor",
            expected: format!("1..={} kept row variables", high.len()),
            got: kept,
        });
    }
    constrain_width::<E, F>(circuit, high);
    constrain_width::<E, F>(circuit, survivor);
    let mut tensor = BinaryTowerTensorTarget::<E>::one(circuit)?;
    let selector = if let Some((kept, alpha)) = successor {
        constrain_width::<E, F>(circuit, core::slice::from_ref(alpha));
        let selector = high.len() - kept;
        let one = circuit.binary128_constant(1)?;
        let mut a_product = one.clone();
        let mut b_complement = alpha.clone();
        let mut b_product = one.clone();
        for (a, b) in high[selector..].iter().zip(&survivor[selector..]).rev() {
            let next_a = circuit.binary128_mul(&a_product, a);
            let not_b = circuit.binary128_add(&one, b);
            let next_complement = circuit.binary128_mul(&b_complement, &not_b);
            let next_b = circuit.binary128_mul(&b_product, b);
            tensor.equality_factor(circuit, a, b)?;
            let left = circuit.binary128_add(&a_product, &next_a);
            let right = circuit.binary128_add(&b_complement, &next_complement);
            tensor.add_exterior(circuit, &left, &right)?;
            a_product = next_a;
            b_complement = next_complement;
            b_product = next_b;
        }
        let alpha_squared = circuit.binary128_square(alpha);
        let last_right = circuit.binary128_mul(&alpha_squared, &b_product);
        tensor.add_exterior(circuit, &a_product, &last_right)?;
        selector
    } else {
        high.len()
    };
    for (a, b) in high[..selector].iter().zip(&survivor[..selector]) {
        tensor.equality_factor(circuit, a, b)?;
    }
    tensor.evaluate_rows(circuit, batch)
}

fn constrain_width<E: RecursiveBinaryChallengeField, F: Field + Eq + Hash>(
    circuit: &mut CircuitBuilder<F>,
    values: &[BinaryTower128Target],
) {
    for bit in values.iter().flat_map(|value| &value.bits()[E::RAW_BITS..]) {
        let difference = circuit.sub(ExprId::ZERO, *bit);
        circuit.assert_zero(difference);
    }
}

fn check_len(op: &'static str, got: usize, expected: usize) -> Result<(), CircuitBuilderError> {
    if got == expected {
        Ok(())
    } else {
        Err(CircuitBuilderError::NonPrimitiveOpArity {
            op,
            expected: format!("{expected} coordinates"),
            got,
        })
    }
}
