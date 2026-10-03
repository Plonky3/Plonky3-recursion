//! Closed native scalar encodings, independent of recursive limb widths.

use super::*;
use p3_binary_field::{Poly64, Poly192, TowerLevel};
use p3_field::{Field, PrimeCharacteristicRing};

pub(in crate::artifact::binary_native) trait ScalarWire:
    Field
{
    const WIRE_BYTES: usize;
    const INPUT_LIMBS: usize;
    fn write_le(self, w: &mut Writer) -> Result<(), ArtifactError>;
    fn read_le(r: &mut Reader<'_>) -> Result<Self, ArtifactError>;
}

impl<F: RecursiveBinaryTowerField> ScalarWire for F {
    const WIRE_BYTES: usize = F::RAW_BITS / 8;
    const INPUT_LIMBS: usize = 8;
    fn write_le(self, w: &mut Writer) -> Result<(), ArtifactError> {
        w.write_bytes(&self.raw_coordinates().to_le_bytes()[..Self::WIRE_BYTES])
    }
    fn read_le(r: &mut Reader<'_>) -> Result<Self, ArtifactError> {
        Ok(Self::from_le_byte_iter(
            r.read_bytes(Self::WIRE_BYTES)?.iter().copied(),
        ))
    }
}

impl ScalarWire for Poly64 {
    const WIRE_BYTES: usize = 8;
    const INPUT_LIMBS: usize = 4;
    fn write_le(self, w: &mut Writer) -> Result<(), ArtifactError> {
        w.write_bytes(&self.to_repr().to_le_bytes())
    }
    fn read_le(r: &mut Reader<'_>) -> Result<Self, ArtifactError> {
        Ok(Self::new(u64::from_le_bytes(
            r.read_bytes(8)?.try_into().unwrap(),
        )))
    }
}

impl ScalarWire for Poly192 {
    const WIRE_BYTES: usize = 24;
    const INPUT_LIMBS: usize = 12;
    fn write_le(self, w: &mut Writer) -> Result<(), ArtifactError> {
        for coefficient in self.coefficients() {
            coefficient.write_le(w)?;
        }
        Ok(())
    }
    fn read_le(r: &mut Reader<'_>) -> Result<Self, ArtifactError> {
        let mut coefficients = [Poly64::ZERO; 3];
        for coefficient in &mut coefficients {
            *coefficient = Poly64::read_le(r)?;
        }
        Ok(Self::new(coefficients))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use p3_binary_field::{BinaryField8, BinaryField32, BinaryField128};

    fn check<T: ScalarWire>(value: T, expected: &[u8], limbs: usize) {
        let mut writer = Writer::new(64);
        super::super::write_field(&mut writer, value).unwrap();
        let bytes = writer.finish().unwrap();
        assert_eq!(bytes, expected);
        let limits = ArtifactLimits {
            verifier: crate::verifier::VerifierLimits {
                max_total_scalar_elements: limbs,
                ..Default::default()
            },
            ..Default::default()
        };
        let mut reader = Reader::new(&bytes, &limits);
        assert_eq!(super::super::read_field::<T>(&mut reader).unwrap(), value);
        reader.finish().unwrap();
        for length in 0..bytes.len() {
            assert!(
                super::super::read_field::<T>(&mut Reader::new(&bytes[..length], &limits)).is_err()
            );
        }
        let below = ArtifactLimits {
            verifier: crate::verifier::VerifierLimits {
                max_total_scalar_elements: limbs - 1,
                ..limits.verifier
            },
            ..limits
        };
        assert!(matches!(
            super::super::read_field::<T>(&mut Reader::new(&bytes, &below)),
            Err(ArtifactError::DecodeLimitExceeded { component: "scalar elements", actual, limit })
            if actual == limbs && limit == limbs - 1
        ));
    }

    #[test]
    fn tower_wire_bytes_and_eight_limb_charges_remain_unchanged() {
        check(BinaryField8::from_repr(0xa5), &[0xa5], 8);
        check(
            BinaryField32::from_repr(0x7654_3210),
            &[0x10, 0x32, 0x54, 0x76],
            8,
        );
        let raw = 0xfedc_ba98_7654_3210_0123_4567_89ab_cdefu128;
        check(BinaryField128::from_repr(raw), &raw.to_le_bytes(), 8);
    }

    #[test]
    fn polynomial_wire_preserves_coefficient_order_and_exact_limb_charges() {
        let words = [
            0x0706_0504_0302_0100,
            0x0f0e_0d0c_0b0a_0908,
            0x1716_1514_1312_1110,
        ];
        check(Poly64::new(words[0]), &[0, 1, 2, 3, 4, 5, 6, 7], 4);
        let value = Poly192::new(words.map(Poly64::new));
        check(value, &(0..24u8).collect::<Vec<_>>(), 12);
    }
}
