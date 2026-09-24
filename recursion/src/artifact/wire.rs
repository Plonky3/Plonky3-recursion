#[cfg(test)]
use alloc::string::String;
use alloc::vec::Vec;
use core::marker::PhantomData;
use core::mem::size_of;

use p3_field::integers::QuotientMap;
use p3_field::{BasedVectorSpace, PrimeField32, PrimeField64};

use super::{ArtifactError, ArtifactKind, ArtifactLimits};

const MAGIC: &[u8; 8] = b"P3RCART\0";
const VERSION: u16 = 2;
const HEADER_BYTES: usize = 17;

pub(crate) fn checked_product(left: usize, right: usize) -> Result<usize, ArtifactError> {
    left.checked_mul(right).ok_or(ArtifactError::LengthOverflow)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum FieldWidth {
    U32,
    U64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct FieldEncoding<F> {
    width: FieldWidth,
    _marker: PhantomData<F>,
}

impl<F: PrimeField32> FieldEncoding<F> {
    pub(crate) const fn u32() -> Self {
        Self {
            width: FieldWidth::U32,
            _marker: PhantomData,
        }
    }
}

impl<F: PrimeField64> FieldEncoding<F> {
    pub(crate) const fn u64() -> Self {
        Self {
            width: FieldWidth::U64,
            _marker: PhantomData,
        }
    }

    pub(crate) const fn encoded_bytes(self) -> usize {
        match self.width {
            FieldWidth::U32 => 4,
            FieldWidth::U64 => 8,
        }
    }
}

pub(crate) struct Writer {
    bytes: Vec<u8>,
    max_bytes: usize,
}

impl Writer {
    pub(crate) const fn new(max_bytes: usize) -> Self {
        Self {
            bytes: Vec::new(),
            max_bytes,
        }
    }

    fn write_bytes(&mut self, bytes: &[u8]) -> Result<(), ArtifactError> {
        let actual = self
            .bytes
            .len()
            .checked_add(bytes.len())
            .ok_or(ArtifactError::LengthOverflow)?;
        if actual > self.max_bytes {
            return Err(ArtifactError::DecodeLimitExceeded {
                component: "encoded bytes",
                actual,
                limit: self.max_bytes,
            });
        }
        self.bytes
            .try_reserve_exact(bytes.len())
            .map_err(|_| ArtifactError::AllocationFailed {
                component: "encoded bytes",
            })?;
        self.bytes.extend_from_slice(bytes);
        Ok(())
    }

    pub(crate) fn write_u8(&mut self, value: u8) -> Result<(), ArtifactError> {
        self.write_bytes(&[value])
    }

    pub(crate) fn write_bool(&mut self, value: bool) -> Result<(), ArtifactError> {
        self.write_u8(u8::from(value))
    }

    pub(crate) fn write_u16(&mut self, value: u16) -> Result<(), ArtifactError> {
        self.write_bytes(&value.to_le_bytes())
    }

    pub(crate) fn write_u32(&mut self, value: u32) -> Result<(), ArtifactError> {
        self.write_bytes(&value.to_le_bytes())
    }

    pub(crate) fn write_u64(&mut self, value: u64) -> Result<(), ArtifactError> {
        self.write_bytes(&value.to_le_bytes())
    }

    pub(crate) fn write_count(
        &mut self,
        component: &'static str,
        count: usize,
    ) -> Result<(), ArtifactError> {
        let count = u32::try_from(count).map_err(|_| ArtifactError::DecodeLimitExceeded {
            component,
            actual: count,
            limit: u32::MAX as usize,
        })?;
        self.write_u32(count)
    }

    pub(crate) fn write_vec<T>(
        &mut self,
        component: &'static str,
        values: &[T],
        mut write_item: impl FnMut(&mut Self, &T) -> Result<(), ArtifactError>,
    ) -> Result<(), ArtifactError> {
        self.write_count(component, values.len())?;
        for value in values {
            write_item(self, value)?;
        }
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn write_string(
        &mut self,
        value: &str,
        component: &'static str,
    ) -> Result<(), ArtifactError> {
        self.write_count(component, value.len())?;
        self.write_bytes(value.as_bytes())
    }

    pub(crate) fn write_field<F: PrimeField64>(
        &mut self,
        encoding: FieldEncoding<F>,
        value: F,
    ) -> Result<(), ArtifactError> {
        let value = value.as_canonical_u64();
        match encoding.width {
            FieldWidth::U32 => {
                let value = u32::try_from(value).map_err(|_| ArtifactError::NonCanonicalField)?;
                self.write_u32(value)
            }
            FieldWidth::U64 => self.write_u64(value),
        }
    }

    pub(crate) fn write_extension<F, EF>(
        &mut self,
        encoding: FieldEncoding<F>,
        value: &EF,
    ) -> Result<(), ArtifactError>
    where
        F: PrimeField64,
        EF: BasedVectorSpace<F>,
    {
        for &coefficient in value.as_basis_coefficients_slice() {
            self.write_field(encoding, coefficient)?;
        }
        Ok(())
    }

    pub(crate) fn finish(self) -> Result<Vec<u8>, ArtifactError> {
        Ok(self.bytes)
    }
}

pub(crate) struct Reader<'a> {
    bytes: &'a [u8],
    position: usize,
    limits: &'a ArtifactLimits,
    requested_allocation_bytes: usize,
    container_entries: usize,
    scalar_elements: usize,
}

impl<'a> Reader<'a> {
    pub(crate) const fn new(bytes: &'a [u8], limits: &'a ArtifactLimits) -> Self {
        Self {
            bytes,
            position: 0,
            limits,
            requested_allocation_bytes: 0,
            container_entries: 0,
            scalar_elements: 0,
        }
    }

    pub(crate) const fn remaining(&self) -> usize {
        self.bytes.len() - self.position
    }

    fn read_bytes(&mut self, count: usize) -> Result<&'a [u8], ArtifactError> {
        let end = self
            .position
            .checked_add(count)
            .ok_or(ArtifactError::LengthOverflow)?;
        let bytes = self
            .bytes
            .get(self.position..end)
            .ok_or(ArtifactError::Truncated)?;
        self.position = end;
        Ok(bytes)
    }

    pub(crate) fn read_u8(&mut self) -> Result<u8, ArtifactError> {
        Ok(self.read_bytes(1)?[0])
    }

    pub(crate) fn read_u16(&mut self) -> Result<u16, ArtifactError> {
        Ok(u16::from_le_bytes(self.read_bytes(2)?.try_into().unwrap()))
    }

    pub(crate) fn read_u32(&mut self) -> Result<u32, ArtifactError> {
        Ok(u32::from_le_bytes(self.read_bytes(4)?.try_into().unwrap()))
    }

    pub(crate) fn read_u64(&mut self) -> Result<u64, ArtifactError> {
        Ok(u64::from_le_bytes(self.read_bytes(8)?.try_into().unwrap()))
    }

    pub(crate) fn read_bool(&mut self, component: &'static str) -> Result<bool, ArtifactError> {
        match self.read_u8()? {
            0 => Ok(false),
            1 => Ok(true),
            tag => Err(ArtifactError::InvalidTag { component, tag }),
        }
    }

    pub(crate) fn read_field<F: PrimeField64>(
        &mut self,
        encoding: FieldEncoding<F>,
    ) -> Result<F, ArtifactError> {
        let scalar_elements = self
            .scalar_elements
            .checked_add(1)
            .ok_or(ArtifactError::LengthOverflow)?;
        if scalar_elements > self.limits.verifier.max_total_scalar_elements {
            return Err(ArtifactError::DecodeLimitExceeded {
                component: "scalar elements",
                actual: scalar_elements,
                limit: self.limits.verifier.max_total_scalar_elements,
            });
        }
        self.scalar_elements = scalar_elements;
        match encoding.width {
            FieldWidth::U32 => {
                let value = self.read_u32()?;
                <F as QuotientMap<u32>>::from_canonical_checked(value)
                    .ok_or(ArtifactError::NonCanonicalField)
            }
            FieldWidth::U64 => {
                let value = self.read_u64()?;
                <F as QuotientMap<u64>>::from_canonical_checked(value)
                    .ok_or(ArtifactError::NonCanonicalField)
            }
        }
    }

    pub(crate) fn read_extension<F, EF>(
        &mut self,
        encoding: FieldEncoding<F>,
    ) -> Result<EF, ArtifactError>
    where
        F: PrimeField64,
        EF: BasedVectorSpace<F>,
    {
        let mut error = None;
        let value = EF::from_basis_coefficients_fn(|_| {
            if error.is_some() {
                return F::ZERO;
            }
            match self.read_field(encoding) {
                Ok(value) => value,
                Err(err) => {
                    error = Some(err);
                    F::ZERO
                }
            }
        });
        error.map_or_else(|| Ok(value), Err)
    }

    fn charge_container<T>(&mut self, count: usize) -> Result<(), ArtifactError> {
        let entries = count.checked_add(1).ok_or(ArtifactError::LengthOverflow)?;
        let actual_entries = self
            .container_entries
            .checked_add(entries)
            .ok_or(ArtifactError::LengthOverflow)?;
        if actual_entries > self.limits.max_container_entries {
            return Err(ArtifactError::DecodeLimitExceeded {
                component: "container entries",
                actual: actual_entries,
                limit: self.limits.max_container_entries,
            });
        }

        let storage = checked_product(count, size_of::<T>())?;
        let allocation = size_of::<Vec<T>>()
            .checked_add(storage)
            .ok_or(ArtifactError::LengthOverflow)?;
        let actual_bytes = self
            .requested_allocation_bytes
            .checked_add(allocation)
            .ok_or(ArtifactError::LengthOverflow)?;
        if actual_bytes > self.limits.max_decoded_bytes {
            return Err(ArtifactError::DecodeLimitExceeded {
                component: "decoded allocation bytes",
                actual: actual_bytes,
                limit: self.limits.max_decoded_bytes,
            });
        }

        self.container_entries = actual_entries;
        self.requested_allocation_bytes = actual_bytes;
        Ok(())
    }

    pub(crate) fn charge_conversion_vec<T>(&mut self, count: usize) -> Result<(), ArtifactError> {
        self.charge_container::<T>(count)
    }

    pub(crate) fn read_alternate_slice<T>(
        &mut self,
        bytes: &[u8],
        read: impl FnOnce(&mut Reader<'_>) -> Result<T, ArtifactError>,
    ) -> Result<T, ArtifactError> {
        let mut alternate = Reader {
            bytes,
            position: 0,
            limits: self.limits,
            requested_allocation_bytes: self.requested_allocation_bytes,
            container_entries: self.container_entries,
            scalar_elements: self.scalar_elements,
        };
        let value = read(&mut alternate);
        let consumed_all = alternate.position == alternate.bytes.len();
        self.requested_allocation_bytes = alternate.requested_allocation_bytes;
        self.container_entries = alternate.container_entries;
        self.scalar_elements = alternate.scalar_elements;
        let value = value?;
        if !consumed_all {
            return Err(ArtifactError::TrailingBytes);
        }
        Ok(value)
    }

    pub(crate) fn read_vec<T>(
        &mut self,
        component: &'static str,
        minimum_item_bytes: usize,
        mut read_item: impl FnMut(&mut Self) -> Result<T, ArtifactError>,
    ) -> Result<Vec<T>, ArtifactError> {
        self.read_vec_limited(
            component,
            self.limits.max_container_entries,
            minimum_item_bytes,
            |reader| read_item(reader),
        )
    }

    pub(crate) fn read_vec_limited<T>(
        &mut self,
        component: &'static str,
        max_count: usize,
        minimum_item_bytes: usize,
        mut read_item: impl FnMut(&mut Self) -> Result<T, ArtifactError>,
    ) -> Result<Vec<T>, ArtifactError> {
        let raw_count = self.read_u32()?;
        let count = usize::try_from(raw_count).map_err(|_| ArtifactError::LengthOverflow)?;
        let limit = max_count.min(self.limits.max_container_entries);
        if count > limit {
            return Err(ArtifactError::DecodeLimitExceeded {
                component,
                actual: count,
                limit,
            });
        }
        let minimum_bytes = checked_product(count, minimum_item_bytes)?;
        if minimum_bytes > self.remaining() {
            return Err(ArtifactError::Truncated);
        }
        self.charge_container::<T>(count)?;

        let mut values = Vec::new();
        values
            .try_reserve_exact(count)
            .map_err(|_| ArtifactError::AllocationFailed { component })?;
        for _ in 0..count {
            values.push(read_item(self)?);
        }
        Ok(values)
    }

    pub(crate) fn read_vec_exact<T>(
        &mut self,
        component: &'static str,
        expected_count: usize,
        minimum_item_bytes: usize,
        mut read_item: impl FnMut(&mut Self) -> Result<T, ArtifactError>,
    ) -> Result<Vec<T>, ArtifactError> {
        let raw_count = self.read_u32()?;
        let count = usize::try_from(raw_count).map_err(|_| ArtifactError::LengthOverflow)?;
        if count != expected_count {
            return Err(ArtifactError::MalformedProof { component });
        }
        let minimum_bytes = checked_product(count, minimum_item_bytes)?;
        if minimum_bytes > self.remaining() {
            return Err(ArtifactError::Truncated);
        }
        self.charge_container::<T>(count)?;
        let mut values = Vec::new();
        values
            .try_reserve_exact(count)
            .map_err(|_| ArtifactError::AllocationFailed { component })?;
        for _ in 0..count {
            values.push(read_item(self)?);
        }
        Ok(values)
    }

    pub(crate) fn read_exact_items<T>(
        &mut self,
        component: &'static str,
        count: usize,
        min_item_bytes: usize,
        mut read_item: impl FnMut(&mut Self) -> Result<T, ArtifactError>,
    ) -> Result<Vec<T>, ArtifactError> {
        self.charge_container::<T>(count)?;
        let min_bytes = checked_product(count, min_item_bytes)?;
        if min_bytes > self.remaining() {
            return Err(ArtifactError::Truncated);
        }
        let mut values = Vec::new();
        values
            .try_reserve_exact(count)
            .map_err(|_| ArtifactError::AllocationFailed { component })?;
        for _ in 0..count {
            values.push(read_item(self)?);
        }
        Ok(values)
    }

    #[cfg(test)]
    pub(crate) fn read_string(&mut self, component: &'static str) -> Result<String, ArtifactError> {
        let bytes = self.read_vec(component, 1, |reader| reader.read_u8())?;
        String::from_utf8(bytes).map_err(|_| ArtifactError::NonCanonicalMetadata)
    }

    #[cfg(test)]
    pub(crate) const fn requested_allocation_bytes(&self) -> usize {
        self.requested_allocation_bytes
    }

    #[cfg(test)]
    pub(crate) const fn container_entries(&self) -> usize {
        self.container_entries
    }

    pub(crate) const fn limits(&self) -> &ArtifactLimits {
        self.limits
    }

    pub(crate) const fn finish(self) -> Result<(), ArtifactError> {
        if self.position == self.bytes.len() {
            Ok(())
        } else {
            Err(ArtifactError::TrailingBytes)
        }
    }
}

pub(crate) fn encode_framed(
    kind: ArtifactKind,
    suite: u16,
    max_bytes: usize,
    write_body: impl FnOnce(&mut Writer) -> Result<(), ArtifactError>,
) -> Result<Vec<u8>, ArtifactError> {
    let body_limit =
        max_bytes
            .checked_sub(HEADER_BYTES)
            .ok_or(ArtifactError::DecodeLimitExceeded {
                component: "encoded bytes",
                actual: HEADER_BYTES,
                limit: max_bytes,
            })?;
    let mut body = Writer::new(body_limit);
    write_body(&mut body)?;
    let body = body.finish()?;
    let body_len = u32::try_from(body.len()).map_err(|_| ArtifactError::LengthOverflow)?;

    let mut framed = Writer::new(max_bytes);
    framed.write_bytes(MAGIC)?;
    framed.write_u16(VERSION)?;
    framed.write_u8(kind as u8)?;
    framed.write_u16(suite)?;
    framed.write_u32(body_len)?;
    framed.write_bytes(&body)?;
    framed.finish()
}

pub(crate) fn decode_framed<T>(
    bytes: &[u8],
    expected_kind: ArtifactKind,
    limits: &ArtifactLimits,
    suite_supported: impl FnOnce(u16) -> bool,
    read_body: impl FnOnce(u16, &mut Reader<'_>) -> Result<T, ArtifactError>,
) -> Result<T, ArtifactError> {
    let max_bytes = match expected_kind {
        ArtifactKind::Verifier => limits.max_verifier_bytes,
        ArtifactKind::Proof => limits.max_proof_bytes,
    };
    if bytes.len() > max_bytes {
        return Err(ArtifactError::DecodeLimitExceeded {
            component: "artifact bytes",
            actual: bytes.len(),
            limit: max_bytes,
        });
    }
    if bytes.len() < MAGIC.len() {
        return if MAGIC.starts_with(bytes) {
            Err(ArtifactError::Truncated)
        } else {
            Err(ArtifactError::BadMagic)
        };
    }
    if bytes.get(..MAGIC.len()) != Some(MAGIC) {
        return Err(ArtifactError::BadMagic);
    }
    if bytes.len() < HEADER_BYTES {
        return Err(ArtifactError::Truncated);
    }

    let version = u16::from_le_bytes(bytes[8..10].try_into().unwrap());
    if version != VERSION {
        return Err(ArtifactError::UnsupportedVersion(version));
    }
    if bytes[10] != expected_kind as u8 {
        return Err(ArtifactError::WrongArtifactKind);
    }
    let suite = u16::from_le_bytes(bytes[11..13].try_into().unwrap());
    if !suite_supported(suite) {
        return Err(ArtifactError::UnsupportedSuite(suite));
    }
    let body_len = u32::from_le_bytes(bytes[13..17].try_into().unwrap());
    let body_len = usize::try_from(body_len).map_err(|_| ArtifactError::LengthOverflow)?;
    let expected_len = HEADER_BYTES
        .checked_add(body_len)
        .ok_or(ArtifactError::LengthOverflow)?;
    if bytes.len() < expected_len {
        return Err(ArtifactError::Truncated);
    }
    if bytes.len() > expected_len {
        return Err(ArtifactError::TrailingBytes);
    }

    let mut reader = Reader::new(&bytes[HEADER_BYTES..], limits);
    let value = read_body(suite, &mut reader)?;
    reader.finish()?;
    Ok(value)
}

pub(crate) fn validate_frame_envelope(
    bytes: &[u8],
    expected_kind: ArtifactKind,
    max_bytes: usize,
) -> Result<(), ArtifactError> {
    if bytes.len() > max_bytes {
        return Err(ArtifactError::DecodeLimitExceeded {
            component: "artifact bytes",
            actual: bytes.len(),
            limit: max_bytes,
        });
    }
    if bytes.len() < MAGIC.len() {
        return if MAGIC.starts_with(bytes) {
            Err(ArtifactError::Truncated)
        } else {
            Err(ArtifactError::BadMagic)
        };
    }
    if bytes.get(..MAGIC.len()) != Some(MAGIC) {
        return Err(ArtifactError::BadMagic);
    }
    if bytes.len() < HEADER_BYTES {
        return Err(ArtifactError::Truncated);
    }
    let version = u16::from_le_bytes(bytes[8..10].try_into().unwrap());
    if version != VERSION {
        return Err(ArtifactError::UnsupportedVersion(version));
    }
    if bytes[10] != expected_kind as u8 {
        return Err(ArtifactError::WrongArtifactKind);
    }
    let body_len = usize::try_from(u32::from_le_bytes(bytes[13..17].try_into().unwrap()))
        .map_err(|_| ArtifactError::LengthOverflow)?;
    let expected_len = HEADER_BYTES
        .checked_add(body_len)
        .ok_or(ArtifactError::LengthOverflow)?;
    if bytes.len() < expected_len {
        return Err(ArtifactError::Truncated);
    }
    if bytes.len() > expected_len {
        return Err(ArtifactError::TrailingBytes);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use alloc::vec;

    use p3_baby_bear::BabyBear;
    use p3_field::{PrimeCharacteristicRing, PrimeField32};
    use p3_goldilocks::Goldilocks;

    use super::{
        ArtifactError, ArtifactKind, ArtifactLimits, FieldEncoding, Reader, Writer,
        checked_product, decode_framed, encode_framed,
    };

    #[test]
    fn header_has_exact_golden_bytes_and_roundtrips_body() {
        let limits = ArtifactLimits::default();
        let encoded = encode_framed(ArtifactKind::Proof, 0x1234, limits.max_proof_bytes, |w| {
            w.write_u16(0xabcd)
        })
        .unwrap();

        assert_eq!(
            encoded,
            vec![
                b'P', b'3', b'R', b'C', b'A', b'R', b'T', 0, 1, 0, 2, 0x34, 0x12, 2, 0, 0, 0, 0xcd,
                0xab,
            ]
        );

        let value = decode_framed(
            &encoded,
            ArtifactKind::Proof,
            &limits,
            |suite| suite == 0x1234,
            |suite, reader| {
                assert_eq!(suite, 0x1234);
                reader.read_u16()
            },
        )
        .unwrap();
        assert_eq!(value, 0xabcd);
    }

    #[test]
    fn header_rejects_bad_kind_version_suite_extent_and_trailing_data() {
        let limits = ArtifactLimits::default();
        let valid =
            encode_framed(ArtifactKind::Proof, 7, limits.max_proof_bytes, |_| Ok(())).unwrap();

        let decode = |bytes: &[u8], kind, suite_ok: fn(u16) -> bool| {
            decode_framed(bytes, kind, &limits, suite_ok, |_, _| Ok(()))
        };
        assert_eq!(
            decode(&valid, ArtifactKind::Verifier, |_| true),
            Err(ArtifactError::WrongArtifactKind)
        );

        let mut wrong_version = valid.clone();
        wrong_version[8] = 2;
        assert_eq!(
            decode(&wrong_version, ArtifactKind::Proof, |_| true),
            Err(ArtifactError::UnsupportedVersion(2))
        );
        assert_eq!(
            decode(&valid, ArtifactKind::Proof, |_| false),
            Err(ArtifactError::UnsupportedSuite(7))
        );

        let mut too_long = valid.clone();
        too_long[13..17].copy_from_slice(&1_u32.to_le_bytes());
        assert_eq!(
            decode(&too_long, ArtifactKind::Proof, |_| true),
            Err(ArtifactError::Truncated)
        );

        let mut trailing = valid;
        trailing.push(0);
        assert_eq!(
            decode(&trailing, ArtifactKind::Proof, |_| true),
            Err(ArtifactError::TrailingBytes)
        );
        assert_eq!(
            decode(&[1, 2, 3], ArtifactKind::Proof, |_| true),
            Err(ArtifactError::BadMagic)
        );
        assert_eq!(
            decode(b"P3R", ArtifactKind::Proof, |_| true),
            Err(ArtifactError::Truncated)
        );

        let postcard = postcard::to_allocvec(&17_u32).unwrap();
        assert_eq!(
            decode(&postcard, ArtifactKind::Proof, |_| true),
            Err(ArtifactError::BadMagic)
        );
    }

    #[test]
    fn canonical_fields_reject_modulus_and_truncated_extension() {
        let limits = ArtifactLimits::default();
        let mut writer = Writer::new(64);
        let field = FieldEncoding::<BabyBear>::u32();
        writer.write_field(field, BabyBear::from_u32(9)).unwrap();
        let encoded = writer.finish().unwrap();
        assert_eq!(encoded, 9_u32.to_le_bytes());

        let mut reader = Reader::new(&encoded, &limits);
        assert_eq!(reader.read_field(field).unwrap().as_canonical_u32(), 9);
        reader.finish().unwrap();

        let modulus = BabyBear::ORDER_U32.to_le_bytes();
        let mut reader = Reader::new(&modulus, &limits);
        assert_eq!(
            reader.read_field(field),
            Err(ArtifactError::NonCanonicalField)
        );

        type EF = p3_field::extension::BinomialExtensionField<BabyBear, 4>;
        let mut reader = Reader::new(&[0; 12], &limits);
        assert_eq!(
            reader.read_extension::<BabyBear, EF>(field),
            Err(ArtifactError::Truncated)
        );
    }

    #[test]
    fn counts_check_minimum_body_and_charge_empty_containers() {
        let limits = ArtifactLimits {
            max_container_entries: 3,
            ..ArtifactLimits::default()
        };
        let excessive_count = 4_u32.to_le_bytes();
        let mut reader = Reader::new(&excessive_count, &limits);
        assert_eq!(
            reader.read_vec("items", 1, |_| Ok(())),
            Err(ArtifactError::DecodeLimitExceeded {
                component: "items",
                actual: 4,
                limit: 3,
            })
        );

        let limits = ArtifactLimits {
            max_container_entries: 6,
            ..ArtifactLimits::default()
        };
        let bytes = [
            2_u32.to_le_bytes(),
            0_u32.to_le_bytes(),
            0_u32.to_le_bytes(),
        ]
        .concat();
        let mut reader = Reader::new(&bytes, &limits);
        let nested = reader
            .read_vec("outer", 4, |r| {
                r.read_vec::<u8>("inner", 1, |_| unreachable!())
            })
            .unwrap();
        assert_eq!(nested, vec![vec![], vec![]]);
        assert_eq!(reader.container_entries(), 5);

        let default_limits = ArtifactLimits::default();
        let mut reader = Reader::new(&[2, 0, 0, 0, 1], &default_limits);
        assert_eq!(
            reader.read_vec::<u16>("u16s", 2, |r| r.read_u16()),
            Err(ArtifactError::Truncated)
        );
    }

    #[test]
    fn allocation_budget_applies_before_reservation_at_exact_boundary() {
        let vec_cost = core::mem::size_of::<alloc::vec::Vec<u64>>() + 2 * size_of::<u64>();
        let bytes = [
            2_u32.to_le_bytes().as_slice(),
            &[1, 0, 0, 0, 0, 0, 0, 0],
            &[2, 0, 0, 0, 0, 0, 0, 0],
        ]
        .concat();

        let exact = ArtifactLimits {
            max_decoded_bytes: vec_cost,
            ..ArtifactLimits::default()
        };
        let mut reader = Reader::new(&bytes, &exact);
        assert_eq!(
            reader.read_vec("values", 8, |r| r.read_u64()).unwrap(),
            vec![1, 2]
        );
        assert_eq!(reader.requested_allocation_bytes(), vec_cost);

        let mut below = exact;
        below.max_decoded_bytes -= 1;
        let mut reader = Reader::new(&bytes, &below);
        assert_eq!(
            reader.read_vec::<u64>("values", 8, |r| r.read_u64()),
            Err(ArtifactError::DecodeLimitExceeded {
                component: "decoded allocation bytes",
                actual: vec_cost,
                limit: vec_cost - 1,
            })
        );
        assert_eq!(reader.requested_allocation_bytes(), 0);
    }

    #[test]
    fn u64_fields_and_exact_bool_string_encodings_are_canonical() {
        let limits = ArtifactLimits::default();
        let mut writer = Writer::new(128);
        writer
            .write_field(FieldEncoding::<Goldilocks>::u64(), Goldilocks::from_u64(17))
            .unwrap();
        writer.write_bool(true).unwrap();
        writer.write_string("ok", "metadata").unwrap();
        let bytes = writer.finish().unwrap();
        assert_eq!(&bytes[..8], &17_u64.to_le_bytes());

        let mut reader = Reader::new(&bytes, &limits);
        assert_eq!(
            reader
                .read_field(FieldEncoding::<Goldilocks>::u64())
                .unwrap(),
            Goldilocks::from_u64(17)
        );
        assert!(reader.read_bool("enabled").unwrap());
        assert_eq!(reader.read_string("metadata").unwrap(), "ok");
        reader.finish().unwrap();

        let mut reader = Reader::new(&[2], &limits);
        assert_eq!(
            reader.read_bool("enabled"),
            Err(ArtifactError::InvalidTag {
                component: "enabled",
                tag: 2,
            })
        );
        let mut reader = Reader::new(&[1, 0, 0, 0, 0xff], &limits);
        assert_eq!(
            reader.read_string("metadata"),
            Err(ArtifactError::NonCanonicalMetadata)
        );
    }

    #[test]
    fn empty_strings_consume_container_work_and_products_are_checked() {
        let mut writer = Writer::new(128);
        writer.write_u32(4).unwrap();
        for _ in 0..4 {
            writer.write_string("", "metadata").unwrap();
        }
        let bytes = writer.finish().unwrap();
        let limits = ArtifactLimits {
            max_container_entries: 8,
            ..ArtifactLimits::default()
        };
        let mut reader = Reader::new(&bytes, &limits);
        assert_eq!(
            reader.read_vec::<alloc::string::String>("strings", 4, |reader| {
                reader.read_string("metadata")
            }),
            Err(ArtifactError::DecodeLimitExceeded {
                component: "container entries",
                actual: 9,
                limit: 8,
            })
        );
        assert_eq!(
            checked_product(usize::MAX, 2),
            Err(ArtifactError::LengthOverflow)
        );
    }

    #[test]
    fn encoded_byte_limit_is_exact() {
        let exact =
            encode_framed(ArtifactKind::Proof, 1, 19, |writer| writer.write_u16(9)).unwrap();
        assert_eq!(exact.len(), 19);
        assert_eq!(
            encode_framed(ArtifactKind::Proof, 1, 18, |writer| writer.write_u16(9)),
            Err(ArtifactError::DecodeLimitExceeded {
                component: "encoded bytes",
                actual: 2,
                limit: 1,
            })
        );
    }
}
