//! Closed streaming serde bridge for the released opaque grouped multiproof.

use core::fmt;
use core::marker::PhantomData;
use core::mem::size_of;

use p3_binary_pcs::GroupedCodewordMmcs;
use p3_commit::Mmcs;
use p3_field::PackedValue;
use serde::de::{DeserializeSeed, SeqAccess, Visitor};
use serde::ser::{Impossible, SerializeSeq, SerializeStruct, SerializeTuple};
use serde::{Deserialize, Serialize};

use super::super::config::NativeMmcs;
use super::GroupedOracleDecode;
use crate::artifact::ArtifactError;
use crate::artifact::wire::{Reader, Writer, checked_product};
use crate::pcs::binary::RecursiveBinaryTowerField;

type Proof<F> = <GroupedCodewordMmcs<NativeMmcs<F>> as Mmcs<F>>::MultiProof;

#[derive(Debug)]
struct Error(ArtifactError);
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}
impl core::error::Error for Error {}
const fn invalid() -> Error {
    Error(ArtifactError::MalformedProof {
        component: "binary grouped proof structure",
    })
}
impl serde::ser::Error for Error {
    fn custom<T: fmt::Display>(_: T) -> Self {
        invalid()
    }
}
impl serde::de::Error for Error {
    fn custom<T: fmt::Display>(_: T) -> Self {
        invalid()
    }
}
impl From<ArtifactError> for Error {
    fn from(e: ArtifactError) -> Self {
        Self(e)
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Node {
    Root,
    Inner,
    Frontier,
    Missing,
    Digest,
    Field(usize),
}

pub(super) fn write<F>(w: &mut Writer, p: &Proof<F>) -> Result<(), ArtifactError>
where
    F: RecursiveBinaryTowerField + PackedValue<Value = F>,
{
    p.serialize(Encoder {
        sink: Sink::Writer(w),
        node: Node::Root,
        bits: F::RAW_BITS,
    })
    .map_err(|e| e.0)
}

enum Sink<'a> {
    Writer(&'a mut Writer),
    Byte(&'a mut u8),
}
impl<'a> Sink<'a> {
    fn bytes(self, bytes: &[u8]) -> Result<(), Error> {
        match self {
            Self::Writer(w) => w.write_bytes(bytes).map_err(Error),
            Self::Byte(slot) if bytes.len() == 1 => {
                *slot = bytes[0];
                Ok(())
            }
            _ => Err(invalid()),
        }
    }
    const fn writer(self) -> Result<&'a mut Writer, Error> {
        match self {
            Self::Writer(w) => Ok(w),
            _ => Err(invalid()),
        }
    }
}
struct Encoder<'a> {
    sink: Sink<'a>,
    node: Node,
    bits: usize,
}
struct Sequence<'a> {
    w: &'a mut Writer,
    child: Node,
    bits: usize,
    remaining: usize,
    digest: Option<[u8; 32]>,
}
struct Structure<'a> {
    w: &'a mut Writer,
    node: Node,
    bits: usize,
    index: usize,
}

impl Sequence<'_> {
    fn item<T: ?Sized + Serialize>(&mut self, value: &T) -> Result<(), Error> {
        if self.remaining == 0 {
            return Err(invalid());
        }
        let sink = if let Some(digest) = &mut self.digest {
            Sink::Byte(&mut digest[32 - self.remaining])
        } else {
            Sink::Writer(self.w)
        };
        value.serialize(Encoder {
            sink,
            node: self.child,
            bits: self.bits,
        })?;
        self.remaining -= 1;
        Ok(())
    }
    fn finish(self) -> Result<(), Error> {
        if self.remaining == 0 {
            if let Some(digest) = self.digest {
                self.w.write_bytes(&digest)?;
            }
            Ok(())
        } else {
            Err(invalid())
        }
    }
}
impl SerializeSeq for Sequence<'_> {
    type Ok = ();
    type Error = Error;
    fn serialize_element<T: ?Sized + Serialize>(&mut self, v: &T) -> Result<(), Error> {
        self.item(v)
    }
    fn end(self) -> Result<(), Error> {
        self.finish()
    }
}
impl SerializeTuple for Sequence<'_> {
    type Ok = ();
    type Error = Error;
    fn serialize_element<T: ?Sized + Serialize>(&mut self, v: &T) -> Result<(), Error> {
        self.item(v)
    }
    fn end(self) -> Result<(), Error> {
        self.finish()
    }
}
impl SerializeStruct for Structure<'_> {
    type Ok = ();
    type Error = Error;
    fn serialize_field<T: ?Sized + Serialize>(
        &mut self,
        key: &'static str,
        value: &T,
    ) -> Result<(), Error> {
        let child = match (self.node, self.index, key) {
            (Node::Root, 0, "inner") => Node::Inner,
            (Node::Root, 1, "missing_symbols") => Node::Missing,
            (Node::Inner, 0, "sibling_hashes") => Node::Frontier,
            _ => return Err(invalid()),
        };
        value.serialize(Encoder {
            sink: Sink::Writer(self.w),
            node: child,
            bits: self.bits,
        })?;
        self.index += 1;
        Ok(())
    }
    fn end(self) -> Result<(), Error> {
        match (self.node, self.index) {
            (Node::Root, 2) | (Node::Inner, 1) => Ok(()),
            _ => Err(invalid()),
        }
    }
}
macro_rules! unsigned_ser {
    ($($method:ident : $ty:ty = $bits:expr),*) => {$ (
        fn $method(self, value: $ty) -> Result<(), Error> {
            if self.node != Node::Field($bits) { return Err(invalid()); }
            self.sink.bytes(&value.to_le_bytes())
        }
    )*};
}
macro_rules! rejected_ser {
    ($($method:ident : $ty:ty),*) => {$ (
        fn $method(self, _: $ty) -> Result<(), Error> { Err(invalid()) }
    )*};
}
impl<'a> serde::Serializer for Encoder<'a> {
    type Ok = ();
    type Error = Error;
    type SerializeSeq = Sequence<'a>;
    type SerializeTuple = Sequence<'a>;
    type SerializeStruct = Structure<'a>;
    type SerializeTupleStruct = Impossible<(), Error>;
    type SerializeTupleVariant = Impossible<(), Error>;
    type SerializeMap = Impossible<(), Error>;
    type SerializeStructVariant = Impossible<(), Error>;
    unsigned_ser!(serialize_u8:u8=8,serialize_u16:u16=16,serialize_u32:u32=32,serialize_u64:u64=64,serialize_u128:u128=128);
    rejected_ser!(serialize_bool:bool,serialize_i8:i8,serialize_i16:i16,serialize_i32:i32,serialize_i64:i64,serialize_i128:i128,serialize_f32:f32,serialize_f64:f64,serialize_char:char);
    fn serialize_str(self, _: &str) -> Result<(), Error> {
        Err(invalid())
    }
    fn serialize_bytes(self, _: &[u8]) -> Result<(), Error> {
        Err(invalid())
    }
    fn serialize_none(self) -> Result<(), Error> {
        Err(invalid())
    }
    fn serialize_some<T: ?Sized + Serialize>(self, _: &T) -> Result<(), Error> {
        Err(invalid())
    }
    fn serialize_unit(self) -> Result<(), Error> {
        Err(invalid())
    }
    fn serialize_unit_struct(self, _: &'static str) -> Result<(), Error> {
        Err(invalid())
    }
    fn serialize_unit_variant(self, _: &'static str, _: u32, _: &'static str) -> Result<(), Error> {
        Err(invalid())
    }
    fn serialize_newtype_struct<T: ?Sized + Serialize>(
        self,
        _: &'static str,
        _: &T,
    ) -> Result<(), Error> {
        Err(invalid())
    }
    fn serialize_newtype_variant<T: ?Sized + Serialize>(
        self,
        _: &'static str,
        _: u32,
        _: &'static str,
        _: &T,
    ) -> Result<(), Error> {
        Err(invalid())
    }
    fn serialize_seq(self, len: Option<usize>) -> Result<Sequence<'a>, Error> {
        let child = match self.node {
            Node::Frontier => Node::Digest,
            Node::Missing => Node::Field(self.bits),
            _ => return Err(invalid()),
        };
        let len = len.ok_or_else(invalid)?;
        let w = self.sink.writer()?;
        w.write_count("binary grouped proof vector", len)?;
        Ok(Sequence {
            w,
            child,
            bits: self.bits,
            remaining: len,
            digest: None,
        })
    }
    fn serialize_tuple(self, len: usize) -> Result<Sequence<'a>, Error> {
        if self.node != Node::Digest || len != 32 {
            return Err(invalid());
        }
        Ok(Sequence {
            w: self.sink.writer()?,
            child: Node::Field(8),
            bits: self.bits,
            remaining: 32,
            digest: Some([0; 32]),
        })
    }
    fn serialize_struct(self, name: &'static str, len: usize) -> Result<Structure<'a>, Error> {
        match (self.node, name, len) {
            (Node::Root, "GroupedCodewordProof", 2) | (Node::Inner, "PrunedMerklePaths", 1) => {}
            _ => return Err(invalid()),
        }
        Ok(Structure {
            w: self.sink.writer()?,
            node: self.node,
            bits: self.bits,
            index: 0,
        })
    }
    fn serialize_tuple_struct(
        self,
        _: &'static str,
        _: usize,
    ) -> Result<Self::SerializeTupleStruct, Error> {
        Err(invalid())
    }
    fn serialize_tuple_variant(
        self,
        _: &'static str,
        _: u32,
        _: &'static str,
        _: usize,
    ) -> Result<Self::SerializeTupleVariant, Error> {
        Err(invalid())
    }
    fn serialize_map(self, _: Option<usize>) -> Result<Self::SerializeMap, Error> {
        Err(invalid())
    }
    fn serialize_struct_variant(
        self,
        _: &'static str,
        _: u32,
        _: &'static str,
        _: usize,
    ) -> Result<Self::SerializeStructVariant, Error> {
        Err(invalid())
    }
    fn collect_str<T: ?Sized + fmt::Display>(self, _: &T) -> Result<(), Error> {
        Err(invalid())
    }
    fn is_human_readable(&self) -> bool {
        false
    }
}

#[derive(Clone, Copy)]
struct Bounds {
    frontier: usize,
    missing: usize,
}
impl Bounds {
    fn from_shape(s: &GroupedOracleDecode) -> Result<Self, ArtifactError> {
        let groups = (1usize << s.symbol_bits) / s.group_size;
        let q = s.rows / s.coset_width;
        let touched = checked_product(q, (s.coset_width / s.group_size).max(1))?.min(groups);
        Ok(Self {
            frontier: checked_product(touched, s.path_len)?,
            missing: checked_product(touched, s.group_size - s.group_size.min(s.coset_width))?,
        })
    }
}

pub(super) fn read<F>(
    r: &mut Reader<'_>,
    s: &GroupedOracleDecode,
    total: &mut usize,
) -> Result<Proof<F>, ArtifactError>
where
    F: RecursiveBinaryTowerField + PackedValue<Value = F>,
{
    let bounds = Bounds::from_shape(s)?;
    Proof::<F>::deserialize(Decoder::<F> {
        r,
        node: Node::Root,
        bounds,
        total,
        field: PhantomData,
    })
    .map_err(|e| e.0)
}

struct Decoder<'a, 'r, F> {
    r: &'a mut Reader<'r>,
    node: Node,
    bounds: Bounds,
    total: &'a mut usize,
    field: PhantomData<F>,
}
struct Access<'a, 'r, F> {
    r: &'a mut Reader<'r>,
    parent: Node,
    bounds: Bounds,
    total: &'a mut usize,
    index: usize,
    remaining: usize,
    field: PhantomData<F>,
}
impl<F: RecursiveBinaryTowerField> Decoder<'_, '_, F> {
    fn visit<'de, V: Visitor<'de>>(self, count: usize, v: V) -> Result<V::Value, Error> {
        let mut access = Access::<F> {
            r: self.r,
            parent: self.node,
            bounds: self.bounds,
            total: self.total,
            index: 0,
            remaining: count,
            field: PhantomData,
        };
        let value = v.visit_seq(&mut access)?;
        if access.remaining != 0 {
            return Err(invalid());
        }
        Ok(value)
    }
    fn vector<T>(
        &mut self,
        component: &'static str,
        max: usize,
        bytes: usize,
        scalars: usize,
    ) -> Result<usize, Error> {
        let n = usize::try_from(self.r.read_u32()?).map_err(|_| ArtifactError::LengthOverflow)?;
        let limit = max.min(self.r.limits().max_container_entries);
        if n > limit {
            return Err(Error(ArtifactError::DecodeLimitExceeded {
                component,
                actual: n,
                limit,
            }));
        }
        if checked_product(n, bytes)? > self.r.remaining() {
            return Err(Error(ArtifactError::Truncated));
        }
        // Locked serde reserves at most 1 MiB before pushing remaining items.
        // These element sizes are powers of two; std's doubling growth stays
        // below 2*n. Charge the capacity allowance separately from logical items.
        let capacity = if checked_product(n, size_of::<T>())? > 1 << 20 {
            n.checked_mul(2).ok_or(ArtifactError::LengthOverflow)?
        } else {
            n
        };
        self.r.charge_streamed_vec::<T>(n, capacity)?;
        self.r.charge_binary_scalars(checked_product(n, scalars)?)?;
        Ok(n)
    }
}
impl<'de, F: RecursiveBinaryTowerField> SeqAccess<'de> for Access<'_, '_, F> {
    type Error = Error;
    fn next_element_seed<T: DeserializeSeed<'de>>(
        &mut self,
        seed: T,
    ) -> Result<Option<T::Value>, Error> {
        if self.remaining == 0 {
            return Ok(None);
        }
        let node = match (self.parent, self.index) {
            (Node::Root, 0) => Node::Inner,
            (Node::Root, 1) => Node::Missing,
            (Node::Inner, 0) => Node::Frontier,
            (Node::Frontier, _) => Node::Digest,
            (Node::Missing, _) => Node::Field(F::RAW_BITS),
            (Node::Digest, _) => Node::Field(8),
            _ => return Err(invalid()),
        };
        let value = seed.deserialize(Decoder::<F> {
            r: self.r,
            node,
            bounds: self.bounds,
            total: self.total,
            field: PhantomData,
        })?;
        self.index += 1;
        self.remaining -= 1;
        Ok(Some(value))
    }
    fn size_hint(&self) -> Option<usize> {
        Some(self.remaining)
    }
}
macro_rules! unsigned_de {
    ($($method:ident : $ty:ty = $bits:expr => $visit:ident),*) => {$ (
        fn $method<V:Visitor<'de>>(self,v:V)->Result<V::Value,Error>{
            if self.node!=Node::Field($bits){return Err(invalid());}
            let bytes=self.r.read_bytes($bits/8)?;
            v.$visit(<$ty>::from_le_bytes(bytes.try_into().map_err(|_|invalid())?))
        }
    )*};
}
impl<'de, F: RecursiveBinaryTowerField> serde::Deserializer<'de> for Decoder<'_, '_, F> {
    type Error = Error;
    fn deserialize_any<V: Visitor<'de>>(self, _: V) -> Result<V::Value, Error> {
        Err(invalid())
    }
    unsigned_de!(deserialize_u8:u8=8=>visit_u8,deserialize_u16:u16=16=>visit_u16,deserialize_u32:u32=32=>visit_u32,deserialize_u64:u64=64=>visit_u64,deserialize_u128:u128=128=>visit_u128);
    fn deserialize_struct<V: Visitor<'de>>(
        self,
        name: &'static str,
        fields: &'static [&'static str],
        v: V,
    ) -> Result<V::Value, Error> {
        let count = match (self.node, name, fields) {
            (Node::Root, "GroupedCodewordProof", ["inner", "missing_symbols"]) => 2,
            (Node::Inner, "PrunedMerklePaths", ["sibling_hashes"]) => 1,
            _ => return Err(invalid()),
        };
        self.visit(count, v)
    }
    fn deserialize_tuple<V: Visitor<'de>>(self, len: usize, v: V) -> Result<V::Value, Error> {
        if self.node != Node::Digest || len != 32 {
            return Err(invalid());
        }
        self.visit(32, v)
    }
    fn deserialize_seq<V: Visitor<'de>>(mut self, v: V) -> Result<V::Value, Error> {
        let count = match self.node {
            Node::Frontier => {
                let remaining = self
                    .r
                    .limits()
                    .verifier
                    .max_compressed_frontier_hashes
                    .checked_sub(*self.total)
                    .ok_or(ArtifactError::LengthOverflow)?;
                let n = self.vector::<[u8; 32]>(
                    "binary compressed frontier",
                    self.bounds.frontier.min(remaining),
                    32,
                    16,
                )?;
                *self.total = self
                    .total
                    .checked_add(n)
                    .ok_or(ArtifactError::LengthOverflow)?;
                n
            }
            Node::Missing => self.vector::<F>(
                "binary grouped supplements",
                self.bounds.missing,
                F::RAW_BITS / 8,
                8,
            )?,
            _ => return Err(invalid()),
        };
        self.visit(count, v)
    }
    serde::forward_to_deserialize_any! {
        bool i8 i16 i32 i64 i128 f32 f64 char str string bytes byte_buf option unit
        unit_struct newtype_struct tuple_struct map enum identifier ignored_any
    }
    fn is_human_readable(&self) -> bool {
        false
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec;
    use alloc::vec::Vec;

    use p3_binary_field::{BinaryField8, BinaryField64, BinaryField128};
    use p3_merkle_tree::PrunedMerklePaths;

    use super::*;
    use crate::artifact::ArtifactLimits;

    #[derive(Serialize)]
    #[serde(rename = "GroupedCodewordProof")]
    struct Shell<F> {
        inner: PrunedMerklePaths<u8, 32>,
        missing_symbols: Vec<F>,
    }

    fn shape() -> GroupedOracleDecode {
        GroupedOracleDecode {
            rows: 4,
            symbol_bits: 8,
            group_size: 4,
            coset_width: 2,
            path_len: 5,
        }
    }
    fn roundtrip<F: RecursiveBinaryTowerField + PackedValue<Value = F>>() {
        let fields = [0u128, 0x91, u128::MAX]
            .map(|v| F::from_le_byte_iter(v.to_le_bytes().into_iter().take(F::RAW_BITS / 8)));
        let source = Shell {
            inner: PrunedMerklePaths {
                sibling_hashes: vec![[3; 32], [0xff; 32], [17; 32]],
            },
            missing_symbols: fields.to_vec(),
        };
        // Test-only native construction: production uses the streaming shell.
        let encoded = postcard::to_allocvec(&source).unwrap();
        let native: Proof<F> = postcard::from_bytes(&encoded).unwrap();
        let mut w = Writer::new(4096);
        write::<F>(&mut w, &native).unwrap();
        let bytes = w.finish().unwrap();
        let mut expected = 3u32.to_le_bytes().to_vec();
        expected.extend([3u8; 32]);
        expected.extend([0xffu8; 32]);
        expected.extend([17u8; 32]);
        expected.extend(3u32.to_le_bytes());
        for value in fields {
            expected.extend(&value.raw_coordinates().to_le_bytes()[..F::RAW_BITS / 8]);
        }
        assert_eq!(bytes, expected);
        let limits = ArtifactLimits::default();
        let mut r = Reader::new(&bytes, &limits);
        let mut total = 0;
        let restored = read::<F>(&mut r, &shape(), &mut total).unwrap();
        r.finish().unwrap();
        assert_eq!(total, 3);
        let mut w = Writer::new(4096);
        write::<F>(&mut w, &restored).unwrap();
        assert_eq!(w.finish().unwrap(), bytes);
    }
    #[test]
    fn released_opaque_fields_stream_in_their_exact_native_widths() {
        roundtrip::<BinaryField8>();
        roundtrip::<BinaryField64>();
        roundtrip::<BinaryField128>();
    }
    #[test]
    fn declared_counts_and_minimum_bodies_are_checked_before_vector_allocation() {
        let limits = ArtifactLimits::default();
        let mut total = 0;
        let bytes = u32::MAX.to_le_bytes();
        let mut r = Reader::new(&bytes, &limits);
        assert!(matches!(
            read::<BinaryField8>(&mut r, &shape(), &mut total),
            Err(ArtifactError::DecodeLimitExceeded {
                component: "binary compressed frontier",
                ..
            })
        ));
        assert_eq!(r.requested_allocation_bytes(), 0);
        let bytes = 1u32.to_le_bytes();
        let mut r = Reader::new(&bytes, &limits);
        assert!(matches!(
            read::<BinaryField8>(&mut r, &shape(), &mut total),
            Err(ArtifactError::Truncated)
        ));
        assert_eq!(r.requested_allocation_bytes(), 0);
        let mut no_missing = shape();
        no_missing.group_size = 1;
        let bytes = [0, 0, 0, 0, 1, 0, 0, 0];
        let mut r = Reader::new(&bytes, &limits);
        assert!(matches!(
            read::<BinaryField8>(&mut r, &no_missing, &mut total),
            Err(ArtifactError::DecodeLimitExceeded {
                component: "binary grouped supplements",
                ..
            })
        ));
    }
    #[test]
    fn consecutive_opaque_oracles_share_the_frontier_budget() {
        let mut bytes = 2u32.to_le_bytes().to_vec();
        bytes.extend([7u8; 64]);
        bytes.extend(0u32.to_le_bytes());
        let both = [bytes.as_slice(), bytes.as_slice()].concat();
        let mut limits = ArtifactLimits::default();
        limits.verifier.max_compressed_frontier_hashes = 3;
        let mut r = Reader::new(&both, &limits);
        let mut total = 0;
        read::<BinaryField128>(&mut r, &shape(), &mut total).unwrap();
        let allocated = r.requested_allocation_bytes();
        assert_eq!(total, 2);
        assert!(matches!(
            read::<BinaryField128>(&mut r, &shape(), &mut total),
            Err(ArtifactError::DecodeLimitExceeded {
                component: "binary compressed frontier",
                ..
            })
        ));
        assert_eq!(r.requested_allocation_bytes(), allocated);
    }
    #[test]
    fn serde_growth_capacity_is_budgeted_above_the_preallocation_threshold() {
        let count = 32769usize;
        let mut bytes = (count as u32).to_le_bytes().to_vec();
        bytes.resize(4 + count * 32, 0);
        bytes.extend(0u32.to_le_bytes());
        let shape = GroupedOracleDecode {
            rows: count * 2,
            symbol_bits: 20,
            group_size: 1,
            coset_width: 2,
            path_len: 1,
        };
        let mut limits = ArtifactLimits::default();
        limits.max_decoded_bytes = 1 << 21;
        let mut r = Reader::new(&bytes, &limits);
        let mut total = 0;
        assert!(matches!(
            read::<BinaryField128>(&mut r, &shape, &mut total),
            Err(ArtifactError::DecodeLimitExceeded {
                component: "decoded allocation bytes",
                ..
            })
        ));
        assert_eq!(r.requested_allocation_bytes(), 0);
        let allowance = count * 2 * 32 + 2 * size_of::<Vec<u8>>();
        limits.max_decoded_bytes = allowance;
        let mut r = Reader::new(&bytes, &limits);
        read::<BinaryField128>(&mut r, &shape, &mut total).unwrap();
        assert_eq!(r.requested_allocation_bytes(), allowance);
        r.finish().unwrap();
        limits.max_decoded_bytes = allowance - 1;
        let mut r = Reader::new(&bytes, &limits);
        let mut total = 0;
        assert!(matches!(
            read::<BinaryField128>(&mut r, &shape, &mut total),
            Err(ArtifactError::DecodeLimitExceeded {
                component: "decoded allocation bytes",
                ..
            })
        ));
    }
    #[test]
    fn serde_requests_outside_the_released_shape_fail_closed() {
        #[derive(Serialize)]
        #[serde(rename = "GroupedCodewordProof")]
        struct Bad {
            inner: u8,
            missing_symbols: Vec<BinaryField8>,
        }
        let mut w = Writer::new(1024);
        assert!(
            Bad {
                inner: 0,
                missing_symbols: vec![]
            }
            .serialize(Encoder {
                sink: Sink::Writer(&mut w),
                node: Node::Root,
                bits: 8
            })
            .is_err()
        );
        #[derive(Serialize)]
        #[serde(rename = "PrunedMerklePaths")]
        struct WrongDigest {
            sibling_hashes: Vec<[u8; 31]>,
        }
        let mut w = Writer::new(1024);
        assert!(
            WrongDigest {
                sibling_hashes: vec![[0; 31]]
            }
            .serialize(Encoder {
                sink: Sink::Writer(&mut w),
                node: Node::Inner,
                bits: 8
            })
            .is_err()
        );
        let limits = ArtifactLimits::default();
        let mut r = Reader::new(&[], &limits);
        let mut total = 0;
        assert!(
            bool::deserialize(Decoder::<BinaryField8> {
                r: &mut r,
                node: Node::Root,
                bounds: Bounds {
                    frontier: 0,
                    missing: 0
                },
                total: &mut total,
                field: PhantomData
            })
            .is_err()
        );
        assert_eq!(r.requested_allocation_bytes(), 0);
    }
}
