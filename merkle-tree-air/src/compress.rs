use p3_field::{PrimeField, PrimeField64};
use p3_symmetric::{
    CompressionFunctionFromHasher, CryptographicHasher, CryptographicPermutation,
    PseudoCompressionFunction, TruncatedPermutation,
};

pub trait FieldCompression<F: PrimeField, const N: usize, const DIGEST_ELEMS: usize>:
    Clone
{
    fn compress_field(&self, inputs: [[F; DIGEST_ELEMS]; N]) -> [F; DIGEST_ELEMS];
}

impl<F: PrimeField, InnerP, const N: usize, const CHUNK: usize, const WIDTH: usize>
    FieldCompression<F, N, CHUNK> for TruncatedPermutation<InnerP, N, CHUNK, WIDTH>
where
    F: Copy + Default,
    InnerP: CryptographicPermutation<[F; WIDTH]>,
{
    fn compress_field(&self, inputs: [[F; CHUNK]; N]) -> [F; CHUNK] {
        self.compress(inputs)
    }
}

impl<F: PrimeField64, H, const N: usize, const CHUNK: usize> FieldCompression<F, N, CHUNK>
    for CompressionFunctionFromHasher<H, N, CHUNK>
where
    F: Copy,
    H: CryptographicHasher<u64, [u64; CHUNK]>,
{
    fn compress_field(&self, inputs: [[F; CHUNK]; N]) -> [F; CHUNK] {
        let field_inps = inputs
            .iter()
            .map(|xs| {
                xs.iter()
                    .map(|x| x.as_canonical_u64())
                    .collect::<Vec<_>>()
                    .try_into()
                    .unwrap()
            })
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();
        let bytes = self.compress(field_inps);
        bytes
            .iter()
            .map(|b| F::from_u64(*b))
            .collect::<Vec<_>>()
            .try_into()
            .unwrap()
    }
}
