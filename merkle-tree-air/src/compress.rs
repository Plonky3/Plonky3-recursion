use alloc::vec::Vec;

use p3_field::extension::BinomiallyExtendable;
use p3_field::{ExtensionField, Field, PrimeField, PrimeField64};
use p3_symmetric::{
    CompressionFunctionFromHasher, CryptographicHasher, CryptographicPermutation,
    PseudoCompressionFunction, TruncatedPermutation,
};

pub trait FieldCompression<F, EF, const D: usize, const N: usize, const DIGEST_ELEMS: usize>:
    Clone
{
    fn compress_field(&self, inputs: [[EF; DIGEST_ELEMS]; N]) -> [EF; DIGEST_ELEMS];
}

impl<F, EF, InnerP, const D: usize, const N: usize, const CHUNK: usize, const WIDTH: usize>
    FieldCompression<F, EF, D, N, CHUNK> for TruncatedPermutation<InnerP, N, CHUNK, WIDTH>
where
    EF: Copy + Default,
    InnerP: CryptographicPermutation<[EF; WIDTH]>,
{
    fn compress_field(&self, inputs: [[EF; CHUNK]; N]) -> [EF; CHUNK] {
        self.compress(inputs)
    }
}

// impl<F: PrimeField64, H, const N: usize, const CHUNK: usize> FieldCompression<F, F, 1, N, CHUNK>
//     for CompressionFunctionFromHasher<H, N, CHUNK>
// where
//     F: Copy,
//     H: CryptographicHasher<u64, [u64; CHUNK]>,
// {
//     fn compress_field(&self, inputs: [[F; CHUNK]; N]) -> [F; CHUNK] {
//         let field_inps = inputs
//             .iter()
//             .map(|xs| {
//                 xs.iter()
//                     .map(|x| x.as_canonical_u64())
//                     .collect::<Vec<_>>()
//                     .try_into()
//                     .unwrap()
//             })
//             .collect::<Vec<_>>()
//             .try_into()
//             .unwrap();
//         let bytes = self.compress(field_inps);
//         bytes
//             .iter()
//             .map(|b| F::from_u64(*b))
//             .collect::<Vec<_>>()
//             .try_into()
//             .unwrap()
//     }
// }

impl<F, EF, H, const D: usize, const N: usize, const CHUNK: usize, const BIG_CHUNK: usize>
    FieldCompression<F, EF, D, N, CHUNK> for CompressionFunctionFromHasher<H, N, BIG_CHUNK>
where
    F: PrimeField64 + Copy,
    EF: ExtensionField<F> + Copy,
    H: CryptographicHasher<u64, [u64; BIG_CHUNK]>,
{
    fn compress_field(&self, inputs: [[EF; CHUNK]; N]) -> [EF; CHUNK] {
        debug_assert!(CHUNK * D == BIG_CHUNK);
        let field_inps = inputs
            .iter()
            .map(|xs| {
                xs.iter()
                    .map(|xs| {
                        xs.as_basis_coefficients_slice()
                            .iter()
                            .map(|x| x.as_canonical_u64())
                    })
                    .flatten()
                    .collect::<Vec<_>>()
                    .try_into()
                    .unwrap()
            })
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();
        let bytes = self.compress(field_inps);
        bytes
            .chunks_exact(D)
            .map(|b| EF::from_basis_coefficients_fn(|i| F::from_u64(b[i])))
            .collect::<Vec<_>>()
            .try_into()
            .unwrap()
    }
}
