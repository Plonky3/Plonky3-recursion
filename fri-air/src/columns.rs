#[repr(C)]
pub struct OpenInputColumns<T, const D: usize> {
    pub alpha: [T; D],
    pub x: [T; D],
    pub z: [T; D],
    pub alpha_pow: [T; D],
    pub pow_at_x: [T; D],
    pub pow_at_z: [T; D],
    pub ro: [T; D],
}
