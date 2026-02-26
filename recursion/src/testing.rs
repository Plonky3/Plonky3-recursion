#[derive(Debug, Clone, Copy)]
pub struct FriParams {
    pub log_blowup: usize,
    pub max_log_arity: usize,
    pub cap_height: usize,
    pub log_final_poly_len: usize,
    pub commit_pow_bits: usize,
    pub query_pow_bits: usize,
}
