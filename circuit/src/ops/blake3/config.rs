//! Blake3 configuration types.

/// Config payload stored in `NpoConfig` for the Blake3 table.
///
/// Since Blake3 computation is performed natively in u32 arithmetic
/// by the executor, the config only carries static compression parameters.
#[derive(Clone, Debug)]
pub(crate) struct Blake3ConfigData {
    pub counter_low: u32,
    pub counter_high: u32,
    pub block_len: u32,
    pub flags: u32,
}

impl Default for Blake3ConfigData {
    fn default() -> Self {
        Self {
            counter_low: 0,
            counter_high: 0,
            block_len: 64,
            flags: 0x04, // PARENT
        }
    }
}
