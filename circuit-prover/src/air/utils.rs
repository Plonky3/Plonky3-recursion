/// Shared utilities for AIR implementations
use alloc::vec::Vec;

use p3_field::Field;

/// Helper to pad trace values to power-of-two height by repeating the last row
pub fn pad_to_power_of_two<F: Field>(values: &mut Vec<F>, width: usize, original_height: usize) {
    if original_height == 0 {
        // Empty trace - just ensure we have at least one row of zeros
        values.resize(width, F::ZERO);
        return;
    }

    let target_height = original_height.next_power_of_two();
    if target_height == original_height {
        return; // Already power of two
    }

    // Repeat the last row to reach target height
    let last_row_start = (original_height - 1) * width;
    let last_row: Vec<F> = values[last_row_start..original_height * width].to_vec();

    for _ in original_height..target_height {
        values.extend_from_slice(&last_row);
    }
}

/// Helper to pad witness trace with monotonic index continuation
pub fn pad_witness_to_power_of_two<F: Field>(
    values: &mut Vec<F>,
    width: usize,
    original_height: usize,
) {
    assert!(
        original_height > 0,
        "original_height must be greater than 0"
    );

    let target_height = original_height.next_power_of_two();
    if target_height == original_height {
        return; // Already power of two
    }

    // Get last row values (excluding index)
    let last_row_start = (original_height - 1) * width;
    let last_row_values: Vec<F> = values[last_row_start..last_row_start + width - 1].to_vec();

    // Add padding rows with monotonic indices
    for i in original_height..target_height {
        values.extend_from_slice(&last_row_values);
        values.push(F::from_usize(i));
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec;

    use p3_baby_bear::BabyBear as Val;
    use p3_field::PrimeCharacteristicRing;

    use super::*;

    #[test]
    fn test_pad_to_power_of_two_basic() {
        // Test with 3 rows -> should pad to 4
        let mut values = vec![
            Val::from_u64(1),
            Val::from_u64(10), // row 0: [value=1, index=10]
            Val::from_u64(2),
            Val::from_u64(11), // row 1: [value=2, index=11]
            Val::from_u64(3),
            Val::from_u64(12), // row 2: [value=3, index=12]
        ];
        let width = 2;
        let original_height = 3;

        pad_to_power_of_two(&mut values, width, original_height);

        // Should be padded to 4 rows
        assert_eq!(values.len(), 4 * width);

        // Original rows should be unchanged
        assert_eq!(values[0], Val::from_u64(1));
        assert_eq!(values[1], Val::from_u64(10));
        assert_eq!(values[2], Val::from_u64(2));
        assert_eq!(values[3], Val::from_u64(11));
        assert_eq!(values[4], Val::from_u64(3));
        assert_eq!(values[5], Val::from_u64(12));

        // Padded row should repeat the last row exactly
        assert_eq!(values[6], Val::from_u64(3)); // same as row 2
        assert_eq!(values[7], Val::from_u64(12)); // same as row 2
    }

    #[test]
    fn test_pad_to_power_of_two_already_power_of_two() {
        // Test with 4 rows (already power of two) -> should not change
        let mut values = vec![
            Val::from_u64(1),
            Val::from_u64(2),
            Val::from_u64(3),
            Val::from_u64(4),
            Val::from_u64(5),
            Val::from_u64(6),
            Val::from_u64(7),
            Val::from_u64(8),
        ];
        let original = values.clone();
        let width = 2;
        let original_height = 4;

        pad_to_power_of_two(&mut values, width, original_height);

        // Should remain unchanged
        assert_eq!(values, original);
        assert_eq!(values.len(), 4 * width);
    }

    #[test]
    fn test_pad_witness_to_power_of_two_monotonic_indices() {
        // Test witness padding with 3 rows -> should pad to 4 with monotonic indices
        let mut values = vec![
            Val::from_u64(10),
            Val::from_u64(0), // row 0: [value=10, index=0]
            Val::from_u64(20),
            Val::from_u64(1), // row 1: [value=20, index=1]
            Val::from_u64(30),
            Val::from_u64(2), // row 2: [value=30, index=2]
        ];
        let width = 2;
        let original_height = 3;

        pad_witness_to_power_of_two(&mut values, width, original_height);

        // Should be padded to 4 rows
        assert_eq!(values.len(), 4 * width);

        // Original rows should be unchanged
        assert_eq!(values[0], Val::from_u64(10));
        assert_eq!(values[1], Val::from_u64(0));
        assert_eq!(values[2], Val::from_u64(20));
        assert_eq!(values[3], Val::from_u64(1));
        assert_eq!(values[4], Val::from_u64(30));
        assert_eq!(values[5], Val::from_u64(2));

        // Padded row should repeat last value but continue monotonic index
        assert_eq!(values[6], Val::from_u64(30)); // value from last row
        assert_eq!(values[7], Val::from_u64(3)); // index continues: 2 + 1 = 3
    }

    #[test]
    fn test_pad_witness_extension_field() {
        // Test witness padding with extension field (width = 5: 4 coefficients + 1 index)
        let mut values = vec![
            // Row 0: [a0, a1, a2, a3, index=0]
            Val::from_u64(1),
            Val::from_u64(2),
            Val::from_u64(3),
            Val::from_u64(4),
            Val::from_u64(0),
            // Row 1: [b0, b1, b2, b3, index=1]
            Val::from_u64(5),
            Val::from_u64(6),
            Val::from_u64(7),
            Val::from_u64(8),
            Val::from_u64(1),
            // Row 2: [c0, c1, c2, c3, index=2]
            Val::from_u64(9),
            Val::from_u64(10),
            Val::from_u64(11),
            Val::from_u64(12),
            Val::from_u64(2),
        ];
        let width = 5;
        let original_height = 3;

        pad_witness_to_power_of_two(&mut values, width, original_height);

        // Should be padded to 4 rows
        assert_eq!(values.len(), 4 * width);

        // Check padded row: should repeat last coefficients with monotonic index
        assert_eq!(values[15], Val::from_u64(9)); // c0 repeated
        assert_eq!(values[16], Val::from_u64(10)); // c1 repeated
        assert_eq!(values[17], Val::from_u64(11)); // c2 repeated
        assert_eq!(values[18], Val::from_u64(12)); // c3 repeated
        assert_eq!(values[19], Val::from_u64(3)); // index continues: 2 + 1 = 3
    }
}
