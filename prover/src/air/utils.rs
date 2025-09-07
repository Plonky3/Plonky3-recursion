/// Shared utilities for AIR implementations
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
