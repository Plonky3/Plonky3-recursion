FRI Verifier Immediate Values — Notes

Source test for reference:
- ../plonky3/fri/tests/fri.rs:190
- ../plonky3/fri/tests/fri.rs:316
- ../plonky3/fri/tests/fri.rs:415

Purpose
- Capture the exact sequence of transcript observations and computed values in the FRI verifier to inform AIR/circuit design for recursion.

Transcript Order (must match verifier)
- Observe polynomial sizes as field elements.
- Observe PCS commitment, then sample challenge point `zeta`.
- Observe all opened evaluations (PCS step before FRI verify).
- Sample batch-combination challenge `alpha` (../plonky3/fri/tests/fri.rs:437).
- For each commit-phase commitment: observe commitment then sample `beta` (../plonky3/fri/tests/fri.rs:456).
- Observe all final polynomial coefficients (constant when `log_final_poly_len = 0`).
- Check proof-of-work via `challenger.check_witness(bits, witness)`.
- For each query: sample index with `sample_bits(log_max_height)`, then perform input openings and FRI folding verification.

Key Parameters (from PCS FRI params)
- `log_blowup`, `log_final_poly_len`, `num_queries`, `proof_of_work_bits`.
- Heights: `log_global_max_height = rounds + log_blowup + log_final_poly_len` and `log_max_height` equal to the same in this setup.

Input Opening (reduced openings)
- For each matrix/domain (height `log_height`):
  - Compute `rev_reduced_index = reverse_bits_len(index >> bits_reduced, log_height)`.
  - Compute `x = g * h^rev_reduced_index` with `g = Val::GENERATOR`, `h = two_adic_generator(log_height)`.
  - For each `z` and evaluation pair `(p_at_x, p_at_z)`:
    - `quotient = (z - x)^{-1}`.
    - Accumulate reduced opening at `log_height`:
      `ro += alpha_pow * (p_at_z - p_at_x) * quotient`.
      Then update `alpha_pow *= alpha`.
- Constant-matrix check: if a matrix has height `log_blowup`, its reduced opening must be zero.

Commit-Phase MMCS Verification
- For phase `i` (0-based):
  - Domain height `log_folded_height = log_max_height - i - 1`.
  - Dimensions: `width = 2`, `height = 2^(log_folded_height)`.
  - Verify sibling opening with `fri_mmcs.verify_batch(commit_i, dims, domain_index_parent, proof)`.

Two-ary FRI Folding at beta
- With `evals = [e0, e1]` and subgroup points `x0, x1` where `x1 = -x0`:
  - Compute `rev_bits = reverse_bits_len(domain_index, log_folded_height)`.
  - `generator = two_adic_generator(log_folded_height + 1)` and `x0 = generator^rev_bits`.
  - Interpolation at `beta`:
    `folded_eval = e0 + (beta - x0) * (e1 - e0) * (x1 - x0)^{-1}`.
  - Roll-in (if any at this height): `folded_eval += beta^2 * reduced_opening`.

Final Check
- Compute final domain point `x` using `reverse_bits_len(domain_index, log_max_height)` and `two_adic_generator(log_max_height)`.
- Evaluate final polynomial at `x` (constant when `log_final_poly_len = 0`).
- Require equality with the folded evaluation from FRI.

Notable Line References
- Test function start: ../plonky3/fri/tests/fri.rs:190
- Capture function start: ../plonky3/fri/tests/fri.rs:316
- Verification simulation start: ../plonky3/fri/tests/fri.rs:415
- Alpha sampling: ../plonky3/fri/tests/fri.rs:437
- Beta sampling loop (after observing commitments): ../plonky3/fri/tests/fri.rs:456

