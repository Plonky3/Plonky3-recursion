#!/usr/bin/env bash
set -euo pipefail

# Runs a recursive example, keeps only the PROFILING lines,
# truncates to the chunk starting at the LAST "global: OpCounts" (included),
# then converts OpCounts blocks to CSV.
#
# Usage: ./scripts/profiling.sh [fibonacci|keccak|aggregation]
# Default example is "fibonacci".
#
# Default example parameters:
# - fibonacci:  -n 10000
# - keccak:     -n 1000
# - aggregation: (no -n argument)
#
# Output columns:
# scope, # primitives, publics, consts, adds, subs, muls, divs, horner_accs, bool_checks, # non-primitives, poseidon2_perm, recompose_npo, unconstrained

export RUSTFLAGS="-Ctarget-cpu=native -Copt-level=3"

example="${1:-fibonacci}"

case "$example" in
  fibonacci)
    example_bin="recursive_fibonacci"
    example_args="-n 10000 --num-recursive-layers 4"
    ;;
  keccak)
    example_bin="recursive_keccak"
    example_args="-n 1000 --num-recursive-layers 4"
    ;;
  aggregation)
    example_bin="recursive_aggregation"
    example_args="--num-recursive-layers 3"
    ;;
  *)
    echo "Unknown example: $example" >&2
    echo "Usage: $0 [fibonacci|keccak|aggregation]" >&2
    exit 1
    ;;
esac

echo "Profiling $example_bin with args: $example_args"
echo "----------------------------------------"

RUST_LOG=info cargo run --release --example "$example_bin" -q --features parallel,profiling -- $example_args \
| grep -E "PROFILING" \
| awk '
  # Keep only lines after the LAST appearance of "global: OpCounts" (included).
  /global: OpCounts/ { n=0 }
  { buf[n++] = $0 }
  END { for (i=0; i<n; i++) print buf[i] }
' \
| awk '
  BEGIN {
    OFS=",";
    print "scope,# primitives,publics,consts,adds,subs,muls,divs,horner_accs,bool_checks,# non-primitives,poseidon2_perm,recompose_npo,unconstrained"
  }

  /\[PROFILING\].*OpCounts \{/ {
    # --- scope name ---
    scope = ""
    if ($0 ~ /\[PROFILING\].*global: OpCounts/) {
      scope = "global"
    } else if (match($0, /scope: "[^"]+"/)) {
      scope = substr($0, RSTART+8, RLENGTH-9)  # inside quotes
    } else {
      next
    }

    # Defaults
    publics=0; consts=0; adds=0; subs=0; muls=0; divs=0; horner_accs=0; bool_checks=0;
    poseidon2_perm=0; recompose_npo=0; unconstrained=0;

    # Extract OpCounts body for simpler parsing
    line = $0
    start = index(line, "OpCounts {")
    if (start == 0) next
    body = substr(line, start)

    # Primitive fields (if present)
    if (match(body, /publics: [0-9]+/)) publics = substr(body, RSTART+9,  RLENGTH-9)  + 0
    if (match(body, /consts: [0-9]+/))  consts  = substr(body, RSTART+8,  RLENGTH-8)  + 0
    if (match(body, /adds: [0-9]+/))    adds    = substr(body, RSTART+6,  RLENGTH-6)  + 0
    if (match(body, /subs: [0-9]+/))    subs    = substr(body, RSTART+6,  RLENGTH-6)  + 0
    if (match(body, /muls: [0-9]+/))    muls    = substr(body, RSTART+6,  RLENGTH-6)  + 0
    if (match(body, /divs: [0-9]+/))    divs    = substr(body, RSTART+6,  RLENGTH-6)  + 0
    if (match(body, /horner_accs: [0-9]+/)) horner_accs = substr(body, RSTART+13, RLENGTH-13) + 0
    if (match(body, /bool_checks: [0-9]+/)) bool_checks = substr(body, RSTART+13, RLENGTH-13) + 0

    # non_primitives { ... } (if present)
    if (match(body, /non_primitives: \{[^}]*\}/)) {
      np = substr(body, RSTART, RLENGTH)

      # Poseidon2 perm NPO (old and new formats).
      if (match(np, /Poseidon2Perm\(KoalaBearD4Width16\): [0-9]+/)) {
        key_p = "Poseidon2Perm(KoalaBearD4Width16): "
        poseidon2_perm = substr(np, RSTART + length(key_p), RLENGTH - length(key_p)) + 0
      } else if (match(np, /NpoTypeId\(poseidon2_perm\/koala_bear_d4_w16\): [0-9]+/)) {
        key_p = "NpoTypeId(poseidon2_perm/koala_bear_d4_w16): "
        poseidon2_perm = substr(np, RSTART + length(key_p), RLENGTH - length(key_p)) + 0
      }

      # Recompose NPO (BF→EF packing), accounting for both legacy and new key formats.
      if (match(np, /recompose: [0-9]+/)) {
        key_r = "recompose: "
        recompose_npo = substr(np, RSTART + length(key_r), RLENGTH - length(key_r)) + 0
      } else if (match(np, /NpoTypeId\(recompose\): [0-9]+/)) {
        key_r = "NpoTypeId(recompose): "
        recompose_npo = substr(np, RSTART + length(key_r), RLENGTH - length(key_r)) + 0
      }

      # Unconstrained NPO (old and new formats).
      if (match(np, /Unconstrained: [0-9]+/)) {
        key_u = "Unconstrained: "
        unconstrained = substr(np, RSTART + length(key_u), RLENGTH - length(key_u)) + 0
      } else if (match(np, /NpoTypeId\(unconstrained\): [0-9]+/)) {
        key_u = "NpoTypeId(unconstrained): "
        unconstrained = substr(np, RSTART + length(key_u), RLENGTH - length(key_u)) + 0
      }
    }

    primitives_sum = publics + consts + adds + subs + muls + divs + horner_accs + bool_checks
    nonprims_sum   = poseidon2_perm + recompose_npo + unconstrained

    print scope, primitives_sum, publics, consts, adds, subs, muls, divs, horner_accs, bool_checks, nonprims_sum, poseidon2_perm, recompose_npo, unconstrained
  }
'
