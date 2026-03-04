#!/usr/bin/env bash
set -euo pipefail

# Runs the recursive_fibonacci example, keeps only the PROFILING lines,
# truncates to the chunk starting at the LAST "global: OpCounts" (included),
# then converts OpCounts blocks to CSV.
#
# Output columns:
# scope, # primitives, publics, consts, adds, subs, muls, divs, # non-primitives, poseidon2_perm, unconstrained

export RUSTFLAGS="-Ctarget-cpu=native -Copt-level=3"

echo "Profiling recursive_fibonacci with N=10000."
echo "----------------------------------------"

RUST_LOG=info cargo run --release --example recursive_fibonacci -q --features parallel,profiling -- -n 10000 --num-recursive-layers 4 \
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
    print "scope,# primitives,publics,consts,adds,subs,muls,divs,# non-primitives,poseidon2_perm,unconstrained"
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
    publics=0; consts=0; adds=0; subs=0; muls=0; divs=0;
    poseidon2_perm=0; unconstrained=0;

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

    # non_primitives { ... } (if present)
    if (match(body, /non_primitives: \{[^}]*\}/)) {
      np = substr(body, RSTART, RLENGTH)

      if (match(np, /Poseidon2Perm\(KoalaBearD4Width16\): [0-9]+/)) {
        key = "Poseidon2Perm(KoalaBearD4Width16): "
        poseidon2_perm = substr(np, RSTART + length(key), RLENGTH - length(key)) + 0
      }
      if (match(np, /Unconstrained: [0-9]+/)) {
        key2 = "Unconstrained: "
        unconstrained = substr(np, RSTART + length(key2), RLENGTH - length(key2)) + 0
      }
    }

    primitives_sum = publics + consts + adds + subs + muls + divs
    nonprims_sum   = poseidon2_perm + unconstrained

    print scope, primitives_sum, publics, consts, adds, subs, muls, divs, nonprims_sum, poseidon2_perm, unconstrained
  }
'
