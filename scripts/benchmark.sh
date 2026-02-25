#!/usr/bin/env bash
set -euo pipefail

# benchmark.sh
#
# Usage:
#   bash benchmark.sh recursive_fibonacci
#   bash benchmark.sh recursive_keccak
#   bash benchmark.sh recursive_aggregation
#
# Output: CSV to stdout.
#
# fibonacci/keccak:
#   - layer index = order of prove_next_layer lines within each run
#   - stats per layer across 5 runs: min/mean/max, samples
#
# aggregation:
#   - within each run, for each Aggregation level K, average all prove_aggregation_layer timings
#   - then stats across 5 runs on those per-run means: min/mean/max, runs_with_level

example="${1:-}"
if [[ -z "${example}" ]]; then
  echo "usage: $0 <recursive_fibonacci|recursive_keccak|recursive_aggregation>" >&2
  exit 2
fi

export RUSTFLAGS="-Ctarget-cpu=native -Copt-level=3"
runs=5

run_fib_or_keccak() {
  local ex="$1"
  shift
  local -a args=("$@")

  {
    for ((r=1; r<=runs; r++)); do
      echo "###RUN ${r}###"
      RUST_LOG=info cargo run --release --example "${ex}" -q --features parallel -- "${args[@]}" || true
    done
  } | perl -ne '
    use strict;
    use warnings;

    our (%sum, %sum2, %cnt, %minv, %maxv, $run, $idx);

    BEGIN {
      %sum=(); %sum2=(); %cnt=(); %minv=(); %maxv=();
      $run = 0;
      $idx = 0;
    }

    sub upd_stats {
      my ($k, $x) = @_;
      $sum{$k}  += $x;
      $sum2{$k} += $x * $x;
      $cnt{$k}  += 1;
      if (!exists $minv{$k} || $x < $minv{$k}) { $minv{$k} = $x; }
      if (!exists $maxv{$k} || $x > $maxv{$k}) { $maxv{$k} = $x; }
    }

    if (/^###RUN\s+(\d+)###\s*$/) {
      $run = $1;
      $idx = 0;
      next;
    }

    next unless /\bprove_next_layer\b/ || /\bprove\b/;

    $idx++;

    my $ms;
    if (/\[\s*([0-9]+(?:\.[0-9]+)?)\s*(ms|s)\b/) {
      my ($v, $u) = ($1, $2);
      $ms = ($u eq "s") ? ($v * 1000.0) : ($v + 0.0);
    } else {
      next;
    }

    upd_stats($idx, $ms);

    END {
      print "layer, min_ms, mean_ms, max_ms, samples\n";
      for my $k (sort { $a <=> $b } keys %sum) {
        my $n = $cnt{$k} || 0;
        my $mean = $n ? ($sum{$k} / $n) : 0;

        my $var = 0;
        if ($n) {
          $var = ($sum2{$k} / $n) - ($mean * $mean);
          $var = 0 if $var < 0;
        }

        printf "%d, %d ms, %d ms, %d ms, %d\n", $k, $minv{$k}, $mean, $maxv{$k}, $n;
      }
    }
  '
}

run_aggregation() {
  {
    for ((r=1; r<=runs; r++)); do
      echo "###RUN ${r}###"
      RUST_LOG=info cargo run --release --example recursive_aggregation -q --features parallel -- --num-recursive-layers 5 || true
    done
  } | perl -ne '
    use strict;
    use warnings;

    our ($run, $cur_level);
    our (%run_sum, %run_cnt, %seen_first);
    our (%sum, %sum2, %cnt, %minv, %maxv);

    BEGIN {
      $run = 0;
      undef $cur_level;
      %run_sum=(); %run_cnt=(); %seen_first=();
      %sum=(); %sum2=(); %cnt=(); %minv=(); %maxv=();
    }

    sub upd_stats {
      my ($k, $x) = @_;
      $sum{$k}  += $x;
      $sum2{$k} += $x * $x;
      $cnt{$k}  += 1;
      if (!exists $minv{$k} || $x < $minv{$k}) { $minv{$k} = $x; }
      if (!exists $maxv{$k} || $x > $maxv{$k}) { $maxv{$k} = $x; }
    }

    sub finalize_run {
      for my $lvl (keys %run_sum) {
        next unless $run_cnt{$lvl};
        my $mean = $run_sum{$lvl} / $run_cnt{$lvl};
        upd_stats($lvl, $mean);
      }
      %run_sum = ();
      %run_cnt = ();
      %seen_first = ();
      undef $cur_level;
    }

    if (/^###RUN\s+(\d+)###\s*$/) {
      finalize_run() if $run != 0;
      $run = $1;
      next;
    }

    if (/Aggregation level\s+(\d+):/) {
      $cur_level = $1 + 0;
      next;
    }

    next unless /prove_aggregation_layer/;
    next unless defined $cur_level;

    my $ms;
    if (/\[\s*([0-9]+(?:\.[0-9]+)?)\s*(ms|s)\b/) {
      my ($v, $u) = ($1, $2);
      $ms = ($u eq "s") ? ($v * 1000.0) : ($v + 0.0);
    } else {
      next;
    }

    # --- Skip first aggregation per level (cold / no caching) ---
    if (!exists $seen_first{$cur_level}) {
      $seen_first{$cur_level} = 1;
      next;
    }

    $run_sum{$cur_level} += $ms;
    $run_cnt{$cur_level} += 1;

    END {
      finalize_run() if $run != 0;

      print "aggregation_level, min_ms, mean_ms, max_ms, runs_with_level\n";
      for my $lvl (sort { $a <=> $b } keys %sum) {
        my $n = $cnt{$lvl} || 0;
        my $mean = $n ? ($sum{$lvl} / $n) : 0;

        my $var = 0;
        if ($n) {
          $var = ($sum2{$lvl} / $n) - ($mean * $mean);
          $var = 0 if $var < 0;
        }

        printf "%d, %d ms, %d ms, %d ms, %d\n", $lvl, $minv{$lvl}, $mean, $maxv{$lvl}, $n;
      }
    }
  '
}

case "${example}" in
  recursive_fibonacci)
    echo "----------------------------------------------"
    echo "Recursive Fibonacci with N=10000 and 4 layers."
    echo "----------------------------------------------"
    run_fib_or_keccak "recursive_fibonacci" -n 10000 --num-recursive-layers 4
    echo "------------------------------------"
    ;;
  recursive_keccak)
    echo "------------------------------------------"
    echo "Recursive Keccak with N=1000 and 4 layers."
    echo "------------------------------------------"
    run_fib_or_keccak "recursive_keccak" -n 1000 --num-recursive-layers 4
    echo "------------------------------------"
    ;;
  recursive_aggregation)
    echo "------------------------------------"
    echo "Recursive Aggregation with 5 layers."
    echo "------------------------------------"
    run_aggregation
    echo "------------------------------------"
    ;;
  *)
    echo "unknown example: ${example}" >&2
    echo "allowed: recursive_fibonacci | recursive_keccak | recursive_aggregation" >&2
    exit 2
    ;;
esac
