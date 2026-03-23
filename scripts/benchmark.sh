#!/usr/bin/env bash
set -euo pipefail

# benchmark.sh
#
# Usage: ./scripts/benchmark.sh [fibonacci|keccak|aggregation] [runs]
#
# runs: optional positive integer (default 5).
#
# Output: CSV to stdout.
#
# fibonacci/keccak:
#   - layer index = order of prove_next_layer lines within each run
#   - stats per layer across runs: min/mean/median/max, samples
#
# aggregation:
#   - within each run, for each Aggregation level K, average all prove_aggregation_layer timings
#   - if runs > 1: skip the first prove_aggregation_layer per level per run (cold / no caching)
#   - then stats across runs on those per-run means: min/mean/median/max

example="${1:-}"
runs="${2:-5}"

if [[ -z "${example}" ]]; then
  echo "usage: $0 [fibonacci|keccak|aggregation] [runs]" >&2
  exit 2
fi

if ! [[ "${runs}" =~ ^[1-9][0-9]*$ ]]; then
  echo "runs must be a positive integer, got: ${runs}" >&2
  exit 2
fi

export RUSTFLAGS="-Ctarget-cpu=native -Copt-level=3"

run_fib_or_keccak() {
  local ex="$1"
  shift
  local -a args=("$@")

  {
    for ((r=1; r<=runs; r++)); do
      echo "###RUN ${r}###"
      RUST_LOG=info cargo run --profile optimized --example "${ex}" -q --features parallel -- "${args[@]}" || true
    done
  } | perl -ne '
    use strict;
    use warnings;

    our (%vals, %minv, %maxv, $idx);

    BEGIN {
      %vals=(); %minv=(); %maxv=();
      $idx = 0;
    }

    sub median {
      my ($ref) = @_;
      my @a = sort { $a <=> $b } @$ref;
      my $n = @a;
      return 0 unless $n;
      if ($n % 2) {
        return $a[($n - 1) / 2];
      }
      return ($a[$n / 2 - 1] + $a[$n / 2]) / 2;
    }

    sub arith_mean {
      my ($ref) = @_;
      my $n = @$ref;
      return 0 unless $n;
      my $s = 0;
      $s += $_ for @$ref;
      return $s / $n;
    }

    sub upd_stats {
      my ($k, $x) = @_;
      push @{ $vals{$k} }, $x;
      if (!exists $minv{$k} || $x < $minv{$k}) { $minv{$k} = $x; }
      if (!exists $maxv{$k} || $x > $maxv{$k}) { $maxv{$k} = $x; }
    }

    if (/^###RUN\s+(\d+)###\s*$/) {
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
      print "layer, min_ms, mean_ms, median_ms, max_ms\n";
      for my $k (sort { $a <=> $b } keys %vals) {
        my $ref = $vals{$k};
        my $n = $ref ? @$ref : 0;
        my $mn  = $n ? arith_mean($ref) : 0;
        my $med = $n ? median($ref)     : 0;
        printf "%d, %d ms, %d ms, %d ms, %d ms", $k, $minv{$k}, int($mn + 0.5), int($med + 0.5), $maxv{$k};
      }
    }
  '
}

run_aggregation() {
  {
    for ((r=1; r<=runs; r++)); do
      echo "###RUN ${r}###"
      RUST_LOG=info cargo run --profile optimized --example recursive_aggregation -q --features parallel -- --num-recursive-layers 5 || true
    done
  } | BENCHMARK_AGG_RUNS="$runs" perl -ne '
    use strict;
    use warnings;

    our ($run, $cur_level, $skip_cold_first);
    our (%run_sum, %run_cnt, %seen_first);
    our (%vals, %minv, %maxv);

    BEGIN {
      $run = 0;
      $skip_cold_first = ($ENV{BENCHMARK_AGG_RUNS} // 1) > 1;
      undef $cur_level;
      %run_sum=(); %run_cnt=(); %seen_first=();
      %vals=(); %minv=(); %maxv=();
    }

    sub median {
      my ($ref) = @_;
      my @a = sort { $a <=> $b } @$ref;
      my $n = @a;
      return 0 unless $n;
      if ($n % 2) {
        return $a[($n - 1) / 2];
      }
      return ($a[$n / 2 - 1] + $a[$n / 2]) / 2;
    }

    sub arith_mean {
      my ($ref) = @_;
      my $n = @$ref;
      return 0 unless $n;
      my $s = 0;
      $s += $_ for @$ref;
      return $s / $n;
    }

    sub upd_stats {
      my ($k, $x) = @_;
      push @{ $vals{$k} }, $x;
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

    # --- Skip first aggregation per level when runs>1 (cold / no caching) ---
    if ($skip_cold_first && !exists $seen_first{$cur_level}) {
      $seen_first{$cur_level} = 1;
      next;
    }

    $run_sum{$cur_level} += $ms;
    $run_cnt{$cur_level} += 1;

    END {
      finalize_run() if $run != 0;

      print "aggregation_level, min_ms, mean_ms, median_ms, max_ms\n";
      for my $lvl (sort { $a <=> $b } keys %vals) {
        my $ref = $vals{$lvl};
        my $n = $ref ? @$ref : 0;
        my $mn  = $n ? arith_mean($ref) : 0;
        my $med = $n ? median($ref)     : 0;
        printf "%d, %d ms, %d ms, %d ms, %d ms\n", $lvl, $minv{$lvl}, int($mn + 0.5), int($med + 0.5), $maxv{$lvl};
      }
    }
  '
}

case "${example}" in
  fibonacci)
    echo "----------------------------------------------"
    echo "Recursive Fibonacci with N=10000 and 5 layers."
    echo "----------------------------------------------"
    run_fib_or_keccak "recursive_fibonacci" -n 10000 --num-recursive-layers 5
    echo "------------------------------------"
    ;;
  keccak)
    echo "------------------------------------------"
    echo "Recursive Keccak with N=1000 and 5 layers."
    echo "------------------------------------------"
    run_fib_or_keccak "recursive_keccak" -n 1000 --num-recursive-layers 5
    echo "------------------------------------"
    ;;
  aggregation)
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
