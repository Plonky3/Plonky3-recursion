#!/usr/bin/env bash
set -euo pipefail

BASE_REF="${BASE_REF:?BASE_REF is required}"
HEAD_REF="${HEAD_REF:?HEAD_REF is required}"

REGRESSION_THRESHOLD_PCT="${REGRESSION_THRESHOLD_PCT:-5}"
PERF_RUNS="${PERF_RUNS:-3}"
PERF_WARMUPS="${PERF_WARMUPS:-1}"
PERF_TIMEOUT_SECONDS="${PERF_TIMEOUT_SECONDS:-1200}"
PERF_CARGO_FEATURES="${PERF_CARGO_FEATURES:-p3-circuit-prover/parallel,p3-poseidon2-circuit-air/parallel}"

if [[ "${PERF_RUNS}" -lt 1 ]]; then
  echo "PERF_RUNS must be >= 1" >&2
  exit 1
fi

if [[ "${PERF_WARMUPS}" -lt 0 ]]; then
  echo "PERF_WARMUPS must be >= 0" >&2
  exit 1
fi

REPO_ROOT="$(git rev-parse --show-toplevel)"
RESULT_DIR="${REPO_ROOT}/target/perf-gate"
LOG_DIR="${RESULT_DIR}/logs"
WORKTREE_ROOT="${RESULT_DIR}/worktrees-$$"
mkdir -p "${LOG_DIR}" "${WORKTREE_ROOT}"

# Format: bench_name|package_name|args|success_pattern
BENCHMARKS=(
  "recursive_fibonacci|p3-recursion|--field koala-bear --n 10000 --num-recursive-layers 4|Recursive proof verified successfully"
)
if [[ -n "${PERF_BENCHMARKS:-}" ]]; then
  IFS=';' read -r -a BENCHMARKS <<<"${PERF_BENCHMARKS}"
fi

BASE_WORKTREE="${WORKTREE_ROOT}/base"
HEAD_WORKTREE="${WORKTREE_ROOT}/head"
BASE_TARGET_DIR="${RESULT_DIR}/target-base"
HEAD_TARGET_DIR="${RESULT_DIR}/target-head"
TIMEOUT_BIN=""

if command -v timeout >/dev/null 2>&1; then
  TIMEOUT_BIN="timeout"
elif command -v gtimeout >/dev/null 2>&1; then
  TIMEOUT_BIN="gtimeout"
else
  echo "Warning: neither 'timeout' nor 'gtimeout' found; benchmarks will run without a timeout guard." >&2
fi

now_ns() {
  local ts
  ts="$(date +%s%N 2>/dev/null || true)"
  if [[ "${ts}" =~ ^[0-9]+$ ]]; then
    echo "${ts}"
    return 0
  fi

  # Fallback for shells where date lacks %N (e.g. BSD date)
  python3 - <<'PY'
import time
print(time.time_ns())
PY
}

prepare_worktree() {
  local ref="$1"
  local dir="$2"

  git worktree add --force --detach "${dir}" "${ref}" >/dev/null
}

build_example() {
  local worktree_dir="$1"
  local target_dir="$2"
  local package_name="$3"
  local example_name="$4"
  local -a feature_args=()

  if [[ -n "${PERF_CARGO_FEATURES}" ]]; then
    feature_args=(--features "${PERF_CARGO_FEATURES}")
  fi

  (
    cd "${worktree_dir}"
    CARGO_TARGET_DIR="${target_dir}" cargo build --release "${feature_args[@]}" --package "${package_name}" --example "${example_name}"
  )
}

resolve_example_binary() {
  local target_dir="$1"
  local example_name="$2"
  local direct="${target_dir}/release/examples/${example_name}"

  if [[ -x "${direct}" ]]; then
    echo "${direct}"
    return 0
  fi

  local -a candidates=()
  # Cargo may suffix example filenames with metadata hashes.
  shopt -s nullglob
  candidates=("${target_dir}/release/examples/${example_name}-"*)
  shopt -u nullglob

  local candidate
  for candidate in "${candidates[@]}"; do
    if [[ -x "${candidate}" && "${candidate}" != *.d && "${candidate}" != *.rcgu.o ]]; then
      echo "${candidate}"
      return 0
    fi
  done

  return 1
}

run_once_ms() {
  local worktree_dir="$1"
  local target_dir="$2"
  local example_name="$3"
  local args="$4"
  local log_file="$5"
  local success_pattern="$6"
  local start_ns end_ns elapsed_ms cmd_status example_bin
  local -a args_array=()

  read -r -a args_array <<<"${args}"

  if ! example_bin="$(resolve_example_binary "${target_dir}" "${example_name}")"; then
    echo "Could not locate built example binary for ${example_name} under ${target_dir}/release/examples" >&2
    return 127
  fi

  start_ns="$(now_ns)"
  if [[ -n "${TIMEOUT_BIN}" ]]; then
    (
      cd "${worktree_dir}"
      CARGO_TARGET_DIR="${target_dir}" "${TIMEOUT_BIN}" "${PERF_TIMEOUT_SECONDS}" "${example_bin}" "${args_array[@]}" >"${log_file}" 2>&1
    )
  else
    (
      cd "${worktree_dir}"
      CARGO_TARGET_DIR="${target_dir}" "${example_bin}" "${args_array[@]}" >"${log_file}" 2>&1
    )
  fi
  cmd_status=$?
  end_ns="$(now_ns)"

  if [[ "${cmd_status}" -ne 0 ]]; then
    echo "Benchmark command failed for ${example_name} (exit=${cmd_status}). See ${log_file}" >&2
    return "${cmd_status}"
  fi

  if [[ -n "${success_pattern}" ]] && ! grep -F -q -- "${success_pattern}" "${log_file}"; then
    echo "Benchmark did not emit success marker for ${example_name}. See ${log_file}" >&2
    return 1
  fi

  elapsed_ms="$(((end_ns - start_ns) / 1000000))"
  echo "${elapsed_ms}"
}

median_of_samples() {
  printf "%s\n" "$@" | sort -n | awk '
    { vals[NR] = $1 }
    END {
      if (NR == 0) {
        print 0
        exit
      }
      mid = int((NR + 1) / 2)
      if (NR % 2 == 1) {
        print vals[mid]
      } else {
        print int((vals[mid] + vals[mid + 1]) / 2)
      }
    }
  '
}

run_benchmark_for_ref() {
  local worktree_dir="$1"
  local target_dir="$2"
  local ref_label="$3"
  local bench_name="$4"
  local package_name="$5"
  local example_name="$6"
  local args="$7"
  local success_pattern="$8"
  local log_prefix="${LOG_DIR}/${bench_name}-${ref_label}"
  local samples=()

  build_example "${worktree_dir}" "${target_dir}" "${package_name}" "${example_name}"

  for ((i = 1; i <= PERF_WARMUPS; i++)); do
    if ! run_once_ms "${worktree_dir}" "${target_dir}" "${example_name}" "${args}" "${log_prefix}-warmup-${i}.log" "${success_pattern}" >/dev/null; then
      return 1
    fi
  done

  for ((i = 1; i <= PERF_RUNS; i++)); do
    local ms run_log prove_next_layer_lines
    run_log="${log_prefix}-run-${i}.log"
    if ! ms="$(run_once_ms "${worktree_dir}" "${target_dir}" "${example_name}" "${args}" "${run_log}" "${success_pattern}")"; then
      return 1
    fi
    samples+=("${ms}")

    prove_next_layer_lines="$(grep -c "prove_next_layer" "${run_log}" || true)"
    if [[ "${prove_next_layer_lines}" -gt 0 ]]; then
      echo "${bench_name} (${ref_label}) run ${i}/${PERF_RUNS}: ${ms} ms (prove_next_layer lines: ${prove_next_layer_lines})" >&2
    else
      echo "${bench_name} (${ref_label}) run ${i}/${PERF_RUNS}: ${ms} ms" >&2
    fi
  done

  median_of_samples "${samples[@]}"
}

write_summary_header() {
  if [[ -n "${GITHUB_STEP_SUMMARY:-}" ]]; then
    {
      echo "## Performance Gate"
      echo
      echo "Threshold: ${REGRESSION_THRESHOLD_PCT}% max regression"
      echo
      echo "| Benchmark | Base (ms) | PR (ms) | Delta (ms) | Regression (%) | Status |"
      echo "|---|---:|---:|---:|---:|---|"
    } >>"${GITHUB_STEP_SUMMARY}"
  fi
}

append_summary_row() {
  local bench_name="$1"
  local base_ms="$2"
  local head_ms="$3"
  local delta_ms="$4"
  local regression_pct="$5"
  local status="$6"

  if [[ -n "${GITHUB_STEP_SUMMARY:-}" ]]; then
    echo "| ${bench_name} | ${base_ms} | ${head_ms} | ${delta_ms} | ${regression_pct} | ${status} |" >>"${GITHUB_STEP_SUMMARY}"
  fi
}

cleanup() {
  git worktree remove --force "${BASE_WORKTREE}" >/dev/null 2>&1 || true
  git worktree remove --force "${HEAD_WORKTREE}" >/dev/null 2>&1 || true
  rm -rf "${WORKTREE_ROOT}" >/dev/null 2>&1 || true
}
trap cleanup EXIT

prepare_worktree "${BASE_REF}" "${BASE_WORKTREE}"
prepare_worktree "${HEAD_REF}" "${HEAD_WORKTREE}"

write_summary_header

failures=0

for benchmark in "${BENCHMARKS[@]}"; do
  IFS='|' read -r bench_name package_name args success_pattern <<<"${benchmark}"
  example_name="${bench_name}"

  echo "Running benchmark: ${bench_name}" >&2
  echo "Args: ${args}" >&2

  base_ms="$(run_benchmark_for_ref "${BASE_WORKTREE}" "${BASE_TARGET_DIR}" "base" "${bench_name}" "${package_name}" "${example_name}" "${args}" "${success_pattern}" | tail -n1)"
  head_ms="$(run_benchmark_for_ref "${HEAD_WORKTREE}" "${HEAD_TARGET_DIR}" "head" "${bench_name}" "${package_name}" "${example_name}" "${args}" "${success_pattern}" | tail -n1)"

  if ! [[ "${base_ms}" =~ ^[0-9]+$ ]] || ! [[ "${head_ms}" =~ ^[0-9]+$ ]]; then
    echo "Non-numeric benchmark result: base='${base_ms}', head='${head_ms}'" >&2
    exit 1
  fi

  delta_ms="$((head_ms - base_ms))"
  regression_pct="$(awk -v base="${base_ms}" -v head="${head_ms}" 'BEGIN { printf "%.2f", ((head - base) * 100.0) / base }')"
  display_kind="regression"
  display_pct="${regression_pct}"
  if awk -v pct="${regression_pct}" 'BEGIN { exit !(pct < 0) }'; then
    display_kind="improvement"
    display_pct="$(awk -v pct="${regression_pct}" 'BEGIN { printf "%.2f", -pct }')"
  fi

  status="PASS"
  if awk -v base="${base_ms}" -v head="${head_ms}" -v threshold="${REGRESSION_THRESHOLD_PCT}" \
      'BEGIN { exit !(((head - base) * 100.0 / base) > threshold) }'; then
    status="FAIL"
    failures=$((failures + 1))
  fi

  echo "Result ${bench_name}: base=${base_ms}ms, pr=${head_ms}ms, ${display_kind}=${display_pct}% -> ${status}" >&2
  append_summary_row "${bench_name}" "${base_ms}" "${head_ms}" "${delta_ms}" "${regression_pct}" "${status}"
done

if [[ "${failures}" -gt 0 ]]; then
  echo "Performance regression gate failed: (${failures} benchmark(s) exceeded ${REGRESSION_THRESHOLD_PCT}%)." >&2
  exit 1
fi

echo "Performance gate passed." >&2
