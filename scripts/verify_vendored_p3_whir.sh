#!/usr/bin/env bash
set -euo pipefail

# verify_vendored_p3_whir.sh
#
# vendor/p3-whir is a local patch of the crates.io p3-whir 0.7.0 release
# (see the root Cargo.toml's [patch.crates-io] entry). This script re-fetches
# that exact release from crates.io, verifies its checksum against the
# crates.io index, and diffs it against vendor/p3-whir. Everything must be
# byte-for-byte identical except:
#
#   - the files in ALLOWED_CHANGED_FILES below (the sampler fix and its tests)
#   - the Cargo.toml delta this script checks explicitly (an empty
#     [workspace] table, plus five dev-dependencies the published manifest
#     omits because cargo drops unversioned path dev-dependencies on publish)
#
# Anything else differing — including added or removed files — fails.

CRATE_NAME="p3-whir"
CRATE_VERSION="0.7.0"

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VENDOR_DIR="${REPO_ROOT}/vendor/p3-whir"
WORK_DIR="$(mktemp -d)"
trap 'rm -rf "${WORK_DIR}"' EXIT

# Files this workspace intentionally modified relative to upstream (task 13's
# STIR-sampler fix and its tests). Diffed loosely; any further edit here is
# expected to be covered by this workspace's own review process, not this
# script's identity check.
ALLOWED_CHANGED_FILES=(
    "src/pcs/mod.rs"
    "src/pcs/proof.rs"
    "src/pcs/utils.rs"
    "src/pcs/zk/base_case/tests.rs"
)

# Paths this script does not compare at all: build output, and registry
# bookkeeping files that describe the local checkout rather than crate content.
EXCLUDED_PATHS=(
    "target"
    "Cargo.lock"
    ".cargo-ok"
    ".cargo_vcs_info.json"
)

echo "== Fetching ${CRATE_NAME} ${CRATE_VERSION} checksum from the crates.io index =="
# Sparse-index path convention for a 4+ character crate name: first two
# characters, then the next two, then the crate name itself.
# "p3-whir" -> "p3" / "-w" / "p3-whir".
INDEX_PREFIX="p3/-w"
INDEX_URL="https://index.crates.io/${INDEX_PREFIX}/${CRATE_NAME}"
INDEX_JSON="$(curl --fail --silent --show-error "${INDEX_URL}")"
EXPECTED_CKSUM="$(printf '%s\n' "${INDEX_JSON}" \
    | grep -F "\"vers\":\"${CRATE_VERSION}\"" \
    | sed -n 's/.*"cksum":"\([0-9a-f]*\)".*/\1/p' \
    | head -n1)"

if [ -z "${EXPECTED_CKSUM}" ]; then
    echo "FAIL: could not find a cksum for ${CRATE_NAME} ${CRATE_VERSION} in the crates.io index" >&2
    exit 1
fi
echo "Expected sha256 (from index): ${EXPECTED_CKSUM}"

echo "== Downloading the ${CRATE_NAME} ${CRATE_VERSION} crate tarball =="
TARBALL="${WORK_DIR}/${CRATE_NAME}-${CRATE_VERSION}.crate"
curl --fail --silent --show-error --location \
    "https://static.crates.io/crates/${CRATE_NAME}/${CRATE_NAME}-${CRATE_VERSION}.crate" \
    -o "${TARBALL}"

ACTUAL_CKSUM="$(sha256sum "${TARBALL}" | cut -d' ' -f1)"
echo "Actual sha256 (downloaded):   ${ACTUAL_CKSUM}"
if [ "${ACTUAL_CKSUM}" != "${EXPECTED_CKSUM}" ]; then
    echo "FAIL: downloaded tarball checksum does not match the crates.io index" >&2
    exit 1
fi
echo "Checksum verified."

echo "== Extracting pristine upstream source =="
tar -xzf "${TARBALL}" -C "${WORK_DIR}"
UPSTREAM_DIR="${WORK_DIR}/${CRATE_NAME}-${CRATE_VERSION}"
if [ ! -d "${UPSTREAM_DIR}" ]; then
    echo "FAIL: expected ${UPSTREAM_DIR} after extraction" >&2
    exit 1
fi

echo "== Diffing vendor/p3-whir against pristine upstream =="
EXCLUDE_ARGS=()
for p in "${EXCLUDED_PATHS[@]}"; do
    EXCLUDE_ARGS+=(--exclude="${p}")
done

FULL_DIFF="${WORK_DIR}/full.diff"
diff -ruN "${EXCLUDE_ARGS[@]}" "${UPSTREAM_DIR}" "${VENDOR_DIR}" > "${FULL_DIFF}" || true

FAILED=0

# Split the unified diff into per-file hunks (each starts with "diff -ruN").
CURRENT_FILE=""
CURRENT_HUNK="${WORK_DIR}/current.hunk"
: > "${CURRENT_HUNK}"

is_allowed_file() {
    local rel="$1"
    for allowed in "${ALLOWED_CHANGED_FILES[@]}"; do
        if [ "${rel}" = "${allowed}" ]; then
            return 0
        fi
    done
    return 1
}

check_hunk() {
    local rel="$1"
    local hunk_file="$2"

    if [ ! -s "${hunk_file}" ]; then
        return
    fi

    if [ "${rel}" = "Cargo.toml" ]; then
        check_cargo_toml_hunk "${hunk_file}"
        return
    fi

    if is_allowed_file "${rel}"; then
        echo "  (allowed) ${rel} differs from upstream — this is the intentional patch."
        return
    fi

    echo "FAIL: ${rel} differs from upstream p3-whir ${CRATE_VERSION} and is not in ALLOWED_CHANGED_FILES:" >&2
    cat "${hunk_file}" >&2
    FAILED=1
}

check_cargo_toml_hunk() {
    local hunk_file="$1"

    # Every added line (skipping the "+++ ..." file header) must be one of
    # the known-good additions; no line may be removed.
    local removed
    removed="$(grep -E '^-[^-]' "${hunk_file}" || true)"
    if [ -n "${removed}" ]; then
        echo "FAIL: Cargo.toml removes lines relative to upstream (expected additions only):" >&2
        echo "${removed}" >&2
        FAILED=1
    fi

    local added
    added="$(grep -E '^\+[^+]' "${hunk_file}" || true)"

    local expected_added
    expected_added="$(cat <<'EOF'
+[workspace]
+
+[dev-dependencies.p3-baby-bear]
+version = "0.7.0"
+
+[dev-dependencies.p3-blake3]
+version = "0.7.0"
+
+[dev-dependencies.p3-fri]
+version = "0.7.0"
+
+[dev-dependencies.p3-keccak]
+version = "0.7.0"
+
+[dev-dependencies.p3-koala-bear]
+version = "0.7.0"
EOF
)"

    local unexpected
    unexpected="$(comm -23 <(printf '%s\n' "${added}" | sort) <(printf '%s\n' "${expected_added}" | sort))"
    if [ -n "${unexpected}" ]; then
        echo "FAIL: Cargo.toml adds lines beyond the expected [workspace] + dev-dependencies delta:" >&2
        echo "${unexpected}" >&2
        FAILED=1
    fi

    if [ "${FAILED}" -eq 0 ]; then
        echo "  (allowed) Cargo.toml differs from upstream exactly as expected (workspace marker + restored dev-deps)."
    fi
}

while IFS= read -r line; do
    if [[ "${line}" == diff\ -ruN* ]]; then
        if [ -n "${CURRENT_FILE}" ]; then
            check_hunk "${CURRENT_FILE}" "${CURRENT_HUNK}"
        fi
        # Extract the vendor-side path (second path argument) and make it
        # relative to VENDOR_DIR.
        vendor_path="$(printf '%s\n' "${line}" | awk '{print $NF}')"
        CURRENT_FILE="${vendor_path#"${VENDOR_DIR}"/}"
        : > "${CURRENT_HUNK}"
    else
        printf '%s\n' "${line}" >> "${CURRENT_HUNK}"
    fi
done < "${FULL_DIFF}"

if [ -n "${CURRENT_FILE}" ]; then
    check_hunk "${CURRENT_FILE}" "${CURRENT_HUNK}"
fi

if [ "${FAILED}" -ne 0 ]; then
    echo "" >&2
    echo "FAIL: vendor/p3-whir has drifted from upstream p3-whir ${CRATE_VERSION} outside the allowed patch." >&2
    exit 1
fi

echo ""
echo "OK: vendor/p3-whir matches upstream p3-whir ${CRATE_VERSION} apart from the allowed patch."
