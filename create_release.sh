#!/bin/bash

# Script to automate release generation for `Plonky3-recursion`.
#
# This script creates a release PR that, when merged, triggers CI to publish to crates.io.
#
# Usage:
#   ./create_release.sh                # let release-plz compute the next version
#   ./create_release.sh 0.2.0-rc.1     # manually cut a release candidate
#
# How it works (no argument):
# 1. `release-plz release-pr` analyzes commits since the last release
# 2. Determines version bumps based on conventional commits (respecting version_group for lock-step)
# 3. Generates changelogs using cliff.toml
# 4. Creates a PR with the "release" label containing all changes
# 5. When that PR is merged, CI runs `release-plz release` to publish to crates.io
#
# Release candidates (rc argument):
# release-plz never derives an `-rc` version on its own, so an rc must be set by
# hand. Only rc versions may be passed here — stable bumps are always left to
# release-plz's automatic semver. The rc path edits the shared workspace version
# and opens the "release"-labelled PR directly; once published, plain reruns
# (no argument) advance rc.N -> rc.N+1 automatically.

set -euo pipefail

if [ "$#" -gt 1 ]; then
  echo "Error: expected no argument or one X.Y.Z-rc.N version." >&2
  exit 1
fi

rc_version="${1:-}"
if [ "$#" -eq 1 ] && ! [[ "$rc_version" =~ ^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)-rc\.(0|[1-9][0-9]*)$ ]]; then
  echo "Error: RC version must have the form X.Y.Z-rc.N without leading zeroes." >&2
  exit 1
fi

check_binary_installed() {
  local binary_name="$1"
  if ! command -v "$binary_name" &> /dev/null; then
    echo "Error: $binary_name is not installed."
    exit 1
  fi
}

if [ -z "${GIT_TOKEN:-}" ]; then
  echo "Error: GIT_TOKEN is not set. release-plz requires it to create PRs."
  exit 1
fi

check_binary_installed "release-plz"

# release-plz opens the release PR against the checked-out branch. Its publish
# workflow and push CI both cover only main and these version/RC base lines.
branch=$(git symbolic-ref --short HEAD)
if [[ "$branch" != "main" && ! "$branch" =~ ^v[0-9]+\.[0-9]+\.[0-9]+(-rc[0-9]+|-rc\.[0-9]+)?$ ]]; then
  echo "Error: Unsupported release base '$branch'; use main or a vX.Y.Z version/RC branch." >&2
  exit 1
fi

if [ -n "$rc_version" ]; then
  if ! git diff --quiet || ! git diff --cached --quiet; then
    echo "Error: Commit or discard tracked and staged changes before cutting an RC." >&2
    exit 1
  fi

  pr_branch="robin/release-$rc_version"
  if git show-ref --verify --quiet "refs/heads/$pr_branch"; then
    echo "Error: Branch '$pr_branch' already exists." >&2
    exit 1
  fi
fi

# Ensure the local release branch is up-to-date with its remote.
git fetch origin "$branch"
local_head=$(git rev-parse HEAD)
remote_head=$(git rev-parse "origin/$branch")

if [ "$local_head" != "$remote_head" ]; then
  echo "Error: Local '$branch' is not up-to-date with 'origin/$branch'."
  echo "Please run: git checkout $branch && git pull"
  exit 1
fi

if [ -n "$rc_version" ]; then
  check_binary_installed "gh"
  check_binary_installed "python3"

  if git ls-remote --exit-code --heads origin "refs/heads/$pr_branch" > /dev/null; then
    echo "Error: Remote branch '$pr_branch' already exists." >&2
    exit 1
  else
    lookup_status=$?
    if [ "$lookup_status" -ne 2 ]; then
      echo "Error: Could not check whether remote branch '$pr_branch' exists." >&2
      exit "$lookup_status"
    fi
  fi

  echo "Cutting release candidate '$rc_version' from '$branch'..."

  git switch -c "$pr_branch"
  python3 "$(dirname "${BASH_SOURCE[0]}")/scripts/set_release_candidate.py" Cargo.toml "$rc_version"
  # --workspace refreshes local package entries without updating registry versions.
  cargo update --workspace --offline
  cargo metadata --offline --locked --format-version 1 > /dev/null
  git add Cargo.toml Cargo.lock
  git commit -m "chore: release $rc_version" -- Cargo.toml Cargo.lock
  git push -u origin "$pr_branch"

  GH_TOKEN="$GIT_TOKEN" gh pr create \
    --base "$branch" \
    --head "$pr_branch" \
    --title "chore: release $rc_version" \
    --body "Release candidate \`$rc_version\` (manually cut)." \
    --label release
  exit 0
fi

echo "Creating release PR for '$branch'..."
release-plz release-pr
