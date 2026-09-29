#!/usr/bin/env python3
"""Advisory PR API report against explicit crates.io release baselines."""

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


# None means that crates.io currently has no release under this exact name.
BASELINES = {
    "p3-circuit": "0.1.0",
    "p3-circuit-prover": "0.1.0",
    "p3-poseidon-circuit-cols": None,
    "p3-poseidon1-circuit-air": None,
    "p3-poseidon2-circuit-air": None,
    "p3-recursion": "0.1.0",
}
TOOL_VERSION = "0.50.0"


class CheckError(RuntimeError):
    """An incomplete API check or invalid baseline configuration."""


def workspace_packages(metadata, baselines):
    members = set(metadata["workspace_members"])
    packages = {
        package["name"]: package["version"]
        for package in metadata["packages"]
        if package["id"] in members and package.get("publish") != []
    }
    if not packages or set(packages) != set(baselines):
        raise CheckError(
            "publishable workspace classification mismatch: "
            f"unclassified={sorted(set(packages) - set(baselines))}, "
            f"configured but absent={sorted(set(baselines) - set(packages))}"
        )
    return packages


def fetch_registry(name):
    request = Request(
        f"https://crates.io/api/v1/crates/{name}",
        headers={"User-Agent": "Plonky3-recursion-api-compatibility/1.0"},
    )
    try:
        with urlopen(request, timeout=20) as response:
            return response.status, response.read()
    except HTTPError as error:
        try:
            if error.code == 404:
                return 404, error.read()
            raise CheckError(f"{name}: registry HTTP {error.code}") from error
        finally:
            error.close()
    except (URLError, TimeoutError, OSError) as error:
        raise CheckError(f"{name}: registry request failed: {error}") from error


def classify_registry(name, baseline, status, body):
    if status not in (200, 404):
        raise CheckError(f"{name}: registry HTTP {status}")
    try:
        data = json.loads(body)
    except (UnicodeError, ValueError) as error:
        raise CheckError(f"{name}: malformed registry response") from error
    if not isinstance(data, dict):
        raise CheckError(f"{name}: malformed registry response")
    if status == 404:
        errors = data.get("errors")
        expected = f"crate `{name}` does not exist"
        if not isinstance(errors, list) or not any(
            isinstance(item, dict) and item.get("detail") == expected
            for item in errors
        ):
            raise CheckError(f"{name}: invalid 404 response from registry")
        if baseline is not None:
            raise CheckError(f"{name}: expected baseline {baseline}, but crate is absent")
        return "NEW CRATE / NO RELEASE BASELINE"

    crate = data.get("crate")
    versions = data.get("versions")
    if (not isinstance(crate, dict) or crate.get("id") != name
            or not isinstance(versions, list) or not versions
            or any(not isinstance(v, dict) or not isinstance(v.get("num"), str)
                   or not isinstance(v.get("yanked"), bool) for v in versions)):
        raise CheckError(f"{name}: malformed registry response")
    if baseline is None:
        raise CheckError(f"{name}: now published; pin a baseline in BASELINES")
    matches = [version for version in versions if version["num"] == baseline]
    if not matches:
        raise CheckError(f"{name}: baseline {baseline} is absent from registry")
    if matches[0]["yanked"]:
        raise CheckError(f"{name}: baseline {baseline} is yanked; update baseline policy")
    return "RELEASED"


def run_command(command, timeout, env=None):
    try:
        return subprocess.run(command, capture_output=True, text=True, timeout=timeout, env=env)
    except FileNotFoundError as error:
        raise CheckError(f"executable not found: {command[0]}") from error
    except subprocess.TimeoutExpired as error:
        raise CheckError(f"command timed out after {timeout}s: {' '.join(command)}") from error
    except OSError as error:
        raise CheckError(f"cannot run {command[0]}: {error}") from error


def verify_tool():
    result = run_command(["cargo", "semver-checks", "--version"], 30)
    expected = f"cargo-semver-checks {TOOL_VERSION}"
    if result.returncode != 0 or result.stdout.strip() != expected:
        raise CheckError(f"expected {expected}; got exit {result.returncode}: {result.stdout.strip()} {result.stderr.strip()}")


def run_semver(manifest, name, baseline, current, log_dir):
    command = [
        "cargo", "semver-checks", "--manifest-path", str(manifest),
        "--package", name, "--baseline-version", baseline,
        "--release-type", "patch", "--all-features", "--color", "never",
    ]
    log = log_dir / f"{name}.log"
    # cargo-semver-checks documents crates from temporary directories. The
    # workspace rustdoc config uses a relative header path, which is absent
    # there (including for published baselines), so supply its absolute path.
    env = os.environ.copy()
    env.pop("CARGO_ENCODED_RUSTDOCFLAGS", None)
    env["RUSTDOCFLAGS"] = f"--html-in-header {manifest.parent / '.cargo/katex-header.html'}"
    try:
        result = run_command(command, 1200, env=env)
    except CheckError as error:
        log.write_text(f"$ {' '.join(command)}\nCurrent version: {current}\nBaseline: {baseline}\nERROR: {error}\n")
        raise
    log.write_text(
        f"$ {' '.join(command)}\nCurrent version: {current}\n"
        f"Baseline: {baseline}\nExit: {result.returncode}\n\n"
        f"STDOUT:\n{result.stdout}\nSTDERR:\n{result.stderr}"
    )
    if result.returncode == 0:
        return "CLEAN"
    if result.returncode == 100:
        return "ADVISORY FINDINGS"
    raise CheckError(f"{name}: cargo-semver-checks exit {result.returncode}; see {log}")


def render_summary(rows):
    lines = [
        "## Advisory API report",
        "",
        "Released crates are compared with their pinned crates.io baselines using "
        "cargo-semver-checks 0.50.0, all features, and a forced patch threshold. "
        "The patch threshold surfaces changes even if a manifest version has risen; "
        "maintainers apply the existing release version policy. Exit 100 findings are advisory.",
        "",
        "| Package | Released baseline | Current version | Result | Log |",
        "| --- | --- | --- | --- | --- |",
    ]
    for name, baseline, current, state, log in rows:
        lines.append(f"| {name} | {baseline} | {current} | {state} | {log} |")
    lines += ["", "Full tool logs are in the api-compatibility-logs artifact.", ""]
    return "\n".join(lines)


def check(manifest, log_dir):
    log_dir.mkdir(parents=True, exist_ok=True)
    rows = []
    failure = False
    try:
        metadata_result = run_command(
            ["cargo", "metadata", "--no-deps", "--format-version", "1", "--manifest-path", str(manifest)], 60
        )
        if metadata_result.returncode != 0:
            raise CheckError(f"cargo metadata failed: {metadata_result.stderr.strip()}")
        packages = workspace_packages(json.loads(metadata_result.stdout), BASELINES)
    except (CheckError, ValueError, KeyError, TypeError) as error:
        rows.append(("workspace", "—", "—", f"ERROR: {error}", "—"))
        return rows, True

    try:
        verify_tool()
        tool_error = None
    except CheckError as error:
        tool_error = str(error)
        failure = True

    for name, baseline in BASELINES.items():
        current = packages[name]
        log_name = "—"
        try:
            status, body = fetch_registry(name)
            release_state = classify_registry(name, baseline, status, body)
            if release_state == "NEW CRATE / NO RELEASE BASELINE":
                rows.append((name, "—", current, release_state, "—"))
                continue
            if tool_error:
                raise CheckError(tool_error)
            log_name = f"{name}.log"
            state = run_semver(manifest, name, baseline, current, log_dir)
            rows.append((name, baseline, current, state, log_name))
        except CheckError as error:
            failure = True
            rows.append((name, baseline or "—", current, f"ERROR: {error}", log_name))
    return rows, failure


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest-path", type=Path, default=Path(__file__).resolve().parents[1] / "Cargo.toml")
    parser.add_argument("--log-dir", type=Path, default=Path("api-compatibility-logs"))
    args = parser.parse_args()
    rows, failure = check(args.manifest_path.resolve(), args.log_dir)
    summary = render_summary(rows)
    print(summary)
    (args.log_dir / "summary.md").write_text(summary)
    if "GITHUB_STEP_SUMMARY" in os.environ:
        with open(os.environ["GITHUB_STEP_SUMMARY"], "a", encoding="utf-8") as output:
            output.write(summary)
    return 1 if failure else 0


if __name__ == "__main__":
    sys.exit(main())
