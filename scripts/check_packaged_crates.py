#!/usr/bin/env python3
"""Build published workspace archives as dependencies of an external consumer."""

import argparse
import json
import os
from pathlib import Path, PurePosixPath
import subprocess
import sys
import tarfile
import tempfile
import tomllib


SMOKE = r'''use p3_baby_bear::BabyBear;
use p3_circuit::{CircuitBuilder, StatementExport};
use p3_circuit_prover::batch_stark_prover::{StatementAirBuilder, StatementPreprocessor, StatementProver};
use p3_circuit_prover::common::{NpoAirBuilder, NpoPreprocessor};
use p3_circuit_prover::{config, BatchStarkProver, ConstraintProfile};

// Compiling this function checks the trusted recursion route as a downstream API.
#[allow(dead_code)]
fn recurse(
    config: p3_recursion::builtin_config::KoalaBearD4Poseidon2BinaryConfig,
    backend: p3_recursion::prelude::FriRecursionBackendForExt<4>,
    child_verifier: p3_circuit_prover::CircuitVerifier<p3_recursion::builtin_config::KoalaBearD4Poseidon2BinaryConfig>,
    child_proof: &p3_circuit_prover::BatchStarkProof<p3_recursion::builtin_config::KoalaBearD4Poseidon2BinaryConfig>,
    statement: &[p3_koala_bear::KoalaBear],
) -> Result<p3_recursion::prelude::RecursionOutput<p3_recursion::builtin_config::KoalaBearD4Poseidon2BinaryConfig>, p3_recursion::prelude::VerificationError> {
    use p3_recursion::prelude::*;
    let owner = TrustedPreparedLayer::<_, _, BatchOnly, _, 4>::new(
        TrustedPreparedSource::BatchStark { verifier: child_verifier, proof: child_proof, statement },
        config, backend, ProveNextLayerParams::default(),
    )?;
    let output = owner.prove(TrustedPreparedInput::BatchStark { proof: child_proof, statement })?;
    owner.verifier().verify(&output.0, statement)?;
    Ok(output)
}

fn main() {
    let mut builder = CircuitBuilder::<BabyBear>::new();
    let x = builder.public_input();
    let schema = builder.set_statement_exports::<BabyBear>(&[StatementExport::Base(x)]).unwrap();
    let circuit = builder.build().unwrap();
    let preprocessors: Vec<Box<dyn NpoPreprocessor<BabyBear>>> =
        vec![Box::new(StatementPreprocessor::new(schema.clone()))];
    let air_builders: Vec<Box<dyn NpoAirBuilder<config::BabyBearConfig, 1>>> =
        vec![Box::new(StatementAirBuilder::<1>::new(schema.clone()))];
    let mut prover = BatchStarkProver::new(config::baby_bear());
    prover.register_table_prover(Box::new(StatementProver::<1>::new(schema)));
    let prepared = prover.prepare_circuit::<BabyBear, 1>(
        &circuit, &preprocessors, &air_builders, ConstraintProfile::Standard,
    ).unwrap();
    let verifier = prepared.verifier();
    let expected = BabyBear::new(3);
    let mut runner = circuit.runner();
    runner.set_public_inputs(&[expected]).unwrap();
    let traces = runner.run().unwrap();
    let proof = prepared.prove(&traces).unwrap();
    verifier.verify(&proof, &[expected]).unwrap();
}
'''


def run(command, cwd, env=None):
    print("+", " ".join(map(str, command)), flush=True)
    return subprocess.run(command, cwd=cwd, env=env, check=True, text=True, capture_output=True)


def packages_from_metadata(metadata):
    members = set(metadata["workspace_members"])
    workspace = [p for p in metadata["packages"] if p["id"] in members]
    selected = {p["name"]: p for p in workspace if p["publish"] != []}
    if not selected:
        raise ValueError("no publishable workspace packages")
    by_directory = {Path(p["manifest_path"]).parent.resolve(): p for p in workspace}
    for package in selected.values():
        for dependency in package["dependencies"]:
            if dependency["kind"] not in (None, "build") or not dependency.get("path"):
                continue
            path = Path(dependency["path"]).resolve()
            target = by_directory.get(path)
            if target is None or target["name"] not in selected:
                raise ValueError(f'{package["name"]}: local {dependency["kind"] or "normal"} dependency {dependency["name"]} is not a publishable workspace package')
    return sorted((p["name"], p["version"]) for p in selected.values())


def extract_archives(package_dir, packages, output):
    roots = {}
    for name, version in packages:
        archive = package_dir / f"{name}-{version}.crate"
        if not archive.is_file():
            raise ValueError(f"missing archive: {archive}")
        prefix = f"{name}-{version}"
        root = output / prefix
        root.mkdir(parents=True)
        with tarfile.open(archive, "r:gz") as tar:
            for member in tar:
                parts = PurePosixPath(member.name).parts
                if not parts or parts[0] != prefix or any(part in ("", ".", "..") for part in parts):
                    raise ValueError(f"unsafe archive path: {member.name}")
                destination = output.joinpath(*parts)
                if member.isdir():
                    destination.mkdir(parents=True, exist_ok=True)
                elif member.isfile():
                    destination.parent.mkdir(parents=True, exist_ok=True)
                    with tar.extractfile(member) as source, destination.open("wb") as sink:
                        sink.write(source.read())
                else:
                    raise ValueError(f"unsupported archive entry: {member.name}")
        manifest = root / "Cargo.toml"
        if not manifest.is_file():
            raise ValueError(f"archive has no manifest: {archive}")
        identity = tomllib.loads(manifest.read_text())["package"]
        if (identity["name"], identity["version"]) != (name, version):
            raise ValueError(f"archive identity mismatch: {archive}")
        roots[name] = root.resolve()
    return roots


def write_consumer(path, packages, roots, source):
    path.mkdir()
    (path / "src").mkdir()
    (path / "src/main.rs").write_text(source)
    lines = ['[package]', 'name = "archive-consumer"', 'version = "0.0.0"', 'edition = "2021"', 'publish = false', '', '[workspace]', '', '[dependencies]']
    for name, version in packages:
        lines.append(f'{json.dumps(name)} = {json.dumps("=" + version)}')
    if source == SMOKE:
        lines.extend(['p3-baby-bear = "0.8.0"', 'p3-koala-bear = "0.8.0"'])
    lines.extend(['', '[patch.crates-io]'])
    for name, _ in packages:
        lines.append(f'{json.dumps(name)} = {{ path = {json.dumps(str(roots[name]))} }}')
    (path / "Cargo.toml").write_text("\n".join(lines) + "\n")


def check_graph(metadata, packages, roots, consumer):
    selected = dict(packages)
    seen = set()
    for package in metadata["packages"]:
        name = package["name"]
        if name == "p3-test-utils":
            raise ValueError("private test helper entered consumer graph")
        if name in selected:
            expected = roots[name] / "Cargo.toml"
            if package["version"] != selected[name] or Path(package["manifest_path"]).resolve() != expected:
                raise ValueError(f"{name} resolved outside its expected archive: {package['manifest_path']}")
            seen.add(name)
        elif package["source"] is None and Path(package["manifest_path"]).resolve() != (consumer / "Cargo.toml").resolve():
            raise ValueError(f"unexpected local source in consumer graph: {package['manifest_path']}")
    if seen != set(selected):
        raise ValueError(f"archive packages missing from graph: {sorted(set(selected) - seen)}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workspace", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--consumer-source", type=Path, help="Rust source for a small fixture consumer")
    parser.add_argument("--offline", action="store_true")
    args = parser.parse_args()
    workspace = args.workspace.resolve()
    manifest = workspace / "Cargo.toml"
    offline = ["--offline"] if args.offline else []
    metadata = json.loads(run(["cargo", "metadata", "--no-deps", "--format-version", "1", "--manifest-path", str(manifest), *offline], workspace).stdout)
    packages = packages_from_metadata(metadata)
    excluded = [p["name"] for p in metadata["packages"] if p["id"] in metadata["workspace_members"] and p["publish"] == []]
    source = args.consumer_source.read_text() if args.consumer_source else SMOKE
    with tempfile.TemporaryDirectory(prefix="packaged-crates-") as tmp:
        scratch = Path(tmp)
        target = scratch / "target"
        command = ["cargo", "package", "--workspace", "--no-verify", "--exclude-lockfile", "--target-dir", str(target), "--manifest-path", str(manifest), *offline]
        for name in excluded:
            command.extend(["--exclude", name])
        run(command, workspace)
        roots = extract_archives(target / "package", packages, scratch / "archives")
        consumer = scratch / "consumer"
        write_consumer(consumer, packages, roots, source)
        env = os.environ.copy()
        env["CARGO_TARGET_DIR"] = str(target / "consumer")
        resolved = json.loads(run(["cargo", "metadata", "--format-version", "1", *offline], consumer, env).stdout)
        check_graph(resolved, packages, roots, consumer)
        result = run(["cargo", "run", "--locked", *offline], consumer, env)
        if result.stdout:
            print(result.stdout, end="")
        print("Verified archive consumer:", ", ".join(f"{name}@{version}" for name, version in packages))


if __name__ == "__main__":
    try:
        main()
    except (ValueError, subprocess.CalledProcessError, OSError, tarfile.TarError) as error:
        if isinstance(error, subprocess.CalledProcessError):
            print(error.stdout or "", file=sys.stderr, end="")
            print(error.stderr or "", file=sys.stderr, end="")
        print(f"package consumer check failed: {error}", file=sys.stderr)
        sys.exit(1)
