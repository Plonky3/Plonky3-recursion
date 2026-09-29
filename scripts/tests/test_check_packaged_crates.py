"""Exercise package consumption across a real Cargo archive boundary."""

import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


SCRIPT = Path(__file__).resolve().parents[1] / "check_packaged_crates.py"


def write(path, contents):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(contents)


def fixture(root, omit_module=False):
    write(root / "Cargo.toml", '[workspace]\nmembers = ["alpha", "beta", "helper"]\nresolver = "2"\n')
    write(root / "alpha/Cargo.toml", '[package]\nname = "fixture-alpha"\nversion = "0.1.0"\nedition = "2021"\n')
    write(root / "alpha/src/lib.rs", "pub fn value() -> u32 { 7 }\n")
    write(root / "beta/Cargo.toml", '''[package]
name = "fixture-beta"
version = "0.1.0"
edition = "2021"
''' + ('include = ["Cargo.toml", "src/lib.rs"]\n' if omit_module else '') + '''
[dependencies]
fixture-alpha = { path = "../alpha", version = "0.1.0" }
[dev-dependencies]
fixture-helper = { path = "../helper", version = "0.1.0" }
''')
    write(root / "beta/src/lib.rs", "mod secret;\npub fn value() -> u32 { fixture_alpha::value() + secret::extra() }\n")
    write(root / "beta/src/secret.rs", "pub fn extra() -> u32 { 1 }\n")
    write(root / "helper/Cargo.toml", '[package]\nname = "fixture-helper"\nversion = "0.1.0"\nedition = "2021"\npublish = false\n')
    write(root / "helper/src/lib.rs", "pub fn helper() {}\n")
    write(root / "consumer.rs", "fn main() { assert_eq!(fixture_beta::value(), 8); }\n")
    subprocess.run(["git", "init", "-q", str(root)], check=True)
    subprocess.run(["git", "-C", str(root), "add", "."], check=True)
    subprocess.run(["git", "-C", str(root), "-c", "commit.gpgsign=false", "-c", "user.name=Fixture", "-c", "user.email=fixture@example.test", "commit", "-qm", "fixture"], check=True)


class PackageConsumerTest(unittest.TestCase):
    def test_registry_dependency_without_path_is_allowed(self):
        spec = importlib.util.spec_from_file_location("check_packaged_crates", SCRIPT)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        metadata = {"workspace_members": ["alpha"], "packages": [{"id": "alpha", "name": "fixture-alpha", "version": "0.1.0", "publish": None, "manifest_path": "/tmp/fixture-alpha/Cargo.toml", "dependencies": [{"name": "serde", "kind": None}]}]}
        self.assertEqual(module.packages_from_metadata(metadata), [("fixture-alpha", "0.1.0")])

    def test_unpublished_normal_dependency_is_rejected(self):
        spec = importlib.util.spec_from_file_location("check_packaged_crates", SCRIPT)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        metadata = {"workspace_members": ["alpha", "helper"], "packages": [
            {"id": "alpha", "name": "fixture-alpha", "version": "0.1.0", "publish": None, "manifest_path": "/tmp/alpha/Cargo.toml", "dependencies": [{"name": "fixture-helper", "kind": None, "path": "/tmp/helper"}]},
            {"id": "helper", "name": "fixture-helper", "version": "0.1.0", "publish": [], "manifest_path": "/tmp/helper/Cargo.toml", "dependencies": []},
        ]}
        with self.assertRaisesRegex(ValueError, "not a publishable"):
            module.packages_from_metadata(metadata)

    def test_source_tree_substitution_is_rejected(self):
        spec = importlib.util.spec_from_file_location("check_packaged_crates", SCRIPT)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            metadata = {"packages": [{"name": "fixture-alpha", "version": "0.1.0", "manifest_path": str(root / "workspace/Cargo.toml"), "source": None}]}
            with self.assertRaisesRegex(ValueError, "outside its expected archive"):
                module.check_graph(metadata, [("fixture-alpha", "0.1.0")], {"fixture-alpha": root / "archive"}, root / "consumer")

    def test_two_archives_and_private_dev_helper(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "fixture"
            root.mkdir()
            fixture(root)
            result = subprocess.run([sys.executable, str(SCRIPT), "--workspace", str(root), "--consumer-source", str(root / "consumer.rs"), "--offline"], capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn("fixture-alpha", result.stdout)
            self.assertIn("fixture-beta", result.stdout)

    def test_omitted_normal_module_fails_external_compilation(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "fixture"
            root.mkdir()
            fixture(root, omit_module=True)
            result = subprocess.run([sys.executable, str(SCRIPT), "--workspace", str(root), "--consumer-source", str(root / "consumer.rs"), "--offline"], capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("secret", result.stdout + result.stderr)

    def test_missing_archive_is_rejected(self):
        spec = importlib.util.spec_from_file_location("check_packaged_crates", SCRIPT)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaisesRegex(ValueError, "missing archive"):
                module.extract_archives(Path(tmp), [("fixture-alpha", "0.1.0")], Path(tmp) / "extract")


if __name__ == "__main__":
    unittest.main()
