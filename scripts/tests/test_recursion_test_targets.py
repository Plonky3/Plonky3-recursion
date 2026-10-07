import re
import shlex
import tomllib
import unittest
from collections import Counter
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[2]
RECURSION = ROOT / "recursion"
TESTS = RECURSION / "tests"
MODULE = re.compile(r'#\[path = "([^"]+)"\]\s+mod (\w+);')


class RecursionTestTargetsTests(unittest.TestCase):
    def setUp(self):
        self.manifest = tomllib.loads((RECURSION / "Cargo.toml").read_text())
        self.targets = self.manifest.get("test", [])

    def test_integration_binaries_are_bounded(self):
        self.assertIs(self.manifest["package"].get("autotests", True), False)
        self.assertGreater(len(self.targets), 1)
        self.assertLessEqual(len(self.targets), 10)

    def test_every_integration_file_is_registered_once(self):
        expected = set(TESTS.glob("*.rs"))
        registered = []
        for target in self.targets:
            entry = RECURSION / target["path"]
            self.assertTrue(entry.is_file(), entry)
            if entry.parent == TESTS:
                registered.append(entry)
                continue
            self.assertEqual(entry.parent, TESTS / "suites")
            for relative, module in MODULE.findall(entry.read_text()):
                source = (entry.parent / relative).resolve()
                self.assertTrue(source.is_file(), source)
                if module in {"common", "test_config"}:
                    filename = "mod.rs" if module == "common" else "test_config.rs"
                    self.assertEqual(source, TESTS / "common" / filename)
                    continue
                self.assertEqual(module, source.stem)
                registered.append(source)
        self.assertEqual(set(registered), expected)
        self.assertEqual(set(Counter(registered).values()), {1})

    def test_common_fixture_types_are_shared(self):
        for source in TESTS.glob("*.rs"):
            if source.stem != "whir_quintic":
                self.assertIsNone(
                    re.search(r"(?m)^mod common;$", source.read_text()),
                    f"{source} reloads the common fixture",
                )

    def test_ci_build_groups_cover_every_workspace_target_once(self):
        workflow = yaml.safe_load((ROOT / ".github/workflows/ci.yml").read_text())
        job = workflow["jobs"]["workspace_tests"]
        groups = job["strategy"]["matrix"]["shard"]
        selected = []
        kinds = []
        for group in groups:
            arguments = shlex.split(group["targets"])
            for position, argument in enumerate(arguments):
                if argument == "--test":
                    selected.append(arguments[position + 1])
                elif argument in {"--lib", "--bins", "--examples", "--benches"}:
                    kinds.append(argument)

        workspace = tomllib.loads((ROOT / "Cargo.toml").read_text())
        expected = set()
        for member in workspace["workspace"]["members"]:
            directory = ROOT / member
            manifest = tomllib.loads((directory / "Cargo.toml").read_text())
            expected.update(target["name"] for target in manifest.get("test", []))
            if manifest["package"].get("autotests", True):
                expected.update(source.stem for source in (directory / "tests").glob("*.rs"))
        self.assertEqual(set(selected), expected)
        self.assertEqual(set(Counter(selected).values()), {1})
        self.assertEqual(Counter(kinds), Counter({"--lib": 1, "--bins": 1, "--examples": 1, "--benches": 1}))


if __name__ == "__main__":
    unittest.main()
