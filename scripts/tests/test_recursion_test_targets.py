import re
import tomllib
import unittest
from collections import Counter
from pathlib import Path


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
                if module == "common":
                    self.assertEqual(source, TESTS / "common" / "mod.rs")
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


if __name__ == "__main__":
    unittest.main()
