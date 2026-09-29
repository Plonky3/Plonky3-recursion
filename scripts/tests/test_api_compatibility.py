import importlib.util
import io
import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock
from urllib.error import HTTPError, URLError


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts/check_api_compatibility.py"
SPEC = importlib.util.spec_from_file_location("check_api_compatibility", SCRIPT)
api = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(api)


class RegistryTests(unittest.TestCase):
    def payload(self, name, versions):
        return json.dumps({"crate": {"id": name}, "versions": versions}).encode()

    def test_released_baseline_and_missing_version(self):
        body = self.payload("p3-circuit", [{"num": "0.1.0", "yanked": False}])
        self.assertEqual(api.classify_registry("p3-circuit", "0.1.0", 200, body), "RELEASED")
        with self.assertRaisesRegex(api.CheckError, "baseline 0.2.0 is absent"):
            api.classify_registry("p3-circuit", "0.2.0", 200, body)

    def test_yanked_baseline_is_operational_error(self):
        body = self.payload("p3-circuit", [{"num": "0.1.0", "yanked": True}])
        with self.assertRaisesRegex(api.CheckError, "yanked"):
            api.classify_registry("p3-circuit", "0.1.0", 200, body)

    def test_true_absence_only_for_expected_unreleased_crate(self):
        absent = b'{"errors":[{"detail":"crate `p3-new` does not exist"}]}'
        self.assertEqual(api.classify_registry("p3-new", None, 404, absent), "NEW CRATE / NO RELEASE BASELINE")
        with self.assertRaisesRegex(api.CheckError, "expected baseline 0.1.0"):
            api.classify_registry("p3-new", "0.1.0", 404, absent)
        with self.assertRaisesRegex(api.CheckError, "malformed registry response"):
            api.classify_registry("p3-new", None, 404, b"not found")

    def test_newly_released_crate_needs_baseline(self):
        body = self.payload("p3-new", [{"num": "0.1.0", "yanked": False}])
        with self.assertRaisesRegex(api.CheckError, "pin a baseline"):
            api.classify_registry("p3-new", None, 200, body)

    def test_malformed_and_http_errors_fail(self):
        for status, body in [(200, b"no"), (200, b"{}"), (429, b"rate limit"), (500, b"error")]:
            with self.subTest(status=status, body=body), self.assertRaises(api.CheckError):
                api.classify_registry("p3-circuit", "0.1.0", status, body)

    def test_transport_errors_fail(self):
        with mock.patch.object(api, "urlopen", side_effect=URLError("timeout")):
            with self.assertRaisesRegex(api.CheckError, "registry request failed"):
                api.fetch_registry("p3-circuit")
        body = io.BytesIO(b"error")
        error = HTTPError("https://example.invalid", 503, "unavailable", {}, body)
        with mock.patch.object(api, "urlopen", side_effect=error):
            with self.assertRaisesRegex(api.CheckError, "HTTP 503"):
                api.fetch_registry("p3-circuit")
        self.assertTrue(body.closed)


class WorkspaceTests(unittest.TestCase):
    def test_publishable_set_must_match_policy(self):
        metadata = {"packages": [
            {"name": "p3-circuit", "version": "0.2.0", "publish": None, "id": "p3-circuit 0.2.0 (path+file:///test)"},
            {"name": "p3-private", "version": "0.1.0", "publish": [], "id": "p3-private 0.1.0 (path+file:///test)"},
        ], "workspace_members": ["p3-circuit 0.2.0 (path+file:///test)", "p3-private 0.1.0 (path+file:///test)"]}
        self.assertEqual(api.workspace_packages(metadata, {"p3-circuit": "0.1.0"}), {"p3-circuit": "0.2.0"})
        with self.assertRaisesRegex(api.CheckError, "classification mismatch"):
            api.workspace_packages(metadata, {"p3-other": None})


class ToolTests(unittest.TestCase):
    def test_tool_version_and_missing_executable(self):
        with mock.patch.object(api.subprocess, "run", return_value=subprocess.CompletedProcess([], 0, "cargo-semver-checks 0.50.0\n", "")):
            api.verify_tool()
        with mock.patch.object(api.subprocess, "run", return_value=subprocess.CompletedProcess([], 0, "cargo-semver-checks 0.49.0\n", "")):
            with self.assertRaisesRegex(api.CheckError, "expected cargo-semver-checks 0.50.0"):
                api.verify_tool()
        with mock.patch.object(api.subprocess, "run", side_effect=FileNotFoundError):
            with self.assertRaisesRegex(api.CheckError, "not found"):
                api.verify_tool()

    def test_semver_exit_codes_and_log(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)
            for code, state in [(0, "CLEAN"), (100, "ADVISORY FINDINGS")]:
                with self.subTest(code=code), mock.patch.object(api.subprocess, "run", return_value=subprocess.CompletedProcess([], code, "details", "warnings")) as command:
                    self.assertEqual(api.run_semver(Path("/tmp/Cargo.toml"), "p3-circuit", "0.1.0", "0.2.0", output), state)
                    self.assertEqual(command.call_args.kwargs["env"]["RUSTDOCFLAGS"],
                                     "--html-in-header /tmp/.cargo/katex-header.html")
                    log = (output / "p3-circuit.log").read_text()
                    self.assertIn("--release-type patch --all-features", log)
                    self.assertIn("details", log)
            for code in (101, 2):
                with self.subTest(code=code), mock.patch.object(api.subprocess, "run", return_value=subprocess.CompletedProcess([], code, "failed", "reason")):
                    with self.assertRaisesRegex(api.CheckError, f"exit {code}"):
                        api.run_semver(Path("/tmp/Cargo.toml"), "p3-circuit", "0.1.0", "0.2.0", output)
                    self.assertIn("reason", (output / "p3-circuit.log").read_text())
            with mock.patch.object(api.subprocess, "run", side_effect=FileNotFoundError):
                with self.assertRaisesRegex(api.CheckError, "not found"):
                    api.run_semver(Path("/tmp/Cargo.toml"), "p3-circuit", "0.1.0", "0.2.0", output)

    def test_summary_does_not_call_new_crate_compatible(self):
        rows = [
            ("p3-circuit", "0.1.0", "0.2.0", "ADVISORY FINDINGS", "p3-circuit.log"),
            ("p3-new", "—", "0.1.0", "NEW CRATE / NO RELEASE BASELINE", "—"),
            ("p3-broken", "0.1.0", "0.2.0", "ERROR: HTTP 429", "—"),
        ]
        summary = api.render_summary(rows)
        self.assertIn("Advisory API report", summary)
        self.assertIn("patch threshold", summary)
        self.assertIn("NO RELEASE BASELINE", summary)
        self.assertIn("ERROR: HTTP 429", summary)
        self.assertNotIn("All crates compatible", summary)

    def test_check_continues_after_operational_failure_and_keeps_advisory_result(self):
        names = list(api.BASELINES)
        metadata = {"packages": [
            {"name": name, "version": "0.1.0", "publish": None,
             "id": f"{name} 0.1.0 (path+file:///test)"}
            for name in names
        ], "workspace_members": [
            f"{name} 0.1.0 (path+file:///test)" for name in names
        ]}
        metadata_result = subprocess.CompletedProcess([], 0, json.dumps(metadata), "")
        def registry(name):
            if name == "p3-circuit":
                raise api.CheckError("registry HTTP 429")
            if api.BASELINES[name] is None:
                return 404, json.dumps({"errors": [
                    {"detail": f"crate `{name}` does not exist"}
                ]}).encode()
            return 200, json.dumps({"crate": {"id": name}, "versions": [
                {"num": "0.1.0", "yanked": False}
            ]}).encode()

        with tempfile.TemporaryDirectory() as directory, \
                mock.patch.object(api, "run_command", return_value=metadata_result), \
                mock.patch.object(api, "verify_tool"), \
                mock.patch.object(api, "fetch_registry", side_effect=registry), \
                mock.patch.object(api, "run_semver", return_value="ADVISORY FINDINGS") as semver:
            (Path(directory) / "p3-circuit.log").write_text("stale run")
            rows, failed = api.check(Path("/tmp/Cargo.toml"), Path(directory))
        self.assertTrue(failed)
        self.assertEqual(len(rows), len(names))
        self.assertIn("ERROR: registry HTTP 429", rows[0][3])
        self.assertEqual(rows[0][4], "—")
        self.assertEqual(rows[1][3], "ADVISORY FINDINGS")
        self.assertEqual(rows[2][3], "NEW CRATE / NO RELEASE BASELINE")
        self.assertEqual(semver.call_count, 2)


if __name__ == "__main__":
    unittest.main()
