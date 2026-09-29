import json
import os
from pathlib import Path
import subprocess
import tempfile
import textwrap
import tomllib
import unittest


SCRIPT = Path(__file__).resolve().parents[2] / "create_release.sh"


class CreateReleaseTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp_dir.cleanup)
        self.root = Path(self.temp_dir.name)
        self.repo = self.root / "repo"
        self.repo.mkdir()
        (self.repo / "Cargo.toml").write_text(
            textwrap.dedent(
                '''\
                [workspace]
                members = ["alpha", "test-utils"]
                resolver = "2"

                [workspace.package]
                version = "0.1.0" # keep this comment
                edition = "2021"

                [workspace.dependencies]
                alpha = { path = "alpha", version = "0.1.0" } # local
                test-utils = { path = "test-utils", version = "0.1.0" }
                external = { path = "../external", version = "1.2.3" } # external
                '''
            )
        )
        for directory, name, publish in (
            ("alpha", "alpha", ""),
            ("test-utils", "test-utils", "publish = false\n"),
        ):
            crate = self.repo / directory
            (crate / "src").mkdir(parents=True)
            (crate / "src" / "lib.rs").write_text("pub fn value() -> u8 { 1 }\n")
            (crate / "Cargo.toml").write_text(
                f'[package]\nname = "{name}"\nversion.workspace = true\n'
                f'edition.workspace = true\n{publish}'
                + ("\n[dependencies]\nexternal.workspace = true\n" if name == "alpha" else "")
            )
        external = self.root / "external"
        (external / "src").mkdir(parents=True)
        (external / "src" / "lib.rs").write_text("pub fn external() {}\n")
        (external / "Cargo.toml").write_text(
            '[package]\nname = "external"\nversion = "1.2.3"\nedition = "2021"\n'
        )
        self.git("init", "-q", "-b", "main")
        self.git("config", "user.name", "Fixture")
        self.git("config", "user.email", "fixture@example.invalid")
        self.git("config", "commit.gpgsign", "false")
        self.cargo("generate-lockfile", "--offline")
        self.git("add", ".")
        self.git("commit", "-qm", "initial")
        self.remote = self.root / "origin.git"
        self.git("clone", "-q", "--bare", str(self.repo), str(self.remote))
        self.git("remote", "add", "origin", str(self.remote))
        self.git("update-ref", "refs/remotes/origin/main", "HEAD")
        self.initial_manifest = (self.repo / "Cargo.toml").read_bytes()
        self.initial_lock = (self.repo / "Cargo.lock").read_bytes()
        self.bin = self.root / "bin"
        self.bin.mkdir()
        self.events = self.root / "events"
        self.make_stub(
            "git",
            '''
            if len(sys.argv) > 1 and sys.argv[1] in ("fetch", "push"):
                log("git " + " ".join(sys.argv[1:]))
            else:
                os.execv(REAL_GIT, [REAL_GIT, *sys.argv[1:]])
            ''',
        )
        self.make_stub("gh", 'log("gh " + " ".join(sys.argv[1:]))')
        self.make_stub("release-plz", 'log("release-plz " + " ".join(sys.argv[1:]))')

    def git(self, *args):
        return subprocess.check_output(["git", *args], cwd=self.repo, text=True).strip()

    def cargo(self, *args):
        return subprocess.check_output(["cargo", *args], cwd=self.repo, text=True)

    def remote_ref(self, branch):
        self.git(
            f"--git-dir={self.remote}",
            "update-ref",
            f"refs/heads/{branch}",
            self.git("rev-parse", "HEAD"),
        )

    def make_stub(self, name, action):
        path = self.bin / name
        path.write_text(
            "#!/usr/bin/env python3\n"
            "import os, sys\n"
            "from pathlib import Path\n"
            "REAL_GIT = os.environ['RELEASE_TEST_REAL_GIT']\n"
            "def log(value):\n"
            "    with Path(os.environ['RELEASE_TEST_EVENTS']).open('a') as f: f.write(value + '\\n')\n"
            + textwrap.dedent(action)
        )
        path.chmod(0o755)

    def run_release(self, *args):
        env = os.environ.copy()
        env.update(
            PATH=f"{self.bin}{os.pathsep}{env['PATH']}",
            GIT_TOKEN="fixture-token",
            RELEASE_TEST_REAL_GIT=subprocess.check_output(["which", "git"], text=True).strip(),
            RELEASE_TEST_EVENTS=str(self.events),
            CARGO_TARGET_DIR=str(self.root / "target"),
        )
        return subprocess.run(
            ["bash", str(SCRIPT), *args], cwd=self.repo, env=env, capture_output=True, text=True
        )

    def events_text(self):
        return self.events.read_text() if self.events.exists() else ""

    def assert_unchanged(self, branch="main"):
        self.assertEqual((self.repo / "Cargo.toml").read_bytes(), self.initial_manifest)
        self.assertEqual((self.repo / "Cargo.lock").read_bytes(), self.initial_lock)
        self.assertEqual(self.git("branch", "--show-current"), branch)

    def test_rc_updates_workspace_and_lock_and_opens_pr(self):
        (self.repo / "untracked-notes.md").write_text("preserve me\n")
        result = self.run_release("0.2.0-rc.0")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.git("branch", "--show-current"), "robin/release-0.2.0-rc.0")
        manifest_text = (self.repo / "Cargo.toml").read_text()
        manifest = tomllib.loads(manifest_text)
        self.assertEqual(manifest["workspace"]["package"]["version"], "0.2.0-rc.0")
        for dependency in ("alpha", "test-utils"):
            self.assertEqual(manifest["workspace"]["dependencies"][dependency]["version"], "0.2.0-rc.0")
        self.assertEqual(manifest["workspace"]["dependencies"]["external"]["version"], "1.2.3")
        self.assertIn('version = "0.2.0-rc.0" # keep this comment', manifest_text)
        self.assertIn('# local', manifest_text)
        self.assertIn('# external', manifest_text)
        lock = tomllib.loads((self.repo / "Cargo.lock").read_text())
        versions = {p["name"]: p["version"] for p in lock["package"]}
        self.assertEqual(
            versions, {"alpha": "0.2.0-rc.0", "test-utils": "0.2.0-rc.0", "external": "1.2.3"}
        )
        original_external = next(
            p for p in tomllib.loads(self.initial_lock.decode())["package"] if p["name"] == "external"
        )
        current_external = next(p for p in lock["package"] if p["name"] == "external")
        self.assertEqual(current_external, original_external)
        metadata = json.loads(self.cargo("metadata", "--offline", "--locked", "--format-version", "1"))
        external_id = next(p["id"] for p in metadata["packages"] if p["name"] == "external")
        self.assertNotIn(external_id, metadata["workspace_members"])
        self.assertEqual((self.repo / "untracked-notes.md").read_text(), "preserve me\n")
        self.assertEqual(self.git("status", "--porcelain"), "?? untracked-notes.md")
        self.assertEqual(self.git("show", "--pretty=format:", "--name-only", "HEAD"), "Cargo.lock\nCargo.toml")
        events = self.events_text()
        self.assertIn("git fetch origin main", events)
        self.assertIn("git push -u origin robin/release-0.2.0-rc.0", events)
        self.assertIn("gh pr create --base main --head robin/release-0.2.0-rc.0", events)

    def test_invalid_args_fail_before_network_or_mutation(self):
        for args in (
            ("0.2.0",), ("01.2.3-rc.1",), ("1.02.3-rc.1",),
            ("1.2.03-rc.1",), ("1.2.3-rc.01",), ("1.2.3-rc1",),
            ("1.2.3-rc.1x",), ("1.2.3-rc.1", "extra"), ("",),
        ):
            with self.subTest(args=args):
                result = self.run_release(*args)
                self.assertNotEqual(result.returncode, 0)
                self.assert_unchanged()
                self.assertEqual(self.events_text(), "")

    def test_dirty_tracked_and_staged_work_fail_before_fetch(self):
        manifest_path = self.repo / "Cargo.toml"
        manifest_path.write_bytes(self.initial_manifest + b"\n# dirty\n")
        result = self.run_release("1.2.3-rc.4")
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.events_text(), "")
        self.assertEqual(manifest_path.read_bytes(), self.initial_manifest + b"\n# dirty\n")
        self.git("checkout", "--", "Cargo.toml")
        manifest_path.write_bytes(self.initial_manifest + b"\n# staged\n")
        self.git("add", "Cargo.toml")
        result = self.run_release("1.2.3-rc.4")
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.events_text(), "")
        self.assertEqual(manifest_path.read_bytes(), self.initial_manifest + b"\n# staged\n")

    def test_existing_release_branch_fails_without_mutation_or_fetch(self):
        self.git("branch", "robin/release-1.2.3-rc.4")
        result = self.run_release("1.2.3-rc.4")
        self.assertNotEqual(result.returncode, 0)
        self.assert_unchanged()
        self.assertEqual(self.events_text(), "")

    def test_supported_version_bases_allow_automatic_and_rc_modes(self):
        for index, base in enumerate(("v1.2.3", "v1.2.3-rc4", "v1.2.3-rc.4"), 1):
            with self.subTest(base=base):
                self.git("switch", "-q", "-c", base)
                self.remote_ref(base)
                self.git("update-ref", f"refs/remotes/origin/{base}", "HEAD")
                automatic = self.run_release()
                self.assertEqual(automatic.returncode, 0, automatic.stderr)
                self.assert_unchanged(base)
                self.assertIn("release-plz release-pr", self.events_text())
                self.events.unlink()

                version = f"0.2.{index}-rc.0"
                candidate = self.run_release(version)
                self.assertEqual(candidate.returncode, 0, candidate.stderr)
                self.assertEqual(self.git("branch", "--show-current"), f"robin/release-{version}")
                self.assertIn(
                    f"gh pr create --base {base} --head robin/release-{version}", self.events_text()
                )
                self.git("switch", "-q", "main")
                self.events.unlink()

    def test_unsupported_bases_fail_before_fetch_in_both_modes(self):
        for base in ("feature/other", "v1.2", "v1.2.3-rcX"):
            with self.subTest(base=base):
                self.git("switch", "-q", "-c", base)
                for args in ((), ("0.2.0-rc.1",)):
                    result = self.run_release(*args)
                    self.assertNotEqual(result.returncode, 0)
                    self.assert_unchanged(base)
                    self.assertEqual(self.events_text(), "")
                self.git("switch", "-q", "main")
                self.events.unlink(missing_ok=True)

    def test_remote_only_release_branch_fails_before_mutation(self):
        self.remote_ref("robin/release-1.2.3-rc.4")
        result = self.run_release("1.2.3-rc.4")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("already exists", result.stderr)
        self.assert_unchanged()
        self.assertEqual(self.events_text(), "git fetch origin main\n")

    def test_remote_lookup_error_is_not_treated_as_missing_branch(self):
        self.git("remote", "set-url", "origin", str(self.root / "missing-remote"))
        result = self.run_release("1.2.3-rc.4")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("could not check", result.stderr.lower())
        self.assert_unchanged()
        self.assertEqual(self.events_text(), "git fetch origin main\n")

    def test_automatic_mode_delegates_without_version_edits(self):
        result = self.run_release()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assert_unchanged()
        self.assertEqual(self.events_text(), "git fetch origin main\nrelease-plz release-pr\n")


if __name__ == "__main__":
    unittest.main()
