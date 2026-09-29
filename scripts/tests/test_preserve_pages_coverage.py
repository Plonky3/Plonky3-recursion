import importlib.util
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts/preserve_pages_coverage.py"


def git(*args, cwd):
    return subprocess.run(
        ["git", *args], cwd=cwd, capture_output=True, check=True
    ).stdout


class PreserveCoverageTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.origin = self.root / "origin.git"
        self.repo = self.root / "repo"
        self.book = self.root / "book"
        self.book.mkdir()
        git("init", "--bare", str(self.origin), cwd=self.root)
        git("init", "-b", "gh-pages", str(self.repo), cwd=self.root)
        git("config", "user.name", "Test", cwd=self.repo)
        git("config", "user.email", "test@example.com", cwd=self.repo)
        git("config", "commit.gpgsign", "false", cwd=self.repo)
        git("remote", "add", "origin", str(self.origin), cwd=self.repo)
        self.published = {}

    def publish(self, files):
        git("rm", "-r", "--ignore-unmatch", ".", cwd=self.repo)
        for name, data in files.items():
            target = self.repo / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(data)
        git("add", "-A", cwd=self.repo)
        git("commit", "--allow-empty", "-m", "publish fixture", cwd=self.repo)
        git("push", "origin", "HEAD:refs/heads/gh-pages", cwd=self.repo)
        self.published = files.copy()

    def run_helper(self):
        return subprocess.run(
            [sys.executable, str(SCRIPT), str(self.book)],
            cwd=self.repo, capture_output=True, text=True
        )

    def book_publish(self, files):
        for name, data in files.items():
            target = self.book / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(data)
        result = self.run_helper()
        self.assertEqual(result.returncode, 0, result.stderr)
        replacement = {
            str(path.relative_to(self.book)): path.read_bytes()
            for path in self.book.rglob("*") if path.is_file()
        }
        self.publish(replacement)

    def coverage_publish(self, files):
        replacement = {
            name: data for name, data in self.published.items()
            if not name.startswith("coverage/")
        }
        replacement.update({f"coverage/{name}": data for name, data in files.items()})
        self.publish(replacement)

    def test_book_preserves_coverage_and_removes_stale_book_pages(self):
        self.publish({
            "old.html": b"stale", "coverage/index.html": b"report",
            "coverage/style.css": b"style"
        })
        self.book_publish({"index.html": b"new book"})
        self.assertEqual(self.published, {
            "index.html": b"new book", "coverage/index.html": b"report",
            "coverage/style.css": b"style"
        })

    def test_coverage_replaces_only_its_subtree(self):
        self.publish({
            "index.html": b"book", "chapter.html": b"chapter",
            "coverage/index.html": b"old", "coverage/stale.css": b"stale"
        })
        self.coverage_publish({"index.html": b"new report"})
        self.assertEqual(self.published, {
            "index.html": b"book", "chapter.html": b"chapter",
            "coverage/index.html": b"new report"
        })

    def test_both_publication_orders(self):
        for order in ("coverage-first", "book-first"):
            with self.subTest(order=order):
                self.publish({"index.html": b"old book", "coverage/index.html": b"old report"})
                for operation in (("coverage", "book") if order == "coverage-first"
                                  else ("book", "coverage")):
                    if operation == "coverage":
                        self.coverage_publish({"index.html": b"new report"})
                    else:
                        # Recreate a clean generated output for each order.
                        shutil.rmtree(self.book)
                        self.book.mkdir()
                        self.book_publish({"index.html": b"new book"})
                self.assertEqual(self.published, {
                    "index.html": b"new book", "coverage/index.html": b"new report"
                })

    def test_initial_branch_and_missing_coverage_are_noops(self):
        self.assertEqual(self.run_helper().returncode, 0)
        self.assertFalse((self.book / "coverage").exists())
        self.publish({"index.html": b"book only"})
        self.assertEqual(self.run_helper().returncode, 0)
        self.assertFalse((self.book / "coverage").exists())

    def test_remote_query_failure_is_not_treated_as_missing_branch(self):
        git("remote", "set-url", "origin", str(self.root / "missing.git"), cwd=self.repo)
        result = self.run_helper()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("could not query", result.stderr)

    def test_fetch_failure_is_not_treated_as_missing_coverage(self):
        spec = importlib.util.spec_from_file_location("preserve_pages_coverage", SCRIPT)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        remote = subprocess.CompletedProcess([], 0, b"a\trefs/heads/gh-pages\n", b"")
        with mock.patch.object(module, "git", side_effect=[remote, RuntimeError("fetch failed")]):
            with self.assertRaisesRegex(RuntimeError, "fetch failed"):
                module.preserve_coverage(self.book)

    def test_generated_book_cannot_occupy_coverage_path(self):
        (self.book / "coverage").write_bytes(b"book content")
        result = self.run_helper()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("reserved path", result.stderr)

    def test_published_coverage_symlink_is_rejected(self):
        (self.repo / "coverage").mkdir()
        os.symlink("../../outside", self.repo / "coverage/escape")
        git("add", "-A", cwd=self.repo)
        git("commit", "-m", "symlink fixture", cwd=self.repo)
        git("push", "origin", "HEAD:refs/heads/gh-pages", cwd=self.repo)
        result = self.run_helper()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("unsafe coverage tree entry", result.stderr)
        self.assertFalse((self.book / "coverage").exists())


class WorkflowTests(unittest.TestCase):
    def test_deploy_jobs_share_lock_and_own_published_paths(self):
        try:
            import yaml
        except ImportError:
            self.skipTest("PyYAML unavailable for workflow parsing")

        book = yaml.safe_load((ROOT / ".github/workflows/book.yml").read_text())
        coverage = yaml.safe_load((ROOT / ".github/workflows/coverage.yml").read_text())
        for workflow in (book, coverage):
            self.assertNotIn("concurrency", workflow)
            deploy = workflow["jobs"]["deploy"]
            self.assertEqual(deploy["concurrency"], {
                "group": "gh-pages", "cancel-in-progress": False
            })
            self.assertEqual(deploy["permissions"], {"contents": "write"})
        self.assertEqual(book["jobs"]["build"]["permissions"], {"contents": "read"})
        self.assertEqual(coverage["jobs"]["coverage"]["permissions"], {"contents": "read"})
        self.assertEqual(book["jobs"]["deploy"]["needs"], "build")
        self.assertEqual(coverage["jobs"]["deploy"]["needs"], "coverage")

        book_steps = book["jobs"]["deploy"]["steps"]
        preserve_index = next(i for i, step in enumerate(book_steps)
                              if "preserve_pages_coverage.py" in step.get("run", ""))
        publish_index = next(i for i, step in enumerate(book_steps)
                             if step.get("uses", "").startswith("peaceiris/actions-gh-pages@"))
        self.assertLess(preserve_index, publish_index)
        book_publish = book_steps[publish_index]["with"]
        self.assertNotIn("destination_dir", book_publish)
        self.assertFalse(book_publish.get("keep_files", False))

        coverage_steps = coverage["jobs"]["deploy"]["steps"]
        self.assertTrue(any(step.get("uses", "").startswith("actions/download-artifact@")
                            for step in coverage_steps))
        coverage_publish = next(step["with"] for step in coverage_steps
                                if step.get("uses", "").startswith("peaceiris/actions-gh-pages@"))
        self.assertEqual(coverage_publish["destination_dir"], "coverage")
        self.assertFalse(coverage_publish.get("keep_files", False))


if __name__ == "__main__":
    unittest.main()
