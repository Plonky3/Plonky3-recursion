#!/usr/bin/env python3
"""Copy the published gh-pages coverage tree into a freshly built book."""

import argparse
import os
import subprocess
from pathlib import Path


BRANCH = "refs/heads/gh-pages"


def git(*args, check=True):
    result = subprocess.run(["git", *args], capture_output=True)
    if check and result.returncode:
        raise RuntimeError(
            f"git {' '.join(args)} failed: {result.stderr.decode(errors='replace').strip()}"
        )
    return result


def preserve_coverage(book_dir):
    book_dir = Path(book_dir)
    if not book_dir.is_dir() or book_dir.is_symlink():
        raise ValueError(f"book output must be a real directory: {book_dir}")
    coverage_dir = book_dir / "coverage"
    if os.path.lexists(coverage_dir):
        raise ValueError(f"book output already contains reserved path: {coverage_dir}")

    remote = git("ls-remote", "--exit-code", "--refs", "origin", BRANCH, check=False)
    if remote.returncode == 2:
        return
    if remote.returncode != 0:
        raise RuntimeError(
            f"could not query {BRANCH}: {remote.stderr.decode(errors='replace').strip()}"
        )
    if len(remote.stdout.splitlines()) != 1 or not remote.stdout.endswith(
        f"\t{BRANCH}\n".encode()
    ):
        raise RuntimeError(f"unexpected remote response for {BRANCH}")

    git("fetch", "--no-tags", "--depth=1", "origin", BRANCH)
    tree = git("ls-tree", "-r", "-z", "--full-tree", "FETCH_HEAD", "--", "coverage")
    files = []
    for entry in tree.stdout.split(b"\0"):
        if not entry:
            continue
        metadata, path = entry.split(b"\t", 1)
        mode, kind, oid = metadata.split(b" ")
        parts = path.split(b"/")
        if (len(parts) < 2 or parts[0] != b"coverage"
                or any(part in (b"", b".", b"..") for part in parts)
                or kind != b"blob" or mode not in (b"100644", b"100755")):
            raise ValueError(f"unsafe coverage tree entry: {path!r} ({mode.decode()})")
        files.append((parts[1:], oid.decode("ascii"), mode))

    for parts, oid, mode in files:
        target = coverage_dir.joinpath(*(os.fsdecode(part) for part in parts))
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(git("cat-file", "blob", oid).stdout)
        if mode == b"100755":
            target.chmod(0o755)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("book_dir", type=Path)
    preserve_coverage(parser.parse_args().book_dir)
