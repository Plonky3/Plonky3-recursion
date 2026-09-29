#!/usr/bin/env python3
"""Set the shared RC version without reformatting unrelated manifest content."""

from pathlib import Path
import re
import sys
import tomllib


def replace_one(section: str, pattern: str, version: str, label: str) -> str:
    updated, count = re.subn(
        pattern,
        lambda match: f'{match.group(1)}{version}{match.group(2)}',
        section,
        count=1,
        flags=re.MULTILINE,
    )
    if count != 1:
        raise ValueError(f"could not find a single-line version for {label}")
    return updated


def replace_section(text: str, name: str, update) -> str:
    header = re.search(rf"(?m)^\[{re.escape(name)}\]\s*(?:#.*)?$", text)
    if header is None:
        raise ValueError(f"missing [{name}]")
    next_header = re.search(r"(?m)^\[", text[header.end() :])
    end = header.end() + next_header.start() if next_header else len(text)
    return text[: header.end()] + update(text[header.end() : end]) + text[end:]


def set_version(manifest_path: Path, version: str) -> None:
    original = manifest_path.read_text()
    parsed = tomllib.loads(original)
    workspace = parsed["workspace"]
    members = {(manifest_path.parent / member).resolve() for member in workspace["members"]}
    local_deps = {
        name
        for name, definition in workspace["dependencies"].items()
        if isinstance(definition, dict)
        and "path" in definition
        and (manifest_path.parent / definition["path"]).resolve() in members
    }

    updated = replace_section(
        original,
        "workspace.package",
        lambda section: replace_one(
            section, r'^(\s*version\s*=\s*")[^"]+("[^\n]*)$', version, "workspace.package"
        ),
    )

    def update_dependencies(section: str) -> str:
        for name in sorted(local_deps):
            section = replace_one(
                section,
                rf'^(\s*{re.escape(name)}\s*=\s*\{{[^\n]*?\bversion\s*=\s*")[^"]+("[^\n]*)$',
                version,
                name,
            )
        return section

    updated = replace_section(updated, "workspace.dependencies", update_dependencies)
    check = tomllib.loads(updated)
    assert check["workspace"]["package"]["version"] == version
    assert all(check["workspace"]["dependencies"][name]["version"] == version for name in local_deps)
    manifest_path.write_text(updated)


if __name__ == "__main__":
    if len(sys.argv) != 3:
        raise SystemExit("usage: set_release_candidate.py Cargo.toml VERSION")
    set_version(Path(sys.argv[1]), sys.argv[2])
