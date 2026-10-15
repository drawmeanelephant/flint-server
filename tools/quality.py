#!/usr/bin/env python3
"""Dependency-free repository policy checks, also used by the staged hook."""

from pathlib import Path
import os
import re
import subprocess

ROOT = Path(__file__).resolve().parents[1]
MAX_BYTES = 1_048_576
MAX_SOURCE_LINES = 1_000
CLONE_LINES = 40
DEBT = re.compile(r"\b(?:TODO|FIXME|HACK)\b")
ISSUE = re.compile(r"\(#\d+\)|https://github\.com/[^/\s]+/[^/\s]+/issues/\d+")
ZIG_TOKENS = re.compile(
    r'//[^\n]*|\\\\[^\n]*|@"(?:\\.|[^"\\])*"|"(?:\\.|[^"\\])*"|'
    r"'(?:\\.|[^'\\])*'|[A-Za-z_]\w*|\S"
)


def tracked_files(root):
    result = subprocess.run(
        ["git", "ls-files", "-z", "--cached", "--others", "--exclude-standard"],
        cwd=root, capture_output=True, check=False,
    )
    if result.returncode == 0:
        return sorted({root / name for name in result.stdout.decode().split("\0") if name})
    # A staged-snapshot hook deliberately runs without .git metadata.
    excluded = {".git", ".zig-cache", "zig-cache", "zig-out", "reports", "__pycache__", ".venv"}
    paths = []
    for directory, directories, files in os.walk(root):
        directories[:] = sorted(name for name in directories if name not in excluded)
        paths.extend(Path(directory) / name for name in files)
    return sorted(paths)


def source_findings(path, text):
    findings = []
    lines = text.splitlines()
    if len(lines) > MAX_SOURCE_LINES:
        findings.append(f"{path}: {len(lines)} lines exceeds {MAX_SOURCE_LINES}")
    for match in ZIG_TOKENS.finditer(text):
        comment = match[0]
        if comment.startswith("//") and DEBT.search(comment) and not ISSUE.search(comment):
            number = text.count("\n", 0, match.start()) + 1
            findings.append(f"{path}:{number}: debt marker must link an issue")
    return findings


def duplicate_blocks(sources):
    """Flag exact 40-significant-line clones, not merely similar syntax."""
    seen = {}
    findings = []
    reported = set()
    for path, text in sources:
        lines = [
            (number, line.strip())
            for number, line in enumerate(text.splitlines(), 1)
            if line.strip() and not line.lstrip().startswith("//")
        ]
        for index in range(len(lines) - CLONE_LINES + 1):
            block = tuple(line for _, line in lines[index:index + CLONE_LINES])
            current = (str(path), lines[index][0])
            first = seen.get(block)
            if first:
                # One diagnostic per pair of files, including same-file clones.
                pair = (first[0], current[0])
                if pair not in reported:
                    findings.append(f"{current[0]}:{current[1]}: exact {CLONE_LINES}-line clone of {first[0]}:{first[1]}")
                    reported.add(pair)
            else:
                seen[block] = current
    return findings


def zig_string(literal):
    """Decode Zig string/quoted-identifier escapes, not JSON or Python escapes."""
    text = literal[1:-1]
    result = bytearray()
    index = 0
    escapes = {"n": b"\n", "r": b"\r", "t": b"\t", "\\": b"\\", '"': b'"', "'": b"'"}
    while index < len(text):
        if text[index] != "\\":
            result.extend(text[index].encode())
            index += 1
            continue
        index += 1
        escape = text[index]
        index += 1
        if escape in escapes:
            result.extend(escapes[escape])
        elif escape == "x":
            result.append(int(text[index:index + 2], 16))
            index += 2
        elif escape == "u" and text[index] == "{":
            end = text.index("}", index)
            result.extend(chr(int(text[index + 1:end], 16)).encode())
            index = end + 1
        else:
            raise ValueError("Unsupported Zig string escape")
    return result.decode("utf-8", errors="surrogateescape")


def dependency_findings(manifest, build):
    """Compare declared Zig dependency names with build graph references."""
    tokens = [match[0] for match in ZIG_TOKENS.finditer(manifest)
              if not match[0].startswith("//")]
    start = next((i + 5 for i in range(len(tokens) - 4)
                  if tokens[i:i + 5] == [".", "dependencies", "=", ".", "{"]), None)
    if start is None:
        return ["build.zig.zon: cannot locate dependencies"]
    declared = set()
    depth = 1
    for index in range(start, len(tokens)):
        token = tokens[index]
        if depth == 1 and token == "." and index + 2 < len(tokens) and tokens[index + 2] == "=":
            name = tokens[index + 1]
            declared.add(zig_string(name[1:]) if name.startswith('@"') else name)
        depth += (token == "{") - (token == "}")
        if depth == 0:
            break
    else:
        return ["build.zig.zon: unterminated dependency block"]
    tokens = [match[0] for match in ZIG_TOKENS.finditer(build)
              if not match[0].startswith("//")]
    used = set()
    for index in range(len(tokens) - 3):
        if tokens[index] == "." and tokens[index + 1] in {"dependency", "lazyDependency"} and tokens[index + 2] == "(":
            if not tokens[index + 3].startswith('"'):
                return ["build.zig: dependency names must be string literals for usage validation"]
            used.add(zig_string(tokens[index + 3]))
    return [f"build.zig.zon: unused dependency {name}" for name in sorted(declared - used)]


def check(root=ROOT):
    findings = []
    sources = []
    for path in tracked_files(root):
        if path.is_symlink():
            findings.append(f"{path.relative_to(root)}: tracked symlinks require an explicit policy review")
            continue
        if not path.is_file():
            continue
        relative = path.relative_to(root)
        if path.stat().st_size > MAX_BYTES:
            findings.append(f"{relative}: file exceeds {MAX_BYTES} bytes")
            continue
        if path.suffix == ".zig":
            text = path.read_text()
            sources.append((relative, text))
            findings.extend(source_findings(relative, text))
    findings.extend(duplicate_blocks(sources))
    findings.extend(dependency_findings(
        (root / "build.zig.zon").read_text(),
        (root / "build.zig").read_text(),
    ))
    return findings


if __name__ == "__main__":
    errors = check()
    for error in errors:
        print(error)
    if not errors:
        print("Repository policies passed (file limits, linked debt, exact clones, dependency usage).")
    raise SystemExit(bool(errors))
