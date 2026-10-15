#!/usr/bin/env python3
"""Enforce an AST-based branch budget and retain per-function quality metrics."""

import argparse
import json
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[1]
MAX_COMPLEXITY = 50


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", type=Path, default=ROOT / "reports/quality.json")
    args = parser.parse_args()
    paths = ["build.zig"] + [str(path.relative_to(ROOT)) for path in sorted(ROOT.glob("src/*.zig"))]
    result = subprocess.run(["zig", "run", "tools/analyze.zig", "--", *paths],
                            cwd=ROOT, capture_output=True, text=True, check=True, timeout=120)
    functions = []
    for line in result.stdout.splitlines():
        path, name, count = line.rsplit("\t", 2)
        functions.append({"path": path, "function": name, "complexity": int(count)})
    if not functions:
        raise RuntimeError("AST analyzer reported no functions")
    functions.sort(key=lambda row: (-row["complexity"], row["path"], row["function"]))
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps({"max_allowed": MAX_COMPLEXITY, "functions": functions}, indent=2) + "\n")
    failed = False
    for row in functions:
        if row["complexity"] > MAX_COMPLEXITY:
            print(f"{row['path']}:{row['function']}: complexity {row['complexity']} exceeds {MAX_COMPLEXITY}")
            failed = True
    print(f"Analyzed {len(functions)} functions; maximum complexity {functions[0]['complexity']}/{MAX_COMPLEXITY}.")
    return int(failed)


if __name__ == "__main__":
    raise SystemExit(main())
