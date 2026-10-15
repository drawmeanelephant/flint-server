#!/usr/bin/env python3
"""Run documented gates with bounded execution and durable timing evidence."""

import argparse
import json
import os
from pathlib import Path
import shlex
import signal
import subprocess
import sys
import time

import quality

ROOT = Path(__file__).resolve().parents[1]


def documented_commands(root):
    text = (root / "AGENTS.md").read_text()
    start = "<!-- validated-commands:start -->"
    end = "<!-- validated-commands:end -->"
    if text.count(start) != 1 or text.count(end) != 1:
        raise ValueError("AGENTS.md must have exactly one validated command section")
    section = text.split(start, 1)[1].split(end, 1)[0].strip()
    if not section.startswith("```sh\n") or not section.endswith("\n```"):
        raise ValueError("Validated commands must be a single sh code block")
    commands = [shlex.split(line) for line in section[6:-4].splitlines() if line.strip()]
    expected = [
        ["zig", "build"],
        ["zig", "build", "test", "--summary", "all"],
        ["python3", "tools/docs.py", "--check"],
        ["bash", "tools/sync-journey"],
        ["python3", "tools/tcp-smoke.py"],
    ]
    if commands != expected:
        raise ValueError("AGENTS.md command contract changed; update the gate and its tests together")
    return commands


def stop_group(process):
    def send(sig):
        try:
            os.killpg(process.pid, sig)
        except ProcessLookupError:
            pass
    send(signal.SIGTERM)
    try:
        return process.communicate(timeout=2)
    except subprocess.TimeoutExpired:
        send(signal.SIGKILL)
        return process.communicate()
    finally:
        # Also terminate descendants that detached their stdio or ignored TERM.
        send(signal.SIGKILL)


def run(command, report_dir, records, timeout=180):
    name = f"{len(records) + 1:02d}"
    started = time.monotonic()
    process = subprocess.Popen(command, cwd=ROOT, stdin=subprocess.DEVNULL,
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                               text=True, start_new_session=True)
    try:
        stdout, stderr = process.communicate(timeout=timeout)
        output = stdout + stderr
        code = process.returncode
    except subprocess.TimeoutExpired:
        stdout, stderr = stop_group(process)
        output, code = stdout + stderr + f"Command exceeded the {timeout}-second deadline.\n", 124
    except BaseException:
        stop_group(process)
        raise
    elapsed = round(time.monotonic() - started, 3)
    print(f"$ {shlex.join(command)}", flush=True)
    print(output, end="" if output.endswith("\n") else "\n", flush=True)
    print(f"exit={code} duration={elapsed:.3f}s", flush=True)
    (report_dir / f"{name}.log").write_text(output)
    records.append({"command": command, "exit_code": code, "seconds": elapsed, "log": f"{name}.log"})
    (report_dir / "timings.json").write_text(json.dumps(records, indent=2) + "\n")
    return code


def lint(report_dir, records):
    commands = [["zig", "fmt", "--check", "build.zig", "src", "tools/analyze.zig"]]
    commands += [["zig", "ast-check", str(path.relative_to(ROOT))]
                 for path in sorted(ROOT.glob("src/*.zig"))]
    commands += [["zig", "ast-check", "build.zig"], ["zig", "test", "tools/analyze.zig"]]
    commands += [[sys.executable, "tools/metrics.py", "--report", str(report_dir / "quality.json")]]
    commands += [[sys.executable, "-m", "compileall", "-q", "tools", ".devcontainer"]]
    failed = False
    for command in commands:
        failed |= run(command, report_dir, records) != 0
    errors = quality.check()
    for error in errors:
        print(error)
    return int(failed or bool(errors))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--lint-only", action="store_true")
    parser.add_argument("--repeat", type=int, default=1, choices=range(1, 11))
    parser.add_argument("--report-dir", type=Path, default=ROOT / "reports" / "checks")
    args = parser.parse_args()
    args.report_dir.mkdir(parents=True, exist_ok=True)
    records = []
    if args.lint_only:
        return lint(args.report_dir, records)

    try:
        commands = documented_commands(ROOT)
    except ValueError as error:
        print(error, file=sys.stderr)
        return 1
    tooling = [sys.executable, "-m", "unittest", "discover", "-s", "tools/tests", "-v"]
    if run(tooling, args.report_dir, records):
        return 1
    if lint(args.report_dir, records):
        return 1
    for command in commands:
        if run(command, args.report_dir, records):
            return 1
    # Each extra attempt directly executes tests, even if build results are cached.
    # Any failure exits nonzero immediately; successful retries never mask it.
    for _ in range(args.repeat - 1):
        if run(["zig", "test", "src/main.zig"], args.report_dir, records):
            return 1
    print(f"All checks passed; tests executed {args.repeat} time(s). Timings: {args.report_dir / 'timings.json'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
