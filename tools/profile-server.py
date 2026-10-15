#!/usr/bin/env python3
"""Capture a bounded development profile of an explicitly chosen process."""

import argparse
from pathlib import Path
import platform
import shutil
import subprocess


def command(system, pid, seconds, output):
    if system == "Darwin":
        return ["sample", str(pid), str(seconds), "-file", str(output)]
    if system == "Linux":
        return ["perf", "record", "-F", "99", "--call-graph", "dwarf",
                "-p", str(pid), "-o", str(output), "--", "sleep", str(seconds)]
    raise ValueError("Profiling is supported on Linux and macOS")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pid", type=int, required=True)
    parser.add_argument("--seconds", type=int, default=10, choices=range(1, 61))
    parser.add_argument("--output", type=Path, default=Path("reports/profile.out"))
    args = parser.parse_args()
    if args.pid <= 0:
        parser.error("pid must identify the development process you own")
    invocation = command(platform.system(), args.pid, args.seconds, args.output)
    if not shutil.which(invocation[0]):
        parser.error("required platform profiler is not installed")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    subprocess.run(invocation, check=True, timeout=args.seconds + 30)
    print(f"Profile saved locally to {args.output}; review for sensitive paths before sharing.")


if __name__ == "__main__":
    main()
