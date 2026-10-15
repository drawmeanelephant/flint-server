#!/usr/bin/env python3
"""Publish retained build/test timing data in the GitHub Actions summary."""

import json
import os
from pathlib import Path
import shlex

source = Path("reports/checks/timings.json")
if source.exists():
    rows = json.loads(source.read_text())
    lines = ["## Build and test evidence", "", "| Command | Seconds | Exit |", "| --- | ---: | ---: |"]
    for row in rows:
        command = shlex.join(row["command"]).replace("|", "\\|").replace("`", "'")
        lines.append(f"| `{command}` | {row['seconds']:.3f} | {row['exit_code']} |")
    lines += ["", "Full command logs and timings are retained in the checks artifact.", ""]
else:
    lines = ["## Build and test evidence", "", "No timing report was produced. Inspect setup-step failures.", ""]
summary = "\n".join(lines)
print(summary)
destination = os.environ.get("GITHUB_STEP_SUMMARY")
if destination:
    with open(destination, "a") as output:
        output.write(summary)
