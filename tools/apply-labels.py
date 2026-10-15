#!/usr/bin/env python3
"""Apply label definitions. Run only with explicit repository-admin approval."""

import json
from pathlib import Path
import subprocess

root = Path(__file__).resolve().parents[1]
for label in json.loads((root / ".github/labels.json").read_text()):
    subprocess.run([
        "gh", "label", "create", label["name"], "--force",
        "--color", label["color"], "--description", label["description"],
    ], cwd=root, check=True)
