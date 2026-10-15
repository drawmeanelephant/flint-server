#!/usr/bin/env python3
"""Build all supported targets and create checksummed release archives."""

import argparse
import hashlib
from pathlib import Path
import re
import subprocess
import tarfile

ROOT = Path(__file__).resolve().parents[1]
TARGETS = ("x86_64-linux", "aarch64-linux", "aarch64-macos", "x86_64-macos")


def validate_tag(tag, manifest):
    match = re.search(r'\.version\s*=\s*"(\d+\.\d+\.\d+)"', manifest)
    if not match or tag != "v" + match[1]:
        raise ValueError("Release tag must be vX.Y.Z and match build.zig.zon")
    return tag


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tag", required=True)
    args = parser.parse_args()
    tag = validate_tag(args.tag, (ROOT / "build.zig.zon").read_text())
    output = ROOT / "reports/release"
    output.mkdir(parents=True, exist_ok=True)
    checksums = []
    for target in TARGETS:
        prefix = output / "build" / target
        subprocess.run(["zig", "build", "-Dtarget=" + target, "-Doptimize=safe",
                        "--prefix", str(prefix)], cwd=ROOT, check=True, timeout=180)
        archive = output / f"flintd-{tag}-{target}.tar.gz"
        with tarfile.open(archive, "w:gz") as bundle:
            bundle.add(prefix / "bin/flintd", arcname="flintd")
            for name in ("LICENSE", "README.md", "SECURITY.md", "AGENTS.md",
                         "CONTRIBUTING.md", ".env.example", "docs",
                         "tools/healthcheck.py", "tools/profile-server.py"):
                bundle.add(ROOT / name, arcname=name)
        checksums.append(hashlib.sha256(archive.read_bytes()).hexdigest() + "  " + archive.name)
    (output / "SHA256SUMS").write_text("\n".join(checksums) + "\n")
    print(f"Packaged {len(TARGETS)} targets with SHA256SUMS in {output}")


if __name__ == "__main__":
    main()
