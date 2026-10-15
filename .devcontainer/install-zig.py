"""Install a fixed official Zig release, verifying its published SHA-256."""

import hashlib
import json
from pathlib import Path
import platform
import subprocess
import sys
import tempfile
import urllib.parse
import urllib.request

version = sys.argv[1]
architecture = {"x86_64": "x86_64", "aarch64": "aarch64"}[platform.machine()]
with urllib.request.urlopen("https://ziglang.org/download/index.json", timeout=30) as response:
    release = json.load(response)[version][architecture + "-linux"]
url = urllib.parse.urlparse(release["tarball"])
if url.scheme != "https" or url.netloc != "ziglang.org":
    raise SystemExit("Unexpected Zig download origin")
with tempfile.TemporaryDirectory() as temporary:
    archive = Path(temporary) / "zig.tar.xz"
    digest = hashlib.sha256()
    with urllib.request.urlopen(url.geturl(), timeout=120) as response, archive.open("wb") as output:
        while block := response.read(1024 * 1024):
            digest.update(block)
            output.write(block)
    if digest.hexdigest() != release["shasum"]:
        raise SystemExit("Zig archive checksum mismatch")
    Path("/opt/zig").mkdir()
    subprocess.run(["tar", "-xf", str(archive), "--strip-components=1", "-C", "/opt/zig"], check=True)
