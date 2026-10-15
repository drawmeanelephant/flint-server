from pathlib import Path
import os
import signal
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import quality
import check


class QualityTests(unittest.TestCase):
    def test_debt_requires_issue(self):
        self.assertTrue(quality.source_findings("x.zig", "// TODO: fix"))
        self.assertFalse(quality.source_findings("x.zig", "// TODO(#123): fix"))
        self.assertFalse(quality.source_findings("x.zig", '// FIXME https://github.com/a/b/issues/7'))
        self.assertFalse(quality.source_findings("x.zig", 'const marker = "TODO";'))
        self.assertTrue(quality.source_findings("x.zig", "const x = 1; // TODO: fix"))
        self.assertFalse(quality.source_findings("x.zig", 'const marker = "// TODO: literal";'))

    def test_source_limit(self):
        self.assertTrue(quality.source_findings("x.zig", "x\n" * 1001))
        self.assertFalse(quality.source_findings("x.zig", "x\n" * 1000))

    def test_exact_clone_detection(self):
        source = "\n".join(f"const field_{i} = {i};" for i in range(40))
        self.assertEqual(len(quality.duplicate_blocks([("a.zig", source), ("b.zig", source)])), 1)
        self.assertFalse(quality.duplicate_blocks([("a.zig", source)]))

    def test_unused_dependencies(self):
        manifest = '.{ .dependencies = .{ .unused = .{ .url = "x", .hash = "y" }, .used = .{ .path = "x" } } }'
        self.assertEqual(quality.dependency_findings(manifest, 'b.dependency("used", .{})'), [
            "build.zig.zon: unused dependency unused",
        ])
        self.assertFalse(quality.dependency_findings('.{ .dependencies = .{} }', ""))
        self.assertFalse(quality.dependency_findings(
            '.{ .dependencies = .{ .used = .{ .path = "x" } } }',
            'b.lazyDependency("used", .{})',
        ))
        self.assertEqual(quality.dependency_findings(
            '.{ .dependencies = .{ .@"some-dep" = .{ .hash = "}", .url = "x" } } }',
            '// b.dependency("some-dep", .{})',
        ), ["build.zig.zon: unused dependency some-dep"])
        self.assertFalse(quality.dependency_findings(
            '.{ .dependencies = .{ .@"some-dep" = .{ .path = "x" } } }',
            'b.dependency("some-dep", .{})',
        ))

    def test_documented_commands_are_executable_contract(self):
        self.assertEqual(len(check.documented_commands(quality.ROOT)), 5)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "AGENTS.md").write_text("# Missing command contract")
            with self.assertRaises(ValueError):
                check.documented_commands(root)

    def test_zig_specific_literal_escapes(self):
        self.assertEqual(quality.zig_string(r'"\x66oo"'), "foo")
        self.assertEqual(quality.zig_string(r'"\u{66}oo"'), "foo")
        self.assertEqual(quality.zig_string(r'"\xc3\xa9"'), "é")
        self.assertFalse(quality.dependency_findings(
            r'.{ .dependencies = .{ .@"\x66oo" = .{ .path = "x" } } }',
            r'b.dependency("\u{66}oo", .{})',
        ))

    def test_snapshot_prunes_generated_directories(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            cache = root / ".zig-cache"
            cache.mkdir()
            (cache / "generated").write_text("not source")
            (root / "main.zig").write_text("")
            visited = []
            walk = os.walk

            def observe(*args):
                for entry in walk(*args):
                    visited.append(entry[0])
                    yield entry

            with patch.object(quality.subprocess, "run", return_value=SimpleNamespace(returncode=1)):
                with patch.object(quality.os, "walk", side_effect=observe):
                    self.assertEqual(quality.tracked_files(root), [root / "main.zig"])
            self.assertNotIn(str(cache), visited)

    def test_timeout_terminates_descendants(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            pid_file = root / "child.pid"
            script = (
                "import pathlib,subprocess,sys,time; "
                "child=subprocess.Popen([sys.executable,'-c','import time; time.sleep(30)']); "
                f"pathlib.Path({str(pid_file)!r}).write_text(str(child.pid)); time.sleep(30)"
            )
            try:
                self.assertEqual(check.run([sys.executable, "-c", script], root, [], timeout=1), 124)
                pid = int(pid_file.read_text())
                status = subprocess.run(["ps", "-o", "stat=", "-p", str(pid)], capture_output=True, text=True)
                self.assertTrue(not status.stdout.strip() or status.stdout.strip().startswith("Z"))
            finally:
                if pid_file.exists():
                    try:
                        os.kill(int(pid_file.read_text()), signal.SIGKILL)
                    except ProcessLookupError:
                        pass


if __name__ == "__main__":
    unittest.main()
