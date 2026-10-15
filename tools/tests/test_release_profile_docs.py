import importlib.util
import json
from pathlib import Path
import sys
import unittest

TOOLS = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(TOOLS))
import docs

profile_spec = importlib.util.spec_from_file_location("profile_server", TOOLS / "profile-server.py")
profile = importlib.util.module_from_spec(profile_spec)
profile_spec.loader.exec_module(profile)

spec = importlib.util.spec_from_file_location("package_release", TOOLS / "package-release.py")
release = importlib.util.module_from_spec(spec)
spec.loader.exec_module(release)


class ReleaseProfileDocsTests(unittest.TestCase):
    def test_release_version_must_match_manifest(self):
        manifest = '.{ .version = "0.1.0" }'
        self.assertEqual(release.validate_tag("v0.1.0", manifest), "v0.1.0")
        for tag in ("v0.2.0", "v0.1.0;command", "0.1.0", "v../"):
            with self.assertRaises(ValueError):
                release.validate_tag(tag, manifest)

    def test_profiles_are_bounded_platform_commands(self):
        self.assertEqual(profile.command("Darwin", 123, 2, Path("out")),
                         ["sample", "123", "2", "-file", "out"])
        self.assertIn("--call-graph", profile.command("Linux", 123, 2, Path("out")))
        with self.assertRaises(ValueError):
            profile.command("unknown", 123, 2, Path("out"))

    def test_generated_reference_and_local_links(self):
        schema = json.loads((docs.ROOT / "docs/flint-sync.schema.json").read_text())
        generated = docs.render(schema)
        self.assertEqual(generated, (docs.ROOT / "docs/protocol-reference.md").read_text())
        self.assertFalse(docs.broken_links(docs.ROOT))
        self.assertEqual(set(docs.OPERATIONS), set(
            item["$ref"].rsplit("/", 1)[1]
            for item in schema["$defs"]["request"]["allOf"][1]["oneOf"]
        ))
        self.assertEqual(schema["$defs"]["open"]["required"], ["op"])
        self.assertEqual(schema["$defs"]["open"]["anyOf"][1]["required"], ["name"])
        self.assertEqual(schema["$defs"]["open"]["anyOf"][1]["not"], {"required": ["stream"]})


if __name__ == "__main__":
    unittest.main()
