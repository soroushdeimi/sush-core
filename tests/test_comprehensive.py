#!/usr/bin/env python3
"""Documentation and packaging alignment tests for sushCore."""

import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class DocumentationTests(unittest.TestCase):
    def test_readme_highlights_cli(self):
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        self.assertTrue(readme.startswith("# sushCore"))
        self.assertIn("python sush_cli.py proxy", readme)
        self.assertIn("python tests/test_smoke.py", readme)

    def test_architecture_mentions_layers(self):
        architecture = (ROOT / "ARCHITECTURE.md").read_text(encoding="utf-8")
        self.assertIn("Control Layer", architecture)
        self.assertIn("Transport Layer", architecture)


class PackagingTests(unittest.TestCase):
    def test_setup_points_to_sush_namespace(self):
        setup = (ROOT / "setup.py").read_text(encoding="utf-8")
        # Check with flexible quotes
        self.assertTrue(
            "packages=find_packages(include=['sush', 'sush.*'])" in setup
            or 'packages=find_packages(include=["sush", "sush.*"])' in setup
        )
        self.assertIn('"sush": ["config/*.conf"]', setup)

    def test_cli_imports_sush_client(self):
        cli = (ROOT / "sush_cli.py").read_text(encoding="utf-8")
        # Allow combined import
        self.assertTrue(
            "from sush.client import SushClient" in cli
            or "from sush.client import ClientConfig, SushClient" in cli
        )


if __name__ == "__main__":
    unittest.main()
