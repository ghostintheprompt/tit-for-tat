"""Regression test: every VULNERABLE_PLUGINS key must match a scanned plugin.

scan_plugins() detects a plugin folder name from its path (e.g. 'edit-flow')
and then checks `vuln_plugin in plugin_name` against each VULNERABLE_PLUGINS
key. If a key doesn't appear in any scanned folder name (as happened when the
key was 'editflow' but the folder is 'edit-flow'), that CVE check silently
never fires. This test fails loudly if the keys and the scanned folders drift
apart again.
"""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.cms import VULNERABLE_PLUGINS

# The plugin folders scan_plugins() probes (mirrors its plugin_paths list).
SCANNED_FOLDERS = [
    "edit-flow",
    "co-authors-plus",
    "advanced-custom-fields-pro",
    "custom-editorial-workflow",
]


class VulnKeyMatch(unittest.TestCase):
    def test_every_vuln_key_matches_a_scanned_folder(self):
        for key in VULNERABLE_PLUGINS:
            self.assertTrue(
                any(key in folder for folder in SCANNED_FOLDERS),
                f"VULNERABLE_PLUGINS key {key!r} matches no scanned plugin folder; "
                f"its CVE check can never fire",
            )

    def test_known_edit_flow_match_fires(self):
        # The exact case the bug broke: detected folder 'edit-flow' must match.
        matched = [k for k in VULNERABLE_PLUGINS if k in "edit-flow"]
        self.assertIn("edit-flow", matched)


if __name__ == "__main__":
    unittest.main(verbosity=2)
