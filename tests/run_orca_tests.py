#!/usr/bin/env python3
"""OrcaRouter provider test runner.

Usage:
    python3 tests/run_orca_tests.py            # every OrcaRouter test
    python3 tests/run_orca_tests.py pkce       # one group: provider|api_key|pkce|catalog|capabilities|errors

Groups map to whole test classes; the offline tests start a local fake gateway
and never touch the network, so no credentials are needed.
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

GROUPS = {
    "provider": ["tests.test_orca_provider.ProviderEntryTest"],
    "api_key": ["tests.test_orca_provider.ApiKeyAdapterTest"],
    "catalog": ["tests.test_orca_provider.CatalogTest"],
    "capabilities": ["tests.test_orca_provider.SelectorOptionsTest"],
    "errors": ["tests.test_orca_provider.ErrorPathTest", "tests.test_orca_harness.AuthErrorDetectionTest"],
    "pkce": ["tests.test_orca_pkce"],
    "harness": ["tests.test_orca_harness"],
}
DEFAULT_GROUPS = ["provider", "api_key", "catalog", "capabilities", "errors", "pkce", "harness"]


def main(argv: list[str]) -> int:
    names = [a for a in argv if not a.startswith("-")] or DEFAULT_GROUPS
    unknown = [n for n in names if n not in GROUPS]
    if unknown:
        print(f"unknown group(s): {', '.join(unknown)}; choose from {', '.join(GROUPS)}", file=sys.stderr)
        return 2
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    for name in names:
        for target in GROUPS[name]:
            suite.addTests(loader.loadTestsFromName(target))
    result = unittest.TextTestRunner(verbosity=1).run(suite)
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
