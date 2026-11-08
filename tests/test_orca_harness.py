"""harvest.py / agent_exec.py wiring for the OrcaRouter provider and CLI entry points."""

from __future__ import annotations

import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import agent_exec  # noqa: E402
import harvest  # noqa: E402
import net_llm  # noqa: E402
import orca_auth  # noqa: E402
import orca_models  # noqa: E402
from tests.fake_openai_server import FakeServer  # noqa: E402

VALID_KEY = "sk-orca-test-valid-key-0001"


class EnvBase(unittest.TestCase):
    def setUp(self) -> None:
        self.srv = FakeServer().start()
        self.auth_srv = FakeServer().start()  # separate auth origin, like www vs api
        self.tmp = Path(tempfile.mkdtemp())
        self._patch = mock.patch.dict(
            os.environ,
            {
                "PI_MODELS_JSON": str(self.tmp / "models.json"),
                "ORCA_API_BASE_URL": self.srv.base,
                "ORCA_AUTH_BASE_URL": self.auth_srv.base,
                "PI_RECON_LLM_ROUTE": "public",
                "PI_RECON_LLM_PROVIDER": "orcarouter",
                "PI_RECON_LLM_KEY": VALID_KEY,
                "PI_RECON_ORCA_AUTH": "api_key",
            },
            clear=False,
        )
        self._patch.start()

    def tearDown(self) -> None:
        self._patch.stop()
        self.srv.stop()
        self.auth_srv.stop()


class ConnectCommandTest(EnvBase):
    def test_connect_command_lists_both_auth_choices(self):
        with mock.patch("builtins.print") as printed:
            rc = harvest.main(["--connect-orcarouter", "--no-prompt"])
        self.assertEqual(rc, 0)
        out = "\n".join(str(c.args[0]) for c in printed.call_args_list if c.args)
        lowered = out.lower()
        self.assertIn("api key", lowered)
        self.assertIn("--orca-auth pkce", out)
        self.assertNotIn(VALID_KEY, out)

    def test_missing_key_is_fatal_without_prompt(self):
        os.environ.pop("PI_RECON_LLM_KEY", None)
        with mock.patch("builtins.print"):
            rc = harvest.main(["--connect-orcarouter", "--no-prompt"])
        self.assertEqual(rc, 3)

    def test_catalog_command_prints_live_models(self):
        seen = {}

        def fake_catalog(api_url, key, **kw):
            seen["api_url"] = api_url
            return orca_models.fetch_catalog(api_url, key)

        with mock.patch("orca_models.discover_catalog", side_effect=fake_catalog), mock.patch("builtins.print") as printed:
            rc = harvest.main(["--orcarouter-catalog", "--no-prompt"])
        self.assertEqual(rc, 0)
        out = "\n".join(str(c.args[0]) for c in printed.call_args_list if c.args)
        self.assertIn("orcarouter/auto", out)
        self.assertIn("openai/gpt-5.5", out)
        self.assertNotIn("openai/gpt-image-1", out)
        self.assertEqual(seen["api_url"], self.srv.base + "/v1")

    def test_harvest_runs_with_pkce_credential(self):
        os.environ.pop("PI_RECON_LLM_KEY", None)
        os.environ["PI_RECON_ORCA_AUTH"] = "pkce"
        captured = {}

        def fake_setup(**kw):
            captured.update(kw)
            return VALID_KEY, "orcarouter/auto"

        with mock.patch.object(net_llm, "setup_orcarouter", side_effect=fake_setup), mock.patch.object(
            harvest, "list_challenges", return_value=[]
        ), mock.patch("builtins.print"):
            rc = harvest.main(["--only", "a-05"])
        self.assertEqual(rc, 0)
        self.assertEqual(captured["auth"], "pkce")
        self.assertTrue(captured["prompt_key"])

    def test_default_model_is_orcarouter_auto_and_cyber_choice_is_named(self):
        seen = {}

        def fake_setup(**kw):
            seen.update(kw)
            return VALID_KEY, "orcarouter/auto"

        with mock.patch.object(net_llm, "setup_orcarouter", side_effect=fake_setup), mock.patch.object(
            harvest, "list_challenges", return_value=[]
        ), mock.patch("builtins.print"):
            rc = harvest.main(["--provider", "orcarouter", "--only", "a-05"])
            self.assertEqual(rc, 0)
            self.assertIsNone(seen["model"], "no deepseek id passed as the OrcaRouter default")
            seen.clear()
            rc = harvest.main(
                ["--provider", "orcarouter", "--orcarouter-model", "orcacyber-ultra-1.0", "--only", "a-05"]
            )
        self.assertEqual(rc, 0)
        self.assertEqual(seen["model"], "orcacyber-ultra-1.0")


class AuthErrorDetectionTest(unittest.TestCase):
    def _log(self, text: str) -> Path:
        p = Path(tempfile.mkdtemp()) / "agent.out"
        p.write_text(text, encoding="utf-8")
        return p

    def test_detects_relay_401(self):
        self.assertTrue(agent_exec.auth_error_seen(self._log("Error: 401 Unauthorized: invalid api key")))
        self.assertTrue(agent_exec.auth_error_seen(self._log('{"error":{"message":"Incorrect API key provided"}}')))
        self.assertFalse(agent_exec.auth_error_seen(self._log("Error: Connection error")))

    def test_keep_flag_only_for_orcarouter(self):
        route_env = {}
        for provider in ("orcarouter", "deepseek"):
            route_env[provider] = (
                (os.environ.get("PI_RECON_ORCA_KEEP") or "").strip() == "1"
                and str(provider).strip().lower() == "orcarouter"
            )
        self.assertFalse(route_env["deepseek"])


if __name__ == "__main__":
    unittest.main()


class PkceFlowFromEnvTest(EnvBase):
    def test_scope_env_selects_oob_flow(self):
        os.environ.pop("PI_RECON_LLM_KEY", None)
        os.environ["PI_RECON_ORCA_AUTH"] = "pkce"
        os.environ["PI_RECON_ORCA_SCOPE"] = "oob"
        seen = {}

        def fake_resolve(**kw):
            seen["flow"] = kw["pkce"].flow
            return orca_auth.OrcaCredential(key=VALID_KEY, source="pkce")

        with mock.patch("orca_auth.resolve_credential", side_effect=fake_resolve):
            net_llm.setup_orcarouter(auth="pkce", diagnose=False)
        self.assertEqual(seen["flow"], "oob")
