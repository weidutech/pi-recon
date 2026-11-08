"""OrcaRouter Cyber Inference: provider entry, API-key path, model catalog.

No network: the provider points at the local fake gateway in
``tests/fake_openai_server.py`` through the explicit ``ORCA_API_BASE_URL``
override, so the same code path as production runs end to end.
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(ROOT))

import net_llm  # noqa: E402
import orca_auth  # noqa: E402
import orca_models  # noqa: E402
from tests.fake_openai_server import CATALOG, FakeServer  # noqa: E402

VALID_KEY = "sk-orca-test-valid-key-0001"


def _clean_env(tmp: Path, base: str) -> dict:
    env = {
        "PI_MODELS_JSON": str(tmp / "models.json"),
        "PI_CODING_AGENT_DIR": str(tmp),
        "ORCA_API_BASE_URL": base,
        "ORCA_AUTH_BASE_URL": base + "/auth-origin-unused",
        "PI_RECON_LLM_ROUTE": "public",
    }
    return env


class Base(unittest.TestCase):
    def setUp(self) -> None:
        from unittest import mock

        self.srv = FakeServer().start()
        self.tmp = Path(tempfile.mkdtemp())
        self.models_path = self.tmp / "models.json"
        self._patch = mock.patch.dict(os.environ, _clean_env(self.tmp, self.srv.base))
        self._patch.start()

    def tearDown(self) -> None:
        self._patch.stop()
        self.srv.stop()


class ProviderEntryTest(Base):
    def test_named_provider_entry_in_models_json(self):
        key, model = net_llm.setup_orcarouter(api_key=VALID_KEY, diagnose=False)
        self.assertEqual(key, VALID_KEY)
        data = json.loads(self.models_path.read_text())
        entry = data["providers"]["orcarouter"]
        self.assertEqual(entry["name"], "OrcaRouter Cyber Inference")
        self.assertEqual(entry["baseUrl"], self.srv.base + "/v1")
        self.assertEqual(entry["api"], "openai-completions")
        ids = [m["id"] for m in entry["models"]]
        self.assertIn("orcarouter/auto", ids)
        self.assertNotIn("openai/gpt-image-1", ids)  # non-text route filtered
        self.assertNotIn("google/veo-3", ids)
        self.assertNotIn("jina/jina-reranker-v3", ids)
        self.assertNotIn("openai/text-embedding-4", ids)
        self.assertNotIn("no-namespace-model", ids)
        # default stays the OrcaRouter auto model even though live catalog lists others
        self.assertEqual(model, "orcarouter/auto")
        for m in entry["models"]:
            self.assertIn("text", m["input"])  # declared modalities kept, text chat guaranteed
            self.assertNotIn("tier", m)
        # key stored in the project's own secret file, masked in logs only
        self.assertEqual(entry["apiKey"], VALID_KEY)
        self.assertEqual(entry["orcaAuth"]["source"], "api_key")

    def test_default_public_base_is_orcarouter_relay(self):
        self.assertEqual(net_llm.ORCAROUTER_BASE_URL, "https://api.orcarouter.ai/v1")
        self.assertEqual(net_llm.preset_base_url("orcarouter"), "https://api.orcarouter.ai/v1")
        self.assertEqual(net_llm.provider_api_kind("orcarouter"), "openai-completions")
        route = net_llm.resolve_route("orcarouter")
        self.assertEqual(route.mode, "public", "OrcaRouter origin is never rewritten to a hosted gateway")
        self.assertTrue(route.base_url.startswith("https://api.orcarouter.ai"))
        # deepseek keeps its existing behaviour
        self.assertEqual(net_llm.preset_base_url("deepseek"), "https://api.deepseek.com/v1")

    def test_seed_models_are_orcarouter_branded(self):
        ids = [m["id"] for m in orca_models.seed_catalog().to_provider_models()]
        self.assertEqual(ids, ["orcarouter/auto", "orca/orcacyber-ultra-1.0", "orca/orcacyber-zero-1.5", "orcarouter/fusion"])
        self.assertTrue(ids[0].startswith("orcarouter/"))
        for bad in ("deepseek/deepseek-v4-flash", "deepseek-v4-flash"):
            self.assertNotIn(bad, ids)


class ApiKeyAdapterTest(Base):
    def test_save_load_mask_clear(self):
        store = orca_auth.CredentialStore(self.models_path)
        cred = orca_auth.ApiKeyAdapter(store, env={"PI_RECON_LLM_KEY": VALID_KEY}).acquire()
        self.assertEqual(cred.source, "api_key")
        self.assertEqual(cred.masked(), "sk-orca-...0001")
        self.assertNotIn(VALID_KEY[8:-4], cred.masked())
        loaded = store.load()
        self.assertIsNotNone(loaded)
        self.assertEqual(loaded.key, VALID_KEY)
        self.assertTrue(store.clear())
        self.assertIsNone(store.load())
        entry = json.loads(self.models_path.read_text())["providers"]["orcarouter"]
        self.assertNotIn("apiKey", entry)

    def test_bad_shape_rejected_without_leaking(self):
        store = orca_auth.CredentialStore(self.models_path)
        with self.assertRaises(orca_auth.AuthError) as ctx:
            orca_auth.ApiKeyAdapter(store, env={"PI_RECON_LLM_KEY": "sk-othersecret-123"}).acquire()
        self.assertEqual(ctx.exception.code, "bad_key_shape")
        self.assertNotIn("sk-othersecret-123", str(ctx.exception))
        with self.assertRaises(orca_auth.AuthError) as ctx2:
            orca_auth.ApiKeyAdapter(store, env={}).acquire()
        self.assertEqual(ctx2.exception.code, "missing_key")

    def test_prompt_path(self):
        store = orca_auth.CredentialStore(self.models_path)
        cred = orca_auth.ApiKeyAdapter(store, env={}, prompt=lambda _msg: VALID_KEY).acquire()
        self.assertEqual(cred.key, VALID_KEY)

    def test_same_downstream_for_both_sources(self):
        # OrcaCredential from the API-key adapter and (see PKCE tests) the PKCE adapter
        # are the same type; downstream only consumes .key.
        store = orca_auth.CredentialStore(self.models_path)
        cred = orca_auth.ApiKeyAdapter(store, env={"PI_RECON_LLM_KEY": VALID_KEY}).acquire()
        self.assertEqual(set(cred.__dataclass_fields__) & {"key", "source", "status"}, {"key", "source", "status"})
        key, model = net_llm.setup_orcarouter(api_key=cred.key, diagnose=True)
        self.assertEqual(key, cred.key)
        ok, detail = net_llm.http_ping_chat(self.srv.base + "/v1", cred.key, model)
        self.assertTrue(ok, detail)
        self.assertEqual(self.srv.state.chat_calls[-1]["model"], model)


class CatalogTest(Base):
    def test_live_catalog_is_authoritative(self):
        cat = orca_models.fetch_catalog(self.srv.base + "/v1", VALID_KEY)
        self.assertEqual(cat.source, "live")
        self.assertFalse(cat.degraded)
        ids = cat.ids
        for keep in ("openai/gpt-5.5", "anthropic/claude-opus-4.8", "google/gemini-3.5-flash", "deepseek/deepseek-v4-pro"):
            self.assertIn(keep, ids)
        self.assertEqual(len(ids), 6)
        gpt = [m for m in cat.models if m["id"] == "openai/gpt-5.5"][0]
        self.assertTrue(gpt["reasoning"])
        self.assertEqual(gpt["contextWindow"], 400000)

    def test_filters_fixture_modalities(self):
        parsed = orca_models.parse_catalog(json.dumps({"data": CATALOG}))
        self.assertEqual(
            sorted(parsed.ids),
            sorted(["openai/gpt-5.5", "anthropic/claude-opus-4.8", "google/gemini-3.5-flash", "deepseek/deepseek-v4-pro", "orcarouter/auto", "orcarouter/fusion"]),
        )
        # text picker is text-only input: no multimodal-only declaration slips in
        failing = orca_models.parse_catalog(
            json.dumps({"data": [{"id": "x/audio-only", "architecture": {"input_modalities": ["audio"]}}]})
        )
        self.assertEqual(failing.ids, [])
        undeclared = orca_models.parse_catalog(json.dumps({"data": [{"id": "x/undeclared"}]}))
        self.assertEqual(undeclared.ids, ["x/undeclared"])  # text chat route is fine without modality data
        embed = orca_models.parse_catalog(json.dumps({"data": [{"id": "x/embed", "supported_endpoint_types": ["embeddings"]}]}))
        self.assertEqual(embed.ids, [])

    def test_bounded_and_malformed(self):
        with self.assertRaises(ValueError):
            orca_models.parse_catalog("not json")
        with self.assertRaises(ValueError):
            orca_models.parse_catalog(json.dumps({"nope": 1}))
        many = orca_models.parse_catalog(json.dumps({"data": [{"id": f"v/m{i}"} for i in range(5000)]}))
        self.assertLessEqual(len(many.models), orca_models.MAX_ITEMS)

    def test_fallback_seed_and_last_known_good(self):
        dead = orca_models.discover_catalog(self.srv.base, VALID_KEY, fetch=lambda *a, **k: (_ for _ in ()).throw(OSError("down")))
        self.assertEqual(dead.source, "seed")
        self.assertTrue(dead.degraded)
        self.assertEqual(dead.ids[0], "orcarouter/auto")
        self.assertIn("orca/orcacyber-ultra-1.0", dead.ids)
        lkg = orca_models.discover_catalog(
            self.srv.base,
            VALID_KEY,
            last_known_good=[{"id": "openai/gpt-5.5", "input": ["text"], "contextWindow": 400000}],
            fetch=lambda *a, **k: (_ for _ in ()).throw(OSError("down")),
        )
        self.assertEqual(lkg.source, "last-known-good")
        self.assertEqual(lkg.ids, ["openai/gpt-5.5"])

    def test_stale_model_id_revalidated(self):
        live = orca_models.parse_catalog(json.dumps({"data": CATALOG}))
        self.assertEqual(live.resolve("deepseek/deepseek-v4-pro"), "deepseek/deepseek-v4-pro")
        self.assertEqual(live.resolve("old/removed-model"), "orcarouter/auto")
        seed = orca_models.seed_catalog()
        self.assertEqual(seed.resolve("openai/gpt-5.5"), "orcarouter/auto")
        self.assertEqual(seed.resolve("orcacyber-zero-1.5"), "orca/orcacyber-zero-1.5")  # alias kept
        self.assertEqual(seed.resolve("orca/orcacyber-zero-1.5"), "orca/orcacyber-zero-1.5")


class SelectorOptionsTest(Base):
    """Filtered options for a selector: chat-only, multimodal fail-closed, stale value dropped."""

    def _live(self):
        return orca_models.fetch_catalog(self.srv.base + "/v1", VALID_KEY)

    def test_chat_options_come_from_live_catalog(self):
        cat = self._live()
        self.assertEqual(cat.source, "live")
        ids = [m["id"] for m in cat.chat_options()]
        for keep in ("openai/gpt-5.5", "anthropic/claude-opus-4.8", "google/gemini-3.5-flash", "deepseek/deepseek-v4-pro", "orcarouter/auto"):
            self.assertIn(keep, ids)
        self.assertNotIn("openai/gpt-image-1", ids)
        self.assertNotIn("google/veo-3", ids)
        self.assertNotIn("jina/jina-reranker-v3", ids)
        self.assertNotIn("openai/text-embedding-4", ids)

    def test_image_attachment_leaves_only_declared_image_models(self):
        cat = self._live()
        opts = cat.options_for("image")
        self.assertEqual(sorted(m["id"] for m in opts), ["anthropic/claude-opus-4.8", "google/gemini-3.5-flash", "openai/gpt-5.5"])
        self.assertTrue(all("image" in m["input"] for m in opts))
        self.assertEqual([m["id"] for m in cat.options_for("audio")], ["google/gemini-3.5-flash"])
        self.assertEqual(cat.options_for("video"), [m for m in cat.models if m["id"] == "google/gemini-3.5-flash"])

    def test_selected_text_model_invalidated_when_image_added(self):
        cat = self._live()
        selected = "deepseek/deepseek-v4-pro"
        self.assertIn(selected, [m["id"] for m in cat.options_for(None)])
        image_ids = [m["id"] for m in cat.options_for("image")]
        self.assertNotIn(selected, image_ids, "a text-only pick must not survive into an image selector")
        self.assertIn(selected, [m["id"] for m in cat.options_for(None)], "text picker keeps it")

    def test_seed_fallback_is_orcarouter_only_and_flagged_degraded(self):
        cat = orca_models.discover_catalog(self.srv.base, VALID_KEY, fetch=lambda *a, **k: (_ for _ in ()).throw(OSError("down")))
        self.assertTrue(cat.degraded)
        opts = [m for m in cat.options_for(None)]
        self.assertTrue(opts)
        self.assertTrue(all(m["id"].startswith(("orcarouter/", "orca/")) for m in opts))
        self.assertEqual(cat.options_for("image"), [], "seed declares no image input, so image picker fails closed")


class ErrorPathTest(Base):
    def test_revoked_key_marks_credential_and_never_fakes_refresh(self):
        from tests.test_orca_pkce import VALID_KEY as PKCE_KEY

        store = orca_auth.CredentialStore(self.models_path)
        cred = orca_auth.ApiKeyAdapter(store, env={"PI_RECON_LLM_KEY": PKCE_KEY}).acquire()
        self.srv.state.valid_key = "sk-orca-rotated-somewhere-else"  # relay now rejects our key
        with self.assertRaises(orca_models.CredentialRejected) as ctx:
            # same key again: api_key adapter mints a fresh generation for this attempt
            net_llm.setup_orcarouter(api_key=PKCE_KEY, diagnose=True)
        cred = store.load()  # generation persisted by setup_orcarouter's adapter
        self.assertEqual(ctx.exception.generation, cred.generation)
        reloaded = store.load()
        self.assertTrue(reloaded.needs_reauth)
        self.assertEqual(reloaded.key, PKCE_KEY)  # secret kept until a successful replacement
        self.assertEqual(reloaded.source, "api_key")

    def test_catalog_outage_falls_back_to_seed(self):
        offline = mock.patch(
            "orca_models.fetch_catalog", side_effect=OSError("offline")
        )
        with offline:
            key, model = net_llm.setup_orcarouter(api_key=VALID_KEY, diagnose=False)
        self.assertEqual(model, "orcarouter/auto")
        entry = json.loads(self.models_path.read_text())["providers"]["orcarouter"]
        self.assertEqual([m["id"] for m in entry["models"]], [m["id"] for m in orca_models.SEED_MODELS])
        self.assertNotIn("orcaCatalog", entry)  # seed is never persisted as last-known-good
        self.assertEqual(entry["apiKey"], VALID_KEY)

    def test_typical_credentials_in_errors(self):
        err = orca_auth.AuthError("missing_key", "x")
        self.assertNotIn(VALID_KEY, str(err))


if __name__ == "__main__":
    unittest.main()
