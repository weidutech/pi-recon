"""OAuth 2.0 + PKCE connect adapter (Flow A loopback and Flow B out-of-band).

Every request goes to a local fake auth origin (``tests/fake_openai_server.py``);
no real consent is performed or faked.
"""

from __future__ import annotations

import json
import re
import sys
import tempfile
import threading
import unittest
import unittest.mock
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import net_llm  # noqa: E402
import orca_auth  # noqa: E402
from tests.fake_openai_server import FakeServer  # noqa: E402

VALID_KEY = "sk-orca-test-valid-key-0001"
_SENT_STATE: dict = {}
_SENT_STATE["state"] = urllib.parse.parse_qs(  # the adapter's fresh state is not knowable here
    "state=probe"
)["state"][0]


class _CaptureState:
    """Browser stub that records the state we actually sent."""

    def __init__(self, adapter_box: dict):
        self.adapter_box = adapter_box

    def __call__(self, url: str) -> bool:
        parsed = urllib.parse.urlparse(url)
        self.adapter_box["url"] = url
        _SENT_STATE["state"] = urllib.parse.parse_qs(parsed.query)["state"][0]
        return True


class _SyncedReceiver(orca_auth.LoopbackReceiver):
    """Waits in short slices so the test thread keeps control; never delivers."""

    def wait(self, timeout):
        self._done.wait(min(timeout, 0.1))
        return self._result or (None, None)


class ConsumingReceiverBase(orca_auth.LoopbackReceiver):
    def __init__(self):  # bind a throwaway port like the real loopback receiver
        super().__init__()
        self.delivered = False


class PkceBase(unittest.TestCase):
    def setUp(self) -> None:
        self.auth = FakeServer().start()  # auth origin (www)
        self.api = FakeServer().start()  # inference origin (api)
        self.tmp = Path(tempfile.mkdtemp())
        self.models_path = self.tmp / "models.json"
        self.store = orca_auth.CredentialStore(self.models_path)
        self.origins = orca_auth.Origins(auth_base=self.auth.base, api_base=self.api.base)
        self.logged: list[str] = []
        self._orig_pkce_init = None

    def tearDown(self) -> None:
        if getattr(self, "_orig_pkce_init", None) is not None:
            orca_auth.PkceAdapter.__init__ = self._orig_pkce_init
            self._orig_pkce_init = None
        self.auth.stop()
        self.api.stop()

    def _adapter(self, **kw) -> orca_auth.PkceAdapter:
        if "open_browser" not in kw and "receiver_factory" not in kw and kw.get("flow", "auto") in ("auto", "loopback"):
            # A browser that is driven inside wait(), like a real consent click.
            kw["receiver_factory"] = self._consuming_receiver
        kw.setdefault("open_browser", self._open)
        return orca_auth.PkceAdapter(self.store, origins=self.origins, printer=self.logged.append, **kw)

    def _open(self, url: str) -> bool:
        self._pending_url = url
        return True

    def _consuming_receiver(self):
        fetch = self._fetch
        harness = self

        class ConsumingReceiver(orca_auth.LoopbackReceiver):
            """Delivers the redirect to the socket endpoint until it settles."""

            def __init__(inner):
                super().__init__()
                inner.delivered = False

            def wait(inner, timeout):
                if not inner.delivered:
                    fetch(harness._pending_url)  # returns once the redirect is delivered
                    inner.delivered = True
                result = super().wait(min(timeout, 5.0))
                if result[1] == "access_denied":
                    raise orca_auth.AuthError("access_denied", "denied in fixture")
                return result

        return ConsumingReceiver()

    def _consuming_oob_receiver(self):
        fetch = self._fetch
        harness = self

        class ConsumingOobReceiver(ConsumingReceiverBase):
            """Consent stub answers JSON for ``callback_url=oob``; hand the code back."""

            def wait(inner, timeout):
                if not inner.delivered:
                    import json as _json

                    with urllib.request.urlopen(harness._pending_url, timeout=10) as r:
                        inner.code = _json.loads(r.read())["code"]
                    inner.delivered = True
                return inner.code, None

        return ConsumingOobReceiver()

    def _sync_receiver(self):
        # Bare loopback receiver that keeps pytest threads in sync: used for
        # timeout/cancel tests where no redirect is ever delivered.
        return _SyncedReceiver()

    def _fetch(self, url: str) -> bytes:
        """Hit the consent endpoint; if it redirects, deliver it from a helper thread."""
        req = urllib.request.Request(url)
        opener = urllib.request.build_opener(_NoRedirect)
        try:
            with opener.open(req, timeout=10) as resp:
                location = resp.headers.get("Location")
                body = b"" if location else resp.read()
        except urllib.error.HTTPError as e:
            location = e.headers.get("Location")
            body = b"" if location else e.read()
            e.close()
        box = {}

        def deliver():
            try:
                with urllib.request.urlopen(location, timeout=10) as r:
                    box["body"] = r.read()
            except Exception as e:  # noqa: BLE001
                box["error"] = e

        t = threading.Thread(target=deliver, daemon=True)
        t.start()
        t.join(10)
        if "error" in box:
            raise box["error"]
        return box.get("body", b"")


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


class PkceFlowATest(PkceBase):
    def test_loopback_roundtrip_persists_key(self):
        cred = self._adapter(flow="loopback").acquire()
        self.assertEqual(cred.key, VALID_KEY)
        self.assertEqual(cred.source, "pkce")
        self.assertEqual(cred.scope, "api")
        self.assertEqual(cred.status, orca_auth.STATUS_OK)
        stored = self.store.load()
        self.assertEqual(stored.key, VALID_KEY)
        entry = json.loads(self.models_path.read_text())["providers"]["orcarouter"]
        self.assertEqual(entry["orcaAuth"]["refresh"], "orcarouter-durable-key")
        self.assertEqual(entry["orcaAuth"]["status"], "ok")

    def test_authorize_url_shape(self):
        seen = {}

        def capture(url):
            seen["url"] = url
            return self._fetch(url) and True

        self._adapter(flow="loopback", open_browser=capture).acquire()
        parsed = urllib.parse.urlparse(seen["url"])
        q = urllib.parse.parse_qs(parsed.query)
        self.assertEqual(parsed.netloc, urllib.parse.urlparse(self.auth.base).netloc)
        self.assertEqual(parsed.path, "/auth")
        self.assertEqual(q["code_challenge_method"], ["S256"])
        self.assertTrue(q["callback_url"][0].startswith("http://127.0.0.1:"))
        self.assertGreaterEqual(len(q["state"][0]), 20)
        self.assertNotIn("=", q["code_challenge"][0])  # unpadded base64url
        self.assertEqual(q["app_name"], ["PI Recon"])
        # the verifier is never in the URL or the printed hint
        self.assertFalse(any("verifier" in u for u in (seen["url"], *self.logged)))
        self.assertFalse(any(VALID_KEY in line for line in self.logged))

    def test_fresh_verifier_and_state_per_attempt(self):
        urls = []
        orig_fetch = self._fetch

        def capture(url):
            urls.append(url)
            return orig_fetch(url) and True

        for _ in range(2):
            self.store.clear()
            self._adapter(flow="loopback", open_browser=capture).acquire()
        qs = [urllib.parse.parse_qs(urllib.parse.urlparse(u).query) for u in urls]
        self.assertNotEqual(qs[0]["code_challenge"], qs[1]["code_challenge"])
        self.assertNotEqual(qs[0]["state"], qs[1]["state"])

    def test_state_mismatch_aborts(self):
        class HostileReceiver(orca_auth.LoopbackReceiver):
            """Delivers a code with someone else's state."""

            def wait(self, timeout):
                self.last_state = "attacker-state"
                return "some-code", None

        with self.assertRaises(orca_auth.AuthError) as ctx:
            self._adapter(flow="loopback", receiver_factory=HostileReceiver, open_browser=self._open).acquire()
        self.assertEqual(ctx.exception.code, "state_mismatch")
        self.assertIsNone(self.store.load())

    def test_denial(self):
        sent = {"state": ""}

        class DenyingBrowserAndReceiver(orca_auth.LoopbackReceiver):
            """Consent screen answers error=access_denied, echoing the sent state."""

            def wait(self, timeout):
                self.last_state = sent["state"]
                return None, "access_denied"

        def browser(url):
            sent["state"] = urllib.parse.parse_qs(urllib.parse.urlparse(url).query)["state"][0]
            return True

        with self.assertRaises(orca_auth.AuthError) as ctx:
            self._adapter(flow="loopback", receiver_factory=DenyingBrowserAndReceiver, open_browser=browser).acquire()
        self.assertEqual(ctx.exception.code, "access_denied")
        self.assertIn("access_denied", ctx.exception.message)
        self.assertIsNone(self.store.load())

    def test_timeout(self):
        with self.assertRaises(orca_auth.AuthError) as ctx:
            self._adapter(flow="loopback", receiver_factory=self._sync_receiver, open_browser=self._open, login_timeout=0.5).acquire()
        self.assertEqual(ctx.exception.code, "timeout")

    def test_explicit_cancel(self):
        adapter = self._adapter(flow="loopback", receiver_factory=self._sync_receiver, open_browser=self._open, login_timeout=10)
        t = threading.Thread(target=adapter.acquire)
        t.start()
        import time

        time.sleep(0.3)
        adapter.cancel("user pressed cancel")
        t.join(5)
        self.assertFalse(t.is_alive())


class PkceFlowBTest(PkceBase):
    def test_oob_roundtrip(self):
        codes = []

        def read_code(_prompt):
            # Ask the consent stub for the displayed code for the real authorize URL.
            url = next(u for u in self.authorize_urls if u)
            with urllib.request.urlopen(url, timeout=10) as r:
                return json.loads(r.read())["code"]

        self.authorize_urls = []
        adapter = self._adapter(
            flow="oob",
            open_browser=lambda url: (self.authorize_urls.append(url), True)[1],
            read_code=read_code,
        )
        cred = adapter.acquire()
        self.assertEqual(cred.key, VALID_KEY)
        q = urllib.parse.parse_qs(urllib.parse.urlparse(self.authorize_urls[0]).query)
        self.assertEqual(q["callback_url"], ["oob"])
        self.assertEqual(q["code_challenge_method"], ["S256"])

    def test_oob_empty_code(self):
        with self.assertRaises(orca_auth.AuthError) as ctx:
            self._adapter(flow="oob", open_browser=lambda u: True, read_code=lambda p: "  ").acquire()
        self.assertEqual(ctx.exception.code, "missing_code")


class ExchangeTest(PkceBase):
    """Exchange errors, single-use codes, 429 and network failures terminate cleanly."""

    def _run_exchange(self, **kw):
        return orca_auth.exchange_code(exchange_url=self.auth.base + "/api/v1/auth/keys", **kw)

    def test_uses_auth_origin_path_not_relay(self):
        seen = {}

        def opener(req, timeout=None):
            seen["url"] = req.full_url
            seen["body"] = json.loads(req.data)
            req.data = req.data
            return urllib.request.urlopen(req, timeout=timeout)

        verifier = orca_auth.make_verifier()
        challenge = orca_auth.challenge_for(verifier)
        code = self.auth.state.issue_code(challenge)
        res = orca_auth.exchange_code(
            exchange_url=self.origins.exchange_url(), code=code, verifier=verifier, opener=opener
        )
        self.assertEqual(res.key, VALID_KEY)
        self.assertEqual(seen["url"], self.auth.base + "/api/v1/auth/keys")
        self.assertNotIn("/v1/auth/keys", seen["url"].replace("/api/v1/auth/keys", ""))
        self.assertEqual(seen["body"]["code_challenge_method"], "S256")
        self.assertEqual(seen["body"]["code_verifier"], verifier)

    def test_code_reuse_rejected(self):
        verifier = orca_auth.make_verifier()
        code = self.auth.state.issue_code(orca_auth.challenge_for(verifier))
        self._run_exchange(code=code, verifier=verifier)
        with self.assertRaises(orca_auth.AuthError) as ctx:
            self._run_exchange(code=code, verifier=verifier)
        self.assertEqual(ctx.exception.code, "exchange_rejected")

    def test_wrong_verifier_403(self):
        code = self.auth.state.issue_code(orca_auth.challenge_for(orca_auth.make_verifier()))
        with self.assertRaises(orca_auth.AuthError) as ctx:
            self._run_exchange(code=code, verifier=orca_auth.make_verifier())
        self.assertEqual(ctx.exception.code, "exchange_rejected")

    def test_429_and_network_error(self):
        with self.assertRaises(orca_auth.AuthError) as ctx:
            orca_auth.parse_exchange_response(429, "{}")
        self.assertEqual(ctx.exception.code, "rate_limited")
        with self.assertRaises(orca_auth.AuthError) as ctx2:
            orca_auth.exchange_code(exchange_url="http://127.0.0.1:1/api/v1/auth/keys", code="c", verifier="v", timeout=1)
        self.assertEqual(ctx2.exception.code, "network_error")
        self.assertNotIn("sk-orca", str(ctx2.exception))

    def test_scope_downgrade_reported(self):
        res = orca_auth.parse_exchange_response(200, json.dumps({"key": VALID_KEY, "scope": "connector"}), requested_scope="api")
        self.assertEqual(res.scope, "connector")
        cred = orca_auth.OrcaCredential(key=res.key, source="pkce", scope=res.scope)
        self.assertEqual(cred.scope, "connector")

    def test_bad_response(self):
        with self.assertRaises(orca_auth.AuthError) as ctx:
            orca_auth.parse_exchange_response(200, json.dumps({"scope": "api"}))
        self.assertEqual(ctx.exception.code, "bad_response")


class OriginsTest(unittest.TestCase):
    def test_defaults_are_distinct(self):
        o = orca_auth.Origins.from_env({})
        self.assertEqual(o.auth_base, "https://www.orcarouter.ai")
        self.assertEqual(o.api_url, "https://api.orcarouter.ai/v1")
        self.assertEqual(o.authorize_url(), "https://www.orcarouter.ai/auth")
        self.assertEqual(o.exchange_url(), "https://www.orcarouter.ai/api/v1/auth/keys")
        self.assertNotIn("api.orcarouter.ai", o.exchange_url())

    def test_overrides_and_shared_base(self):
        o = orca_auth.Origins.from_env({"ORCA_BASE_URL": "https://orca.internal"})
        self.assertEqual(o.auth_base, "https://orca.internal")
        self.assertEqual(o.api_url, "https://orca.internal/v1")
        o2 = orca_auth.Origins.from_env(
            {"ORCA_BASE_URL": "https://orca.internal", "ORCA_AUTH_BASE_URL": "https://sso.internal", "ORCA_API_BASE_URL": "https://relay.internal/v1"}
        )
        self.assertEqual(o2.auth_base, "https://sso.internal")
        self.assertEqual(o2.api_url, "https://relay.internal/v1")

    def test_http_only_for_loopback(self):
        with self.assertRaises(orca_auth.AuthError):
            orca_auth.Origins.from_env({"ORCA_BASE_URL": "http://orca.example.com"})
        o = orca_auth.Origins.from_env({"ORCA_BASE_URL": "http://127.0.0.1:8080"})
        self.assertEqual(o.api_url, "http://127.0.0.1:8080/v1")

    def test_api_origin_cannot_be_auth_origin(self):
        with self.assertRaises(orca_auth.AuthError):
            orca_auth.Origins.from_env({"ORCA_API_BASE_URL": "https://www.orcarouter.ai"})


class LifecycleTest(PkceBase):
    def _pkce_cred(self):
        return self._adapter(flow="loopback").acquire()

    def test_durable_key_reused(self):
        first = self._pkce_cred()
        before = self.auth.state.used_codes.copy()
        adapter = self._adapter(flow="loopback", open_browser=lambda u: self.fail("browser must not open"))
        cred = orca_auth.resolve_credential(method="pkce", models_path=self.models_path, pkce=adapter)
        self.assertEqual(cred.key, first.key)
        self.assertEqual(self.auth.state.used_codes, before)  # no new grant minted

    def test_401_marks_exact_generation_only(self):
        cred = self._pkce_cred()
        self.assertTrue(self.store.mark_needs_reauth(cred.generation))
        self.assertEqual(self.store.load().status, orca_auth.STATUS_NEEDS_REAUTH)
        # old request's late 401 must not poison a newer key
        newer = self._pkce_cred_again()
        self.assertFalse(self.store.mark_needs_reauth(cred.generation))
        self.assertEqual(self.store.load().status, orca_auth.STATUS_OK)
        self.assertEqual(self.store.load().generation, newer.generation)

    def _pkce_cred_again(self):
        self.store.clear()
        return self._adapter(flow="loopback").acquire()

    def test_needs_reauth_triggers_new_login_and_key_kept_until_success(self):
        cred = self._pkce_cred()
        self.store.mark_needs_reauth(cred.generation)
        calls = []

        class Failing(orca_auth.PkceAdapter):
            def acquire(self_inner):
                calls.append(1)
                raise orca_auth.AuthError("network_error", "down")

        failing = Failing(self.store, origins=self.origins, printer=self.logged.append)
        with self.assertRaises(orca_auth.AuthError):
            orca_auth.resolve_credential(method="pkce", models_path=self.models_path, pkce=failing)
        self.assertEqual(calls, [1])
        # old secret is not deleted before a successful replacement
        self.assertEqual(self.store.load().key, cred.key)

    def test_revoked_key_does_not_fake_refresh(self):
        cred = self._pkce_cred()
        entry = json.loads(self.models_path.read_text())["providers"]["orcarouter"]
        self.assertEqual(entry["orcaAuth"]["refresh"], "orcarouter-durable-key")
        self.assertTrue(self.store.mark_needs_reauth(cred.generation))
        reloaded = self.store.load()
        self.assertTrue(reloaded.needs_reauth)
        # no refresh endpoint is ever called: the auth server saw no /token-like POST
        self.assertEqual(self.auth.state.used_codes.__len__(), 1)

    def test_secrets_not_in_logs(self):
        self._pkce_cred()
        self.assertNotIn(VALID_KEY, "\n".join(self.logged))
        from contextlib import redirect_stdout
        from io import StringIO

        buf = StringIO()
        with redirect_stdout(buf):
            self._pkce_cred_again()
        out = buf.getvalue()
        self.assertNotIn(VALID_KEY, out)
        self.assertIn("sk-orca-...0001", out)  # masked form only


class SetupIntegrationTest(PkceBase):
    def test_pkce_connects_provider_and_catalog(self):
        old = dict(__import__("os").environ)
        try:
            __import__("os").environ.update(
                {
                    "ORCA_AUTH_BASE_URL": self.auth.base,
                    "ORCA_API_BASE_URL": self.api.base,
                    "PI_MODELS_JSON": str(self.models_path),
                    "PI_RECON_LLM_ROUTE": "public",
                }
            )
            import orca_auth as _oa

            orig = _oa.PkceAdapter.__init__

            def patched(self_, store, **kw):
                kw.setdefault("open_browser", lambda url: self._fetch(url) and True)
                orig(self_, store, **kw)

            self._orig_pkce_init = orig
            _oa.PkceAdapter.__init__ = patched
            try:
                key, model = net_llm.setup_orcarouter(auth="pkce", diagnose=False)
            finally:
                _oa.PkceAdapter.__init__ = orig
            self.assertEqual(key, VALID_KEY)
            self.assertEqual(model, "orcarouter/auto")
            entry = json.loads(self.models_path.read_text())["providers"]["orcarouter"]
            self.assertEqual(entry["orcaAuth"]["source"], "pkce")
            self.assertEqual(entry["baseUrl"], self.api.base + "/v1")
            self.assertGreaterEqual(self.api.state.model_calls, 1)
            self.assertEqual(self.auth.state.model_calls, 0)  # catalog never hits auth origin
        finally:
            __import__("os").environ.clear()
            __import__("os").environ.update(old)


if __name__ == "__main__":
    unittest.main()
