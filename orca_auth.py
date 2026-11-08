"""OrcaRouter credential seam: obtain one ``sk-orca-…`` relay key.

Two independent adapters sit on the same seam and both hand the rest of
PI Recon the same :class:`OrcaCredential`:

* :class:`ApiKeyAdapter`   - the operator already has a key (env / prompt / ``.env``).
* :class:`PkceAdapter`     - "Connect with OrcaRouter", OAuth 2.0 + PKCE (S256).

Flow A (loopback redirect) is used when the operator asks for a browser login
and we can bind ``127.0.0.1``; otherwise Flow B (out-of-band code) is used,
which is what a sandboxed / hosted / SSH run needs. Both flows always send an
S256 challenge, never ``plain``.

Auth and inference are different origins:

* auth:      ``https://www.orcarouter.ai``      (authorize ``/auth``, exchange ``/api/v1/auth/keys``)
* inference: ``https://api.orcarouter.ai/v1``   (keys, chat, model catalog)

Overrides, highest precedence first: ``ORCA_AUTH_BASE_URL`` / ``ORCA_API_BASE_URL``,
then shared ``ORCA_BASE_URL`` (self-hosted, API origin = shared + ``/v1``),
then the public defaults.  The auth origin is never derived from the API origin
by string surgery and vice versa.

The PKCE exchange returns a durable API key, not a refresh token: there is no
refresh grant, so a revoked key is marked ``needs_reauth`` and the user runs the
connect flow again.  The key is persisted in ``models.json`` next to the
provider entry (the file PI Recon already uses for provider secrets) and only
a masked form is ever printed.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import secrets
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import webbrowser
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Dict, Mapping, Optional, Tuple

ORCAROUTER_PROVIDER = "orcarouter"
DEFAULT_AUTH_BASE_URL = "https://www.orcarouter.ai"
DEFAULT_API_BASE_URL = "https://api.orcarouter.ai"
AUTHORIZE_PATH = "/auth"
EXCHANGE_PATH = "/api/v1/auth/keys"
APP_NAME = "PI Recon"
SCOPE_API = "api"
KEY_PREFIX = "sk-orca-"
KEY_HOME = "https://www.orcarouter.ai/console/keys"
PROVIDER_HOME = "https://www.orcarouter.ai/cyber"
CYBER_MODEL_CATALOG = "https://www.orcarouter.ai/models?tier=cyber"
LOOPBACK_HOSTS = ("127.0.0.1", "localhost", "[::1]")
CALLBACK_PATH = "/cb"
DEFAULT_EXCHANGE_TIMEOUT = 30.0
DEFAULT_LOGIN_TIMEOUT = 300.0
REFRESH_FIELD = "orcarouter-durable-key"  # sentinel: never a real refresh grant


def user_agent(role: str = "auth") -> str:
    return f"pi-recon-orcarouter/1 (+{PROVIDER_HOME}; {role})"


class AuthError(Exception):
    """Credential acquisition failed; ``code`` is stable for tests and UI."""

    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code
        self.message = message


def _log(message: str) -> None:
    print(f"[orca] {message}", flush=True)


# --------------------------------------------------------------------------- utils


def b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def make_verifier() -> str:
    """Fresh cryptographic verifier for one attempt (never reused, never logged)."""
    return b64url(secrets.token_bytes(32))


def challenge_for(verifier: str) -> str:
    return b64url(hashlib.sha256(verifier.encode("ascii")).digest())


def make_state() -> str:
    return b64url(secrets.token_bytes(16))


def states_match(a: Optional[str], b: str) -> bool:
    if not a or not b:
        return False
    return secrets.compare_digest(str(a).encode("utf-8"), str(b).encode("utf-8"))


def mask_secret(key: str) -> str:
    key = key or ""
    if len(key) <= 12:
        return "*" * len(key)
    return f"{key[:8]}...{key[-4:]}"


def _is_loopback_host(host: str) -> bool:
    return (host or "").lower() in LOOPBACK_HOSTS


class Origins:
    """Resolved auth / inference origins with explicit precedence and HTTPS rules."""

    def __init__(self, auth_base: str, api_base: str):
        self.auth_base = auth_base.rstrip("/")
        self.api_base = api_base.rstrip("/")

    @classmethod
    def from_env(cls, env: Optional[Mapping[str, str]] = None) -> "Origins":
        env = os.environ if env is None else env
        shared = (env.get("ORCA_BASE_URL") or "").strip().rstrip("/")
        auth = (env.get("ORCA_AUTH_BASE_URL") or "").strip().rstrip("/") or shared or DEFAULT_AUTH_BASE_URL
        api = (env.get("ORCA_API_BASE_URL") or "").strip().rstrip("/") or (
            f"{shared}/v1" if shared else DEFAULT_API_BASE_URL
        )
        # Never derive one public origin from the other by hostname surgery:
        # the relay origin must not be the auth origin (explicitly set).
        api_explicit = bool((env.get("ORCA_API_BASE_URL") or "").strip())
        if api_explicit and api.rstrip("/") in (f"{auth}/v1", auth):
            raise AuthError(
                "bad_origins",
                "ORCA_API_BASE_URL points at the auth origin; inference must use api.orcarouter.ai/v1",
            )
        for label, url in (("auth", auth), ("api", api)):
            _check_origin(label, url)
        return cls(auth, api)

    @property
    def api_url(self) -> str:
        """Inference root used over the wire (always ends in ``/v1``)."""
        return self.api_base if self.api_base.endswith("/v1") else f"{self.api_base}/v1"

    def authorize_url(self) -> str:
        return self.auth_base + AUTHORIZE_PATH

    def exchange_url(self) -> str:
        return self.auth_base + EXCHANGE_PATH


def _check_origin(label: str, url: str) -> None:
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        raise AuthError("bad_origins", f"{label} origin must be an absolute http(s) URL")
    if parsed.scheme == "http" and not _is_loopback_host(parsed.hostname):
        raise AuthError("bad_origins", f"{label} origin must use HTTPS unless it is loopback")


def build_authorize_url(
    *,
    auth_before: str,
    callback_url: str,
    challenge: str,
    state: str,
    app_name: str = APP_NAME,
    scope: str = SCOPE_API,
) -> str:
    params = {
        "callback_url": callback_url,
        "code_challenge": challenge,
        "code_challenge_method": "S256",
        "state": state,
        "app_name": app_name,
    }
    if scope:
        params["scope"] = scope
    return f"{auth_before}{AUTHORIZE_PATH}?{urllib.parse.urlencode(params)}"


# ----------------------------------------------------------------------- credential

STATUS_OK = "ok"
STATUS_NEEDS_REAUTH = "needs_reauth"


@dataclass(frozen=True)
class OrcaCredential:
    """The one thing every adapter produces; downstream code never sees the source."""

    key: str
    source: str  # "api_key" | "pkce"
    scope: str = SCOPE_API
    user_id: str = ""
    generation: str = ""
    status: str = STATUS_OK

    @property
    def needs_reauth(self) -> bool:
        return self.status == STATUS_NEEDS_REAUTH

    def masked(self) -> str:
        return mask_secret(self.key)

    def with_status(self, status: str) -> "OrcaCredential":
        return OrcaCredential(
            key=self.key,
            source=self.source,
            scope=self.scope,
            user_id=self.user_id,
            generation=self.generation,
            status=status,
        )


@dataclass(frozen=True)
class ExchangeResult:
    key: str
    scope: str
    user_id: str


def parse_exchange_response(status: int, body: str, *, requested_scope: str = SCOPE_API) -> ExchangeResult:
    try:
        data = json.loads(body or "{}")
    except json.JSONDecodeError:
        data = {}
    if status == 429:
        raise AuthError("rate_limited", "too many OrcaRouter key grants (10 per user / 24h); retry later")
    if status == 403:
        raise AuthError(
            "exchange_rejected",
            "OrcaRouter rejected the code (unknown, expired, already used, or verifier mismatch)",
        )
    if status == 400:
        raise AuthError("bad_request", "OrcaRouter rejected the request (code_challenge_method mismatch)")
    if status != 200 or not isinstance(data, dict):
        raise AuthError("exchange_failed", f"OrcaRouter key exchange failed with HTTP {status}")
    key = str(data.get("key") or "").strip()
    if not key.startswith(KEY_PREFIX):
        raise AuthError("bad_response", "OrcaRouter key exchange returned no sk-orca- key")
    granted = str(data.get("scope") or "")
    if granted != requested_scope:
        # Report what was granted rather than assuming we hold what we asked for.
        _log(f"granted scope is {granted!r}, not {requested_scope!r}")
    return ExchangeResult(key=key, scope=granted, user_id=str(data.get("user_id") or ""))


def exchange_code(
    *,
    exchange_url: str,
    code: str,
    verifier: str,
    timeout: float = DEFAULT_EXCHANGE_TIMEOUT,
    requested_scope: str = SCOPE_API,
    opener: Optional[Callable[..., object]] = None,
) -> ExchangeResult:
    payload = json.dumps(
        {"code": code, "code_verifier": verifier, "code_challenge_method": "S256"}
    ).encode("utf-8")
    req = urllib.request.Request(
        exchange_url,
        data=payload,
        headers={"Content-Type": "application/json", "Accept": "application/json", "User-Agent": user_agent("auth")},
        method="POST",
    )
    open_fn = opener or urllib.request.urlopen
    try:
        with open_fn(req, timeout=timeout) as resp:
            return parse_exchange_response(
                getattr(resp, "status", 200),
                resp.read().decode("utf-8", errors="replace"),
                requested_scope=requested_scope,
            )
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", errors="replace") if e.fp else ""
        return parse_exchange_response(e.code, body, requested_scope=requested_scope)
    except AuthError:
        raise
    except Exception as e:  # noqa: BLE001 - network failures must end the attempt
        raise AuthError("network_error", f"OrcaRouter key exchange network error: {type(e).__name__}") from None


# ------------------------------------------------------------------------- store


class CredentialStore:
    """Persist the key in the project's existing secret file (``models.json``)."""

    def __init__(self, models_path: Path, provider: str = ORCAROUTER_PROVIDER):
        self.path = Path(models_path)
        self.provider = provider

    def read(self) -> Dict:
        mc = self._read().get("providers", {}).get(self.provider)
        return mc if isinstance(mc, dict) else {}

    def _read(self) -> Dict:
        if not self.path.is_file():
            return {"providers": {}}
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return {"providers": {}}
        if not isinstance(data, dict):
            return {"providers": {}}
        data.setdefault("providers", {})
        return data

    def _write(self, data: Dict) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(self.path.suffix + ".tmp")
        tmp.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        os.replace(tmp, self.path)

    def load(self) -> Optional[OrcaCredential]:
        entry = (self._read().get("providers") or {}).get(self.provider) or {}
        key = str(entry.get("apiKey") or "").strip()
        if not key:
            return None
        meta = entry.get("orcaAuth") or {}
        return OrcaCredential(
            key=key,
            source=str(meta.get("source") or "api_key"),
            scope=str(meta.get("scope") or SCOPE_API),
            user_id=str(meta.get("user_id") or ""),
            generation=str(meta.get("generation") or ""),
            status=str(meta.get("status") or STATUS_OK),
        )

    def save(self, cred: OrcaCredential) -> None:
        data = self._read()
        entry = data["providers"].get(self.provider)
        if not isinstance(entry, dict):
            entry = {"name": "OrcaRouter Cyber Inference", "api": "openai-completions", "models": []}
            data["providers"][self.provider] = entry
        entry["apiKey"] = cred.key
        entry["orcaAuth"] = {
            "source": cred.source,
            "scope": cred.scope,
            "user_id": cred.user_id,
            "generation": cred.generation,
            "status": cred.status,
            "saved_at": int(time.time()),
            # Durable key, not an OAuth refresh token: nothing rotates it.
            "refresh": REFRESH_FIELD,
        }
        self._write(data)
        _log(f"stored OrcaRouter key {cred.masked()} (source={cred.source})")

    def mark_needs_reauth(self, generation: str) -> bool:
        """Flag the exact rejected credential generation; never touch a newer one."""
        data = self._read()
        entry = data["providers"].get(self.provider)
        if not isinstance(entry, dict) or not entry.get("apiKey"):
            return False
        meta = entry.get("orcaAuth") or {}
        if me := meta.get("generation"):
            if me != generation:
                return False  # a late 401 from an old request must not poison a new key
        meta["status"] = STATUS_NEEDS_REAUTH
        entry["orcaAuth"] = meta
        self._write(data)
        return True

    def remember_catalog(self, models: list) -> None:
        """Remember the authoritative catalog so an outage keeps it (bounded, verified)."""
        data = self._read()
        entry = data["providers"].get(self.provider)
        if not isinstance(entry, dict):
            return
        entry["orcaCatalog"] = {"source": "live", "degraded": False, "saved_at": int(time.time()), "models": list(models)[:1000]}
        self._write(data)

    def forget_catalog(self) -> None:
        data = self._read()
        entry = data["providers"].get(self.provider)
        if isinstance(entry, dict) and entry.pop("orcaCatalog", None) is not None:
            self._write(data)

    def clear(self) -> bool:
        data = self._read()
        entry = data["providers"].get(self.provider)
        if not isinstance(entry, dict):
            return False
        changed = False
        for field in ("apiKey", "orcaAuth"):
            if field in entry:
                del entry[field]
                changed = True
        if changed:
            self._write(data)
        return changed


# ----------------------------------------------------------------------- adapters


class ApiKeyAdapter:
    """Adapter 1: operator supplies an existing ``sk-orca-…`` key."""

    source = "api_key"

    def __init__(
        self,
        store: CredentialStore,
        env: Optional[Mapping[str, str]] = None,
        prompt: Optional[Callable[[str], str]] = None,
    ):
        self.store = store
        self.env = os.environ if env is None else env
        self.prompt = prompt

    def acquire(self) -> OrcaCredential:
        key = self._from_env()
        if not key and self.prompt is not None:
            key = (self.prompt(f"OrcaRouter API key ({KEY_PREFIX}…), or leave empty to abort: ") or "").strip()
        if not key:
            raise AuthError(
                "missing_key",
                f"set PI_RECON_LLM_KEY to an OrcaRouter key; create one at {KEY_HOME}",
            )
        self._check_shape(key)
        cred = OrcaCredential(key=key, source=self.source, generation=secrets.token_hex(8))
        self.store.save(cred)
        return cred

    def _from_env(self) -> str:
        # Dedicated recon key names only: never alias another provider's key here.
        for name in ("PI_RECON_LLM_KEY", "PI_RECON_API_KEY", "ORCAROUTER" + "_API_KEY"):
            value = (self.env.get(name) or "").strip()
            if value:
                return value
        return ""

    @staticmethod
    def _check_shape(key: str) -> None:
        if key.startswith(KEY_PREFIX):
            return
        raise AuthError(
            "bad_key_shape",
            f"that does not look like an OrcaRouter key (expected {KEY_PREFIX}…); "
            f"keys from {KEY_HOME} start with {KEY_PREFIX}",
        )


class LoopbackReceiver:
    """Flow A: bind 127.0.0.1 first, then hand the port to the authorize URL."""

    def __init__(self, host: str = "127.0.0.1", path: str = CALLBACK_PATH):
        import http.server
        import socketserver

        self.path = path
        outer = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self) -> None:  # noqa: N802
                parsed = urllib.parse.urlparse(self.path)
                outer._handle(parsed.query, self)

            def log_message(self, *args) -> None:  # silence stdlib request logging
                return

        class Server(socketserver.TCPServer):
            allow_reuse_address = True
            timeout = 30  # an idle local request must not block serve_forever forever

        self._server = Server((host, 0), Handler)
        self._closed = False
        self.port = self._server.server_address[1]
        self.callback_url = f"http://{host}:{self.port}{path}"
        self._result: Optional[Tuple[Optional[str], Optional[str]]] = None
        self.last_state: Optional[str] = None
        self._done = threading.Event()

    def _handle(self, query: str, handler) -> None:
        if self._done.is_set() or self._result is not None:
            try:
                handler.send_response(204)
                handler.end_headers()
            except OSError:
                pass
            return
        params = urllib.parse.parse_qs(query or "")
        # Read params first, always answer, validate later in acquire().
        if self._result is None:
            code = (params.get("code") or [None])[0]
            err = (params.get("error") or [None])[0]
            self.last_state = (params.get("state") or [None])[0]
            self._result = (code, err)
        body = b"<p>Connected. You can close this tab.</p>"
        try:
            handler.send_response(200)
            handler.send_header("Content-Type", "text/html; charset=utf-8")
            handler.send_header("Content-Length", str(len(body)))
            handler.end_headers()
            handler.wfile.write(body)
        except OSError:
            pass
        self._done.set()

    def serve_in_background(self) -> None:
        def _loop() -> None:
            while not self._done.is_set() and not self._closed:
                self._server.handle_request()

        threading.Thread(target=_loop, daemon=True, name="orca-loopback").start()

    def wait(self, timeout: float) -> Tuple[Optional[str], Optional[str]]:
        if not self._done.wait(timeout):
            raise AuthError("timeout", f"no OrcaRouter redirect within {int(timeout)}s")
        return self._result or (None, None)

    def close(self) -> None:
        self._closed = True
        try:
            self._server.server_close()  # idempotent; frees the loopback port
        except OSError:
            pass


class PkceAdapter:
    """Adapter 2: 'Connect with OrcaRouter' via OAuth 2.0 + PKCE."""

    source = "pkce"

    def __init__(
        self,
        store: CredentialStore,
        *,
        origins: Optional[Origins] = None,
        flow: str = "auto",
        scope: str = SCOPE_API,
        open_browser: Optional[Callable[[str], bool]] = None,
        read_code: Optional[Callable[[str], str]] = None,
        exchange: Optional[Callable[..., ExchangeResult]] = None,
        login_timeout: float = DEFAULT_LOGIN_TIMEOUT,
        receiver_factory: Optional[Callable[[], LoopbackReceiver]] = None,
        printer: Callable[[str], None] = _log,
    ):
        if flow not in ("auto", "loopback", "oob"):
            raise AuthError("bad_flow", f"unknown PKCE flow {flow!r}")
        self.store = store
        self.origins = origins or Origins.from_env()
        self.flow = flow
        self.scope = scope
        self._open_browser = open_browser or webbrowser.open
        self._read_code = read_code or (lambda prompt: input(prompt))
        self._exchange = exchange or exchange_code
        self.login_timeout = login_timeout
        self._receiver_factory = receiver_factory or LoopbackReceiver
        self._print = printer
        self._pending: Optional[dict] = None
        self.cancel_reason: str = ""
        self._cancel_spoken = threading.Event()

    # -- allow an operator / signal handler to brake a waiting login
    def cancel(self, reason: str = "cancelled") -> None:
        self.cancel_reason = reason
        pending = self._pending or {}
        if pending.get("receiver") is not None:
            try:
                pending["receiver"].close()
            except Exception:  # noqa: BLE001
                pass
        if pending.get("done") is not None:
            pending["done"].set()

    def acquire(self) -> OrcaCredential:
        verifier = make_verifier()
        challenge = challenge_for(verifier)
        state = make_state()
        receiver: Optional[LoopbackReceiver] = None
        flow = self.flow
        if flow == "auto":
            try:
                receiver = self._receiver_factory()
                flow = "loopback"
            except OSError:
                flow = "oob"
        elif flow == "loopback":
            receiver = self._receiver_factory()

        done = threading.Event()
        self._pending = {"receiver": receiver, "done": done}
        if receiver is not None:
            receiver.serve_in_background()
            callback_url = receiver.callback_url
        else:
            callback_url = "oob"

        url = build_authorize_url(
            auth_before=self.origins.auth_base,
            callback_url=callback_url,
            challenge=challenge,
            state=state,
            app_name=APP_NAME,
            scope=self.scope,
        )
        try:
            if not self._open_browser(url):
                self._print(f"open this URL to connect OrcaRouter:\n{url}")
            self._print("waiting for OrcaRouter authorization…")

            if receiver is not None:
                deadline = time.monotonic() + (self.login_timeout if self.login_timeout else 3600)
                code, err = None, None
                got, last_err = False, None
                while not got:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        break
                    try:
                        code, err = receiver.wait(min(remaining, 10.0))
                        got = True
                    except AuthError as e:
                        last_err = e
                if self.cancel_reason:
                    raise AuthError("cancelled", f"OrcaRouter login cancelled ({self.cancel_reason})")
                if last_err is not None:
                    raise AuthError(last_err.code, f"OrcaRouter login failed: {last_err.message}")
                if code is None and err in (None, ""):
                    raise AuthError("timeout", f"no OrcaRouter redirect within {int(self.login_timeout)}s")
                # Compare state before anything else, then branch.
                params_state = getattr(receiver, "last_state", None)
                if not params_state or not states_match(params_state, state):
                    raise AuthError("state_mismatch", "OrcaRouter redirect state did not match; login aborted")
                if err is not None and err != "":
                    raise AuthError("access_denied" if err == "access_denied" else "authorize_error", f"OrcaRouter authorization failed: {err}")
                if not code:
                    raise AuthError("missing_code", "OrcaRouter redirect carried no code")
            else:
                self._print("authorize in a browser, then paste the code shown on the consent page")
                if self.cancel_reason:
                    raise AuthError("cancelled", f"OrcaRouter login cancelled ({self.cancel_reason})")
                try:
                    code = (self._read_code("Code: ") or "").strip()
                except (EOFError, KeyboardInterrupt):
                    raise AuthError("cancelled", "OrcaRouter login cancelled") from None
                if self.cancel_reason:
                    raise AuthError("cancelled", f"OrcaRouter login cancelled ({self.cancel_reason})")
                if not code:
                    raise AuthError("missing_code", "no OrcaRouter code entered")

            result = self._exchange(
                exchange_url=self.origins.exchange_url(),
                code=code,
                verifier=verifier,
            )
        finally:
            self._pending = None
            if receiver is not None:
                receiver.close()

        cred = OrcaCredential(
            key=result.key,
            source=self.source,
            scope=result.scope or "",
            user_id=result.user_id,
            generation=secrets.token_hex(8),
        )
        self.store.save(cred)
        return cred


# ------------------------------------------------------------------- seam facade


def resolve_credential(
    *,
    method: str,
    models_path: Path,
    env: Optional[Mapping[str, str]] = None,
    prompt: Optional[Callable[[str], str]] = None,
    pkce: Optional[PkceAdapter] = None,
) -> OrcaCredential:
    """Single credential seam for the OrcaRouter provider.

    ``method`` is ``api_key`` or ``pkce``; both return the same
    :class:`OrcaCredential`, so provider wiring never branches on how the key
    was obtained.
    """
    store = CredentialStore(models_path)
    if method == "pkce":
        stored = store.load()
        if stored is not None and stored.status == STATUS_OK:
            # Reuse the durable key; never re-authorize on every launch.
            return stored
        adapter = pkce or PkceAdapter(store, origins=Origins.from_env(env))
        return adapter.acquire()
    if method == "api_key":
        return ApiKeyAdapter(store, env=env, prompt=prompt).acquire()
    raise AuthError("bad_method", f"unknown auth method {method!r} (use api_key or pkce)")
