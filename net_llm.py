"""Pick LLM base URL for hosted sandboxes (TSec gateway vs public)."""

from __future__ import annotations

import json
import os
import socket
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Optional, Tuple
from urllib.parse import urlparse, urlunparse

TSEC_GW_SUFFIX = ".tsecbench.gw"

# First-class named providers: id -> preset (base URL + OpenAI-compatible api kind).
# OrcaRouter is an OpenAI-compatible gateway; its relay lives at api.orcarouter.ai/v1.
ORCAROUTER_PROVIDER = "orcarouter"
ORCAROUTER_BASE_URL = "https://api.orcarouter.ai/v1"
ORCAROUTER_KEY_PREFIX = "sk-orca-"
ORCAROUTER_ENV_KEY = "ORCAROUTER" + "_API_KEY"  # optional explicit name; PI_RECON_LLM_KEY wins
ORCAROUTER_KEY_HOME = "https://www.orcarouter.ai/console/keys"
ORCAROUTER_NAME = "OrcaRouter Cyber Inference"
PROVIDER_PRESETS = {
    "deepseek": {"base_url": "https://api.deepseek.com/v1", "api": "openai-completions"},
    ORCAROUTER_PROVIDER: {"base_url": ORCAROUTER_BASE_URL, "api": "openai-completions"},
}
# Providers we rely on; upstream of them is never rewritten to a hosted gateway.
PINNED_PROVIDER_BASE_SUBSTRINGS = ("api.orcarouter.ai",)


def is_orcarouter(provider: str) -> bool:
    return (provider or "").strip().lower() == ORCAROUTER_PROVIDER


def preset_base_url(provider: str) -> str:
    preset = PROVIDER_PRESETS.get((provider or "").strip().lower())
    return (preset or {}).get("base_url", "")


def provider_api_kind(provider: str) -> str:
    preset = PROVIDER_PRESETS.get((provider or "").strip().lower())
    return (preset or {}).get("api", "openai-completions")


def default_models_path() -> Path:
    env_dir = (os.environ.get("PI_CODING_AGENT_DIR") or "").strip()
    if env_dir:
        return Path(env_dir).expanduser() / "models.json"
    # container image uses /root; local uses $HOME
    docker = Path("/root/.pi/agent/models.json")
    try:
        docker_present = docker.is_file()
    except OSError:  # unreadable HOME when not running as root
        docker_present = False
    if docker_present or os.environ.get("PI_RECON_IN_DOCKER"):
        return docker
    # the image sets /root/.pi/agent, but the agent itself may run as a non-root user
    # whose HOME is writable; prefer that over an unwritable /root
    home_path = Path.home() / ".pi" / "agent" / "models.json"
    if Path("/.dockerenv").exists() and not _writable_ancestor(home_path):
        return docker
    return home_path


def _writable_ancestor(path: Path) -> bool:
    """True when ``path`` already exists and is writable, or its nearest existing parent is."""
    candidate = path
    while True:
        try:
            if candidate.exists():
                return os.access(candidate, os.W_OK if candidate.is_file() else os.W_OK | os.X_OK)
        except OSError:
            return False
        if candidate.parent == candidate:
            return False
        candidate = candidate.parent


DEFAULT_MODELS = default_models_path()  # evaluated at import; prefer default_models_path() at runtime

@dataclass
class Route:
    mode: str
    base_url: str
    reason: str
    probe_ok: Optional[bool] = None


def _log(msg: str) -> None:
    print(msg, flush=True)


def inject_tsec_gw(url: str) -> str:
    raw = (url or "").strip()
    if not raw:
        return raw
    if TSEC_GW_SUFFIX in raw:
        return raw.replace("https://", "http://", 1) if raw.startswith("https://") else raw
    p = urlparse(raw)
    host = p.hostname or ""
    if not host:
        return raw
    if not host.endswith(TSEC_GW_SUFFIX):
        host = f"{host}{TSEC_GW_SUFFIX}"
    netloc = f"{host}:{p.port}" if p.port and p.port not in (80, 443) else host
    return urlunparse(("http", netloc, p.path or "", p.params, p.query, p.fragment))


def probe_tcp(url: str, timeout: float = 2.0) -> bool:
    p = urlparse(url if "://" in url else f"http://{url}")
    host = p.hostname or ""
    if not host:
        return False
    if p.port:
        port = p.port
    elif (p.scheme or "http") == "https":
        port = 443
    else:
        port = 80
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def read_models_base(provider: str = "deepseek", models_path: Optional[Path] = None) -> str:
    path = models_path or Path(os.environ.get("PI_MODELS_JSON") or str(default_models_path()))
    if not path.is_file():
        return (os.environ.get("DEEPSEEK_BASE_URL") or os.environ.get("LLM_BASE_URL") or "").strip()
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        bu = ((data.get("providers") or {}).get(provider) or {}).get("baseUrl") or ""
        return str(bu).strip().rstrip("/")
    except (OSError, json.JSONDecodeError, TypeError):
        return ""


def write_models_base(
    base_url: str,
    provider: str = "deepseek",
    models_path: Optional[Path] = None,
    models: Optional[list] = None,
) -> None:
    path = models_path or Path(os.environ.get("PI_MODELS_JSON") or str(default_models_path()))
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
    except OSError as e:
        _log(f"[llm] warn: cannot mkdir {path.parent}: {e}")
        return
    if path.is_file():
        data = json.loads(path.read_text(encoding="utf-8"))
    else:
        data = {"providers": {}}
    provs = data.setdefault("providers", {})
    if not isinstance(provs.get(provider), dict):
        entry = {
            "baseUrl": base_url,
            "api": provider_api_kind(provider),
            "models": [],
        }
        if is_orcarouter(provider):
            entry["name"] = "OrcaRouter Cyber Inference"
        provs[provider] = entry
    else:
        provs[provider]["baseUrl"] = base_url
    if models is not None:
        provs[provider]["models"] = list(models)
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def prefer_mode() -> str:
    route = (os.environ.get("PI_RECON_LLM_ROUTE") or os.environ.get("LLM_ROUTE") or "").strip().lower()
    if route in {"gateway", "gw", "tsec", "hosted"}:
        return "force_gateway"
    if route in {"public", "local", "direct", "baidu"}:
        return "force_public"
    if (os.environ.get("TSEC_HOSTED") or "").strip() in {"1", "true", "yes"}:
        return "force_gateway"
    return "auto"


def resolve_route(provider: str = "deepseek") -> Route:
    public = (
        (os.environ.get("PI_RECON_LLM_BASE") or os.environ.get("DEEPSEEK_BASE_URL") or os.environ.get("LLM_BASE_URL") or "").strip().rstrip("/")
        or read_models_base(provider)
        or preset_base_url(provider)
        or "https://api.deepseek.com/v1"
    )
    # Baidu AWD host must stay public (no tsec rewrite)
    if "agent-awd.baidu.com" in public:
        return Route("public", public, "baidu AWD gateway (no tsec rewrite)")
    # Named providers with a fixed public origin keep it public (no tsec rewrite)
    low = public.lower()
    for pinned in PINNED_PROVIDER_BASE_SUBSTRINGS:
        if pinned in low:
            return Route("public", public, f"{pinned} pinned public base (no tsec rewrite)")

    if TSEC_GW_SUFFIX in public:
        gw = inject_tsec_gw(public)
        return Route("gateway", gw, "base already gateway")

    gw = inject_tsec_gw(public)
    pref = prefer_mode()
    if pref == "force_public":
        return Route("public", public, "LLM_ROUTE=public")

    ok = probe_tcp(gw)
    if ok:
        return Route(
            "gateway",
            gw,
            f"tsec gateway reachable ({gw})",
            probe_ok=True,
        )
    if pref == "force_gateway":
        # still try gateway URL even if TCP probe failed (some sandboxes block probe weirdly)
        return Route(
            "gateway",
            gw,
            f"hosted force gateway but probe failed; still using {gw}",
            probe_ok=False,
        )
    # auto degrade
    pub_ok = probe_tcp(public)
    return Route(
        "public",
        public,
        f"gateway unreachable; public probe={'ok' if pub_ok else 'fail'} → {public}",
        probe_ok=False,
    )


def http_ping_chat(base_url: str, api_key: str, model: str, timeout: float = 20.0) -> Tuple[bool, str]:
    """Minimal OpenAI-compatible ping; returns (ok, detail)."""
    url = base_url.rstrip("/") + "/chat/completions"
    body = json.dumps(
        {
            "model": model,
            "messages": [{"role": "user", "content": "ping"}],
            "max_tokens": 8,
            "stream": False,
        }
    ).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=body,
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {api_key}",
            "User-Agent": "pi-recon-orcarouter/1 (+https://www.orcarouter.ai/cyber; inference)" if is_orcarouter(os.environ.get("PROVIDER") or "") else "pi-recon/1",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            text = resp.read().decode("utf-8", errors="replace")
            return True, f"HTTP {resp.status} body={text[:200]}"
    except urllib.error.HTTPError as e:
        text = e.read().decode("utf-8", errors="replace") if e.fp else str(e)
        # 4xx means network path works
        if 400 <= e.code < 500:
            return True, f"HTTP {e.code} (reachable) body={text[:200]}"
        return False, f"HTTP {e.code} body={text[:300]}"
    except Exception as e:  # noqa: BLE001
        return False, f"{type(e).__name__}: {e}"


def apply_route_and_diagnose(
    *,
    provider: str = "deepseek",
    model: Optional[str] = None,
    api_key: str = "",
) -> Route:
    model = model or os.environ.get("PI_RECON_LLM_MODEL") or route_model_default(provider)
    route = resolve_route(provider)
    write_models_base(route.base_url, provider=provider)
    os.environ["DEEPSEEK_BASE_URL"] = route.base_url
    os.environ["LLM_BASE_URL"] = route.base_url
    _log(f"[llm] route={route.mode} base={route.base_url}")
    _log(f"[llm] reason={route.reason} tcp_probe={route.probe_ok}")
    if api_key:
        ok, detail = http_ping_chat(route.base_url, api_key, model)
        _log(f"[llm] chat_ping ok={ok} detail={detail}")
        if not ok:
            # one more try: if public baidu-style failed and we weren't on gateway, try gateway of deepseek public
            if "agent-awd.baidu.com" in route.base_url and not is_orcarouter(provider):
                alt = "https://api.deepseek.com/v1"
                gw = inject_tsec_gw(alt)
                if probe_tcp(gw) or prefer_mode() in {"force_gateway", "auto"}:
                    _log(f"[llm] baidu base failed; trying TSec deepseek gateway {gw}")
                    write_models_base(gw, provider=provider)
                    os.environ["DEEPSEEK_BASE_URL"] = gw
                    ok2, detail2 = http_ping_chat(gw, api_key, model)
                    _log(f"[llm] chat_ping(alt) ok={ok2} detail={detail2}")
                    if ok2:
                        return Route("gateway", gw, "fallback from baidu to tsec deepseek", True)
            _log("[llm] WARNING: model API not reachable — pi sessions will print Connection error")
    else:
        _log("[llm] WARNING: no api key for chat_ping")
    return route


def diagnose_provider(
    provider: str, model: Optional[str] = None, api_key: str = "", models: Optional[list] = None
) -> Route:
    """Resolve the route for ``provider``, patch models.json and ping.

    Shared by the CLI entry point, ``harvest.py --diagnose-llm`` and the
    provider credential seam so every entry point routes the same way.
    """
    provider = (provider or "deepseek").strip()
    route = resolve_route(provider)
    write_models_base(route.base_url, provider=provider, models=models)
    os.environ["DEEPSEEK_BASE_URL"] = route.base_url
    os.environ["LLM_BASE_URL"] = route.base_url
    _log(f"[llm] provider={provider} route={route.mode} base={route.base_url}")
    _log(f"[llm] reason={route.reason} tcp_probe={route.probe_ok}")
    if models is not None:
        _log(f"[llm] models={len(models)} from catalog")
    if api_key:
        ok, detail = http_ping_chat(route.base_url, api_key, model or route_model_default(provider))
        _log(f"[llm] chat_ping ok={ok} detail={detail}")
        if not ok:
            _log("[llm] WARNING: model API not reachable — pi sessions will print Connection error")
    else:
        _log("[llm] WARNING: no api key for chat_ping")
    return route


def route_model_default(provider: str) -> str:
    if is_orcarouter(provider):
        return "orcarouter/auto"
    return os.environ.get("PI_RECON_LLM_MODEL") or "deepseek-v4-flash"


def orcarouter_auth_method() -> str:
    """``pkce`` only when explicitly asked for; default keeps existing key behaviour."""
    raw = (os.environ.get("PI_RECON_ORCA_AUTH") or "api_key").strip().lower()
    if raw in {"pkce", "oauth", "connect", "login"}:
        return "pkce"
    return "api_key"


def discover_with_reauth(api_url: str, cred, store, last_known) -> "orca_models.Catalog":
    """Live catalog lookup that turns a 401 into a generation-safe ``needs_reauth``."""
    import orca_models

    fetch = getattr(orca_models, "fetch_catalog")
    try:
        return orca_models.discover_catalog(
            api_url, cred.key, last_known_good=last_known, credential_generation=cred.generation, fetch=fetch
        )
    except orca_models.CredentialRejected:
        store.mark_needs_reauth(cred.generation)
        raise


def orcarouter_models_path() -> Path:
    return Path(os.environ.get("PI_MODELS_JSON") or str(default_models_path()))


def setup_orcarouter(
    *,
    model: Optional[str] = None,
    api_key: Optional[str] = None,
    auth: Optional[str] = None,
    catalog: Optional["orca_models.Catalog"] = None,
    prompt_key: bool = True,
    diagnose: bool = True,
) -> Tuple[str, str]:
    """Credential seam -> model catalog -> models.json -> optional ping.

    Both credential adapters (``api_key`` / ``pkce``) return the same
    ``OrcaCredential``; everything below this line only sees a key string, so
    provider wiring never branches on how the key was obtained.
    """
    import orca_auth
    import orca_models

    path = orcarouter_models_path()
    method = (auth or orcarouter_auth_method()).strip().lower()
    method = "pkce" if method == "pkce" else "api_key"
    if method == "pkce":
        flow = (os.environ.get("PI_RECON_ORCA_SCOPE") or "auto").strip().lower()
        if flow not in ("auto", "loopback", "oob"):
            _log(f"[orca] unknown PI_RECON_ORCA_SCOPE={flow!r}; using auto")
            flow = "auto"
    else:
        flow = "auto"
    env = dict(os.environ)
    if api_key and method == "api_key":
        env["PI_RECON_LLM_KEY"] = api_key
    # The API-key adapter only sees names/scoped to this provider.
    for foreign in ("DEEPSEEK" + "_API_KEY", "OPENAI" + "_API_KEY", "ANTHROPIC" + "_API_KEY"):
        env.pop(foreign, None)
    prompt = (lambda msg: input(msg)) if (prompt_key and method == "api_key" and not api_key and os.isatty(0)) else None
    pkce = orca_auth.PkceAdapter(orca_auth.CredentialStore(path), origins=orca_auth.Origins.from_env(env), flow=flow)
    cred = orca_auth.resolve_credential(method=method, models_path=path, env=env, prompt=prompt, pkce=pkce)

    origins = orca_auth.Origins.from_env()
    store = orca_auth.CredentialStore(path)
    last_known = orca_models.load_last_known_good(store.read())
    if catalog is None:
        catalog = discover_with_reauth(origins.api_url, cred, store, last_known)
    _log(
        f"[orca] catalog source={catalog.source} degraded={catalog.degraded} "
        f"models={len(catalog.models)} ({catalog.detail})"
    )
    if catalog.source in (orca_models.LIVE_SOURCE, orca_models.LKG_SOURCE) and not catalog.degraded:
        store.remember_catalog(catalog.to_provider_models())
    elif catalog.source == orca_models.SEED_SOURCE and last_known:
        store.forget_catalog()
    chosen = catalog.resolve(model or orca_models.DEFAULT_MODEL)
    requested = (model or "").strip()
    if requested and chosen != __import__("orca_models").ALIASES.get(requested, requested):
        _log(f"[orca] model {model!r} not in catalog; using {chosen!r}")

    if diagnose:
        diagnose_provider(ORCAROUTER_PROVIDER, model=chosen, api_key=cred.key, models=catalog.to_provider_models())
    else:
        write_models_base(origins.api_url, provider=ORCAROUTER_PROVIDER, models=catalog.to_provider_models())
        os.environ["DEEPSEEK_BASE_URL"] = origins.api_url
        os.environ["LLM_BASE_URL"] = origins.api_url
        _log(f"[llm] provider={ORCAROUTER_PROVIDER} base={origins.api_url}")
    _log(f"[orca] credential source={cred.source} key={cred.masked()} needs_reauth={cred.needs_reauth}")
    return cred.key, chosen


def orcarouter_models_json(models_path: Optional[Path] = None) -> dict:
    """The named provider entry written to models.json (used by docs/tests)."""
    import orca_models

    return {
        "name": ORCAROUTER_NAME,
        "baseUrl": ORCAROUTER_BASE_URL,
        "api": "openai-completions",
        "models": orca_models.seed_catalog().to_provider_models(),
    }


if __name__ == "__main__":
    provider = (os.environ.get("PROVIDER") or os.environ.get("PI_RECON_LLM_PROVIDER") or "deepseek").strip()
    key_names = ("PI_RECON_LLM_KEY", "PI_RECON_API_KEY")
    if not is_orcarouter(provider):
        key_names += ("DEEPSEEK_API_KEY", "API_KEY")
    key = next((os.environ[n].strip() for n in key_names if (os.environ.get(n) or "").strip()), "")
    diagnose_provider(
        provider=provider,
        model=os.environ.get("PI_RECON_LLM_MODEL") or os.environ.get("MODEL") or "deepseek-v4-flash",
        api_key=key,
    )
