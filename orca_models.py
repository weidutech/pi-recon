"""OrcaRouter Cyber Inference model catalog: verified seed + bounded live discovery.

The single source of truth for the OrcaRouter model list is
``GET {api_origin}/v1/models``.  Auth keys travel only on the server/CLI side
(never to a browser).  Live discovery is authoritative, but bounded (timeout,
byte cap, item cap, accepted shapes); when it fails the verified seed below
keeps a fresh install usable and its metadata (context, text-only input,
reasoning) is preserved.

The seed uses OrcaRouter-branded model ids only.  Live entries whose route is
not text chat (image generation, video, rerank, embeddings) are filtered out of
the text picker: PI Recon only ever sends text prompts to the reconnaissance
agent, so no multimodal catalog entry is offered.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional, Tuple

CATALOG_VERSION = 1
MAX_BYTES = 512 * 1024
MAX_ITEMS = 1000
TIMEOUT_SEC = 10.0
TEXT_ENDPOINT_TYPES = {"openai", "anthropic", "gemini", "openai-response"}
NON_TEXT_ENDPOINT_TYPES = {"image-generation", "openai-video", "jina-rerank", "embeddings"}
CHAT_ENDPOINT_MARKERS = frozenset(TEXT_ENDPOINT_TYPES)
TEXT_ONLY_INPUT = frozenset({"text"})

DEFAULT_MODEL = "orcarouter/auto"
CYBER_ULTRA = "orca/orcacyber-ultra-1.0"
CYBER_ZERO = "orca/orcacyber-zero-1.5"
CYBER_MODELS = (CYBER_ULTRA, CYBER_ZERO)
FALLBACK_MODEL = "orcarouter/fusion"

# Verified cold-start seed.  Only OrcaRouter-branded ids; text-only input.
# The OrcaCyber tiers carry the ``orca/`` vendor namespace used by GET /v1/models
# (live catalog checked 2026-11-08: ``orca/orcacyber-ultra-1.0``,
# ``orca/orcacyber-zero-1.5``); the bare ``orcacyber-*`` spelling is accepted as
# an alias so an older config keeps working.  Capabilities come from the live
# entry (context_length, architecture.input_modalities, supported_parameters)
# when discovery succeeds; the seed keeps only what was verified.
SEED_MODELS: Tuple[Dict, ...] = (
    {
        "id": DEFAULT_MODEL,
        "name": "OrcaRouter Auto",
        "reasoning": False,
        "input": ["text"],
        "contextWindow": 128000,
        "maxTokens": 8192,
        "api": "openai-completions",
        "tier": "default",
    },
    {
        "id": CYBER_ULTRA,
        "name": "OrcaCyber Ultra",
        "reasoning": True,
        "input": ["text"],
        "contextWindow": 1048576,
        "maxTokens": 384000,
        "api": "openai-completions",
        "tier": "cyber",
    },
    {
        "id": CYBER_ZERO,
        "name": "OrcaCyber Zero",
        "reasoning": True,
        "input": ["text"],
        "contextWindow": 1000000,
        "maxTokens": 384000,
        "api": "openai-completions",
        "tier": "cyber",
    },
    {
        "id": FALLBACK_MODEL,
        "name": "OrcaRouter Fusion",
        "reasoning": False,
        "input": ["text"],
        "contextWindow": 1000000,
        "maxTokens": 8192,
        "api": "openai-completions",
        "tier": "fallback",
    },
)

ALIASES = {
    "orcacyber-ultra-1.0": CYBER_ULTRA,
    "orcacyber-zero-1.5": CYBER_ZERO,
}

class CredentialRejected(Exception):
    """The relay answered 401: the credential is revoked/invalid (terminal, not transient)."""

    def __init__(self, generation: str = "", message: str = "credential rejected"):
        super().__init__(message)
        self.generation = generation


SEED_SOURCE = "seed"
LIVE_SOURCE = "live"
LKG_SOURCE = "last-known-good"


@dataclass
class Catalog:
    models: List[Dict] = field(default_factory=list)
    source: str = SEED_SOURCE
    degraded: bool = True
    detail: str = ""

    @property
    def ids(self) -> List[str]:
        return [m["id"] for m in self.models]

    def has(self, model_id: str) -> bool:
        return any(m["id"] == model_id for m in self.models)

    def resolve(self, model_id: Optional[str]) -> str:
        """Return ``model_id`` if still offered, else the provider default."""
        model_id = ALIASES.get((model_id or "").strip(), (model_id or "").strip())
        if model_id and self.has(model_id):
            return model_id
        return self.default_id()

    def default_id(self) -> str:
        if self.has(DEFAULT_MODEL):
            return DEFAULT_MODEL
        if self.models:
            return self.models[0]["id"]
        return DEFAULT_MODEL

    def to_provider_models(self) -> List[Dict]:
        """Drop catalog-only keys (``tier``) before writing ``models.json``."""
        out = []
        for m in self.models:
            out.append({k: v for k, v in m.items() if k != "tier"})
        return out

    def chat_options(self) -> List[Dict]:
        """Text chat/agent selector options: chat routes only, text input only."""
        out = []
        for m in self.models:
            declared = set(m.get("endpointTypes") or [])
            if declared and not CHAT_ENDPOINT_MARKERS & declared:
                continue
            if not TEXT_ONLY_INPUT.issubset(set(m.get("input") or [])):
                continue
            out.append(m)
        return out

    def multimodal_options(self, modality: str) -> List[Dict]:
        """Understanding selectors: chat route *and* an explicit declaration of the modality."""
        return [m for m in self.chat_options() if modality in (m.get("input") or [])]

    def options_for(self, modality: Optional[str] = None) -> List[Dict]:
        return self.chat_options() if not modality else self.multimodal_options(modality)


def seed_catalog() -> Catalog:
    return Catalog(models=[dict(m) for m in SEED_MODELS], source=SEED_SOURCE, degraded=True, detail="verified seed")


def parse_catalog(body: str, *, source: str = LIVE_SOURCE) -> Catalog:
    """Parse ``GET /v1/models`` (OpenAI shape or ``{"models": [...]}``), bounded and filtered."""
    try:
        data = json.loads(body)
    except json.JSONDecodeError:
        raise ValueError("catalog is not JSON")
    items = None
    if isinstance(data, dict):
        items = data.get("data", data.get("models"))
    elif isinstance(data, list):
        items = data
    if not isinstance(items, list):
        raise ValueError("catalog has no model list")

    models: List[Dict] = []
    seen = set()
    for raw in items[:MAX_ITEMS]:
        entry = _normalize(raw)
        if entry is None or entry["id"] in seen:
            continue
        seen.add(entry["id"])
        models.append(entry)
    return Catalog(models=models, source=source, degraded=False, detail=f"{len(models)} models")


def _endpoint_types(raw: Dict) -> List[str]:
    types = raw.get("supported_endpoint_types") or raw.get("supportedEndpointTypes") or []
    if isinstance(types, str):
        types = [types]
    if not isinstance(types, list):
        return []
    return [str(t) for t in types]


def _input_modalities(raw: Dict) -> Optional[List[str]]:
    arch = raw.get("architecture") if isinstance(raw.get("architecture"), dict) else {}
    mods = arch.get("input_modalities", raw.get("input_modalities"))
    if mods is None and isinstance(raw.get("input"), list):
        mods = raw["input"]
    if mods is None:
        return None  # undeclared: fail closed for non-text requirements
    if isinstance(mods, str):
        mods = [mods]
    if not isinstance(mods, list):
        return None
    return [str(m) for m in mods if str(m)]


def _normalize(raw: object) -> Optional[Dict]:
    if not isinstance(raw, dict):
        return None
    model_id = str(raw.get("id") or "").strip()
    if not model_id or "/" not in model_id or len(model_id) > 200:
        return None  # vendor/model namespace is kept verbatim; reject junk
    types = _endpoint_types(raw)
    if types and not (set(types) & TEXT_ENDPOINT_TYPES):
        return None  # not a chat route (image / video / rerank / embedding only)
    if set(types) & NON_TEXT_ENDPOINT_TYPES and not (set(types) & TEXT_ENDPOINT_TYPES):
        return None
    mods = _input_modalities(raw)
    if mods is not None and "text" not in mods:
        return None
    try:
        ctx = int(raw.get("context_length") or raw.get("contextWindow") or raw.get("context_window") or 0)
    except (TypeError, ValueError):
        ctx = 0
    try:
        max_tokens = int(raw.get("max_output_tokens") or raw.get("maxTokens") or raw.get("max_tokens") or 0)
    except (TypeError, ValueError):
        max_tokens = 0
    entry = {
        "id": model_id,
        "name": str(raw.get("name") or model_id)[:120],
        "reasoning": bool(raw.get("reasoning") or (raw.get("supports_reasoning") is True)),
        "input": ["text"],
        "api": "openai-completions",
    }
    # Keep the declared modalities and endpoint types for the selector filters;
    # the text-chat guarantee stays enforced above (text must be present).
    if mods:
        entry["input"] = list(dict.fromkeys(mods))
    if types:
        entry["endpointTypes"] = list(types)
    if ctx > 0:
        entry["contextWindow"] = ctx
    if max_tokens > 0:
        entry["maxTokens"] = max_tokens
    return entry


def fetch_catalog(
    api_root: str,
    api_key: str,
    *,
    timeout: float = TIMEOUT_SEC,
    credential_generation: str = "",
) -> Catalog:
    """``GET {api_root}/v1/models`` with Bearer auth; bounded read; raises on any failure."""
    url = api_root.rstrip("/") + "/models"
    req = urllib.request.Request(
        url,
        headers={
            "Authorization": f"Bearer {api_key}",
            "Accept": "application/json",
            "User-Agent": f"pi-recon-orcarouter/1 (+https://www.orcarouter.ai/cyber; inference)",
        },
        method="GET",
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            status = getattr(resp, "status", 200)
            if status != 200:
                raise ValueError(f"HTTP {status}")
            body = resp.read(MAX_BYTES + 1).decode("utf-8", errors="replace")
    except urllib.error.HTTPError as e:
        if e.code == 401:
            raise CredentialRejected(credential_generation, "OrcaRouter rejected the key (401)")
        raise
    if len(body) > MAX_BYTES:
        raise ValueError("catalog too large")
    return parse_catalog(body)


def discover_catalog(
    api_root: str,
    api_key: str,
    *,
    last_known_good: Optional[List[Dict]] = None,
    fetch=fetch_catalog,
    credential_generation: str = "",
) -> Catalog:
    """Live catalog when it works; else last-known-good; else the verified seed.

    A 401 is terminal: :class:`CredentialRejected` propagates so the caller can
    mark exactly this credential generation ``needs_reauth`` instead of quietly
    serving a stale seed forever.
    """
    try:
        live = fetch(api_root, api_key, credential_generation=credential_generation)
        if not live.models:
            raise ValueError("empty catalog")
        return live
    except CredentialRejected:
        raise
    except (urllib.error.URLError, OSError, ValueError, TimeoutError) as e:  # noqa: BLE001
        detail = f"{type(e).__name__}: {e}"
    if last_known_good:
        return Catalog(models=[dict(m) for m in last_known_good], source=LKG_SOURCE, degraded=True, detail=detail)
    cat = seed_catalog()
    cat.detail = detail
    return cat


def load_last_known_good(provider_entry: Dict) -> Optional[List[Dict]]:
    cat = provider_entry.get("orcaCatalog") if isinstance(provider_entry, dict) else None
    if not isinstance(cat, dict):
        return None
    models = cat.get("models")
    if not isinstance(models, list):
        return None
    out = []
    for m in models[:MAX_ITEMS]:
        norm = _normalize(m) if isinstance(m, dict) else None
        if norm:
            out.append(norm)
    return out or None
