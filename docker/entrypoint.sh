#!/usr/bin/env bash
# PI Recon harvester auto-start (first-pass recon only).
set -euo pipefail

export PATH="/app/tools/bin:/usr/local/bin:${PATH:-}"
export NO_PROXY="${NO_PROXY:-*}"
export no_proxy="${no_proxy:-*}"
export PYTHONUNBUFFERED=1
export PYTHONIOENCODING=utf-8
export PI_RECON_IN_DOCKER=1

# Prefer line-buffered stdio when platform scrapes docker logs
if command -v stdbuf >/dev/null 2>&1; then
  # re-exec once under stdbuf (guard with PI_RECON_STDBUF)
  if [[ -z "${PI_RECON_STDBUF:-}" ]]; then
    export PI_RECON_STDBUF=1
    exec stdbuf -oL -eL "$0" "$@"
  fi
fi

echo "[pi-recon] boot"
echo "[pi-recon] PYTHONUNBUFFERED=$PYTHONUNBUFFERED stdbuf=${PI_RECON_STDBUF:-0}"
echo "[pi-recon] BENCHMARK_BASE_URL=${BENCHMARK_BASE_URL:-<unset>}"
echo "[pi-recon] BENCHMARK_TOKEN set=$([ -n "${BENCHMARK_TOKEN:-}" ] && echo yes || echo no)"

if [[ -z "${BENCHMARK_BASE_URL:-}" || -z "${BENCHMARK_TOKEN:-}" ]]; then
  echo "[pi-recon] ERROR: BENCHMARK_BASE_URL and BENCHMARK_TOKEN required" >&2
  exit 2
fi

# Dedicated pi-recon key first; fall back only if operator reused a generic name
KEY="${PI_RECON_LLM_KEY:-${PI_RECON_API_KEY:-${DEEPSEEK_API_KEY:-${API_KEY:-${LLM_API_KEY:-}}}}}"
if [[ -z "$KEY" ]]; then
  echo "[pi-recon] ERROR: set PI_RECON_LLM_KEY" >&2
  exit 3
fi
export PI_RECON_LLM_KEY="$KEY"
export DEEPSEEK_API_KEY="$KEY"
export API_KEY="$KEY"
# OrcaRouter runs must not carry another provider's key in its legacy aliases:
# the credential seam only reads PI_RECON_LLM_KEY / PI_RECON_ORCA_KEY.
if [[ "${PI_RECON_LLM_PROVIDER:-${PROVIDER:-deepseek}}" == orcarouter* ]]; then
  unset DEEPSEEK_API_KEY API_KEY LLM_API_KEY PI_RECON_API_KEY
fi

PROVIDER="${PI_RECON_LLM_PROVIDER:-${PROVIDER:-deepseek}}"
MODEL="${PI_RECON_LLM_MODEL:-${MODEL:-}}"
if [[ -z "$MODEL" ]]; then
  # OrcaRouter defaults to the provider's auto model; others keep the historical default.
  case "$PROVIDER" in
    orcarouter*) MODEL="orcarouter/auto" ;;
    *) MODEL="deepseek-v4-flash" ;;
  esac
fi
BASE_HINT="${PI_RECON_LLM_BASE:-${DEEPSEEK_BASE_URL:-}}"
export PROVIDER MODEL
if [[ -n "$BASE_HINT" ]]; then
  export PI_RECON_LLM_BASE="$BASE_HINT"
  export DEEPSEEK_BASE_URL="$BASE_HINT"
fi

echo "[pi-recon] provider=$PROVIDER model=$MODEL route=${PI_RECON_LLM_ROUTE:-${LLM_ROUTE:-auto}}"
echo "[pi-recon] key_len=${#KEY}"

if [[ -f /root/.pi/agent/models.json ]]; then
  python3 - <<'PY'
import json, os
from pathlib import Path
mp = Path("/root/.pi/agent/models.json")
key = os.environ.get("PI_RECON_LLM_KEY") or ""
base = (os.environ.get("PI_RECON_LLM_BASE") or os.environ.get("DEEPSEEK_BASE_URL") or "").strip()
if not mp.is_file():
    raise SystemExit(0)
data = json.loads(mp.read_text(encoding="utf-8"))
provs = data.setdefault("providers", {})
if isinstance(provs.get("deepseek"), dict):
    if key:
        provs["deepseek"]["apiKey"] = key
    if base:
        provs["deepseek"]["baseUrl"] = base
    mp.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print("[pi-recon] models.json provider=deepseek base=", provs["deepseek"].get("baseUrl"), flush=True)
PY
fi

echo "[pi-recon] llm probe..."
python3 /app/net_llm.py || true

# OrcaRouter: credential seam (API key or PKCE) + live /v1/models -> models.json.
# The entrypoint already exports PI_RECON_LLM_KEY, which is the API-key adapter's input.
# --orcarouter-model drives both the connect step and the harvest run below.
ORCA_MODEL_ARGS=()
if [[ "$PROVIDER" == orcarouter* ]]; then
  echo "[pi-recon] orcarouter auth=${PI_RECON_ORCA_AUTH:-api_key} scope=${PI_RECON_ORCA_SCOPE:-auto} model=${MODEL}"
  ORCA_CONNECT_ARGS=(--provider orcarouter --orcarouter-catalog --no-prompt --orcarouter-model "${MODEL}")
  if [[ -n "${PI_RECON_ORCA_AUTH:-}" ]]; then
    ORCA_CONNECT_ARGS+=(--orca-auth "${PI_RECON_ORCA_AUTH}")
  fi
  ORCA_MODEL_ARGS=(--orcarouter-model "${MODEL}")
  if ! python3 /app/harvest.py "${ORCA_CONNECT_ARGS[@]}"; then
    echo "[pi-recon] ERROR: OrcaRouter connect failed - exiting so the orchestrator can restart with a fresh credential" >&2
    exit 3
  fi
fi

# Platform max active instances is typically 3
CONC="${PI_RECON_CONCURRENCY:-${MAX_PARALLEL:-3}}"
TO="${PI_RECON_JOB_TIMEOUT_SEC:-${WALL_CLOCK:-1200}}"
SEGS="${PI_RECON_SEGMENTS:-2}"
JOBS="${PI_RECON_JOBS_DIR:-${WORK_DIR:-/app/jobs}}"

echo "[pi-recon] parallel_slots=${CONC} job_timeout_sec=${TO} segments=${SEGS} jobs_dir=${JOBS}"
echo "[pi-recon] hint_after_fail=${PI_RECON_HINT_AFTER_FAIL:-1} second_wave=${PI_RECON_SECOND_WAVE:-1}"
echo "[pi-recon] endgame=${PI_RECON_ENDGAME:-1} endgame_max_rounds=${PI_RECON_ENDGAME_MAX_ROUNDS:-0} campaign_timeout=${PI_RECON_CAMPAIGN_TIMEOUT_SEC:-0}"
echo "[pi-recon] each stdout line will be tagged [unique_code]"

ARGS=(
  --concurrency "${CONC}"
  --job-timeout "${TO}"
  --segments "${SEGS}"
  --provider "${PROVIDER}"
  --model "${MODEL}"
  --api-key "${KEY}"
  --jobs-dir "${JOBS}"
)
ARGS+=("${ORCA_MODEL_ARGS[@]+"${ORCA_MODEL_ARGS[@]}"}")
# explicit flags from env (0 disables)
if [[ "${PI_RECON_HINT_AFTER_FAIL:-1}" == "0" ]]; then
  ARGS+=(--no-hint-after-fail)
fi
if [[ "${PI_RECON_SECOND_WAVE:-1}" == "0" ]]; then
  ARGS+=(--no-second-wave)
fi
# endgame default ON (unlimited rounds). Set PI_RECON_ENDGAME=0 to disable.
if [[ "${PI_RECON_ENDGAME:-1}" == "0" ]]; then
  ARGS+=(--no-endgame)
else
  ARGS+=(--endgame)
  ARGS+=(--endgame-max-rounds "${PI_RECON_ENDGAME_MAX_ROUNDS:-0}")
  ARGS+=(--campaign-timeout "${PI_RECON_CAMPAIGN_TIMEOUT_SEC:-0}")
fi

if [[ -n "${PI_RECON_ONLY:-${ONLY:-}}" ]]; then
  ARGS+=(--only "${PI_RECON_ONLY:-${ONLY}}")
fi
if [[ -n "${PI_RECON_THINKING:-${THINKING:-}}" ]]; then
  ARGS+=(--thinking "${PI_RECON_THINKING:-${THINKING}}")
fi

if [[ "${1:-}" == "--" ]]; then
  shift
fi
if [[ $# -gt 0 ]]; then
  echo "[pi-recon] extra: $*"
  exec python3 /app/harvest.py "${ARGS[@]}" "$@"
fi

exec python3 /app/harvest.py "${ARGS[@]}"
