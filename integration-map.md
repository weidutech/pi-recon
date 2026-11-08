# OrcaRouter integration map — pi-recon

- Repository: weidutech/pi-recon (thin Python 3.10+ AI red-team harness around the `pi` coding agent CLI)
- Default branch: `main` · PR base: `main`
- Base SHA: `7398358a27f174b0b6f2b39c2ab07884a24bdeac`
- Work branch: `feat/orcarouter-provider`
- Integration scope: `api_key_pkce` — API key **and** OAuth 2.0 + PKCE, profile `cli`
- OAuth seam: implemented in-repo (`orca_auth.PkceAdapter`, no client secret), `has_oauth_seam: true`
- Serve hint: none (CLI tool; no web UI)

## Where the provider lives

| Concern | File | Notes |
| --- | --- | --- |
| Provider id / name / base URL / route | `net_llm.py` | `ORCAROUTER_PROVIDER="orcarouter"`, name `OrcaRouter Cyber Inference`, `https://api.orcarouter.ai/v1`; pinned so hosted-gateway rewriting never touches OrcaRouter |
| Credential seam (API key, PKCE, store) | `orca_auth.py` | `ApiKeyAdapter`, `PkceAdapter` (S256, state, loopback + OOB), `CredentialStore` |
| Model catalog | `orca_models.py` | live `GET /v1/models` → last-known-good → verified seed; text-only filter; alias `orcacyber-*` → `orca/orcacyber-*` |
| `pi` models.json entry | `net_llm.setup_orcarouter` | `api: openai-completions`, `apiKey`, `orcaAuth` metadata, `orcaCatalog` LKG |
| CLI entry | `harvest.py` | `--provider orcarouter`, `--connect-orcarouter`, `--orcarouter-catalog`, `--orcarouter-model`, `--orca-auth {api_key,pkce}` |
| 401 → stop run | `harvest.py`, `agent_exec.py` | `PI_RECON_ORCA_KEEP=1` makes a revoked key fail the job instead of being retried |
| Docker | `docker/entrypoint.sh`, `docker/models.*.json` | auto catalog refresh at start; seeded provider blocks |
| Docs | `README.md`, `.env.example` | both auth methods, models, links |

## Endpoints used

- Auth origin `https://www.orcarouter.ai`: `/auth` (authorize), `/api/v1/auth/keys` (code exchange, `scope=api`)
- Inference `https://api.orcarouter.ai/v1`: `/models`, `/chat/completions`

## Defaults

- Default model: `orcarouter/auto`
- Recommended cyber models: `orca/orcacyber-ultra-1.0`, `orca/orcacyber-zero-1.5`
- General fallback: `orcarouter/fusion`
- `deepseek` remains available only as an explicit opt-in provider, never the default.
