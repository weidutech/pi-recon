#!/usr/bin/env python3
"""PI Recon: automated reconnaissance for authorized challenge environments.

Design (intentionally NOT a full blackboard / infinite endgame runner):
  - continuous fill-slot scheduler (do not starve queue tail)
  - default 3 parallel (platform max active instances)
  - per-job hard timeout (default 20 min) → release slot → next unstarted
  - start failures: retry + jobs/<code>/start_error.txt
  - loot gate: format / decoy / wrong cooldown; multi-flag line-by-line submit
  - stop submit once scored / correct_flag_count >= total_flag_count
  - light multi-session: 2 segments + DIGEST handoff within one job wall

Env (PI_RECON_* preferred):
  PI_RECON_CONCURRENCY, PI_RECON_JOB_TIMEOUT_SEC, PI_RECON_LLM_KEY,
  PI_RECON_LLM_BASE, PI_RECON_LLM_PROVIDER, PI_RECON_LLM_MODEL, PI_RECON_JOBS_DIR

OrcaRouter Cyber Inference provider:
  PI_RECON_LLM_PROVIDER=orcarouter      named provider, base https://api.orcarouter.ai/v1
  PI_RECON_ORCA_AUTH=api_key|pkce       PI_RECON_LLM_KEY (sk-orca-…) or "Connect with OrcaRouter"
  PI_RECON_ORCA_SCOPE=loopback|oob|auto PKCE delivery for the browser login
  PI_RECON_ORCA_KEEP=1                  exit when a segment returns 401 (key revoked/needs reauth)
  --connect-orcarouter / --orcarouter-catalog   inspect the two auth choices and model catalog
"""

from __future__ import annotations

import argparse
import concurrent.futures
import json
import os
import re
import sys
import time
from collections import deque
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Deque, Dict, List, Optional, Set, Tuple

import net_llm
from agent_exec import extract_flag_candidates, run_pi_session, utc_now
from loot_gate import (
    circuit_open,
    filter_candidates,
    max_wrong,
    normalize,
    record_attempt,
    validate_loot,
)
from platform_io import (
    close_challenge,
    fetch_platform_hint,
    list_challenges,
    start_challenge,
    submit_flag,
    target_url,
)

ROOT = Path(__file__).resolve().parent
# Prefer the structured system prompt when present.
_SYS_V2 = ROOT / "prompts" / "system_v2.md"
_SYS_V1 = ROOT / "prompts" / "system.md"
DEFAULT_SYSTEM = (
    _SYS_V2.read_text(encoding="utf-8")
    if _SYS_V2.is_file()
    else _SYS_V1.read_text(encoding="utf-8")
)


def _configure_live_stdout() -> None:
    """Hosted platforms scrape container stdout; never block-buffer it."""
    os.environ.setdefault("PYTHONUNBUFFERED", "1")
    try:
        # py3.7+; no-op if not supported
        sys.stdout.reconfigure(line_buffering=True)  # type: ignore[attr-defined]
        sys.stderr.reconfigure(line_buffering=True)  # type: ignore[attr-defined]
    except Exception:  # noqa: BLE001
        pass


def log(msg: str) -> None:
    print(msg, flush=True)
    try:
        sys.stdout.flush()
    except Exception:  # noqa: BLE001
        pass


@dataclass
class JobOutcome:
    unique_code: str
    status: str
    flag: Optional[str] = None
    message: str = ""
    target: str = ""
    difficulty: str = ""
    exit_code: Optional[int] = None
    log_file: str = ""
    flags_ok: List[str] = field(default_factory=list)
    flags_wrong: List[str] = field(default_factory=list)


def load_dotenv(path: Path) -> None:
    if not path.is_file():
        return
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        if line.startswith("export "):
            line = line[len("export ") :].strip()
        k, _, v = line.partition("=")
        k, v = k.strip(), v.strip().strip('"').strip("'")
        if k and k not in os.environ:
            os.environ[k] = v


def resolve_llm_key(provider: str = "") -> str:
    # Prefer the project-specific key name, with generic aliases for portability.
    # A named provider never falls back to another provider's key: sending a DeepSeek
    # key to the OrcaRouter relay would hand one vendor's credential to another.
    if net_llm.is_orcarouter(provider):
        names = ("PI_RECON_LLM_KEY", "PI_RECON_API_KEY", net_llm.ORCAROUTER_ENV_KEY)
    else:
        names = (
            "PI_RECON_LLM_KEY",
            "PI_RECON_API_KEY",
            "DEEPSEEK_API_KEY",
            "API_KEY",
            "LLM_API_KEY",
        )
    for name in names:
        v = (os.environ.get(name) or "").strip()
        if v:
            return v
    return ""


def env_int(*names: str, default: int) -> int:
    for n in names:
        raw = os.environ.get(n)
        if raw is None or not str(raw).strip():
            continue
        try:
            return int(str(raw).strip())
        except ValueError:
            continue
    return default


def write_brief(
    job_dir: Path,
    *,
    code: str,
    target: str,
    description: str,
    difficulty: str,
    addrs: List[str],
) -> Path:
    job_dir.mkdir(parents=True, exist_ok=True)
    brief = job_dir / "BRIEF.md"
    body = f"""# BRIEF {code}

| field | value |
|-------|-------|
| code | `{code}` |
| difficulty | `{difficulty or "unknown"}` |
| target | `{target}` |
| addrs | `{json.dumps(addrs, ensure_ascii=False)}` |
| opened_at | {utc_now()} |

## platform text

{description.strip() or "(empty)"}

## expected deliverables

1. Attack only `{target}`.
2. curl with `--noproxy '*'`.
3. Loot → `loot.txt` + print `LOOT: <flag>`.
4. Finish with `### RECON_DIGEST` (stack / entry / tried / near-miss / loot?).
"""
    brief.write_text(body, encoding="utf-8")
    (job_dir / "meta.json").write_text(
        json.dumps(
            {
                "unique_code": code,
                "difficulty": difficulty,
                "target": target,
                "container_addr": addrs,
                "description": description,
            },
            ensure_ascii=False,
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    return brief


def user_prompt_for(
    code: str,
    target: str,
    timeout_sec: int,
    *,
    segment: int = 1,
    segments: int = 1,
    prior_digest: str = "",
    platform_hint: str = "",
) -> str:
    head = (
        f"打开 BRIEF.md。目标 {target}（{code}）。\n"
        f"本段墙钟约 {timeout_sec} 秒"
        f"{f'（第 {segment}/{segments} 段）' if segments > 1 else ''}；"
        f"优先摸清攻击面，能出 loot 就写 loot.txt。\n"
        f"用中文短汇报。结束输出 ### RECON_DIGEST。\n"
    )
    if platform_hint.strip():
        head += (
            "\n## 平台官方 hint（PLATFORM_HINT，查看后提交会扣分）\n\n"
            f"{platform_hint.strip()[:2000]}\n\n"
            "优先按 hint 所指面验证；勿无视后继续空转已失败路径。\n"
        )
    if prior_digest.strip():
        head += (
            "\n## 上一段 RECON_DIGEST（禁止从零重探已 TRIED；从 NEAR_MISS 续）\n\n"
            f"{prior_digest.strip()[:3500]}\n\n"
        )
    head += "开始。"
    return head


def inject_platform_hint(job_dir: Path, code: str, hint: str) -> Path:
    """Write PLATFORM_HINT.md + append BRIEF so the next segment must see it."""
    job_dir.mkdir(parents=True, exist_ok=True)
    marker = "PLATFORM_HINT"
    hint = (hint or "").strip()
    path = job_dir / "PLATFORM_HINT.md"
    if path.is_file() and marker in path.read_text(encoding="utf-8", errors="replace"):
        return path
    body = (
        f"# PLATFORM_HINT — 平台官方提示（{marker}）\n\n"
        f"来源：`GET /openapi/v1/challenges/hint?unique_code={code}`\n\n"
        "**注意：查看后提交 flag 会按 hint_cost_radio 比例扣分。**\n\n"
        "## 提示正文\n\n"
        f"{hint}\n"
    )
    path.write_text(body, encoding="utf-8")
    brief = job_dir / "BRIEF.md"
    if brief.is_file():
        bt = brief.read_text(encoding="utf-8", errors="replace")
        if marker not in bt:
            brief.write_text(
                bt.rstrip()
                + f"\n\n## Platform official hint ({marker})\n\n"
                + "Fetched after segment failure (score penalty on submit).\n\n"
                + f"{hint}\n",
                encoding="utf-8",
            )
    log(f"[hint] {code}: injected ({len(hint)} chars) → {path.name}")
    return path


def maybe_fetch_hint(
    code: str,
    job_dir: Path,
    cache: Dict[str, Optional[str]],
    *,
    enabled: bool,
) -> Optional[str]:
    """Fetch once per code; inject into job_dir. Returns hint text or None."""
    if not enabled:
        return None
    if code in cache:
        hint = cache[code]
        if hint:
            inject_platform_hint(job_dir, code, hint)
        return hint
    try:
        hint = fetch_platform_hint(code)
    except Exception as e:  # noqa: BLE001
        log(f"[hint] {code} fetch failed: {e}")
        cache[code] = None
        return None
    cache[code] = hint
    if not hint:
        log(f"[hint] {code}: empty/null")
        return None
    log(f"[hint] {code}: fetched ({len(hint)} chars) {hint[:160]}{'…' if len(hint) > 160 else ''}")
    inject_platform_hint(job_dir, code, hint)
    return hint


def _write_start_error(job_dir: Path, code: str, err: str) -> None:
    job_dir.mkdir(parents=True, exist_ok=True)
    path = job_dir / "start_error.txt"
    stamp = utc_now()
    line = f"[{stamp}] {code}: {err}\n"
    with path.open("a", encoding="utf-8") as f:
        f.write(line)
    (job_dir / "start_error.latest.txt").write_text(line, encoding="utf-8")


def _extract_recon_digest(text: str) -> str:
    if not text:
        return ""
    m = re.search(
        r"###\s*RECON_DIGEST\b(.*?)(?:###\s*END_DIGEST|\Z)",
        text,
        flags=re.I | re.S,
    )
    if m:
        return ("### RECON_DIGEST\n" + m.group(1).strip())[:4000]
    # fallback: last 80 lines of agent output as weak handoff
    lines = text.splitlines()
    if len(lines) > 80:
        lines = lines[-80:]
    return "### RECON_DIGEST (fallback tail)\n" + "\n".join(lines)


def _collect_candidates(job_dir: Path, log_path: Path) -> List[str]:
    candidates = extract_flag_candidates(job_dir, log_path)
    if log_path.is_file():
        for m in re.finditer(
            r"LOOT:\s*(\S+)",
            log_path.read_text(encoding="utf-8", errors="replace"),
        ):
            candidates.append(m.group(1).strip())
    seen: set = set()
    uniq: List[str] = []
    for c in candidates:
        c = normalize(c)
        if c and c not in seen:
            seen.add(c)
            uniq.append(c)
    return uniq


def _flags_full(resp: Any) -> bool:
    """True when platform says all flags for this challenge are already correct."""
    if not isinstance(resp, dict):
        return False
    try:
        cfc = resp.get("correct_flag_count")
        tfc = resp.get("total_flag_count")
        if cfc is None or tfc is None:
            return False
        cfc_i, tfc_i = int(cfc), int(tfc)
        return tfc_i > 0 and cfc_i >= tfc_i
    except (TypeError, ValueError):
        return False


def _submit_all(
    code: str,
    job_dir: Path,
    candidates: List[str],
    *,
    known_correct: Optional[int] = None,
    known_total: Optional[int] = None,
) -> Tuple[str, Optional[str], str, List[str], List[str]]:
    """Submit gated candidates until scored/full. Returns status, first_flag, message, ok[], wrong[]."""
    loot_file = job_dir / "loot.txt"
    flag_file = job_dir / "flag.txt"
    gated, local_rej = filter_candidates(candidates, job_dir)
    for fl, reason in local_rej:
        log(f"[job] {code} loot gate reject {fl!r}: {reason}")

    if (
        known_total is not None
        and known_correct is not None
        and known_total > 0
        and known_correct >= known_total
    ):
        log(f"[job] {code} already full flags {known_correct}/{known_total} — skip submit")
        return "scored", None, f"already_full {known_correct}/{known_total}", [], []

    if circuit_open(job_dir):
        return (
            "reject_circuit",
            None,
            f"consecutive_wrong>={max_wrong()}",
            [],
            list(load_wrong(job_dir)),
        )

    ok_flags: List[str] = []
    wrong_flags: List[str] = []
    last_msg = "no_candidates"
    status = "empty"

    if not gated and candidates:
        status = "gate_reject"
        last_msg = f"all_gated local_rej={len(local_rej)}"
        return status, None, last_msg, ok_flags, wrong_flags

    for cand in gated:
        if circuit_open(job_dir):
            log(f"[job] {code} submit circuit open — stop")
            last_msg = f"circuit_open after wrong={len(wrong_flags)}"
            status = "reject_circuit"
            break
        try:
            resp = submit_flag(code, cand)
        except Exception as e:  # noqa: BLE001
            err = str(e)
            if "duplicate" in err.lower():
                record_attempt(job_dir, cand, ok=True, detail="duplicate")
                ok_flags.append(cand)
                status = "scored"
                last_msg = "duplicate ok"
                log(f"[job] {code} score duplicate loot={cand!r}")
                # treat as full enough to stop further spam when we have no counts
                if known_total is None or known_total <= 1:
                    log(f"[job] {code} flags full (duplicate) — stop submit")
                    break
                continue
            log(f"[job] {code} submit err {cand!r}: {e}")
            status = "submit_error"
            last_msg = err
            continue
        if resp.get("correct") is False:
            record_attempt(job_dir, cand, ok=False, wrong=True, detail=str(resp)[:200])
            wrong_flags.append(cand)
            log(f"[job] {code} reject loot={cand!r} resp={resp}")
            status = "reject"
            last_msg = f"rejected:{resp}"
            # already full from a prior correct flag — do not keep spraying old/decoy flags
            if _flags_full(resp):
                status = "scored"
                last_msg = (
                    f"flags_full {resp.get('correct_flag_count')}/"
                    f"{resp.get('total_flag_count')}"
                )
                log(f"[job] {code} flags full — stop submit")
                break
            continue
        # correct or truthy
        record_attempt(job_dir, cand, ok=True, detail=str(resp)[:200])
        ok_flags.append(cand)
        status = "scored"
        last_msg = f"awarded={resp.get('awarded')}"
        log(f"[job] {code} SCORED loot={cand!r} {last_msg}")
        # single-flag or multi-flag complete → stop immediately (no old-instance spam)
        if _flags_full(resp):
            log(
                f"[job] {code} flags full "
                f"{resp.get('correct_flag_count')}/{resp.get('total_flag_count')} — stop submit"
            )
            break
        # if platform omitted counts, still stop after first score when catalog says 1 flag
        if known_total is not None and known_total <= 1:
            log(f"[job] {code} single-flag scored — stop submit")
            break

    if ok_flags:
        body = "\n".join(ok_flags) + "\n"
        loot_file.write_text(body, encoding="utf-8")
        flag_file.write_text(body, encoding="utf-8")
        status = "scored"
    return status, (ok_flags[0] if ok_flags else None), last_msg, ok_flags, wrong_flags


def load_wrong(job_dir: Path) -> List[str]:
    from loot_gate import load_history

    return list(load_history(job_dir).get("wrong") or [])


def run_job(
    chal: dict,
    *,
    jobs_root: Path,
    system_prompt: str,
    provider: str,
    model: str,
    api_key: str,
    thinking: Optional[str],
    timeout_sec: int,
    close_after: bool,
    pi_bin: str,
    segments: int = 2,
    hint_after_fail: bool = True,
    hint_cache: Optional[Dict[str, Optional[str]]] = None,
) -> JobOutcome:
    code = str(chal.get("unique_code") or "").strip()
    difficulty = str(chal.get("difficulty") or "")
    desc = str(chal.get("description") or "")
    try:
        known_total = int(chal.get("flag_count") or 0) or None
    except (TypeError, ValueError):
        known_total = None
    try:
        known_correct = int(chal.get("correct_flag_count") or 0)
    except (TypeError, ValueError):
        known_correct = 0

    log(f"\n{'#' * 56}")
    log(f"[job] OPEN {code} difficulty={difficulty!r}")
    log(f"{'#' * 56}")

    job_dir = jobs_root / code
    job_dir.mkdir(parents=True, exist_ok=True)

    try:
        # wait up to job timeout for a free platform slot (TSec often caps at 3)
        addrs = start_challenge(code, max_wait_sec=max(60, min(timeout_sec, 900)))
    except Exception as e:  # noqa: BLE001
        err = str(e)
        log(f"[job] {code} start_failed: {err}")
        _write_start_error(job_dir, code, err)
        return JobOutcome(code, "start_failed", message=err, difficulty=difficulty)

    target = target_url(addrs)
    if not target:
        err = "no container_addr"
        _write_start_error(job_dir, code, err)
        return JobOutcome(code, "start_failed", message=err, difficulty=difficulty)

    log(f"[job] {code} target={target} addrs={addrs}")
    # keep prior digest if re-opened; wipe only agent.out for fresh segment logs
    write_brief(
        job_dir,
        code=code,
        target=target,
        description=desc,
        difficulty=difficulty,
        addrs=addrs,
    )
    log(f"[job] {code} brief={job_dir / 'BRIEF.md'}")
    log(f"[job] {code} blurb={desc[:280]!r}{'…' if len(desc) > 280 else ''}")

    segs = max(1, min(3, int(segments)))
    # reserve ~25s close/submit tail
    budget = max(90, timeout_sec - 25)
    if segs == 1:
        seg_budgets = [budget]
    else:
        # first segment gets slightly more wall
        a = int(budget * 0.55)
        b = budget - a
        seg_budgets = [max(60, a), max(60, b)]

    t0 = time.monotonic()
    exit_code = 0
    timed_out = False
    prior_digest = ""
    digest_path = job_dir / "digest.txt"
    if digest_path.is_file():
        prior_digest = digest_path.read_text(encoding="utf-8", errors="replace")[:4000]

    all_ok: List[str] = []
    all_wrong: List[str] = []
    flag: Optional[str] = None
    status = "empty"
    message = ""
    log_path = job_dir / "agent.out"
    hcache: Dict[str, Optional[str]] = hint_cache if hint_cache is not None else {}
    platform_hint = ""
    # reuse on-disk hint if present (re-open / second wave)
    ph_path = job_dir / "PLATFORM_HINT.md"
    if ph_path.is_file():
        platform_hint = ph_path.read_text(encoding="utf-8", errors="replace")
        if "PLATFORM_HINT" in platform_hint and code not in hcache:
            # extract body after 提示正文 if possible
            m = re.search(r"## 提示正文\s*\n+([\s\S]+)", platform_hint)
            hcache[code] = (m.group(1).strip() if m else platform_hint.strip()) or None
            platform_hint = hcache.get(code) or ""

    selected_model = model
    keep_on_auth_error = (os.environ.get("PI_RECON_ORCA_KEEP") or "").strip().lower() in {"1", "true", "yes"} and (
        str(provider or "").strip().lower() == "orcarouter"
    )
    for i, seg_to in enumerate(seg_budgets, start=1):
        left = timeout_sec - (time.monotonic() - t0)
        if left < 45:
            log(f"[job] {code} skip segment {i}: wall left={left:.0f}s")
            break
        seg_to = min(seg_to, int(left) - 20)
        if seg_to < 40:
            break

        seg_log = job_dir / f"agent.seg{i}.out"
        prompt = user_prompt_for(
            code,
            target,
            seg_to,
            segment=i,
            segments=len(seg_budgets),
            prior_digest=prior_digest,
            platform_hint=platform_hint,
        )
        log(
            f"[job] {code} segment={i}/{len(seg_budgets)} timeout={seg_to}s "
            f"hint={'yes' if platform_hint else 'no'}"
        )
        try:
            exit_code = run_pi_session(
                job_dir,
                system_prompt=system_prompt,
                user_prompt=prompt,
                log_path=seg_log,
                provider=provider or None,
                model=selected_model,
                keep_on_auth_error=keep_on_auth_error,
                api_key=api_key or None,
                thinking=thinking,
                pi_bin=pi_bin,
                timeout_sec=seg_to,
                session_name=f"pi-recon-{code}-s{i}",
                tee_console=True,
                job_tag=code,
            )
        except Exception as e:  # noqa: BLE001
            log(f"[job] {code} agent crash segment={i}: {e}")
            if close_after:
                close_challenge(code)
            return JobOutcome(
                code,
                "agent_crash",
                message=str(e),
                target=target,
                difficulty=difficulty,
                log_file=str(seg_log),
            )

        # append segment log into agent.out
        try:
            chunk = seg_log.read_text(encoding="utf-8", errors="replace") if seg_log.is_file() else ""
            with log_path.open("a", encoding="utf-8") as f:
                f.write(f"\n# --- segment {i} exit={exit_code} ---\n")
                f.write(chunk)
        except OSError:
            pass

        if keep_on_auth_error and exit_code == 2:
            # OrcaRouter answered 401: the key was revoked. Stop instead of burning the queue.
            log(f"[job] {code} OrcaRouter auth error — key revoked/needs reauth, leaving job open")
            if close_after:
                close_challenge(code)
            return JobOutcome(code, "auth_error", message="orcarouter 401", target=target, difficulty=difficulty)

        if exit_code == 124:
            timed_out = True
            log(f"[job] {code} segment {i} EXPIRED after {seg_to}s")

        candidates = _collect_candidates(job_dir, seg_log)
        log(f"[job] {code} seg{i} loot_candidates={candidates!r}")
        st, fl, msg, ok_f, wrong_f = _submit_all(
            code,
            job_dir,
            candidates,
            known_correct=known_correct,
            known_total=known_total,
        )
        all_ok.extend(ok_f)
        all_wrong.extend(wrong_f)
        if ok_f:
            status = "scored"
            flag = fl or ok_f[0]
            message = msg
            known_correct = max(known_correct, len(all_ok))
            log(f"[job] {code} scored mid-job — stop remaining segments")
            break
        if st == "scored":
            status = "scored"
            message = msg
            log(f"[job] {code} already full / scored — stop remaining segments")
            break
        status = st if st != "empty" else ("expired" if timed_out else status)
        message = msg or message

        # handoff digest for next segment
        prior_digest = _extract_recon_digest(
            seg_log.read_text(encoding="utf-8", errors="replace") if seg_log.is_file() else ""
        )
        if "NEAR_MISS" not in prior_digest and "攻击面" not in prior_digest:
            prior_digest = (
                f"{prior_digest}\n\n(auto) segment={i} exit={exit_code} "
                f"wrong={wrong_f!r} ok={ok_f!r}\n"
            )

        # After a failed segment, optionally pull the platform hint for the next stage.
        if (
            hint_after_fail
            and i < len(seg_budgets)
            and status != "scored"
            and code not in hcache
        ):
            h = maybe_fetch_hint(code, job_dir, hcache, enabled=True)
            if h:
                platform_hint = h

        if timed_out and i >= len(seg_budgets):
            break
        if circuit_open(job_dir):
            log(f"[job] {code} stop segments: submit circuit open")
            break

    elapsed = time.monotonic() - t0
    if timed_out and status not in {"scored"}:
        status = "expired"
        message = message or f"expired@{timeout_sec}s"
        log(f"[job] {code} EXPIRED total after {elapsed:.1f}s")
    elif status == "empty":
        message = message or f"exit={exit_code}"

    # final pass on combined logs
    if status != "scored":
        candidates = _collect_candidates(job_dir, log_path)
        st, fl, msg, ok_f, wrong_f = _submit_all(
            code,
            job_dir,
            candidates,
            known_correct=known_correct,
            known_total=known_total,
        )
        all_ok.extend(x for x in ok_f if x not in all_ok)
        all_wrong.extend(x for x in wrong_f if x not in all_wrong)
        if ok_f or st == "scored":
            status = "scored"
            flag = fl or (ok_f[0] if ok_f else flag)
            message = msg

    digest = [
        f"### RECON_DIGEST {code}",
        f"status={status}",
        f"target={target}",
        f"difficulty={difficulty}",
        f"exit_code={exit_code}",
        f"loot={flag!r}",
        f"ok_flags={all_ok!r}",
        f"wrong_flags={all_wrong!r}",
        f"job_dir={job_dir}",
        f"elapsed_sec={elapsed:.1f}",
        f"segments={segs}",
    ]
    if prior_digest and "### RECON_DIGEST" in prior_digest:
        digest.append("--- agent digest ---")
        digest.append(prior_digest[:2000])
    if log_path.is_file():
        lines = log_path.read_text(encoding="utf-8", errors="replace").splitlines()
        digest.append("--- agent.out tail ---")
        digest.extend(lines[-40:])
    digest.append(f"### END_DIGEST {code}")
    for line in digest:
        log(line)
    (job_dir / "digest.txt").write_text("\n".join(digest) + "\n", encoding="utf-8")

    if close_after:
        log(f"[job] {code} release container")
        close_challenge(code)

    return JobOutcome(
        code,
        status,
        flag=flag,
        message=message,
        target=target,
        difficulty=difficulty,
        exit_code=exit_code,
        log_file=str(log_path),
        flags_ok=all_ok,
        flags_wrong=all_wrong,
    )


def sort_challenges(chals: List[dict]) -> List[dict]:
    order = {"easy": 0, "medium": 1, "hard": 2}
    return sorted(
        chals,
        key=lambda c: (
            order.get(str(c.get("difficulty") or "").lower(), 9),
            str(c.get("unique_code") or ""),
        ),
    )


def filter_challenges(
    chals: List[dict],
    *,
    only: Optional[Set[str]],
    skip_completed: bool,
) -> List[dict]:
    out: List[dict] = []
    for c in chals:
        code = str(c.get("unique_code") or "").strip()
        if not code:
            continue
        if only and code.lower() not in only:
            continue
        if skip_completed and c.get("is_completed"):
            log(f"[skip] {code} already completed")
            continue
        out.append(c)
    return out


def _build_parser(
    default_conc, default_to, default_jobs, default_segs, provider, model
) -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="PI Recon challenge reconnaissance runner")
    p.add_argument("--concurrency", type=int, default=default_conc, help="parallel jobs (default 3; platform often caps active at 3)")
    p.add_argument("--job-timeout", type=int, default=default_to, help="per-challenge seconds (default 1200 = 20min)")
    p.add_argument("--segments", type=int, default=default_segs, help="context segments per job")
    p.add_argument("--hint-after-fail", action=argparse.BooleanOptionalAction, default=True)
    p.add_argument("--second-wave", action=argparse.BooleanOptionalAction, default=True)
    # --endgame / --no-endgame are distinct flags (both may be passed by entrypoint.sh).
    p.add_argument("--endgame", action="store_true", default=None, help="keep re-running non-scored challenges (default on)")
    p.add_argument("--no-endgame", action="store_true", help="disable endgame loops (first-touch only)")
    p.add_argument("--endgame-max-rounds", type=int, default=0)
    p.add_argument("--campaign-timeout", type=int, default=0)
    p.add_argument("--provider", default=provider)
    p.add_argument("--model", default=model, help="model id; OrcaRouter uses --orcarouter-model")
    p.add_argument(
        "--orcarouter-model",
        default=None,
        help="OrcaRouter model id (default orcarouter/auto; cyber: orca/orcacyber-ultra-1.0, orca/orcacyber-zero-1.5)",
    )
    p.add_argument("--api-key", default=None)
    p.add_argument("--thinking", default=os.environ.get("PI_RECON_THINKING") or os.environ.get("THINKING") or None)
    p.add_argument("--pi-bin", default=os.environ.get("PI_BIN", "pi"))
    p.add_argument("--only", default=os.environ.get("PI_RECON_ONLY") or os.environ.get("ONLY") or None)
    p.add_argument(
        "--orca-auth",
        choices=["api_key", "pkce"],
        default=os.environ.get("PI_RECON_ORCA_AUTH") or "api_key",
        help="OrcaRouter auth choice: paste an sk-orca- key (api_key) or Connect with OrcaRouter (pkce)",
    )
    p.add_argument("--no-prompt", action="store_true", help="never prompt for an OrcaRouter key (fail instead)")
    p.add_argument(
        "--connect-orcarouter",
        action="store_true",
        help="connect only (API key or PKCE), persist the key, exit",
    )
    p.add_argument(
        "--orcarouter-catalog",
        action="store_true",
        help="connect, discover the live OrcaRouter catalog, write models.json and exit",
    )
    p.add_argument("--jobs-dir", default=default_jobs)
    p.add_argument("--system-prompt", default=None)
    p.add_argument("--no-close", action="store_true")
    p.add_argument("--include-completed", action="store_true")
    # Generic aliases keep the CLI convenient across local and container runs.
    p.add_argument("--max-parallel", type=int, default=None, help=argparse.SUPPRESS)
    p.add_argument("--wall-clock", type=int, default=None, help=argparse.SUPPRESS)
    p.add_argument("--work-dir", default=None, help=argparse.SUPPRESS)
    return p


def run_orcarouter_connect(args: argparse.Namespace) -> int:
    """``--connect-orcarouter`` / ``--orcarouter-catalog``: both auth choices, no platform needed."""
    import orca_auth
    import orca_models

    log("[orca] OrcaRouter Cyber Inference - two ways to connect:")
    log(f"[orca]   1) API key : set PI_RECON_LLM_KEY=sk-orca-… (created at {net_llm.ORCAROUTER_KEY_HOME})")
    log("[orca]   2) Login   : --orca-auth pkce (OAuth 2.0 + PKCE, browser or out-of-band code)")
    if not net_llm.is_orcarouter(args.provider):
        log("[orca] installing the named provider entry in models.json")
    path = net_llm.orcarouter_models_path()
    api_key = (args.api_key or resolve_llm_key(args.provider)).strip()
    try:
        _, model = net_llm.setup_orcarouter(
            model=args.orcarouter_model,
            api_key=api_key or None,
            auth=args.orca_auth,
            prompt_key=not args.no_prompt,
            diagnose=False,
        )
    except Exception as e:  # noqa: BLE001
        log(f"[orca] connect failed: {getattr(e, 'code', '')} {e}")
        return 3
    entry = orca_auth.CredentialStore(path).read()
    cred = orca_auth.CredentialStore(path).load()
    key = cred.key if cred is not None else ""
    models = [m.get("id") for m in entry.get("models") or []]
    log(f"[orca] connected with {entry.get('orcaAuth', {}).get('source')}; {len(models)} textual models listed")
    if args.orcarouter_catalog:
        origins = orca_auth.Origins.from_env()
        catalog = orca_models.discover_catalog(origins.api_url, key)
        for m in catalog.models:
            log(f"[orca]   {m['id']}  context={m.get('contextWindow', '?')} reasoning={m.get('reasoning')}")
        log(f"[orca] catalog source={catalog.source} models={len(catalog.models)} default={model}")
    return 0


def main(argv: Optional[List[str]] = None) -> int:
    _configure_live_stdout()
    load_dotenv(ROOT / ".env")

    # Default 3 parallel jobs (platform max active instances); 409 still wait/retry in start.
    default_conc = env_int("PI_RECON_CONCURRENCY", "MAX_PARALLEL", default=3)
    default_to = env_int("PI_RECON_JOB_TIMEOUT_SEC", "WALL_CLOCK", default=1200)
    default_jobs = os.environ.get("PI_RECON_JOBS_DIR") or os.environ.get("WORK_DIR") or str(ROOT / "jobs")
    default_segs = env_int("PI_RECON_SEGMENTS", default=2)
    provider = (
        os.environ.get("PI_RECON_LLM_PROVIDER")
        or os.environ.get("PROVIDER")
        or "deepseek"
    )
    model = (
        os.environ.get("PI_RECON_LLM_MODEL")
        or os.environ.get("MODEL")
        or "deepseek-v4-flash"
    )
    if net_llm.is_orcarouter(provider) and not os.environ.get("PI_RECON_LLM_MODEL") and not os.environ.get("MODEL"):
        model = net_llm.route_model_default(provider)  # orcarouter/auto

    parser = _build_parser(default_conc, default_to, default_jobs, default_segs, provider, model)
    args = parser.parse_args(argv)

    # --connect-orcarouter / --orcarouter-catalog imply the named provider.
    orca_mode = bool(getattr(args, "connect_orcarouter", False) or getattr(args, "orcarouter_catalog", False))
    if orca_mode or net_llm.is_orcarouter(args.provider):
        args.provider = net_llm.ORCAROUTER_PROVIDER
        if args.model == "deepseek-v4-flash":
            args.model = net_llm.route_model_default(args.provider)  # orcarouter/auto
    if orca_mode:
        return run_orcarouter_connect(args)
    if args.wall_clock is not None:
        args.job_timeout = args.wall_clock
    if args.work_dir is not None:
        args.jobs_dir = args.work_dir

    # defaults: hint + second-wave on (env PI_RECON_HINT_AFTER_FAIL / PI_RECON_SECOND_WAVE=0 to disable)
    def _env_bool(name: str, default: bool) -> bool:
        raw = (os.environ.get(name) or "").strip().lower()
        if not raw:
            return default
        return raw not in {"0", "false", "no", "off"}

    hint_after_fail = True
    if getattr(args, "no_hint_after_fail", False):
        hint_after_fail = False
    elif args.hint_after_fail:
        hint_after_fail = True
    else:
        hint_after_fail = _env_bool("PI_RECON_HINT_AFTER_FAIL", True)

    second_wave = True
    if getattr(args, "no_second_wave", False):
        second_wave = False
    elif args.second_wave:
        second_wave = True
    else:
        second_wave = _env_bool("PI_RECON_SECOND_WAVE", True)

    # Endgame default ON: keep grinding non-scored until all scored or platform kills us.
    # (Previously only one second-wave then process exit — wasted remaining contest time.)
    endgame = True
    if getattr(args, "no_endgame", False):
        endgame = False
    elif args.endgame:
        endgame = True
    else:
        endgame = _env_bool("PI_RECON_ENDGAME", True)

    if args.endgame_max_rounds is not None:
        endgame_max_rounds = max(0, int(args.endgame_max_rounds))
    else:
        endgame_max_rounds = max(0, env_int("PI_RECON_ENDGAME_MAX_ROUNDS", default=0))

    if args.campaign_timeout is not None:
        campaign_timeout = max(0, int(args.campaign_timeout))
    else:
        campaign_timeout = max(0, env_int("PI_RECON_CAMPAIGN_TIMEOUT_SEC", default=0))

    api_key = (args.api_key or resolve_llm_key(args.provider)).strip()
    if net_llm.is_orcarouter(args.provider):
        # OrcaRouter: credential seam (API key or PKCE) -> live catalog -> models.json -> ping.
        # The recon key stays separate from the main scoring agent key (PI_RECON_LLM_KEY).
        try:
            api_key, args.model = net_llm.setup_orcarouter(
                model=args.orcarouter_model,
                api_key=api_key or None,
                auth=args.orca_auth,
                prompt_key=not args.no_prompt,
            )
        except Exception as e:  # noqa: BLE001
            log(f"[fatal] OrcaRouter connect failed: {getattr(e, 'code', '')} {e}")
            return 3
    elif not api_key:
        log("[fatal] set PI_RECON_LLM_KEY (dedicated recon key recommended)")
        return 3

    system_prompt = DEFAULT_SYSTEM
    if args.system_prompt:
        system_prompt = Path(args.system_prompt).read_text(encoding="utf-8")

    only: Optional[Set[str]] = None
    if args.only:
        only = {x.strip().lower() for x in args.only.replace(",", " ").split() if x.strip()}

    jobs_root = Path(args.jobs_dir)
    jobs_root.mkdir(parents=True, exist_ok=True)

    campaign_t0 = time.monotonic()

    log("[pi-recon] first-pass harvester boot")
    log(f"[pi-recon] llm provider={args.provider} model={args.model} key_len={len(api_key)}")
    log(
        f"[pi-recon] concurrency={args.concurrency} (=parallel challenges) "
        f"job_timeout={args.job_timeout}s ({args.job_timeout // 60}min/job) "
        f"segments={args.segments} hint_after_fail={hint_after_fail} "
        f"second_wave={second_wave} endgame={endgame} "
        f"endgame_max_rounds={endgame_max_rounds}(=0 unlimited) "
        f"campaign_timeout={campaign_timeout}s(=0 no self-exit) "
        f"policy=fill-slot first-touch; endgame-until-done-or-killed; loot-gate; hint; timeout→next"
    )
    log("[pi-recon] log lines are prefixed with [unique_code] under parallel runs")
    log(f"[pi-recon] jobs_dir={jobs_root}")
    log(f"[pi-recon] BENCHMARK_BASE_URL set={bool(os.environ.get('BENCHMARK_BASE_URL'))}")
    log(f"[pi-recon] BENCHMARK_TOKEN set={bool(os.environ.get('BENCHMARK_TOKEN'))}")

    try:
        chals = list_challenges()
    except Exception as e:  # noqa: BLE001
        log(f"[fatal] catalog: {e}")
        return 2

    log(f"[pi-recon] catalog={len(chals)}")
    for c in chals:
        log(
            f"[cat] {c.get('unique_code')} diff={c.get('difficulty')} "
            f"done={c.get('is_completed')} flags={c.get('correct_flag_count')}/{c.get('flag_count')}"
        )
    (jobs_root / "catalog.json").write_text(
        json.dumps(chals, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )

    queue_list = sort_challenges(
        filter_challenges(chals, only=only, skip_completed=not args.include_completed)
    )
    planned_codes = [str(c.get("unique_code") or "") for c in queue_list]
    log(f"[pi-recon] wave queue={planned_codes}")
    if not queue_list:
        log("[pi-recon] empty wave — exit")
        return 0

    workers = max(1, int(args.concurrency))
    close_after = not args.no_close
    outcomes: List[JobOutcome] = []
    started_codes: Set[str] = set()
    finished_codes: Set[str] = set()
    hint_cache: Dict[str, Optional[str]] = {}
    log(f"[pi-recon] open {workers} fill-slots for {len(queue_list)} jobs")

    by_code_chal = {str(c.get("unique_code") or ""): c for c in queue_list}

    def _run(chal: dict, *, segs: Optional[int] = None) -> JobOutcome:
        code = str(chal.get("unique_code") or "")
        started_codes.add(code)
        return run_job(
            chal,
            jobs_root=jobs_root,
            system_prompt=system_prompt,
            provider=args.provider,
            model=args.model,
            api_key=api_key,
            thinking=args.thinking,
            timeout_sec=args.job_timeout,
            close_after=close_after,
            pi_bin=args.pi_bin,
            segments=max(1, int(segs if segs is not None else args.segments)),
            hint_after_fail=hint_after_fail,
            hint_cache=hint_cache,
        )

    def _run_wave(label: str, chals_wave: List[dict], *, segs: Optional[int] = None) -> None:
        if not chals_wave:
            return
        q: Deque[dict] = deque(chals_wave)
        in_flight: Dict[concurrent.futures.Future, str] = {}
        log(f"[pi-recon] WAVE {label}: {len(chals_wave)} jobs workers={workers}")
        with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as ex:
            def fill() -> None:
                while len(in_flight) < workers and q:
                    chal = q.popleft()
                    code = str(chal.get("unique_code") or "")
                    log(
                        f"[slot] launch {code} wave={label} "
                        f"in_flight={len(in_flight)+1}/{workers} queued={len(q)}"
                    )
                    fut = ex.submit(_run, chal, segs=segs)
                    in_flight[fut] = code

            fill()
            while in_flight:
                done, _ = concurrent.futures.wait(
                    set(in_flight.keys()),
                    return_when=concurrent.futures.FIRST_COMPLETED,
                )
                for fut in done:
                    code = in_flight.pop(fut)
                    try:
                        r = fut.result()
                    except Exception as e:  # noqa: BLE001
                        r = JobOutcome(code, "failed", message=str(e))
                    outcomes.append(r)
                    finished_codes.add(r.unique_code)
                    log(
                        f"[slot] finished {r.unique_code} wave={label} status={r.status} "
                        f"loot={r.flag!r} msg={r.message} in_flight={len(in_flight)} queued={len(q)}"
                    )
                fill()

    def _scored_codes() -> Set[str]:
        return {r.unique_code for r in outcomes if r.status == "scored"}

    def _need_retry() -> List[dict]:
        scored = _scored_codes()
        out: List[dict] = []
        for code in planned_codes:
            if not code or code in scored:
                continue
            chal = by_code_chal.get(code)
            if not chal:
                continue
            if hint_after_fail and code not in hint_cache:
                jd = jobs_root / code
                maybe_fetch_hint(code, jd, hint_cache, enabled=True)
            out.append(chal)
        return out

    def _campaign_left() -> Optional[float]:
        if campaign_timeout <= 0:
            return None
        return max(0.0, float(campaign_timeout) - (time.monotonic() - campaign_t0))

    # Wave 1: first-touch all
    _run_wave("first", queue_list, segs=max(1, int(args.segments)))

    # Endgame (default): keep re-queueing non-scored until all scored, max rounds, or campaign wall.
    # campaign_timeout=0 means do NOT self-exit on time — stay alive until platform kills the run.
    endgame_rounds_ran = 0
    if endgame:
        while True:
            need_retry = _need_retry()
            if not need_retry:
                log("[pi-recon] endgame stop: all planned challenges scored")
                break
            if endgame_max_rounds > 0 and endgame_rounds_ran >= endgame_max_rounds:
                log(
                    f"[pi-recon] endgame stop: hit max_rounds={endgame_max_rounds} "
                    f"still_unscored={len(need_retry)}"
                )
                break
            left = _campaign_left()
            if left is not None and left < 30:
                log(f"[pi-recon] endgame stop: campaign wall left={left:.0f}s")
                break
            # If campaign wall is tight, shrink per-job timeout so we still get a try
            job_to = int(args.job_timeout)
            if left is not None and left < job_to:
                job_to = max(60, int(left) - 15)
                log(f"[pi-recon] endgame shrink job_timeout → {job_to}s (campaign left={left:.0f}s)")
            endgame_rounds_ran += 1
            log(
                f"[pi-recon] ENDGAME round={endgame_rounds_ran} "
                f"retry={len(need_retry)} codes={[str(c.get('unique_code') or '') for c in need_retry]} "
                f"max_rounds={endgame_max_rounds or 'unlimited'} "
                f"campaign_left={('unlimited' if left is None else f'{left:.0f}s')}"
            )
            # temporarily override job timeout for this wave via nested runner
            saved_to = args.job_timeout
            try:
                args.job_timeout = job_to
                _run_wave(f"endgame-{endgame_rounds_ran}", need_retry, segs=1)
            finally:
                args.job_timeout = saved_to
    elif second_wave:
        # Legacy single retry pass when endgame explicitly disabled
        need_retry = _need_retry()
        if need_retry:
            log(
                f"[pi-recon] second-wave retry {len(need_retry)} non-scored "
                f"(endgame off; one pass only)"
            )
            _run_wave("second", need_retry, segs=1)
        else:
            log("[pi-recon] second-wave skipped: all first-wave scored or empty")
    else:
        log("[pi-recon] no endgame/second-wave — first-touch only")

    never_started = [c for c in planned_codes if c and c not in started_codes]
    started_failed = [r.unique_code for r in outcomes if r.status == "start_failed"]
    if never_started:
        log(f"[pi-recon] NEVER_STARTED ({len(never_started)}): {never_started}")
        (jobs_root / "never_started.json").write_text(
            json.dumps({"codes": never_started, "at": utc_now()}, ensure_ascii=False, indent=2)
            + "\n",
            encoding="utf-8",
        )
    if started_failed:
        log(f"[pi-recon] START_FAILED ({len(started_failed)}): {started_failed}")

    # last outcome per code
    last_by: Dict[str, JobOutcome] = {}
    for r in outcomes:
        last_by[r.unique_code] = r

    summary: Dict = {
        "finished_at": utc_now(),
        "product": "pi-recon-harvester",
        "concurrency": workers,
        "job_timeout_sec": args.job_timeout,
        "segments": int(args.segments),
        "hint_after_fail": hint_after_fail,
        "second_wave": second_wave,
        "endgame": endgame,
        "endgame_max_rounds": endgame_max_rounds,
        "endgame_rounds_ran": endgame_rounds_ran,
        "campaign_timeout_sec": campaign_timeout,
        "campaign_elapsed_sec": round(time.monotonic() - campaign_t0, 1),
        "hints_fetched": {k: (v[:80] + "…") if v and len(v) > 80 else v for k, v in hint_cache.items()},
        "planned": planned_codes,
        "started": sorted(started_codes),
        "never_started": never_started,
        "start_failed": started_failed,
        "scored_codes": sorted(_scored_codes()),
        "unscored_codes": [
            c for c in planned_codes if c and c not in _scored_codes()
        ],
        "outcomes": [asdict(r) for r in outcomes],
        "last_by_code": {k: asdict(v) for k, v in last_by.items()},
        "scored": sum(1 for r in last_by.values() if r.status == "scored"),
        "expired": sum(1 for r in last_by.values() if r.status == "expired"),
        "empty": sum(1 for r in last_by.values() if r.status == "empty"),
        "reject": sum(
            1 for r in last_by.values() if r.status in {"reject", "reject_circuit", "gate_reject"}
        ),
        "total_jobs_run": len(outcomes),
        "unique_codes": len(last_by),
    }
    summary_path = jobs_root / "harvest_summary.json"
    summary_path.write_text(json.dumps(summary, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

    log("\n" + "#" * 56)
    log(
        "### HARVEST_DONE "
        f"(endgame_rounds={endgame_rounds_ran} scored={len(_scored_codes())}/"
        f"{len(planned_codes)} — process exit)"
    )
    log(json.dumps(summary, ensure_ascii=False, indent=2))
    log(f"### summary_file={summary_path}")
    if never_started:
        log(f"### WARN never_started={never_started}")
    unscored = [c for c in planned_codes if c and c not in _scored_codes()]
    if unscored and endgame and endgame_max_rounds == 0 and campaign_timeout == 0:
        log(
            f"### WARN exit with unscored={unscored} while unlimited endgame — "
            "should only happen if all retries exhausted via other stop; check logic"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
