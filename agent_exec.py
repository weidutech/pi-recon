"""Run one non-interactive `pi` session; tee + heartbeats + session jsonl mirror.

Why: pi often prints almost nothing to stdout while waiting on the LLM (or when
piped). Platform "live logs" look empty. We emit heartbeats and mirror
.pi-sessions/*.jsonl so progress is visible.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional, TextIO


def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _prefix_tag(tag: str, line: str) -> str:
    """Prefix challenge id on every console/file line so parallel jobs are separable."""
    t = (tag or "").strip()
    if not t:
        return line
    # avoid double-prefix
    if line.startswith(f"[{t}]") or line.startswith(f"# [{t}]"):
        return line
    if line.startswith("#"):
        return f"# [{t}] {line[1:].lstrip()}"
    return f"[{t}] {line}"


def _write(
    lock: threading.Lock,
    logf: TextIO,
    line: str,
    console: bool,
    tag: str = "",
) -> None:
    line = _prefix_tag(tag, line)
    if not line.endswith("\n"):
        line = line + "\n"
    with lock:
        logf.write(line)
        logf.flush()
        if console:
            sys.stdout.write(line)
            sys.stdout.flush()


def _tee(
    stream,
    logf: TextIO,
    lock: threading.Lock,
    console: bool,
    tag: str = "",
) -> None:
    try:
        for raw in iter(stream.readline, ""):
            _write(lock, logf, raw.rstrip("\n"), console, tag=tag)
    except Exception as e:  # noqa: BLE001
        _write(lock, logf, f"# tee error: {e}", console, tag=tag)


def _clip(text: str, n: int = 240) -> str:
    text = " ".join(str(text).split())
    if len(text) <= n:
        return text
    return text[: n - 1] + "…"


def _format_session_event(obj: dict) -> Optional[str]:
    if obj.get("type") != "message":
        return None
    msg = obj.get("message") or {}
    if not isinstance(msg, dict):
        return None
    role = msg.get("role") or "?"
    content = msg.get("content")
    ts = (obj.get("timestamp") or "")[-8:]
    head = f"[{ts}]"
    parts: List[str] = []

    if isinstance(content, str):
        parts.append(_clip(content))
    elif isinstance(content, list):
        for block in content:
            if not isinstance(block, dict):
                continue
            btype = block.get("type")
            if btype == "text" and block.get("text"):
                parts.append(_clip(str(block["text"])))
            elif btype == "thinking" and block.get("thinking"):
                parts.append("think:" + _clip(str(block["thinking"]), 160))
            elif btype in {"toolCall", "toolUse", "tool_use"}:
                name = block.get("name") or block.get("toolName") or "tool"
                args = block.get("arguments") or block.get("input") or {}
                if isinstance(args, dict):
                    summary = (
                        args.get("command")
                        or args.get("cmd")
                        or args.get("path")
                        or args.get("file_path")
                        or args.get("url")
                        or json.dumps(args, ensure_ascii=False)[:120]
                    )
                else:
                    summary = str(args)[:120]
                parts.append(f"call {name}: {_clip(str(summary), 200)}")
            elif btype in {"toolResult", "tool_result"}:
                text = block.get("text") or block.get("content") or ""
                if isinstance(text, list):
                    text = " ".join(
                        str(x.get("text", x)) if isinstance(x, dict) else str(x) for x in text
                    )
                parts.append("result:" + _clip(str(text), 200))

    if role == "toolResult":
        name = msg.get("toolName") or "tool"
        text = ""
        if isinstance(content, list):
            for block in content:
                if isinstance(block, dict) and block.get("text"):
                    text = str(block["text"])
                    break
        elif isinstance(content, str):
            text = content
        return f"{head} toolResult {name}: {_clip(text, 220)}"

    if not parts:
        return None
    if role == "assistant":
        return f"{head} assistant: " + " | ".join(parts)
    if role == "user":
        return f"{head} user: " + " | ".join(parts)
    return f"{head} {role}: " + " | ".join(parts)


def _mirror_session_jsonl(
    session_dir: Path,
    logf: TextIO,
    lock: threading.Lock,
    stop: threading.Event,
    console: bool,
    tag: str = "",
) -> None:
    offsets: dict[str, int] = {}
    _write(
        lock,
        logf,
        "# --- live session mirror (.pi-sessions/*.jsonl); stdout often empty while LLM waits ---",
        console,
        tag=tag,
    )
    while not stop.is_set():
        try:
            files = (
                sorted(p for p in session_dir.rglob("*.jsonl") if p.is_file())
                if session_dir.is_dir()
                else []
            )
            for path in files:
                key = str(path)
                pos = offsets.get(key, 0)
                try:
                    size = path.stat().st_size
                except OSError:
                    continue
                if size < pos:
                    pos = 0
                if size == pos:
                    continue
                try:
                    with path.open("r", encoding="utf-8", errors="replace") as f:
                        f.seek(pos)
                        chunk = f.read()
                        new_pos = f.tell()
                except OSError:
                    continue
                offsets[key] = new_pos
                for line in chunk.splitlines():
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        obj = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    if not isinstance(obj, dict):
                        continue
                    pretty = _format_session_event(obj)
                    if pretty:
                        _write(lock, logf, pretty, console, tag=tag)
        except Exception as e:  # noqa: BLE001
            _write(lock, logf, f"# mirror error: {e}", console, tag=tag)
        stop.wait(0.4)


def _heartbeat(
    logf: TextIO,
    lock: threading.Lock,
    stop: threading.Event,
    console: bool,
    t0: float,
    session_dir: Path,
    tag: str = "",
    timeout_sec: int = 0,
) -> None:
    n = 0
    # first tick sooner so platform logs are not blank for 15s
    intervals = [5.0, 10.0]
    while True:
        wait = intervals[min(n, len(intervals) - 1)] if n < 3 else 10.0
        if stop.wait(wait):
            break
        n += 1
        elapsed = time.monotonic() - t0
        n_jsonl = 0
        n_bytes = 0
        if session_dir.is_dir():
            files = [p for p in session_dir.rglob("*.jsonl") if p.is_file()]
            n_jsonl = len(files)
            n_bytes = 0
            for p in files:
                try:
                    n_bytes += p.stat().st_size
                except OSError:
                    pass
        left = max(0, int(timeout_sec - elapsed)) if timeout_sec else 0
        _write(
            lock,
            logf,
            f"# heartbeat n={n} elapsed={elapsed:.0f}s timeout_left={left}s pi_alive=1 "
            f"session_jsonl={n_jsonl} bytes={n_bytes} "
            f"(stdout live; waiting on model/tools if no new agent lines)",
            console,
            tag=tag,
        )


def which_pi(pi_bin: str = "pi") -> str:
    return shutil.which(pi_bin) or pi_bin


def _models_base_hint() -> str:
    for path in (
        Path(os.environ.get("PI_CODING_AGENT_DIR") or "") / "models.json",
        Path("/root/.pi/agent/models.json"),
        Path.home() / ".pi" / "agent" / "models.json",
    ):
        if not path.is_file():
            continue
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            bu = ((data.get("providers") or {}).get("deepseek") or {}).get("baseUrl")
            if bu:
                return str(bu)
        except (OSError, json.JSONDecodeError, TypeError):
            continue
    return os.environ.get("DEEPSEEK_BASE_URL") or os.environ.get("LLM_BASE_URL") or "<unknown>"


def run_pi_session(
    work_dir: Path,
    *,
    system_prompt: str,
    user_prompt: str,
    log_path: Path,
    provider: Optional[str] = None,
    model: Optional[str] = None,
    api_key: Optional[str] = None,
    thinking: Optional[str] = None,
    pi_bin: str = "pi",
    timeout_sec: int = 900,
    session_name: str = "session",
    tee_console: bool = True,
    extra_args: Optional[List[str]] = None,
    job_tag: str = "",
    keep_on_auth_error: bool = False,
) -> int:
    work_dir.mkdir(parents=True, exist_ok=True)
    log_path.parent.mkdir(parents=True, exist_ok=True)
    session_dir = work_dir / ".pi-sessions"
    session_dir.mkdir(parents=True, exist_ok=True)
    # challenge id for parallel log separation (a-05 / c-07 / ...)
    tag = (job_tag or work_dir.name or "").strip()

    pi = which_pi(pi_bin)
    cmd = [
        pi,
        "-p",
        "--approve",
        "--verbose",
        "--mode",
        "text",
        "--session-dir",
        str(session_dir),
        "--name",
        session_name,
        "--system-prompt",
        system_prompt,
    ]
    if provider:
        cmd.extend(["--provider", provider])
    if model:
        cmd.extend(["--model", model])
    if api_key:
        cmd.extend(["--api-key", api_key])
    if thinking:
        cmd.extend(["--thinking", thinking])
    if extra_args:
        cmd.extend(extra_args)
    cmd.append(user_prompt)

    meta_cmd = list(cmd)
    try:
        i = meta_cmd.index("--system-prompt")
        meta_cmd[i + 1] = f"<system_prompt {len(system_prompt)} chars>"
    except (ValueError, IndexError):
        pass
    try:
        i = meta_cmd.index("--api-key")
        meta_cmd[i + 1] = "<redacted>"
    except (ValueError, IndexError):
        pass
    if meta_cmd:
        meta_cmd[-1] = f"<user_prompt {len(user_prompt)} chars>"

    env = os.environ.copy()
    if provider.strip().lower() == "orcarouter":
        # pi reads the key from models.json; keep other vendors' credential names out of its env.
        for foreign in ("DEEPSEEK" + "_API_KEY", "OPENAI" + "_API_KEY", "ANTHROPIC" + "_API_KEY"):
            env.pop(foreign, None)
    env.setdefault("NO_PROXY", "*")
    env.setdefault("no_proxy", "*")
    env.setdefault("PYTHONUNBUFFERED", "1")
    # Prefer line-buffered node when piped
    env["NODE_OPTIONS"] = (env.get("NODE_OPTIONS") or "") + " --trace-uncaught"
    env.setdefault("FORCE_COLOR", "0")
    tools = Path("/app/tools/bin")
    if tools.is_dir():
        env["PATH"] = f"{tools}:{env.get('PATH', '')}"
    try:
        local_tools = work_dir.resolve().parents[1] / "tools" / "bin"
        if local_tools.is_dir():
            env["PATH"] = f"{local_tools}:{env.get('PATH', '')}"
    except IndexError:
        pass

    lock = threading.Lock()
    t0 = time.monotonic()
    exit_code = 1
    timed_out = False
    base_hint = _models_base_hint()

    with log_path.open("w", encoding="utf-8", errors="replace") as logf:
        header = (
            f"# pi-recon agent transcript job={tag}\n"
            f"# started_at={utc_now()}\n"
            f"# cwd={work_dir}\n"
            f"# timeout_sec={timeout_sec}\n"
            f"# llm_base_hint={base_hint}\n"
            f"# provider={provider} model={model} api_key_set={bool(api_key)}\n"
            f"# cmd={json.dumps(meta_cmd, ensure_ascii=False)}\n"
            f"# parallel logs: every line prefixed with [{tag or '?'}]\n"
            f"# --- begin ---\n"
        )
        _write(lock, logf, header.rstrip("\n"), tee_console, tag=tag)
        _write(lock, logf, f"# user_prompt_preview=\n{user_prompt[:1500]}", tee_console, tag=tag)
        _write(lock, logf, "# --- agent output ---", tee_console, tag=tag)
        _write(lock, logf, f"# spawning pi at {utc_now()} ...", tee_console, tag=tag)

        stop = threading.Event()
        mirror = threading.Thread(
            target=_mirror_session_jsonl,
            args=(session_dir, logf, lock, stop, tee_console, tag),
            daemon=True,
            name=f"jsonl-mirror-{tag or 'job'}",
        )
        heart = threading.Thread(
            target=_heartbeat,
            args=(logf, lock, stop, tee_console, t0, session_dir, tag, timeout_sec),
            daemon=True,
            name=f"heartbeat-{tag or 'job'}",
        )
        mirror.start()
        heart.start()

        try:
            proc = subprocess.Popen(
                cmd,
                cwd=str(work_dir),
                env=env,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
            )
            assert proc.stdout is not None
            _write(lock, logf, f"# pi pid={proc.pid}", tee_console, tag=tag)
            reader = threading.Thread(
                target=_tee,
                args=(proc.stdout, logf, lock, tee_console, tag),
                daemon=True,
                name=f"tee-{tag or 'job'}",
            )
            reader.start()
            try:
                exit_code = proc.wait(timeout=timeout_sec)
            except subprocess.TimeoutExpired:
                timed_out = True
                proc.kill()
                try:
                    proc.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    pass
                exit_code = 124
                _write(
                    lock,
                    logf,
                    f"# --- killed: timeout after {timeout_sec}s — slot free for next job ---",
                    tee_console,
                    tag=tag,
                )
            reader.join(timeout=5)
            if exit_code == 0 and keep_on_auth_error and auth_error_seen(log_path):
                exit_code = 2  # surfaced as JobOutcome("auth_error")
        except FileNotFoundError as e:
            _write(lock, logf, f"# --- failed to spawn pi: {e} ---", tee_console, tag=tag)
            exit_code = 127
        except Exception as e:  # noqa: BLE001
            _write(lock, logf, f"# --- runner error: {e} ---", tee_console, tag=tag)
            exit_code = 1
        finally:
            stop.set()
            mirror.join(timeout=2)
            heart.join(timeout=1)

        elapsed = time.monotonic() - t0
        # dump any leftover session jsonl names
        if session_dir.is_dir():
            files = list(session_dir.rglob("*"))
            _write(
                lock,
                logf,
                f"# session_dir files={[p.name for p in files[:20]]}",
                tee_console,
                tag=tag,
            )
        _write(
            lock,
            logf,
            f"# --- end exit={exit_code} elapsed_sec={elapsed:.2f} timed_out={timed_out} ---",
            tee_console,
            tag=tag,
        )

    meta = {
        "started_at": utc_now(),
        "cwd": str(work_dir),
        "exit_code": exit_code,
        "timed_out": timed_out,
        "timeout_sec": timeout_sec,
        "provider": provider,
        "model": model,
        "llm_base_hint": base_hint,
        "cmd": meta_cmd,
        "log_file": str(log_path),
    }
    (log_path.parent / (log_path.stem + ".meta.json")).write_text(
        json.dumps(meta, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    return exit_code


_AUTH_ERROR_RE = re.compile(
    r"(invalid[ _-]?api[ _-]?key|incorrect api key|401 unauthorized|unauthorized \(401|\b401\b[^\n]{0,40}api key)",
    re.IGNORECASE,
)


def auth_error_seen(log_path: Path) -> bool:
    """True when the piped agent log shows the relay rejected the credential."""
    try:
        text = log_path.read_text(encoding="utf-8", errors="replace")[-65536:]
    except OSError:
        return False
    return bool(_AUTH_ERROR_RE.search(text))


def extract_flag_candidates(work_dir: Path, log_path: Path) -> List[str]:
    found: List[str] = []
    for name in ("loot.txt", "flag.txt"):
        flag_file = work_dir / name
        if not flag_file.is_file():
            continue
        for line in flag_file.read_text(encoding="utf-8", errors="replace").splitlines():
            s = line.strip()
            if s:
                found.append(s)

    text = ""
    if log_path.is_file():
        text = log_path.read_text(encoding="utf-8", errors="replace")
    # also scan session jsonl under work_dir
    session_dir = work_dir / ".pi-sessions"
    if session_dir.is_dir():
        for p in session_dir.glob("*.jsonl"):
            try:
                text += "\n" + p.read_text(encoding="utf-8", errors="replace")
            except OSError:
                pass
    pats = [
        r"flag\{[^\n\r]{1,200}\}",
        r"FLAG\{[^\n\r]{1,200}\}",
        r"[a-z]{2,12}\{[^\n\r]{4,200}\}",
    ]
    for pat in pats:
        for m in re.finditer(pat, text, flags=re.I):
            found.append(m.group(0))

    out: List[str] = []
    seen = set()
    for f in found:
        if f not in seen:
            seen.add(f)
            out.append(f)
    return out
