"""Minimal OpenAI-compatible stand-in for tests and the local server demo.

Serves ``/v1/models`` (Bearer-gated), ``/v1/chat/completions`` and the
OrcaRouter auth endpoints (``/auth`` consent stub, ``/api/v1/auth/keys``) used
by the PKCE adapter against a local fake auth origin.  Non-2xx responses carry
the OpenAI-style error envelope ``{"error": {"message": ...}}``.

Run standalone: ``python3 -m tests.fake_openai_server --port 8765``
"""

from __future__ import annotations

import argparse
import json
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Dict, List, Optional
from urllib.parse import parse_qs, urlparse

# Deliberately mixes text chat routes with non-text routes so the capability
# filter has something to reject.  Vendor/model namespaces are kept verbatim.
CATALOG: List[Dict] = [
    {
        "id": "openai/gpt-5.5",
        "name": "GPT-5.5",
        "context_length": 400000,
        "supported_endpoint_types": ["openai", "openai-response"],
        "architecture": {"input_modalities": ["text", "image"]},
        "supports_reasoning": True,
    },
    {
        "id": "anthropic/claude-opus-4.8",
        "name": "Claude Opus 4.8",
        "context_length": 200000,
        "supported_endpoint_types": ["anthropic"],
        "architecture": {"input_modalities": ["text", "image"]},
    },
    {
        "id": "google/gemini-3.5-flash",
        "name": "Gemini 3.5 Flash",
        "context_length": 1000000,
        "supported_endpoint_types": ["gemini", "openai"],
        "architecture": {"input_modalities": ["text", "image", "audio", "video"]},
    },
    {
        "id": "deepseek/deepseek-v4-pro",
        "name": "DeepSeek V4 Pro",
        "context_length": 128000,
        "supported_endpoint_types": ["openai"],
        "architecture": {"input_modalities": ["text"]},
    },
    {
        "id": "orcarouter/auto",
        "name": "OrcaRouter Auto",
        "context_length": 128000,
        "supported_endpoint_types": ["openai"],
        "architecture": {"input_modalities": ["text"]},
    },
    {
        "id": "orcarouter/fusion",
        "name": "OrcaRouter Fusion",
        "context_length": 128000,
        "supported_endpoint_types": ["openai"],
        "architecture": {"input_modalities": ["text"]},
    },
    {
        "id": "openai/gpt-image-1",
        "name": "GPT Image 1",
        "supported_endpoint_types": ["image-generation"],
        "architecture": {"input_modalities": ["text"], "output_modalities": ["image"]},
    },
    {
        "id": "google/veo-3",
        "name": "Veo 3",
        "supported_endpoint_types": ["openai-video"],
        "architecture": {"input_modalities": ["text"]},
    },
    {
        "id": "jina/jina-reranker-v3",
        "name": "Jina Reranker",
        "supported_endpoint_types": ["jina-rerank"],
        "architecture": {"input_modalities": ["text"]},
    },
    {
        "id": "openai/text-embedding-4",
        "name": "Text Embedding 4",
        "supported_endpoint_types": ["embeddings"],
        "architecture": {"input_modalities": ["text"]},
    },
    {"id": "no-namespace-model", "name": "junk"},
]


class FakeState:
    def __init__(self) -> None:
        self.keys = {"sk-orca-test-valid-key-0001"}
        self.valid_key = "sk-orca-test-valid-key-0001"
        self.issues: Dict[str, Dict] = {}  # code -> {"verifier_challenge": ...}
        self.used_codes = set()
        self.chat_calls: List[Dict] = []
        self.model_calls = 0
        self.lock = threading.Lock()

    def issue_code(self, challenge: str) -> str:
        code = f"code-{int(time.time() * 1000)}-{len(self.issues)}"
        self.issues[code] = {"challenge": challenge}
        return code


def _handler(state: FakeState):
    class H(BaseHTTPRequestHandler):
        def log_message(self, *args) -> None:  # keep test output quiet
            return

        def _send(self, status: int, payload) -> None:
            body = json.dumps(payload).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _auth_ok(self) -> bool:
            return self.headers.get("Authorization", "") == f"Bearer {state.valid_key}"

        def do_GET(self) -> None:  # noqa: N802
            path = urlparse(self.path).path
            if path == "/v1/models":
                if not self._auth_ok():
                    self._send(401, {"error": {"message": "invalid api key"}})
                    return
                state.model_calls += 1
                self._send(200, {"object": "list", "data": CATALOG})
                return
            if path == "/auth":
                # Consent stub: "approve" immediately and redirect with code + state.
                q = parse_qs(urlparse(self.path).query)
                cb = (q.get("callback_url") or [""])[0]
                ch = (q.get("code_challenge") or [""])[0]
                st = (q.get("state") or [""])[0]
                if q.get("code_challenge_method", [""])[0] != "S256":
                    self._send(400, {"error": "invalid_request"})
                    return
                if cb == "oob":
                    self._send(200, {"code": state.issue_code(ch), "state": st, "mode": "oob"})
                    return
                self.send_response(302)
                self.send_header("Location", f"{cb}?code={state.issue_code(ch)}&state={st}")
                self.end_headers()
                return
            self._send(404, {"error": {"message": "not found"}})

        def do_POST(self) -> None:  # noqa: N802
            path = urlparse(self.path).path
            length = int(self.headers.get("Content-Length") or 0)
            try:
                body = json.loads(self.rfile.read(length) or b"{}")
            except json.JSONDecodeError:
                self._send(400, {"error": "invalid_request"})
                return
            if path == "/api/v1/auth/keys":
                if body.get("code_challenge_method") != "S256":
                    self._send(400, {"error": "invalid_request", "error_description": "method mismatch"})
                    return
                code = body.get("code")
                import base64
                import hashlib

                verifier = body.get("code_verifier") or ""
                challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).decode().rstrip("=")
                with state.lock:
                    rec = state.issues.get(code)
                    if rec is None or code in state.used_codes or rec["challenge"] != challenge:
                        self._send(403, {"error": "invalid_grant", "error_description": "code invalid"})
                        return
                    state.used_codes.add(code)
                self._send(200, {"key": state.valid_key, "user_id": "u-test", "scope": body.get("scope") or "api"})
                return
            if path == "/v1/chat/completions":
                if not self._auth_ok():
                    self._send(401, {"error": {"message": "invalid api key"}})
                    return
                state.chat_calls.append(body)
                model = body.get("model") or ""
                self._send(
                    200,
                    {
                        "id": "chatcmpl-test",
                        "object": "chat.completion",
                        "model": model,
                        "choices": [{"index": 0, "message": {"role": "assistant", "content": "pong"}, "finish_reason": "stop"}],
                        "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2},
                    },
                )
                return
            self._send(404, {"error": {"message": "not found"}})

    return H


class FakeServer:
    def __init__(self, host: str = "127.0.0.1", port: int = 0):
        self.state = FakeState()
        self.httpd = ThreadingHTTPServer((host, port), _handler(self.state))
        self.host, self.port = self.httpd.server_address[:2]
        self.thread: Optional[threading.Thread] = None

    @property
    def base(self) -> str:
        return f"http://{self.host}:{self.port}"

    def start(self) -> "FakeServer":
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True, name="fake-openai")
        self.thread.start()
        return self

    def stop(self) -> None:
        self.httpd.shutdown()
        self.httpd.server_close()


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=8765)
    args = ap.parse_args()
    srv = FakeServer(port=args.port).start()
    print(f"fake OpenAI-compatible server on {srv.base}/v1 (key sk-orca-test-valid-key-0001)", flush=True)
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        srv.stop()
