"""A fake LiteLLM-style proxy for testing without LM Studio or OpenRouter.

Serves both shapes AgentGuard can use:

* ``POST /v1/chat/completions`` — OpenAI schema, returns a JSON plan
* ``POST /v1/decisions``       — decision-model schema (``state`` + ``questions``)

The decision answers are computed from the request so a denial can be forced
predictably: any tool call whose arguments contain a shell metacharacter or a
write is judged unsafe.

    python3 tests/stub_proxy.py 4100
"""

from __future__ import annotations

import json
import re
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

# Calls the fake adjudicator refuses, mirroring a real d1 with a guardrail prompt.
_UNSAFE_TOOLS = {"write_file", "edit_file", "delete_file", "exfiltrate"}
_UNSAFE_ARGS = re.compile(r"[|;`]|curl\s|rm\s|\$\(", re.IGNORECASE)


def judge(state: dict) -> dict:
    call = state.get("proposed_tool_call", {})
    tool = str(call.get("tool", ""))
    blob = json.dumps(call.get("args", {}))

    unsafe = tool in _UNSAFE_TOOLS or bool(_UNSAFE_ARGS.search(blob))
    safe_probability = 0.12 if unsafe else 0.94

    if tool in _UNSAFE_TOOLS:
        intent = "destructive"
    elif _UNSAFE_ARGS.search(blob):
        intent = "exfiltration" if "curl" in blob.lower() else "privilege"
    else:
        intent = "routine"

    risk = 4 if unsafe else 0
    return {
        "answers": {
            "safe": {"noul": safe_probability},
            "intent": {"choice": intent, "confidence": 0.9,
                       "probabilities": {"routine": 1 - safe_probability}},
            "risk": {
                "score": risk,
                "legend": {str(i): name for i, name in enumerate(
                    ["none", "low", "medium", "high", "severe"])},
            },
        }
    }


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def _send(self, payload: dict, status: int = 200) -> None:
        body = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self) -> None:
        length = int(self.headers.get("Content-Length", "0"))
        try:
            body = json.loads(self.rfile.read(length) or b"{}")
        except json.JSONDecodeError:
            self._send({"error": "invalid JSON"}, 400)
            return

        if self.path.endswith("/chat/completions"):
            task = body.get("messages", [{}])[-1].get("content", "")
            plan = [{"tool": "run_shell", "args": {"command": f"pytest -q {task[:20]}"}}]
            self._send({
                "choices": [{"message": {"role": "assistant", "content": json.dumps(plan)}}]
            })
        elif self.path.endswith("/decisions"):
            self._send(judge(body.get("state", body)))
        else:
            self._send({"error": "not found"}, 404)


def serve(port: int = 4100) -> None:
    httpd = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    print(f"stub proxy on http://127.0.0.1:{port}/v1")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()


if __name__ == "__main__":
    serve(int(sys.argv[1]) if len(sys.argv) > 1 else 4100)
