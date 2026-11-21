"""Configuration from the environment, optionally seeded from a ``.env`` file.

One API endpoint is configured — a local LiteLLM-style proxy is expected to
handle upstream selection and fallback. If that endpoint is unreachable the
planner degrades to the deterministic mock, so a demo cannot be lost to a dead
proxy or a dead venue network.

Two roles are configured:

``planner``   a regular chat model, asked for a JSON plan of tool calls.
``adjudicator``
              a decision model (Liquid ``d1-*``) that judges one already-formed
              tool call. It cannot produce a plan and it cannot allow anything
              the policy already denied — it only tightens the boundary.

Set ``AG_MODEL_TYPE=decision`` if the endpoint serves a decision model.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

REGULAR = "regular"
DECISION = "decision"

VALID_TYPES = (REGULAR, DECISION)


def load_dotenv(path: str | Path = ".env") -> None:
    """Load ``.env`` without overwriting variables already set."""
    file = Path(path)
    if not file.is_file():
        return
    for raw in file.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip()
        if key.startswith("export "):
            key = key[len("export ") :].strip()
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            value = value[1:-1]
        os.environ.setdefault(key, value)


def _bool(name: str, default: bool) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.strip().lower() in ("1", "true", "yes", "on")


def _float(name: str, default: float) -> float:
    try:
        return float(os.environ.get(name, "") or default)
    except ValueError:
        return default


@dataclass(frozen=True)
class Config:
    api_url: str
    api_key: str
    model: str
    model_type: str
    adjudicator_model: str
    adjudicator_type: str
    decision_url: str = ""
    fallback_to_mock: bool = True
    timeout: float = 60.0
    decision_threshold: float = 0.5
    max_tokens: int = 2048
    explicit: bool = False

    @property
    def is_decision(self) -> bool:
        return self.model_type == DECISION

    @property
    def adjudicator_is_decision(self) -> bool:
        return self.adjudicator_type == DECISION

    @property
    def decision_endpoint(self) -> str:
        """Where decision-model calls go.

        Defaults to ``<AG_API_URL>/decisions``. Set ``AG_DECISION_URL`` when the
        proxy does not route decision requests but a local runtime serves them
        directly (LM Studio exposes ``/v1/decisions`` natively).
        """
        if self.decision_url:
            return self.decision_url.rstrip("/")
        base = self.api_url.rstrip("/")
        if base.endswith("/decisions"):
            return base
        return base + "/decisions"

    @property
    def configured(self) -> bool:
        """True when an endpoint was actually configured, not just defaulted.

        Without this, a bare checkout would spend a timeout per call trying to
        reach a proxy that was never set up.
        """
        return self.explicit and bool(self.api_url and self.model)


def config_from_env() -> Config:
    explicit_url = os.environ.get("AG_API_URL") or os.environ.get("LLM_BASE_URL")
    api_url = (explicit_url or "http://localhost:4000/v1").rstrip("/")

    api_key = os.environ.get("AG_API_KEY") or os.environ.get("LLM_API_KEY", "")
    model = os.environ.get("AG_MODEL") or os.environ.get("LLM_MODEL") or "local-model"

    model_type = (os.environ.get("AG_MODEL_TYPE") or REGULAR).strip().lower()
    if model_type not in VALID_TYPES:
        model_type = REGULAR

    adjudicator_model = os.environ.get("AG_ADJUDICATOR_MODEL", "").strip()
    adjudicator_type = (
        os.environ.get("AG_ADJUDICATOR_TYPE") or DECISION
    ).strip().lower()
    if adjudicator_type not in VALID_TYPES:
        adjudicator_type = DECISION

    return Config(
        api_url=api_url,
        api_key=api_key,
        model=model,
        model_type=model_type,
        adjudicator_model=adjudicator_model,
        adjudicator_type=adjudicator_type,
        decision_url=(os.environ.get("AG_DECISION_URL") or "").strip(),
        fallback_to_mock=_bool("AG_FALLBACK_TO_MOCK", True),
        timeout=_float("AG_TIMEOUT", 60.0),
        decision_threshold=_float("AG_DECISION_THRESHOLD", 0.5),
        max_tokens=int(_float("AG_MAX_TOKENS", 2048)),
        explicit=bool(explicit_url),
    )
