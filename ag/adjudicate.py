"""Decision-model adjudication of individual tool calls.

A Liquid ``d1-*`` decision model is *not* a chat model: it reads a state and a
set of named questions and returns typed, calibrated answers from a single
forward pass — no sampling, no generated tokens. It cannot plan. What it can do
is judge one already-formed tool call, which is a useful second opinion *after*
the policy has run.

Two rules make this safe to bolt onto the runtime:

1. **Monotonic.** The adjudicator may deny a call the policy allowed. It can
   never allow a call the policy denied, and it never sees un-denied proposals.
2. **Fail open, labelled.** If the adjudicator is unreachable the policy verdict
   stands, and the run records that adjudication was unavailable rather than
   pretending the extra check happened.

A regular chat model can serve the same role through the JSON fallback, so the
demo still works when only a proxy with a chat model is on hand.
"""

from __future__ import annotations

import json
import urllib.error
from dataclasses import dataclass, field
from typing import Any

from .config import Config
from .policy import ALLOW, DENY, Decision
from .llm import OpenAICompatProvider


@dataclass(frozen=True)
class Verdict:
    """Outcome of adjudicating one tool call."""

    allow: bool
    confidence: float
    reason: str
    source: str = "decision-model"
    questions: dict[str, Any] = field(default_factory=dict)

    def as_decision(self, original: Decision) -> Decision:
        """Apply this verdict on top of the policy decision (tighten only)."""
        if self.allow or original.verdict == DENY:
            return original
        return Decision(
            DENY,
            f"adjudicator:{original.rule}",
            f"{self.reason} (p={self.confidence:.2f})",
            original.asi,
        )


# The decision API takes a *list* of typed questions, not a mapping:
#   predicate -> {"probability": p}
#   choice    -> {"choice": value, "probabilities": [{value, probability}]}
#   score     -> {"score": n, "probabilities": [{value, label, probability}]}
PROBE: list[dict[str, Any]] = [
    {
        "name": "safe",
        "type": "predicate",
        "instructions": (
            "Is this tool call safe to execute automatically, with no human "
            "review, in a CI/CD assistant?"
        ),
    },
    {
        "name": "intent",
        "type": "choice",
        "instructions": "What is this tool call actually doing?",
        "choices": [
            {"value": "routine", "description": "Tests, reads, builds, formatting"},
            {"value": "release", "description": "Deploying, pushing, publishing"},
            {"value": "destructive", "description": "Deleting, wiping, overwriting"},
            {"value": "exfiltration", "description": "Moving data or secrets to another host"},
            {"value": "privilege", "description": "Changing identities, credentials or permissions"},
        ],
    },
    {
        "name": "risk",
        "type": "score",
        "instructions": (
            "How much damage could this call cause if the user's request was malicious?"
        ),
        "levels": [
            {"value": 0, "label": "none"},
            {"value": 1, "label": "low"},
            {"value": 2, "label": "medium"},
            {"value": 3, "label": "high"},
            {"value": 4, "label": "severe"},
        ],
    },
]


def _state(tool: str, args: dict[str, Any], task: str) -> dict[str, Any]:
    """The state a decision model reasons over: one request, one proposed call."""
    return {
        "user_request": task,
        "proposed_tool_call": {"tool": tool, "args": args},
    }


def _input_text(tool: str, args: dict[str, Any], task: str) -> str:
    """Serialize the state the way the decision API expects: one input string."""
    return json.dumps(_state(tool, args, task), indent=2, default=str)


def _answers_to_map(raw: Any) -> dict[str, Any]:
    """Normalise the decision API's ``answers`` list into ``{name: answer}``.

    LM Studio returns ``answers`` as an array of typed objects
    (``{"type": "predicate", "name": "safe", "probability": 0.67}``); a proxy
    may instead return a plain mapping. Accept both.
    """
    if isinstance(raw, dict):
        return raw
    if not isinstance(raw, list):
        return {}

    mapped: dict[str, Any] = {}
    for item in raw:
        if not isinstance(item, dict):
            continue
        name = item.get("name")
        if not isinstance(name, str):
            continue
        kind = item.get("type")

        if kind == "predicate" or "probability" in item:
            value = item.get("probability")
            if value is None:
                value = item.get("p")
            mapped[name] = {"noul": value}
        elif kind == "choice":
            probabilities = {
                p.get("value"): p.get("probability")
                for p in item.get("probabilities", [])
                if isinstance(p, dict)
            }
            mapped[name] = {
                "choice": item.get("choice"),
                "confidence": item.get("confidence"),
                "probabilities": probabilities,
            }
        elif kind == "score":
            legend = {
                str(p.get("value")): p.get("label")
                for p in item.get("probabilities", [])
                if isinstance(p, dict)
            }
            mapped[name] = {
                "score": item.get("score"),
                "confidence": item.get("confidence"),
                "legend": legend,
            }
        else:
            mapped[name] = item
    return mapped


def _parse_answers(body: dict[str, Any]) -> dict[str, Any]:
    """Pull the answers out of a decision-model or chat-shaped response."""
    if "answers" in body:
        return _answers_to_map(body["answers"])

    choices = body.get("choices")
    if isinstance(choices, list) and choices:
        content = choices[0].get("message", {}).get("content", "")
        if isinstance(content, dict):
            return _answers_to_map(content.get("answers", content))
        try:
            parsed = json.loads(content)
        except (json.JSONDecodeError, TypeError):
            return {}
        if not isinstance(parsed, dict):
            return {}
        return _answers_to_map(parsed.get("answers", parsed))

    return _answers_to_map(body) if "safe" in body else {}


# Intents that never run unattended, whatever the probability says.
NEVER_AUTOMATIC = frozenset({"destructive", "exfiltration", "privilege"})

# Risk levels that refuse outright.
BLOCKING_RISK = frozenset({"high", "severe"})


def _verdict_from_answers(answers: dict[str, Any], threshold: float) -> Verdict:
    safe = answers.get("safe")
    if isinstance(safe, dict):
        probability = safe.get("noul", safe.get("probability"))
    elif isinstance(safe, bool):
        probability = 1.0 if safe else 0.0
    elif isinstance(safe, (int, float)):
        probability = float(safe)
    else:
        probability = None

    intent = answers.get("intent") or {}
    kind = intent.get("choice", "unknown")

    risk = answers.get("risk") or {}
    level: Any = "unknown"
    if isinstance(risk.get("legend"), dict) and risk.get("score") is not None:
        level = risk["legend"].get(str(risk["score"]), risk["score"])
    elif risk.get("score") is not None:
        level = risk["score"]

    confidence = float(probability) if isinstance(probability, (int, float)) else 0.0

    # The ``safe`` scalar is not trustworthy on its own. Measured on d1-2B, the
    # same harmless call scored anywhere from 0.05 to 0.96 depending only on how
    # the question was phrased, while ``intent`` stayed correct every time. So
    # the categorical heads decide, and the scalar is used only to break ties on
    # medium risk. It is still reported, so a reviewer can see it.
    known_risk = level in ("none", "low", "medium", "high", "severe")

    if kind in NEVER_AUTOMATIC:
        allow, why = False, f"intent {kind} never runs unattended"
    elif level in BLOCKING_RISK:
        allow, why = False, f"{level} risk"
    elif level == "medium" and confidence < threshold:
        allow, why = False, f"medium risk and p={confidence:.2f} < {threshold:.2f}"
    elif not known_risk:
        # A missing risk head is not evidence of safety: fall back to the
        # scalar rather than silently allowing the call.
        allow = confidence >= threshold
        why = f"risk unreported, p={confidence:.2f} vs {threshold:.2f}"
    else:
        allow, why = True, f"intent {kind}, {level} risk, p={confidence:.2f}"

    return Verdict(
        allow=allow,
        confidence=confidence,
        reason=why,
        questions={"safe": confidence, "intent": kind, "risk": level},
    )


def _parse_answers(body: dict[str, Any]) -> dict[str, Any]:
    """Pull the answers out of a decision-model or chat-shaped response."""
    if "answers" in body:
        return _answers_to_map(body["answers"])

    choices = body.get("choices")
    if isinstance(choices, list) and choices:
        content = choices[0].get("message", {}).get("content", "")
        if isinstance(content, dict):
            return _answers_to_map(content.get("answers", content))
        try:
            parsed = json.loads(content)
        except (json.JSONDecodeError, TypeError):
            return {}
        if not isinstance(parsed, dict):
            return {}
        return _answers_to_map(parsed.get("answers", parsed))

    return _answers_to_map(body) if "safe" in body else {}


# Intents that never run unattended, whatever the probability says.
class Adjudicator:
    """Decide whether one policy-approved tool call should still be refused."""

    def __init__(self, config: Config, *, threshold: float | None = None) -> None:
        self.config = config
        self.threshold = config.decision_threshold if threshold is None else threshold
        self.model = config.adjudicator_model or config.model

    def _decision_url(self) -> str:
        """Where decision calls go; see ``Config.decision_endpoint``."""
        return self.config.decision_endpoint

    def _post(self, payload: dict[str, Any]) -> dict[str, Any]:
        import urllib.request

        request = urllib.request.Request(
            self._decision_url(),
            data=json.dumps(payload).encode(),
            headers={
                "Content-Type": "application/json",
                **(
                    {"Authorization": f"Bearer {self.config.api_key}"}
                    if self.config.api_key
                    else {}
                ),
            },
        )
        with urllib.request.urlopen(request, timeout=self.config.timeout) as response:
            return json.loads(response.read().decode())

    def _ask_decision_model(self, tool: str, args: dict[str, Any], task: str) -> dict[str, Any]:
        # Native decision-model calls are keyed by ``questions``; a proxy in
        # front of d1 is expected to forward this shape unchanged.
        body = self._post(
            {
                "model": self.model,
                "input": _input_text(tool, args, task),
                "questions": PROBE,
            }
        )
        return _parse_answers(body)

    def _ask_chat_model(self, tool: str, args: dict[str, Any], task: str) -> dict[str, Any]:
        provider = OpenAICompatProvider(
            base_url=self.config.api_url,
            model=self.model,
            api_key=self.config.api_key,
            name="adjudicator-chat",
            timeout=self.config.timeout,
        )
        raw = provider.complete(
            [
                {
                    "role": "system",
                    "content": (
                        "You judge whether a proposed tool call is safe to run "
                        "unattended. Answer with JSON only: "
                        '{"safe": <0..1>, "intent": <routine|release|destructive|'
                        'exfiltration|privilege>, "risk": <0..4>}'
                    ),
                },
                {"role": "user", "content": json.dumps(_state(tool, args, task), indent=2)},
            ]
        )
        try:
            parsed = json.loads(raw.strip().strip("`").removeprefix("json"))
        except (json.JSONDecodeError, AttributeError):
            return {}
        if not isinstance(parsed, dict):
            return {}
        return {
            "safe": {"noul": parsed.get("safe")},
            "intent": {"choice": parsed.get("intent")},
            "risk": {"score": parsed.get("risk"), "legend": {}},
        }

    def adjudicate(
        self, tool: str, args: dict[str, Any], task: str
    ) -> Verdict | None:
        """Return a verdict, or ``None`` when the adjudicator is unavailable."""
        questioner = (
            self._ask_decision_model
            if self.config.adjudicator_is_decision
            else self._ask_chat_model
        )
        try:
            answers = questioner(tool, args, task)
        except (urllib.error.URLError, TimeoutError, OSError, ValueError, KeyError):
            return None

        if not answers:
            return None
        return _verdict_from_answers(answers, self.threshold)


def probe_adjudicator(config: Config) -> dict[str, Any]:
    """Smoke-check the adjudicator without running the agent."""
    adjudicator = Adjudicator(config)
    verdict = adjudicator.adjudicate(
        "run_shell", {"command": "pytest -q"}, "run the test suite"
    )
    if verdict is None:
        return {
            "ok": False,
            "model": adjudicator.model,
            "type": config.adjudicator_type,
            "error": "unreachable or unparseable",
        }
    return {
        "ok": True,
        "model": adjudicator.model,
        "type": config.adjudicator_type,
        "allow": verdict.allow,
        "confidence": round(verdict.confidence, 3),
        "reason": verdict.reason,
        "source": verdict.source,
    }
