"""Declarative tool policy: allow / require-approval / deny, per-argument rules.

The policy is data, not code, so it can be reviewed, diffed and unit-tested.
Evaluation order for a single tool call:

1. unknown tool            -> deny
2. forbidden token in args -> deny
3. tool deny patterns      -> deny
4. path escape             -> deny
5. tainted input to a sink -> deny      (ASI06)
6. tool requires approval  -> approval
7. otherwise               -> allow
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Iterable

ALLOW = "allow"
APPROVAL = "approval"
DENY = "deny"

# Tools whose effects leave the agent's boundary; tainted data must never reach them.
SINKS = frozenset({"run_shell", "git_push", "write_file", "delete_file"})


@dataclass(frozen=True)
class Decision:
    verdict: str
    rule: str
    reason: str
    asi: str | None = None

    @property
    def blocked(self) -> bool:
        return self.verdict == DENY

    @property
    def needs_approval(self) -> bool:
        return self.verdict == APPROVAL


@dataclass
class ToolPolicy:
    """Policy for one tool."""

    name: str
    verdict: str = ALLOW
    deny_patterns: tuple[str, ...] = ()
    allow_paths: tuple[str, ...] = ()
    asi: str = "ASI02"


@dataclass
class Policy:
    tools: dict[str, ToolPolicy] = field(default_factory=dict)
    forbidden_tokens: tuple[str, ...] = ()

    def add(self, tool: ToolPolicy) -> "Policy":
        self.tools[tool.name] = tool
        return self

    def evaluate(
        self,
        tool: str,
        args: dict[str, Any],
        *,
        tainted: Iterable[str] = (),
    ) -> Decision:
        spec = self.tools.get(tool)
        if spec is None:
            return Decision(
                DENY, "unknown-tool", f"tool {tool!r} is not registered", "ASI02"
            )

        blob = _flatten(args)

        for token in self.forbidden_tokens:
            if token in blob:
                return Decision(
                    DENY,
                    "forbidden-token",
                    f"argument contains forbidden token {token!r}",
                    "ASI02",
                )

        for pattern in spec.deny_patterns:
            if re.search(pattern, blob, re.IGNORECASE):
                return Decision(
                    DENY,
                    "deny-pattern",
                    f"argument matches deny pattern {pattern!r}",
                    spec.asi,
                )

        if spec.allow_paths and tool in {"write_file", "edit_file"}:
            target = str(args.get("path", ""))
            if not any(target.startswith(p) for p in spec.allow_paths):
                return Decision(
                    DENY,
                    "path-escape",
                    f"path {target!r} escapes the agent sandbox",
                    "ASI05",
                )

        sources = sorted(set(tainted))
        if sources and tool in SINKS:
            return Decision(
                DENY,
                "tainted-context",
                f"side effect attempted with data from untrusted source {sources[0]!r}",
                "ASI06",
            )

        if spec.verdict == DENY:
            return Decision(DENY, "tool-denied", f"{tool} is denied by policy", spec.asi)

        if spec.verdict == APPROVAL:
            return Decision(
                APPROVAL,
                "human-approval",
                f"{tool} requires a human in the loop",
                "ASI09",
            )

        return Decision(ALLOW, "default-allow", "allowed by policy")


@dataclass
class ApprovalBudget:
    """Caps fan-out so one prompt cannot expand into unbounded tool calls.

    Also tracks consecutive human approvals: after ``fatigue_after`` approvals
    the next request is refused unless the caller re-confirms, modelling the
    approval-fatigue failure mode in ASI09.
    """

    limit: int = 12
    fatigue_after: int = 3
    used: int = 0
    approvals: int = 0

    def charge(self) -> bool:
        self.used += 1
        return self.used <= self.limit

    def exhausted(self) -> Decision:
        return Decision(
            DENY,
            "budget-exhausted",
            f"tool budget of {self.limit} calls exceeded (cascading fan-out)",
            "ASI08",
        )


def _flatten(args: dict[str, Any]) -> str:
    """Join all argument values into one searchable string."""
    parts: list[str] = []
    for value in args.values():
        if isinstance(value, (list, tuple)):
            parts.extend(str(v) for v in value)
        elif isinstance(value, dict):
            parts.append(_flatten(value))
        else:
            parts.append(str(value))
    return " ".join(parts)


def default_policy() -> Policy:
    """Policy modelled on a CI/CD assistant with shell, git and file access."""
    policy = Policy(
        forbidden_tokens=(
            "rm -rf",
            "sudo",
            "mkfs",
            "shutdown",
            "reboot",
            ":(){",
            "chmod 777",
        ),
    )
    policy.add(
        ToolPolicy(
            "run_shell",
            verdict=APPROVAL,
            deny_patterns=(
                r"\bcurl\b[^|]*\|\s*(ba)?sh",
                r"base64\s+-d",
                r"\beval\s*\(",
                r"/etc/(passwd|shadow)",
                r"\.ssh/",
                r"AKIA[0-9A-Z]{16}",
            ),
            asi="ASI05",
        )
    )
    policy.add(ToolPolicy("git_push", verdict=APPROVAL, asi="ASI02"))
    policy.add(
        ToolPolicy(
            "write_file",
            verdict=APPROVAL,
            allow_paths=("workspace/", "sandbox/"),
            deny_patterns=(r"\.\./", r"\.env\b"),
            asi="ASI05",
        )
    )
    policy.add(ToolPolicy("edit_file", verdict=ALLOW, allow_paths=("workspace/", "sandbox/"), asi="ASI05"))
    policy.add(
        ToolPolicy(
            "install_dependency",
            verdict=ALLOW,
            deny_patterns=(
                r"--(index-url|registry)\s+https?://(?!pypi\.org|registry\.npmjs\.org)",
                r"\bgit\+https?://",
            ),
            asi="ASI04",
        )
    )
    policy.add(ToolPolicy("read_file", verdict=ALLOW, asi="ASI02"))
    policy.add(ToolPolicy("web_fetch", verdict=ALLOW, asi="ASI04"))
    policy.add(ToolPolicy("read_email", verdict=ALLOW, asi="ASI04"))
    policy.add(ToolPolicy("delete_file", verdict=DENY, asi="ASI02"))
    policy.add(ToolPolicy("rotate_credentials", verdict=DENY, asi="ASI03"))
    return policy
