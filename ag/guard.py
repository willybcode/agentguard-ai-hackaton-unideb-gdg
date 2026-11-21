"""AgentGuard as a library, for embedding in a real agent loop.

The runtime was built for the demo: a scripted planner, a simulated executor, a
policy in between. To use it for real you supply your own three pieces and keep
the middle one:

    from ag import guard

    g = guard.AgentGuard(policy=guard.load_policy("agentguard.policy.json"))

    # 1. ask your model for a plan (any provider)
    plan = my_model.propose(task)

    # 2. let the guard vet it, one call at a time
    for call in g.vet_all(plan, task=task):
        if call.refused:
            log.warning("%s blocked by %s (%s)", call.tool, call.rule, call.asi)
            continue
        if call.needs_human and not ask_a_human(call):
            continue
        call.invoke(my_real_executor)      # only runs if the guard allowed it

The guard is deliberately small and dependency-free so it can sit inside
someone else's process. It makes no network calls of its own unless you enable
an adjudicator.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Iterable, Iterator

from .adjudicate import Adjudicator
from .audit import AuditLog
from .config import Config, config_from_env
from .owl import label
from .policy import ALLOW, APPROVAL, ApprovalBudget, Decision, Policy, default_policy

__all__ = [
    "AgentGuard",
    "Call",
    "load_policy",
    "Decision",
    "Policy",
    "AuditLog",
    "default_policy",
]


@dataclass
class Call:
    """One proposed tool call, with the guard's verdict attached."""

    tool: str
    args: dict[str, Any]
    decision: Decision
    asi_label: str = ""
    adjudicated: bool = False

    @property
    def refused(self) -> bool:
        return self.decision.verdict != ALLOW and self.decision.verdict != APPROVAL

    @property
    def needs_human(self) -> bool:
        return self.decision.verdict == APPROVAL

    @property
    def rule(self) -> str:
        return self.decision.rule

    @property
    def asi(self) -> str | None:
        return self.decision.asi

    def invoke(self, executor: Callable[[str, dict[str, Any]], Any]) -> Any:
        """Run the call. Refuses to execute anything the guard did not clear.

        This is the whole point: there is no path from ``Call`` to the executor
        that skips ``refused``, so a caller cannot accidentally forget to check.
        """
        if self.refused:
            raise PermissionError(
                f"AgentGuard refused {self.tool}: {self.decision.rule} "
                f"({self.decision.reason})"
            )
        return executor(self.tool, self.args)


class AgentGuard:
    """Policy + budget + adjudicator + audit, without a planner or executor."""

    def __init__(
        self,
        policy: Policy | None = None,
        *,
        audit: AuditLog | None = None,
        budget: ApprovalBudget | None = None,
        adjudicator: Adjudicator | None = None,
        config: Config | None = None,
    ) -> None:
        self.policy = policy if policy is not None else default_policy()
        self.audit = audit if audit is not None else AuditLog()
        self.budget = budget
        self.adjudicator = adjudicator
        self.config = config or config_from_env()

    # -- single calls -----------------------------------------------------

    def vet(
        self,
        tool: str,
        args: dict[str, Any],
        *,
        task: str = "",
        tainted: Iterable[str] = (),
    ) -> Call:
        """Vet one proposed call. Never raises; refusal is a value, not an error."""
        decision = self.policy.evaluate(tool, args, tainted=tainted)

        if decision.verdict in (ALLOW, APPROVAL) and self.budget is not None:
            if not self.budget.charge():
                decision = self.budget.exhausted()

        adjudicated = False
        if self.adjudicator is not None and decision.verdict in (ALLOW, APPROVAL):
            verdict = self.adjudicator.adjudicate(tool, args, task)
            if verdict is not None:
                adjudicated = True
                decision = verdict.as_decision(decision)

        self.audit.append(
            tool=tool,
            args=args,
            verdict=decision.verdict,
            rule=decision.rule,
            reason=decision.reason,
            asi=decision.asi,
        )
        return Call(
            tool=tool,
            args=args,
            decision=decision,
            asi_label=label(decision.asi) if decision.asi else "",
            adjudicated=adjudicated,
        )

    def vet_all(
        self,
        plan: Iterable[dict[str, Any]],
        *,
        task: str = "",
        tainted: Iterable[str] = (),
    ) -> Iterator[Call]:
        """Vet a plan lazily, so a caller can stop at the first refusal."""
        seen = set(tainted)
        for step in plan:
            tool = step.get("tool", "")
            args = step.get("args", {}) or {}
            call = self.vet(tool, args, task=task, tainted=seen)
            yield call
            if call.tool in ("web_fetch", "read_email"):
                seen.add(call.tool)

    # -- offline checks ---------------------------------------------------

    def check(self, plan: Iterable[dict[str, Any]], *, task: str = "") -> list[Call]:
        """Vet a plan without executing anything. Useful in CI."""
        return list(self.vet_all(plan, task=task))

    def report(self) -> dict[str, Any]:
        intact, bad = self.audit.verify()
        return {
            "entries": len(self.audit),
            "intact": intact,
            "tampered_at": bad,
            "head": self.audit.entries[-1].hash[:16] if self.audit.entries else "",
        }


# ---------------------------------------------------------------------------
# Policy files
# ---------------------------------------------------------------------------

def load_policy(path: str | Path) -> Policy:
    """Load a policy from JSON, so it can live in a repo and be code-reviewed.

    Shape::

        {
          "forbidden_tokens": ["rm -rf", "sudo"],
          "tools": {
            "run_shell": {"verdict": "approval", "deny_patterns": ["curl.*\\\\|\\\\s*sh"]},
            "read_file": {"verdict": "allow"},
            "rotate_credentials": {"verdict": "deny"}
          }
        }
    """
    from .policy import DENY, ToolPolicy  # local import keeps the module surface small

    raw = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise ValueError("policy file must contain a JSON object")

    policy = Policy(forbidden_tokens=tuple(raw.get("forbidden_tokens", ())))
    for name, spec in (raw.get("tools") or {}).items():
        spec = spec or {}
        verdict = str(spec.get("verdict", "allow")).lower()
        if verdict not in ("allow", "approval", "deny"):
            raise ValueError(f"{name}: verdict must be allow, approval or deny")
        policy.add(
            ToolPolicy(
                name=name,
                verdict=DENY if verdict == "deny" else verdict,
                deny_patterns=tuple(spec.get("deny_patterns", ())),
                allow_paths=tuple(spec.get("allow_paths", ())),
                asi=str(spec.get("asi", "ASI02")),
            )
        )
    return policy


def dump_policy(policy: Policy) -> dict[str, Any]:
    """Serialise a policy back to the file shape, for documentation."""
    return {
        "forbidden_tokens": list(policy.forbidden_tokens),
        "tools": {
            name: {
                "verdict": spec.verdict,
                "deny_patterns": list(spec.deny_patterns),
                "allow_paths": list(spec.allow_paths),
                "asi": spec.asi,
            }
            for name, spec in policy.tools.items()
        },
    }
