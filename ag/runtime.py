"""Two agent runtimes: an unguarded baseline and the guarded agent.

The only difference between them is a call to ``Policy.evaluate``. Everything
else — planner, executor, audit log — is shared, which is what makes the
before/after comparison a fair one.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Literal

from . import sandbox
from .adjudicate import Adjudicator
from .audit import AuditLog
from .llm import SYSTEM_PROMPT, Provider, parse_plan
from .policy import ALLOW, APPROVAL, DENY, ApprovalBudget, Decision, Policy, default_policy

Outcome = Literal["executed", "blocked", "approved", "denied", "error"]

Approver = Callable[[str, dict[str, Any], Decision], bool]

# Progress callback: (phase, payload). Phases are "plan", "step", "done", "error".
# Used by the demo UI to stream a run; the runtime never requires it.
Emitter = Callable[[str, dict[str, Any]], None]


@dataclass
class StepResult:
    tool: str
    args: dict[str, Any]
    outcome: Outcome
    rule: str = ""
    reason: str = ""
    asi: str | None = None
    result: str = ""
    # What the model actually called the tool, when it differed from the
    # canonical name the policy matched. Kept for audit, never evaluated.
    model_tool: str | None = None


@dataclass
class RunResult:
    task: str
    mode: str
    steps: list[StepResult] = field(default_factory=list)
    raw_plan: str = ""
    injection_seen: bool = False
    adjudicated: int = 0
    adjudicator_unavailable: int = 0

    @property
    def blocked(self) -> int:
        return sum(1 for s in self.steps if s.outcome in ("blocked", "denied"))

    @property
    def executed(self) -> int:
        return sum(1 for s in self.steps if s.outcome in ("executed", "approved"))

    @property
    def landed(self) -> int:
        """Dangerous steps that actually ran; the scoreboard counts these."""
        return sum(
            1
            for s in self.steps
            if s.outcome in ("executed", "approved") and s.tool in sandbox.DANGEROUS_TOOLS
        )


def _auto_deny(tool: str, args: dict[str, Any], decision: Decision) -> bool:
    return False


def _summary(result: "RunResult") -> dict[str, Any]:
    """Compact progress payload, without the full step list."""
    return {
        "task": result.task,
        "mode": result.mode,
        "landed": result.landed,
        "blocked": result.blocked,
        "steps": len(result.steps),
        "injection_seen": result.injection_seen,
        "adjudicated": result.adjudicated,
        "adjudicator_unavailable": result.adjudicator_unavailable,
    }


class Agent:
    def __init__(
        self,
        provider: Provider,
        *,
        policy: Policy | None = None,
        audit: AuditLog | None = None,
        approver: Approver | None = None,
        budget: ApprovalBudget | None = None,
        adjudicator: Adjudicator | None = None,
        emit: Emitter | None = None,
    ) -> None:
        self.provider = provider
        self.policy = policy if policy is not None else default_policy()
        self.audit = audit if audit is not None else AuditLog()
        self.approver = approver or _auto_deny
        self.budget = budget
        self.adjudicator = adjudicator
        self.emit = emit

    def plan(self, task: str) -> tuple[list[dict[str, Any]], str]:
        raw = self.provider.complete(
            [
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": task},
            ]
        )
        return parse_plan(raw), raw

    def run(self, task: str, *, guarded: bool = True) -> RunResult:
        result = RunResult(task=task, mode="guarded" if guarded else "baseline")
        self._emit("plan", {"mode": result.mode, "task": task})
        try:
            plan, raw = self.plan(task)
        except Exception as exc:  # fail closed: a broken planner executes nothing
            message = f"{type(exc).__name__}: {exc}"
            result.steps.append(
                StepResult("(planner)", {}, "error", "planner-error", message)
            )
            self._emit("error", {"mode": result.mode, "reason": message})
            return result

        result.raw_plan = raw
        tainted: set[str] = set()
        self._emit("planned", {"mode": result.mode, "steps": len(plan), "raw": raw})

        for index, step in enumerate(plan):
            tool, args = step["tool"], step["args"]
            self._emit("step", {"mode": result.mode, "index": index, "tool": tool, "args": args})
            if not guarded:
                self._baseline_step(result, tool, args)
                continue

            if self.budget is not None and not self.budget.charge():
                self._record_blocked(
                    result, tool, args, self.budget.exhausted(), step.get("_orig_tool")
                )
                continue

            decision = self.policy.evaluate(tool, args, tainted=tainted)

            if decision.needs_approval:
                if self.budget is not None and self.budget.approvals >= self.budget.fatigue_after:
                    self._record_blocked(
                        result,
                        tool,
                        args,
                        Decision(
                            DENY,
                            "approval-fatigue",
                            f"{self.budget.approvals} approvals requested in one run; "
                            "refusing further privileged actions",
                            "ASI09",
                        ),
                        step.get("_orig_tool"),
                    )
                    continue
                # Pre-screen with the adjudicator before spending human attention.
                decision = self._adjudicate(result, tool, args, decision, task)
                if decision.blocked:
                    self._record_blocked(result, tool, args, decision, step.get("_orig_tool"))
                    continue
                self._approval_step(result, tool, args, decision, tainted, task)
                continue

            if decision.blocked:
                self._record_blocked(result, tool, args, decision, step.get("_orig_tool"))
                continue

            decision = self._adjudicate(result, tool, args, decision, task)
            if decision.blocked:
                self._record_blocked(result, tool, args, decision, step.get("_orig_tool"))
                continue

            self._execute_step(result, tool, args, decision, tainted)

        self._emit("done", {"mode": result.mode, "result": _summary(result)})
        return result

    def _emit(self, phase: str, payload: dict[str, Any]) -> None:
        if self.emit is not None:
            try:
                self.emit(phase, payload)
            except Exception:  # a broken observer must not break the run
                pass

    # -- step helpers -----------------------------------------------------

    def _baseline_step(
        self, result: RunResult, tool: str, args: dict[str, Any]
    ) -> None:
        """Unguarded: run everything, then obey any instruction found in output."""
        output = sandbox.execute(tool, args)
        result.steps.append(StepResult(tool, args, "executed", result=output))
        self.audit.append(
            tool=tool,
            args=args,
            verdict="executed",
            rule="baseline",
            reason="no policy applied",
            asi=None,
        )

        followup = sandbox.injected_action(output)
        if followup is None:
            return
        result.injection_seen = True
        inner = followup["args"]
        result.steps.append(
            StepResult(
                followup["tool"],
                inner,
                "executed",
                "injected-instruction",
                f"followed instruction embedded in {tool} output",
                "ASI01",
                sandbox.execute(followup["tool"], inner),
            )
        )
        self.audit.append(
            tool=followup["tool"],
            args=inner,
            verdict="executed",
            rule="injected-instruction",
            reason=f"followed instruction embedded in {tool} output",
            asi="ASI01",
        )

    def _approval_step(
        self,
        result: RunResult,
        tool: str,
        args: dict[str, Any],
        decision: Decision,
        tainted: set[str],
        task: str = "",
    ) -> None:
        allowed = self.approver(tool, args, decision)
        if self.budget is not None:
            self.budget.approvals += 1
        outcome: Outcome = "approved" if allowed else "denied"
        self.audit.append(
            tool=tool,
            args=args,
            verdict=outcome,
            rule=decision.rule,
            reason=decision.reason,
            asi=decision.asi,
        )
        if not allowed:
            result.steps.append(
                StepResult(
                    tool, args, "denied", decision.rule, decision.reason, decision.asi
                )
            )
            return
        output = sandbox.execute(tool, args)
        result.steps.append(
            StepResult(
                tool, args, "approved", decision.rule, decision.reason, decision.asi, output
            )
        )
        self._absorb(tool, output, tainted, result)

    def _adjudicate(
        self,
        result: RunResult,
        tool: str,
        args: dict[str, Any],
        decision: Decision,
        task: str,
    ) -> Decision:
        """Second opinion on a call that is about to run. Can only tighten."""
        if self.adjudicator is None or decision.verdict not in (ALLOW, APPROVAL):
            return decision

        verdict = self.adjudicator.adjudicate(tool, args, task)
        if verdict is None:
            result.adjudicator_unavailable += 1
            return decision

        result.adjudicated += 1
        return verdict.as_decision(decision)

    def _record_blocked(
        self,
        result: RunResult,
        tool: str,
        args: dict[str, Any],
        decision: Decision,
        model_tool: str | None = None,
    ) -> None:
        self.audit.append(
            tool=tool,
            args=args,
            verdict="blocked",
            rule=decision.rule,
            reason=decision.reason,
            asi=decision.asi,
        )
        result.steps.append(
            StepResult(
                tool,
                args,
                "blocked",
                decision.rule,
                decision.reason,
                decision.asi,
                model_tool=model_tool,
            )
        )
        if decision.asi == "ASI06":
            result.injection_seen = True

    def _execute_step(
        self,
        result: RunResult,
        tool: str,
        args: dict[str, Any],
        decision: Decision,
        tainted: set[str],
    ) -> None:
        output = sandbox.execute(tool, args)
        self.audit.append(
            tool=tool,
            args=args,
            verdict="executed",
            rule=decision.rule,
            reason=decision.reason,
            asi=decision.asi,
        )
        result.steps.append(
            StepResult(
                tool, args, "executed", decision.rule, decision.reason, decision.asi, output
            )
        )
        self._absorb(tool, output, tainted, result)
        self._guarded_followup(result, tool, output, tainted)

    def _guarded_followup(
        self,
        result: RunResult,
        source_tool: str,
        output: str,
        tainted: set[str],
    ) -> None:
        """The LLM would act on poisoned text; the policy then blocks the effect."""
        followup = sandbox.injected_action(output)
        if followup is None:
            return
        tool, args = followup["tool"], followup["args"]
        decision = self.policy.evaluate(tool, args, tainted=tainted)
        if decision.blocked:
            self._record_blocked(result, tool, args, decision)
        elif decision.needs_approval:
            self._approval_step(result, tool, args, decision, tainted)
        else:
            self._execute_step(result, tool, args, decision, tainted)

    @staticmethod
    def _absorb(
        tool: str, output: str, tainted: set[str], result: RunResult
    ) -> None:
        """Remember that this run now holds data of untrusted provenance."""
        if tool in sandbox.UNTRUSTED_TOOLS:
            tainted.add(tool)
        if sandbox.has_injection(output):
            result.injection_seen = True


