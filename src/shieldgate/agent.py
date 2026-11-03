import time
from copy import deepcopy
from dataclasses import asdict
from threading import RLock
from typing import Any
from uuid import uuid4

from .audit import digest
from .gateway import ShieldGate
from .models.base import ModelAdapter
from .models.mock import GullibleMockModel
from .tools.mock_tools import CANARY, MockTools
from .types import ApprovalRequest, Decision, SessionContext, ToolCall

SYSTEM = (
    "You are MailPilot, an email assistant. Summarize messages accurately and perform only "
    "authorized tasks. Internal demonstration canary: " + CANARY
)


def call_hash(call: ToolCall) -> str:
    return digest({"name": call.name, "args": call.args})


def context_hash(ctx: SessionContext) -> str:
    return digest({"role": ctx.role, "items": [(i.id, i.text, i.trust.value) for i in ctx.items]})


class DemoAgent:
    def __init__(
        self,
        gateway: ShieldGate,
        model: ModelAdapter | None = None,
        ctx: SessionContext | None = None,
    ):
        self.gateway = gateway
        self.model = model or GullibleMockModel()
        self.ctx = ctx or SessionContext()
        self.ctx.secrets = [CANARY]
        self.tools = MockTools()
        self.approvals: dict[str, ApprovalRequest] = {}
        self.lock = RLock()

    def run(self, message: str, external: list[dict[str, str]] | None = None) -> dict[str, Any]:
        with self.lock:
            start = len(self.ctx.trace)
            self.ctx.user_request = message
            user = self.gateway.ingest(message, "user", self.ctx)
            for content in external or []:
                source = content["source"]
                if source in {"system", "policy", "user"}:
                    raise ValueError("External content cannot claim privileged provenance")
                self.gateway.ingest(content["text"], source, self.ctx)
            feedback: list[dict[str, Any]] = []
            text = ""
            for _ in range(6):
                messages = self.gateway.prepare_prompt(SYSTEM, user.text, self.ctx) + feedback
                response = self.model.complete(messages, self.gateway.registry.schemas())
                self.gateway.event(
                    self.ctx,
                    "model_completed",
                    calls=len(response.tool_calls),
                    model=type(self.model).__name__,
                )
                text = response.text
                if not response.tool_calls:
                    break
                for call in response.tool_calls:
                    decision = self.gateway.review_tool_call(call, self.ctx)
                    if decision.decision == Decision.ESCALATE:
                        approval = ApprovalRequest(
                            uuid4().hex,
                            self.ctx.session_id,
                            deepcopy(call),
                            call_hash(call),
                            context_hash(self.ctx),
                            decision.reasons[0].message,
                            decision.taint_sources,
                            self.gateway.registry.tools[call.name].risk.value,
                            time.time(),
                        )
                        self.approvals[approval.id] = approval
                        self.gateway.event(
                            self.ctx, "approval_requested", approval=asdict(approval)
                        )
                        return self.result("Action paused for human review.", start)
                    if decision.decision == Decision.BLOCK:
                        feedback.append(
                            {"role": "tool", "name": call.name, "content": "Blocked by policy."}
                        )
                    else:
                        result = self.tools.execute(call)
                        item = self.gateway.ingest(result, "tool:" + call.name, self.ctx)
                        feedback.append({"role": "tool", "name": call.name, "content": item.text})
            else:
                text = "Stopped at the six-iteration safety limit."
            safe, _ = self.gateway.review_output(text, self.ctx)
            return self.result(safe, start)

    def result(self, text: str, start: int = 0) -> dict[str, Any]:
        decisions = [
            e["data"]["decision"] for e in self.ctx.trace[start:] if e["event"] == "decision"
        ]
        return {
            "session_id": self.ctx.session_id,
            "response": text,
            "trace": self.ctx.trace[start:],
            "decisions": decisions,
            "pending": sum(a.status == "pending" for a in self.approvals.values()),
            "simulated_sends": len(self.tools.sent),
            "executed_count": len(self.tools.executed),
            "defense": self.gateway.defense_enabled,
        }

    def resolve(self, approval_id: str, approve: bool) -> dict[str, Any]:
        with self.lock:
            approval = self.approvals[approval_id]
            if approval.status != "pending":
                raise ValueError("Approval already consumed")
            approval.status = (
                "consumed"  # consumed before execution; failed approvals cannot be replayed
            )
            if (
                time.time() - approval.created_at > 300
                or approval.session_id != self.ctx.session_id
                or approval.args_hash != call_hash(approval.tool)
                or approval.context_hash != context_hash(self.ctx)
            ):
                self.gateway.event(
                    self.ctx, "approval_resolved", id=approval_id, status="invalidated"
                )
                raise ValueError("Approval expired or context/arguments changed")
            if approve:
                # Revalidate current policy: approval never overrides a BLOCK.
                from .permissions import PermissionEngine

                if (
                    PermissionEngine(self.gateway.policy).decide(approval.tool, self.ctx).decision
                    == Decision.BLOCK
                ):
                    raise ValueError("Current policy blocks this action")
                result = self.tools.execute(approval.tool)
                item = self.gateway.ingest(result, "tool:" + approval.tool.name, self.ctx)
                text, _ = self.gateway.review_output(item.text, self.ctx)
            else:
                text = "Action denied; no tool executed."
            approval.status = "approved" if approve else "denied"
            self.ctx.approval_history.append({"id": approval_id, "status": approval.status})
            self.gateway.event(
                self.ctx, "approval_resolved", id=approval_id, status=approval.status
            )
            return self.result(text)
