from .policy import Policy
from .tools.registry import ToolRegistry
from .types import (
    Decision,
    Finding,
    GatewayDecision,
    RiskTier,
    SessionContext,
    ToolCall,
    TrustLevel,
)
from .validate import validate_tool_call


class PermissionEngine:
    def __init__(self, policy: Policy):
        self.policy = policy
        self.registry = ToolRegistry()
        self.validation_enabled = True

    def decide(self, call: ToolCall, ctx: SessionContext) -> GatewayDecision:
        taint = sorted(
            {i.id for i in ctx.items if i.trust in (TrustLevel.UNTRUSTED, TrustLevel.HOSTILE)}
            | ctx.taint
        )
        config = self.policy.tools.get(call.name)
        tool = self.registry.get(call.name)
        role = self.policy.roles.get(ctx.role)

        def result(decision: Decision, code: str, message: str) -> GatewayDecision:
            return GatewayDecision(
                decision,
                [
                    Finding(
                        "permissions",
                        code,
                        "high" if decision == Decision.BLOCK else "medium",
                        message,
                    )
                ],
                call,
                taint,
            )

        if (
            not tool
            or not config
            or not config.enabled
            or not role
            or call.name not in role.allow_tools
        ):
            return result(
                Decision.BLOCK, "TOOL_NOT_ALLOWED", "Tool is not permitted for this session."
            )
        findings = (
            validate_tool_call(call, self.registry, self.policy.for_context(ctx))
            if self.validation_enabled
            else []
        )
        if any(f.severity in {"high", "critical"} for f in findings):
            return GatewayDecision(Decision.BLOCK, findings, call, taint)
        if any(i.trust == TrustLevel.HOSTILE for i in ctx.items) and tool.risk != RiskTier.LOW:
            return result(
                Decision.BLOCK,
                "HOSTILE_CONTEXT",
                "Hostile content preceded a tool with side effects.",
            )
        if taint and (tool.risk == RiskTier.HIGH or tool.egress):
            actions = []
            if tool.risk == RiskTier.HIGH:
                actions.append(self.policy.taint.high_risk_tools)
            if tool.egress:
                actions.append(self.policy.taint.egress_tools)
            decision = Decision.BLOCK if "block" in actions else Decision.ESCALATE
            return result(
                decision,
                "TAINTED_ACTION",
                f"The agent requested {call.name} after reading untrusted content. Human review is required.",
            )
        if config.require_human_approval == "always" or (
            taint and config.require_human_approval_if_tainted
        ):
            return result(
                Decision.ESCALATE,
                "APPROVAL_REQUIRED",
                "This action requires explicit human approval.",
            )
        return GatewayDecision(Decision.ALLOW, [], call, taint)
