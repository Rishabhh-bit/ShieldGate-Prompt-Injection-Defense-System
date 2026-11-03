from dataclasses import asdict
from time import perf_counter
from typing import Any

from .audit import AuditLog
from .detect import Detector, HeuristicDetector
from .isolate import build_prompt
from .output_guard import guard_output
from .permissions import PermissionEngine
from .policy import Policy
from .sanitize import sanitize
from .tools.registry import ToolRegistry
from .trust import make_item
from .types import (
    ContentItem,
    Decision,
    Finding,
    GatewayDecision,
    SessionContext,
    ToolCall,
    TrustLevel,
)
from .validate import validate_tool_call

LAYERS = ("trust", "sanitize", "isolate", "detect", "validate", "permissions", "output", "audit")


class ShieldGate:
    def __init__(
        self,
        policy: Policy,
        registry: ToolRegistry,
        audit: AuditLog,
        detector: Detector | None = None,
    ):
        self.policy, self.registry, self.audit = policy, registry, audit
        self.detector = detector or HeuristicDetector()
        self.defense_enabled = True
        self.disabled_layers: set[str] = set()
        self.defense_ms = 0.0

    def enabled(self, layer: str) -> bool:
        return self.defense_enabled and layer not in self.disabled_layers

    def event(self, ctx: SessionContext, event: str, **data: Any) -> None:
        # Baseline and audit ablation retain safe in-memory traces, no persistence.
        log = self.audit if self.enabled("audit") else AuditLog()
        ctx.trace.append(log.append(ctx.session_id, event, data, ctx.secrets))

    def ingest(self, text: str, source: str, ctx: SessionContext) -> ContentItem:
        start = perf_counter()
        item = make_item(text, source, is_user=source == "user")
        if not self.enabled("trust") and source != "user":
            item.trust = TrustLevel.USER  # intentionally unsafe experimental ablation
        self.event(ctx, "content_ingested", id=item.id, source=source, trust=item.trust.value)
        result = sanitize(text) if self.enabled("sanitize") else None
        item.text = result.clean_text if result else text
        item.meta["sanitize_findings"] = [asdict(f) for f in result.findings] if result else []
        self.event(
            ctx,
            "sanitized",
            id=item.id,
            modified=result.modified if result else False,
            findings=item.meta["sanitize_findings"],
            enabled=self.enabled("sanitize"),
        )
        if self.enabled("detect"):
            # Inspect raw AND cleaned forms: removing hidden text must not erase its risk signal.
            raw = self.detector.detect(text[:20000], source_trust=item.trust)
            clean = self.detector.detect(item.text, source_trust=item.trust)
            detected = max((raw, clean), key=lambda r: r.score)
            if detected.label == "injection":
                item.trust = TrustLevel.HOSTILE
            item.meta["score"] = detected.score
            self.event(
                ctx,
                "detected",
                id=item.id,
                score=detected.score,
                label=detected.label,
                findings=[asdict(f) for f in detected.findings],
            )
        ctx.items.append(item)
        if item.trust in (TrustLevel.UNTRUSTED, TrustLevel.HOSTILE):
            ctx.taint.add(item.id)
        self.defense_ms += (perf_counter() - start) * 1000
        return item

    def prepare_prompt(self, system: str, user: str, ctx: SessionContext) -> list[dict[str, Any]]:
        start = perf_counter()
        ctx.system_prompt = system
        external = [i for i in ctx.items if i.source != "user"]
        if self.enabled("isolate"):
            messages = build_prompt(system, user, external)
        else:
            messages = [
                {"role": "system", "content": system},
                {"role": "user", "kind": "request", "content": user},
            ] + [{"role": "user", "kind": "external", "content": i.text} for i in external]
        self.event(ctx, "isolated", items=len(external), enabled=self.enabled("isolate"))
        self.defense_ms += (perf_counter() - start) * 1000
        return messages

    def review_tool_call(self, call: ToolCall, ctx: SessionContext) -> GatewayDecision:
        start = perf_counter()
        self.event(ctx, "tool_proposed", tool=asdict(call))
        findings = (
            validate_tool_call(call, self.registry, self.policy.for_context(ctx))
            if self.enabled("validate")
            else []
        )
        self.event(
            ctx,
            "validated",
            findings=[asdict(f) for f in findings],
            enabled=self.enabled("validate"),
        )
        if findings:
            decision = GatewayDecision(Decision.BLOCK, findings, call, sorted(ctx.taint))
        elif self.enabled("permissions"):
            engine = PermissionEngine(self.policy)
            engine.registry = self.registry
            engine.validation_enabled = False  # L5 already ran, allowing true individual ablation
            decision = engine.decide(call, ctx)
        else:
            decision = GatewayDecision(Decision.ALLOW, [], call, sorted(ctx.taint))
        ctx.tool_call_count += 1
        ctx.tool_counts[call.name] = ctx.tool_counts.get(call.name, 0) + 1
        self.event(
            ctx,
            "decision",
            decision=decision.decision.value,
            tool=call.name,
            reasons=[asdict(f) for f in decision.reasons],
            taint_sources=decision.taint_sources,
        )
        self.defense_ms += (perf_counter() - start) * 1000
        return decision

    def review_output(self, text: str, ctx: SessionContext) -> tuple[str, list[Finding]]:
        start = perf_counter()
        result = guard_output(text, ctx, self.policy) if self.enabled("output") else (text, [])
        self.event(
            ctx,
            "output_guarded",
            findings=[asdict(f) for f in result[1]],
            enabled=self.enabled("output"),
        )
        self.defense_ms += (perf_counter() - start) * 1000
        return result
