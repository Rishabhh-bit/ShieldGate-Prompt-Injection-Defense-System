from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, PrivateAttr, model_validator

from .types import SessionContext

ROOT = Path(__file__).resolve().parents[2]


class ClosedModel(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


class Role(ClosedModel):
    allow_tools: list[str]


class ToolPolicy(ClosedModel):
    enabled: bool = True
    risk: Literal["low", "medium", "high"] = "low"
    recipient_domains_allowlist: list[str] = Field(default_factory=list)
    domain_allowlist: list[str] = Field(default_factory=list)
    max_recipients: int = Field(default=3, ge=1, le=3)
    require_human_approval_if_tainted: bool = False
    require_human_approval: Literal["always", "never"] = "never"
    max_calls: int = Field(default=10, ge=1, le=100)


class TaintPolicy(ClosedModel):
    high_risk_tools: Literal["escalate", "block"] = "escalate"
    egress_tools: Literal["escalate", "block"] = "escalate"
    hostile_content_present: Literal["block"] = "block"


class Limits(ClosedModel):
    max_tool_calls_per_session: int = Field(default=20, ge=1, le=100)


class Policy(ClosedModel):
    version: Literal[1]
    default_action: Literal["block"]
    roles: dict[str, Role]
    tools: dict[str, ToolPolicy]
    taint: TaintPolicy = Field(default_factory=TaintPolicy)
    limits: Limits = Field(default_factory=Limits)
    sandbox_dir: str = "./sandbox"
    output_domains: list[str] = Field(default_factory=lambda: ["docs.python.org", "wikipedia.org"])
    redact_pii: bool = False
    _ctx: SessionContext | None = PrivateAttr(default=None)

    @model_validator(mode="after")
    def known_tools(self) -> "Policy":
        from .tools.registry import ToolRegistry

        known = set(ToolRegistry().tools)
        if set(self.tools) - known or any(
            set(r.allow_tools) - set(self.tools) for r in self.roles.values()
        ):
            raise ValueError("Unknown tool or missing tool policy")
        return self

    def for_context(self, ctx: SessionContext) -> "Policy":
        copy = self.model_copy(deep=True)
        copy._ctx = ctx
        return copy


def load_policy(path: str | Path | None = None) -> Policy:
    import os

    target = Path(path or os.environ.get("SHIELDGATE_POLICY") or ROOT / "policies/default.yaml")
    policy = Policy.model_validate(yaml.safe_load(target.read_text()))
    policy.sandbox_dir = str(
        Path(os.environ.get("SHIELDGATE_SANDBOX", policy.sandbox_dir)).resolve()
    )
    return policy
