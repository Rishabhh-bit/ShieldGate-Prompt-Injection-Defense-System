"""Public contracts and server-owned session state."""

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Literal
from uuid import uuid4


class TrustLevel(str, Enum):
    TRUSTED = "trusted"
    USER = "user"
    UNTRUSTED = "untrusted"
    HOSTILE = "hostile"


class RiskTier(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class Decision(str, Enum):
    ALLOW = "allow"
    BLOCK = "block"
    ESCALATE = "escalate"


@dataclass
class ContentItem:
    id: str
    text: str
    source: str
    trust: TrustLevel = TrustLevel.UNTRUSTED
    meta: dict[str, Any] = field(default_factory=dict)


@dataclass
class ToolCall:
    name: str
    args: dict[str, Any]
    call_id: str = ""


@dataclass
class Finding:
    layer: str
    code: str
    severity: Literal["info", "low", "medium", "high", "critical"]
    message: str
    evidence: str = ""


@dataclass
class GatewayDecision:
    decision: Decision
    reasons: list[Finding]
    tool_call: ToolCall | None
    taint_sources: list[str]


@dataclass
class ModelResponse:
    text: str = ""
    tool_calls: list[ToolCall] = field(default_factory=list)


@dataclass
class SessionContext:
    role: str = "assistant_standard"
    session_id: str = field(default_factory=lambda: uuid4().hex)
    items: list[ContentItem] = field(default_factory=list)
    taint: set[str] = field(default_factory=set)
    tool_call_count: int = 0
    tool_counts: dict[str, int] = field(default_factory=dict)
    approval_history: list[dict[str, Any]] = field(default_factory=list)
    trace: list[dict[str, Any]] = field(default_factory=list)
    system_prompt: str = ""
    secrets: list[str] = field(default_factory=list)
    user_request: str = ""


@dataclass
class ApprovalRequest:
    id: str
    session_id: str
    tool: ToolCall
    args_hash: str
    context_hash: str
    reason: str
    taint_sources: list[str]
    risk: str
    created_at: float
    status: str = "pending"
