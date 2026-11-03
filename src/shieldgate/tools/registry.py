from dataclasses import dataclass
from typing import Any

from ..types import RiskTier


@dataclass(frozen=True)
class ToolDefinition:
    name: str
    schema: dict[str, Any]
    risk: RiskTier
    egress: bool = False


def string(limit: int = 2000) -> dict[str, Any]:
    return {"type": "string", "minLength": 1, "maxLength": limit}


def schema(properties: dict[str, Any]) -> dict[str, Any]:
    return {
        "type": "object",
        "properties": properties,
        "required": list(properties),
        "additionalProperties": False,
    }


class ToolRegistry:
    def __init__(self) -> None:
        low, medium, high = RiskTier.LOW, RiskTier.MEDIUM, RiskTier.HIGH
        definitions = [
            ToolDefinition("read_inbox", schema({}), low),
            ToolDefinition("read_file", schema({"path": string(512)}), low),
            ToolDefinition("search_web", schema({"query": string(500)}), low),
            ToolDefinition("http_get", schema({"url": string(2048)}), medium, True),
            ToolDefinition(
                "write_note", schema({"title": string(120), "body": string(4000)}), medium
            ),
            ToolDefinition(
                "send_email",
                schema(
                    {
                        "to": {"type": "array", "items": string(254), "minItems": 1, "maxItems": 3},
                        "subject": string(200),
                        "body": string(8000),
                    }
                ),
                high,
                True,
            ),
            ToolDefinition("delete_file", schema({"path": string(512)}), high),
            ToolDefinition("run_shell", schema({"command": string(2000)}), high, True),
        ]
        self.tools = {item.name: item for item in definitions}

    def get(self, name: str) -> ToolDefinition | None:
        return self.tools.get(name)

    def schemas(self) -> list[dict[str, Any]]:
        return [{"name": t.name, "input_schema": t.schema} for t in self.tools.values()]
