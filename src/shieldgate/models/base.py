from typing import Any, Protocol

from ..types import ModelResponse


class ModelAdapter(Protocol):
    def complete(
        self, messages: list[dict[str, Any]], tools: list[dict[str, Any]]
    ) -> ModelResponse: ...
