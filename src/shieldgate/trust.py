"""Only the host assigns provenance. Never derive trust from document text."""

from typing import Any
from uuid import uuid4

from .types import ContentItem, TrustLevel

EXTERNAL = ("email:", "web:", "file:", "tool:", "rag:", "agent:")


def classify(source: str, *, is_system: bool = False, is_user: bool = False) -> TrustLevel:
    if source.startswith(EXTERNAL):
        return TrustLevel.UNTRUSTED
    if source in {"system", "policy"} and is_system:
        return TrustLevel.TRUSTED
    if source == "user" and is_user:
        return TrustLevel.USER
    return TrustLevel.UNTRUSTED


def make_item(text: str, source: str, **kw: Any) -> ContentItem:
    return ContentItem(
        id=kw.get("id", uuid4().hex[:12]),
        text=text,
        source=source,
        trust=classify(
            source, is_system=kw.get("is_system", False), is_user=kw.get("is_user", False)
        ),
        meta=kw.get("meta", {}),
    )
