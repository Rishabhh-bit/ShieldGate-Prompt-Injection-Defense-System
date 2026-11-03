"""Bounded normalization and visible-text extraction, not a general HTML renderer."""

import base64
import re
import unicodedata
from dataclasses import dataclass
from html.parser import HTMLParser

from .detect import detect
from .types import Finding, TrustLevel

CONFUSABLES = str.maketrans({"о": "o", "е": "e", "а": "a", "і": "i", "с": "c", "р": "p", "х": "x"})


@dataclass
class SanitizeResult:
    clean_text: str
    findings: list[Finding]
    modified: bool


class VisibleText(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.stack: list[tuple[str, bool]] = []
        self.parts: list[str] = []
        self.hidden = False

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        a = dict(attrs)
        style = re.sub(r"\s+", "", a.get("style") or "").lower()
        hide = (
            tag in {"script", "style", "template", "iframe", "object", "svg", "head", "noscript"}
            or "hidden" in a
            or (a.get("aria-hidden") or "").lower() == "true"
            or bool(
                re.search(
                    r"display:none|visibility:hidden|font-size:0(?:[a-z;%]|$)|opacity:0(?:[;.]|$)",
                    style,
                )
            )
            or bool(re.search(r"(?:^|;)color:(?:white|#fff(?:fff)?)(?:;|$)", style))
        )
        inherited = any(h for _, h in self.stack)
        if hide or tag in {"img", "meta", "link", "input", "source"}:
            self.hidden = True
        if tag not in {
            "area",
            "base",
            "br",
            "col",
            "embed",
            "hr",
            "img",
            "input",
            "link",
            "meta",
            "param",
            "source",
            "track",
            "wbr",
        }:
            self.stack.append((tag, hide or inherited))
        if tag in {"p", "div", "br", "li"} and not inherited:
            self.parts.append("\n")

    def handle_startendtag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self.handle_starttag(tag, attrs)
        self.handle_endtag(tag)

    def handle_endtag(self, tag: str) -> None:
        for i in range(len(self.stack) - 1, -1, -1):
            if self.stack[i][0] == tag:
                self.stack = self.stack[:i]
                break

    def handle_data(self, data: str) -> None:
        if not any(hidden for _, hidden in self.stack):
            self.parts.append(data)

    def handle_comment(self, data: str) -> None:
        self.hidden = True


def sanitize(text: str, *, max_len: int = 20_000) -> SanitizeResult:
    if max_len < 1:
        raise ValueError("max_len must be positive")
    original, findings = text, []

    def flag(code: str, message: str) -> None:
        findings.append(Finding("sanitize", code, "medium", message))

    if len(text) > max_len:
        text = text[:max_len]
        flag("TRUNCATED", "Input exceeded the configured length cap.")
    normalized = unicodedata.normalize("NFKC", text).translate(CONFUSABLES)
    if normalized != text:
        flag("UNICODE_NORMALIZED", "Normalized compatibility characters and selected confusables.")
    text = normalized
    for pattern, code in [
        (r"[\u200b-\u200f\u2060\ufeff]", "ZERO_WIDTH_CHARS"),
        (r"[\u202a-\u202e\u2066-\u2069]", "BIDI_OVERRIDE"),
        (r"[\U000e0000-\U000e007f]", "TAG_CHARS"),
    ]:
        if re.search(pattern, text):
            text = re.sub(pattern, "", text)
            flag(code, "Removed invisible or directional characters.")
    for blob in set(re.findall(r"(?<![\w])[A-Za-z0-9+/=]{32,}(?![\w])", text)):
        for decoder in (base64.b64decode, bytes.fromhex):
            try:
                decoded = decoder(blob).decode("utf-8")
            except (ValueError, UnicodeError):
                continue
            if detect(decoded, source_trust=TrustLevel.UNTRUSTED).score >= 0.3:
                text = text.replace(blob, "[encoded instruction removed]")
                flag("ENCODED_PAYLOAD", "Encoded text contained an instruction pattern.")
                break
    if re.search(r"</?[a-zA-Z]|<!--", text):
        parser = VisibleText()
        parser.feed(text)
        parser.close()
        text = "".join(parser.parts)
        if parser.hidden:
            flag("HIDDEN_HTML", "Removed hidden HTML, comments, metadata or active elements.")
    pattern = r"!?\[[^\]]*\]\(\s*(?:https?:)?//[^\s)]*(?:\s+[^)]*)?\)"
    if re.search(pattern, text, re.I):
        text = re.sub(pattern, "[remote reference removed]", text, flags=re.I)
        flag("MD_REMOTE_IMAGE", "Neutralized a remote Markdown image or link.")
    text = re.sub(r"[ \t]{2,}", " ", text)
    text = re.sub(r"\n\s*\n(?:\s*\n)+", "\n\n", text).strip()
    return SanitizeResult(text, findings, text != original)
