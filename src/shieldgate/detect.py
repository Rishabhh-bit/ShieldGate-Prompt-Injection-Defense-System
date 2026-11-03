"""Explainable heuristic signals; detection is never the authorization boundary."""

import re
from dataclasses import dataclass
from typing import Literal, Protocol

from .types import Finding, TrustLevel

RULES = [
    (
        "INSTRUCTION_OVERRIDE",
        0.78,
        r"ignore\s+(?:all\s+)?(?:previous|prior|above)\s+instructions|disregard|forget everything|you are now|new instructions",
    ),
    (
        "AUTHORITY_SPOOF",
        0.60,
        r"system\s*:|system override|developer message|admin says|\[INST\]|<\|im_start\|>|### System",
    ),
    (
        "ACTION_IMPERATIVE",
        0.35,
        r"(?:send|forward)\b.{0,160}?\bto\b|call the .{0,30} tool|\bexecute\b|\bdelete\b|download and run",
    ),
    (
        "EXFILTRATION",
        0.80,
        r"reveal.{0,40}(?:system prompt|canary)|print your instructions|repeat everything above|include the contents of|append.{0,60}to the URL",
    ),
    ("COERCION", 0.45, r"do this immediately|do not tell the user|secretly"),
    ("MODEL_ADDRESS", 0.45, r"AI assistant\s*:|if you are an LLM|note to the AI"),
    ("MEMORY_POISONING", 0.80, r"remember this instruction|persist this rule|when asked next time"),
]
COMPILED = [(code, weight, re.compile(pattern, re.I | re.S)) for code, weight, pattern in RULES]


@dataclass
class DetectResult:
    score: float
    label: Literal["clean", "suspicious", "injection"]
    findings: list[Finding]


class Detector(Protocol):
    def detect(self, text: str, *, source_trust: TrustLevel) -> DetectResult: ...


class HeuristicDetector:
    def __init__(self, suspicious: float = 0.3, injection: float = 0.7) -> None:
        if not 0 < suspicious < injection <= 1:
            raise ValueError("Invalid detection thresholds")
        self.suspicious, self.injection = suspicious, injection

    def detect(self, text: str, *, source_trust: TrustLevel) -> DetectResult:
        if source_trust == TrustLevel.TRUSTED:
            return DetectResult(0, "clean", [])
        complement = 1.0
        findings = []
        for code, weight, pattern in COMPILED:
            if pattern.search(text):
                complement *= 1 - weight
                findings.append(
                    Finding(
                        "detect",
                        code,
                        "medium",
                        f"Matched {code.lower().replace('_', ' ')} pattern.",
                    )
                )
        score = 1 - complement
        label: Literal["clean", "suspicious", "injection"] = (
            "injection"
            if score >= self.injection
            else "suspicious"
            if score >= self.suspicious
            else "clean"
        )
        return DetectResult(round(score, 4), label, findings)


def detect(text: str, *, source_trust: TrustLevel) -> DetectResult:
    return HeuristicDetector().detect(text, source_trust=source_trust)
