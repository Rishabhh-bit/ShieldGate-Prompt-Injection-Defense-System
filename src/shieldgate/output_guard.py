import re
from urllib.parse import unquote, urlsplit

from .policy import Policy
from .types import Finding, SessionContext

SECRET_PATTERNS = [
    r"CANARY-[A-Za-z0-9_-]+",
    r"\bsk-[A-Za-z0-9_-]{12,}",
    r"\bAKIA[A-Z0-9]{16}\b",
    r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+",
    r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----[\s\S]*?(?:-----END [^-]*PRIVATE KEY-----|$)",
]


def redact_secrets(text: str, secrets: list[str] | None = None) -> str:
    for secret in secrets or []:
        if secret:
            text = text.replace(secret, "[REDACTED]")
    for pattern in SECRET_PATTERNS:
        text = re.sub(pattern, "[REDACTED]", text)
    return text


def guard_output(text: str, ctx: SessionContext, policy: Policy) -> tuple[str, list[Finding]]:
    findings: list[Finding] = []
    safe = redact_secrets(text, ctx.secrets)
    if safe != text:
        findings.append(
            Finding("output", "SECRET_LEAK", "critical", "Protected secret removed from response.")
        )
    words = re.findall(r"\w+", ctx.system_prompt.lower())
    candidate = " ".join(re.findall(r"\w+", text.lower()))
    grams = {" ".join(words[i : i + 8]) for i in range(max(0, len(words) - 7))}
    if grams and sum(g in candidate for g in grams) / len(grams) >= 0.35:
        safe = "[Response withheld: internal instructions detected.]"
        findings.append(
            Finding(
                "output", "SYSTEM_PROMPT_LEAK", "critical", "Internal instruction overlap detected."
            )
        )
    # Active HTML is removed entirely; dashboard also uses textContent, never innerHTML for data.
    if re.search(r"<[^>]+>", safe):
        safe = re.sub(
            r"<(?:script|style|iframe|object|svg)\b[^>]*>[\s\S]*?</(?:script|style|iframe|object|svg)>",
            "[active content removed]",
            safe,
            flags=re.I,
        )
        safe = re.sub(r"<[^>]+>", "[HTML removed]", safe)
        findings.append(Finding("output", "ACTIVE_HTML", "high", "HTML rendering was neutralized."))

    def replace_url(match: re.Match[str]) -> str:
        url = match[0]
        try:
            parsed = urlsplit(url if not url.startswith("//") else "https:" + url)
            decoded_url = url
            for _ in range(3):
                decoded_url = unquote(decoded_url)
            contains_secret = redact_secrets(decoded_url, ctx.secrets) != decoded_url
            allowed = (
                not contains_secret
                and parsed.scheme == "https"
                and parsed.hostname in policy.output_domains
                and not parsed.username
                and not parsed.password
                and parsed.port in (None, 443)
                and not parsed.query
                and not parsed.fragment
                and "REDACTED" not in unquote(url)
            )
        except ValueError:
            allowed = False
        if not allowed:
            findings.append(
                Finding("output", "UNSAFE_LINK", "high", "External or data-bearing link removed.")
            )
            return "[link removed]"
        return url

    safe = re.sub(r"(?:https?:)?//[^\s)<>\"\x27]+", replace_url, safe)
    safe = re.sub(r"(?i)(?:javascript|data):[^\s)]+", "[active URL removed]", safe)
    if policy.redact_pii:
        pattern = r"\b[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}\b|(?<!\w)\+?\d[\d -]{8,}\d(?!\w)"

        def pii(match: re.Match[str]) -> str:
            if match[0] in ctx.user_request:
                return match[0]
            findings.append(
                Finding(
                    "output", "PII_REDACTED", "medium", "Out-of-scope personal identifier removed."
                )
            )
            return "[PII removed]"

        safe = re.sub(pattern, pii, safe)
    return safe, findings
