import json
import re
from pathlib import Path
from urllib.parse import unquote, urlsplit

from jsonschema import Draft202012Validator

from .policy import Policy
from .tools.registry import ToolRegistry
from .types import Finding, ToolCall


def validate_tool_call(call: ToolCall, registry: ToolRegistry, policy: Policy) -> list[Finding]:
    findings: list[Finding] = []

    def fail(code: str, message: str) -> None:
        findings.append(Finding("validate", code, "high", message))

    ctx = policy._ctx
    role = policy.roles.get(ctx.role if ctx else "assistant_standard")
    tool, config = registry.get(call.name), policy.tools.get(call.name)
    if (
        not tool
        or not config
        or not config.enabled
        or not role
        or call.name not in role.allow_tools
    ):
        fail("TOOL_NOT_ALLOWED", "Tool is not permitted for this session.")
        return findings
    if list(Draft202012Validator(tool.schema).iter_errors(call.args)):
        fail("SCHEMA_VIOLATION", "Arguments do not match the closed tool schema.")
        return findings
    if ctx and (
        ctx.tool_call_count >= policy.limits.max_tool_calls_per_session
        or ctx.tool_counts.get(call.name, 0) >= config.max_calls
    ):
        fail("RATE_LIMIT", "Session or tool call budget exhausted.")
    if "path" in call.args:
        raw = str(call.args["path"])
        decoded = unquote(unquote(raw)).replace("\\", "/")
        sandbox = Path(policy.sandbox_dir).resolve()
        # /sandbox is a virtual demo alias, never an arbitrary host-file mount.
        relative = decoded.removeprefix("/sandbox/")
        candidate = Path(relative)
        try:
            target = (sandbox / candidate).resolve()
            target.relative_to(sandbox)
            if ".." in candidate.parts or "\x00" in decoded or ":" in decoded:
                raise ValueError("Invalid path")
        except (ValueError, OSError):
            fail("PATH_ESCAPE", "File path escapes the configured sandbox.")
    if call.name == "http_get":
        url = str(call.args["url"])
        try:
            parsed = urlsplit(url)
            if (
                parsed.scheme != "https"
                or parsed.hostname not in config.domain_allowlist
                or parsed.username
                or parsed.password
                or parsed.port not in (None, 443)
                or re.search(r"[\s\\]", url)
            ):
                fail("URL_NOT_ALLOWED", "URL scheme, host, port or credentials are not allowed.")
            decoded = unquote(unquote(url))
            if (
                re.search(r"[A-Za-z0-9+/=_-]{32,}", parsed.query)
                or "CANARY-" in decoded
                or any(s and s in decoded for s in (ctx.secrets if ctx else []))
            ):
                fail("EXFIL_IN_ARGS", "Possible secret or encoded data in URL arguments.")
            if ctx:
                for item in ctx.items:
                    if item.id in ctx.taint and len(item.text) >= 12 and item.text in decoded:
                        fail("EXFIL_IN_ARGS", "URL contains external context text.")
                        break
        except ValueError:
            fail("URL_NOT_ALLOWED", "Malformed URL.")
    if call.name == "send_email":
        if len(call.args["to"]) > config.max_recipients:
            fail("RECIPIENT_LIMIT", "Too many email recipients.")
        for recipient in call.args["to"]:
            if (
                not re.fullmatch(r"[A-Za-z0-9.!#$%&\x27*+/=?^_`{|}~-]+@[A-Za-z0-9.-]+", recipient)
                or recipient.rsplit("@", 1)[-1].lower() not in config.recipient_domains_allowlist
            ):
                fail("RECIPIENT_NOT_ALLOWED", "Recipient is outside permitted email domains.")
        if any("\r" in s or "\n" in s for s in call.args["to"] + [call.args["subject"]]):
            fail("HEADER_INJECTION", "Email header contains a line break.")
        serialized = json.dumps(call.args)
        if ctx and any(secret and secret in serialized for secret in ctx.secrets):
            fail("EXFIL_IN_ARGS", "Email contains a protected secret.")
    return findings
