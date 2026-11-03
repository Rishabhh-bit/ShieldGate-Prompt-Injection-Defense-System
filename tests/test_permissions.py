from pathlib import Path

import pytest

from shieldgate.permissions import PermissionEngine
from shieldgate.policy import load_policy
from shieldgate.tools.registry import ToolRegistry
from shieldgate.types import ContentItem, Decision, SessionContext, ToolCall, TrustLevel
from shieldgate.validate import validate_tool_call


def test_fail_closed(tmp_path):
    with pytest.raises(FileNotFoundError):
        load_policy(tmp_path / "missing")
    for value in [
        "garbage",
        "version: 1\ndefault_action: allow",
        "version: 1\ndefault_action: block\nroles: {}\ntools: {}\nextra: true",
    ]:
        p = tmp_path / "bad.yaml"
        p.write_text(value)
        with pytest.raises(ValueError):
            load_policy(p)


@pytest.mark.parametrize(
    "name,args,code",
    [
        ("unknown", {}, "TOOL_NOT_ALLOWED"),
        ("run_shell", {"command": "echo test"}, "TOOL_NOT_ALLOWED"),
        ("read_file", {"path": "../../etc/passwd"}, "PATH_ESCAPE"),
        ("read_file", {"path": "/etc/passwd"}, "PATH_ESCAPE"),
        ("read_file", {"path": "%252e%252e/outside"}, "PATH_ESCAPE"),
        ("read_file", {"path": "x", "admin": True}, "SCHEMA_VIOLATION"),
        ("read_file", {"path": 12}, "SCHEMA_VIOLATION"),
        ("http_get", {"url": "https://docs.python.org.evil.com"}, "URL_NOT_ALLOWED"),
        ("http_get", {"url": "http://docs.python.org"}, "URL_NOT_ALLOWED"),
        ("http_get", {"url": "https://docs.python.org:88"}, "URL_NOT_ALLOWED"),
        ("http_get", {"url": "https://user@docs.python.org"}, "URL_NOT_ALLOWED"),
        ("http_get", {"url": "https://["}, "URL_NOT_ALLOWED"),
        ("http_get", {"url": "https://docs.python.org/?data=" + "a" * 40}, "EXFIL_IN_ARGS"),
        (
            "send_email",
            {"to": ["evil@example.test"], "subject": "x", "body": "x"},
            "RECIPIENT_NOT_ALLOWED",
        ),
        (
            "send_email",
            {"to": ["bob@company.com"], "subject": "x\r\ny", "body": "x"},
            "HEADER_INJECTION",
        ),
    ],
)
def test_validation(name, args, code):
    assert code in {
        f.code for f in validate_tool_call(ToolCall(name, args), ToolRegistry(), load_policy())
    }


def test_symlink(tmp_path):
    p = load_policy()
    p.sandbox_dir = str(tmp_path / "sandbox")
    Path(p.sandbox_dir).mkdir()
    (Path(p.sandbox_dir) / "link").symlink_to(tmp_path)
    assert validate_tool_call(ToolCall("read_file", {"path": "link/outside"}), ToolRegistry(), p)


def test_taint_and_limits():
    p = load_policy()
    engine = PermissionEngine(p)
    ctx = SessionContext()
    mail = ToolCall("send_email", {"to": ["bob@company.com"], "subject": "x", "body": "x"})
    assert engine.decide(mail, ctx).decision == Decision.ALLOW
    ctx.items.append(ContentItem("u", "plain", "file:x"))
    ctx.taint.add("u")
    assert engine.decide(mail, ctx).decision == Decision.ESCALATE
    ctx.items[0].trust = TrustLevel.HOSTILE
    assert engine.decide(mail, ctx).decision == Decision.BLOCK
    assert (
        engine.decide(ToolCall("read_file", {"path": "notes.txt"}), ctx).decision == Decision.ALLOW
    )
    ctx.role = "unknown"
    assert engine.decide(mail, ctx).decision == Decision.BLOCK
    ctx.role = "assistant_standard"
    ctx.items = []
    ctx.taint.clear()
    ctx.tool_call_count = 20
    assert engine.decide(mail, ctx).reasons[0].code == "RATE_LIMIT"
    ctx.tool_call_count = 0
    ctx.secrets = ["private-value"]
    mail.args["body"] = "private-value"
    assert engine.decide(mail, ctx).reasons[0].code == "EXFIL_IN_ARGS"
