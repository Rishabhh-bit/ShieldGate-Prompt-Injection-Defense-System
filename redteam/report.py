import json
import platform
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from shieldgate.gateway import LAYERS

from .runner import ROOT, load_cases, run_case, run_suite


def build_report(ablation: bool = True) -> dict[str, Any]:
    baseline, protected = run_suite(False), run_suite(True)
    benign = [run_case(c, benign=True) for c in load_cases(True)]
    latencies = sorted(r["defense_ms"] for r in protected["rows"])
    summary = {
        "attack_count": baseline["cases"],
        "benign_count": len(benign),
        "baseline_asr": baseline["asr"],
        "protected_asr": protected["asr"],
        "false_positive_rate": sum(r["false_positive"] for r in benign) / len(benign),
        "benign_escalation_rate": sum("escalate" in r["decisions"] for r in benign) / len(benign),
        "latency_p50_ms": latencies[len(latencies) // 2],
        "latency_p95_ms": latencies[min(len(latencies) - 1, int(len(latencies) * 0.95))],
        "latency_max_ms": max(latencies),
    }
    categories = []
    for category in sorted({r["category"] for r in baseline["rows"]}):
        b = [r for r in baseline["rows"] if r["category"] == category]
        p = [r for r in protected["rows"] if r["category"] == category]
        categories.append(
            {
                "category": category,
                "count": len(b),
                "baseline_asr": sum(r["success"] for r in b) / len(b),
                "protected_asr": sum(r["success"] for r in p) / len(p),
            }
        )
    ablations = (
        [{"disabled_layer": layer, "asr": run_suite(True, layer)["asr"]} for layer in LAYERS]
        if ablation
        else []
    )
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "model": "deterministic GullibleMockModel",
        "python": platform.python_version(),
        "summary": summary,
        "categories": categories,
        "breakdown": dict(Counter(r["disposition"] for r in protected["rows"])),
        "ablations": ablations,
        "baseline": baseline["rows"],
        "protected": protected["rows"],
        "benign": benign,
        "methodology": "Executed mock-tool effects and final output are scored, not proposed calls. Pending approval is containment, not completed work. Benign set uses RobustMockModel. Same cases and model rules across ablations. Each run starts a fresh session. Timing covers deterministic layers with in-memory audit, excludes model/tool time; not a hardware-independent SLA. No LLM efficacy claim.",
    }


def write_report(output: Path | None = None) -> dict[str, Any]:
    report = build_report()
    target = output or ROOT / "reports"
    target.mkdir(parents=True, exist_ok=True)
    (target / "redteam_report.json").write_text(json.dumps(report, indent=2))
    s = report["summary"]
    lines = [
        "# ShieldGate red-team evaluation",
        "",
        f"Generated: {report['generated_at']}",
        "",
        "**Scope: synthetic offline evaluation using rule-based mock models. These numbers do not measure real LLM robustness.**",
        "",
        "| Metric | Measured |",
        "|---|---|",
        f"| Attack cases | {s['attack_count']} |",
        f"| Benign cases | {s['benign_count']} |",
        f"| Baseline ASR | {s['baseline_asr']:.2%} |",
        f"| Protected ASR | {s['protected_asr']:.2%} |",
        f"| Benign false-positive rate | {s['false_positive_rate']:.2%} |",
        f"| Benign escalation rate | {s['benign_escalation_rate']:.2%} |",
        f"| Deterministic latency p50 / p95 | {s['latency_p50_ms']} / {s['latency_p95_ms']} ms |",
        "",
        "## Method",
        "",
        report["methodology"],
        "",
        "The corpus is a fixed regression set, not an independently held-out test set. ACTION JSON cases explicitly test tool-boundary validation; other cases exercise natural-language patterns. The gullible model intentionally ignores spotlighting. Thus a zero ablation delta for isolation does not assess its value on a real LLM. Audit is observational; removing it is not expected to change ASR. Redundant controls can also yield zero individual deltas.",
        "",
        "## Categories",
        "",
        "| Category | Cases | Baseline | Protected |",
        "|---|---:|---:|---:|",
    ]
    lines += [
        f"| {r['category']} | {r['count']} | {r['baseline_asr']:.1%} | {r['protected_asr']:.1%} |"
        for r in report["categories"]
    ]
    lines += [
        "",
        "## Protected outcomes",
        "",
        str(report["breakdown"]),
        "",
        "## Individual ablations",
        "",
        "| Disabled layer | ASR |",
        "|---|---:|",
    ]
    lines += [f"| {r['disabled_layer']} | {r['asr']:.2%} |" for r in report["ablations"]]
    lines += [
        "",
        "## First observed stopping layer",
        "",
        "Attribution is observational, not proof that a layer was necessary. Sanitization attribution is used when content was removed and no harmful action reached the gateway. Baseline failures are marked separately.",
        "",
        "| Case | Baseline reproduced | Protected outcome | First layer |",
        "|---|---|---|---|",
    ]
    for b, p in zip(report["baseline"], report["protected"], strict=True):
        lines.append(
            f"| {p['id']} | {b['success']} | {p['disposition']} | {p['first_stopping_layer'] if b['success'] else 'baseline not reproduced'} |"
        )
    (target / "redteam_report.md").write_text("\n".join(lines) + "\n")
    return report


if __name__ == "__main__":
    print(json.dumps(write_report()["summary"], indent=2))
