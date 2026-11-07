"""Evidence discipline: markers, body diffs, timing and the 7-Question Gate."""

from __future__ import annotations

import re
import secrets
import statistics
from datetime import datetime, timezone

MARKER_RE = re.compile(r"^hun[0-9a-f]{8}$")


def make_marker(prefix: str = "hun") -> str:
    marker = f"{prefix}{secrets.token_hex(4)}"
    return marker


def baseline_has_marker(baseline: str, marker: str) -> bool:
    return bool(marker) and marker in (baseline or "")


def reflected_raw(baseline: str, body: str, marker: str) -> bool:
    """A reflection only counts if it is raw and absent from the baseline."""
    if not marker or marker not in (body or ""):
        return False
    if baseline_has_marker(baseline, marker):
        return False
    return True


def reflected_encoded(baseline: str, body: str, marker: str) -> bool:
    if not marker:
        return False
    encoded = marker.replace("<", "&lt;").replace(">", "&gt;")
    return encoded != marker and encoded in (body or "") and not baseline_has_marker(baseline, marker)


def normalized(body: str) -> str:
    return re.sub(r"\s+", " ", body or "").strip()


def body_changed(baseline: str, candidate: str, min_ratio: float = 0.01) -> bool:
    a, b = normalized(baseline), normalized(candidate)
    if a == b:
        return False
    if not a or not b:
        return True
    common = sum(1 for x, y in zip(a, b) if x == y)
    ratio = common / max(len(a), len(b))
    return (1.0 - ratio) >= min_ratio


def timing_signal(control: list[float], test: list[float]) -> tuple[bool, dict]:
    info = {"control_n": len(control), "test_n": len(test)}
    if len(control) < 5 or len(test) < 5:
        info["reason"] = "amostras insuficientes (n < 5)"
        return False, info
    control_mean = statistics.fmean(control)
    test_mean = statistics.fmean(test)
    sigma = statistics.pstdev(control)
    threshold = control_mean + 2.0 * max(sigma, 0.02)
    info.update(
        {
            "control_mean": round(control_mean, 4),
            "test_mean": round(test_mean, 4),
            "control_sigma": round(sigma, 4),
            "threshold": round(threshold, 4),
        }
    )
    return test_mean >= threshold and test_mean > control_mean + 0.2, info


def seven_question_gate(finding: dict) -> tuple[bool, list[str]]:
    """The 7-Question Gate.  A failed gate can never be 'confirmed'."""
    checks = [
        ("asset dentro do escopo", bool(finding.get("in_scope", True))),
        ("reproduzível", bool(finding.get("reproducible"))),
        ("evidência concreta anexada", bool(finding.get("evidence"))),
        ("impacto demonstrado, não inferido", bool(finding.get("impact_demonstrated"))),
        ("prerequisitos declarados", bool(finding.get("prerequisites"))),
        ("teste não destrutivo", bool(finding.get("non_destructive", True))),
        ("não é apenas um lead de scanner", bool(finding.get("marker_verified", True))),
    ]
    failed = [name for name, ok in checks if not ok]
    return not failed, failed


def finalize(finding: dict) -> dict:
    """Down-grade status when the evidence does not clear the gate."""
    passed, failed = seven_question_gate(finding)
    finding["gate_passed"] = passed
    finding["gate_failed"] = failed
    if not passed and finding.get("status") == "confirmed":
        finding["status"] = "potential"
        finding["gate_note"] = "rebaixado para potential: " + ", ".join(failed)
    return finding


def severity_ok(status: str, severity: str) -> bool:
    if status == "potential":
        return severity in ("low", "medium", "high", "critical", "info")
    return severity in ("low", "medium", "high", "critical")


def run_validation(ctx, host: str) -> None:
    """Phase 4 pass over all findings: gate, confidence and coverage."""
    state = ctx.targets[host]
    phase = state["phases"]["validate"]
    phase["status"] = "running"
    phase["started_utc"] = phase.get("started_utc") or datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    ctx.budget.mark_phase("validate")
    for finding in state.get("findings", []):
        finalize(finding)
        if finding.get("gate_passed"):
            detail = "gate 7 perguntas aprovado"
        else:
            detail = "rebaixado: " + ", ".join(finding.get("gate_failed", []))
        ctx.add_coverage(host, finding.get("endpoint", ""), "validate", finding.get("status", ""), detail)
    phase["status"] = "done"
    phase["finished_utc"] = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    ctx.flush(host)
