import json
from dataclasses import dataclass
from typing import Any


@dataclass
class PlanStep:
    plugin: str
    reason: str
    risk_tier: str


def planner(target: str, profile: str = "standard") -> list[PlanStep]:
    steps = [PlanStep(plugin="httpx", reason="Enumerasi endpoint aktif", risk_tier="low")]
    if "api" in target or profile in {"standard", "deep"}:
        steps.append(PlanStep(plugin="nuclei", reason="Template vulnerability scan", risk_tier="medium"))
    if profile == "deep":
        steps.append(PlanStep(plugin="nmap", reason="Service fingerprint", risk_tier="medium"))
    return steps


def judge(step: PlanStep, exit_code: int, output_excerpt: str) -> dict[str, Any]:
    verdict = "pass" if exit_code == 0 else "retry_or_review"
    confidence = 70 if exit_code == 0 else 30
    if "vulnerable" in output_excerpt.lower() or "cve-" in output_excerpt.lower():
        confidence = min(95, confidence + 20)
    return {
        "plugin": step.plugin,
        "verdict": verdict,
        "confidence": confidence,
        "reason": step.reason,
    }


def dry_run_explain(target: str, profile: str = "standard") -> str:
    plan = planner(target, profile=profile)
    payload = {
        "target": target,
        "profile": profile,
        "mode": "dry_run_explain",
        "steps": [s.__dict__ for s in plan],
    }
    return json.dumps(payload, ensure_ascii=True, indent=2)
