import os
import time
from datetime import datetime
from pathlib import Path

try:
    from .ai_loop import PlanStep, judge
    from .importers import parse_generic_output, parse_nuclei_output
    from .policy import classify_plugin_tier, worker_approval_allowed
    from .plugin_loader import load_plugins
    from .runner import run_command
    from .state_db import (
        append_timeline_event,
        claim_next_job,
        finish_job,
        init_db,
        list_jobs,
        update_scan_status,
        upsert_finding,
    )
except ImportError:
    from ai_loop import PlanStep, judge
    from importers import parse_generic_output, parse_nuclei_output
    from policy import classify_plugin_tier, worker_approval_allowed
    from plugin_loader import load_plugins
    from runner import run_command
    from state_db import (
        append_timeline_event,
        claim_next_job,
        finish_job,
        init_db,
        list_jobs,
        update_scan_status,
        upsert_finding,
    )


def _write_output(path: str, content: str) -> None:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(content, encoding="utf-8")


def _extract_findings(plugin_name: str, output_path: str):
    if plugin_name == "nuclei":
        return parse_nuclei_output(output_path)
    return parse_generic_output(output_path, plugin_name)


def recompute_scan_status(scan_id: int) -> None:
    jobs = [j for j in list_jobs(scan_id=scan_id, limit=500)]
    if not jobs:
        return
    statuses = {j["status"] for j in jobs}
    if "running" in statuses or "pending" in statuses:
        update_scan_status(scan_id, "running")
        return
    if "awaiting_approval" in statuses and "failed" not in statuses and "blocked" not in statuses:
        update_scan_status(scan_id, "awaiting_approval")
        return
    if "failed" in statuses or "blocked" in statuses or "awaiting_approval" in statuses:
        update_scan_status(scan_id, "partial_failed_or_blocked")
        return
    update_scan_status(scan_id, "completed")


def run_worker_loop(poll_sec: float = 1.5) -> None:
    init_db()
    plugins = load_plugins()
    print("[worker] started")
    while True:
        job = claim_next_job()
        if not job:
            time.sleep(poll_sec)
            continue

        job_id = int(job["id"])
        scan_id = int(job["scan_id"])
        plugin = job["plugin_name"]
        cmd = job["command"]
        output_path = str(job["output_path"] or "")
        timeout_sec = int(plugins.get(plugin, {}).get("timeout_sec", 900))
        tier = classify_plugin_tier(plugin, plugins.get(plugin, {}))
        decision_id = f"D-{scan_id}-{job_id}-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}"
        update_scan_status(scan_id, "running")
        append_timeline_event(
            scan_id=scan_id,
            job_id=job_id,
            decision_id=decision_id,
            event="plan",
            status="created",
            detail=f"plugin={plugin}; tier={tier}; command={cmd}",
        )

        allowed, approval_reason = worker_approval_allowed(tier)
        append_timeline_event(
            scan_id=scan_id,
            job_id=job_id,
            decision_id=decision_id,
            event="approval",
            status="approved" if allowed else "awaiting_approval",
            detail=f"tier={tier}; reason={approval_reason}",
        )
        if not allowed:
            finish_job(job_id, "awaiting_approval", None)
            recompute_scan_status(scan_id)
            continue

        print(f"[worker] running job={job_id} plugin={plugin}")
        try:
            append_timeline_event(
                scan_id=scan_id,
                job_id=job_id,
                decision_id=decision_id,
                event="execute",
                status="running",
                detail=f"timeout_sec={timeout_sec}",
            )
            exit_code, out = run_command(cmd, timeout_sec=timeout_sec)
            _write_output(output_path, out)
            status = "done" if exit_code == 0 else "failed"
            finish_job(job_id, status, exit_code)
            append_timeline_event(
                scan_id=scan_id,
                job_id=job_id,
                decision_id=decision_id,
                event="execute",
                status=status,
                detail=f"exit_code={exit_code}; output={output_path}",
            )

            verdict = judge(
                PlanStep(plugin=plugin, reason=f"run {plugin}", risk_tier=tier),
                exit_code=exit_code,
                output_excerpt=(out or "")[:1200],
            )
            append_timeline_event(
                scan_id=scan_id,
                job_id=job_id,
                decision_id=decision_id,
                event="verdict",
                status=str(verdict.get("verdict", "unknown")),
                detail=(
                    f'confidence={verdict.get("confidence", 0)}; '
                    f'reason={verdict.get("reason", "")}'
                ),
            )

            for f in _extract_findings(plugin, output_path):
                upsert_finding(
                    scan_id=scan_id,
                    issue_key=f.issue_key,
                    title=f.title,
                    severity=f.severity,
                    confidence=f.confidence,
                    evidence=f.evidence,
                    source=f.source,
                    cve=f.cve,
                    cwe=f.cwe,
                )
        except Exception as e:
            msg = f"worker exception: {e}"
            if output_path:
                _write_output(output_path, msg)
            finish_job(job_id, "failed", 1)
            append_timeline_event(
                scan_id=scan_id,
                job_id=job_id,
                decision_id=decision_id,
                event="execute",
                status="failed_exception",
                detail=msg,
            )
        finally:
            recompute_scan_status(scan_id)


if __name__ == "__main__":
    poll = float(os.getenv("NEXUS_PLATFORM_WORKER_POLL_SEC", "1.5"))
    run_worker_loop(poll_sec=poll)
