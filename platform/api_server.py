import json
import os
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

try:
    from .ai_loop import dry_run_explain
    from .plugin_loader import load_plugins
    from .runner import command_preview, ensure_output_path, render_command
    from .state_db import (
        approve_job,
        append_timeline_event,
        create_job,
        create_scan,
        get_job,
        init_db,
        list_approval_jobs,
        list_findings,
        list_jobs,
        list_scans,
        list_timeline_events,
        reject_job,
        replay_failed_jobs,
        update_scan_status,
    )
except ImportError:
    from ai_loop import dry_run_explain
    from plugin_loader import load_plugins
    from runner import command_preview, ensure_output_path, render_command
    from state_db import (
        approve_job,
        append_timeline_event,
        create_job,
        create_scan,
        get_job,
        init_db,
        list_approval_jobs,
        list_findings,
        list_jobs,
        list_scans,
        list_timeline_events,
        reject_job,
        replay_failed_jobs,
        update_scan_status,
    )


PROJECT_ROOT = Path(__file__).resolve().parents[1]
WEB_DIR = PROJECT_ROOT / "platform" / "web"


def _json(handler: BaseHTTPRequestHandler, status: int, payload):
    data = json.dumps(payload, ensure_ascii=True).encode("utf-8")
    handler.send_response(status)
    handler.send_header("Content-Type", "application/json; charset=utf-8")
    handler.send_header("Content-Length", str(len(data)))
    handler.end_headers()
    handler.wfile.write(data)


def _read_json(handler: BaseHTTPRequestHandler):
    length = int(handler.headers.get("Content-Length", "0"))
    raw = handler.rfile.read(length) if length > 0 else b"{}"
    return json.loads(raw.decode("utf-8"))


class ApiHandler(BaseHTTPRequestHandler):
    plugins = load_plugins()

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path

        if path == "/" or path == "/ui":
            index = WEB_DIR / "index.html"
            data = index.read_bytes()
            self.send_response(HTTPStatus.OK)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
            return

        if path == "/api/plugins":
            _json(self, 200, {"plugins": list(self.plugins.values())})
            return

        if path == "/api/scans":
            _json(self, 200, {"items": list_scans(100)})
            return

        if path == "/api/jobs":
            q = parse_qs(parsed.query)
            scan_id = q.get("scan_id", [None])[0]
            sid = int(scan_id) if scan_id and scan_id.isdigit() else None
            _json(self, 200, {"items": list_jobs(scan_id=sid, limit=500)})
            return

        if path == "/api/findings":
            q = parse_qs(parsed.query)
            scan_id = q.get("scan_id", [None])[0]
            sid = int(scan_id) if scan_id and scan_id.isdigit() else None
            _json(self, 200, {"items": list_findings(scan_id=sid, limit=500)})
            return

        if path == "/api/approvals":
            _json(self, 200, {"items": list_approval_jobs(limit=500)})
            return

        if path == "/api/timeline":
            q = parse_qs(parsed.query)
            scan_id = q.get("scan_id", [None])[0]
            sid = int(scan_id) if scan_id and scan_id.isdigit() else None
            _json(self, 200, {"items": list_timeline_events(scan_id=sid, limit=800)})
            return

        _json(self, 404, {"error": "not found"})

    def do_POST(self):
        parsed = urlparse(self.path)
        path = parsed.path

        if path == "/api/ai/explain":
            try:
                body = _read_json(self)
            except Exception:
                _json(self, 400, {"error": "invalid json"})
                return
            target = str(body.get("target", "")).strip()
            profile = str(body.get("profile", "standard")).strip()
            if not target:
                _json(self, 400, {"error": "target required"})
                return
            plan = dry_run_explain(target, profile=profile)
            _json(self, 200, {"plan": json.loads(plan)})
            return

        if path == "/api/scans":
            try:
                body = _read_json(self)
            except Exception:
                _json(self, 400, {"error": "invalid json"})
                return

            target = str(body.get("target", "")).strip()
            selected = body.get("plugins") or []
            profile = str(body.get("profile", "standard"))

            if not target:
                _json(self, 400, {"error": "target required"})
                return
            if not isinstance(selected, list) or not selected:
                _json(self, 400, {"error": "plugins list required"})
                return

            scan_id = create_scan(target=target, profile=profile)
            update_scan_status(scan_id, "running")
            created_jobs = []

            for plugin_name in selected:
                p = self.plugins.get(plugin_name)
                if not p:
                    continue
                template = str(p.get("command_template", "")).strip()
                if not template:
                    continue
                out = ensure_output_path(scan_id, target, plugin_name)
                cmd = render_command(template, target=target, output_path=out)
                jid = create_job(scan_id, plugin_name, cmd, out)
                created_jobs.append(
                    {
                        "job_id": jid,
                        "plugin": plugin_name,
                        "command_preview": command_preview(cmd),
                        "output_path": out,
                    }
                )
                append_timeline_event(
                    scan_id=scan_id,
                    job_id=jid,
                    decision_id=None,
                    event="plan",
                    status="queued",
                    detail=f"plugin={plugin_name}; command={command_preview(cmd)}",
                )

            _json(self, 201, {"scan_id": scan_id, "jobs": created_jobs})
            return

        # /api/scans/<id>/replay
        parts = [p for p in path.split("/") if p]
        if len(parts) == 4 and parts[0] == "api" and parts[1] == "scans" and parts[3] == "replay":
            scan_id_raw = parts[2]
            if not scan_id_raw.isdigit():
                _json(self, 400, {"error": "invalid scan id"})
                return
            scan_id = int(scan_id_raw)
            replayed = replay_failed_jobs(scan_id)
            if replayed > 0:
                update_scan_status(scan_id, "running")
                append_timeline_event(
                    scan_id=scan_id,
                    event="replay",
                    status="queued",
                    detail=f"replayed_jobs={replayed}",
                )
            _json(self, 200, {"scan_id": scan_id, "replayed_jobs": replayed})
            return

        # /api/jobs/<id>/approve
        if len(parts) == 4 and parts[0] == "api" and parts[1] == "jobs" and parts[3] == "approve":
            job_id_raw = parts[2]
            if not job_id_raw.isdigit():
                _json(self, 400, {"error": "invalid job id"})
                return
            job_id = int(job_id_raw)
            before = get_job(job_id)
            if not before:
                _json(self, 404, {"error": "job not found"})
                return
            updated = approve_job(job_id)
            if not updated:
                _json(self, 404, {"error": "job not found"})
                return
            scan_id = int(updated["scan_id"])
            update_scan_status(scan_id, "running")
            append_timeline_event(
                scan_id=scan_id,
                job_id=job_id,
                event="approval",
                status="manually_approved",
                detail=f"from_status={before['status']}; to_status={updated['status']}",
            )
            _json(self, 200, {"job": updated})
            return

        # /api/jobs/<id>/reject
        if len(parts) == 4 and parts[0] == "api" and parts[1] == "jobs" and parts[3] == "reject":
            job_id_raw = parts[2]
            if not job_id_raw.isdigit():
                _json(self, 400, {"error": "invalid job id"})
                return
            try:
                body = _read_json(self)
            except Exception:
                body = {}
            reason = str(body.get("reason", "")).strip()
            job_id = int(job_id_raw)
            before = get_job(job_id)
            if not before:
                _json(self, 404, {"error": "job not found"})
                return
            updated = reject_job(job_id, reason=reason)
            if not updated:
                _json(self, 404, {"error": "job not found"})
                return
            scan_id = int(updated["scan_id"])
            append_timeline_event(
                scan_id=scan_id,
                job_id=job_id,
                event="approval",
                status="rejected",
                detail=f"from_status={before['status']}; reason={reason or 'unspecified'}",
            )
            _json(self, 200, {"job": updated})
            return

        # /api/approvals/bulk
        if len(parts) == 3 and parts[0] == "api" and parts[1] == "approvals" and parts[2] == "bulk":
            try:
                body = _read_json(self)
            except Exception:
                _json(self, 400, {"error": "invalid json"})
                return
            action = str(body.get("action", "")).strip().lower()
            ids_raw = body.get("job_ids") or []
            reason = str(body.get("reason", "")).strip()
            if action not in {"approve", "reject"}:
                _json(self, 400, {"error": "action must be approve|reject"})
                return

            if isinstance(ids_raw, list) and ids_raw:
                job_ids = [int(x) for x in ids_raw if str(x).isdigit()]
            else:
                job_ids = [int(j["id"]) for j in list_approval_jobs(limit=2000)]

            affected = 0
            for job_id in job_ids:
                before = get_job(job_id)
                if not before:
                    continue
                if action == "approve":
                    updated = approve_job(job_id)
                    if not updated:
                        continue
                    scan_id = int(updated["scan_id"])
                    update_scan_status(scan_id, "running")
                    append_timeline_event(
                        scan_id=scan_id,
                        job_id=job_id,
                        event="approval",
                        status="manually_approved_bulk",
                        detail=f"from_status={before['status']}; to_status={updated['status']}",
                    )
                    affected += 1
                else:
                    updated = reject_job(job_id, reason=reason)
                    if not updated:
                        continue
                    scan_id = int(updated["scan_id"])
                    append_timeline_event(
                        scan_id=scan_id,
                        job_id=job_id,
                        event="approval",
                        status="rejected_bulk",
                        detail=f"from_status={before['status']}; reason={reason or 'unspecified'}",
                    )
                    affected += 1
            _json(self, 200, {"action": action, "affected": affected, "job_ids": job_ids})
            return

        _json(self, 404, {"error": "not found"})

    def log_message(self, format, *args):
        return


def run_server():
    init_db()
    host = os.getenv("NEXUS_PLATFORM_HOST", "127.0.0.1")
    port = int(os.getenv("NEXUS_PLATFORM_PORT", "8787"))
    server = ThreadingHTTPServer((host, port), ApiHandler)
    print(f"[api] listening on http://{host}:{port}")
    server.serve_forever()


if __name__ == "__main__":
    run_server()
