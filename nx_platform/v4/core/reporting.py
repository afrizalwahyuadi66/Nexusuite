import json
import os
import hashlib
import time
from datetime import datetime

class AuditReporter:
    """
    Sistem Reporting & Auditing Otonom untuk Nexusuite V4.
    Menghasilkan laporan teknis dan audit trail dengan integritas SHA-256.
    """
    def __init__(self, output_base="results/v4"):
        self.output_base = output_base
        os.makedirs(self.output_base, exist_ok=True)

    def generate_report(self, job_data: dict):
        """
        Menghasilkan laporan komprehensif (JSON & Markdown) untuk setiap job.
        """
        # Mendukung struktur data flat (legacy) atau nested metadata (V4-Evolution)
        metadata = job_data.get("metadata", job_data)
        job_id = metadata.get("job_id", job_data.get("id", "unknown"))
        target = metadata.get("target", "unknown_target")
        
        target_safe = target.replace("https://", "").replace("http://", "").replace("/", "_")
        
        report_dir = os.path.join(self.output_base, f"{target_safe}_{job_id}")
        os.makedirs(report_dir, exist_ok=True)
        
        # 1. Generate Technical JSON Report
        json_report_path = os.path.join(report_dir, "technical_report.json")
        with open(json_report_path, "w") as f:
            json.dump(job_data, f, indent=4)
        
        # 2. Generate Executive Markdown Report
        md_report_path = os.path.join(report_dir, "executive_summary.md")
        self._write_markdown_summary(md_report_path, job_data)
        
        # 3. Generate Audit Trail (SHA-256 Integrity)
        audit_trail_path = os.path.join(report_dir, "audit_trail.txt")
        self._generate_audit_trail(audit_trail_path, report_dir, [json_report_path, md_report_path])
        
        return report_dir

    def save_job_report(self, job_data):
        job_id = job_data.get("id", "unknown")
        target = job_data.get("url", "unknown")
        
        # Ekstrak nama domain untuk folder yang lebih rapi
        from urllib.parse import urlparse
        domain = urlparse(target).netloc or target.replace("/", "_")
        
        # Struktur: Result/DOMAIN_SCAN_TIMESTAMP/
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_dir = os.path.join("Result", f"{domain}_SCAN_{timestamp}")
        os.makedirs(report_dir, exist_ok=True)

        # 1. Save Clean AI-Parsable JSON
        json_path = os.path.join(report_dir, "ai_intelligence_data.json")
        with open(json_path, "w") as f:
            json.dump(job_data, f, indent=4)

        # 2. Save Human-Readable & AI-Instructional Markdown
        md_path = os.path.join(report_dir, "full_report.md")
        self._write_markdown_summary(md_path, job_data)
        
        return report_dir

    def _write_markdown_summary(self, path, data):
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        metadata = data.get("metadata", data)
        findings = data.get("findings", [])
        
        # Data terstruktur dengan fallback untuk menghindari 'undefined'
        structured_vulns = data.get("structured_vulnerabilities", []) or []
        structured_exploits = data.get("structured_exploits", []) or []
        
        target = metadata.get("url", metadata.get("target", "N/A"))
        job_id = data.get("id", "N/A")

        content = f"""# NEXUSUITE AI - INTELLIGENCE REPORT
> **Job ID:** {job_id}
> **Target:** {target}
> **Generated:** {timestamp}

---

## 🦾 AI Reasoning Summary
The **Nexusuite Advanced Engine** has processed this target through iterative reasoning. 
This file is designed for both human review and automated AI ingestion.

## � Critical & Verified Findings
"""
        if not structured_vulns:
            content += "\n*No structured vulnerabilities confirmed in this session.*\n"
        else:
            for v in structured_vulns:
                # Fallback values for cleaner parsing
                name = v.get('name') or v.get('vuln_name') or "Unknown Vulnerability"
                sev = (v.get('severity') or "medium").upper()
                port = v.get('port') or "N/A"
                svc = v.get('service') or "N/A"
                desc = v.get('description') or "No description provided."
                
                content += f"### [{sev}] {name}\n"
                content += f"- **Service/Port:** `{svc}` / `{port}`\n"
                content += f"- **Technical Detail:** {desc}\n"
                
                if v.get('fixes'):
                    content += "- **Remediation Steps:**\n"
                    for fix in v['fixes']:
                        f_text = fix.get('fix_text') or "Contact administrator."
                        content += f"  - {f_text}\n"
                content += "\n"

        if structured_exploits:
            content += "## 🚀 Verified Exploits & PoCs\n"
            for e in structured_exploits:
                exp_name = e.get('exploit_name') or "Unnamed Exploit"
                tool = e.get('tool_used') or "Manual/AI"
                payload = e.get('payload') or "N/A"
                res = e.get('result') or "Successful"
                
                content += f"### {exp_name}\n"
                content += f"- **Vector:** `{tool}`\n"
                content += f"- **Payload:** `{payload}`\n"
                content += f"- **Outcome:** {res}\n\n"

        content += "\n---\n*Report finalized by Nexusuite NX-AI Core.*"
        
        with open(path, "w") as f:
            f.write(content)

    def _generate_audit_trail(self, path, base_dir, files):
        with open(path, "w") as f:
            f.write(f"NEXUSUITE V4 AUDIT TRAIL\n")
            f.write(f"Generated: {datetime.now()}\n")
            f.write(f"{'='*40}\n\n")
            
            for file_path in files:
                filename = os.path.basename(file_path)
                sha256 = self._calculate_sha256(file_path)
                f.write(f"FILE: {filename}\n")
                f.write(f"HASH: {sha256}\n")
                f.write(f"{'-'*40}\n")

    def _calculate_sha256(self, filepath):
        hasher = hashlib.sha256()
        with open(filepath, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hasher.update(chunk)
        return hasher.hexdigest()

audit_reporter = AuditReporter()
