import re
from pathlib import Path

try:
    from .findings import Finding, build_issue_key
except ImportError:
    from findings import Finding, build_issue_key


def parse_nuclei_output(path: str) -> list[Finding]:
    p = Path(path)
    if not p.exists():
        return []
    findings: list[Finding] = []
    for raw in p.read_text(encoding="utf-8", errors="ignore").splitlines():
        line = raw.strip()
        if not line:
            continue
        sev = "info"
        m = re.search(r"\[(critical|high|medium|low|info)\]", line, re.IGNORECASE)
        if m:
            sev = m.group(1).lower()
        cve_match = re.search(r"(CVE-\d{4}-\d+)", line, re.IGNORECASE)
        cve = cve_match.group(1).upper() if cve_match else None
        title = f"Nuclei finding ({sev})"
        conf = 55
        if sev == "critical":
            conf = 90
        elif sev == "high":
            conf = 80
        elif sev == "medium":
            conf = 65
        issue_key = build_issue_key("nuclei", title, line)
        findings.append(
            Finding(
                issue_key=issue_key,
                title=title,
                severity=sev,
                confidence=conf,
                evidence=line,
                source="nuclei",
                cve=cve,
            )
        )
    return findings


def parse_generic_output(path: str, source: str) -> list[Finding]:
    p = Path(path)
    if not p.exists():
        return []
    findings: list[Finding] = []
    for raw in p.read_text(encoding="utf-8", errors="ignore").splitlines():
        line = raw.strip()
        if not line:
            continue
        if re.search(r"vulnerable|critical|high|cve-\d{4}-\d+", line, re.IGNORECASE):
            sev = "medium"
            if re.search(r"critical", line, re.IGNORECASE):
                sev = "critical"
            elif re.search(r"high", line, re.IGNORECASE):
                sev = "high"
            cve_match = re.search(r"(CVE-\d{4}-\d+)", line, re.IGNORECASE)
            cve = cve_match.group(1).upper() if cve_match else None
            issue_key = build_issue_key(source, f"{source} finding", line)
            findings.append(
                Finding(
                    issue_key=issue_key,
                    title=f"{source} finding",
                    severity=sev,
                    confidence=60 if sev != "critical" else 88,
                    evidence=line,
                    source=source,
                    cve=cve,
                )
            )
    return findings
