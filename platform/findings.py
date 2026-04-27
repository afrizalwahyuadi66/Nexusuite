import hashlib
import re
from dataclasses import dataclass


@dataclass
class Finding:
    issue_key: str
    title: str
    severity: str
    confidence: int
    evidence: str
    source: str
    cve: str | None = None
    cwe: str | None = None


def normalize_text(s: str) -> str:
    out = s.lower().strip()
    out = re.sub(r"https?://[^\s]+", "<url>", out)
    out = re.sub(r"\b\d{1,6}\b", "<n>", out)
    return out


def build_issue_key(source: str, title: str, evidence: str) -> str:
    basis = f"{source}|{normalize_text(title)}|{normalize_text(evidence)}"
    return hashlib.sha256(basis.encode("utf-8")).hexdigest()[:24]


def severity_rank(sev: str) -> int:
    mapping = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}
    return mapping.get(sev.lower(), 1)
