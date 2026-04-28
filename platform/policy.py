import os
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_POLICY = PROJECT_ROOT / "config" / "risk_policy.yaml"


def _is_true(v: str | None) -> bool:
    if v is None:
        return False
    return str(v).strip().lower() in {"1", "true", "yes", "y", "on"}


def _load_policy_map() -> dict[str, str]:
    policy_file = Path(os.getenv("AI_RISK_POLICY_FILE", str(DEFAULT_POLICY)))
    out: dict[str, str] = {}
    if not policy_file.exists():
        return out
    for raw in policy_file.read_text(encoding="utf-8", errors="ignore").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or ":" not in line:
            continue
        k, v = line.split(":", 1)
        out[k.strip()] = v.strip()
    return out


def policy_get(key: str, default: str = "") -> str:
    return _load_policy_map().get(key, default)


def approval_mode_for_tier(tier: str) -> str:
    t = (tier or "high").strip().lower()
    if t == "low":
        return policy_get("approval_low", "auto")
    if t == "medium":
        return policy_get("approval_medium", "prompt_once")
    return policy_get("approval_high", "prompt_each")


def classify_plugin_tier(plugin_name: str, plugin_cfg: dict) -> str:
    declared = str(plugin_cfg.get("tier", "")).strip().lower()
    if declared in {"low", "medium", "high"}:
        return declared
    return "high"


def worker_approval_allowed(tier: str) -> tuple[bool, str]:
    if _is_true(os.getenv("NEXUS_PLATFORM_AUTO_APPROVE_ALL")):
        return True, "auto_approve_all"

    mode = approval_mode_for_tier(tier)
    if mode == "auto":
        return True, "auto"
    if mode == "prompt_once":
        if _is_true(os.getenv("NEXUS_PLATFORM_APPROVE_MEDIUM")):
            return True, "approved_medium_env"
        return False, "blocked_medium_need_env"
    if mode == "prompt_each":
        if _is_true(os.getenv("NEXUS_PLATFORM_APPROVE_HIGH")):
            return True, "approved_high_env"
        return False, "blocked_high_need_env"
    return False, f"blocked_unknown_mode:{mode}"
