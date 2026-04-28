import os
from pathlib import Path
from urllib.parse import urlparse


def _load_dotenv_if_exists() -> None:
    project_root = Path(__file__).resolve().parents[1]
    env_path = project_root / ".env"
    if not env_path.exists():
        return

    for raw in env_path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip().strip('"').strip("'")
        os.environ.setdefault(key, value)


def _merge_no_proxy(host: str) -> str:
    parsed = urlparse(host)
    current = os.getenv("AI_NO_PROXY") or os.getenv("NO_PROXY") or os.getenv("no_proxy") or ""
    entries = [item.strip() for item in current.split(",") if item.strip()]

    for entry in ("localhost", "127.0.0.1", "::1", parsed.hostname or ""):
        if entry and entry not in entries:
            entries.append(entry)

    merged = ",".join(entries)
    os.environ["AI_NO_PROXY"] = merged
    os.environ["NO_PROXY"] = merged
    os.environ["no_proxy"] = merged
    return merged


def get_ai_settings() -> dict:
    _load_dotenv_if_exists()
    host = os.getenv("OLLAMA_HOST", "http://localhost:11434").rstrip("/")
    model = os.getenv("OLLAMA_MODEL", "deepseek-r1:8b")
    timeout = int(os.getenv("AI_HTTP_TIMEOUT", "300"))
    snippet_chars = int(os.getenv("AI_LOG_SNIPPET_CHARS", "6000"))
    enable_web_search = os.getenv("AI_ENABLE_WEB_SEARCH", "true").lower() in {
        "1",
        "true",
        "yes",
        "y",
        "on",
    }
    no_proxy = _merge_no_proxy(host)
    return {
        "host": host,
        "model": model,
        "timeout": timeout,
        "snippet_chars": snippet_chars,
        "enable_web_search": enable_web_search,
        "no_proxy": no_proxy,
        "tags_api": f"{host}/api/tags",
        "generate_api": f"{host}/api/generate",
    }
