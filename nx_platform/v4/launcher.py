import requests

HEALTH_URL = "http://localhost:8000/health"

def is_engine_alive(timeout: int = 2) -> bool:
    """Return True if the V4 engine health endpoint is reachable."""
    try:
        resp = requests.get(HEALTH_URL, timeout=timeout)
        return resp.status_code == 200
    except Exception:
        return False

def ensure_engine_running() -> bool:
    """Check if engine is running. Returns True if alive, otherwise False."""
    return is_engine_alive()
