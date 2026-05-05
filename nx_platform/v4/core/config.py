import logging
import os
from pathlib import Path

# --- .env Loader ---
def load_env():
    # Go up from nx_platform/v4/core/ to project root
    project_root = Path(__file__).resolve().parents[3]
    env_path = project_root / ".env"
    if env_path.exists():
        with open(env_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                key, value = line.split("=", 1)
                os.environ.setdefault(key.strip(), value.strip().strip('"').strip("'"))

load_env()

# Structured JSON Logging Configuration
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")
DEBUG_ENV = os.getenv("NX_DEBUG", "0").lower() in ("1", "true", "yes")

def setup_logging():
    logging.basicConfig(
        level=LOG_LEVEL,
        format='{"timestamp": "%(asctime)s", "name": "%(name)s", "level": "%(levelname)s", "message": "%(message)s"}'
    )
    logger = logging.getLogger("nexusuite-v4")
    if DEBUG_ENV:
        logger.setLevel(logging.DEBUG)
    return logger

logger = setup_logging()

# Global Constants
API_V1_STR = "/api/v1"
PROJECT_NAME = "Nexusuite v4 AI-First Core Engine"
PLATFORM_VERSION = "4.1.0"
ADMIN_KEY = os.getenv("NX_ADMIN_KEY", "admin-secret-key")
USER_KEY = os.getenv("NX_USER_KEY", "user-secret-key")
