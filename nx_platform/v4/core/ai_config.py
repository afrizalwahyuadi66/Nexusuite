"""
AI Configuration for Ollama integration
"""
import os


def get_config():
    """Get AI/Ollama configuration"""
    return {
        "host": os.getenv("OLLAMA_HOST", "http://localhost:11434"),
        "model": os.getenv("OLLAMA_MODEL", "deepseek-r1:8b"),
        "timeout": int(os.getenv("AI_HTTP_TIMEOUT", "600")),
        "curl_timeout": int(os.getenv("AI_CURL_TIMEOUT", "15")),
        "temperature": 0.3,
        "top_p": 0.8
    }


def get_model_list():
    """Get available Ollama models"""
    import requests
    try:
        host = os.getenv("OLLAMA_HOST", "http://localhost:11434")
        resp = requests.get(f"{host}/api/tags", timeout=10)
        if resp.status_code == 200:
            data = resp.json()
            return [m["name"] for m in data.get("models", [])]
    except:
        pass
    return ["deepseek-r1:8b", "llama3:8b"]


def check_ollama_available():
    """Check if Ollama is running"""
    import requests
    try:
        host = os.getenv("OLLAMA_HOST", "http://localhost:11434")
        resp = requests.get(f"{host}/api/tags", timeout=5)
        return resp.status_code == 200
    except:
        return False