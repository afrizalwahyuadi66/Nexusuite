from pathlib import Path


PLUGIN_DIR = Path(__file__).resolve().parents[1] / "config" / "tool_plugins"


def _parse_scalar(value: str):
    v = value.strip()
    if v.lower() in {"true", "false"}:
        return v.lower() == "true"
    if v.isdigit():
        return int(v)
    if (v.startswith('"') and v.endswith('"')) or (v.startswith("'") and v.endswith("'")):
        return v[1:-1]
    return v


def parse_simple_yaml(path: Path) -> dict:
    data: dict = {}
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        key = key.strip()
        value = value.strip()
        data[key] = _parse_scalar(value)
    return data


def load_plugins() -> dict[str, dict]:
    plugins: dict[str, dict] = {}
    if not PLUGIN_DIR.exists():
        return plugins
    for p in sorted(PLUGIN_DIR.glob("*.yaml")):
        cfg = parse_simple_yaml(p)
        name = str(cfg.get("name", p.stem))
        cfg["name"] = name
        plugins[name] = cfg
    return plugins
