import os
import shlex
import subprocess
from pathlib import Path


def safe_target_dir_name(target: str) -> str:
    return "".join(c if c.isalnum() or c in ".-" else "_" for c in target)


def render_command(template: str, target: str, output_path: str) -> str:
    return template.replace("{target}", target).replace("{output}", output_path)


def run_command(command: str, timeout_sec: int = 900) -> tuple[int, str]:
    proc = subprocess.run(
        command,
        shell=True,
        capture_output=True,
        text=True,
        timeout=timeout_sec,
        env=os.environ.copy(),
    )
    output = (proc.stdout or "") + ("\n" + proc.stderr if proc.stderr else "")
    return int(proc.returncode), output


def ensure_output_path(scan_id: int, target: str, plugin_name: str) -> str:
    base = Path(__file__).resolve().parents[1] / "platform_runs" / f"scan_{scan_id}" / safe_target_dir_name(target)
    base.mkdir(parents=True, exist_ok=True)
    return str(base / f"{plugin_name}.log")


def command_preview(cmd: str) -> str:
    try:
        return " ".join(shlex.split(cmd))
    except Exception:
        return cmd
