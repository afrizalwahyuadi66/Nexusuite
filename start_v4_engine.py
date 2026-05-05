import sys
import os
import subprocess
import time
from pathlib import Path

def kill_port_8000():
    """Membersihkan port 8000 jika sedang digunakan (Linux/WSL & Windows)."""
    import platform
    import subprocess
    
    print("[*] Mengecek apakah port 8000 sedang digunakan...")
    try:
        if platform.system() != "Windows" or "microsoft" in platform.uname().release.lower():
            # Logic untuk Linux/WSL
            subprocess.run(["fuser", "-k", "8000/tcp"], stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL)
        else:
            # Logic untuk Windows Native
            output = subprocess.check_output(["netstat", "-ano", "|", "findstr", ":8000"], shell=True).decode()
            for line in output.splitlines():
                if "LISTENING" in line:
                    pid = line.strip().split()[-1]
                    subprocess.run(["taskkill", "/F", "/PID", pid], stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL)
    except:
        pass

def start_engine():
    kill_port_8000() # Bersihkan port sebelum mulai
    project_root = Path(__file__).resolve().parent
    main_py = project_root / "nx_platform" / "v4" / "main.py"
    
    if not main_py.exists():
        print(f"[-] Error: {main_py} tidak ditemukan!")
        return

    print("\n" + "="*50)
    print("   NEXUSUITE V4 ENGINE - MANUAL LAUNCHER")
    print("="*50)
    print(f"[*] Root: {project_root}")
    print("[*] Port: 8000")
    print("[*] Mode: Production (Reload Disabled for Stability)")
    print("="*50 + "\n")

    # Set environment variables jika diperlukan
    env = os.environ.copy()
    env["PYTHONPATH"] = str(project_root)

    try:
        # Menjalankan uvicorn secara langsung via modul python
        subprocess.run([
            sys.executable, "-m", "uvicorn", 
            "nx_platform.v4.main:app", 
            "--host", "0.0.0.0", 
            "--port", "8000",
            "--log-level", "info"
        ], env=env)
    except KeyboardInterrupt:
        print("\n[!] Engine dihentikan oleh pengguna.")
    except Exception as e:
        print(f"\n[-] Fatal Error: {e}")

if __name__ == "__main__":
    start_engine()
