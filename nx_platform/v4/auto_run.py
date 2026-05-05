import argparse
import sys
import os
import time
import requests
import json
import subprocess
from nx_platform.v4.core.bootstrap import check_and_install_deps, setup_environment

class NexusuiteAutonomousCLI:
    def __init__(self):
        self.api_url = "http://localhost:8000/api/v1"

    def splash(self):
        # Menggunakan normal string agar \033 (ANSI escape) berfungsi.
        # Melarikan backslash (\\) untuk menghindari SyntaxWarning pada Python 3.12+.
        print("""
\033[1;32m
    _  _                                _         
   | \\| | ___ __ __ _  _  ___ _  _  _ _| |_ ___   
   | .  |/ -_)\\ \\ /| || |(_-<| || || | |  _/ -_)  
   |_|\\_|\\___|/_\\_\\ \\_,_|/__/ \\_,_||_|_|\\__\\___|  
\033[1;37m>> Autonomous Offensive Architect [V4 Core] <<\033[0m
        """)

    def start_engine(self):
        """Memastikan backend V4 Engine berjalan di background."""
        try:
            requests.get("http://localhost:8000/health", timeout=2)
            print("[+] V4 Backend Engine terdeteksi aktif.")
        except:
            print("[*] Memulai V4 Backend Engine secara otonom...")
            
            # Setup Path untuk subprocess
            current_file_path = os.path.abspath(__file__)
            root_dir = os.path.dirname(os.path.dirname(os.path.dirname(current_file_path)))

            # Menjalankan main.py di background
            subprocess.Popen(
                [sys.executable, "-m", "nx_platform.v4.main"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                env=os.environ,
                cwd=root_dir, # Set working directory ke root proyek
                creationflags=subprocess.CREATE_NEW_PROCESS_GROUP if sys.platform == 'win32' else 0
            )
            time.sleep(10) # Memberi waktu engine untuk init (tingkatkan ke 10s)

    def execute(self, domain):
        self.splash()
        setup_environment()
        check_and_install_deps()
        self.start_engine()

        print(f"\n[*] Target Terdeteksi: \033[1;34m{domain}\033[0m")
        print("[*] AI sedang menganalisis attack surface dan merencanakan strategi...")

        try:
            # Menggunakan API Key default atau dari environment
            api_key = os.getenv("NX_ADMIN_KEY", "admin-secret-key")
            
            resp = requests.post(f"{self.api_url}/scan", json={
                "url": domain,
                "ai_mode": os.getenv("AI_AGENT_MODE", "nx_advanced")
            }, headers={
                "X-API-Key": api_key
            }, timeout=30)
            
            if resp.status_code == 200:
                job_id = resp.json()['job_id']
                print(f"[+] Operasi dimulai secara asinkron. Job ID: {job_id}")
                print(f"[*] Menghubungkan ke monitoring stream...\n")
                
                # Memanggil CLI monitor internal
                from nx_platform.v4.core.cli import NexusuiteCLI
                cli_monitor = NexusuiteCLI()
                cli_monitor.monitor_scan(job_id)
            else:
                print(f"[-] Gagal memulai operasi: {resp.text}")
        except Exception as e:
            print(f"[-] Fatal Error: {e}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("domain", help="Nama domain target untuk diproses secara otonom")
    args = parser.parse_args()

    if args.domain:
        # Tambahkan direktori root ke sys.path agar modul nx_platform terbaca
        # Mencari root berdasarkan lokasi file auto_run.py (nx_platform/v4/auto_run.py)
        # 1 level up: nx_platform/v4/
        # 2 level up: nx_platform/
        # 3 level up: Nexusuite/ (ROOT)
        current_file_path = os.path.abspath(__file__)
        root_dir = os.path.dirname(os.path.dirname(os.path.dirname(current_file_path)))
        
        if root_dir not in sys.path:
            sys.path.insert(0, root_dir)
            
        nx_cli = NexusuiteAutonomousCLI()
        nx_cli.execute(args.domain)
