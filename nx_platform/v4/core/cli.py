import requests
import os
import time
import sys
import argparse
import json
import subprocess
from typing import Optional

# Setup Path
root_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../.."))
if root_dir not in sys.path:
    sys.path.insert(0, root_dir)

try:
    from nx_platform.v4.core.config import logger  # type: ignore
except Exception:
    import logging
    logger = logging.getLogger("nexusuite-v4")
    if not logger.handlers:
        logging.basicConfig(level=logging.INFO)

try:
    # Import launcher lazily
    from nx_platform.v4.launcher import ensure_engine_running
except Exception as e:
    ensure_engine_running = None  # type: ignore

class NexusuiteCLI:
    def __init__(self, base_url: str = "http://localhost:8000/api/v1"):
        self.base_url = base_url
        # Gunakan variabel global ensure_engine_running
        global ensure_engine_running
        
        # Auto-start V4 Engine if it's not running (on-demand for AI Agent Mode)
        engine_alive = False
        if ensure_engine_running is not None:
            try:
                engine_alive = ensure_engine_running()
            except Exception:
                engine_alive = False

        if not engine_alive:
            try:
                logger.info("[AI] V4 Engine not detected. Auto-starting backend engine on port 8000...")
                # Start V4 engine in background
                log_file = open("v4_engine.log", "a")
                
                # Gunakan sys.executable untuk memastikan menggunakan python yang sama
                subprocess.Popen(
                    [sys.executable, "-m", "nx_platform.v4.main"],
                    stdout=log_file,
                    stderr=log_file,
                    env=os.environ,
                    cwd=root_dir, # Set working directory ke root proyek
                    creationflags=subprocess.CREATE_NEW_PROCESS_GROUP if sys.platform == 'win32' else 0
                )
                
                # WAIT UNTIL ENGINE IS ACTUALLY READY (Health Check Loop)
                max_wait = 60 # Tingkatkan ke 60 detik untuk Windows/Slow machine
                logger.info(f"[*] Waiting up to {max_wait}s for V4 Engine to initialize...")
                for i in range(max_wait):
                    try:
                        # Re-import jika sebelumnya gagal
                        if ensure_engine_running is None:
                            from nx_platform.v4.launcher import ensure_engine_running
                        
                        if ensure_engine_running():
                            logger.info("[+] V4 Engine is READY and accepting requests.")
                            break
                    except:
                        pass
                    
                    if i % 5 == 0 and i > 0:
                        logger.info(f"[*] Still waiting for engine... ({i}s)")
                        
                    time.sleep(1)
                    if i == max_wait - 1:
                        logger.warning("[-] V4 Engine initialization is taking longer than expected. Proceeding anyway...")
            except Exception as e:
                logger.warning(f"[AI] Auto-start of V4 Engine failed: {e}")

    def start_scan(self, url: str, mode: str = "autonomous", force_enum: bool = False, retries: int = 3):
        # Menggunakan API Key default atau dari environment
        api_key = os.getenv("NX_ADMIN_KEY", "admin-secret-key")
        
        for i in range(retries):
            try:
                resp = requests.post(f"{self.base_url}/scan", json={
                    "url": url,
                    "ai_mode": mode,
                    "force_enum": force_enum
                }, headers={
                    "X-API-Key": api_key
                }, timeout=30)
                resp.raise_for_status()
                data = resp.json()
                print(f"[+] Scan queued! Job ID: {data['job_id']}")
                return data['job_id']
            except requests.exceptions.ConnectionError:
                if i < retries - 1:
                    print(f"[*] Menunggu Nexusuite V4 Engine siap... (Percobaan {i+1}/{retries})")
                    time.sleep(3)
                    continue
                print(f"\033[1;31m[-] Gagal terhubung ke Nexusuite V4 Engine (localhost:8000).\033[0m")
                print(f"[*] Pastikan engine sudah berjalan dengan: python3 -m nx_platform.v4.main")
                sys.exit(1)
            except requests.exceptions.HTTPError as e:
                print(f"\033[1;31m[-] HTTP Error: {e.response.status_code}\033[0m")
                try:
                    detail = e.response.json().get('detail', e.response.text)
                    print(f"[-] Server Detail: {detail}")
                except:
                    print(f"[-] Server Response: {e.response.text}")
                sys.exit(1)
            except Exception as e:
                print(f"[-] Error starting scan: {e}")
                sys.exit(1)

    def stop_scan(self, job_id: str):
        api_key = os.getenv("NX_ADMIN_KEY", "admin-secret-key")
        try:
            resp = requests.delete(f"{self.base_url}/scan/{job_id}", headers={"X-API-Key": api_key}, timeout=30)
            if resp.status_code == 200:
                print(f"\033[1;32m[+] Scan {job_id} berhasil dihentikan.\033[0m")
            elif resp.status_code == 404:
                print(f"\033[1;33m[!] Job ID {job_id} tidak ditemukan (mungkin sudah selesai atau server restart).\033[0m")
            else:
                print(f"[-] Gagal menghentikan scan: {resp.text}")
        except Exception as e:
            print(f"[-] Error stopping scan: {e}")

    def monitor_scan(self, job_id: str):
        print(f"[*] Monitoring scan {job_id}... (Tekan Ctrl+C untuk berhenti memantau)")
        last_status = ""
        findings_count = 0
        logs_count = 0
        consecutive_errors = 0
        
        while True:
            try:
                resp = requests.get(f"{self.base_url}/scan/{job_id}", timeout=5)
                
                if resp.status_code == 404:
                    print(f"\033[1;31m[-] Job ID {job_id} hilang dari server (404).\033[0m")
                    print("[*] Hal ini biasanya terjadi jika server V4 Engine direstart.")
                    break
                
                resp.raise_for_status()
                data = resp.json()
                consecutive_errors = 0 # Reset error counter
                
                status = data['status']
                findings = data.get('findings', [])
                logs = data.get('logs', [])
                
                # Tampilkan log baru
                if len(logs) > logs_count:
                    for i in range(logs_count, len(logs)):
                        print(f"    {logs[i]}")
                    logs_count = len(logs)

                if status != last_status:
                    print(f"[*] Status changed: {status.upper()}")
                    last_status = status
                
                if len(findings) > findings_count:
                    for i in range(findings_count, len(findings)):
                        finding = findings[i]
                        # Ambil evidence dari data temuan
                        evidence = finding.get('data', {}).get('evidence', 'No evidence')
                        print(f"\033[1;32m[!] NEW FINDING: {evidence} (Confidence: {finding.get('confidence', 0)})\033[0m")
                    findings_count = len(findings)
                
                if status in ["completed", "failed", "stopped"]:
                    print(f"[*] Scan {job_id} finished with status: {status}")
                    break
                    
                time.sleep(2)
            except KeyboardInterrupt:
                print("\n\n\033[1;33m[?] Monitoring dihentikan.\033[0m")
                choice = input("[?] Apakah Anda ingin menghentikan proses scanning di server juga? (y/n) [n]: ").lower()
                if choice == 'y':
                    self.stop_scan(job_id)
                else:
                    print("[*] Scan tetap berjalan di background server.")
                break
            except (requests.exceptions.Timeout, requests.exceptions.ConnectionError):
                consecutive_errors += 1
                if consecutive_errors > 5:
                    print(f"\033[1;31m[-] Gagal terhubung ke server setelah {consecutive_errors} kali percobaan. Berhenti.\033[0m")
                    break
                print(f"[*] Koneksi lambat/terputus, mencoba lagi... ({consecutive_errors}/5)")
                time.sleep(5)
            except Exception as e:
                print(f"[-] Monitoring error: {e}")
                time.sleep(5)

def main():
    parser = argparse.ArgumentParser(description="Nexusuite v4 CLI Client")
    parser.add_argument("--start", help="Target URL to scan")
    parser.add_argument("--stop", help="Job ID to stop")
    parser.add_argument("--monitor", help="Job ID to monitor")
    parser.add_argument("--mode", default="autonomous", help="Scan mode")
    parser.add_argument("--force-enum", action="store_true", help="Bypass subdomain cache")
    
    args = parser.parse_args()
    cli = NexusuiteCLI()
    
    if args.start:
        job_id = cli.start_scan(args.start, args.mode, args.force_enum)
        cli.monitor_scan(job_id)
    elif args.stop:
        cli.stop_scan(args.stop)
    elif args.monitor:
        cli.monitor_scan(args.monitor)
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
