import subprocess
import sys
import os
import shutil
import logging

def check_and_install_deps():
    """
    Sistem Self-Healing: Otomatis mendeteksi tool yang hilang dan mencoba menginstalnya.
    """
    required_binaries = {
        "subfinder": "go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
        "httpx": "go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest",
        "nuclei": "go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
        "katana": "go install -v github.com/projectdiscovery/katana/cmd/katana@latest",
        "dalfox": "go install -v github.com/hahwul/dalfox/v2@latest",
        "sqlmap": "pip install sqlmap",
        "gau": "go install -v github.com/lc/gau/v2/cmd/gau@latest",
        "paramspider": "pip install git+https://github.com/devanshbatham/paramspider"
    }

    print("[*] Menjalankan sistem otonom: Memeriksa dependensi...")
    
    missing = []
    for tool, install_cmd in required_binaries.items():
        if not shutil.which(tool):
            print(f"[!] Tool '{tool}' tidak ditemukan. Mencoba instalasi otomatis...")
            try:
                subprocess.run(install_cmd, shell=True, check=True)
                print(f"[+] '{tool}' berhasil diinstal.")
            except Exception as e:
                print(f"[-] Gagal menginstal '{tool}': {e}")
                missing.append(tool)
    
    if missing:
        print(f"[!] Warning: Beberapa tool gagal diinstal secara otomatis: {', '.join(missing)}")
    else:
        print("[+] Semua dependensi siap. Memulai mesin V4...")

def setup_environment():
    """Konfigurasi path dan environment secara otomatis."""
    go_bin = os.path.expanduser("~/go/bin")
    if os.path.exists(go_bin) and go_bin not in os.environ["PATH"]:
        os.environ["PATH"] += os.pathsep + go_bin
        print(f"[*] Menambahkan {go_bin} ke PATH.")

if __name__ == "__main__":
    setup_environment()
    check_and_install_deps()
