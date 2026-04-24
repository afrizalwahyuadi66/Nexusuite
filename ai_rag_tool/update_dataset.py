import requests
import csv
import json
import os
import io

# URL Dataset resmi Exploit-DB (CSV file)
EXPLOIT_DB_CSV_URL = "https://raw.githubusercontent.com/offensive-security/exploitdb/master/files_exploits.csv"
OUTPUT_JSON = os.path.join(os.path.dirname(__file__), "exploit_db_real.json")

def download_and_convert_exploitdb():
    print(f"[*] Mengunduh dataset Exploit-DB resmi dari {EXPLOIT_DB_CSV_URL}...")
    try:
        response = requests.get(EXPLOIT_DB_CSV_URL, timeout=30)
        response.raise_for_status()
        
        # Membaca CSV dari memory (string)
        csv_data = io.StringIO(response.text)
        reader = csv.DictReader(csv_data)
        
        exploits = []
        count = 0
        
        print("[*] Mem-parsing data CSV menjadi format JSON RAG...")
        for row in reader:
            # Format dari CSV ExploitDB: id, file, description, date_published, author, type, platform, port
            # Kita ubah formatnya agar cocok dengan sistem RAG kita
            
            # Abaikan exploit yang tidak memiliki deskripsi jelas
            if not row.get("description"):
                continue
                
            item = {
                "id": f"EDB-ID-{row.get('id', 'UNKNOWN')}",
                "software": row.get("description", "").split(" ")[0], # Coba ambil kata pertama sbg nama software
                "version": "Varies", # Exploit-DB mencampur versi di deskripsi
                "vulnerability": row.get("type", "Unknown Type"),
                "description": row.get("description", ""),
                "platform": row.get("platform", ""),
                "port": row.get("port", ""),
                "payload_suggestion": f"Lihat source code exploit di: https://www.exploit-db.com/exploits/{row.get('id', '')}"
            }
            exploits.append(item)
            count += 1
            
            # Untuk demo dan agar tidak terlalu berat saat pencarian string lokal (karena ini > 45.000 data),
            # kita ambil 5000 data terbaru (biasanya ID terbesar ada di akhir/awal tergantung sorting)
            if count >= 5000:
                break
                
        # Simpan ke JSON
        with open(OUTPUT_JSON, "w", encoding="utf-8") as f:
            json.dump(exploits, f, indent=2)
            
        print(f"[+] Selesai! Berhasil mengonversi {count} eksploit nyata ke {OUTPUT_JSON}.")
        print("[+] Sekarang AI Anda memiliki dataset hacking sungguhan (Exploit-DB).")
        
    except Exception as e:
        print(f"[-] Gagal mengunduh atau memproses dataset: {e}")

if __name__ == "__main__":
    download_and_convert_exploitdb()
