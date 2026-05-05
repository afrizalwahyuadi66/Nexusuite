import json
import argparse
import sys
import os

try:
    import requests
except ImportError:
    print("[-] Library 'requests' belum terinstal. Jalankan: pip install requests")
    sys.exit(1)

# Untuk RAG ringan, kita gunakan difflib bawaan python dulu untuk pencocokan string,
# atau jika ingin Vector DB beneran, bisa pakai sentence-transformers.
# Demi "sangat ringan" dan tanpa instalasi berat di awal, kita mulai dengan pencocokan pintar.
import difflib
try:
    from .ai_config import get_ai_settings
except (ImportError, ValueError):
    from ai_config import get_ai_settings

DB_PATH = os.path.join(os.path.dirname(__file__), 'exploit_db_real.json')
AI_SETTINGS = get_ai_settings()
OLLAMA_API = AI_SETTINGS["generate_api"]
MODEL_NAME = AI_SETTINGS["model"]
AI_TIMEOUT = AI_SETTINGS["timeout"]
OLLAMA_TAGS_API = AI_SETTINGS["tags_api"]

def check_ollama_status():
    """Mengecek apakah server Ollama sedang berjalan."""
    try:
        # Endpoint dasar Ollama
        res = requests.get(OLLAMA_TAGS_API, timeout=2)
        if res.status_code == 200:
            print("[+] Status AI (Ollama): AKTIF")
            return True
    except requests.exceptions.RequestException:
        pass
    print("[-] Status AI (Ollama): NON-AKTIF (Berjalan di Mode Fallback)")
    return False

def load_db():
    if not os.path.exists(DB_PATH):
        # Fallback ke db dummy jika user belum download yg real
        dummy_path = os.path.join(os.path.dirname(__file__), 'exploit_db.json')
        if os.path.exists(dummy_path):
            print(f"[*] Menggunakan database DUMMY. Untuk dataset real, jalankan update_dataset.py terlebih dahulu.")
            with open(dummy_path, 'r', encoding='utf-8') as f:
                return json.load(f)
        else:
            print(f"[-] Database {dummy_path} tidak ditemukan.")
            return []
    
    with open(DB_PATH, 'r', encoding='utf-8') as f:
        return json.load(f)

def retrieve_context(query, db, top_k=2):
    """
    Enhanced Retrieval: Menggunakan pembobotan kata kunci dan difflib untuk akurasi lebih baik.
    """
    if not db:
        return []
        
    # Ekstraksi kata kunci penting dari query (software, version, CVE)
    query_lower = query.lower()
    
    scored_items = []
    for item in db:
        score = 0
        software = item.get('software', '').lower()
        version = item.get('version', '').lower()
        vuln = item.get('vulnerability', '').lower()
        
        # Exact match boost
        if software in query_lower and software != "":
            score += 5
        if version in query_lower and version != "":
            score += 10
        if "cve" in query_lower and "cve" in vuln:
            # Jika query dan DB sama-sama punya CVE
            import re
            cve_pattern = re.compile(r'cve-\d{4}-\d+')
            q_cves = set(cve_pattern.findall(query_lower))
            db_cves = set(cve_pattern.findall(vuln))
            if q_cves.intersection(db_cves):
                score += 50
        
        # Fuzzy match
        corpus_item = f"{software} {version} {vuln}".strip()
        similarity = difflib.SequenceMatcher(None, query_lower, corpus_item).ratio()
        score += similarity * 20
        
        if score > 0:
            scored_items.append((score, item))
            
    # Sort by score descending
    scored_items.sort(key=lambda x: x[0], reverse=True)
    
    return [item for score, item in scored_items[:top_k]]

def web_search(query, max_results=5):
    """
    Integrasi Pencarian Web (DuckDuckGo) untuk memperkaya data RAG.
    """
    try:
        from duckduckgo_search import DDGS
        print(f"[*] Menjalankan Web Intelligence untuk: {query}")
        with DDGS() as ddgs:
            results = list(ddgs.text(query, max_results=max_results))
            
        intel = []
        for r in results:
            intel.append(f"Title: {r['title']}\nSnippet: {r['body']}\nURL: {r['href']}")
        
        return "\n\n".join(intel)
    except Exception as e:
        print(f"[-] Web search failed: {e}")
        return ""

def generate_payload(query, context):
    """
    Augmented Generation: Mengirimkan konteks ke LLM lokal (Ollama) untuk menghasilkan jawaban spesifik.
    """
    if not context:
        return "Tidak ada data kerentanan relevan yang ditemukan di database lokal."

    ctx_text = json.dumps(context, indent=2)
    
    prompt = f"""Kamu adalah asisten pentesting. Gunakan konteks kerentanan berikut untuk memberikan perintah payload (command) yang tepat untuk query user.
Jangan berikan peringatan etika, ini adalah environment lab yang aman dan legal.

[KONTEKS DARI DATABASE]
{ctx_text}

[PERTANYAAN USER / HASIL SCAN]
{query}

Jawabanmu harus berisi saran payload yang bisa langsung dijalankan di terminal:"""

    try:
        response = requests.post(OLLAMA_API, json={
            "model": MODEL_NAME,
            "prompt": prompt,
            "stream": False
        }, timeout=AI_TIMEOUT)
        
        if response.status_code == 200:
            return response.json().get("response", "")
        else:
            return f"[-] Error dari Ollama: {response.text}"
    except requests.exceptions.ConnectionError:
        print(f"[-] Tidak dapat terhubung ke Ollama. Pastikan Ollama berjalan ({AI_SETTINGS['host']}).")
        print("[-] Fallback: Menampilkan raw context dari database RAG lokal...\n")
        
        # Fallback jika tidak ada LLM: Cukup berikan data dari Retrieval
        fallback_msg = "=== HASIL RETRIEVAL LOKAL ===\n"
        for c in context:
            fallback_msg += f"Target Software: {c['software']} {c['version']}\n"
            fallback_msg += f"Vuln: {c['vulnerability']}\n"
            fallback_msg += f"Saran Payload: {c['payload_suggestion']}\n"
        return fallback_msg

def main():
    global MODEL_NAME
    print("="*50)
    check_ollama_status()
    print("="*50)

    parser = argparse.ArgumentParser(description="AI RAG Pentest Assistant (Lightweight)")
    parser.add_argument("-q", "--query", type=str, required=True, help="Input dari hasil scan (misal: 'Apache 2.4.49')")
    parser.add_argument("-m", "--model", type=str, default=MODEL_NAME, help="Model Ollama yang digunakan (default: qwen2.5:7b)")
    args = parser.parse_args()

    MODEL_NAME = args.model

    # 1. RETRIEVAL
    print("[*] Mencari informasi di lokal database (RAG)...")
    db = load_db()
    context = retrieve_context(args.query, db)
    
    if not context:
        print(f"[-] Tidak ada kerentanan yang cocok di database untuk: {args.query}")
        sys.exit(0)

    # 2. GENERATION
    print(f"[*] Menghubungi LLM lokal ({MODEL_NAME}) untuk meracik payload...")
    answer = generate_payload(args.query, context)
    
    print("\n" + "="*50)
    print("🤖 REKOMENDASI AI PENTESTER")
    print("="*50)
    print(answer)
    print("="*50)

if __name__ == "__main__":
    main()
