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

DB_PATH = os.path.join(os.path.dirname(__file__), 'exploit_db_real.json')
OLLAMA_API = "http://localhost:11434/api/generate"
MODEL_NAME = "qwen2:0.5b" # Model yang sangat ringan (~300MB) atau gemma:2b / llama3.2:1b

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

def retrieve_context(query, db, top_k=1):
    """
    Retrieval ringan: Mengambil konteks dari database dummy kita berdasarkan kemiripan query
    dengan software/vulnerability di database.
    """
    # Menggabungkan semua text di DB sebagai corpus
    corpus = [f"{item['software']} {item['version']} {item['vulnerability']} {item['description']}" for item in db]
    
    # Mencari yang paling mirip menggunakan difflib (Ringan, tanpa GPU/RAM besar)
    matches = difflib.get_close_matches(query, corpus, n=top_k, cutoff=0.1)
    
    contexts = []
    for match in matches:
        idx = corpus.index(match)
        contexts.append(db[idx])
        
    return contexts

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
        }, timeout=10)
        
        if response.status_code == 200:
            return response.json().get("response", "")
        else:
            return f"[-] Error dari Ollama: {response.text}"
    except requests.exceptions.ConnectionError:
        print("[-] Tidak dapat terhubung ke Ollama. Pastikan Ollama berjalan (http://localhost:11434).")
        print("[-] Fallback: Menampilkan raw context dari database RAG lokal...\n")
        
        # Fallback jika tidak ada LLM: Cukup berikan data dari Retrieval
        fallback_msg = "=== HASIL RETRIEVAL LOKAL ===\n"
        for c in context:
            fallback_msg += f"Target Software: {c['software']} {c['version']}\n"
            fallback_msg += f"Vuln: {c['vulnerability']}\n"
            fallback_msg += f"Saran Payload: {c['payload_suggestion']}\n"
        return fallback_msg

def main():
    parser = argparse.ArgumentParser(description="AI RAG Pentest Assistant (Lightweight)")
    parser.add_argument("-q", "--query", type=str, required=True, help="Input dari hasil scan (misal: 'Apache 2.4.49')")
    parser.add_argument("-m", "--model", type=str, default=MODEL_NAME, help="Model Ollama yang digunakan (default: qwen2:0.5b)")
    args = parser.parse_args()

    global MODEL_NAME
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
