#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/ai_config.sh"

TARGET=""
LOG_DIR=""

while [[ "$#" -gt 0 ]]; do
    case "$1" in
        --target) TARGET="${2:-}"; shift ;;
        --log-dir) LOG_DIR="${2:-}"; shift ;;
        *) ;;
    esac
    shift
done

if [[ -z "$TARGET" || -z "$LOG_DIR" ]]; then
    echo "[AI OVERLORD][ERROR] Usage: ai_terminal_overlord.sh --target <target> --log-dir <target_dir>"
    exit 1
fi

OVERLORD_LOG="$LOG_DIR/vulnerabilities/ai_overlord_terminal.log"
: > "$OVERLORD_LOG"

echo -e "\033[1;90m============================================================\033[0m" | tee -a "$OVERLORD_LOG"
echo -e "\033[41m\033[1;97m ☢️ [Fase 4] AI TERMINAL OVERLORD MODE DIAKTIFKAN \033[0m" | tee -a "$OVERLORD_LOG"
echo -e "\033[1;36mTarget:\033[0m \033[1;37m$TARGET\033[0m" | tee -a "$OVERLORD_LOG"
echo -e "\033[1;90m============================================================\033[0m" | tee -a "$OVERLORD_LOG"

# Batas maksimum iterasi untuk mencegah infinite loop
MAX_ITERATIONS="${AI_OVERLORD_MAX_ITERATIONS:-5}"
ITERATION=1
PREVIOUS_OUTPUTS=""

ollama_generate() {
    local prompt="$1"
    local payload
    payload="$(jq -n --arg model "$OLLAMA_MODEL" --arg prompt "$prompt" '{model: $model, prompt: $prompt, stream: false}')"
    ollama_curl -fsS -m "${AI_HTTP_TIMEOUT:-120}" -X POST "$OLLAMA_GENERATE_API" -H "Content-Type: application/json" -d "$payload"
}

# Memuat Memori AI Jangka Panjang (Long-Term Memory)
SAFE_MODEL_NAME="${OLLAMA_MODEL//[:\/]/_}"
GLOBAL_AI_MEMORY_DIR="$SCRIPT_DIR/../ai_memory"
GLOBAL_MEMORY_FILE="$GLOBAL_AI_MEMORY_DIR/memory_ai_${SAFE_MODEL_NAME}.jsonl"

load_recent_campaign_memory() {
    local count="${AI_MEMORY_WINDOW:-30}"
    if [[ -s "$GLOBAL_MEMORY_FILE" ]]; then
        tail -n "$count" "$GLOBAL_MEMORY_FILE" 2>/dev/null || true
    else
        echo "Memori masih kosong. Ini adalah pengalaman pertamamu."
    fi
}

CAMPAIGN_MEMORY_SNIPPET="$(load_recent_campaign_memory)"

# Loop Overlord
while [[ $ITERATION -le $MAX_ITERATIONS ]]; do
    echo -e "\n\033[44m\033[1;97m 🔄 ITERASI $ITERATION / $MAX_ITERATIONS \033[0m" | tee -a "$OVERLORD_LOG"

    PROMPT=$(cat <<EOF
Kamu adalah AI Terminal Overlord. Kamu diberi kendali penuh atas shell linux untuk meretas target secara etis (White Hat).
Target Utama: $TARGET

Konteks Sejarah (Output terminal dari langkah sebelumnya):
$PREVIOUS_OUTPUTS

[LONG-TERM AI MEMORY (CROSS-SESSION LEARNING)]
$CAMPAIGN_MEMORY_SNIPPET

TUGASMU:
Berpikirlah seperti peretas elit (berpikir cerdas, logis, eksplosif, dan adaptif). 
- Jadikan [LONG-TERM AI MEMORY] sebagai pedoman mutlak. Jika teknik tersebut pernah berhasil, gunakan lagi untuk menjadi lebih tajam.
- Jika target adalah IP, cek apakah ini IP asli atau reDNS (cek dari Nmap/Nikto atau jalankan curl/nslookup).
- Cari CVE yang relevan berdasarkan teknologi yang berjalan (Gunakan 'searchsploit' atau curl ke database eksploit publik).
- Bangun payload kustom jika menemukan endpoint rentan, lalu kirim request (Gunakan 'curl', 'httpx', 'sqlmap', dll).
- Baca isi website jika perlu dengan 'curl -s http://target | grep -i password'.
- Lakukan enumerasi lebih dalam jika kamu merasa hasil sebelumnya kurang.

Kamu BEBAS memilih SATU command bash (linux) apapun yang aman (jangan gunakan rm -rf, mkfs, atau command destruktif pada sistem lokalmu sendiri).

KEMBALIKAN HANYA JSON VALID (tanpa markdown/code block) DENGAN SCHEMA INI:
{
  "thought_process": "Penjelasan rinci mengapa kamu memilih langkah ini, apa analisamu tentang target, dan apa yang ingin kamu capai.",
  "command": "Perintah bash yang ingin dieksekusi (contoh: curl -sI http://target || searchsploit apache 2.4)",
  "is_finished": true/false (Pilih true HANYA JIKA kamu sudah merasa mentok, tidak ada lagi yang bisa di-exploit, atau sudah menemukan bukti kuat)
}

Berpikirlah di dalam tag <think>...</think> terlebih dahulu sebelum memberikan JSON.
EOF
)

    echo "[AI OVERLORD] Memikirkan langkah selanjutnya..." | tee -a "$OVERLORD_LOG"
    RAW_RESP="$(ollama_generate "$PROMPT" || true)"
    
    if [[ -z "$RAW_RESP" ]]; then
        echo "[AI OVERLORD][ERROR] Ollama tidak merespon." | tee -a "$OVERLORD_LOG"
        break
    fi

    JSON_RESP="$(clean_json_response "$(echo "$RAW_RESP" | jq -r '.response // empty' 2>/dev/null)")"
    
    if [[ -z "$JSON_RESP" ]]; then
        echo "[AI OVERLORD][WARN] AI tidak memberikan JSON valid. Menghentikan Overlord." | tee -a "$OVERLORD_LOG"
        break
    fi

    THOUGHT=$(echo "$JSON_RESP" | jq -r '.thought_process // "Berpikir..."')
    CMD=$(echo "$JSON_RESP" | jq -r '.command // ""')
    IS_FINISHED=$(echo "$JSON_RESP" | jq -r '.is_finished // false')

    echo -e "\033[1;35m[AI THOUGHT]\033[0m \033[1;37m$THOUGHT\033[0m" | tee -a "$OVERLORD_LOG"
    
    if [[ "$IS_FINISHED" == "true" || -z "$CMD" || "$CMD" == "null" ]]; then
        echo -e "\033[42m\033[1;97m ✅ AI memutuskan untuk mengakhiri serangannya. \033[0m" | tee -a "$OVERLORD_LOG"
        break
    fi

    # Keamanan: Tolak command yang merusak mesin lokal
    if [[ "$CMD" =~ (rm[[:space:]]+-rf|mkfs|dd[[:space:]]+if|:\|:|>\s*/dev/sda) ]]; then
         echo -e "\033[41m\033[1;97m ❌ [BLOCKED] Command ditolak karena berpotensi merusak mesin lokal: $CMD \033[0m" | tee -a "$OVERLORD_LOG"
         CMD_OUTPUT="ERROR: Command ditolak oleh sistem keamanan."
    else
         echo -e "\033[46m\033[1;97m 🚀 [EXEC] Menjalankan: \033[0m \033[1;36m$CMD\033[0m" | tee -a "$OVERLORD_LOG"
         # Eksekusi command secara nyata
         CMD_OUTPUT=$(timeout 60 bash -c "$CMD" 2>&1 | head -c 5000 || echo "[Timeout atau Output terlalu panjang]")
    fi

    echo -e "\033[1;90m--- OUTPUT ---\033[0m" | tee -a "$OVERLORD_LOG"
    echo -e "\033[38;5;245m$CMD_OUTPUT\033[0m" | tee -a "$OVERLORD_LOG"
    echo -e "\033[1;90m------------------------------------------------------------\033[0m" | tee -a "$OVERLORD_LOG"

    # Simpan output untuk konteks iterasi selanjutnya (dibatasi agar tidak kepanjangan)
    PREVIOUS_OUTPUTS="--- PERINTAH SEBELUMNYA: $CMD ---\n$CMD_OUTPUT\n"

    ((ITERATION++))
done

echo -e "\n\033[1;90m============================================================\033[0m" | tee -a "$OVERLORD_LOG"
echo -e "\033[42m\033[1;97m � [Fase 4] AI TERMINAL OVERLORD SELESAI \033[0m" | tee -a "$OVERLORD_LOG"
echo -e "\033[1;90m============================================================\033[0m" | tee -a "$OVERLORD_LOG"
exit 0
