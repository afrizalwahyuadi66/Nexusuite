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
SHARED_MEMORY_FILE="${AI_MEMORY_SHARED_FILE:-$GLOBAL_AI_MEMORY_DIR/memory_ai_shared.jsonl}"
if [[ "$LOG_DIR" == *"/targets/"* ]]; then
    OUTPUT_BASE="${LOG_DIR%%/targets/*}"
else
    OUTPUT_BASE="$(dirname "$LOG_DIR")"
fi
CAMPAIGN_MEMORY_FILE="$OUTPUT_BASE/ai_memory/campaign_memory.jsonl"

load_recent_campaign_memory() {
    local count="${AI_MEMORY_WINDOW:-30}"
    local target_lc="${TARGET,,}"
    local target_root
    target_root="$(echo "$target_lc" | sed -E 's#^https?://##; s#/.*$##' | awk -F. '{if (NF>2) print $(NF-1)"."$NF; else print $0}')"
    if command -v jq >/dev/null 2>&1; then
        jq -n \
          --arg t "$target_lc" \
          --arg tr "$target_root" \
          --argjson n "$count" \
          --argjson half_life "${AI_MEMORY_DECAY_HALFLIFE_DAYS:-14}" \
          --argjson bl_fail "${AI_MEMORY_BLACKLIST_FAIL_THRESHOLD:-3}" \
          --argjson bl_days "${AI_MEMORY_BLACKLIST_WINDOW_DAYS:-30}" \
          --arg shared_on "${AI_MEMORY_SHARED:-false}" \
          --slurpfile s "$CAMPAIGN_MEMORY_FILE" \
          --slurpfile g "$GLOBAL_MEMORY_FILE" \
          --slurpfile h "$SHARED_MEMORY_FILE" '
          def to_list($arr; $src): $arr | map(. + {source:$src});
          def age_days($ts): ((now - (($ts | fromdateiso8601?) // now)) / 86400);
          def decay($days): (if $days <= 0 then 1 else pow(0.5; ($days / ($half_life | if . <= 0 then 14 else . end))) end);
          def target_score($target):
            ($target // "" | ascii_downcase) as $tt
            | if $tt == $t then 1.0
              elif ($tt | contains($t)) then 0.9
              elif (($tr|length) > 0 and (($tt | contains($tr)) or ($t | contains($tr)))) then 0.6
              else 0.15 end;
          ((to_list($s; "session")
            + to_list($g; "global")
            + (if ($shared_on == "true" or $shared_on == "1") then to_list($h; "shared") else [] end)
           ) | map(select(type=="object"))) as $all
          | ($all | map(select(((.target // "" | ascii_downcase) == $t) or ((.target // "" | ascii_downcase) | contains($t)))) | length) as $same_hits
          | (if $same_hits > 0 then 1.35 else 0.9 end) as $session_bias
          | (if $same_hits > 0 then 0.95 else 1.1 end) as $global_bias
          | (if $same_hits > 0 then 0.70 else 0.85 end) as $shared_bias
          | ($all | map(
              . as $e
              | ($e.timestamp // null) as $ts
              | (if $ts == null then 365 else age_days($ts) end) as $days
              | (if $e.source == "session" then $session_bias
                 elif $e.source == "shared" then $shared_bias
                 else $global_bias end) as $srcb
              | (target_score($e.target) * 42
                 + (if ($e.risk // "" | ascii_downcase) == "critical" then 20 elif ($e.risk // "" | ascii_downcase) == "high" then 12 elif ($e.risk // "" | ascii_downcase) == "medium" then 6 else 2 end)
                 + (if ($e.outcome // "unknown") == "success" then 8 elif ($e.outcome // "unknown") == "failed" then -6 else 0 end)
                 + ((($e.verification_ok // 0) + ($e.controlled_ok // 0)) * 2)
                ) as $raw
              | . + {score: ($raw * decay($days) * $srcb), age_days: $days}
            )) as $scored
          | ($scored
             | map(select(((.age_days // 9999) <= $bl_days) and ((.technique // "N/A") != "N/A")))
             | sort_by(.technique)
             | group_by(.technique)
             | map({technique:.[0].technique, fails:(map(select((.outcome // "") == "failed"))|length), successes:(map(select((.outcome // "") == "success"))|length)})
             | map(select(.fails >= $bl_fail and .successes == 0))
             | map(.technique)
            ) as $blacklist
          | ([
              "[MEMORY ENGINE v2] source_mix=session+global" + (if ($shared_on == "true" or $shared_on == "1") then "+shared" else "" end) + " adaptive=true decay_half_life_days=\($half_life)",
              "[BLACKLIST TECHNIQUE AUTO]",
              (if ($blacklist|length)==0 then "- none" else ($blacklist[] | "- \(.)") end),
              "[TOP RELEVANT MEMORIES]"
            ]
            + ($scored
               | sort_by(-.score, .timestamp)
               | .[:$n]
               | map("[\(.timestamp // "NA")] src=\(.source) score=\((.score|floor)) target=\(.target // "NA") risk=\(.risk // "NA") outcome=\(.outcome // "unknown") cve=\(.cve // "None") technique=\(.technique // "N/A")")
              )
           ) | .[]
        ' 2>/dev/null || {
            if [[ -s "$CAMPAIGN_MEMORY_FILE" ]]; then
                tail -n "$count" "$CAMPAIGN_MEMORY_FILE" 2>/dev/null || true
            else
                tail -n "$count" "$GLOBAL_MEMORY_FILE" 2>/dev/null || true
            fi
        }
    elif [[ -s "$CAMPAIGN_MEMORY_FILE" ]]; then
        tail -n "$count" "$CAMPAIGN_MEMORY_FILE" 2>/dev/null || true
    elif [[ -s "$GLOBAL_MEMORY_FILE" ]]; then
        tail -n "$count" "$GLOBAL_MEMORY_FILE" 2>/dev/null || true
    else
        echo "Memori masih kosong. Ini adalah pengalaman pertamamu."
    fi
}

CAMPAIGN_MEMORY_SNIPPET="$(load_recent_campaign_memory)"

if [[ -s "$CAMPAIGN_MEMORY_FILE" ]] || [[ -s "$GLOBAL_MEMORY_FILE" ]]; then
    total_campaign=$(wc -l < "$CAMPAIGN_MEMORY_FILE" 2>/dev/null || echo 0)
    total_global=$(wc -l < "$GLOBAL_MEMORY_FILE" 2>/dev/null || echo 0)
    echo -e "\033[1;36m[AI SYSTEM]\033[0m \033[1;32mBerhasil memuat Memori AI Jangka Panjang\033[0m \033[1;90m(Sesi: $total_campaign | Global: $total_global)\033[0m" | tee -a "$OVERLORD_LOG"
else
    echo -e "\033[1;33m[AI SYSTEM]\033[0m \033[1;37mMemori AI kosong. Ini adalah pengalaman pertama AI untuk target ini.\033[0m" | tee -a "$OVERLORD_LOG"
fi

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
- Hormati [BLACKLIST TECHNIQUE AUTO]: jangan ulangi teknik yang ditandai gagal berulang.
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

    # UI Upgrade: Tampilan Thought yang lebih cyberpunk
    echo -e "\033[1;35m╔══ [AI THOUGHT]\033[0m" | tee -a "$OVERLORD_LOG"
    echo -e "\033[1;35m║\033[0m \033[3;37m$THOUGHT\033[0m" | tee -a "$OVERLORD_LOG"
    echo -e "\033[1;35m╚═══════════════════════════════════════════════════════════\033[0m" | tee -a "$OVERLORD_LOG"
    
    if [[ "$IS_FINISHED" == "true" || -z "$CMD" || "$CMD" == "null" ]]; then
        echo -e "\033[42m\033[1;97m ✅ AI memutuskan untuk mengakhiri serangannya. \033[0m" | tee -a "$OVERLORD_LOG"
        break
    fi

    # Keamanan: Tolak command yang merusak mesin lokal
    if [[ "$CMD" =~ (rm[[:space:]]+-rf|mkfs|dd[[:space:]]+if|:\|:|>\s*/dev/sda) ]]; then
         echo -e "\033[41m\033[1;97m ❌ [BLOCKED] Command ditolak karena berpotensi merusak mesin lokal: \033[0m" | tee -a "$OVERLORD_LOG"
         echo -e "\033[1;31m   > $CMD \033[0m" | tee -a "$OVERLORD_LOG"
         CMD_OUTPUT="ERROR: Command ditolak oleh sistem keamanan."
    else
         echo -e "\033[46m\033[1;97m 🚀 [EXEC] Menjalankan: \033[0m \033[1;36m$CMD\033[0m" | tee -a "$OVERLORD_LOG"
         # Eksekusi command secara nyata
         CMD_OUTPUT=$(timeout 60 bash -c "$CMD" 2>&1 | head -c 5000 || echo "[Timeout atau Output terlalu panjang]")
    fi

    echo -e "\033[1;90m┌── OUTPUT ─────────────────────────────────────────────────\033[0m" | tee -a "$OVERLORD_LOG"
    # Menambahkan warna abu-abu untuk output terminal agar tidak menyakiti mata
    echo -e "\033[38;5;245m$CMD_OUTPUT\033[0m" | tee -a "$OVERLORD_LOG"
    echo -e "\033[1;90m└───────────────────────────────────────────────────────────\033[0m" | tee -a "$OVERLORD_LOG"

    # Simpan output untuk konteks iterasi selanjutnya (dibatasi agar tidak kepanjangan)
    PREVIOUS_OUTPUTS="--- PERINTAH SEBELUMNYA: $CMD ---\n$CMD_OUTPUT\n"

    ((ITERATION++))
done

echo -e "\n\033[1;90m============================================================\033[0m" | tee -a "$OVERLORD_LOG"
echo -e "\033[42m\033[1;97m � [Fase 4] AI TERMINAL OVERLORD SELESAI \033[0m" | tee -a "$OVERLORD_LOG"
echo -e "\033[1;90m============================================================\033[0m" | tee -a "$OVERLORD_LOG"
exit 0
