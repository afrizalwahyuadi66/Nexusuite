# Nexusuite Architecture Map

Dokumen ini adalah peta arsitektur operasional Nexusuite untuk memahami struktur proyek, alur eksekusi, dan lokasi logika bisnis utama.

## 1) Gambaran Sistem

Nexusuite adalah framework security automation berbasis Bash dengan subsistem AI (Bash + Python) yang bekerja dalam mode:

- CLI scanner utama (`nexusuite.sh`)
- AI-assisted/autonomous execution (`ai_rag_tool/`)
- Platform mode (API/worker + web UI) yang terdokumentasi, namun beberapa file backend belum ada di checkout saat ini

## 2) Struktur Direktori Utama

- `nexusuite.sh`  
  Entry point utama untuk mode interaktif dan flag CLI (`--doctor`, `--dry-run`, `--platform-api`, `--platform-worker`).
- `modules/`  
  Pipeline inti scanning, orchestration, auditing, reporting.
- `ai_rag_tool/`  
  Orkestrasi AI, risk policy, memory, assistant Python.
- `config/`  
  Risk policy dan plugin template YAML.
- `platform/`  
  Dokumen platform + web UI (`platform/web/index.html`).
- `run_windows.ps1`, `install.sh`  
  Bootstrap/launcher untuk Windows (WSL) dan instalasi dependency.

## 3) Stack dan Dependensi Runtime

- Bahasa utama: Bash
- Bahasa pendukung: Python 3
- AI provider lokal: Ollama (`OLLAMA_HOST`, `OLLAMA_MODEL`)
- Tool pentest utama: `subfinder`, `httpx`, `nmap`, `nuclei`, `dalfox`, `gau`, `katana`, `arjun`, `sqlmap`, `paramspider`, `nikto`, `ffuf`, `wafw00f`
- Python deps utama: `requests`, `duckduckgo-search` (`ai_rag_tool/requirements.txt`)

## 4) Alur Eksekusi End-to-End

Urutan eksekusi utama saat menjalankan `./nexusuite.sh`:

1. Parse argument dan tentukan mode startup.
2. Source modul berurutan:
   - `modules/00_error_handler.sh`
   - `modules/01_init.sh`
   - `modules/02_prompts.sh`
   - `modules/02b_proxy_manager.sh`
   - `modules/08_ai_advanced.sh`
   - `modules/03_core.sh`
   - `modules/04_execution.sh`
   - `modules/05_auditing.sh`
   - `modules/06_reporting.sh`
   - `modules/07_html_report.sh`
3. Ambil target + konfigurasi run (`02_prompts`).
4. Jalankan pipeline scan per target (`03_core`) sesuai modul terpilih/AI plan.
5. Jalankan batch/concurrency orchestration (`04_execution`).
6. Audit findings + verifikasi/aksi terkontrol (`05_auditing`).
7. Generate laporan text + HTML (`06_reporting`, `07_html_report`).

## 5) Tanggung Jawab Modul Inti

- `modules/00_error_handler.sh`  
  Trap/signal handling, recovery dasar, stabilitas proses.
- `modules/01_init.sh`  
  Inisialisasi environment, helper log global, setup output session.
- `modules/02_prompts.sh`  
  Input target, pilihan mode/module, persist konfigurasi run.
- `modules/02b_proxy_manager.sh`  
  Rotasi/health proxy, lock file, routing mode (best-effort/strict).
- `modules/03_core.sh`  
  Logika bisnis paling padat: recon, URL harvest/filter, vuln scan, retries, throttling, integrasi AI planning/replanning.
- `modules/04_execution.sh`  
  Queue target dan parallel execution (`wait -n`, kontrol job aktif).
- `modules/05_auditing.sh`  
  Triage temuan, scoring/konfirmasi, handoff ke autonomous pentester.
- `modules/06_reporting.sh`  
  Konsolidasi output teknis ke text report.
- `modules/07_html_report.sh`  
  Dashboard HTML dan ringkasan visual sesi.
- `modules/08_ai_advanced.sh`  
  Helper AI tingkat lanjut yang dipakai selama pipeline.

## 6) Subsistem AI dan Risk Control

Lokasi kunci:

- `ai_rag_tool/ai_config.sh`  
  Loader konfigurasi AI dari `.env`, default value, no-proxy behavior.
- `ai_rag_tool/risk_policy.sh`  
  Parser dan evaluator policy (tier command, scope checks, approval logic).
- `ai_rag_tool/autonomous_pentester.sh`  
  Engine keputusan AI, command suggestion/execution terkontrol, memory append.
- `ai_rag_tool/ai_orchestrator_safe.sh`  
  Orkestrator AI dengan guardrail execution.
- `ai_rag_tool/ai_terminal_overlord.sh`  
  Eksekusi command yang dihasilkan AI (area sensitif, perlu policy ketat).

Policy utama:

- `config/risk_policy.yaml` sebagai sumber aturan scope + approval.
- Urutan precedence scope: blocklist > allowlist > private/local checks.

## 7) Data, State, dan Artefak Output

State runtime utama bersifat file-based:

- Session output folder (`OWASP_SCAN_YYYYMMDD_HHMMSS` pattern)
- `README_OUTPUT.txt`, `report/full_report.txt`, `report/index.html`
- Per-target artifact (`targets/<target>/scan.log`, `README_TARGET.txt`, proxy report)
- File status internal (`.status`, skip marker, completed targets list)
- AI memory lintas sesi (`ai_memory/memory_ai_<model>.jsonl`)

Tidak ada framework DB migration formal di alur CLI utama saat ini.

## 8) Platform Mode: Kondisi Saat Ini

Yang ada:

- `platform/README.md`
- `platform/web/index.html` (UI yang memanggil endpoint `/api/...`)

Yang direferensikan namun belum terlihat di checkout ini:

- `platform/api_server.py`
- `platform/worker.py`

Artinya fitur platform di dokumentasi/UI tampak dirancang, tetapi implementasi backend mungkin belum ikut tersinkron pada snapshot repo ini.

## 9) Lokasi Logika Bisnis Paling Penting

Jika ingin memahami 80% perilaku sistem, fokus baca urutan ini:

1. `nexusuite.sh`
2. `modules/03_core.sh`
3. `modules/04_execution.sh`
4. `modules/05_auditing.sh`
5. `ai_rag_tool/autonomous_pentester.sh`
6. `ai_rag_tool/risk_policy.sh`

## 10) Area Kompleks / Rawan Regresi

- Orkestrasi scan multi-tool + retry/proxy fallback di `modules/03_core.sh`
- Eksekusi command berbasis output LLM di `ai_rag_tool/autonomous_pentester.sh` dan `ai_terminal_overlord.sh`
- Sinkronisasi process/signal/background job (`00_error_handler` + `04_execution`)
- Doc/code drift pada platform mode (UI + README vs file backend yang belum ada)

## 11) Konvensi dan Praktik yang Perlu Diingat

- Arsitektur berpusat pada output file, bukan service internal monolitik.
- Bash scripts mencampur pesan Indonesia + English; ini normal di repo.
- Tool eksternal adalah dependency kritikal; error handling lebih banyak terjadi di runtime daripada compile time.
- Validasi environment (`--doctor`, `--doctor-json`) penting sebelum scan skala besar.

## 12) Checklist Onboarding Cepat (Untuk Konteks Penuh)

1. Jalankan `./nexusuite.sh --doctor`.
2. Baca `nexusuite.sh` untuk memahami mode startup.
3. Telusuri modul sesuai urutan source.
4. Fokus detail `modules/03_core.sh` + `modules/05_auditing.sh`.
5. Validasi konfigurasi AI di `.env` + `ai_rag_tool/ai_config.sh`.
6. Review policy di `config/risk_policy.yaml`.
7. Cocokkan output nyata dari satu run dengan peta ini.

---

Dokumen ini ditujukan sebagai peta kerja stabil. Jika struktur module bertambah, update bagian **4**, **5**, dan **9** terlebih dulu agar peta tetap akurat.
