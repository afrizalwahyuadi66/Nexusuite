# Technical Documentation - Nexusuite v4

## 1. Introduction
Nexusuite v4 adalah platform keamanan ofensif otonom yang dirancang untuk melakukan pengujian penetrasi (pentesting) secara end-to-end. Sistem ini menggabungkan kekuatan alat keamanan open-source dengan kecerdasan buatan (AI) untuk memberikan hasil yang presisi dan otomatis.

## 2. Core Components & Modules

### 2.1. Backend API (`nx_platform/v4/api/`)
- **`routes.py`**: Mendefinisikan endpoint REST API menggunakan FastAPI. Mengelola inisiasi scan, penghentian job, dan pengambilan data aktivitas AI.
- **`models.py`**: Skema data Pydantic untuk permintaan target, status job, dan log aktivitas.

### 2.2. Autonomous Engine (`nx_platform/v4/engine/`)
- **`worker.py`**: Implementasi `autonomous_scan_loop`. Mengelola siklus hidup scan dari Recon hingga Exploit. Menggunakan `ReconManager` untuk penemuan target.
- **`orchestrator.py`**: Menggunakan LLM (Ollama) dan RAG untuk merencanakan strategi serangan dan mengevaluasi temuan secara cerdas.

### 2.3. AI Intelligence (`nx_platform/v4/ai_agent/`)
- **`ai_brain.py`**: Logika utama agen AI untuk pengambilan keputusan.
- **`form_analyzer.py`**: Menganalisis form HTML untuk mendeteksi potensi kerentanan seperti CSRF dan IDOR.
- **`url_classifier.py`**: Mengklasifikasikan URL berdasarkan sensitivitas dan tipe (e.g., login, upload, admin).

### 2.4. Core Utilities (`nx_platform/v4/core/`)
- **`bootstrap.py`**: Sistem self-healing yang mengotomatisasi instalasi dependensi yang hilang.
- **`registry.py`**: Registry pusat untuk manajemen perintah tool keamanan.
- **`storage.py`**: Integrasi database SQLite untuk persistensi data.
- **`auth.py`**: Sistem autentikasi berbasis API Key.

## 3. Workflow Detail

### 3.1. Initialization & Bootstrapping
1. Menjalankan `bootstrap.py`.
2. Memeriksa keberadaan binary tool (nuclei, sqlmap, dll.).
3. Menyiapkan environment variable dan PATH.
4. Menjalankan server FastAPI.

### 3.2. User Authentication
Sistem menggunakan header `X-API-Key` untuk memvalidasi pengguna.
- **Admin**: Akses penuh ke semua fitur.
- **User**: Akses terbatas (biasanya read-only pada versi produksi).

### 3.3. Scanning Lifecycle
1. **Phase 1 & 2: Reconnaissance**: Menggunakan `assetfinder`, `amass`, `httpx`, dan `nmap` untuk memetakan permukaan serangan.
2. **Phase 3: Intelligence Gathering**: Crawling menggunakan `katana` dan `gau`. Mining parameter dengan `paramspider`.
3. **Phase 3.5: AI Observation**: AI Agent menganalisis semua URL yang ditemukan untuk memprioritaskan target.
4. **Phase 4: Vulnerability Research**: Menjalankan scanner otomatis seperti `nuclei` dan `nikto`.
5. **Phase 4.5: Advanced Testing**: AI menganalisis form dan melakukan pengujian CSRF/IDOR secara spesifik.
6. **Phase 5: Exploitation**: Upaya eksploitasi terfokus menggunakan `sqlmap` dan `dalfox` pada target yang divalidasi oleh AI.

### 3.4. Database Integration
- **SQLite** digunakan untuk menyimpan:
    - `jobs`: Data metadata pemindaian.
    - `ai_activities`: Log interaksi dan keputusan AI.
    - `vulnerabilities`: Temuan kerentanan terstruktur.
    - `exploits`: Detail upaya eksploitasi.

### 3.5. Response & Reporting
Setelah pemindaian selesai:
1. Data dikonsolidasikan dari database.
2. `reporting.py` menghasilkan laporan dalam format JSON dan Markdown.
3. User dapat mengunduh laporan melalui API atau melihatnya di dashboard.

## 4. Dependencies & Environment

### 4.1. System Dependencies (External Tools)
Sistem memerlukan tool berikut terinstal di sistem operasi:
- `subfinder`, `httpx`, `nuclei`, `katana`, `amass`, `assetfinder` (ProjectDiscovery tools)
- `sqlmap`, `dalfox`, `arjun`, `nikto`, `nmap`
- `go` (untuk instalasi tool ProjectDiscovery)
- `python 3.10+`

### 4.2. Python Libraries
Daftar library utama (berdasarkan `requirements.txt`):
- `fastapi`, `uvicorn`: Web framework dan server.
- `httpx`, `aiohttp`: Client HTTP asinkron.
- `pydantic`: Validasi data.
- `beautifulsoup4`: Parsing HTML.
- `PyYAML`: Parsing file konfigurasi.
- `sqlite3`: Database engine.

### 4.3. Environment Variables
- `NX_ADMIN_KEY`: API Key untuk akses admin.
- `NX_USER_KEY`: API Key untuk akses user.
- `OLLAMA_HOST`: URL server Ollama (default: http://localhost:11434).
- `OLLAMA_MODEL`: Model LLM yang digunakan (e.g., deepseek-coder, llama3).
- `NX_MODE`: Mode aplikasi (`development` atau `production`).

## 5. Maintenance & Extension
- **Menambah Tool Baru**: Tambahkan entri di `ToolRegistry` dalam `registry.py`.
- **Update AI Logic**: Modifikasi prompt atau logika di `orchestrator.py` atau `ai_agent/`.
- **Database Schema**: Update fungsi `init_db()` di `storage.py` untuk migrasi tabel.
