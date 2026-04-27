# Nexusuite Platform v1

Platform mode menambahkan pondasi:
- Plugin-based runner (`config/tool_plugins/*.yaml`)
- Queue + worker (SQLite `platform_state.db`)
- REST API + Web UI ringan
- Unified finding schema + dedup awal

## Jalankan

Terminal 1 (API + UI):
```bash
./nexusuite.sh --platform-api
```

Terminal 2 (Worker):
```bash
./nexusuite.sh --platform-worker
```

Buka:
- `http://127.0.0.1:8787/ui`

## Endpoint API

- `GET /api/plugins`
- `GET /api/scans`
- `GET /api/jobs?scan_id=<id>`
- `GET /api/findings?scan_id=<id>`
- `GET /api/approvals`
- `GET /api/timeline?scan_id=<id>`
- `POST /api/scans`
- `POST /api/scans/<id>/replay`
- `POST /api/jobs/<id>/approve`
- `POST /api/jobs/<id>/reject`
- `POST /api/approvals/bulk`
- `POST /api/ai/explain`

Payload `POST /api/scans`:
```json
{
  "target": "https://example.com",
  "plugins": ["httpx", "nuclei"],
  "profile": "platform_v1"
}
```

## Catatan

- Worker mengeksekusi command dari plugin template dengan placeholder:
  - `{target}`
  - `{output}`
- Hasil command disimpan ke `platform_runs/scan_<id>/...`
- Temuan hasil parser di-upsert ke tabel `findings` berdasar `issue_key`.
- Timeline event disimpan ke tabel `timeline_events` dengan jejak `plan -> approval -> execute -> verdict`.

## Approval Worker (Policy-aware)

Worker membaca approval mode dari `config/risk_policy.yaml`:
- `approval_low` (default `auto`)
- `approval_medium` (default `prompt_once`)
- `approval_high` (default `prompt_each`)

Jika tier medium/high belum diizinkan, job akan masuk status `awaiting_approval` dan bisa di-approve dari:
- UI `Approval Center`
- API `POST /api/jobs/<id>/approve`
- API `POST /api/jobs/<id>/reject` (dengan reason)
- API `POST /api/approvals/bulk` untuk aksi massal `approve|reject`
- UI mendukung search/filter approvals, select all visible, dan select by `scan_id`
- UI mendukung preset cepat: `Only High-Risk`, `Medium+`, `Only Nuclei`, dan `Scan Filter Aktif`

Opsional via env (auto-approve):
- `NEXUS_PLATFORM_APPROVE_MEDIUM=true`
- `NEXUS_PLATFORM_APPROVE_HIGH=true`
- `NEXUS_PLATFORM_AUTO_APPROVE_ALL=true` (override semua tier, gunakan dengan hati-hati)
