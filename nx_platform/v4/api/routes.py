import asyncio
from fastapi import APIRouter, BackgroundTasks, HTTPException, Query
from typing import Optional, List
from nx_platform.v4.api.models import TargetRequest, ACTIVE_JOBS, ScanJob, AIActivityLog, GLOBAL_AI_LOGS
from nx_platform.v4.engine.worker import autonomous_scan_loop
from nx_platform.v4.core.storage import save_job, get_all_jobs, get_ai_activities, save_ai_activity, get_job
from nx_platform.v4.core.ai_config import get_model_list, check_ollama_available
from datetime import datetime

from nx_platform.v4.core.auth import admin_only, get_current_user, Depends

router = APIRouter()

import logging

# Setup logger for routes
logger = logging.getLogger("nexusuite.routes")

@router.get("/ai/models")
async def list_models():
    """
    Get available AI models from Ollama.
    """
    return {"models": get_model_list(), "online": check_ollama_available()}

@router.post("/scan")
async def start_scan(req: TargetRequest, background_tasks: BackgroundTasks):
    """
    Endpoint untuk memulai pemindaian otonom.
    Sekarang menggunakan BackgroundTasks untuk mencegah timeout pada client.
    """
    try:
        logger.info(f"[API] Initializing scan for {req.url}...")
        
        # 1. Create Job Object (In-Memory)
        job = ScanJob(req.url)
        ACTIVE_JOBS[job.id] = job
        
        # 2. Definisikan Fungsi Runner untuk Background
        async def run_scan_in_background():
            try:
                # Persist awal ke DB (Sekarang dilakukan di background)
                job_data = job.to_dict()
                save_job(job_data)
                
                # Jalankan Loop Scan Utama
                await autonomous_scan_loop(
                    job.id, 
                    req.url, 
                    force_enum=req.force_enum,
                    ai_mode=req.ai_mode,
                    ai_model=req.ai_model
                )
            except Exception as e:
                logger.error(f"[API] Background Scan Error for {job.id}: {e}")
                job.status = "failed"
                job.logs.append(f"[-] Fatal error: {str(e)}")
                save_job(job.to_dict())

        # 3. Masukkan ke Background Tasks FastAPI
        background_tasks.add_task(run_scan_in_background)
        
        # 4. Berikan respon secepat mungkin (Cegah timeout)
        return {
            "message": "Scan mission initiated", 
            "id": job.id,
            "job_id": job.id, 
            "status": "initiated",
            "target": req.url
        }
        
    except Exception as e:
        logger.error(f"[API] Error in start_scan: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.delete("/scan/{job_id}")
async def stop_scan(job_id: str):
    """
    Menghentikan pemindaian yang sedang berjalan.
    """
    if job_id not in ACTIVE_JOBS:
        raise HTTPException(status_code=404, detail="Job not found")
    
    job = ACTIVE_JOBS[job_id]
    
    # 1. Batalkan Task Utama
    if job._task and not job._task.done():
        job._task.cancel()
        job.logs.append("[!] Scan dihentikan oleh pengguna.")
        job.status = "stopped"
        job.end_time = datetime.now()
        save_job(job.to_dict())
    
    # 2. Kill semua subprocess yang masih berjalan
    for proc in job._processes:
        try:
            proc.kill()
        except:
            pass
    
    job._processes = []
    
    return {"message": "Scan stopped successfully", "id": job_id, "job_id": job_id}

@router.get("/scans")
async def list_scans(limit: int = 50, offset: int = 0):
    """
    Mengambil daftar semua pemindaian dari database.
    """
    jobs = get_all_jobs(limit=limit, offset=offset)
    # Ensure it's a list for JQ processing in shell scripts
    if not isinstance(jobs, list):
        return []
    return jobs

@router.get("/scan/{job_id}")
async def get_scan_status(job_id: str):
    # Try active jobs first for real-time data from memory
    if job_id in ACTIVE_JOBS:
        # We still want to enrich it from DB if possible, but keep task/logs from memory
        mem_job = ACTIVE_JOBS[job_id].to_dict()
        db_job = get_job(job_id)
        if db_job:
            # Merge memory state with DB structured findings
            mem_job['structured_vulnerabilities'] = db_job.get('structured_vulnerabilities', [])
            mem_job['structured_exploits'] = db_job.get('structured_exploits', [])
            mem_job['ai_activities'] = db_job.get('ai_activities', [])
        return mem_job
    
    # Fallback to DB only
    job = get_job(job_id)
    if job:
        return job
            
    raise HTTPException(status_code=404, detail="Job not found")

@router.get("/activities")
async def list_activities(
    job_id: Optional[str] = None,
    activity_type: Optional[str] = None,
    limit: int = 100
):
    """
    Mengambil log aktivitas AI dengan filter.
    """
    return get_ai_activities(job_id=job_id, activity_type=activity_type, limit=limit)

@router.get("/reports/stats")
async def get_reports_stats():
    """
    Mengambil statistik untuk dashboard (Daily/Weekly/Monthly).
    """
    jobs = get_all_jobs()
    activities = get_ai_activities(limit=1000)
    
    total_scans = len(jobs)
    total_findings = sum(len(j['findings']) for j in jobs)
    success_rate = 100.0 # Default
    
    # Basic metrics calculation
    if total_scans > 0:
        completed_scans = sum(1 for j in jobs if j['status'] == 'completed')
        success_rate = (completed_scans / total_scans) * 100
        
    avg_response_time = 0
    if activities:
        avg_response_time = sum(a['duration'] for a in activities) / len(activities)
        
    return {
        "total_scans": total_scans,
        "total_findings": total_findings,
        "success_rate": success_rate,
        "avg_response_time": avg_response_time,
        "activity_counts": {
            "chat": sum(1 for a in activities if a['activity_type'] == 'chat'),
            "analyze": sum(1 for a in activities if a['activity_type'] == 'analyze'),
            "exploit": sum(1 for a in activities if a['activity_type'] == 'exploit'),
            "think": sum(1 for a in activities if a['activity_type'] == 'think'),
            "plan": sum(1 for a in activities if a['activity_type'] == 'plan'),
            "observe": sum(1 for a in activities if a['activity_type'] == 'observe')
        }
    }

@router.get("/export")
async def export_data(format: str = "csv"):
    """
    Ekspor data aktivitas AI ke CSV atau JSON.
    """
    activities = get_ai_activities(limit=1000)
    
    if format == "json":
        return activities
    
    # Simple CSV conversion
    import io
    import csv
    from fastapi.responses import StreamingResponse
    
    output = io.StringIO()
    writer = csv.writer(output)
    
    if activities:
        writer.writerow(activities[0].keys())
        for act in activities:
            writer.writerow(act.values())
            
    output.seek(0)
    return StreamingResponse(
        io.BytesIO(output.getvalue().encode()),
        media_type="text/csv",
        headers={"Content-Disposition": f"attachment; filename=ai_activities_{datetime.now().strftime('%Y%m%d')}.csv"}
    )
