from fastapi import FastAPI, Request
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
from nx_platform.v4.api.routes import router as api_router
from nx_platform.v4.core.config import PROJECT_NAME, API_V1_STR, logger
import os

app = FastAPI(title=PROJECT_NAME)

# Setup Templates & Static Files
current_dir = os.path.dirname(os.path.abspath(__file__))
templates = Jinja2Templates(directory=os.path.join(current_dir, "templates"))
app.mount("/static", StaticFiles(directory=os.path.join(current_dir, "static")), name="static")

# Include API Routes
app.include_router(api_router, prefix=API_V1_STR)

@app.get("/")
async def root(request: Request):
    # Menggunakan dashboard v2 terbaru
    return templates.TemplateResponse("dashboard_v2.html", {"request": request})

@app.get("/legacy")
async def legacy_dashboard(request: Request):
    return templates.TemplateResponse("dashboard.html", {"request": request})

@app.get("/health")
async def health():
    return {
        "project": PROJECT_NAME,
        "version": "4.1.0-PTES",
        "status": "online",
        "engine": "AI-First Autonomous"
    }

if __name__ == "__main__":
    import uvicorn
    import sys
    import os

    root_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../.."))
    if root_dir not in sys.path:
        sys.path.insert(0, root_dir)

    # Force cleanup of port 8000 before starting (Linux/WSL2/Termux)
    try:
        if os.name != 'nt':
            os.system("fuser -k 8000/tcp >/dev/null 2>&1 || true")
        else:
            # Windows alternative
            os.system("FOR /F \"tokens=5\" %P IN ('netstat -aon ^| findstr :8000') DO taskkill /F /PID %P >nul 2>&1")
    except:
        pass

    logger.info(f"Starting {PROJECT_NAME}...")
    uvicorn.run(
        "nx_platform.v4.main:app",
        host="0.0.0.0",
        port=8000,
        reload=False, # Matikan reload untuk mencegah restart saat scan menulis file
        workers=1,
        log_level="info"
    )
