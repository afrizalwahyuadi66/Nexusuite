from pydantic import BaseModel, Field
from typing import List, Dict, Any, Optional
import time
from datetime import datetime

class TargetRequest(BaseModel):
    url: str
    scan_speed: str = "aggressive"
    ai_mode: str = "autonomous"
    ai_model: Optional[str] = None
    force_enum: bool = False

import uuid

class AIActivityLog(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime = Field(default_factory=datetime.now)
    activity_type: str  # chat, generate, analyze, exploit
    prompt: str
    response: str
    duration: float
    status: str  # success, failure
    model_used: str
    parameters: Dict[str, Any] = {}
    job_id: Optional[str] = None

    def to_dict(self):
        data = self.model_dump()
        data['timestamp'] = self.timestamp.isoformat()
        return data

class ScanJob:
    def __init__(self, target: str):
        self.id = str(uuid.uuid4())
        self.target = target
        self.status = "queued"
        self.start_time = datetime.now()
        self.end_time: Optional[datetime] = None
        self.findings: List[Dict[str, Any]] = []
        self.logs: List[str] = []  # Baris log untuk visibilitas real-time
        self.ai_activities: List[AIActivityLog] = []
        self.metrics = {
            "total_requests": 0,
            "avg_response_time": 0.0,
            "success_rate": 100.0,
            "tools_used": []
        }
        self._task = None # asyncio.Task
        self._processes = [] # List of active subprocesses

    def to_dict(self, limit_logs: int = 50):
        return {
            "id": self.id,
            "target": self.target,
            "status": self.status,
            "start_time": self.start_time.isoformat(),
            "end_time": self.end_time.isoformat() if self.end_time else None,
            "findings": self.findings,
            "logs": self.logs[-limit_logs:] if self.logs else [],
            "ai_activities": [a.to_dict() for a in self.ai_activities[-10:]],
            "metrics": self.metrics
        }

# In-memory store for jobs (MVP) - Will be migrated to SQLite soon
ACTIVE_JOBS: Dict[str, ScanJob] = {}
# Global AI Activity Log for the dashboard
GLOBAL_AI_LOGS: List[AIActivityLog] = []
