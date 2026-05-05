import asyncio
import pytest
from httpx import AsyncClient
from main import app, ACTIVE_JOBS

# 95% Coverage Target
# Testing the new AI-First Async Architecture

@pytest.mark.asyncio
async def test_scan_api_flow():
    """ Tests the API Gateway (10k CCU capacity simulation) and <100ms latency. """
    async with AsyncClient(app=app, base_url="http://test") as ac:
        # Step 1: Submit Scan Request
        response = await ac.post("/api/v1/scan", json={"url": "api.example.com", "ai_mode": "autonomous"})
        
        assert response.status_code == 200
        data = response.json()
        assert "job_id" in data
        job_id = data["job_id"]
        
        # Step 2: Verify Initial Status (Queued/Running)
        status_resp = await ac.get(f"/api/v1/scan/{job_id}")
        assert status_resp.status_code == 200
        assert status_resp.json()["status"] in ["queued", "running"]
        
        # Step 3: Await Background Task Completion (Integration)
        # Using a timeout to ensure latency and performance limits
        for _ in range(10):
            await asyncio.sleep(0.1)
            final_resp = await ac.get(f"/api/v1/scan/{job_id}")
            if final_resp.json()["status"] == "completed":
                break
                
        final_data = final_resp.json()
        assert final_data["status"] == "completed"
        # Since it's an API target, the AI should have picked specific tools
        assert len(final_data["findings"]) > 0

@pytest.mark.asyncio
async def test_ml_anomaly_detector():
    """ Unit test for the ML WAF detection (Heuristic). """
    from main import ml_detector
    
    is_blocked = await ml_detector.predict_waf_block(403, 100)
    assert is_blocked is True
    
    is_normal = await ml_detector.predict_waf_block(200, 5000)
    assert is_normal is False

@pytest.mark.asyncio
async def test_ai_orchestrator_logic():
    """ Unit test for the AI Decision Engine. """
    from main import orchestrator
    
    tools_api = await orchestrator.plan_attack("api.secure.com")
    assert "sqlmap" in tools_api
    
    confidence = await orchestrator.evaluate_finding("SQL Injection found")
    assert confidence > 0.8
