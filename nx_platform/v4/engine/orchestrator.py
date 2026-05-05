import asyncio
import json
import httpx
import os
import sys
from typing import List, Dict, Any
from nx_platform.v4.core.config import logger

# Integrasi dengan AI RAG Tool
try:
    # Menambahkan root ke path jika belum ada
    root_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
    if root_dir not in sys.path:
        sys.path.append(root_dir)
    
    from ai_rag_tool import rag_assistant
    RAG_AVAILABLE = True
    logger.info("AI: RAG Assistant integrated successfully.")
except ImportError as e:
    logger.warning(f"AI: RAG Assistant not found ({e}). Running without local knowledge base.")
    RAG_AVAILABLE = False

class AIOrchestrator:
    """
    Otak Otonom Nexusuite v4. Mengelola pengambilan keputusan menggunakan LLM (Ollama).
    Kini terintegrasi dengan RAG (Retrieval-Augmented Generation) untuk basis pengetahuan lokal.
    """
    def __init__(self):
        # Gunakan environment variables yang diatur oleh nexusuite.sh
        self.model = os.getenv("OLLAMA_MODEL", "deepseek-coder:6.7b")
        self.host = os.getenv("OLLAMA_HOST", "http://localhost:11434")
        self.api_url = f"{self.host.rstrip('/')}/api/generate"
        
        # Load Local Exploit DB via RAG
        self.exploit_db = []
        if RAG_AVAILABLE:
            try:
                self.exploit_db = rag_assistant.load_db()
                logger.info(f"AI: Loaded {len(self.exploit_db)} exploits from local RAG database.")
            except Exception as e:
                logger.error(f"AI: Failed to load RAG DB: {e}")

        self.system_prompt = """You are the Nexusuite Autonomous Architect. 
Your goal is to perform precision offensive security operations.
Analyze the target and return a JSON list of tools to execute.
Tools available: assetfinder, httpx, nuclei, sqlmap, dalfox, ffuf, katana.
Always respond in JSON format: {"tools": ["tool1", "tool2"], "reasoning": "why"}"""

    async def _call_llm(self, prompt: str, context: str = "") -> Dict[str, Any]:
        """Internal helper to communicate with Ollama with RAG context support."""
        try:
            full_prompt = f"{self.system_prompt}\n\n"
            if context:
                full_prompt += f"[LOCAL KNOWLEDGE CONTEXT]\n{context}\n\n"
            full_prompt += f"User Request: {prompt}"

            logger.info(f"AI: Calling LLM ({self.model}) with context...")
            async with httpx.AsyncClient(timeout=60.0) as client:
                response = await client.post(self.api_url, json={
                    "model": self.model,
                    "prompt": full_prompt,
                    "stream": False,
                    "format": "json"
                })
                if response.status_code == 200:
                    res_json = response.json()
                    resp_text = res_json.get('response', '')
                    if not resp_text:
                         return {"error": "Empty response from AI", "score": 0.0}
                    return json.loads(resp_text)
                else:
                    logger.error(f"AI Error: Ollama returned status {response.status_code}")
                    return {"error": f"HTTP {response.status_code}", "score": 0.0}
        except Exception as e:
            logger.error(f"AI Error: {e}")
            return {"error": str(e), "score": 0.0}

    async def plan_attack(self, target: str) -> List[str]:
        """
        Menentukan strategi serangan secara dinamis berdasarkan analisis target dan context RAG.
        """
        context = ""
        if RAG_AVAILABLE and self.exploit_db:
            # Ambil konteks kerentanan yang relevan dari DB lokal (misal: jika target mengandung tech tertentu)
            relevant_ctx = rag_assistant.retrieve_context(target, self.exploit_db, top_k=2)
            if relevant_ctx:
                context = json.dumps(relevant_ctx, indent=2)

        logger.info(f"AI: Menganalisis target {target} untuk perencanaan otonom...")
        plan = await self._call_llm(f"Analyze target {target}. Create an optimal offensive strategy.", context=context)
        logger.info(f"AI Strategy: {plan.get('reasoning')}")
        return plan.get("tools", ["assetfinder", "httpx", "nuclei"])

    async def evaluate_finding(self, finding: str) -> float:
        """
        Mengevaluasi temuan kerentanan untuk menentukan probabilitas eksploitasi menggunakan RAG.
        """
        context = ""
        if RAG_AVAILABLE and self.exploit_db:
            relevant_ctx = rag_assistant.retrieve_context(finding, self.exploit_db, top_k=2)
            if relevant_ctx:
                context = json.dumps(relevant_ctx, indent=2)
        
        prompt = f"Evaluate this finding and return confidence score (0.0 to 1.0): {finding}"
        result = await self._call_llm(prompt, context=context)
        
        # FIX: Check for system error
        if result.get("error"):
            return 0.0
            
        score = result.get("score", result.get("confidence", 0.5))
        try:
            return float(score)
        except (ValueError, TypeError):
            return 0.0

orchestrator = AIOrchestrator()
