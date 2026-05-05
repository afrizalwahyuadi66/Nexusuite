"""
Nexusuite AI Engine - Advanced Autonomous Reasoning
Refactored logic from internal research to provide deep technical analysis,
iterative tool execution, and real-time security intelligence.
"""
import asyncio
import json
import os
import re
import time
from typing import Dict, List, Optional, Any, Tuple
from urllib.parse import urlparse

import aiohttp
from nx_platform.v4.core.config import logger
from nx_platform.v4.core.ai_config import get_config
from nx_platform.v4.core.registry import ToolRegistry
from nx_platform.v4.api.models import AIActivityLog, GLOBAL_AI_LOGS, ACTIVE_JOBS
from nx_platform.v4.core.storage import save_ai_activity, save_structured_vulnerability, save_structured_fix, save_structured_exploit

# Constants for Reasoning Loop
MAX_REASONING_LOOPS = 10
MAX_TOKENS = 8192

NX_SYSTEM_PROMPT = """You are the Nexusuite Advanced AI Engine (NX-AI), the primary offensive intelligence of the Nexusuite Platform.
You operate as an autonomous security architect with deep technical expertise in web application security, network penetration testing, and vulnerability research.

Your objective is to follow the Nexusuite Standard Offensive Pipeline:
1. RECON: Discover assets, technologies, and subdomains.
2. VULN ANALYSIS: Analyze ports, services, and headers for known vulnerabilities.
3. EXPLOITING: Attempt controlled exploitation of identified weaknesses.
4. PAYLOAD CREATION: Craft custom payloads (SQLi, XSS, SSRF, etc.) based on specific target context.
5. PROOF TESTING: Execute the payload and verify the outcome with technical evidence.
6. REPORTING: Document verified findings with remediation steps.

### 🛠 Tool Execution
To execute a tool or search, you MUST use the following tags:
- [TOOL: <command>] : Runs a security tool (e.g., nmap, assetfinder, nuclei, sqlmap, ffuf, paramspider).
- [SEARCH: <query>] : Gathers intelligence from the web (CVE details, PoCs, documentation).

### 📋 Reporting Standards
You MUST report verified findings using these exact formats:

**Vulnerability Format:**
VULN: <vulnerability_name> | SEVERITY: <critical/high/medium/low> | PORT: <port> | SERVICE: <service>
DESC: <detailed technical description including potential impact>
FIX: <concrete, step-by-step remediation advice>

**Exploit/PoC Format:**
EXPLOIT: <exploit_name> | TOOL: <tool_name> | PAYLOAD: <exact_payload_or_description>
RESULT: <technical_outcome_and_evidence>
NOTES: <analysis of why the exploit worked and its implications>

**Final Assessment:**
RISK_LEVEL: <CRITICAL/HIGH/MEDIUM/LOW>
SUMMARY: <comprehensive summary of the target security posture following the pipeline stages>

### 🛡 Rules of Engagement
1. **Precision**: Follow the pipeline stages sequentially. Do not jump to exploitation without proper recon and analysis.
2. **Evidence**: Every "VULN" or "EXPLOIT" entry must be backed by tool output or technical reasoning.
3. **Accuracy**: Distinguish between potential issues and verified proofs.
"""

async def call_nx_ollama(messages: List[Dict], activity_type: str = "nx_reasoning", job_id: str = None) -> str:
    """Async communication with Ollama backend."""
    config = get_config()
    url = f"{config['host']}/api/chat"
    start_time = time.time()
    
    payload = {
        "model": config["model"],
        "messages": messages,
        "stream": False,
        "options": {
            "temperature": 0.3,
            "top_p": 0.9,
            "num_predict": MAX_TOKENS
        }
    }
    
    response_text = ""
    status = "failure"
    
    try:
        timeout = aiohttp.ClientTimeout(total=600)
        async with aiohttp.ClientSession(timeout=timeout) as session:
            async with session.post(url, json=payload) as resp:
                if resp.status == 200:
                    result = await resp.json()
                    response_text = result.get("message", {}).get("content", "").strip()
                    status = "success"
                else:
                    response_text = f"Error: HTTP {resp.status}"
    except Exception as e:
        response_text = f"Error: {str(e)}"
    
    duration = (time.time() - start_time) * 1000
    
    # Log to Nexusuite Activity System
    activity = AIActivityLog(
        activity_type=activity_type,
        prompt=messages[-1]["content"][:1000], # Truncate for log
        response=response_text,
        duration=duration,
        status=status,
        model_used=config["model"],
        job_id=job_id,
        parameters={"history_depth": len(messages)}
    )
    
    if job_id and job_id in ACTIVE_JOBS:
        ACTIVE_JOBS[job_id].ai_activities.append(activity)
        
    GLOBAL_AI_LOGS.append(activity)
    save_ai_activity(activity.model_dump())
    
    return response_text

async def nx_summarize_data(data: str, job_id: str = None) -> str:
    """Intelligent summarization of large tool outputs to optimize LLM context."""
    if len(data) < 1000:
        return data
        
    prompt = [
        {"role": "system", "content": "You are the Nexusuite Data Processor. Summarize the following security tool output. Extract only actionable items, vulnerabilities, interesting paths, or unique versions. Limit to 20 concise points. NO MARKDOWN."},
        {"role": "user", "content": f"Data to process:\n{data[:10000]}"}
    ]
    
    summary = await call_nx_ollama(prompt, activity_type="nx_data_summary", job_id=job_id)
    return summary if "Error" not in summary else data[:2500]

async def nx_web_search(query: str, job_id: str = None) -> str:
    """Real-time web intelligence gathering."""
    try:
        from ai_rag_tool.rag_assistant import web_search
        loop = asyncio.get_event_loop()
        results = await loop.run_in_executor(None, web_search, query, 5)
        return results if results else "[!] No intelligence found for this query."
    except Exception as e:
        return f"[!] Intelligence gathering failed: {str(e)}"

async def nx_execute_tool(command: str, target: str, job_id: str = None) -> str:
    """Safe execution of security tools within the Nexusuite environment."""
    logger.info(f"[NX AI] Processing command: {command}")
    
    parts = command.strip().split()
    if not parts:
        return "[!] Empty command."
        
    tool_name = parts[0].lower().split("/")[-1]
    # Expanded permitted list based on the new standard
    permitted = {
        "nmap", "subfinder", "httpx", "nuclei", "sqlmap", "dalfox", 
        "paramspider", "gau", "katana", "arjun", "nikto", "whatweb", 
        "whois", "dig", "curl", "assetfinder", "amass", "ffuf", "wapiti", "wafw00f"
    }
    
    if tool_name not in permitted:
        return f"[!] Tool '{tool_name}' is not in the Nexusuite permitted list."
    
    # Check if we should use ToolRegistry for standardized commands
    # If the AI provides just the tool name or a simple command, we can optimize it
    final_cmd = command
    if len(parts) == 2 and parts[1] == target:
        # AI sent something like "nmap target.com", use registry for best flags
        reg_cmd = ToolRegistry.get_command(tool_name, target)
        if reg_cmd:
            final_cmd = reg_cmd
            logger.info(f"[NX AI] Using Registry command: {final_cmd}")
            
    try:
        process = await asyncio.create_subprocess_shell(
            final_cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
        )
        stdout, stderr = await process.communicate()
        raw_output = stdout.decode(errors='ignore') + stderr.decode(errors='ignore')
        
        # Log to active job logs
        if job_id and job_id in ACTIVE_JOBS:
            ACTIVE_JOBS[job_id].logs.append(f"[NX AI] Tool {tool_name} executed.")
            
        return await nx_summarize_data(raw_output, job_id)
    except Exception as e:
        return f"[!] Execution failed: {str(e)}"

class NXAIEngine:
    """Advanced Reasoning Engine for Nexusuite."""
    
    def __init__(self, target: str, job_id: str = None):
        self.target = target
        self.job_id = job_id
        self.context = [{"role": "system", "content": NX_SYSTEM_PROMPT}]
        self.findings = []
        
    async def orchestrate(self, initial_intel: str) -> List[Dict]:
        """The main autonomous reasoning loop."""
        self.context.append({"role": "user", "content": f"Initial target intelligence for {self.target}:\n{initial_intel}"})
        
        for loop_idx in range(MAX_REASONING_LOOPS):
            logger.info(f"[NX AI] Loop {loop_idx + 1}/{MAX_REASONING_LOOPS}")
            
            # Log what we are sending to AI
            last_msg = self.context[-1]["content"]
            if self.job_id and self.job_id in ACTIVE_JOBS:
                ACTIVE_JOBS[self.job_id].logs.append(f"➔ [SENT TO AI] Context size: {len(self.context)} msgs. Last input: {last_msg[:200]}...")

            response = await call_nx_ollama(self.context, job_id=self.job_id)
            self.context.append({"role": "assistant", "content": response})
            
            # Log AI response/thought
            if self.job_id and self.job_id in ACTIVE_JOBS:
                thought_match = re.search(r'SUMMARY:|PLAN:|THOUGHT:', response, re.IGNORECASE)
                summary_preview = response[:250].replace('\n', ' ')
                ACTIVE_JOBS[self.job_id].logs.append(f"🤖 [AI RESPONSE] {summary_preview}...")
            
            # Extract active components from AI response
            tools_to_run = re.findall(r'\[TOOL:\s*(.+?)\]', response)
            searches_to_run = re.findall(r'\[SEARCH:\s*(.+?)\]', response)
            
            if not tools_to_run and not searches_to_run:
                # Loop concludes when AI no longer requests tools/searches
                break
                
            loop_results = ""
            
            # Execute Tools in parallel
            if tools_to_run:
                tasks = [nx_execute_tool(cmd, self.target, self.job_id) for cmd in tools_to_run]
                outputs = await asyncio.gather(*tasks)
                for cmd, out in zip(tools_to_run, outputs):
                    loop_results += f"\n[TOOL OUTPUT: {cmd}]\n{out}\n"
            
            # Execute Searches in parallel
            if searches_to_run:
                tasks = [nx_web_search(q, self.job_id) for q in searches_to_run]
                outputs = await asyncio.gather(*tasks)
                for q, out in zip(searches_to_run, outputs):
                    loop_results += f"\n[SEARCH INTELLIGENCE: {q}]\n{out}\n"
            
            self.context.append({"role": "user", "content": loop_results})
            
        # Post-loop: Extract structured data
        final_text = ""
        for msg in reversed(self.context):
            if msg["role"] == "assistant":
                final_text = msg["content"]
                break
        
        self._parse_and_persist(final_text)
        return self.findings

    def _parse_and_persist(self, text: str):
        """Parse the final AI response into structured Nexusuite database entries."""
        lines = text.splitlines()
        
        # Parse Vulnerabilities & Fixes
        for i, line in enumerate(lines):
            line = line.strip()
            if line.startswith("VULN:"):
                vuln = {"vuln_name": "", "severity": "medium", "port": "", "service": "", "description": "", "fix": ""}
                
                # Parse Header
                parts = line.split("|")
                for p in parts:
                    p = p.strip()
                    if p.startswith("VULN:"): vuln["vuln_name"] = p.replace("VULN:", "").strip()
                    elif p.startswith("SEVERITY:"): vuln["severity"] = p.replace("SEVERITY:", "").strip().lower()
                    elif p.startswith("PORT:"): vuln["port"] = p.replace("PORT:", "").strip()
                    elif p.startswith("SERVICE:"): vuln["service"] = p.replace("SERVICE:", "").strip()
                
                # Look ahead for metadata
                for j in range(i + 1, min(i + 6, len(lines))):
                    next_l = lines[j].strip()
                    if next_l.startswith(("VULN:", "EXPLOIT:", "RISK_LEVEL:")): break
                    if next_l.startswith("DESC:"): vuln["description"] = next_l.replace("DESC:", "").strip()
                    elif next_l.startswith("FIX:"): vuln["fix"] = next_l.replace("FIX:", "").strip()
                
                if vuln["vuln_name"]:
                    v_id = save_structured_vulnerability(self.job_id, vuln)
                    if v_id and vuln["fix"]:
                        save_structured_fix(self.job_id, v_id, vuln["fix"])
                    
                    self.findings.append({
                        "type": vuln["vuln_name"],
                        "severity": vuln["severity"],
                        "description": vuln["description"],
                        "url": self.target, # Default to target if specific URL not parsed
                        "port": vuln["port"],
                        "fix": vuln["fix"],
                        "source": "nx_ai_advanced"
                    })

        # Parse Exploits
        for i, line in enumerate(lines):
            line = line.strip()
            if line.startswith("EXPLOIT:"):
                exp = {"exploit_name": "", "tool_used": "", "payload": "", "result": "", "notes": ""}
                parts = line.split("|")
                for p in parts:
                    p = p.strip()
                    if p.startswith("EXPLOIT:"): exp["exploit_name"] = p.replace("EXPLOIT:", "").strip()
                    elif p.startswith("TOOL:"): exp["tool_used"] = p.replace("TOOL:", "").strip()
                    elif p.startswith("PAYLOAD:"): exp["payload"] = p.replace("PAYLOAD:", "").strip()
                
                for j in range(i + 1, min(i + 6, len(lines))):
                    next_l = lines[j].strip()
                    if next_l.startswith(("VULN:", "EXPLOIT:", "RISK_LEVEL:")): break
                    if next_l.startswith("RESULT:"): exp["result"] = next_l.replace("RESULT:", "").strip()
                    elif next_l.startswith("NOTES:"): exp["notes"] = next_l.replace("NOTES:", "").strip()
                
                if exp["exploit_name"]:
                    save_structured_exploit(self.job_id, exp)

async def run_nx_ai_advanced(target: str, initial_data: str, job_id: str = None) -> List[Dict]:
    """External API to trigger the Nexusuite Advanced AI Engine."""
    engine = NXAIEngine(target, job_id)
    return await engine.orchestrate(initial_data)
