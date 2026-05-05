"""
AI Agent Controller - Integration layer between worker.py and True AI Brain
"""
import asyncio
import os
import sys
from typing import List, Dict

# Add path
root_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if root_dir not in sys.path:
    sys.path.insert(0, root_dir)

from nx_platform.v4.core.config import logger


async def run_true_ai_agent(target: str, all_urls: List[str], job_id: str = None) -> List[Dict]:
    """
    Run the TRUE AI Agent that thinks and decides for itself
    
    This replaces the old programmatic approach with genuine AI decision-making.
    """
    logger.info(f"[AI Agent Controller] 🤖 Starting TRUE AI Agent for {target}")
    logger.info(f"[AI Agent Controller] Processing {len(all_urls)} URLs with AI brain...")
    
    try:
        from .ai_brain import run_ai_agent
        
        # Run the true AI agent
        findings = await run_ai_agent(target, all_urls, job_id)
        
        logger.info(f"[AI Agent Controller] ✅ AI Agent complete. Found {len(findings)} vulnerabilities")
        
        return findings
        
    except ImportError as e:
        logger.error(f"[AI Agent Controller] Import error: {e}")
        return []
    except Exception as e:
        logger.error(f"[AI Agent Controller] Error: {e}")
        return []


async def run_hybrid_approach(target: str, all_urls: List[str], job_id: str = None) -> List[Dict]:
    """
    Hybrid approach: Use both AI Brain for decision making + programmatic tools for execution
    
    This gives best of both worlds:
    - AI decides WHAT to test (smart)
    - Tools execute FAST (efficient)
    """
    logger.info(f"[AI Agent Controller] 🔄 Running Hybrid AI+Tools Approach for {target}")
    
    all_findings = []
    
    try:
        from .ai_brain import AIBrain
        from .execution_engine import ExecutionEngine
        
        async with AIBrain(target, job_id) as brain:
            # 1. OBSERVE - Let AI analyze URLs
            observation = await brain.observe(all_urls[:100])  # AI analyzes first 100
            interesting = observation.get("interesting_urls", [])
            
            logger.info(f"[Hybrid] AI identified {len(interesting)} high-value targets")
            
            # 2. For each interesting URL, let AI decide and tools execute
            async with ExecutionEngine(target, job_id) as engine:
                for url_info in interesting[:20]:  # Limit to 20 for speed
                    url = url_info.get("url")
                    category = url_info.get("category", "unknown")
                    
                    # AI decides what vulnerability to test
                    decision = await brain.think(
                        f"Target URL: {url}\nCategory: {category}\nContext: {url_info.get('reason', '')}\n\n"
                        "What is the most likely vulnerability for this endpoint?"
                    )
                    
                    vuln_type = decision.get("vuln_type", "xss")
                    logger.info(f"[Hybrid] Testing {vuln_type} on {url} (AI decision)")
                    
                    # Instead of AI ACT, we use ExecutionEngine (programmatic)
                    # This is faster and more reliable for known patterns
                    from .smart_payload_generator import PayloadGenerator
                    gen = PayloadGenerator(target)
                    
                    result = None
                    if vuln_type == "sqli":
                        result = await engine.test_sqli_login(url, gen.get_sqli_payloads())
                    elif vuln_type == "xss":
                        result = await engine.test_xss(url, gen.get_xss_payloads())
                    elif vuln_type == "lfi":
                        result = await engine.test_lfi(url, gen.get_lfi_payloads())
                    elif vuln_type == "upload":
                        result = await engine.test_upload_endpoint(url, gen.get_webshell_payloads())
                    elif vuln_type == "403_bypass":
                        result = await engine.test_403_bypass(url, gen.get_403_bypass_payloads(url))
                    
                    if result:
                        all_findings.append(result)
                        # AI learns from success
                        await brain.learn(vuln_type, url, result.get("description", ""), True)
                    
                    await asyncio.sleep(0.2)
        
        # 3. Also run form analysis for CSRF/IDOR (programmatic)
        try:
            from .form_analyzer import analyze_forms_for_url
            from .csrf_idor_tester import run_all_form_tests
            
            # Get valid URLs for form analysis
            form_urls = [u.get("url") for u in interesting if u.get("priority") == "high"]
            
            if form_urls:
                form_results = await analyze_forms_for_url(target, form_urls[:30])
                form_vulns = await run_all_form_tests(target, form_results)
                all_findings.extend(form_vulns)
                
        except Exception as e:
            logger.debug(f"[Hybrid] Form analysis skipped: {e}")
        
        logger.info(f"[Hybrid] Complete. Total findings: {len(all_findings)}")
        return all_findings
        
    except Exception as e:
        logger.error(f"[Hybrid] Error in Hybrid approach: {e}")
        return all_findings


async def run_rag_approach(target: str, all_urls: List[str], job_id: str = None) -> List[Dict]:
    """
    RAG-BASED AGENT: Uses exploit database to find matches and generate payloads
    """
    logger.info(f"[AI Agent Controller] 📚 Running RAG-BASED Agent for {target}")
    
    findings = []
    
    try:
        from ai_rag_tool import rag_assistant
        from .execution_engine import ExecutionEngine
        
        db = rag_assistant.load_db()
        
        if not db:
            logger.warning("[RAG Agent] Exploit database is empty. Fallback to hybrid.")
            return await run_hybrid_approach(target, all_urls, job_id)
            
        async with ExecutionEngine(target, job_id) as engine:
            for url in all_urls[:50]:
                # Extract potential software/version from URL or headers
                # For now, use the URL path as a simple query
                query = urlparse(url).path
                if not query or query == "/": continue
                
                context = rag_assistant.retrieve_context(query, db, top_k=2)
                
                if context:
                    logger.info(f"[RAG Agent] Found match in Exploit-DB for {url}")
                    # AI generates specific payload based on context
                    advice = rag_assistant.generate_payload(url, context)
                    
                    # Log the advice as a potential finding if it contains a payload
                    # FIX: Ensure it's not an error message
                    is_error = "error" in advice.lower() or "gagal" in advice.lower()
                    if not is_error and ("payload" in advice.lower() or "command" in advice.lower()):
                        findings.append({
                            "type": "cve_exploit_match",
                            "url": url,
                            "severity": "high",
                            "confidence": 0.85,
                            "description": f"Match found in Exploit-DB for {query}. AI Advice: {advice[:200]}...",
                            "data": {"advice": advice, "context": context}
                        })
                        
                        # Try to extract and execute payload if possible (advanced)
                        # This part is complex because payloads are unstructured text
        
        return findings
        
    except Exception as e:
        logger.error(f"[RAG Agent] Error: {e}")
        return findings


# Configuration for AI Agent mode
AI_AGENT_MODE = os.getenv("AI_AGENT_MODE", "hybrid")  # "true_ai", "hybrid", "rag_based", "v4_engine", "tools_only"


async def run_ai_agent_main(target: str, all_urls: List[str], job_id: str = None, initial_intel: str = None) -> List[Dict]:
    """
    Main entry point - runs based on AI_AGENT_MODE setting
    """
    mode = AI_AGENT_MODE.lower()
    
    if mode == "true_ai":
        # Pure AI - slower but more intelligent
        logger.info("[AI Agent] Mode: TRUE_AI - AI makes all decisions (OBSERVE -> THINK -> PLAN -> ACT -> LEARN)")
        return await run_true_ai_agent(target, all_urls, job_id)
    
    elif mode == "hybrid":
        # Best of both - AI decides, tools execute
        logger.info("[AI Agent] Mode: HYBRID - AI decides, tools execute")
        return await run_hybrid_approach(target, all_urls, job_id)
    
    elif mode == "rag_based":
        # RAG - Knowledge based
        logger.info("[AI Agent] Mode: RAG_BASED - Exploit-DB knowledge integration")
        return await run_rag_approach(target, all_urls, job_id)
        
    elif mode == "nx_advanced":
        # Nexusuite Advanced Mode - Iterative Tool Loop + Deep Reasoning
        logger.info(f"[AI Agent] Mode: {mode.upper()} - Advanced Reasoning Engine Active")
        try:
            from .nx_ai_engine import run_nx_ai_advanced
            # Use provided intel or combine default context
            intel = initial_intel or f"Target Host: {target}\nDiscovered Endpoints: {len(all_urls)}\nSample Paths: {', '.join(all_urls[:20])}"
            return await run_nx_ai_advanced(target, intel, job_id)
        except Exception as e:
            logger.error(f"[AI Agent] Error in Advanced mode: {e}")
            return []
            
    elif mode == "v4_engine" or mode == "tools_only":
        # Tools only - fast but less intelligent
        logger.info(f"[AI Agent] Mode: {mode.upper()} - Programmatic execution only")
        try:
            from .execution_engine import run_autonomous_test
            from .url_classifier import classify_all_urls
            
            # For V4 Engine, we might want to increase concurrency
            max_urls = 100 if mode == "v4_engine" else 50
            classified = await classify_all_urls(target, all_urls[:max_urls])
            return await run_autonomous_test(target, classified, job_id)
        except Exception as e:
            logger.error(f"[AI Agent] Error in {mode}: {e}")
            return []
    
    else:
        logger.warning(f"[AI Agent] Unknown mode '{mode}'. Falling back to TOOLS_ONLY.")
        try:
            from .execution_engine import run_autonomous_test
            from .url_classifier import classify_all_urls
            classified = await classify_all_urls(target, all_urls[:50])
            return await run_autonomous_test(target, classified, job_id)
        except:
            return []