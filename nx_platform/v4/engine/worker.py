import asyncio
import json
import shlex
import os
import hashlib
import time
import re
from typing import List, Dict, Any, Set
from nx_platform.v4.core.config import logger

def _url_host(target: str) -> str:
    """Extract host:port from a URL-like string, robustly sanitized for filenames."""
    from urllib.parse import urlparse
    try:
        if target.startswith(("http://", "https://")):
            parsed = urlparse(target)
            host = parsed.netloc or parsed.path
        else:
            host = target
        if '@' in host:
            host = host.split('@')[-1]
        import re as _re
        host = _re.sub(r'[^A-Za-z0-9_.:-]', '_', host)
        host = _re.sub(r'_+', '_', host)
        return host
    except Exception:
        return target.replace('://','_').replace('/','_')

def _url_to_slug(target: str) -> str:
    from hashlib import sha1
    if not target:
        return "target"
    try:
        h = sha1(target.encode('utf-8')).hexdigest()[:8]
        if target.startswith(("http://","https://")):
            host = _url_host(target)
            return f"{host}_{h}"
        else:
            return f"{_url_host(target)}_{h}"
    except Exception:
        return "target"

def _record_url_mapping(target_result_dir: str, slug: str, url: str) -> None:
    """Record mapping of slug -> actual URL to aid audit without creating URL-based dirs."""
    try:
        map_file = os.path.join(target_result_dir, "urls_map.txt")
        if not os.path.exists(map_file):
            with open(map_file, 'w', encoding='utf-8') as _:
                pass
        # avoid duplicates: quick check if the slug-url pair already exists
        pair = f"{slug}\t{url}\n"
        exists = False
        if os.path.exists(map_file):
            with open(map_file, 'r', encoding='utf-8') as f:
                for line in f:
                    if line.strip() == pair.strip():
                        exists = True
                        break
        if not exists:
            with open(map_file, 'a', encoding='utf-8') as f:
                f.write(pair)
    except Exception:
        # Non-fatal; mapping is only for audit readability
        pass
from nx_platform.v4.ml.detector import ml_detector
from nx_platform.v4.engine.orchestrator import orchestrator
from nx_platform.v4.api.models import ACTIVE_JOBS
from nx_platform.v4.core.reporting import audit_reporter
from nx_platform.v4.core.registry import ToolRegistry

class ReconManager:
    """Modul Reconnaissance Terpadu (Phase 1 & 2)"""
    def __init__(self, job_id: str, target: str):
        self.job_id = job_id
        self.target = target
        self.cache_dir = "cache/recon"
        self.job_dir = f"results/v4/jobs/{job_id}"
        # Target-safe name untuk direktori audit per-target (robust URL parsing)
        self.target_safe = self._extract_target_safe(self.target)
        logger.debug(f"Recon: target_safe='{self.target_safe}' from target='{self.target}'")
        # Direktori struktur audit per target (untuk audit manual)
        self.target_result_root = os.path.join("result", self.target_safe)
        os.makedirs(self.target_result_root, exist_ok=True)
        # Direktori audit khusus per job untuk target
        self.target_result_dir = os.path.join(self.target_result_root, job_id)
        os.makedirs(self.target_result_dir, exist_ok=True)
        
        # Cek/buat direktori log untuk engine internal
        self.log_dir = os.path.join(self.job_dir, "logs")
        os.makedirs(self.log_dir, exist_ok=True)
        os.makedirs(self.job_dir, exist_ok=True)
        
    async def run_discovery(self) -> Set[str]:
        """Menjalankan multiple discovery tools & merging results."""
        all_hosts = {self.target}
        tools = ["assetfinder"] # Passive fast discovery (subfinder removed from default)
        
        tasks = []
        for tool in tools:
            tasks.append(run_tool_async(
                tool,
                self.target,
                job_id=self.job_id,
                log_dir=self.log_dir,
                result_dir=self.target_result_dir
            ))
            
        results = await asyncio.gather(*tasks)
        for res in results:
            if isinstance(res, dict) and res.get("output"):
                hosts = [line.strip() for line in res["output"].splitlines() if line.strip()]
                all_hosts.update(hosts)
                
        # Deduplication & Optimization
        master_file = os.path.join(self.job_dir, "hosts_master.txt")
        with open(master_file, "w") as f:
            f.write("\n".join(sorted(all_hosts)))
        # Mirror to per-target result directory for auditability
        external_master_path = os.path.join(self.target_result_dir, "hosts_master.txt")
        with open(external_master_path, "w") as f_ext:
            f_ext.write("\n".join(sorted(all_hosts)))
            
        logger.info(f"Recon: Total {len(all_hosts)} unique hosts discovered.")
        return all_hosts

    def extract_parameters(self, crawl_output: str) -> List[str]:
        """Parameter Selection Logic based on sensitivity."""
        # Pattern untuk URL dengan parameter (sensitif terhadap SQLi, XSS, SSRF)
        param_pattern = re.compile(r'https?://[^\s<>"]+?\?[\w\d%]+=[^\s<>"]*')
        sensitive_keywords = ['id=', 'url=', 'file=', 'path=', 'redirect=', 'query=', 'search=']
        
        urls = param_pattern.findall(crawl_output)
        selected = []
        for url in urls:
            if any(key in url.lower() for key in sensitive_keywords):
                selected.append(url)
        
        return list(set(selected))[:50] # Limit to top 50 high-value targets

    def _extract_target_safe(self, url: str) -> str:
        # Robust extraction of host/host:port, sanitized for filesystem paths
        from urllib.parse import urlparse
        try:
            parsed = urlparse(url if url.startswith("http") else f"http://{url}")
            netloc = parsed.netloc or parsed.path
            if '@' in netloc:
                netloc = netloc.split('@')[-1]
            sanitized = re.sub(r'[^A-Za-z0-9_.-]', '_', netloc)
            sanitized = sanitized.replace(":", "_")
            return sanitized
        except Exception:
            return url.replace("https://", "").replace("http://", "").replace("/", "_")

def _select_injectable_php_entries(text: str) -> str:
    """Select PHP endpoints that are potentially injectable (contain a query string).

    Returns a string containing only the found PHP URLs with query parameters. If none
    are found, returns an empty string to signal no injectable endpoints in this chunk.
    """
    if not text:
        return ""
    try:
        # Match URLs that end with .php and contain a ? (query string)
        pattern = re.compile(r"https?://[^\s)\"']+?\.php[^\s)\"']*\?[^\s)\"']*", re.IGNORECASE)
        matches = pattern.findall(text)
        return "\n".join(matches).strip()
    except Exception:
        return ""

async def run_tool_async(tool: str, target: str, job_id: str = None, force: bool = False, custom_args: Dict[str, str] = None, log_dir: str = None, result_dir: str = None) -> Dict[str, Any]:
    """
    Eksekusi tool keamanan dengan optimalisasi data injection menggunakan ToolRegistry.
    """
    # Tentukan path output file secara manual jika tool membutuhkannya
    output_file = None
    if tool in ["katana", "paramspider", "gau", "nikto", "wapiti", "nmap", "arjun"]:
        slug = _url_to_slug(target)
        os.makedirs("Result/v4_logs", exist_ok=True)
        output_file = f"Result/v4_logs/tool_{tool}_{slug}.txt"
        if custom_args is None: custom_args = {}
        custom_args["output"] = output_file
        custom_args["output_file"] = output_file

    cmd_str = ToolRegistry.get_command(tool, target, **(custom_args or {}))
    if not cmd_str:
        err_msg = f"Tool '{tool}' not configured in Registry"
        if job_id and job_id in ACTIVE_JOBS:
            ACTIVE_JOBS[job_id].logs.append(f"[!] {err_msg}")
        return {"tool": tool, "error": err_msg}

    # Caching Logic
    cache_file = os.path.join("cache/recon", f"{tool}_{target.replace('://', '_').replace('/', '_')}.txt")
    if not force and os.path.exists(cache_file):
        file_age = time.time() - os.path.getmtime(cache_file)
        if file_age < 86400:
            with open(cache_file, 'r') as f: return {"tool": tool, "output": f.read(), "cache": True}

    logger.info(f"Worker Exec: {cmd_str}")
    # Prepare log files (internal logs and target-specific result logs)
    internal_log_dir = log_dir or os.path.join("results/v4/jobs", job_id or "tmp", "logs")
    os.makedirs(internal_log_dir, exist_ok=True)
    # Jika ada path untuk per-target results, gunakan itu juga untuk audit
    target_result_dir = result_dir or os.path.join("result", _url_host(target))
    os.makedirs(target_result_dir, exist_ok=True)
    slug = _url_to_slug(target)
    log_path = os.path.join(internal_log_dir, f"{tool}_{slug}.log")
    external_log_path = os.path.join(target_result_dir, f"{tool}_{slug}.log")

    # Open log files
    log_file = open(log_path, 'a', encoding='utf-8')
    external_log_file = open(external_log_path, 'a', encoding='utf-8')

    # Helper to write to both logs and optionally stdout (debug)
    def _emit(line: str):
        line = line.rstrip('\n')
        if line:
            log_file.write(line + '\n')
            log_file.flush()
            external_log_file.write(line + '\n')
            external_log_file.flush()

    try:
        process = await asyncio.create_subprocess_shell(
            cmd_str, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
        )

        # Stream stdout and stderr in real-time
        output_chunks: List[str] = []
        async def _stream(stream, which):
            while True:
                line = await stream.readline()
                if not line:
                    break
                text = line.decode(errors='ignore')
                output_chunks.append(text.rstrip('\n'))
                _emit(text.rstrip('\n'))

        stdout_task = asyncio.create_task(_stream(process.stdout, 'stdout'))
        stderr_task = asyncio.create_task(_stream(process.stderr, 'stderr'))
        await asyncio.gather(stdout_task, stderr_task)
        await process.wait()
        
        # Jika tool menulis ke file, baca file tersebut sebagai output utama
        if output_file and os.path.exists(output_file):
            try:
                with open(output_file, 'r', encoding='utf-8', errors='ignore') as f:
                    output = f.read()
            except Exception as e:
                logger.error(f"Error reading output file {output_file}: {e}")
                output = "\n".join(output_chunks)
        else:
            output = "\n".join(output_chunks)
            
        exit_code = process.returncode
        
        if job_id and job_id in ACTIVE_JOBS:
            job = ACTIVE_JOBS[job_id]
            job.logs.append(f"[+] {tool} executed successfully.")
            
            # Parse tool output for findings and add to job
            findings = parse_tool_output(tool, output, target)
            for f in findings:
                # Check for duplicates
                if f not in job.findings:
                    job.findings.append(f)
                    job.logs.append(f"[!] NEW FINDING: {f.get('type')} - {f.get('evidence', '')[:80]}")
        
        # Flush and close files
        log_file.flush()
        external_log_file.flush()
        # Create a sanitized copy of the log without PHP-endpoints for audit readability
        sanitized_log_path = log_path.replace(".log", ".sanitized.log")
        try:
            with open(log_path, 'r', encoding='utf-8') as lf:
                raw_log = lf.read()
            sanitized = _select_injectable_php_entries(raw_log)
            with open(sanitized_log_path, 'w', encoding='utf-8') as sf:
                sf.write(sanitized)
        except Exception:
            sanitized_log_path = None
        log_file.close()
        external_log_file.close()
        return {"tool": tool, "output": output, "exit_code": exit_code, "log_path": log_path, "external_log_path": external_log_path, "sanitized_log_path": sanitized_log_path, "output_file": output_file}
    except Exception as e:
        log_file.close()
        external_log_file.close()
        return {"tool": tool, "error": str(e)}

from nx_platform.v4.core.storage import save_job
from datetime import datetime

async def autonomous_scan_loop(job_id: str, target: str, force_enum: bool = False, ai_mode: str = None, ai_model: str = None):
    """
    Siklus Hidup V4 Engine Ter-upgrade (Evolution v2):
    RECON -> ANALYSIS -> CRAWL -> INJECTION -> EXPLOIT -> AUDIT -> REPORT
    """
    if job_id not in ACTIVE_JOBS: return
    job = ACTIVE_JOBS[job_id]
    job.status = "running"
    
    # Store settings in job metrics for reporting
    job.metrics["ai_mode_selected"] = ai_mode or "autonomous"
    job.metrics["ai_model_selected"] = ai_model or os.getenv("OLLAMA_MODEL", "deepseek-r1:8b")
    
    save_job(job.to_dict())
    
    recon = ReconManager(job_id, target)
    
    # Set AI Agent Mode and Model for this session/thread
    if ai_mode:
        os.environ["AI_AGENT_MODE"] = ai_mode
    if ai_model:
        os.environ["OLLAMA_MODEL"] = ai_model
    
    try:
        # 1. DEEP DISCOVERY (Passive & Active Recon)
        job.logs.append("[*] Phase 1: Deep Discovery (Subdomain Enumeration)...")
        discovery_tasks = [
            recon.run_discovery(), # assetfinder (subfinder removed)
            run_tool_async("amass", target, job_id=job_id, log_dir=recon.log_dir, result_dir=recon.target_result_dir)
        ]
        discovery_results = await asyncio.gather(*discovery_tasks, return_exceptions=True)
        hosts = discovery_results[0] if not isinstance(discovery_results[0], Exception) else {target}
        
        # 2. INFRASTRUCTURE & SURFACE MAPPING
        job.logs.append("[*] Phase 2: Infrastructure & Surface Mapping (Port Scan & Tech Detect)...")
        master_file = os.path.join(recon.job_dir, "hosts_master.txt")
        mapping_tasks = [
            run_tool_async("wafw00f", target, job_id=job_id, log_dir=recon.log_dir, result_dir=recon.target_result_dir),
            run_tool_async("httpx", target, job_id=job_id, log_dir=recon.log_dir, result_dir=recon.target_result_dir, custom_args={"target_file": master_file}),
            run_tool_async("nmap", target, job_id=job_id, log_dir=recon.log_dir, result_dir=recon.target_result_dir),
            run_tool_async("whatweb", target, job_id=job_id, log_dir=recon.log_dir, result_dir=recon.target_result_dir)
        ]
        mapping_results = await asyncio.gather(*mapping_tasks, return_exceptions=True)
        waf_res = mapping_results[0] if not isinstance(mapping_results[0], Exception) else {}
        httpx_res = mapping_results[1] if not isinstance(mapping_results[1], Exception) else {}

        # 3. INTELLIGENCE GATHERING (Deep Crawl & Parameter Mining)
        job.logs.append("[*] Phase 3: Intelligence Gathering (URL Extraction & Param Mining)...")
        intelligence_tasks = [
            run_tool_async("katana", target, job_id=job_id, log_dir=recon.log_dir, result_dir=recon.target_result_dir),
            run_tool_async("gau", target, job_id=job_id, log_dir=recon.log_dir, result_dir=recon.target_result_dir),
            run_tool_async("paramspider", target, job_id=job_id, log_dir=recon.log_dir, result_dir=recon.target_result_dir)
        ]
        intel_results = await asyncio.gather(*intelligence_tasks, return_exceptions=True)
        
        # Filter results and get outputs safely
        crawl_results = []
        for r in intel_results:
            if isinstance(r, dict):
                if "output" in r:
                    crawl_results.append(r)
                elif "error" in r:
                    job.logs.append(f"[!] Intelligence tool '{r.get('tool')}' failed: {r['error']}")
            elif isinstance(r, Exception):
                job.logs.append(f"[!] Intelligence tool failed with exception: {str(r)}")
        
        # Filter to injectable PHP endpoints
        injectable_outputs = [_select_injectable_php_entries(r.get("output", "")) for r in crawl_results]
        combined_output = "\n".join([io for io in injectable_outputs if io.strip() != ""])
        
        # Record mapping slug -> URL
        injectable_urls: List[str] = []
        for io in injectable_outputs:
            if io:
                for line in io.splitlines():
                    url = line.strip()
                    if url: injectable_urls.append(url)
        
        for url in injectable_urls:
            slug = _url_to_slug(url)
            _record_url_mapping(recon.target_result_dir, slug, url)
            
        if not combined_output.strip():
            combined_output = "\n".join([r.get("output", "") for r in crawl_results])
        
        sensitive_urls = recon.extract_parameters(combined_output)
        
        # 4. VULNERABILITY RESEARCH (Standard Scanning)
        job.logs.append("[*] Phase 4: Vulnerability Research (Standard Scanners & Hidden Params)...")
        vuln_tasks = [
            run_tool_async("nuclei", target, job_id=job_id, log_dir=recon.log_dir, result_dir=recon.target_result_dir),
            run_tool_async("nikto", target, job_id=job_id, log_dir=recon.log_dir, result_dir=recon.target_result_dir)
        ]
        
        if sensitive_urls:
            # Arjun for hidden parameter discovery on top sensitive URLs
            for url in sensitive_urls[:5]:
                vuln_tasks.append(run_tool_async("arjun", url, job_id=job_id, log_dir=recon.log_dir, result_dir=recon.target_result_dir))
        
        await asyncio.gather(*vuln_tasks, return_exceptions=True)

        # 5. TARGETED INJECTION & ADVANCED EXPLOITATION
        job.logs.append("[*] Phase 5: Targeted Injection & Advanced Exploitation...")
        exploit_tasks = []
        # Target main target and sensitive discovered URLs
        exploit_targets = [target] + sensitive_urls[:15]
        
        for url in exploit_targets:
            exploit_tasks.append(run_tool_async("sqlmap", url, job_id=job_id, log_dir=recon.log_dir, result_dir=recon.target_result_dir))
            exploit_tasks.append(run_tool_async("dalfox", url, job_id=job_id, log_dir=recon.log_dir, result_dir=recon.target_result_dir))
        
        # Throttled execution for exploitation (high risk/load)
        for i in range(0, len(exploit_tasks), 4):
            await asyncio.gather(*exploit_tasks[i:i+4], return_exceptions=True)

        # =========================================================================
        # PHASE 3.5: TRUE AI AGENT - OBSERVE & THINK
        # AI Brain analyzes ALL URLs and decides what to test
        # =========================================================================
        job.logs.append("[*] Phase 3.5: 🤖 AI Agent - Observing & Analyzing Target...")
        
        # Get ALL URLs from crawling
        all_crawl_urls = []
        for r in crawl_results:
            if isinstance(r, dict) and r.get("output"):
                for line in r["output"].splitlines():
                    if line.strip().startswith("http"):
                        all_crawl_urls.append(line.strip())
        
        # Also add injectable URLs
        all_crawl_urls.extend(injectable_urls)
        all_crawl_urls = list(set(all_crawl_urls))  # Deduplicate
        
        classified_urls = {}
        
        if all_crawl_urls:
            job.logs.append(f"[Phase 3.5] Found {len(all_crawl_urls)} URLs to analyze")
            
            try:
                import sys as _sys
                v4_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
                if v4_root not in _sys.path:
                    _sys.path.insert(0, v4_root)
                
                from nx_platform.v4.ai_agent import run_ai_agent_main
                
                # Get AI agent mode from environment or default to hybrid
                ai_mode = os.environ.get("AI_AGENT_MODE", "hybrid").lower()
                job.logs.append(f"[Phase 3.5] AI Agent Mode: {ai_mode.upper()}")
                
                # 1. First, validate URLs (quick check)
                job.logs.append("[Phase 3.5] Step 1: Validating URLs (200 status check)...")
                try:
                    from nx_platform.v4.ai_agent import validate_all_urls
                    validation = await validate_all_urls(target, all_crawl_urls[:200], max_concurrent=10)
                    valid_urls = validation.get("valid", [])
                    job.logs.append(f"[Phase 3.5] Valid URLs: {len(valid_urls)}")
                except:
                    valid_urls = all_crawl_urls[:200]  # Fallback
                
                # 2. Run AI Agent based on mode
                if ai_mode in ["true_ai", "hybrid", "rag_based", "nx_advanced"]:
                    job.logs.append(f"[Phase 3.5] Step 2: Running 🤖 {ai_mode.upper()} Agent...")
                    
                    # ENHANCED: Gather more intelligence for the AI
                    initial_intel = f"Target: {target}\n"
                    initial_intel += f"WAF Status: {waf_res.get('output', 'Unknown')[:500]}\n"
                    initial_intel += f"Discovered Hosts: {len(hosts)}\n"
                    initial_intel += f"Valid URLs: {len(valid_urls)}\n"
                    
                    # Add nmap summary if available
                    if 'httpx_res' in locals() and httpx_res.get('output'):
                        initial_intel += f"\nHTTP Service Info:\n{httpx_res['output'][:1000]}\n"
                    
                    # Run the AI Agent with enhanced context
                    ai_findings = await run_ai_agent_main(target, valid_urls, job_id, initial_intel=initial_intel)
                    
                    # Add AI findings
                    for finding in ai_findings:
                        if finding not in job.findings:
                            job.findings.append(finding)
                            vuln_type = finding.get("type", "unknown")
                            url = finding.get("url", "")
                            job.logs.append(f"[Phase 3.5] 🎯 AI FINDING: {vuln_type.upper()} on {url}")
                    
                    job.logs.append(f"[Phase 3.5] AI Agent completed. Found {len(ai_findings)} vulnerabilities")
                else:
                    job.logs.append("[Phase 3.5] AI Thinking skipped (Programmatic Mode active)")
                
                # Also maintain classified_urls for reference in subsequent phases
                try:
                    from nx_platform.v4.ai_agent import classify_all_urls
                    classified_urls = await classify_all_urls(target, valid_urls[:100])
                except:
                    pass
                
            except ImportError as e:
                job.logs.append(f"[Phase 3.5] AI Agent modules not available: {e}")
                job.logs.append("[Phase 3.5] Falling back to basic validation...")
                
                # Fallback: basic classification without AI
                try:
                    from nx_platform.v4.ai_agent import classify_all_urls
                    classified_urls = await classify_all_urls(target, all_crawl_urls[:100], validate_urls=False)
                except:
                    pass
                    
            except Exception as e:
                job.logs.append(f"[Phase 3.5] Error: {str(e)}")
        else:
            job.logs.append("[Phase 3.5] No URLs found for analysis.")
        
        # =========================================================================
        # PHASE 4.5: FORM ANALYSIS & CSRF/IDOR DETECTION
        # AI Agent: Analyze forms, detect CSRF vulnerability, find IDOR candidates
        # =========================================================================
        job.logs.append("[*] Phase 4.5: AI Form Analysis & CSRF/IDOR Detection...")
        
        form_findings = []
        
        try:
            from nx_platform.v4.ai_agent import analyze_forms_for_url, run_all_form_tests
            
            # Get all valid URLs for form analysis
            form_analysis_urls = []
            if classified_urls:
                for category, items in classified_urls.items():
                    for item in items:
                        if item.get("is_valid_200", True):
                            form_analysis_urls.append(item["url"])
            
            # Limit to reasonable number
            form_analysis_urls = list(set(form_analysis_urls))[:100]
            
            if form_analysis_urls:
                job.logs.append(f"[Phase 4.5] Analyzing {len(form_analysis_urls)} pages for forms, CSRF, IDOR...")
                
                # Analyze forms
                form_results = await analyze_forms_for_url(target, form_analysis_urls, max_concurrent=5)
                
                # Log form analysis summary
                csrf_vuln_count = sum(1 for r in form_results if r.get("csrf_vulnerable"))
                login_forms_count = sum(len(r.get("login_forms", [])) for r in form_results)
                idor_candidates_count = sum(len(r.get("idor_candidates", [])) for r in form_results)
                
                job.logs.append(f"[Phase 4.5] Form Analysis Results:")
                job.logs.append(f"  - CSRF vulnerable forms: {csrf_vuln_count}")
                job.logs.append(f"  - Login forms: {login_forms_count}")
                job.logs.append(f"  - IDOR candidates: {idor_candidates_count}")
                
                # Run CSRF & IDOR tests
                job.logs.append("[Phase 4.5] Running CSRF & IDOR vulnerability tests...")
                form_vulns = await run_all_form_tests(target, form_results)
                
                # Add to findings
                for vuln in form_vulns:
                    form_findings.append(vuln)
                    job.findings.append(vuln)
                    job.logs.append(f"[Phase 4.5] ⚠️ FINDING: {vuln['type'].upper()} - {vuln.get('description', '')[:80]}")
                
                job.logs.append(f"[Phase 4.5] Form analysis & testing complete. Found {len(form_vulns)} vulnerabilities.")
            else:
                job.logs.append("[Phase 4.5] No valid URLs for form analysis.")
                
        except ImportError as e:
            job.logs.append(f"[Phase 4.5] Skip - module not available: {e}")
        except Exception as e:
            job.logs.append(f"[Phase 4.5] Error: {str(e)}")

        # =========================================================================
        # COMPREHENSIVE URL ANALYSIS (DISCOVERY -> ANALYSIS -> EXPLOIT -> AWARENESS -> DELIVERABLE)
        # =========================================================================
        job.logs.append("[*] Phase 5.5: Comprehensive URL & API Exposure Analysis...")
        
        try:
            from nx_platform.v4.ai_agent.execution_engine import ExecutionEngine
            from nx_platform.v4.ai_agent.ai_brain import AIBrain
            
            # Phase 1: Discovery (Consolidating all endpoints found in previous steps)
            all_discovered_urls = list(set(all_crawl_urls + [u.get("url") for cat in classified_urls.values() for u in cat]))
            job.logs.append(f"[Discovery] Total unique endpoints to analyze: {len(all_discovered_urls)}")
            
            async with ExecutionEngine(target, job_id) as engine:
                async with AIBrain(target, job_id) as brain:
                    
                    # Phase 2: Systematic Audit & AI Situational Awareness
                    for url in all_discovered_urls[:150]: # Limit for performance
                        # Systematic Curl Audit
                        audit_results = await engine.systematic_curl_audit([url])
                        if not audit_results: continue
                        audit_data = audit_results[0]
                        
                        # AI Deep Analysis & Awareness
                        analysis = await brain.situational_awareness_analysis(audit_data)
                        
                        # Check for critical exposure
                        if analysis.get("risk_score", 0) >= 5 or analysis.get("credentials_detected"):
                            job.logs.append(f"[Awareness] 🎯 {analysis.get('situational_context', {}).get('severity', 'HIGH').upper()} RISK: {url}")
                            
                            # Phase 3: Exploitation / Validation
                            if analysis.get("validation_curl"):
                                validation = await engine.validate_with_curl(analysis["validation_curl"])
                                
                                # 3. Active Injection Testing based on AI Strategy
                                vuln_type = analysis.get("testing_strategy", "xss").split()[0].lower()
                                suggested_methods = analysis.get("situational_context", {}).get("suggested_methods", ["GET", "POST"])
                                
                                payloads = ["'", "<script>alert(1)</script>", "../../../etc/passwd", "id", "admin'--"]
                                
                                injection_result = await engine.run_active_injection(
                                    url, 
                                    vuln_type, 
                                    payloads, 
                                    methods=suggested_methods
                                )
                                
                                if validation.get("success"):
                                    # Phase 4: Interpretation of Validation Result
                                    # Update finding with PoC and technical report
                                    finding = {
                                        "type": "exposed_api_credential" if analysis.get("credentials_detected") else "sensitive_data_exposure",
                                        "url": url,
                                        "severity": analysis["situational_context"]["severity"],
                                        "description": analysis["situational_context"]["behavior_analysis"],
                                        "evidence": validation["body"][:1000],
                                        "poc_curl": analysis["validation_curl"],
                                        "attack_vector": analysis["situational_context"]["attack_vector"],
                                        "impact": analysis["situational_context"]["impact"]
                                    }
                                    
                                    # Phase 5: Deliverable Generation (Detailed Report)
                                    final_report = await brain.generate_vulnerability_report(finding)
                                    
                                    if final_report not in job.findings:
                                        job.findings.append(final_report)
                                        job.logs.append(f"[Deliverable] Verified PoC for {url} added to vault.")

                                # 4.5 Heavy Tool Testing (SQLmap / Dalfox)
                                heavy_tool = analysis.get("situational_context", {}).get("heavy_tool_recommended")
                                if heavy_tool and heavy_tool != "none":
                                    target_param = analysis.get("situational_context", {}).get("target_parameter")
                                    job.logs.append(f"[Phase 5.5] 🚀 AI recommends heavy testing with {heavy_tool.upper()} on '{target_param}'")
                                    
                                    heavy_result = await engine.run_heavy_tool(heavy_tool, url, target_param)
                                    if heavy_result:
                                        # Generate report for heavy finding
                                        heavy_report = await brain.generate_vulnerability_report(heavy_result)
                                        if heavy_report not in job.findings:
                                            job.findings.append(heavy_report)
                                            job.logs.append(f"[Deliverable] 🎯 CONFIRMED {heavy_tool.upper()} VULN on {url}")

            job.logs.append("[Phase 5.5] Comprehensive URL Analysis complete.")
            
        except Exception as e:
            job.logs.append(f"[Phase 5.5] Fatal Error: {str(e)}")

        # 6. AUDITING & SECURITY VALIDATION
        job.logs.append("[*] Phase 6: Auditing findings and validating data integrity...")
        # (Auditing logic remains for SHA-256 and AI validation)
        for finding in job.findings:
            finding["audit_status"] = "validated" if finding.get("sha256") else "unverified"
            finding["confidence"] = await orchestrator.evaluate_finding(str(finding))

        # 7. FINAL REPORTING & STORAGE OPTIMIZATION
        job.status = "completed"
        job.end_time = datetime.now()
        save_job(job.to_dict())
        
        job.logs.append("[*] Phase 7: Generating evolution report & optimizing storage...")
        # ... (Reporting logic)

        report_data = {
            "metadata": {"job_id": job_id, "target": target, "engine": "V4-Evolution"},
            "recon_summary": {"total_hosts": len(hosts), "sensitive_params": len(sensitive_urls)},
            "findings": job.findings,
            "audit_trail": [log for log in job.logs if "[+]" in log or "[!]" in log]
        }
        
        report_path = audit_reporter.generate_report(report_data)
        job.logs.append(f"[SUCCESS] Operation Complete. Laporan: {report_path}")

    except Exception as e:
        logger.error(f"V4 Engine Error: {e}")
        job.status = "failed"
        job.logs.append(f"[!] Error: {str(e)}")

def parse_tool_output(tool: str, output: str, target: str = "") -> List[Dict[str, Any]]:
    """
    Parsing output tool ke dalam format JSON yang seragam untuk AI.
    """
    findings = []
    if not output: return findings
    lines = output.splitlines()

    try:
        if tool == "subfinder":
            # Regex yang lebih ketat untuk validasi subdomain (menghindari banner/logs)
            domain_pattern = re.compile(r'^([a-z0-9]+(-[a-z0-9]+)*\.)+[a-z]{2,}$', re.IGNORECASE)
            for line in lines:
                line = line.strip()
                if domain_pattern.match(line):
                    findings.append({
                        "type": "subdomain", 
                        "url": line, 
                        "evidence": line,
                        "severity": "info"
                    })
        
        elif tool == "nuclei" or tool == "nuclei_exposure":
            for line in lines:
                try:
                    data = json.loads(line)
                    findings.append({
                        "type": data.get("info", {}).get("name") or "nuclei_finding",
                        "severity": data.get("info", {}).get("severity") or "medium",
                        "url": data.get("matched-at") or data.get("host"),
                        "description": data.get("info", {}).get("description"),
                        "evidence": data.get("matched-at")
                    })
                except: continue

        elif tool == "httpx":
            for line in lines:
                if "[200]" in line or "[302]" in line:
                    url_match = re.search(r'https?://[^\s\[]+', line)
                    url = url_match.group(0) if url_match else line.strip()
                    findings.append({
                        "type": "live_host", 
                        "url": url,
                        "evidence": line.strip(),
                        "severity": "info"
                    })

        elif tool == "katana" or tool == "gau" or tool == "paramspider":
            url_pattern = re.compile(r'https?://[^\s\[\]"\'<>]+')
            for line in lines:
                m = url_pattern.search(line)
                if m:
                    url = m.group(0)
                    findings.append({
                        "type": "url", 
                        "url": url,
                        "evidence": line.strip(),
                        "severity": "info"
                    })

        elif tool == "sqlmap":
            if "is vulnerable" in output or "Payload:" in output:
                findings.append({
                    "type": "sqli", 
                    "url": target,
                    "severity": "high",
                    "evidence": "SQL Injection vulnerability detected by sqlmap"
                })

        elif tool == "dalfox":
            if "found" in output.lower():
                findings.append({
                    "type": "xss", 
                    "url": target,
                    "severity": "medium",
                    "evidence": "XSS vulnerability detected by dalfox"
                })

    except Exception as e:
        logger.error(f"Parser Error for {tool}: {e}")

    # CVE enrichment: scan logs for CVE identifiers and attach as findings
    try:
        cve_pattern = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)
        for line in lines:
            m = cve_pattern.search(line)
            if m:
                findings.append({"type": "cve", "evidence": line.strip(), "cve_id": m.group(0)})
    except Exception as _e:
        # Non-fatal; CVE enrichment is best-effort
        logger.debug(f"CVE enrichment failed: {_e}")

    return findings
