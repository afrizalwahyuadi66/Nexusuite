"""
Execution Engine - Performs actual attack testing with feedback loop
"""
import asyncio
import aiohttp
import os
import sys
import re
import hashlib
from typing import List, Dict, Any, Optional
from urllib.parse import urljoin, urlparse

# Add root to path
root_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if root_dir not in sys.path:
    sys.path.insert(0, root_dir)

from nx_platform.v4.core.config import logger


class ExecutionEngine:
    """
    Autonomous execution engine that tests vulnerabilities with feedback loop
    """
    
    def __init__(self, target: str, job_id: str = None):
        self.target = target
        self.job_id = job_id or "unknown"
        self.session: Optional[aiohttp.ClientSession] = None
        self.findings: List[Dict[str, Any]] = []
        
    async def __aenter__(self):
        self.session = aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=30),
            headers={
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
            }
        )
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self.session:
            await self.session.close()
    
    # =========================================================================
    # UPLOAD VULNERABILITY TESTING
    # =========================================================================
    
    async def test_upload_endpoint(self, endpoint_url: str, payloads: List[Dict]) -> Optional[Dict]:
        """
        Test upload endpoint with multiple payloads
        Returns: Finding dict if vulnerable, None if not
        """
        logger.info(f"[Upload Test] Testing: {endpoint_url}")
        
        # First check if URL is valid (not 404 or fake 200)
        # We'll handle this at classification level, but add safety check here
        if "/404" in endpoint_url.lower() or "/error" in endpoint_url.lower():
            logger.warning(f"[Upload Test] Skipping likely 404 endpoint: {endpoint_url}")
            return None
        
        # First, analyze the upload form
        form_info = await self._analyze_upload_form(endpoint_url)
        
        if not form_info:
            logger.warning(f"[Upload Test] Could not analyze form at {endpoint_url}")
        
        # Try each payload
        for payload in payloads:
            logger.info(f"[Upload Test] Trying: {payload.get('description', payload['type'])}")
            
            result = await self._try_upload_payload(endpoint_url, payload, form_info)
            
            if result.get("vulnerable"):
                logger.info(f"[Upload Test] ✓ VULNERABLE: {result['description']}")
                return result
            
            # Small delay between attempts
            await asyncio.sleep(0.5)
        
        logger.info(f"[Upload Test] No upload vulnerability found for {endpoint_url}")
        return None
    
    async def _analyze_upload_form(self, url: str) -> Optional[Dict]:
        """Analyze the upload form to understand expected inputs"""
        try:
            async with self.session.get(url) as resp:
                html = await resp.text()
                
                # Parse form to find upload-related inputs
                form_info = {
                    "url": url,
                    "method": "POST",
                    "action": None,
                    "enctype": "multipart/form-data",
                    "input_names": []
                }
                
                # Find form action
                form_match = re.search(r'<form[^>]*action=["\']([^"\']+)["\']', html, re.I)
                if form_match:
                    form_info["action"] = form_match.group(1)
                
                # Find enctype
                enctype_match = re.search(r'enctype=["\']([^"\']+)["\']', html, re.I)
                if enctype_match:
                    form_info["enctype"] = enctype_match.group(1)
                
                # Find file inputs
                file_inputs = re.findall(r'<input[^>]*type=["\']file["\'][^>]*name=["\']([^"\']+)["\']', html, re.I)
                form_info["input_names"] = file_inputs or ["file", "upload", "attachment"]
                
                # Find other relevant inputs
                other_inputs = re.findall(r'<input[^>]*name=["\']([^"\']+)["\']', html, re.I)
                form_info["other_inputs"] = [i for i in other_inputs if i not in form_info["input_names"]]
                
                return form_info
                
        except Exception as e:
            logger.debug(f"[Upload Test] Form analysis failed: {e}")
            return None
    
    async def _try_upload_payload(self, url: str, payload: Dict, form_info: Dict) -> Dict:
        """Try a single upload payload"""
        try:
            # Determine upload URL
            upload_url = url
            if form_info.get("action"):
                if form_info["action"].startswith("http"):
                    upload_url = form_info["action"]
                else:
                    upload_url = urljoin(url, form_info["action"])
            
            # Prepare form data
            form_data = aiohttp.FormData()
            
            # Add other form fields if present
            for field in form_info.get("other_inputs", []):
                form_data.add_field(field, "test")
            
            # Add the file
            file_content = payload.get("content", b"test")
            if isinstance(file_content, str):
                file_content = file_content.encode()
            
            input_name = form_info.get("input_names", ["file"])[0]
            form_data.add_field(
                input_name,
                file_content,
                filename=payload.get("filename", "test.txt"),
                content_type=payload.get("content_type", "text/plain")
            )
            
            # Send request
            async with self.session.post(upload_url, data=form_data) as resp:
                response_text = await resp.text()
                response_lower = response_text.lower()
                
                # Check for success indicators
                success_indicators = [
                    "uploaded", "saved", "success", "stored",
                    "path:", "/uploads/", "file/", "filename"
                ]
                
                # Check for PHP code execution indicators
                exec_indicators = [
                    "system", "passthru", "exec", "shell_exec",
                    "<?php", "root:", "/bin/bash"
                ]
                
                is_vulnerable = False
                vuln_reason = ""
                
                # Check for successful upload with path disclosure
                if any(ind in response_lower for ind in success_indicators):
                    # Look for file path in response
                    path_match = re.search(r'[a-zA-Z]:\\[^\s]+|/[a-zA-Z0-9_/]+\.(php|asp|jsp|html)', response_text)
                    if path_match:
                        is_vulnerable = True
                        vuln_reason = f"File uploaded successfully: {path_match.group()}"
                
                # Check for code execution
                if any(ind in response_text for ind in exec_indicators):
                    is_vulnerable = True
                    vuln_reason = "Code execution detected in response"
                
                # Check status code (some servers return 200 for successful upload even with error)
                if resp.status in [200, 201, 204]:
                    if "error" not in response_lower and "fail" not in response_lower:
                        # Might be successful - check if file was actually saved
                        pass
                
                if is_vulnerable:
                    return {
                        "type": "file_upload",
                        "severity": "critical",
                        "url": url,
                        "upload_url": upload_url,
                        "payload_type": payload.get("type"),
                        "description": vuln_reason,
                        "evidence": response_text[:500],
                        "confidence": 0.9,
                        "vulnerable": True
                    }
        
        except aiohttp.ClientError as e:
            logger.debug(f"[Upload Test] Request failed: {e}")
        except Exception as e:
            logger.debug(f"[Upload Test] Error: {e}")
        
        return {"vulnerable": False}
    
    # =========================================================================
    # 403 BYPASS TESTING
    # =========================================================================
    
    async def test_403_bypass(self, original_url: str, bypass_payloads: List[Dict]) -> Optional[Dict]:
        """
        Test 403 bypass techniques
        Returns: Finding if bypass succeeds, None if not
        """
        logger.info(f"[403 Bypass] Testing: {original_url}")
        
        for bypass in bypass_payloads:
            logger.info(f"[403 Bypass] Trying: {bypass.get('description', bypass['type'])}")
            
            result = await self._try_403_bypass(original_url, bypass)
            
            if result.get("bypassed"):
                logger.info(f"[403 Bypass] ✓ BYPASSED: {result['description']}")
                return result
            
            await asyncio.sleep(0.3)
        
        logger.info(f"[403 Bypass] No bypass found for {original_url}")
        return None
    
    async def _try_403_bypass(self, original_url: str, bypass: Dict) -> Dict:
        """Try a single 403 bypass technique"""
        try:
            url = bypass.get("url", original_url)
            method = bypass.get("method", "GET")
            headers = bypass.get("headers", {})
            
            # Add bypass headers
            request_headers = dict(headers)
            
            async with self.session.request(method, url, headers=request_headers) as resp:
                if resp.status != 403:
                    # Bypass might have worked
                    response_text = await resp.text()
                    
                    if resp.status == 200 and len(response_text) > 100:
                        # Likely a successful bypass
                        return {
                            "type": "403_bypass",
                            "severity": "high",
                            "original_url": original_url,
                            "bypassed_url": url,
                            "method": method,
                            "technique": bypass.get("description", bypass["type"]),
                            "description": f"Bypass successful with {method} method",
                            "status_code": resp.status,
                            "response_length": len(response_text),
                            "confidence": 0.8,
                            "bypassed": True,
                            "evidence": response_text[:500]
                        }
                
        except Exception as e:
            logger.debug(f"[403 Bypass] Error: {e}")
        
        return {"bypassed": False}
    
    async def systematic_curl_audit(self, urls: List[str]) -> List[Dict[str, Any]]:
        """
        [Phase 1] Systematic curl testing against every identified URL path
        Analyzes response HTTP (status, headers, body)
        """
        audit_results = []
        logger.info(f"[Audit] Starting systematic curl audit on {len(urls)} URLs")
        
        for url in urls:
            try:
                start_time = time.time()
                async with self.session.get(url, allow_redirects=False) as resp:
                    duration = time.time() - start_time
                    headers = dict(resp.headers)
                    body = await resp.text()
                    
                    analysis = await self._analyze_raw_response(url, resp.status, headers, body)
                    analysis["duration"] = duration
                    
                    if analysis.get("indicators"):
                        audit_results.append(analysis)
                        logger.info(f"[Audit] Found {len(analysis['indicators'])} indicators on {url}")
                
                # Success criterion: < 30s per endpoint
                if duration > 30:
                    logger.warning(f"[Audit] Slow response from {url}: {duration:.2f}s")
                    
            except Exception as e:
                logger.debug(f"[Audit] Failed to audit {url}: {e}")
            
            await asyncio.sleep(0.1)
            
        return audit_results

    async def _analyze_raw_response(self, url: str, status: int, headers: Dict, body: str) -> Dict[str, Any]:
        """
        Analyze raw HTTP response for vulnerability indicators
        """
        indicators = []
        
        # 1. Check for sensitive headers
        if "Server" in headers:
            indicators.append({"type": "info_disclosure", "detail": f"Server header leaked: {headers['Server']}", "severity": "low"})
        
        # 2. Check for error messages/stack traces
        error_patterns = {
            "sql_error": r"SQL syntax|mysql_fetch_array|ORA-[0-9]{5}|PostgreSQL query failed|SQLite3::query",
            "stack_trace": r"stack trace|at [a-zA-Z0-9._]+\([a-zA-Z0-9._]+:[0-9]+\)|Internal Server Error",
            "path_disclosure": r"[a-zA-Z]:\\[^\s]+|/[a-z0-9_/]+\.php|/[a-z0-9_/]+\.py",
            "sensitive_info": r"AWS_ACCESS_KEY|SECRET_KEY|PASSWORD|PRIVATE KEY"
        }
        
        for name, pattern in error_patterns.items():
            if re.search(pattern, body, re.I):
                indicators.append({"type": name, "detail": f"Found {name} pattern in response body", "severity": "medium"})

        # 3. Identify potential injection points
        parsed = urlparse(url)
        params = parsed.query.split("&") if parsed.query else []
        injection_points = []
        if params:
            for p in params:
                if "=" in p:
                    key = p.split("=")[0]
                    injection_points.append(key)
        
        return {
            "url": url,
            "status": status,
            "headers": headers,
            "body_preview": body[:1000],
            "indicators": indicators,
            "injection_points": injection_points
        }

    # =========================================================================
    # ACTIVE INJECTION TESTING
    # =========================================================================

    async def validate_with_curl(self, curl_command: str) -> Dict[str, Any]:
        """
        [Phase 3] Execute a raw curl command to validate AI findings
        """
        logger.info(f"[Exploit] Executing AI-generated validation: {curl_command[:100]}...")
        
        try:
            # We use subprocess for raw curl commands to ensure header/body accuracy
            import shlex
            import subprocess
            
            # Basic sanitization to prevent command injection on our own system
            if not curl_command.startswith("curl"):
                return {"success": False, "error": "Invalid curl command"}
                
            args = shlex.split(curl_command)
            process = subprocess.run(
                args,
                capture_output=True,
                text=True,
                timeout=15
            )
            
            return {
                "success": process.returncode == 0,
                "status_code": 200, # Simplified
                "body": process.stdout,
                "error": process.stderr,
                "command": curl_command
            }
        except Exception as e:
            return {"success": False, "error": str(e)}

    async def run_active_injection(self, url: str, vuln_type: str, payloads: List[str], methods: List[str] = ["GET", "POST"]) -> Optional[Dict]:
        """
        [Phase 3] Perform active injection testing across multiple HTTP methods
        Supports: GET, POST, PUT, PATCH, DELETE, OPTIONS
        """
        logger.info(f"[Injection] Testing {vuln_type} on {url} with methods {methods}")
        
        parsed = urlparse(url)
        params = {}
        if parsed.query:
            for p in parsed.query.split("&"):
                if "=" in p:
                    k, v = p.split("=", 1)
                    params[k] = v

        # Logic for each method
        for method in methods:
            for payload in payloads:
                # 1. Parameter Injection (URL or Body)
                if params:
                    for param in params.keys():
                        test_params = params.copy()
                        test_params[param] = payload
                        
                        if method == "GET":
                            query_str = "&".join([f"{k}={v}" for k, v in test_params.items()])
                            test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{query_str}"
                            result = await self._test_url_with_payload(test_url, vuln_type, payload, param, method)
                        else:
                            # For POST, PUT, PATCH, DELETE - test both Form and JSON data
                            # Form Data
                            result = await self._test_url_with_payload(url, vuln_type, payload, param, method, data=test_params)
                            if not result:
                                # JSON Data (API style)
                                result = await self._test_url_with_payload(url, vuln_type, payload, param, method, json_data=test_params)
                        
                        if result: return result

                # 2. Path-based Injection (Direct URL manipulation)
                if vuln_type in ["dir_traversal", "lfi", "cmd_injection"]:
                    path_test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}/{payload}"
                    result = await self._test_url_with_payload(path_test_url, vuln_type, payload, "path", method)
                    if result: return result

                # 3. Verb Tampering / OPTIONS discovery
                if method == "OPTIONS":
                    result = await self._test_verb_tampering(url)
                    if result: return result

            await asyncio.sleep(0.05)
        
        return None

    async def _test_url_with_payload(self, test_url: str, vuln_type: str, payload: str, parameter: str, 
                                     method: str, data: Dict = None, json_data: Dict = None) -> Optional[Dict]:
        """Internal helper to send request and analyze for specific vulnerability with multi-method support"""
        try:
            kwargs = {"timeout": 10}
            if data: kwargs["data"] = data
            if json_data: kwargs["json"] = json_data

            async with self.session.request(method, test_url, **kwargs) as resp:
                body = await resp.text()
                status = resp.status
                headers = dict(resp.headers)
                
                is_vulnerable = False
                evidence = ""
                
                # OWASP Top 10 Analysis Logic (Same as before but with better evidence)
                if vuln_type == "sqli":
                    sql_errors = ["sql syntax", "mysql_fetch", "ora-", "sqlite", "postgresql", "dynamic sql"]
                    if any(e in body.lower() for e in sql_errors):
                        is_vulnerable = True
                        evidence = f"SQL error detected via {method} on {parameter}"
                
                elif vuln_type == "xss":
                    if payload in body:
                        is_vulnerable = True
                        evidence = f"XSS payload reflected via {method} in response body"
                
                elif vuln_type == "lfi" or vuln_type == "dir_traversal":
                    file_markers = ["root:x:", "[boot loader]", "win.ini", "etc/passwd", "var/www/html"]
                    if any(m in body for m in file_markers):
                        is_vulnerable = True
                        evidence = f"Sensitive file content leaked via {method} {vuln_type}"
                
                elif vuln_type == "cmd_injection":
                    cmd_markers = ["uid=", "groups=", "drwxr-xr-x", "Volume Serial Number"]
                    if any(m in body for m in cmd_markers):
                        is_vulnerable = True
                        evidence = f"OS command execution output detected via {method}"
                
                elif vuln_type == "auth_bypass":
                    if status == 200 and any(m in body.lower() for m in ["admin", "dashboard", "logout", "profile"]):
                        is_vulnerable = True
                        evidence = f"Potential auth bypass with {method} method"

                if is_vulnerable:
                    return {
                        "type": vuln_type,
                        "url": test_url,
                        "method": method,
                        "parameter": parameter,
                        "payload": payload,
                        "evidence": evidence,
                        "vulnerable": True,
                        "confidence": 0.85,
                        "severity": "critical" if vuln_type in ["sqli", "cmd_injection", "auth_bypass"] else "high"
                    }
        except:
            pass
        return None

    async def run_heavy_tool(self, tool_name: str, url: str, parameter: str = None) -> Optional[Dict]:
        """
        [Phase 5] Execute professional penetration testing tools (SQLmap, Dalfox)
        Automatically builds commands and parses output for VULN confirmation.
        """
        logger.info(f"[HeavyTool] Launching {tool_name} on {url} (param: {parameter})")
        
        import subprocess
        import shlex
        
        cmd = ""
        if tool_name.lower() == "sqlmap":
            # Build SQLmap command with batch and random-agent
            cmd = f"sqlmap -u '{url}' --batch --random-agent --level=1 --risk=1"
            if parameter:
                cmd += f" -p {parameter}"
        
        elif tool_name.lower() == "dalfox":
            # Build Dalfox command for XSS
            cmd = f"dalfox url '{url}' --silence --no-color --skip-mining-dom"
            if parameter:
                cmd += f" -p {parameter}"
        
        if not cmd:
            return None

        try:
            # Execute and capture output
            process = subprocess.run(
                shlex.split(cmd),
                capture_output=True,
                text=True,
                timeout=300 # 5 minutes max for heavy tools
            )
            
            output = process.stdout + process.stderr
            return self._parse_heavy_tool_output(tool_name, url, parameter, output, cmd)
            
        except subprocess.TimeoutExpired:
            logger.warning(f"[HeavyTool] {tool_name} timed out on {url}")
        except Exception as e:
            logger.error(f"[HeavyTool] Error running {tool_name}: {e}")
            
        return None

    def _parse_heavy_tool_output(self, tool: str, url: str, parameter: str, output: str, command: str) -> Optional[Dict]:
        """
        Analyze tool output to confirm VULN vs False Positive
        """
        is_vulnerable = False
        evidence = ""
        severity = "medium"
        
        if tool.lower() == "sqlmap":
            # Indicators that SQLmap confirmed a vulnerability
            if "is vulnerable" in output or "back-end DBMS is" in output or "Payload:" in output:
                is_vulnerable = True
                evidence = "SQLmap confirmed DBMS exploitation"
                severity = "critical"
                
        elif tool.lower() == "dalfox":
            # Indicators that Dalfox found a reflected/stored XSS
            if "POC" in output or "[VULN]" in output:
                is_vulnerable = True
                evidence = "Dalfox confirmed XSS reflection/execution"
                severity = "high"

        if is_vulnerable:
            # Extract POC if possible (simplified)
            poc = "Confirmed via tool output"
            if "Payload:" in output:
                poc = output.split("Payload:")[1].split("\n")[0].strip()
            elif "POC:" in output:
                poc = output.split("POC:")[1].split("\n")[0].strip()

            return {
                "type": f"confirmed_{tool.lower()}",
                "url": url,
                "parameter": parameter,
                "severity": severity,
                "confidence": 1.0, # Tool confirmed
                "evidence": evidence,
                "poc_command": command,
                "description": f"Verified vulnerability found by {tool} on parameter '{parameter}'",
                "raw_output_snippet": output[-500:] # Last 500 chars of output
            }
            
        return None
    async def test_sqli_login(self, login_url: str, payloads: List[str]) -> Optional[Dict]:
        """Upgrade: Test SQL injection on login forms using robust detection"""
        return await self.run_active_injection(login_url, "sqli", payloads)

    async def test_xss(self, url: str, payloads: List[str]) -> Optional[Dict]:
        """Upgrade: Test XSS on URL parameters using robust detection"""
        return await self.run_active_injection(url, "xss", payloads)

    async def test_lfi(self, url: str, payloads: List[str]) -> Optional[Dict]:
        """Upgrade: Test LFI using robust detection"""
        return await self.run_active_injection(url, "lfi", payloads)

    async def test_upload_endpoint(self, url: str, payloads: List[str]) -> Optional[Dict]:
        """Test file upload vulnerability"""
        return await self.run_active_injection(url, "upload", payloads)


# Factory function to run full autonomous test
async def run_autonomous_test(target: str, classified_urls: Dict[str, List[Dict]], job_id: str = None) -> List[Dict]:
    """
    Run autonomous vulnerability testing on all classified URLs
    """
    findings = []
    
    async with ExecutionEngine(target, job_id) as engine:
        # =========================================================================
        # 1. Test upload endpoints
        # =========================================================================
        upload_endpoints = classified_urls.get("upload", [])
        logger.info(f"[Autonomous Test] Testing {len(upload_endpoints)} upload endpoints...")
        for item in upload_endpoints:
            # Skip if not valid 200
            if not item.get("is_valid_200", True):
                continue
                
            from .smart_payload_generator import PayloadGenerator
            gen = PayloadGenerator(target)
            payloads = gen.get_webshell_payloads()
            
            result = await engine.test_upload_endpoint(item["url"], payloads)
            if result:
                findings.append(result)
        
        # =========================================================================
        # 2. Test 403 bypass on sensitive endpoints
        # =========================================================================
        sensitive_endpoints = classified_urls.get("config", []) + classified_urls.get("admin", [])
        logger.info(f"[Autonomous Test] Testing {len(sensitive_endpoints)} sensitive endpoints for 403 bypass...")
        for item in sensitive_endpoints:
            if not item.get("is_valid_200", True):
                continue
                
            from .smart_payload_generator import PayloadGenerator
            gen = PayloadGenerator(target)
            payloads = gen.get_403_bypass_payloads(item["url"])
            
            result = await engine.test_403_bypass(item["url"], payloads)
            if result:
                findings.append(result)
        
        # =========================================================================
        # 3. Test login SQLi
        # =========================================================================
        login_endpoints = classified_urls.get("login", [])
        logger.info(f"[Autonomous Test] Testing {len(login_endpoints)} login endpoints for SQLi...")
        for item in login_endpoints:
            if not item.get("is_valid_200", True):
                continue
                
            from .smart_payload_generator import PayloadGenerator
            gen = PayloadGenerator(target)
            payloads = gen.get_sqli_payloads()
            
            result = await engine.test_sqli_login(item["url"], payloads)
            if result:
                findings.append(result)
        
        # =========================================================================
        # 4. Test user input for XSS/LFI
        # =========================================================================
        user_input_endpoints = classified_urls.get("user_input", [])
        logger.info(f"[Autonomous Test] Testing {len(user_input_endpoints)} user input endpoints for XSS/LFI...")
        for item in user_input_endpoints:
            if not item.get("is_valid_200", True):
                continue
                
            from .smart_payload_generator import PayloadGenerator
            gen = PayloadGenerator(target)
            
            xss_payloads = gen.get_xss_payloads()
            lfi_payloads = gen.get_lfi_payloads()
            
            xss_result = await engine.test_xss(item["url"], xss_payloads)
            if xss_result:
                findings.append(xss_result)
            
            lfi_result = await engine.test_lfi(item["url"], lfi_payloads)
            if lfi_result:
                findings.append(lfi_result)
        
        # =========================================================================
        # 5. ADVANCED: Form Analysis & Testing (CSRF, IDOR, Login SQLi)
        # =========================================================================
        logger.info(f"[Autonomous Test] Running advanced form analysis & testing...")
        
        try:
            # Get all unique URLs for form analysis
            all_urls_for_form = []
            for category, items in classified_urls.items():
                for item in items:
                    if item.get("is_valid_200", True):
                        all_urls_for_form.append(item["url"])
            
            # Limit to reasonable number for form analysis
            all_urls_for_form = all_urls_for_form[:100]
            
            if all_urls_for_form:
                # Import form analyzer
                from .form_analyzer import analyze_forms_for_url
                
                # Analyze forms on top URLs
                form_results = await analyze_forms_for_url(target, all_urls_for_form, max_concurrent=5)
                
                # Import and run CSRF/IDOR tests
                from .csrf_idor_tester import run_all_form_tests
                
                form_vulns = await run_all_form_tests(target, form_results)
                
                for vuln in form_vulns:
                    findings.append(vuln)
                    logger.info(f"[Form Test] ⚠️ {vuln['type'].upper()}: {vuln.get('description', '')[:80]}")
                
                logger.info(f"[Autonomous Test] Form analysis complete. Found {len(form_vulns)} additional vulnerabilities.")
        except ImportError as e:
            logger.warning(f"[Autonomous Test] Form analysis skipped: {e}")
        except Exception as e:
            logger.error(f"[Autonomous Test] Form analysis error: {e}")
    
    return findings