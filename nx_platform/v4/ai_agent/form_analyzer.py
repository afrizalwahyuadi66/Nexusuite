"""
Form & API Analyzer - Detects POST forms, CSRF, and IDOR opportunities
"""
import asyncio
import aiohttp
import re
import os
import sys
from typing import List, Dict, Any, Optional, Tuple
from urllib.parse import urljoin, urlparse, parse_qs
from bs4 import BeautifulSoup

# Add root to path
root_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if root_dir not in sys.path:
    sys.path.insert(0, root_dir)

from nx_platform.v4.core.config import logger


class FormAnalyzer:
    """
    Analyzes web pages to find forms, their inputs, and potential vulnerabilities
    """
    
    def __init__(self, target: str):
        self.target = target
        self.session: Optional[aiohttp.ClientSession] = None
        
        # CSRF token patterns
        self.csrf_token_patterns = [
            r'name=["\']csrf["\']',
            r'name=["\']_token["\']',
            r'name=["\']token["\']',
            r'name=["\']authenticity_token["\']',
            r'name=["\']__RequestVerificationToken["\']',
            r'id=["\']csrf["\']',
            r'name=["\']xsrf["\']',
            r'name=["\']_csrf["\']',
        ]
        
        # Sensitive input patterns
        self.sensitive_inputs = [
            "password", "passwd", "pwd", "secret", "api_key", "apikey",
            "token", "auth", "key", "private", "credential"
        ]
        
        # IDOR-prone parameter patterns
        self.idor_params = [
            "id", "user_id", "uid", "account_id", "profile_id",
            "order_id", "invoice_id", "transaction_id", "post_id",
            "comment_id", "file_id", "doc_id", "item_id", "product_id",
            "category_id", "group_id", "role_id", "address_id"
        ]
    
    async def __aenter__(self):
        self.session = aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=15),
            headers={
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
            }
        )
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self.session:
            await self.session.close()
    
    async def analyze_page(self, url: str) -> Dict[str, Any]:
        """
        Analyze a page for forms, CSRF vulnerabilities, and IDOR opportunities
        """
        result = {
            "url": url,
            "forms": [],
            "has_csrf": False,
            "csrf_vulnerable": False,
            "api_endpoints": [],
            "idor_candidates": [],
            "login_forms": [],
            "total_forms": 0
        }
        
        try:
            async with self.session.get(url) as resp:
                if resp.status != 200:
                    return result
                
                html = await resp.text()
                soup = BeautifulSoup(html, 'html.parser')
                
                # Find all forms
                forms = soup.find_all('form')
                result["total_forms"] = len(forms)
                
                for form in forms:
                    form_info = self._analyze_form(form, url)
                    result["forms"].append(form_info)
                    
                    # Check if it's a login form
                    if form_info.get("is_login"):
                        result["login_forms"].append(form_info)
                    
                    # Check CSRF protection
                    if not form_info.get("has_csrf_token"):
                        result["csrf_vulnerable"] = True
                
                # Find API-like URLs in the page
                result["api_endpoints"] = self._find_api_endpoints(soup, url)
                
                # Find IDOR candidates in links
                result["idor_candidates"] = self._find_idor_candidates(soup, url)
                
                # Check if page has any CSRF
                result["has_csrf"] = any(f.get("has_csrf_token") for f in result["forms"])
                
                # Add summary
                if result["csrf_vulnerable"]:
                    logger.info(f"[Form Analyzer] ⚠️ CSRF vulnerable form found at: {url}")
                
                if result["login_forms"]:
                    logger.info(f"[Form Analyzer] Login form found: {url}")
                    
        except Exception as e:
            logger.debug(f"[Form Analyzer] Error analyzing {url}: {e}")
        
        return result
    
    def _analyze_form(self, form: BeautifulSoup, base_url: str) -> Dict[str, Any]:
        """Analyze a single form"""
        form_info = {
            "action": form.get("action", ""),
            "method": form.get("method", "get").upper(),
            "inputs": [],
            "has_csrf_token": False,
            "csrf_token_names": [],
            "is_login": False,
            "is_register": False,
            "is_comment": False,
            "is_upload": False,
            "sensitive_inputs": []
        }
        
        # Resolve action URL
        if form_info["action"]:
            form_info["action"] = urljoin(base_url, form_info["action"])
        
        # Analyze inputs
        inputs = form.find_all(['input', 'textarea', 'select'])
        for inp in inputs:
            input_info = self._analyze_input(inp)
            form_info["inputs"].append(input_info)
            
            # Track sensitive inputs
            if input_info.get("is_sensitive"):
                form_info["sensitive_inputs"].append(input_info["name"])
            
            # Check for CSRF tokens
            if input_info.get("is_csrf_token"):
                form_info["has_csrf_token"] = True
                form_info["csrf_token_names"].append(input_info["name"])
        
        # Determine form type based on inputs and action
        form_lower = (form.get("action", "") + " " + str(form)).lower()
        input_names = " ".join([i.get("name", "").lower() for i in form_info["inputs"]])
        
        form_info["is_login"] = any(x in input_names for x in ["user", "login", "email", "password", "pass"])
        form_info["is_register"] = any(x in form_lower for x in ["register", "signup", "create", "join"])
        form_info["is_comment"] = any(x in input_names for x in ["comment", "message", "post", "reply"])
        form_info["is_upload"] = "file" in input_names or form_lower.find("upload") != -1
        
        return form_info
    
    def _analyze_input(self, inp: BeautifulSoup) -> Dict[str, Any]:
        """Analyze a single input field"""
        name = inp.get("name", "")
        input_type = inp.get("type", "text").lower()
        value = inp.get("value", "")
        
        input_info = {
            "name": name,
            "type": input_type,
            "value": value,
            "is_sensitive": False,
            "is_csrf_token": False,
            "is_required": inp.get("required") is not None
        }
        
        # Check if sensitive
        name_lower = name.lower()
        if any(s in name_lower for s in self.sensitive_inputs):
            input_info["is_sensitive"] = True
        
        # Check if CSRF token
        for pattern in self.csrf_token_patterns:
            if re.search(pattern, f'name="{name}"', re.I):
                input_info["is_csrf_token"] = True
                break
        
        return input_info
    
    def _find_api_endpoints(self, soup: BeautifulSoup, base_url: str) -> List[Dict[str, Any]]:
        """Find API-like URLs and endpoints in the page"""
        api_endpoints = []
        
        # Find script tags that might contain API URLs
        scripts = soup.find_all('script')
        for script in scripts:
            if script.get("src"):
                src = script.get("src")
                if "/api/" in src or "/v1/" in src or "/v2/" in src:
                    api_endpoints.append({
                        "type": "script",
                        "url": src,
                        "base": base_url
                    })
        
        # Find links that look like API endpoints
        links = soup.find_all('a', href=True)
        for link in links:
            href = link.get("href", "")
            if any(p in href.lower() for p in ["/api/", "/v1/", "/v2/", "/rest/", "/graphql"]):
                api_endpoints.append({
                    "type": "link",
                    "url": urljoin(base_url, href),
                    "text": link.get_text()[:50]
                })
        
        # Find fetch/XHR calls in inline scripts
        for script in soup.find_all('script'):
            script_text = script.string or ""
            # Look for fetch/axios calls
            fetch_patterns = [
                r'fetch\s*\(\s*["\']([^"\']+)["\']',
                r'axios\.(get|post|put|delete)\s*\(\s*["\']([^"\']+)["\']',
                r'\.ajax\s*\(\s*{[^}]*url:\s*["\']([^"\']+)["\']'
            ]
            for pattern in fetch_patterns:
                matches = re.findall(pattern, script_text, re.I)
                for match in matches:
                    api_url = match[0] if isinstance(match, tuple) else match
                    if api_url.startswith("http"):
                        api_endpoints.append({
                            "type": "xhr",
                            "url": api_url,
                            "base": base_url
                        })
        
        return api_endpoints
    
    def _find_idor_candidates(self, soup: BeautifulSoup, base_url: str) -> List[Dict[str, Any]]:
        """Find URLs that might have IDOR vulnerabilities"""
        idor_candidates = []
        
        links = soup.find_all('a', href=True)
        seen_params = set()
        
        for link in links:
            href = link.get("href", "")
            full_url = urljoin(base_url, href)
            
            # Parse URL to check for IDOR-prone parameters
            try:
                parsed = urlparse(full_url)
                params = parse_qs(parsed.query)
                
                for param_name, param_values in params.items():
                    # Check if parameter is IDOR-prone
                    param_lower = param_name.lower()
                    if any(idor_param in param_lower for idor_param in self.idor_params):
                        # Create unique key to avoid duplicates
                        key = f"{parsed.path}:{param_name}"
                        if key not in seen_params:
                            seen_params.add(key)
                            idor_candidates.append({
                                "url": full_url,
                                "path": parsed.path,
                                "param": param_name,
                                "example_value": param_values[0] if param_values else "",
                                "link_text": link.get_text()[:50]
                            })
            except:
                continue
        
        return idor_candidates


async def analyze_forms_for_url(target: str, urls: List[str], max_concurrent: int = 5) -> List[Dict]:
    """
    Analyze multiple URLs for forms, CSRF, and IDOR
    """
    results = []
    semaphore = asyncio.Semaphore(max_concurrent)
    
    async with FormAnalyzer(target) as analyzer:
        async def analyze_with_semaphore(url):
            async with semaphore:
                return await analyzer.analyze_page(url)
        
        tasks = [analyze_with_semaphore(url) for url in urls]
        results = await asyncio.gather(*tasks, return_exceptions=True)
    
    # Filter out exceptions and log findings
    valid_results = []
    csrf_vulns = 0
    login_forms = 0
    idor_candidates = 0
    
    for result in results:
        if isinstance(result, Exception):
            continue
        
        valid_results.append(result)
        
        if result.get("csrf_vulnerable"):
            csrf_vulns += 1
        
        if result.get("login_forms"):
            login_forms += len(result["login_forms"])
        
        if result.get("idor_candidates"):
            idor_candidates += len(result["idor_candidates"])
    
    logger.info(f"[Form Analyzer] Results:")
    logger.info(f"  - CSRF vulnerable forms: {csrf_vulns}")
    logger.info(f"  - Login forms found: {login_forms}")
    logger.info(f"  - IDOR candidates: {idor_candidates}")
    
    return valid_results


def extract_testable_endpoints(form_results: List[Dict]) -> Dict[str, List[Dict]]:
    """
    Extract endpoints that need testing based on form analysis
    """
    endpoints = {
        "csrf_vulnerable_forms": [],
        "login_forms": [],
        "api_endpoints": [],
        "idor_candidates": [],
        "upload_forms": [],
        "comment_forms": []
    }
    
    for result in form_results:
        url = result["url"]
        
        # CSRF vulnerable
        if result.get("csrf_vulnerable"):
            for form in result.get("forms", []):
                if not form.get("has_csrf_token"):
                    endpoints["csrf_vulnerable_forms"].append({
                        "url": url,
                        "form_action": form.get("action"),
                        "method": form.get("method"),
                        "inputs": form.get("inputs", [])
                    })
        
        # Login forms
        for form in result.get("login_forms", []):
            endpoints["login_forms"].append({
                "url": url,
                "form_action": form.get("action"),
                "method": form.get("method"),
                "inputs": form.get("inputs", [])
            })
        
        # API endpoints
        endpoints["api_endpoints"].extend(result.get("api_endpoints", []))
        
        # IDOR candidates
        endpoints["idor_candidates"].extend(result.get("idor_candidates", []))
        
        # Upload forms
        for form in result.get("forms", []):
            if form.get("is_upload"):
                endpoints["upload_forms"].append({
                    "url": url,
                    "form_action": form.get("action")
                })
        
        # Comment/post forms
        for form in result.get("forms", []):
            if form.get("is_comment"):
                endpoints["comment_forms"].append({
                    "url": url,
                    "form_action": form.get("action"),
                    "method": form.get("method")
                })
    
    return endpoints