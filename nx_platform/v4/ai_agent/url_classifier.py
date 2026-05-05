"""
URL Classifier - AI analyzes all URLs and categorizes them by vulnerability potential
"""
import asyncio
import re
import os
import sys
from typing import List, Dict, Any, Set, Tuple
from urllib.parse import urlparse, parse_qs

# Add root to path
root_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if root_dir not in sys.path:
    sys.path.insert(0, root_dir)

from nx_platform.v4.core.config import logger

try:
    from ai_rag_tool import rag_assistant
    from ai_config import get_ai_settings
    AI_SETTINGS = get_ai_settings()
    RAG_AVAILABLE = True
except ImportError:
    RAG_AVAILABLE = False
    logger.warning("RAG not available, using heuristic-only classification")

# Import URL Validator
try:
    from .url_validator import validate_all_urls, add_url_status_to_classification
    VALIDATOR_AVAILABLE = True
except ImportError:
    VALIDATOR_AVAILABLE = False
    logger.warning("URL Validator not available, skipping validation")

# Interesting URL patterns
URL_PATTERNS = {
    "upload": [
        r"upload", r"file-upload", r"upload\.php", r"upload\.asp",
        r"upload\.jsp", r"uploadify", r"uploadfile", r"fileupload",
        r"avatar", r"profile-picture", r"attach", r"attachment",
        r"media", r"image-upload", r"document-upload", r"submit"
    ],
    "admin": [
        r"admin", r"administrator", r"manage", r"management",
        r"dashboard", r"cp", r"control", r"backend", r"console",
        r"phpmyadmin", r"wp-admin", r"admin\.php", r"login\.php"
    ],
    "login": [
        r"login", r"signin", r"auth", r"authorize", r"logout",
        r"register", r"signup", r"forgot", r"password", r"reset",
        r"account", r"user", r"profile", r"login"
    ],
    "api": [
        r"/api/", r"/v1/", r"/v2/", r"/rest/", r"/graphql",
        r"/swagger", r"/openapi", r"/json", r"/graphql",
        r"endpoint", r"webservice"
    ],
    "config": [
        r"config", r"configuration", r"settings", r".env",
        r"\.git", r"\.svn", r"\.htaccess", r"\.htpasswd",
        r"database", r"db", r"connection", r"phpinfo",
        r"info\.php", r"test\.php", r"debug"
    ],
    "sensitive": [
        r"backup", r"\.bak", r"\.sql", r"\.zip", r"\.tar",
        r"\.gz", r"old", r"temp", r"tmp", r"cache",
        r"logs", r"\.log", r"secret", r"key", r"token"
    ],
    "path_traversal": [
        r"file", r"download", r"view", r"preview", r"read",
        r"path", r"dir", r"folder", r"page", r"include",
        r"require", r"load", r"src", r"img", r"static"
    ],
    "user_input": [
        r"search", r"query", r"q=", r"s=", r"keyword",
        r"id=", r"uid=", r"user_id", r"article", r"post",
        r"comment", r"cat=", r"catid", r"product", r"item"
    ]
}


class URLClassifier:
    """
    AI-powered URL classifier that analyzes all URLs and categorizes them
    based on their potential vulnerabilities
    """
    
    def __init__(self, target: str):
        self.target = target
        self.classified_urls: Dict[str, List[Dict[str, Any]]] = {
            "upload": [],
            "admin": [],
            "login": [],
            "api": [],
            "config": [],
            "sensitive": [],
            "path_traversal": [],
            "user_input": [],
            "other": []
        }
        self.exploit_db = []
        if RAG_AVAILABLE:
            try:
                self.exploit_db = rag_assistant.load_db()
            except:
                pass
    
    def _extract_url_features(self, url: str) -> Dict[str, Any]:
        """Extract features from URL for classification"""
        features = {
            "url": url,
            "path": "",
            "query_params": {},
            "filename": "",
            "extension": "",
            "has_upload_form": False,
            "has_file_param": False,
            "is_api": False,
            "is_auth_related": False
        }
        
        try:
            parsed = urlparse(url)
            features["path"] = parsed.path
            features["query_params"] = parse_qs(parsed.query)
            
            # Extract filename
            path_parts = parsed.path.rstrip('/').split('/')
            if path_parts:
                features["filename"] = path_parts[-1]
                
                # Extract extension
                if '.' in features["filename"]:
                    parts = features["filename"].rsplit('.', 1)
                    if len(parts) > 1:
                        features["extension"] = parts[1].lower()
            
            # Check for upload form indicators
            url_lower = url.lower()
            features["has_upload_form"] = any(p in url_lower for p in URL_PATTERNS["upload"])
            
            # Check for file param indicators
            file_params = ['file', 'path', 'filename', 'document', 'attachment', 'image', 'img']
            features["has_file_param"] = any(p in url_lower for p in file_params)
            
            # Check if API
            features["is_api"] = '/api/' in url_lower or '/v1/' in url_lower
            
            # Check if auth related
            features["is_auth_related"] = any(p in url_lower for p in URL_PATTERNS["login"])
            
        except Exception as e:
            logger.debug(f"Error parsing URL {url}: {e}")
        
        return features
    
    def _classify_by_pattern(self, url: str) -> List[str]:
        """Classify URL based on pattern matching"""
        url_lower = url.lower()
        categories = []
        
        for category, patterns in URL_PATTERNS.items():
            for pattern in patterns:
                if re.search(pattern, url_lower, re.IGNORECASE):
                    categories.append(category)
                    break
        
        return categories if categories else ["other"]
    
    async def classify_urls(self, urls: List[str], validate_urls: bool = True) -> Dict[str, List[Dict[str, Any]]]:
        """
        Main method: Classify all URLs using AI + Pattern matching
        
        Args:
            urls: List of raw URLs to classify
            validate_urls: If True, validate each URL returns 200 OK (not fake 200)
        """
        logger.info(f"[URL Classifier] Processing {len(urls)} URLs...")
        
        # STEP 1: Validate URLs - filter out 404, fake 200, errors
        if validate_urls and VALIDATOR_AVAILABLE:
            logger.info(f"[URL Classifier] Step 1: Validating URLs (checking 200 status + fake 200 detection)...")
            validation_result = await validate_all_urls(self.target, urls, max_concurrent=10)
            
            # Get only valid 200 URLs
            valid_urls = validation_result["valid"]
            logger.info(f"[URL Classifier] URL validation: {validation_result['valid_count']} valid, {validation_result['fake_200_count']} fake 200, {validation_result['other_count']} other issues")
            
            # Use only valid URLs for classification
            urls_to_classify = valid_urls
        else:
            urls_to_classify = urls
            validation_result = None
        
        if not urls_to_classify:
            logger.warning(f"[URL Classifier] No valid URLs to classify after validation!")
            return self.classified_urls
        
        logger.info(f"[URL Classifier] Step 2: Classifying {len(urls_to_classify)} valid URLs...")
        
        classified_count = 0
        
        for url in urls:
            if not url.startswith('http'):
                url = f"http://{self.target}/{url}" if not url.startswith('/') else f"http://{self.target}{url}"
            
            # Extract features
            features = self._extract_url_features(url)
            
            # Get categories
            categories = self._classify_by_pattern(url)
            
            # Additional AI classification for edge cases
            if RAG_AVAILABLE and self.exploit_db:
                ai_category = await self._ai_classify(url, features)
                if ai_category and ai_category not in categories:
                    categories.append(ai_category)
            
            # Add to appropriate category
            for cat in categories:
                self.classified_urls[cat].append({
                    "url": url,
                    "features": features,
                    "categories": categories
                })
                classified_count += 1
        
        # Log summary
        logger.info(f"[URL Classifier] Classification complete:")
        for cat, urls_list in self.classified_urls.items():
            if urls_list:
                logger.info(f"  - {cat}: {len(urls_list)} URLs")
        
        # Add validation info to classified URLs
        if validation_result and VALIDATOR_AVAILABLE:
            self.classified_urls = add_url_status_to_classification(self.classified_urls, validation_result)
            logger.info(f"[URL Classifier] Validation status added to all classified URLs")
        
        return self.classified_urls
    
    async def _ai_classify(self, url: str, features: Dict[str, Any]) -> str:
        """Use AI for additional classification"""
        if not RAG_AVAILABLE:
            return ""
        
        try:
            context = rag_assistant.retrieve_context(url, self.exploit_db, top_k=1)
            if context:
                # AI suggests this URL is interesting
                return "ai_interesting"
        except:
            pass
        
        return ""
    
    def get_urls_by_category(self, category: str) -> List[Dict[str, Any]]:
        """Get all URLs in a specific category"""
        return self.classified_urls.get(category, [])
    
    def get_all_interesting_urls(self) -> List[Dict[str, Any]]:
        """Get all URLs that are interesting (not 'other')"""
        interesting = []
        for cat, urls in self.classified_urls.items():
            if cat != "other":
                interesting.extend(urls)
        return interesting
    
    def get_upload_endpoints(self) -> List[Dict[str, Any]]:
        """Get all upload endpoints for testing"""
        return self.classified_urls.get("upload", [])
    
    def get_admin_endpoints(self) -> List[Dict[str, Any]]:
        """Get all admin/login endpoints"""
        admin_login = self.classified_urls.get("admin", []) + self.classified_urls.get("login", [])
        return admin_login
    
    def get_403_candidates(self) -> List[Dict[str, Any]]:
        """Get URLs that might need 403 bypass"""
        candidates = []
        
        # URLs that commonly get 403
        sensitive_paths = [
            '/admin', '/administrator', '/phpmyadmin', '/.git',
            '/.env', '/config', '/backup', '/includes'
        ]
        
        for cat_urls in self.classified_urls.values():
            for item in cat_urls:
                url = item['url']
                for path in sensitive_paths:
                    if path in url.lower():
                        candidates.append(item)
                        break
        
        return candidates


async def classify_all_urls(target: str, all_urls: List[str]) -> Dict[str, List[Dict[str, Any]]]:
    """
    Main entry point for URL classification
    """
    classifier = URLClassifier(target)
    return await classifier.classify_urls(all_urls)