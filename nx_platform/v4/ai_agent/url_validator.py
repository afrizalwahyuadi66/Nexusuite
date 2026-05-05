"""
URL Validator - Filters URLs to only include valid 200 OK responses
Detects "fake 200" - pages that return 200 but contain 404 content
"""
import asyncio
import aiohttp
import re
import os
import sys
from typing import List, Dict, Any, Set, Tuple

# Add root to path
root_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if root_dir not in sys.path:
    sys.path.insert(0, root_dir)

from nx_platform.v4.core.config import logger


class URLValidator:
    """
    Validates URLs to ensure they return actual 200 OK content
    Detects "fake 200" - pages that return 200 status but display 404 content
    """
    
    def __init__(self, target: str):
        self.target = target
        self.session: aiohttp.ClientSession = None
        
        # Fake 200 detection patterns
        self.fake_200_patterns = [
            r"404\s*not\s*found",
            r"404\s*error",
            r"page\s*not\s*found",
            r"the\s*page\s*you\s*requested",
            r"could\s*not\s*find",
            r"does\s*not\s*exist",
            r"not\s*found\s*-\s*404",
            r"error\s*404",
            r"oops!\s*page\s*not\s*found",
            r"missing\s*page",
            r"invalid\s*url",
            r"this\s*page\s*doesn't\s*exist",
            r"content\s*not\s*found",
            r"deleted\s*or\s*moved",
            r"page\s*removed",
        ]
        
        self.compiled_patterns = [re.compile(p, re.I) for p in self.fake_200_patterns]
    
    async def __aenter__(self):
        self.session = aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=15),
            headers={
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
            }
        )
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self.session:
            await self.session.close()
    
    async def validate_single_url(self, url: str) -> Tuple[bool, Dict[str, Any]]:
        """
        Validate single URL - check status code and fake 200 detection
        
        Returns: (is_valid, info_dict)
        """
        info = {"url": url, "status": None, "is_valid": False, "reason": "", "content_length": 0, "is_fake_200": False}
        
        try:
            async with self.session.get(url, allow_redirects=True) as resp:
                info["status"] = resp.status
                info["content_length"] = resp.headers.get("Content-Length", 0)
                
                # Check if status is 200
                if resp.status != 200:
                    info["reason"] = f"Status {resp.status} (not 200)"
                    return False, info
                
                # Get content to check for fake 200
                content = await resp.text()
                content_lower = content.lower()
                
                # Check content length - very small content might be error page
                if len(content) < 500:
                    # Check for 404 patterns in small content
                    if self._is_fake_200(content_lower):
                        info["is_fake_200"] = True
                        info["reason"] = "Fake 200 - contains 404 content (small)"
                        return False, info
                
                # Check for fake 200 patterns in content
                if self._is_fake_200(content_lower):
                    # Check if it's actually a legitimate small page
                    # or a 404 page disguised as 200
                    if len(content) < 5000:  # Likely a fake 200 if small
                        info["is_fake_200"] = True
                        info["reason"] = "Fake 200 - contains 404 content"
                        return False, info
                    else:
                        # Large content might be legitimate, but still check for obvious 404
                        title_match = re.search(r'<title>([^<]+)</title>', content, re.I)
                        if title_match and '404' in title_match.group(1).lower():
                            info["is_fake_200"] = True
                            info["reason"] = f"Fake 200 - title contains '404': {title_match.group(1)}"
                            return False, info
                
                # Also check for redirect chains that might indicate 404
                if resp.history:
                    final_url = str(resp.url)
                    if "404" in final_url or "not-found" in final_url or "error" in final_url:
                        info["is_fake_200"] = True
                        info["reason"] = "Redirected to 404 URL"
                        return False, info
                
                # URL is valid
                info["is_valid"] = True
                info["reason"] = "Valid 200 OK"
                return True, info
                
        except asyncio.TimeoutError:
            info["reason"] = "Timeout"
            return False, info
        except aiohttp.ClientError as e:
            info["reason"] = f"Connection error: {str(e)[:50]}"
            return False, info
        except Exception as e:
            info["reason"] = f"Error: {str(e)[:50]}"
            return False, info
    
    def _is_fake_200(self, content: str) -> bool:
        """Check if content contains 404/fake-200 patterns"""
        for pattern in self.compiled_patterns:
            if pattern.search(content):
                return True
        return False
    
    async def validate_urls_batch(self, urls: List[str], max_concurrent: int = 10) -> Dict[str, List[Dict]]:
        """
        Validate multiple URLs concurrently with rate limiting
        
        Returns: {
            "valid": [url1, url2, ...],
            "fake_200": [url3, url4, ...],
            "other": [url5, url6, ...]
        }
        """
        logger.info(f"[URL Validator] Validating {len(urls)} URLs...")
        
        valid_urls = []
        fake_200_urls = []
        other_urls = []
        
        # Create semaphore for rate limiting
        semaphore = asyncio.Semaphore(max_concurrent)
        
        async def validate_with_semaphore(url):
            async with semaphore:
                is_valid, info = await self.validate_single_url(url)
                return url, is_valid, info
        
        # Run all validations concurrently
        tasks = [validate_with_semaphore(url) for url in urls]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        valid_count = 0
        fake_200_count = 0
        other_count = 0
        
        for result in results:
            if isinstance(result, Exception):
                other_count += 1
                continue
                
            url, is_valid, info = result
            
            if info["is_valid"]:
                valid_urls.append(url)
                valid_count += 1
            elif info["is_fake_200"]:
                fake_200_urls.append({"url": url, "reason": info["reason"]})
                fake_200_count += 1
            else:
                other_urls.append({"url": url, "reason": info["reason"]})
                other_count += 1
        
        # Log summary
        logger.info(f"[URL Validator] Results:")
        logger.info(f"  - Valid (200 OK): {valid_count}")
        logger.info(f"  - Fake 200 (200 but 404 content): {fake_200_count}")
        logger.info(f"  - Other (not 200, error, timeout): {other_count}")
        
        if fake_200_count > 0:
            logger.info(f"[URL Validator] Fake 200 URLs detected:")
            for item in fake_200_urls[:5]:
                logger.info(f"    - {item['url']}: {item['reason']}")
            if fake_200_count > 5:
                logger.info(f"    ... and {fake_200_count - 5} more")
        
        return {
            "valid": valid_urls,
            "fake_200": fake_200_urls,
            "other": other_urls,
            "valid_count": valid_count,
            "fake_200_count": fake_200_count,
            "other_count": other_count
        }


async def validate_all_urls(target: str, all_urls: List[str], max_concurrent: int = 10) -> Dict[str, Any]:
    """
    Main entry point for URL validation
    """
    async with URLValidator(target) as validator:
        return await validator.validate_urls_batch(all_urls, max_concurrent)


# Utility function to add to classified URLs
def add_url_status_to_classification(classified_urls: Dict[str, List[Dict]], validation_result: Dict) -> Dict[str, List[Dict]]:
    """
    Add validation info to classified URLs
    
    Adds:
    - "is_valid_200": bool
    - "status": int or None
    - "validation_reason": str
    """
    valid_urls_set = set(validation_result["valid"])
    fake_200_urls_dict = {item["url"]: item["reason"] for item in validation_result["fake_200"]}
    other_urls_dict = {item["url"]: item["reason"] for item in validation_result["other"]}
    
    for category, url_list in classified_urls.items():
        for item in url_list:
            url = item["url"]
            if url in valid_urls_set:
                item["is_valid_200"] = True
                item["validation_reason"] = "Valid 200 OK"
            elif url in fake_200_urls_dict:
                item["is_valid_200"] = False
                item["is_fake_200"] = True
                item["validation_reason"] = fake_200_urls_dict[url]
            elif url in other_urls_dict:
                item["is_valid_200"] = False
                item["is_fake_200"] = False
                item["validation_reason"] = other_urls_dict[url]
            else:
                # URL not validated (shouldn't happen)
                item["is_valid_200"] = None
                item["validation_reason"] = "Not validated"
    
    return classified_urls