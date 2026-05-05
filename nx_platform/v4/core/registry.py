import os
import yaml
from typing import Dict, Any, List
from pathlib import Path
from .config import logger

class ToolRegistry:
    """
    Registry pusat untuk manajemen metadata tool, perintah, dan dependensi.
    Memungkinkan pembangunan perintah dinamis berdasarkan konteks target.
    Mendukung pemuatan plugin dari file YAML secara dinamis.
    """
    
    # Default built-in tools (Standard Nexusuite Set)
    TOOLS = {
        "subfinder": {
            "cmd": "subfinder -d {target} -silent -all -recursive",
            "category": "recon",
            "risk": "low",
            "description": "Passive subdomain enumeration"
        },
        "amass": {
            "cmd": "amass enum -passive -d {target} -silent",
            "category": "recon",
            "risk": "low",
            "description": "In-depth subdomain discovery"
        },
        "assetfinder": {
            "cmd": "assetfinder --subs-only {target}",
            "category": "recon",
            "risk": "low",
            "description": "Find related domains and subdomains"
        },
        "httpx": {
            "cmd": "httpx -u {target} -silent -status-code -title -tech-detect -follow-redirects -x all",
            "category": "recon",
            "risk": "low",
            "description": "Probe for alive hosts & tech stack"
        },
        "wafw00f": {
            "cmd": "wafw00f {target} -a",
            "category": "recon",
            "risk": "low",
            "description": "WAF Fingerprinting"
        },
        "katana": {
            "cmd": "katana -u {target} -silent -jc -kf -d 3 -fs rdn",
            "category": "crawl",
            "risk": "low",
            "description": "Next-generation crawling and spidering"
        },
        "gau": {
            "cmd": "gau {target} --subs --blacklist png,jpg,jpeg,gif,svg,woff,ttf,css",
            "category": "crawl",
            "risk": "low",
            "description": "Fetch historical URLs"
        },
        "paramspider": {
            "cmd": "paramspider -d {target} --level high --silent",
            "category": "crawl",
            "risk": "low",
            "description": "Mining parameters from Web Archives"
        },
        "arjun": {
            "cmd": "arjun -u {target} -t 10 --passive -oJ {output_file}",
            "category": "analysis",
            "risk": "medium",
            "description": "HTTP parameter discovery"
        },
        "nuclei": {
            "cmd": "nuclei -u {target} -severity low,medium,high,critical -silent -jsonl -rl 50",
            "category": "vuln",
            "risk": "medium",
            "description": "Vulnerability scanner"
        },
        "nuclei_exposure": {
            "cmd": "nuclei -u {target} -tags exposure -silent -jsonl",
            "category": "vuln",
            "risk": "low",
            "description": "Scan for sensitive data exposure"
        },
        "sqlmap": {
            "cmd": "sqlmap -u \"{target}\" --batch --random-agent --level 3 --risk 2 --threads 5 --technique=BEUSTQ --dbs",
            "category": "exploit",
            "risk": "high",
            "description": "SQL Injection scanner"
        },
        "dalfox": {
            "cmd": "dalfox url \"{target}\" --silence --mining-dict --skip-mining-all --worker 10",
            "category": "exploit",
            "risk": "medium",
            "description": "Advanced XSS scanner"
        },
        "nikto": {
            "cmd": "nikto -h {target} -Tuning 1,2,3,4,8,9 -maxtime 15m -nointeractive -Format json -o {output_file}",
            "category": "vuln",
            "risk": "medium",
            "description": "Web server vulnerability scanner"
        },
        "wapiti": {
            "cmd": "wapiti -u {target} -m common,xss,sql,exec,file -f json -o {output_file}",
            "category": "vuln",
            "risk": "high",
            "description": "Web vuln injector"
        },
        "nmap": {
            "cmd": "nmap -sV -sC -T4 --script=vuln --open {target} -oX {output_file}",
            "category": "analysis",
            "risk": "medium",
            "description": "Deep network & service scan"
        },
        "ffuf": {
            "cmd": "ffuf -u {target}/FUZZ -w {wordlist} -mc 200,301,302,403 -recursion -recursion-depth 2 -silent",
            "category": "fuzz",
            "risk": "medium",
            "description": "Directory/File fuzzing"
        },
        "whatweb": {
            "cmd": "whatweb -a 3 {target} --color=never",
            "category": "recon",
            "risk": "low",
            "description": "Identify technologies"
        },
        "whois": {
            "cmd": "whois {target}",
            "category": "recon",
            "risk": "low",
            "description": "Domain WHOIS lookup"
        },
        "dig": {
            "cmd": "dig {target} ANY +short",
            "category": "recon",
            "risk": "low",
            "description": "DNS record lookup"
        }
    }

    _initialized = False

    @classmethod
    def _initialize(cls):
        if cls._initialized:
            return
            
        # Load external YAML plugins
        project_root = Path(__file__).resolve().parents[3]
        plugin_dir = project_root / "config" / "tool_plugins"
        
        if plugin_dir.exists():
            for yaml_file in plugin_dir.glob("*.yaml"):
                try:
                    with open(yaml_file, "r", encoding="utf-8") as f:
                        data = yaml.safe_load(f)
                        if data and "name" in data:
                            name = data["name"]
                            # Convert YAML keys to registry internal format
                            cls.TOOLS[name] = {
                                "cmd": data.get("command_template", ""),
                                "category": data.get("tier", "unknown"), # Mapping tier to category
                                "risk": data.get("risk", "medium"),
                                "description": data.get("description", ""),
                                "timeout": data.get("timeout_sec", 600)
                            }
                            logger.info(f"Loaded tool plugin: {name} from {yaml_file.name}")
                except Exception as e:
                    logger.error(f"Failed to load plugin {yaml_file}: {e}")
        
        cls._initialized = True

    @classmethod
    def get_command(cls, tool: str, target: str, **kwargs) -> str:
        cls._initialize()
        if tool not in cls.TOOLS:
            return None
        
        template = cls.TOOLS[tool]["cmd"]
        args = {"target": target}
        args.update(kwargs)
        
        try:
            return template.format(**args)
        except KeyError as e:
            # Handle specific required args
            missing_key = str(e).strip("'")
            if missing_key in ["output_file", "output"]:
                args["output_file"] = f"Result/v4_logs/tool_{tool}_{target.replace('://', '_').replace('/', '_')}.txt"
                args["output"] = args["output_file"]
                os.makedirs("Result/v4_logs", exist_ok=True)
                try:
                    return template.format(**args)
                except:
                    pass
            elif missing_key == "wordlist":
                args["wordlist"] = "config/wordlists/default.txt"
                try:
                    return template.format(**args)
                except:
                    pass
            
            # Last resort: just return a safe version if possible, or the template itself
            try:
                import re
                return re.sub(r'\{(?!(target)\})[^}]+\}', '', template).format(target=target)
            except:
                return template.replace("{target}", target)

    @classmethod
    def get_category(cls, tool: str) -> str:
        cls._initialize()
        return cls.TOOLS.get(tool, {}).get("category", "unknown")

    @classmethod
    def get_risk_level(cls, tool: str) -> str:
        cls._initialize()
        return cls.TOOLS.get(tool, {}).get("risk", "unknown")

    @classmethod
    def list_tools(cls) -> List[str]:
        cls._initialize()
        return list(cls.TOOLS.keys())
