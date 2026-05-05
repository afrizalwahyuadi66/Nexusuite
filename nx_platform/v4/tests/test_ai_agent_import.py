import sys
import os

# Add project root to sys.path
root_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../.."))
if root_dir not in sys.path:
    sys.path.insert(0, root_dir)

print(f"[*] Project Root: {root_dir}")
print("[*] Testing imports for nx_platform.v4.ai_agent...")

try:
    from nx_platform.v4.ai_agent.smart_payload_generator import PayloadGenerator
    print("[+] Success: Imported PayloadGenerator")
    
    gen = PayloadGenerator()
    payloads = gen.get_sqli_payloads()
    print(f"[+] Payload test: Found {len(payloads)} SQLi payloads")
    
    from nx_platform.v4.ai_agent import run_ai_agent_main
    print("[+] Success: Imported run_ai_agent_main")
    
    from nx_platform.v4.ai_agent.form_analyzer import analyze_forms_for_url
    print("[+] Success: Imported analyze_forms_for_url")
    
    from nx_platform.v4.ai_agent.execution_engine import ExecutionEngine
    print("[+] Success: Imported ExecutionEngine")
    
    print("\n[!] ALL MODULES IMPORTED SUCCESSFULLY")
    
except ImportError as e:
    print(f"\n[-] IMPORT ERROR: {e}")
    sys.exit(1)
except Exception as e:
    print(f"\n[-] UNEXPECTED ERROR: {e}")
    sys.exit(1)
