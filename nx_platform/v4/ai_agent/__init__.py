"""
AI Agent Package - TRUE Autonomous AI Hacking Agent
"""
from .url_validator import validate_all_urls, add_url_status_to_classification
from .url_classifier import URLClassifier, classify_all_urls
from .smart_payload_generator import PayloadGenerator, get_payloads_for_category
from .form_analyzer import FormAnalyzer, analyze_forms_for_url, extract_testable_endpoints
from .csrf_idor_tester import CSRFTester, IDORTester, run_csrf_tests, run_idor_tests, run_all_form_tests
from .execution_engine import ExecutionEngine, run_autonomous_test
from .ai_brain import AIBrain, run_ai_agent
from .ai_agent_controller import run_ai_agent_main, run_true_ai_agent, run_hybrid_approach, AI_AGENT_MODE

__all__ = [
    # Core
    'AIBrain',
    'run_ai_agent',
    'run_ai_agent_main',
    'run_true_ai_agent',
    'run_hybrid_approach',
    'AI_AGENT_MODE',
    
    # Tools
    'URLClassifier',
    'classify_all_urls',
    'PayloadGenerator',
    'get_payloads_for_category',
    'ExecutionEngine',
    'run_autonomous_test',
    'validate_all_urls',
    'add_url_status_to_classification',
    'FormAnalyzer',
    'analyze_forms_for_url',
    'extract_testable_endpoints',
    'CSRFTester',
    'IDORTester',
    'run_csrf_tests',
    'run_idor_tests',
    'run_all_form_tests'
]