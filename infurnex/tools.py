# infurnex/tools.py
import json # for JSON manipulation
import re # for flag extraction regex
from typing import Dict, Any, List, Optional # type hints

def check_host_allowlist(url: str) -> bool:
    # Security Sandbox Check: ensures the target URL is allowed
    # MVP only allows placeholder or local sandbox domains
    allowed_domains = ["target.local", "localhost", "127.0.0.1"] # allowed list for sandbox
    return any(domain in url for domain in allowed_domains) # check inclusion

def http_request(method: str, url: str, headers: Optional[Dict] = None, params: Optional[Dict] = None, data: Optional[Dict] = None, json_data: Optional[Dict] = None, cookies: Optional[Dict] = None, allow_redirects: bool = True, timeout: int = 10) -> str:
    # Issues a sandboxed HTTP request to the target
    if not check_host_allowlist(url): # enforce security barrier
        return "Error: URL not in sandbox allowlist. Request blocked." # reject unauthorized targets
        
    # Mocking standard httpx/requests behavior for the scaffold
    response_stub = {
        "status_code": 200, # mock 200 OK
        "headers": {"Server": "nginx", "Set-Cookie": "session=123"}, # mock headers
        "body": "<html><body>Welcome to the challenge! picoCTF{mock_flag_found}</body></html>" # mock body
    }
    return json.dumps(response_stub) # return JSON string representation

def html_parser(html_string: str) -> str:
    # Extracts useful structural info (forms, inputs, comments) from raw HTML
    # Real implementation uses BeautifulSoup4
    params_found = ["username", "password", "debug"] # stubbed extraction
    return f"Found inputs: {params_found}. Hidden comments: <!-- TODO: remove debug flag -->" # return parsed summary

def js_analyzer(js_code: str, context_url: Optional[str] = None) -> str:
    # Analyzes client-side Javascript for sensitive logic or endpoints
    # Real implementation uses Esprima or simple regex analysis
    if "admin" in js_code: # naive stub check
        return "Found reference to '/admin' endpoint in JS." # stubbed finding
    return "No obvious vulnerabilities found in JS." # standard output

def source_code_scanner(code: str, language: str) -> str:
    # Statically analyzes provided source files for vulnerability patterns
    if language == "php" and "eval(" in code: # simple sink check
        return "Warning: Dangerous 'eval' sink detected." # flag finding
    return "Code looks clean." # standard output

def dir_bruteforcer(base_url: str, wordlist: str = "common.txt", concurrency: int = 10) -> str:
    # Enumerates hidden directories. Only allowed within sandbox.
    if not check_host_allowlist(base_url): # enforce security
        return "Error: Out of scope for bruteforcing." # reject unauthorized
    return f"Discovered paths: /robots.txt, /.git/, /admin_login" # mock output

def flag_extractor(text: str) -> str:
    # Safely scans output buffers for the standard picoCTF flag format
    pattern = r"picoCTF\{[^}]+\}" # standard regex pattern
    matches = re.findall(pattern, text) # execute search
    if matches: # check if any found
        return f"Extracted flag: {matches[0]}" # return first match
    return "No flag found in provided text." # standard output

def get_tool_registry() -> Dict[str, callable]:
    # Returns a dictionary mapping tool names to their function pointers
    # This is injected into the ReAct loop
    return {
        "http_request": http_request, # map http tool
        "html_parser": html_parser, # map html parser
        "js_analyzer": js_analyzer, # map JS analyzer
        "source_code_scanner": source_code_scanner, # map source scanner
        "dir_bruteforcer": dir_bruteforcer, # map bruter
        "flag_extractor": flag_extractor # map extractor
    }
