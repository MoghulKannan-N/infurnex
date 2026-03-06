# infurnex/payloads.py
import json # standard json library
from typing import List, Dict # type hinting

def load_payload_library(filepath: str = "kb/payloads.json") -> Dict[str, List[str]]:
    # Loads the static vulnerability knowledge base (KB) from a JSON file
    try:
        with open(filepath, 'r') as f: # open file
            return json.load(f) # parse and return
    except FileNotFoundError: # handle missing file
        return {
            "xss": ["<script>alert(1)</script>", "'-prompt(8)-'"], # default mock XSS
            "sqli": ["' OR 1=1--", "' UNION SELECT null,null--"] # default mock SQLi
        }

def payload_mutator(base_payload: str, strategies: List[str]) -> str:
    # Takes a base string and applies evasion or encoding strategies
    mutated = base_payload # initialize mutated string
    
    for strategy in strategies: # iterate over requested strategies
        if strategy == "urlencode": # check strategy
            # replace spaces and quotes for URL encoding (naive stub)
            mutated = mutated.replace(" ", "%20").replace("'", "%27")
        elif strategy == "base64": # check strategy
            import base64 # import library locally
            # perform base64 bytes encoding
            mutated = base64.b64encode(mutated.encode()).decode() 
        elif strategy == "uppercase": # check strategy
            mutated = mutated.upper() # naive WAF bypass technique
            
    return mutated # return the mutated payload string
