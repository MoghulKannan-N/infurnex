# infurnex/probing_engine.py
import httpx # async and sync requests library
import urllib.parse # path building algorithms
import logging # structured standard library logging
from typing import Dict, Any # strictly typing return formats

# Configure standard stdout format
logging.basicConfig(level=logging.INFO, format='%(asctime)s - PROBER - %(message)s')

def inject_payload(endpoint: str, parameter: str, payload: str, location: str = "query", method: str = "GET") -> httpx.Response:
    # Subservient networking function linking HTTPX output directly to probe commands
    # Generates standard requests injecting onto a singular target variable based on input origin
    logging.info(f"Probing {parameter} with payload: {payload[:20]} via {location}") # debug stdout
    
    # Default execution wrapper configurations
    kwargs = {"verify": False, "timeout": 5.0, "follow_redirects": True} 
    
    if location == "query":
        # Inject standard URL GET queries
        kwargs["params"] = {parameter: payload} 
    elif location == "form" or location == "hidden":
        # Inject URL-encoded body boundaries for typical forms
        kwargs["data"] = {parameter: payload} 
        method = "POST" # override strictly for forms
    elif location == "cookie":
        # Inject dictionary directly into the HTTP context Cookie header
        kwargs["cookies"] = {parameter: payload} 
    elif location == "header":
        # Inject custom user header parameters
        kwargs["headers"] = {parameter: payload} 
    elif location == "json":
        # Inject JSON body payloads
        kwargs["json"] = {parameter: payload}
        method = "POST" # override strictly for JSON APIs
    elif location == "path":
        # Overwrite dynamic URL segments
        parsed = urllib.parse.urlparse(endpoint)
        path_segments = [seg for seg in parsed.path.split('/') if seg]
        try:
            idx = int(parameter.split('_')[1]) # parse segment index (e.g. 'segment_0')
            if idx < len(path_segments):
                path_segments[idx] = urllib.parse.quote(payload) # inject payload safely
                new_path = '/' + '/'.join(path_segments)
                endpoint = urllib.parse.urlunparse((parsed.scheme, parsed.netloc, new_path, parsed.params, parsed.query, parsed.fragment))
        except (IndexError, ValueError):
            pass # fallback if parsing fails
            
    # Execute injection offline sandbox or CTF targets ignore SSL cert checks
    return httpx.request(method=method.upper(), url=endpoint, **kwargs)

def probe_reflection(endpoint: str, parameter: str, location: str = "query", method: str = "GET") -> Dict[str, Any]:
    # Determines if user input echoes back unfiltered (Classic heuristic for XSS / SSTI)
    canary = "infurnex_cnry_8f3a" # standard deterministic non-alphanumeric string
    
    response = inject_payload(endpoint, parameter, canary, location, method) # launch dynamic request
    
    vuln_signal = { # initialize expected format schema
        "parameter": parameter, # store tested variable
        "vulnerability": "Reflection", # identify vulnerability sub-class
        "confidence": 0.0, # zero out initial scoring
        "details": "" # empty context buffer
    }
    
    if canary in response.text: # perform naive programmatic search for canary
        vuln_signal["confidence"] = 0.95 # highly confident mapping
        vuln_signal["details"] = "Canary string successfully reflected in response DOM." # add context
        logging.warning(f"Reflection detected on {parameter}!") # warning to user output
        
    return vuln_signal # ship structured object back to agent planner

def probe_sql_injection(endpoint: str, parameter: str, location: str = "query", method: str = "GET") -> Dict[str, Any]:
    # Triggers naive SQL syntax errors or boolean blind behavior programmatically
    # Utilizes classic quote breaking heuristics looking for database tracebacks
    error_payload = "'" # bare single quote break
    boolean_payload = "' OR 1=1--" # standard generic tautology logic
    
    error_resp = inject_payload(endpoint, parameter, error_payload, location, method) # fire traceback attempt
    bool_resp = inject_payload(endpoint, parameter, boolean_payload, location, method) # fire boolean bypass attempt
    
    vuln_signal = { # create signal JSON format
        "parameter": parameter, # trace current fuzz route
        "vulnerability": "SQLi", # map logic map vector
        "confidence": 0.0, # 0.0 default
        "details": "" # empty log array
    }
    
    # Map of classic DB leak strings
    sql_errors = ["syntax error", "mysql_fetch", "ora-", "pg_query", "unclosed quotation mark"]
    
    # Analyze the error attempt explicitly for tracebacks
    for error_str in sql_errors: # loop classic list
        if error_str.lower() in error_resp.text.lower(): # do programmatic lookup
            vuln_signal["confidence"] = 0.92 # highly confident
            vuln_signal["details"] = f"Detected SQL traceback: '{error_str}'" # output context
            logging.warning(f"SQL error traceback found on {parameter}!") # stdout logging
            return vuln_signal # return immediately on find
            
    # As a secondary check, evaluate behavioral status responses
    if bool_resp.status_code == 200 and error_resp.status_code == 500: # heuristic state check
        vuln_signal["confidence"] = 0.85 # strong behavioral indicator
        vuln_signal["details"] = "Detected behavioral SQLi: Status code shifted from 500 to 200 on tautology." # write contextual logic
        logging.warning(f"Boolean blind potential on {parameter}") # stdout emit
        
    return vuln_signal # pass array reference to pipeline 

def probe_command_injection(endpoint: str, parameter: str, location: str = "query", method: str = "GET") -> Dict[str, Any]:
    # Statically probes underlying operating systems via ping or sleep logic strings
    # Leverages classic sub-shell commands to generate mathematical latency
    payloads = ["; sleep 5", "| sleep 5", "`sleep 5`"] # static timing array
    
    vuln_signal = { # schema format setup
        "parameter": parameter, # param binding
        "vulnerability": "OS Command Injection", # class binding
        "confidence": 0.0, # null baseline
        "details": "" # context empty buffer
    }
    
    import time # local procedural import 
    
    for payload in payloads: # iterate latency triggers
        start_time = time.time() # measure start
        response = inject_payload(endpoint, parameter, payload, location, method) # invoke string dynamically
        end_time = time.time() # measure completion latency
        
        elapsed = end_time - start_time # mathematical subtract
        
        if elapsed >= 4.5: # 4.5s is solid given network delay bounds 
            vuln_signal["confidence"] = 0.90 # high behavioral indicator
            vuln_signal["details"] = f"Successful time-based injection. Delay exactly matches payload constraint." # format context string
            logging.warning(f"Time-based OSI detected on {parameter}!") # stdout user emit
            return vuln_signal # exit loop immediately on positive read
            
    return vuln_signal # clear schema out to caller
from response_diff_engine import simhash_diff, status_code_diff # mathematical diffing to detect state behavioral changes

def probe_state_manipulation(endpoint: str, parameter: str, baseline_resp: httpx.Response, location: str = "query", method: str = "GET") -> Dict[str, Any]:
    # Detects non-injection vulnerabilities like IDOR, Authentication Bypass, or Logic flaws
    # Tests numerics (IDOR), booleans (Auth), and privilege escalation values
    state_payloads = [
        "0", "1", "-1", "9999", # Numeric boundary/IDOR testing
        "true", "false", "True", "False", # Boolean state flipping
        "admin", "root", "user", "guest" # Privilege escalation attempts
    ]
    
    vuln_signal = { # schema format setup
        "parameter": parameter, # param binding
        "vulnerability": "State Manipulation", # class binding
        "confidence": 0.0, # null baseline
        "details": "" # empty context buffer
    }
    
    for payload in state_payloads: # fuzz state variables
        fuzzed_resp = inject_payload(endpoint, parameter, payload, location, method) # inject mutation state
        
        # 1. Check for hard WAF/Access control shifts
        status_check = status_code_diff(baseline_resp, fuzzed_resp) # Diff HTTP Status
        if status_check["is_different"] and fuzzed_resp.status_code in [200, 301, 302]:
            # If a previously blocked page became accessible
            if baseline_resp.status_code in [401, 403]: 
                vuln_signal["confidence"] = 0.95 # highly confident Auth Bypass
                vuln_signal["details"] = f"Auth Bypass: Payload '{payload}' shifted status from {baseline_resp.status_code} to {fuzzed_resp.status_code}"
                logging.warning(f"State Manipulation (Auth Bypass) detected on {parameter}!")
                return vuln_signal
                
        # 2. Check for soft behavioral shifts (e.g. IDOR loading a different user's profile)
        if fuzzed_resp.status_code == 200 and baseline_resp.status_code == 200: # if both load fine
            dom_check = simhash_diff(baseline_resp.text, fuzzed_resp.text) # Math diff the DOM
            if dom_check["is_significant"]: # if the page structurally changed
                vuln_signal["confidence"] = 0.85 # strong indicator of business logic flaw
                vuln_signal["details"] = f"Logic Flaw/IDOR: Payload '{payload}' generated significant DOM structural change."
                logging.warning(f"State Manipulation (DOM Shift) detected on {parameter}!")
                return vuln_signal # fast exit
                
    return vuln_signal # return null signal if all payloads failed

def probe_state_enumeration(endpoint: str, parameter: str, baseline_resp: httpx.Response, location: str = "query", method: str = "GET") -> Dict[str, Any]:
    # Specific strategy for enumerating cookies or indexing-based variables determining authorization levels natively
    
    vuln_signal = { # initialize expected format schema
        "parameter": parameter, # store tested variable
        "vulnerability": "State Enumeration", # identify vulnerability sub-class
        "confidence": 0.0, # initial baseline
        "details": "" # empty context buffer
    }
    
    # Generate broad payload sweep array dynamically targeting numeric bypass vulnerabilities: -1, 0, 1, 2... 50, 100, 999
    payloads = ["-1"] + [str(i) for i in range(51)] + ["100", "999"]
    
    # Heuristic signature list for common capture-the-flag formatting strings indicating successful exploitation
    flag_indicators = ["picoCTF{", "flag{", "CTF{"]
    
    for payload in payloads: # loop variable array
        logging.info(f"Probing cookie:{parameter} with payload: {payload}") # specific log formatting request
        fuzzed_resp = inject_payload(endpoint, parameter, payload, location, method) # launch dynamically
        
        # 1. Inspect response statically for explicit flag signatures indicative of sensitive content leak
        for indicator in flag_indicators: # loop possible string bounds
            if indicator in fuzzed_resp.text:
                vuln_signal["confidence"] = 1.0 # mathematical certainty
                vuln_signal["details"] = f"Potential sensitive content discovered (Flag format '{indicator}' matched). Payload: {payload}"
                logging.warning("Potential sensitive content discovered!") # trigger logging
                return vuln_signal
                
        # 2. Check for soft behavioral shifts (Content length or DOM mutation against baseline profile)
        if hasattr(baseline_resp, 'status_code') and fuzzed_resp.status_code == 200 and baseline_resp.status_code == 200:
            if len(fuzzed_resp.content) != len(baseline_resp.content): # Check raw HTTP response bounds change
                dom_check = simhash_diff(baseline_resp.text, fuzzed_resp.text) # Check DOM structures algorithmically
                if dom_check["is_significant"]: # Strong indicator of logical shift
                    vuln_signal["confidence"] = 0.85 # Elevate confidence organically
                    vuln_signal["details"] = f"DOM/Content length changed significantly via state manipulation. Payload: {payload}"
                    logging.info("Response anomaly detected") # emit output
                    return vuln_signal # pass object upwards early
                    
        # 3. Check for hard HTTP behavioral shifts like jumping 403 Forbidden to 200 OK
        if hasattr(baseline_resp, 'status_code') and fuzzed_resp.status_code == 200 and baseline_resp.status_code != 200:
            vuln_signal["confidence"] = 0.85 # Strong behavioral logic indicator
            vuln_signal["details"] = f"Status code flipped from {baseline_resp.status_code} to 200 via bypass payload: {payload}"
            logging.info("Response anomaly detected")
            return vuln_signal
            
    return vuln_signal # Return baseline 0.0 null schema if no anomalous findings mapped
