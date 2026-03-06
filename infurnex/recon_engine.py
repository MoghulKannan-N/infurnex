# infurnex/recon_engine.py
import urllib.parse # standard library for URL handling and query parsing
from typing import Dict, List, Set, Any # typing for data structures
from bs4 import BeautifulSoup # HTML and DOM extraction
import httpx # async and sync robust HTTP requests
import re # regex for javascript endpoint parsing
import logging # structured output

# Initialize recon logging channel
logging.basicConfig(level=logging.INFO, format='%(asctime)s - RECON - %(message)s')

def endpoint_crawler(base_url: str, max_depth: int = 3) -> Dict[str, Any]:
    # Entrypoint for autonomous map generation using standard BFS crawling
    visited: Set[str] = set() # instantiate queue for seen URLs
    to_visit: List[str] = [base_url] # seed crawl with the initial challenge URL
    
    # Store the resulting data structural model compatible with the controller
    attack_surface = {
        "endpoints": [], # discovered accessible paths (for backwards compatibility)
        "parameters": [], # extracted GET query bounds (for backwards compatibility)
        "forms": [], # extracted POST payload templates (for backwards compatibility)
        "targets": [] # NEW: Unified comprehensive input tracking schema
    }
    
    depth = 0 # recursive tracker
    while to_visit and depth < max_depth: # loop while depth permits
        current_url = to_visit.pop(0) # dequeue oldest URL
        if current_url in visited: # skip already processed targets
            continue # break current loop iteration
            
        visited.add(current_url) # mark as crawled
        logging.info(f"Crawling: {current_url}") # stdout log for visibility
        
        try:
            # fetch current page ignoring cert errors for CTF targets, follow redirects to map properly
            resp = httpx.get(current_url, verify=False, timeout=5.0, follow_redirects=True) 
            
            # Record the actual end-URL we landed on (e.g. after a 302 redirect)
            actual_url = str(resp.url) 
            visited.add(actual_url) # mark the destination as visited too
            attack_surface["endpoints"].append(actual_url) # push backwards compat endpoint string
            
            # Initialize a unified target schema for this explicit endpoint
            target_map = {
                "endpoint": actual_url, # route location
                "inputs": [], # array for all injection vectors
                "method": "GET" # base method
            }
            
            # Helper function to prevent duplicate input registration 
            def add_input(name: str, location: str):
                for entry in target_map["inputs"]: # iterate existing bounds
                    if entry["name"] == name and entry["location"] == location:
                        return # Break if duplicate found
                target_map["inputs"].append({"name": name, "location": location}) # append fresh schema
                
            # 1. Scrape HTTP Headers and Cookies directly from the Response
            # Web servers commonly reflect or process custom headers, cookies, or tracking headers
            for cookie_name in resp.cookies.keys(): # iterate server-set cookies
                add_input(cookie_name, "cookie") # log cookie input securely
                logging.info(f"Recon: cookie discovered \u2192 {cookie_name}") # emit specific log format
                
            # Naive heuristics looking for reflection headers or custom routing headers
            for header_name in ["X-Forwarded-For", "Host", "User-Agent", "Referer", "Accept-Language"]: 
                add_input(header_name, "header") # map standard header payloads
                
            # Naive URL Path segment parsing (RESTful routes like /api/user/1234)
            parsed_url = urllib.parse.urlparse(actual_url) # decompose route
            path_segments = [seg for seg in parsed_url.path.split('/') if seg] # split segments securely
            for idx, segment in enumerate(path_segments): # iterate array
                # If a path segment looks numeric or like a long hash, flag it as a variable
                if segment.isdigit() or len(segment) > 16:
                    add_input(f"segment_{idx}", "path") # tag it positionally
                    logging.info(f"Flagged dynamic URL path segment: {segment}")
                    
            # Process actual HTML payload if we received web content
            if "text/html" in resp.headers.get("Content-Type", ""): 
                soup = BeautifulSoup(resp.text, 'html.parser') # construct DOM
                
                # 2. Extract Links for further crawling
                for anchor in soup.find_all('a', href=True): # loop standard hyperreferences
                    href = anchor['href'] # retrieve reference link
                    full_link = urllib.parse.urljoin(actual_url, href) # normalize path
                    if base_url in full_link and full_link not in visited: # scope check
                        to_visit.append(full_link) # append to queue
                        
                # 3. Scrape on-page HTML forms (POST / GET)
                forms_found = form_extractor(actual_url, soup.prettify()) # parse raw HTML with companion function
                for form in forms_found: # form_extractor now yields unified target objects
                    attack_surface["targets"].append(form) # append directly to targets
                    attack_surface["forms"].append(form) # append backwards compat
                    
                # 4. Extract Javascript referenced endpoints (e.g., fetch API calls)
                js_links = extract_javascript_endpoints(actual_url, resp.text) # invoke regex crawler
                for link in js_links: # iterate findings
                    if link not in visited and base_url in link: # scope and deduplicate
                        to_visit.append(link) # enqueue new REST/API paths
                        
            # 5. Scrape query params from the URL explicitly
            params_found = parameter_extractor(actual_url) # evaluate the query string
            for param in params_found: # iterate key inputs
                add_input(param, "query") # map input origin securely
                attack_surface["parameters"].append(param) # backwards compat mapping
                
            # 6. JSON body parsing (heuristic check if a JS endpoint usually accepts JSON)
            # Typically impossible to know passively, but we blindly fuzz common parameters targeting APIs
            if "application/json" in resp.headers.get("Content-Type", "") or "/api/" in actual_url:
                target_map["method"] = "POST" # Assume APIs accept data states
                for common_json_key in ["id", "username", "email", "role", "data"]:
                    add_input(common_json_key, "json") # push JSON parameter map
                
            # If we bound any valid inputs to this generic GET endpoint, push to master tracker
            if target_map["inputs"]: 
                attack_surface["targets"].append(target_map) # push structural mapping
                
        except Exception as e: # handle timeouts or connection resets securely
            logging.error(f"Failed to crawl {current_url}: {str(e)}") # write trace to log
            
        depth += 1 # increment tracker to avoid infinite loops
        
    return attack_surface # yield the populated target map

def form_extractor(current_url: str, html: str) -> List[Dict[str, Any]]:
    # Extracts forms and maps them into the new unified target schema format
    soup = BeautifulSoup(html, 'html.parser') # construct DOM
    forms_extracted = [] # empty array for unified target objects
    
    for form in soup.find_all('form'): # iterate over all literal HTML form tags
        action_route = form.get('action', '') # generic endpoint target
        full_endpoint = urllib.parse.urljoin(current_url, action_route) # normalize to absolute URL
        
        target_details = { # build unified target template
            "endpoint": full_endpoint, # resolved absolute target
            "method": form.get('method', 'GET').upper(), # HTTP verb (POST usually)
            "inputs": [] # unified input list
        }
        
        for input_tag in form.find_all(['input', 'select', 'textarea']): # pull input variants
            input_name = input_tag.get('name') # check for variable mapping name
            input_type = input_tag.get('type', 'text').lower() # determine if hidden vs text
            if input_name: # if it is bound to a variable
                target_details["inputs"].append({ # log it into unified template
                    "name": input_name, # parameter key
                    "location": "hidden" if input_type == "hidden" else "form" # origin mapping
                })
                
        forms_extracted.append(target_details) # attach object
        logging.info(f"Extracted generic form target POSTing to {target_details['endpoint']}") # write debug log
        
    return forms_extracted # yield extracted list

def extract_javascript_endpoints(base_url: str, html: str) -> List[str]:
    # Regex parser looking for API strings referenced visually in JS blocks
    endpoints = [] # accumulator
    # heuristic regex targeting common fetch('/path') or axios.get("/api/v1") calls
    path_regex = r"(?:(?:fetch|axios\.get|axios\.post|\$\.ajax|\$\.get|\$\.post)\s*\(\s*['\"])(/[^'\"]+)(?:['\"])" 
    
    matches = re.findall(path_regex, html) # execute blind evaluation
    for match in matches: # iterate findings
        full_url = urllib.parse.urljoin(base_url, match) # contextualize relative API path
        endpoints.append(full_url) # register path
        logging.info(f"Discovered backend JS API endpoint: {full_url}") # stdout 
        
    return endpoints # return array of URLs

def parameter_extractor(url: str) -> List[str]:
    # Statically converts query strings into fuzzable variable targets
    parsed_url = urllib.parse.urlparse(url) # decompose standard URL segments
    query_params = urllib.parse.parse_qs(parsed_url.query) # extract key-value mappings
    
    params_found = list(query_params.keys()) # pull only the injection sinks (keys)
    if params_found: # log only if present
        logging.info(f"Extracted query parameters: {params_found}") # write array to stdout
        
    return params_found # yield parameters ready to fuzz

def robots_parser(base_url: str) -> List[str]:
    # Probes standard text configuration endpoints that leak administrative routing
    robots_url = urllib.parse.urljoin(base_url, '/robots.txt') # normalize payload path
    hidden_paths = [] # initialization of discovery list
    
    try:
        resp = httpx.get(robots_url, timeout=5.0, follow_redirects=True) # execute naive request
        if resp.status_code == 200: # if file explicitly exists and serves standard HTTP
            for line in resp.text.split('\n'): # iterate line by line
                if line.lower().startswith('disallow:'): # check for indexing denial
                    path = line.split(':')[1].strip() # extract the exact backend suffix
                    # Convert raw path string into an absolute URL so it matches endpoint maps
                    full_link = urllib.parse.urljoin(base_url, path) 
                    hidden_paths.append(full_link) # register absolute URL
                    logging.info(f"Found hidden path in robots.txt: {full_link}") # emit find logic
    except Exception as e: # catch all timeout/resolution failures securely
        logging.warning(f"Could not load robots.txt: {str(e)}") # emit non-fatal warning
        
    return hidden_paths # return administrative target absolute route array
