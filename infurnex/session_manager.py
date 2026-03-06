# infurnex/session_manager.py
import httpx # required for async HTTP requests and standard session handling
from typing import Dict, List, Any, Optional # robust typing for state tracking
from bs4 import BeautifulSoup # for parsing CSRF tokens from HTML responses
import logging # procedural logging structure

# Initialize structured logging for the session manager
logging.basicConfig(level=logging.INFO, format='%(asctime)s - MANAGER - %(message)s')

def create_session() -> Dict[str, Any]:
    # Creates and initializes a fresh HTTP session state dictionary
    return {
        "cookies": {}, # stores domain-scoped cookies
        "headers": {"User-Agent": "INFURNEX/2.0 (Security Agent)"}, # base request headers
        "history": [], # stores chronological request/response history
        "csrf_tokens": {}, # stores discovered anti-CSRF tokens mapped by form or path
        "is_authenticated": False # tracks boolean authentication state
    }

def update_cookies(session_state: Dict[str, Any], new_cookies: Dict[str, str]) -> None:
    # Merges newly discovered cookies into the persistent session store
    for key, value in new_cookies.items(): # iterate over incoming cookie jars
        session_state["cookies"][key] = value # update or insert the cookie value
        logging.info(f"Session updated with cookie: {key}={value[:10]}...") # log partial cookie

def extract_csrf_tokens(session_state: Dict[str, Any], html_response: str, url: str) -> None:
    # Parses the DOM to find hidden CSRF or anti-forgery tokens
    soup = BeautifulSoup(html_response, "html.parser") # instantiate BS4 parser
    # common heuristic names for CSRF input fields
    possible_names = ["csrf", "csrf_token", "_csrf", "authenticity_token", "token"] 
    
    for name in possible_names: # iterate through known token names
        finds = soup.find_all("input", {"name": name}) # search the DOM for matching inputs
        for token_input in finds: # iterate through found inputs
            token_val = token_input.get("value") # extract the hidden value attribute
            if token_val: # if a value actually exists
                session_state["csrf_tokens"][url] = token_val # map token to the URL it was found on
                logging.info(f"Extracted CSRF token for {url}") # log success

def apply_session_to_request(session_state: Dict[str, Any], url: str, method: str, data: Optional[Dict] = None) -> Dict[str, Any]:
    # Injects the stored state (cookies, headers, tokens) into an outbound request payload
    req_kwargs = { # initialize the request arguments dictionary
        "cookies": session_state["cookies"], # inject persistent cookies
        "headers": session_state["headers"], # inject persistent headers
        "follow_redirects": False # defaults to manual redirect tracking
    }
    
    if method.upper() in ["POST", "PUT", "DELETE"]: # if request is a state-changing method
        if data is None: # ensure data dict exists
            data = {} # initialize empty data
        # Check if we have a mapped CSRF token for this target URL
        if url in session_state["csrf_tokens"]: 
            token = session_state["csrf_tokens"][url] # retrieve token
            data["csrf_token"] = token # inject token into payload (heuristic name)
            logging.info("Applied CSRF token to outbound state-change request") # log injection
        req_kwargs["data"] = data # attach data to request kwargs
        
    return req_kwargs # return the fully decorated request arguments

def track_redirects(session_state: Dict[str, Any], response: httpx.Response) -> List[str]:
    # Manually tracks 3xx redirects to build a redirect chain history
    chain = [] # initialize empty path chain
    current_resp = response # start with the initial response
    
    while current_resp.is_redirect: # loop while a 3xx status code is present
        location = current_resp.headers.get("Location") # extract the target redirect URL
        if not location: # if standard header is missing
            break # exit loop
            
        chain.append(location) # append URL to our tracking chain
        logging.info(f"Tracking redirect hop to: {location}") # log the hop
        
        # update the historical request log in the session state
        session_state["history"].append({
            "url": str(current_resp.url), # original URL 
            "status": current_resp.status_code, # trigger status (e.g., 302)
            "redirect_to": location # target URL
        })
        
        # Depending on implementation, you would trigger the next HTTPX request here
        # For procedural tracking, we just break after recording the first required hop
        break 
        
    return chain # return the discovered redirect chain
