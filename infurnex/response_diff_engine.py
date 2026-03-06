# infurnex/response_diff_engine.py
import httpx # standard HTTP response format access
from typing import Dict, Any # strict typing schemas
from bs4 import BeautifulSoup # extracting pure text from HTML nodes

# The simhash library allows for mathematical structural comparisons of strings
# Requires: pip install simhash
try:
    from simhash import Simhash # local namespace import for diff logic
except ImportError: # fail safely if not installed
    class Simhash: # mock stub class
        def __init__(self, val: str): self.val = val # assign raw value
        def distance(self, other): return len(self.val) - len(other.val) # mock diff

import logging # python execution logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - DIFFER - %(message)s') # set parameters

def simhash_diff(html1: str, html2: str) -> Dict[str, Any]:
    # Calculates a structural integer distance between two HTML documents
    # A distance of 0 means structurally identical. A distance > 10 means significantly different
    
    # Pre-process HTML to remove dynamic noise (timestamps, random CSRF values)
    # This prevents false positives during boolean blind attacks
    soup1 = BeautifulSoup(html1, 'html.parser') # process baseline
    soup2 = BeautifulSoup(html2, 'html.parser') # process fuzzed response
    
    # Strip script and style tags to compare only content structure
    for tags in soup1(["script", "style", "input"]): # strip dynamic noise
        tags.decompose() # purge tree nodes 
    for tags in soup2(["script", "style", "input"]): # strip dynamic noise
        tags.decompose() # purge tree nodes
        
    text1 = soup1.get_text() # extract clean literal text
    text2 = soup2.get_text() # extract clean literal text
    
    hash1 = Simhash(text1) # compute baseline structural hash
    hash2 = Simhash(text2) # compute mathematical mutation hash
    
    distance = hash1.distance(hash2) # evaluate binary distance difference
    
    diff_signal = { # structure formatting
        "distance": distance, # output numerical delta
        "is_significant": distance > 5, # heuristic cut-off for major DOM shifts
        "details": f"Simhash distance computed as {distance}" # descriptive log
    }
    
    logging.info(f"Simhash Diff calculated: {distance}") # emit trace
    return diff_signal # return mathematical proof

def status_code_diff(resp1: httpx.Response, resp2: httpx.Response) -> Dict[str, Any]:
    # Extremely cheap heuristic comparison detecting WAF drops or crashing backends
    
    diff_signal = { # structure formatting
        "status_1": resp1.status_code, # load baseline code
        "status_2": resp2.status_code, # load fuzz reaction code
        "is_different": resp1.status_code != resp2.status_code, # boolean logic test
        "details": "" # trace log
    }
    
    if diff_signal["is_different"]: # if a 200 turned into a 500
        diff_signal["details"] = f"Status shifted from {resp1.status_code} to {resp2.status_code}" # format trace
        logging.warning(f"Status Code Anomaly: {diff_signal['details']}") # stdout emit alert
        
    return diff_signal # return result object

def content_length_diff(resp1: httpx.Response, resp2: httpx.Response) -> Dict[str, Any]:
    # Computes byte-level length differences catching boolean True/False shifts
    len1 = len(resp1.content) # raw byte length array 1
    len2 = len(resp2.content) # raw byte length array 2
    
    delta = abs(len1 - len2) # numerical integer subtraction absolute value
    
    diff_signal = { # format schema tracking
        "length_1": len1, # base metric
        "length_2": len2, # mutant metric
        "delta": delta, # exact difference tracking
        "is_significant": delta > 20, # heuristic cutoff for dynamic vs hard deviation
        "details": f"Byte length shifted by {delta} bytes" # output string formatter
    }
    
    logging.info(f"Content Length Diff calculated: {delta} bytes") # debug visual 
    return diff_signal # send state to planner 
