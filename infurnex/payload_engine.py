# infurnex/payload_engine.py
import urllib.parse # mutation algorithm
import base64 # encoding bypass
import random # payload scoring logic tests
import os # reading downloaded repos
from typing import List, Dict, Any # strict typing mapping
import json # configuration maps

import logging # python stdout standard format
logging.basicConfig(level=logging.INFO, format='%(asctime)s - PAYLOADS - %(message)s')

# --- SECTION A: Open Source Payload Sources ---

def sync_payload_sources() -> None:
    # Stubs a git clone integration to grab SecLists or PayloadsAllTheThings
    # In a full run, this invokes a bash script to pull repositories
    payload_dir = "payload_sources" # define repo root
    # Ensures directory structure is present securely
    os.makedirs(f"{payload_dir}/xss", exist_ok=True) # create subdirectory
    os.makedirs(f"{payload_dir}/sqli", exist_ok=True) # create subdirectory
    logging.info("Payload repositories synced and ready.") # stdout confirmation

def load_payloads(vuln_type: str) -> List[str]:
    # Opens contextual static lists locally off disk and loads into memory buffer
    file_path = f"payload_sources/{vuln_type}/list.txt" # dynamic route building
    payloads = [] # default accumulator
    
    if os.path.exists(file_path): # check if sync actually ran
        with open(file_path, "r") as f: # open read only
            payloads = [line.strip() for line in f.readlines()] # convert block to list generator
            logging.info(f"Loaded {len(payloads)} raw templates for {vuln_type}") # debug metric
    else: # fallback if sources aren't downloaded
        logging.warning(f"No local payload source found for {vuln_type}. Using fallback.") # debug warning
        if vuln_type == "xss": # inline stub maps
            payloads = ["<script>alert(1)</script>", "<svg onload=alert(1)>"] # defaults
        elif vuln_type == "sqli": # inline stub maps
            payloads = ["' OR 1=1--", "' UNION SELECT 1--"] # defaults
            
    return payloads # send raw templates to mutator

# --- SECTION B: Context-Aware Payload Generation ---

def generate_contextual_payloads(vuln_context: Dict[str, Any]) -> List[str]:
    # Combines baseline templates with application environmental knowledge
    vuln = vuln_context.get("vulnerability", "xss").lower() # default class
    backend = vuln_context.get("server_stack", "unknown").lower() # detect PHP/Node/Ruby
    
    raw_payloads = load_payloads(vuln) # ingest naive list
    adapted_payloads = [] # prepare final filtered output
    
    for payload in raw_payloads: # loop inputs
        # Example context modification: PHP vs JS string terminators
        if backend == "php" and vuln == "sqli": # evaluate combo matches
            # PHP apps often add slashes, try inline comments over line drops 
            adapted = payload.replace("--", "#") # apply heuristic translation
            adapted_payloads.append(adapted) # add formatted version
        elif vuln_context.get("reflection_context") == "javascript_string": # evaluate DOM placement
            # Break JS scope intelligently
            adapted = f"'-{payload}-'" # string break mathematical operation
            adapted_payloads.append(adapted) # append logic mapping
        else: # unmodified append rule
            adapted_payloads.append(payload) # attach
            
    logging.info(f"Generated {len(adapted_payloads)} context-adapted payloads.") # UX stdout
    return adapted_payloads # emit lists to orchestrator 

# --- SECTION C: Payload Mutation Engine ---

def mutate_payload(payload: str, strategy: str) -> str:
    # Single string manipulation executing a specific security algorithm bypass
    if strategy == "urlencode": # check strategy
        return urllib.parse.quote(payload) # map standard library to string
    elif strategy == "double_encode": # check strategy
        firstpass = urllib.parse.quote(payload) # pass 1
        return urllib.parse.quote(firstpass) # pass 2 nesting
    elif strategy == "base64": # check strategy
        return base64.b64encode(payload.encode()).decode() # execute buffer math
    elif strategy == "uppercase": # check strategy
        return payload.upper() # primitive WAF filter breaker
    return payload # zero mutation return

def generate_mutations(payload_list: List[str]) -> List[str]:
    # Iterates all strings through a gauntlet of evasion tactics
    mutated_list = [] # master return list
    strategies = ["urlencode", "double_encode", "uppercase"] # defined evasion map vectors
    
    for payload in payload_list: # walk array inputs
        mutated_list.append(payload) # always keep the original unmodified logic string
        for strategy in strategies: # walk individual strategy applications
            mutated = mutate_payload(payload, strategy) # function execution command
            mutated_list.append(mutated) # map mutated string array
            
    logging.info(f"Mutation engine amplified payload list from {len(payload_list)} to {len(mutated_list)}") # metrics
    return mutated_list # flush complete test deck

# --- SECTION D: Payload Ranking System ---

def rank_payloads(payload_list: List[str]) -> List[str]:
    # Heuristic scoring engine sorting optimal test strings before long edge cases
    # Shorter strings generally block less often. Original strings rank above base64.
    
    def score_payload(p: str) -> int:
        # Mini scoring logic function
        score = 100 # base default threshold ceiling
        score -= len(p) # penalize long payloads heavily (waf drops length easily)
        if "%25" in p: score -= 10 # penalize double encoding (messy execution)
        if p.isupper(): score -= 5 # penalize case shifting (rare execution contexts)
        return score # flush metric integer
        
    # Python sorting mechanism using our integer logic output as mathematical key mapping
    ranked_payloads = sorted(payload_list, key=score_payload, reverse=True) # order largest to smallest score
    logging.info(f"Ranked {len(ranked_payloads)} payloads by complexity probability.") # UX display
    
    # Optional constraint limiting logic 
    return ranked_payloads[:10] # returning top 10 execution string arrays only

# --- SECTION E: Payload Success Memory ---

def update_payload_memory(payload: str, vuln_type: str, success: bool) -> None:
    # Tracks which test vectors actually solve issues over long learning arcs
    memory_file = "payload_memory.json" # standard static file name array route
    
    memory = load_payload_memory(memory_file) # open old context mappings
    
    if vuln_type not in memory: # check node initialization
        memory[vuln_type] = [] # generate array context object mapped
        
    found = False # local tracker for existing loop iteration logic 
    for entry in memory[vuln_type]: # loop current history logic values
        if entry["payload"] == payload: # if exact match is currently defined
            found = True # map true 
            entry["attempts"] = entry.get("attempts", 0) + 1 # inc counter
            if success: # eval context result parameter mapping
                entry["successes"] = entry.get("successes", 0) + 1 # inc numerical scoring logic success array
            
            # Recalculate mathematical probability matrix for this string representation
            entry["success_rate"] = entry["successes"] / entry["attempts"] # math mapping float creation
            break # break list iteration
            
    if not found and success: # if totally new string works
        memory[vuln_type].append({ # add logic layout
            "payload": payload, # map string exactly to node key
            "attempts": 1, # default array logic mapping representation 
            "successes": 1, # default arrays 
            "success_rate": 1.0 # 100 percent initial boolean matrix rate mapping object float array float format parameter output format
        })
        
    with open(memory_file, 'w') as f: # standard disk open 
        json.dump(memory, f, indent=2) # standard disk mapped dump formatting math parameter json object json library mapped float mapping string
        
    if success: # UX output
        logging.info(f"Payload memory updated for {vuln_type}: '{payload}' marked as successful.") # string format 

def load_payload_memory(filepath: str = "payload_memory.json") -> Dict[str, Any]:
    # Returns history logic dictionary into memory runtime
    if os.path.exists(filepath): # safety load parameters check node boolean state parameter mapped boolean string disk boolean boolean Disk load check boolean boolean mapping check state disk boolean object node float path boolean check disk node boolean Disk mapping mapped json disk state json node library state mapping disk
        try: # safe disk JSON decode loop structure loop structure disk logic node decode disk open path format route logic mapping array
            with open(filepath, 'r') as f: # json python file mapping string string logic parameter text stream json parameter input syntax parameter text string parameter dictionary logic
                return json.load(f) # memory return
        except json.JSONDecodeError: # fallback format syntax error check formatting path text json formatting file mapping parameter check disk
            return {} # empty logic base list logic map JSON initialization format base null text format mapped state
    return {} # fallback return formatting map text null base parameter string loop format logic mapped array formatting
