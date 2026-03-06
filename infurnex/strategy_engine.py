# infurnex/strategy_engine.py
from typing import Dict, Any, List # typing systems
import logging # standardized stdout

logging.basicConfig(level=logging.INFO, format='%(asctime)s - STRATEGY - %(message)s')

def select_attack_strategy(vulnerability_signals: List[Dict[str, Any]]) -> Dict[str, Any]:
    # Evaluates vulnerability probes and returns the optimal payload strategy
    # Default fallback strategy if no strong signals are present
    best_strategy = {"vulnerability": "xss", "confidence": 0.0, "parameter": None}
    
    for signal in vulnerability_signals: # iterate through all prober outputs
        vuln_type = signal.get("vulnerability", "").lower() # identify class
        confidence = signal.get("confidence", 0.0) # identify mathematical probability
        
        # Compare current signal against our highest seen confidence
        if confidence > best_strategy["confidence"]: 
            # Logic branch: Reflection highly implies XSS or SSTI
            if "reflection" in vuln_type:
                best_strategy = {"vulnerability": "xss", "confidence": confidence, "parameter": signal.get("parameter")}
            # Logic branch: SQL errors or boolean differences imply SQLi
            elif "sqli" in vuln_type:
                best_strategy = {"vulnerability": "sqli", "confidence": confidence, "parameter": signal.get("parameter")}
            # Logic branch: Time delays imply command or code injection
            elif "command injection" in vuln_type:
                best_strategy = {"vulnerability": "command_injection", "confidence": confidence, "parameter": signal.get("parameter")}
            # Logic branch: DOM changes from numeric/boolean variance imply Logic Flaws
            elif "state manipulation" in vuln_type:
                best_strategy = {"vulnerability": "state_manipulation", "confidence": confidence, "parameter": signal.get("parameter")}
            # Logic branch: State enumeration variance implies State Enumeration Attack
            elif "state enumeration" in vuln_type:
                best_strategy = {"vulnerability": "state_enumeration_attack", "confidence": confidence, "parameter": signal.get("parameter")}
                
    if best_strategy["parameter"]: # Check if a valid target was actually chosen
        logging.info(f"Strategy selected: Prioritizing {best_strategy['vulnerability']} on {best_strategy['parameter']} (Confidence: {best_strategy['confidence']})")
    else: # Warning if no signals were strong enough
        logging.warning("No strong vulnerability signals detected. Strategy engine failing to default.")
        
    return best_strategy # Return logic map to controller

def rank_targets(attack_surface: Dict[str, Any]) -> List[Dict[str, str]]:
    # Evaluates the recon map and orders parameters from most to least likely to be vulnerable
    # Generates a flat array of targets linking parameters to endpoints
    flat_targets = []
    
    # Process unified targets list from recon engine
    for target in attack_surface.get("targets", []): # iterate discovered endpoints
        endpoint = target.get("endpoint") # routing target
        method = target.get("method", "GET").upper() # verb restriction
        
        for input_obj in target.get("inputs", []): # iterate inputs on this endpoint
            name = input_obj.get("name") # parameter key
            location = input_obj.get("location", "query") # where the parameter belongs
            
            if name:
                score = 50 # Base score
                
                # Heuristics: highly targeted keyword parameter names
                if name.lower() in ["id", "username", "search", "cmd", "file", "url", "email", "query", "role"]:
                    score += 30 # boost priority
                    
                # Heuristics: boost cookies and headers as they are rarer but highly impactful
                if location in ["cookie", "header"]:
                    score += 15 # contextual boost
                    
                flat_targets.append({
                    "endpoint": endpoint,
                    "parameter": name,
                    "location": location,
                    "method": method,
                    "priority": score
                })
                
    # Procedural list sort using lambda accessor mapped to the 'priority' dict key
    ranked = sorted(flat_targets, key=lambda x: x["priority"], reverse=True)
    logging.info(f"Ranked {len(ranked)} potential injection targets.")
    return ranked # return prioritized flat array
