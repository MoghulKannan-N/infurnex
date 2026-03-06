# tools/run_infurnex.py
import re
import subprocess
from string import Template

# Tool descriptor mapping for the LLM SDK
description = "Launch the advanced autonomous INFURNEX pentesting framework against a target URL."

def run_infurnex(target_url: str) -> str:
    """
    Spawns the procedural INFURNEX micro-engine against the specified web target.
    
    INFURNEX is an autonomous deterministic pentesting engine capable of:
    * web vulnerability discovery
    * input fuzzing (query params, forms, JSON, API segments)
    * cookie manipulation and state enumeration
    * payload generation and logical flaw detection
    
    Returns standard stdout and will immediately extract any flags discovered.
    """
    
    # Securely structure the bash array for native subprocess binding
    command_sequence = ["python3", "infurnex/agent_controller.py", target_url.strip()]
    
    try:
        # Launch procedural engine safely
        process = subprocess.run(
            command_sequence,
            capture_output=True,
            text=True,
            timeout=300.0 # Bounding limit to prevent hanging servers on mass fuzzing operations
        )
        
        # Capture raw buffer
        output_buffer = process.stdout + "\n" + process.stderr
        
        # Fast-track string parsing for CTF flags to elevate them to the LLM immediately
        flag_match = re.search(r"picoCTF\{[a-zA-Z0-9_]+\}", output_buffer)
        if flag_match:
            return f"CRITICAL SUCCESS: INFURNEX extracted flag -> {flag_match.group(0)}\n\n" + output_buffer
            
        return output_buffer # Yield the entire payload logic output array for LLM review
        
    except subprocess.TimeoutExpired:
        return "INFURNEX engine execution exceeded the 5-minute timeout window."
    except Exception as e:
        return f"INFURNEX core triggered an unhandled exception: {str(e)}"
