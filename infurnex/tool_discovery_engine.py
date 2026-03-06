# infurnex/tool_discovery_engine.py
import os # system path scanning
import subprocess # tool execution
import logging # procedural logging
from typing import Dict, List, Set, Any, Optional # robust typing

# Setup standard output logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - ORCHESTRATOR - %(message)s')

# Global cache for the capability map to avoid repeating expensive introspection
_CAPABILITY_CACHE: Dict[str, List[str]] = {}

def get_discovery_paths() -> List[str]:
    # Extracts environment PATH and merges it with explicitly required system directories
    env_paths = os.environ.get("PATH", "").split(os.pathsep) if os.environ.get("PATH") else []
    
    # Required legacy and modern Unix directories to check
    required_locations = [
        "/usr/bin",
        "/usr/local/bin",
        "/bin",
        "/usr/sbin",
        "/opt"
    ]
    
    # Merge and deduplicate standard paths, ensuring they exist on disk
    all_paths = set(env_paths)
    for loc in required_locations:
        if os.path.exists(loc):
            all_paths.add(loc)
            
    return list(all_paths)

def discover_tools() -> List[str]:
    # Scans the operating system to dynamically identify all accessible executable binaries.
    # Ignores hardcoded lists, guaranteeing INFURNEX adapts to the host environment.
    discovered_binaries = []
    search_paths = get_discovery_paths() # pull merged paths
    
    for directory in search_paths: # iterate filesystem points
        if not os.path.exists(directory) or not os.path.isdir(directory):
            continue # gracefully skip invalid mounts or broken symlink dirs
            
        try:
            for filename in os.listdir(directory): # enumerate files
                filepath = os.path.join(directory, filename)
                
                # Verify that the file exists, is not a directory, and has executable permission
                if os.path.isfile(filepath) and os.access(filepath, os.X_OK):
                    discovered_binaries.append(filepath) # register absolute file path
        except PermissionError:
            # Safely ignore directories the agent user does not have read access to
            continue
            
    # Deduplicate tools so we only keep the highest precedence binary
    # (e.g. if 'nmap' exists in both /usr/bin and /opt)
    unique_tools = {}
    for binary_path in discovered_binaries:
        base_name = os.path.basename(binary_path)
        if base_name not in unique_tools: # keep first occurrence
            unique_tools[base_name] = binary_path
            
    # Return absolute paths of uniquely named executables
    return list(unique_tools.values())

def extract_capabilities(help_text: str) -> List[str]:
    # Analyzes stdout/stderr from a tool executing and infers its capabilities
    # using normalized keyword mapping. Output is converted to standard tags.
    
    # Normalization dictionary mapping trigger keywords to exact capability tags
    # Ensures compatibility with the INFURNEX strategy engine
    keyword_map = {
        "sql": "sql_injection",
        "sqli": "sql_injection",
        "xss": "xss",
        "fuzz": "fuzzing",
        "fuzzer": "fuzzing",
        "scan": "scanning",
        "api": "api_testing",
        "bruteforce": "bruteforce",
        "directory": "directory_discovery",
        "payload": "payload_generation",
        "exploit": "exploitation",
        "recon": "reconnaissance",
        "http": "http_request",
        "wordlist": "wordlist_processing"
    }
    
    capabilities: Set[str] = set() # use a set to automatically drop duplicate mappings
    help_lower = help_text.lower() # lowercase the entire IO buffer for clean blind matching
    
    for keyword, capability_tag in keyword_map.items(): # iterate the mapping schema
        if keyword in help_lower: # basic substring identification check
            capabilities.add(capability_tag) # register the converted tag
            
    return list(capabilities) # cast to generic list for JSON-like state handling

def execute_help_probe(binary_path: str) -> str:
    # Safely fires a binary with various help flag permutations to extract its manual page.
    # Employs strict timeout handling to prevent hanging on interactive tools.
    help_flags = ["--help", "-h", "help"] # sequence of typical help commands
    
    for flag in help_flags: # sequentially cycle flags
        try:
            # Execute binary using subprocess. Merge stdout/stderr together since many tools write help to stderr.
            result = subprocess.run(
                [binary_path, flag],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT, # pipe stderr into stdout channel
                text=True, # native UT8 string decode
                timeout=1.0 # 1-second aggressive timeout to stop netcat/sh from hanging infinitely
            )
            
            # Use heuristic to checking if help actually fired or if it threw an error
            # If the output string is longer than 50 characters, it's likely a man page.
            if result.stdout and len(result.stdout) > 50:
                return result.stdout 
                
        except subprocess.TimeoutExpired:
            # Tool hung waiting for input. Skip it to protect the agent loop.
            return ""
        except Exception:
            # Binary crashed or threw a fatal filesystem exception
            continue
            
    return "" # Default return if all permutations failed or output was useless

def build_capability_map(force_rescan: bool = False, limit_scan: int = 150) -> Dict[str, List[str]]:
    # Central orchestration function to build the memory state of system capabilities.
    # Uses a cache variable to avoid locking up CPU rescanning identical binaries every loop.
    global _CAPABILITY_CACHE
    
    if _CAPABILITY_CACHE and not force_rescan: # Check cache validity first
        logging.info("Returning capability map from memory cache.")
        return _CAPABILITY_CACHE
        
    logging.info("Initiating dynamic tool discovery scan across host filesystem.")
    _CAPABILITY_CACHE.clear() # purge old memory state explicitly
    
    available_binaries = discover_tools() # index all binaries
    logging.info(f"Discovered {len(available_binaries)} generic executables.")
    
    scanned = 0 # tracking integer
    for binary in available_binaries: # iterate found tools
        if scanned >= limit_scan: # cap the maximum scanned items to preserve execution speed
            break
            
        help_page = execute_help_probe(binary) # fire introspection payload
        if not help_page: # if the tool is invisible or interactive
            continue
            
        inferred_caps = extract_capabilities(help_page) # parse logic from manual page
        if inferred_caps: # If it has recognized offensive tags
            _CAPABILITY_CACHE[binary] = inferred_caps # map the absolute path to the array of string capabilities
            logging.info(f"Mapped {os.path.basename(binary)} -> {inferred_caps}")
            scanned += 1 # only increment tracker for successfully parsed offensive tools
            
    logging.info(f"Capability map successfully built with {len(_CAPABILITY_CACHE)} mapped tools.")
    return _CAPABILITY_CACHE # yield mapping dictionary

def select_tool_for_capability(required_capability: str) -> str:
    # Serves the Strategy Engine by receiving a desired capability string (e.g. "sql_injection") 
    # and returning an absolutely qualified path to a tool that implements it.
    
    capability_map = build_capability_map(force_rescan=False) # fetch map from memory safely
    
    for tool_path, capabilities in capability_map.items(): # iterate over all mapped endpoints
        if required_capability in capabilities: # perform the logic branch
            logging.info(f"Dynamic selection successful: chose {os.path.basename(tool_path)} for '{required_capability}'")
            return tool_path # automatically yield the first available deterministic match
            
    logging.warning(f"No dynamically discovered tool could fulfill capability constraint: '{required_capability}'")
    return "" # fallback

def execute_tool(tool_path: str, arguments: List[str]) -> Dict[str, Any]:
    # Generic subprocess execution wrapper for firing offensive tools dynamically.
    # Designed specifically to run blindly via INFURNEX strategy instructions.
    
    if not tool_path or not os.path.exists(tool_path): # validation
        logging.error("Called execute_tool with an invalid executable path.")
        return {"stdout": "", "stderr": "Invalid tool path", "exit_code": 1}
        
    command_sequence = [tool_path] + arguments # mathematically concatenate execution array
    logging.info(f"Lauching automated orchestrator tool execution: {' '.join(command_sequence)}")
    
    try:
        # Wrap execution in generic subprocess call
        # Allows output to be safely parsed by downstream agent loggers
        result = subprocess.run(
            command_sequence,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True, # enforce string types over bytes
            timeout=120.0 # 2-minute strict bounding limit to preserve sandbox integrity
        )
        
        return { # Yield a unified output schema
            "stdout": result.stdout,
            "stderr": result.stderr,
            "exit_code": result.returncode
        }
        
    except subprocess.TimeoutExpired:
        logging.error(f"Process {tool_path} violently terminated. Maximum timeout of 120.0s exceeded.")
        # Return fallback format upon terminal failure
        return {"stdout": "", "stderr": "PROCESS TIMED OUT AND WAS KILLED", "exit_code": 124}
    except Exception as e:
        logging.error(f"Process {tool_path} triggered unhandled exception: {e}")
        # Return fallback format upon fatal system crash
        return {"stdout": "", "stderr": str(e), "exit_code": 1}
