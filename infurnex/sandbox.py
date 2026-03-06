# infurnex/sandbox.py
import subprocess # for executing OS commands
import logging # for structured logging

# Security policies
ALLOW_LIST: list[str] = ["target.local", "127.0.0.1", "localhost"]

def check_docker_running() -> bool:
    # Procedural check to verify the Docker daemon is accessible
    try:
        # Run docker info command
        result = subprocess.run(["docker", "info"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        return result.returncode == 0 # return True if success
    except FileNotFoundError: # happens if docker is not installed
        return False # not installed

def enforce_network_policy(url: str) -> bool:
    # Validates if the destination URL falls within the permitted sandbox boundary
    for host in ALLOW_LIST:
        if host in url:
            return True
    
    logging.error(f"Sandbox Violation Intercepted: Outbound request to {url} blocked.")
    return False
