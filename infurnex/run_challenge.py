# infurnex/run_challenge.py
import json # for printing pretty formatting
from agent import run_agent_loop # import procedural loop
from tools import get_tool_registry # import tool setup

def main():
    # Example runner script demonstrating how to trigger the agent
    
    # 1. Define the challenge manifest locally
    sample_challenge = {
        "title": "SQL Direct", # name of challenge
        "description": "Connect to the postgres server and extract the flag.", # description
        "url": "http://target.local:10105", # target
        "expected_vuln": "SQLi" # hint for tracking, not necessarily fed to agent
    }
    
    # 2. Initialize the tool registry
    tools = get_tool_registry() # fetch available tools
    
    # 3. Launch the agent
    print(f"Starting INFURNEX against: {sample_challenge['title']}") # UX print
    report = run_agent_loop(sample_challenge, tools, max_iterations=5) # execute loop safely
    
    # 4. Output the final aggregated report
    print(report) # print final output string

if __name__ == "__main__":
    # execute main script when invoked directly
    main()
