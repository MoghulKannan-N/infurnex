# infurnex/agent.py
import os # standard library for environment variables
import json # standard library for JSON parsing
import logging # standard library for structured logging
from typing import Dict, Any, List # typing support

# Set up procedural logging for the agent loop
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def build_system_prompt() -> str:
    # Returns the master system prompt defining the agent's identity and constraints
    return """You are INFURNEX, an expert AI penetration tester specializing in web security.
Your goal is to solve CTF web challenges by reasoning like a skilled security engineer.
You must adhere to the host allowlist and NEVER attack unauthorized targets.
Follow a ReAct (Reasoning + Acting) loop: Analyze, Plan, Act, Observe, Reflect.
Explain every step of your reasoning clearly.
When you find a flag, format your output as FLAG: picoCTF{...}."""

def invoke_llm(prompt: str, context: List[Dict[str, str]], model: str = "gpt-4o-mini") -> str:
    # Stub for calling the LLM API. Replaces real API call for scaffold.
    # Reads the API key from the environment variable (no secrets in code).
    api_key = os.environ.get("OPENAI_API_KEY") 
    # In a real implementation: client.chat.completions.create(messages=context, ...)
    logging.info(f"Invoking LLM model {model} with prompt length {len(prompt)}")
    
    # Return a mocked response for the sake of the unit tests and scaffold
    return "Action: http_request\nAction Input: {\"method\": \"GET\", \"url\": \"http://target.local:10101/\"}"

def parse_llm_action(llm_response: str) -> Dict[str, Any]:
    # Parses the LLM's text output to extract the tool name and JSON arguments
    tool_name = None # initialize tool name
    tool_args = {} # initialize tool arguments Dictionary
    for line in llm_response.split('\n'): # iterate over each line
        if line.startswith("Action:"): # check if line specifies the action
            tool_name = line.split("Action:")[1].strip() # extract action name
        elif line.startswith("Action Input:"): # check if line specifies the input
            arg_str = line.split("Action Input:")[1].strip() # extract JSON string
            try:
                tool_args = json.loads(arg_str) # parse JSON into dict
            except json.JSONDecodeError: # handle bad JSON from LLM
                logging.error("Failed to parse Action Input as JSON") # log error
    return {"tool": tool_name, "args": tool_args} # return the parsed intent

def execute_tool(action: Dict[str, Any], tools_registry: Dict[str, callable]) -> str:
    # Executes the requested tool dynamically from the registry
    tool_name = action.get("tool") # get the requested tool name
    if not tool_name: # check if tool was recognized
        return "Error: No valid action provided." # return error to LLM
    
    tool_fn = tools_registry.get(tool_name) # fetch the function reference
    if not tool_fn: # check if tool exists
        return f"Error: Tool '{tool_name}' not found." # return error to LLM
        
    try:
        # call the tool with unpacked arguments
        result = tool_fn(**action.get("args", {})) 
        return str(result) # return stringified result
    except Exception as e: # catch any tool execution errors
        return f"Tool Execution Error: {str(e)}" # return error to LLM so it can reflect

def run_agent_loop(challenge_manifest: Dict[str, str], tools_registry: Dict[str, callable], max_iterations: int = 10) -> str:
    # Main ReAct loop: runs until the flag is found or max iterations hit
    logging.info(f"Starting challenge: {challenge_manifest.get('title')}") # log start
    
    # Initialize the conversation context with system prompt
    context = [{"role": "system", "content": build_system_prompt()}]
    
    # Build the initial user prompt with challenge details
    initial_prompt = f"Challenge: {challenge_manifest.get('description')}\nTarget URL: {challenge_manifest.get('url')}"
    context.append({"role": "user", "content": initial_prompt}) # add to context
    
    iteration = 0 # tracking variable for loop threshold
    while iteration < max_iterations: # loop constraint
        iteration += 1 # increment counter
        logging.info(f"--- Iteration {iteration} ---") # log current iteration
        
        # 1. Reason & Plan (Call LLM)
        llm_response = invoke_llm(context[-1]["content"], context) # invoke model
        logging.info(f"LLM Reasoning:\n{llm_response}") # log model's thought trace
        context.append({"role": "assistant", "content": llm_response}) # store in history
        
        # Check for early termination (Flag found)
        if "FLAG: picoCTF{" in llm_response: # simple substring check
            logging.info("Agent claims to have found the flag!") # success log
            return generate_report(challenge_manifest, iteration, llm_response) # return formatted report
            
        # 2. Parse expected action
        action = parse_llm_action(llm_response) # extract requested tool
        
        if action.get("tool") is None: # check if an action was actually proposed
             context.append({"role": "user", "content": "Please propose an action using the specified format."})
             continue # skip tool execution
             
        # 3. Execute tool
        observation = execute_tool(action, tools_registry) # run the tool securely
        logging.info(f"Observation: {str(observation)[:200]}...") # truncate log output
        
        # 4. Update context with observation (Reflect)
        context.append({"role": "user", "content": f"Observation: {observation}"}) # add to history
        
    # If loop ends without returning, the maximum iterations were reached
    logging.warning("Max iterations reached. Exploit failed.") # log failure
    return "Failed to find flag within iteration limit. See structured failure report." # return failure

def generate_report(challenge: Dict[str, str], iterations: int, output: str) -> str:
    # Procedural report generator format
    return f"""=== INFURNEX CHALLENGE REPORT ===
Challenge Intro: {challenge.get('title')}
Target: {challenge.get('url')}

Step-by-step walkthrough:
Computed in {iterations} automatic iterations.
Final Output trace: {output}

Conclusion: Flag successfully retrieved in sandboxed environment.

Attribution & Disclaimer: Challenge by PicoCTF (Carnegie Mellon University). This writeup is for educational purposes only and documents our approach. Do not post spoilers for active competitions. We do not host challenge binaries or raw flags.
"""
