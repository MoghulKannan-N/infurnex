#!/usr/bin/env python3
import os
import sys
import io
import asyncio
import contextlib
import subprocess
import re
import argparse
from openai import AsyncOpenAI
from cai.sdk.agents import Runner
# ─────────────────────────────────────────────
class _LiteLLMErrorFilter:
    def write(self, msg):
        if "Tracing client error" in msg:
            return
        if "Incorrect API key provided" in msg:
            return
        sys.__stderr__.write(msg)

    def flush(self):
        sys.__stderr__.flush()

sys.stderr = _LiteLLMErrorFilter()

# ─────────────────────────────────────────────
# GLOBALS
# ─────────────────────────────────────────────
DEBUG_MODE = False

# ─────────────────────────────────────────────
# ENVIRONMENT
# ─────────────────────────────────────────────
os.environ["OPENAI_API_KEY"] = "local"
os.environ["OPENAI_BASE_URL"] = "http://169.254.83.107:1234/v1"
os.environ["CAI_MODEL"] = "openai/mistral-7b-instruct-v0.3"
os.environ["CAI_STREAM"] = "false"
os.environ["CAI_TELEMETRY"] = "false"
os.environ["CAI_VERBOSE"] = "false"

# ─────────────────────────────────────────────
# BOOTSTRAP
# ─────────────────────────────────────────────
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
os.chdir(BASE_DIR)
sys.path.insert(0, BASE_DIR)

# ─────────────────────────────────────────────
# IMPORTS
# ─────────────────────────────────────────────
from agents.decider import build_decider
from agents.planner import build_planner
from agents.researcher import build_researcher
from cai.sdk.agents import Agent
from cai.sdk.agents.models.openai_chatcompletions import OpenAIChatCompletionsModel

# ─────────────────────────────────────────────
# CLIENT
# ─────────────────────────────────────────────
openai_client = AsyncOpenAI(
    api_key="local",
    base_url=os.environ["OPENAI_BASE_URL"],
)

# ─────────────────────────────────────────────
# CHAT AGENT (NO SYSTEM ACCESS)
# ─────────────────────────────────────────────
CHAT_PROMPT = """
You are Infurnex, an AI assistant specializing in Linux, security, and hacking.

I can answer questions about:
- Linux commands and system administration
- Security concepts and vulnerabilities  
- Hacking techniques and CTF challenges
- Penetration testing and exploit development
- General programming and cybersecurity topics

Note: I currently don't have web search enabled, but I have extensive knowledge 
about security, Linux, and hacking from my training data.

Rules:
- Do NOT run system commands (use the system agent for that)
- Provide clear, accurate answers from your knowledge
- If you don't know something, say so honestly
"""

chat = Agent(
    name="Chat",
    instructions=CHAT_PROMPT,
    model=OpenAIChatCompletionsModel(
        model=os.environ["CAI_MODEL"],
        openai_client=openai_client,
    ),
    tools=[],  # No web search - it causes infinite loops
)

# ─────────────────────────────────────────────
# SYSTEM AGENTS
# ─────────────────────────────────────────────
decider = build_decider(openai_client)
planner = build_planner(openai_client)
researcher = build_researcher(openai_client)
runner = Runner()

# ─────────────────────────────────────────────
# REAL SHELL STATE
# ─────────────────────────────────────────────
CURRENT_CWD = os.getcwd()

# ─────────────────────────────────────────────
# SUPPRESS CAI VERBOSE OUTPUT
# ─────────────────────────────────────────────

@contextlib.contextmanager
def suppress_stdout():
    """Temporarily suppress stdout to hide CAI debug boxes, unless in DEBUG_MODE"""
    if DEBUG_MODE:
        yield
        return
        
    old_stdout = sys.stdout
    sys.stdout = io.StringIO()
    try:
        yield
    finally:
        sys.stdout = old_stdout


# ─────────────────────────────────────────────
# COMMAND SANITIZER (COMMAND ONLY)
# ─────────────────────────────────────────────
CMD_RE = re.compile(r"^[a-zA-Z0-9_./~\-][^\n]*$")

def sanitize_command(text: str) -> str:
    if not text:
        return ""

    text = text.strip()

    if text.startswith("```"):
        lines = text.splitlines()[1:]
        if lines and lines[-1].startswith("```"):
            lines = lines[:-1]
    else:
        lines = text.splitlines()

    for line in lines:
        line = line.strip()
        if not line:
            continue
        if line.upper() == "NOTHING":
            return ""
        # Reject commands with placeholders
        if '<' in line and '>' in line:
            continue
        if CMD_RE.match(line):
            return line

    return ""

# ─────────────────────────────────────────────
# EXECUTION ENGINE (TTY-SAFE)
# ─────────────────────────────────────────────
def run_command(cmd: str):
    global CURRENT_CWD

    if not cmd:
        return 0, "(no command executed)"

    # Handle cd internally
    if cmd.startswith("cd "):
        target = os.path.expanduser(cmd[3:].strip())
        if not os.path.isabs(target):
            target = os.path.join(CURRENT_CWD, target)

        if os.path.isdir(target):
            CURRENT_CWD = os.path.abspath(target)
            return 0, f"(cwd changed to {CURRENT_CWD})"
        return 1, f"cd: no such directory: {cmd[3:].strip()}"

    # sudo confirmation
    if cmd.lstrip().startswith("sudo"):
        confirm = input("⚠️  sudo command detected. Execute? (y/N): ").strip().lower()
        if confirm != "y":
            return 1, "(sudo cancelled)"

    # 🔥 DO NOT capture stdout/stderr → allow sudo password prompt
    proc = subprocess.run(
        cmd,
        shell=True,
        executable="/bin/bash",
        cwd=CURRENT_CWD,
    )

    return proc.returncode, "(command finished)"

# ─────────────────────────────────────────────
# MAIN LOOP
# ─────────────────────────────────────────────
async def main():
    global DEBUG_MODE
    
    parser = argparse.ArgumentParser(description="Infurnex AI Agent")
    parser.add_argument("-d", "--debug", action="store_true", help="Enable debug mode (show AI thinking)")
    args = parser.parse_args()
    
    DEBUG_MODE = args.debug
    
    print("Infurnex successfully booted...! >>\n")

    while True:
        try:
            user_input = input("@ >> ").strip()
            if user_input.lower() in ("exit", "quit"):
                break

            with suppress_stdout():
                decision = await runner.run(decider, user_input)
            
            if DEBUG_MODE:
                print(f"\n[DEBUG] Decider Output: {decision.final_output}")
                
            verdict = decision.final_output.strip().split()[0].upper()

            # 1. KNOWLEDGE PATH (Chat)
            if "KNOWLEDGE" in verdict or "NO" in verdict:  # Backward compatibility
                with suppress_stdout():
                    reply = await runner.run(chat, user_input)
                print(f"\ninfurnex > {reply.final_output}\n")
                continue

            # 2. SEARCH PATH (Researcher)
            if "SEARCH" in verdict:
                if not DEBUG_MODE:
                    print("\n(searching internet...)\n")
                with suppress_stdout():
                    result = await runner.run(researcher, user_input)
                print(f"\ninfurnex > {result.final_output}\n")
                continue

            # 3. SYSTEM PATH (Planner)
            # Default to system path if COMMANDS or YES
            with suppress_stdout():
                plan = await runner.run(planner, user_input)
            
            if DEBUG_MODE:
                print(f"[DEBUG] Planner Output: {plan.final_output}")
                
            command = sanitize_command(plan.final_output)
            
            # If Planner couldn't generate a valid command, fall back to Chat
            if not command:
                with suppress_stdout():
                    reply = await runner.run(chat, user_input)
                print(f"\ninfurnex > {reply.final_output}\n")
                continue

            rc, output = run_command(command)
            print(f"infurnex> {output}\n")

            # SINGLE RETHINK ON FAILURE
            if rc != 0 and command:
                rethink_prompt = f"""
The command failed.

Command:
{command}

Error:
{output}

Generate ONE alternative shell command to achieve the same goal.
Output ONLY the command.
"""
                with suppress_stdout():
                    retry = await runner.run(planner, rethink_prompt)
                retry_cmd = sanitize_command(retry.final_output)

                if retry_cmd and retry_cmd != command:
                    rc, output = run_command(retry_cmd)
                    print(f"infurnex > {output}\n")

        except KeyboardInterrupt:
            break
        except Exception as e:
            print(f"[ERROR] {e}")

    print("Bye 👋")

# ─────────────────────────────────────────────
# CLEAN ASYNCIO SHUTDOWN
# ─────────────────────────────────────────────
if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nBye 👋")

