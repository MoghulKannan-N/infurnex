#!/usr/bin/env python3
import os
import sys
import io
import asyncio
import contextlib
import subprocess
import re
import argparse
from dotenv import load_dotenv
from openai import AsyncOpenAI
from cai.sdk.agents import Runner

# Load environment variables from .env file
load_dotenv()

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
# Set defaults if not provided in .env
os.environ.setdefault("CAI_MODEL", "gpt-4o-mini")
os.environ.setdefault("CAI_STREAM", "false")
os.environ.setdefault("CAI_TELEMETRY", "false")
os.environ.setdefault("CAI_VERBOSE", "false")

if not os.getenv("OPENAI_API_KEY"):
    print("❌ Error: OPENAI_API_KEY not found in environment or .env file.")
    print("Please create a .env file based on .env.example")
    sys.exit(1)

# ─────────────────────────────────────────────
# BOOTSTRAP
# ─────────────────────────────────────────────
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
os.chdir(BASE_DIR)
sys.path.insert(0, BASE_DIR)

# ─────────────────────────────────────────────
# IMPORTS
# ─────────────────────────────────────────────
from agents.planner import build_planner
from agents.researcher import build_researcher

# ─────────────────────────────────────────────
# CLIENT
# ─────────────────────────────────────────────
# Uses OPENAI_API_KEY and optionally OPENAI_BASE_URL from environment
openai_client = AsyncOpenAI()

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

Rules:
- Do NOT run system commands (use the system agent for that)
- Provide clear, accurate answers from your knowledge
- If you don't know something, say so honestly
- BE CONCISE to save token costs.
"""


# ─────────────────────────────────────────────
# SYSTEM AGENTS
# ─────────────────────────────────────────────
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
# LLM DECIDER (lightweight direct API call)
# ─────────────────────────────────────────────
def _load_decider_prompt():
    with open("prompts/decider.txt") as f:
        return f.read()

DECIDER_PROMPT = _load_decider_prompt()

async def decide(user_input: str) -> str:
    """
    Ask the LLM to classify the query as KNOWLEDGE, COMMANDS, or SEARCH.
    Uses a direct API call with max_tokens=5 so it's cheap and fast.
    """
    try:
        resp = await openai_client.chat.completions.create(
            model=os.environ["CAI_MODEL"],
            messages=[
                {"role": "system", "content": DECIDER_PROMPT},
                {"role": "user", "content": user_input},
            ],
            max_tokens=5,
            temperature=0,
        )
        word = resp.choices[0].message.content.strip().split()[0].upper()
        if word in ("KNOWLEDGE", "COMMANDS", "SEARCH"):
            return word
        return "KNOWLEDGE"  # safe fallback
    except Exception:
        return "KNOWLEDGE"

async def chat_reply(user_input: str) -> str:
    """Direct API call for conversational responses — no runner overhead."""
    try:
        resp = await openai_client.chat.completions.create(
            model=os.environ["CAI_MODEL"],
            messages=[
                {"role": "system", "content": CHAT_PROMPT},
                {"role": "user", "content": user_input},
            ],
            temperature=0.7,
        )
        return resp.choices[0].message.content.strip()
    except Exception as e:
        return f"(chat error: {e})"


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

    # Capture output while streaming to console
    process = subprocess.Popen(
        cmd,
        shell=True,
        executable="/bin/bash",
        cwd=CURRENT_CWD,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1
    )

    output = []
    while True:
        line = process.stdout.readline()
        if not line and process.poll() is not None:
            break
        if line:
            print(line, end='', flush=True)  # Stream to user
            output.append(line)

    return process.poll(), "".join(output)

# ─────────────────────────────────────────────
# MAIN LOOP
# ─────────────────────────────────────────────
async def main():
    global DEBUG_MODE
    
    parser = argparse.ArgumentParser(description="Infurnex AI Agent")
    parser.add_argument("-d", "--debug", action="store_true", help="Enable debug mode (show AI thinking)")
    args = parser.parse_args()
    
    DEBUG_MODE = args.debug
    
    print("\nInfurnex successfully booted...! >>\n")

    while True:
        try:
            user_input = input("@ >> ").strip()
            if user_input.lower() in ("exit", "quit"):
                break

            verdict = await decide(user_input)

            if DEBUG_MODE:
                print(f"\n[DEBUG] Decider verdict: {verdict}")

            # 1. SEARCH PATH (Researcher)
            if "SEARCH" in verdict:
                if not DEBUG_MODE:
                    print("\n(searching internet...)\n")
                with suppress_stdout():
                    result = await runner.run(researcher, user_input)
                print(f"\ninfurnex > {result.final_output}\n")
                continue

            # 2. SYSTEM PATH (Planner) - EXPLICIT ONLY
            if "COMMANDS" in verdict or "YES" in verdict:
                with suppress_stdout():
                    plan = await runner.run(planner, user_input)
                
                if DEBUG_MODE:
                    print(f"[DEBUG] Planner Output: {plan.final_output}")
                    
                command = sanitize_command(plan.final_output)
                
                # If Planner couldn't generate a valid command, fall back to Chat
                if not command:
                    reply = await chat_reply(user_input)
                    print(f"\ninfurnex > {reply}\n")
                    continue

                rc, output = run_command(command)
                print(f"infurnex> {output}\n")

                # RETRY LOOP (Max 3 attempts)
                attempts = 0
                while rc != 0 and attempts < 3:
                    attempts += 1
                    print(f"\n[!] Command failed. Retrying... ({attempts}/3)\n")
                    
                    rethink_prompt = f"""
                    The previous command failed.
                    
                    Command:
                    {command}
                    
                    Error Output:
                    {output}
                    
                    Analyze the error. If it's a syntax error, fix it.
                    If you don't know the solution, use `web_search` to find the correct command.
                    
                    Output ONLY the corrected shell command.
                    """
                    
                    with suppress_stdout():
                        retry = await runner.run(planner, rethink_prompt)
                    
                    if DEBUG_MODE:
                        print(f"[DEBUG] Planner Retry Plan: {retry.final_output}")

                    retry_cmd = sanitize_command(retry.final_output)
                    
                    if retry_cmd:
                        command = retry_cmd  # Update current command
                        rc, output = run_command(command)
                        print(f"infurnex > {output}\n")
                    else:
                        print("Planner could not generate a fix.")
                        break
                continue

            # 3. KNOWLEDGE PATH (Chat) - DEFAULT FALLBACK
            reply = await chat_reply(user_input)
            print(f"\ninfurnex > {reply}\n")

        except KeyboardInterrupt:
            break
        except Exception as e:
            print(f"[ERROR] {e}")

    print("\n👋")

# ─────────────────────────────────────────────
# CLEAN ASYNCIO SHUTDOWN
# ─────────────────────────────────────────────
if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nBye 👋")

